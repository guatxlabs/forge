"""Mémoire d'engagement — store + dedup + recherche des findings.

v0 : store JSONL local + dedup par clé normalisée (cible, titre/catégorie). Pur-stdlib,
hermétique. La dedup évite de re-rapporter le même finding à chaque scan.

Backend de production (à brancher, P2 suite) : la base FAISS du toolkit YWH
(`toolkit/mcp/findings_db.py`, dedup sémantique à 0.85, knowledge base + triager_feedback).
L'interface ci-dessous (store/seen/search) est volontairement compatible pour swap ultérieur.
"""
import json
import re
from pathlib import Path

_WS = re.compile(r"\s+")
# verdicts/statuts qui varient pour un MÊME finding logique (tested -> vulnerable -> submitted...) :
# on les retire du titre de dedup pour que la clé reste STABLE quel que soit l'avancement du verdict
# (sinon le même bug re-rapporté avec un statut différent passe la dedup et crée un doublon).
_VERDICT_TOKENS = re.compile(
    r"\b(tested|vulnerable|not[_ ]?vulnerable|confirmed|unconfirmed|submitted|accepted|"
    r"rejected|informative|veto|dry[_ ]?run|fire|open|closed|fixed|todo|wip)\b")


def _norm(s):
    return _WS.sub(" ", (s or "").strip().lower())


def _norm_title(s):
    """Titre normalisé STABLE pour la dedup : minuscule + retrait des tokens de verdict/statut.
    Indépendant du verdict -> le même finding dédupe pareil qu'il soit 'tested' ou 'vulnerable'."""
    return _WS.sub(" ", _VERDICT_TOKENS.sub(" ", _norm(s))).strip()


class Memory:
    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.records = []
        self._keys = set()
        if self.path and self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    r = json.loads(line)
                    self.records.append(r)
                    self._keys.add(self._key_d(r))

    @staticmethod
    def _key_d(d):
        return (_norm(d.get("target")), _norm(d.get("category")),
                _norm_title(d.get("title")) or _norm(d.get("category")))

    def key(self, finding):
        return self._key_d(finding.to_dict() if hasattr(finding, "to_dict") else finding)

    def seen(self, finding):
        return self.key(finding) in self._keys

    def store(self, finding):
        """Retourne True si nouveau (stocké), False si déjà vu (dedup)."""
        k = self.key(finding)
        if k in self._keys:
            return False
        self._keys.add(k)
        d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        self.records.append(d)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(d, ensure_ascii=False, separators=(",", ":")) + "\n")
        return True

    def search(self, q, k=10):
        q = _norm(q)
        hits = [r for r in self.records
                if q in _norm(r.get("title")) or q in _norm(r.get("evidence")) or q in _norm(r.get("target"))]
        return hits[:k]

    def stats(self):
        return {"records": len(self.records), "unique_keys": len(self._keys)}


def _shingles(text, k=3):
    t = _norm(text)
    if len(t) < k:
        return {t} if t else set()
    return {t[i:i + k] for i in range(len(t) - k + 1)}


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


class JaccardMemory(Memory):
    """Dedup FLOUE (stdlib) : même cible normalisée + titre similaire (Jaccard de trigrammes >= seuil).

    Améliore l'exact-match : « SSRF in url param » et « SSRF in url param. » sont fusionnés, mais des
    cibles différentes restent distinctes (pas de faux-merge d'IDOR sur /orders/1 vs /orders/2).
    Honnête : Jaccard ≠ vraiment sémantique (pas d'embeddings) — pour ça, voir EmbeddingMemory (FAISS).
    """

    def __init__(self, path=None, threshold=0.8):
        self.threshold = threshold
        self._sig = []          # [(target_norm, category_norm, shingles)]
        super().__init__(path)
        for r in self.records:
            self._sig.append((_norm(r.get("target")), _norm(r.get("category")),
                              _shingles(_norm_title(r.get("title")) or _norm(r.get("category")))))

    def _match(self, finding):
        d = finding.to_dict() if hasattr(finding, "to_dict") else finding
        tgt = _norm(d.get("target"))
        cat = _norm(d.get("category"))
        sh = _shingles(_norm_title(d.get("title")) or _norm(d.get("category")))
        return any(t == tgt and c == cat and _jaccard(sh, s) >= self.threshold
                   for (t, c, s) in self._sig)

    def seen(self, finding):
        return self._match(finding)

    def store(self, finding):
        if self._match(finding):
            return False
        d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        self._sig.append((_norm(d.get("target")), _norm(d.get("category")),
                          _shingles(_norm_title(d.get("title")) or _norm(d.get("category")))))
        self.records.append(d)
        self._keys.add(self._key_d(d))
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(d, ensure_ascii=False, separators=(",", ":")) + "\n")
        return True


def make_memory(path=None, mode="auto", threshold=0.85):
    """Fabrique de mémoire. mode : 'exact' | 'jaccard' | 'faiss' | 'auto'.

    'faiss'/'auto' tente le backend embeddings (dedup sémantique, réutilise la stack du toolkit YWH) ;
    dégrade proprement vers Jaccard (stdlib) si sentence-transformers/faiss sont absents.
    """
    if mode in ("faiss", "auto"):
        try:
            from .memory_faiss import EmbeddingMemory
            return EmbeddingMemory(path, threshold=threshold)
        except Exception:  # noqa: BLE001
            if mode == "faiss":
                import sys
                print("[forge] backend embeddings indisponible -> repli Jaccard (stdlib)", file=sys.stderr)
            # le seuil par défaut (0.85) vise les embeddings ; Jaccard-trigrammes sature plus bas,
            # on le borne à 0.8 pour rester discriminant (sinon quasi aucun fuzzy-merge).
            return JaccardMemory(path, threshold=min(threshold, 0.8))
    if mode == "jaccard":
        return JaccardMemory(path, threshold=min(threshold, 0.8))   # même borne Jaccard que le repli
    return Memory(path)

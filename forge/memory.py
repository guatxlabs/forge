# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mémoire d'engagement — store + dedup + recherche des findings.

Trois backends derrière UNE interface (`store` / `seen` / `search`), du plus strict au plus tolérant :
`Memory` (clé exacte : cible + catégorie + titre normalisé), `JaccardMemory` (dedup FLOUE stdlib :
même cible + trigrammes similaires) et `memory_faiss.EmbeddingMemory` (dedup SÉMANTIQUE, OPT-IN, dont
le chargement de modèle est un egress gouverné). `make_memory` (bas de fichier) les fabrique et fixe
la politique : LE REPLI STDLIB EST LE DÉFAUT.

Store JSONL local, pur-stdlib, hermétique. La dedup évite de re-rapporter le même finding à chaque scan.
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


# Modes qui demandent EXPLICITEMENT le backend à embeddings. `'faiss'` est l'alias HISTORIQUE de
# `'embeddings'` (le nom du module est historique ; il n'y a pas d'index FAISS — cf. memory_faiss).
_EMBEDDING_MODES = ("embeddings", "faiss")


def make_memory(path=None, mode="auto", threshold=0.85, allow_download=False):
    """Fabrique de mémoire. mode : 'exact' | 'jaccard' | 'embeddings' (alias 'faiss') | 'auto'.

    LE REPLI STDLIB EST LE DÉFAUT, et il l'est SANS CONDITION : `'auto'` rend `JaccardMemory` et ne
    TENTE MÊME PAS l'import du backend à embeddings. C'est délibéré — charger un encodeur est un EGRESS
    (téléchargement du modèle), et `'auto'` basculait auparavant sur ce backend dès que
    `sentence-transformers` se TROUVAIT installé dans l'environnement, pour une raison quelconque : le
    défaut sortait alors sur le réseau sans que personne ne l'ait demandé.

    `'embeddings'` est l'OPT-IN explicite. Même là, le modèle est chargé HORS-LIGNE (cache local) sauf
    `allow_download=True`, second opt-in qui autorise la sortie réseau. Toute indisponibilité
    (dépendance absente, modèle non caché, erreur quelconque) DÉGRADE vers Jaccard (stdlib) avec une
    note sur stderr — jamais une exception, jamais un run cassé.
    """
    if mode in _EMBEDDING_MODES:
        try:
            from .memory_faiss import EmbeddingMemory
            return EmbeddingMemory(path, threshold=threshold, allow_download=allow_download)
        except Exception as e:  # noqa: BLE001
            import sys
            print(f"[forge] backend embeddings indisponible ({type(e).__name__}) -> repli Jaccard "
                  f"(stdlib){'' if allow_download else ' ; modèle chargé hors-ligne (cache local seul)'}",
                  file=sys.stderr)
            # le seuil par défaut (0.85) vise les embeddings ; Jaccard-trigrammes sature plus bas,
            # on le borne à 0.8 pour rester discriminant (sinon quasi aucun fuzzy-merge).
            return JaccardMemory(path, threshold=min(threshold, 0.8))
    # `auto` (le DÉFAUT) rejoint `jaccard` : le meilleur backend atteignable SANS egress ni dépendance.
    # Même borne de seuil que le repli ci-dessus (les trigrammes saturent plus bas que les embeddings).
    if mode in ("jaccard", "auto"):
        return JaccardMemory(path, threshold=min(threshold, 0.8))
    return Memory(path)

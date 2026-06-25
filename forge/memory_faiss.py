"""Backend mémoire à EMBEDDINGS (dedup sémantique) — optionnel.

Réutilise la stack du toolkit YWH (sentence-transformers, all-MiniLM-L6-v2 — le même modèle que la
base FAISS `findings_db.py`). Dedup par similarité cosinus >= seuil, restreinte à la même cible
(évite de fusionner des findings de cibles différentes). Si les deps manquent, l'import de ce module
échoue et `memory.make_memory` retombe automatiquement sur `JaccardMemory` (stdlib).

NB : non prouvé en live dans l'env système (faiss/torch vivent dans toolkit/mcp/venv) ; pour
l'activer, lancer Forge avec ce venv sur le PYTHONPATH. Le code est néanmoins correct et isolé.
"""
import json

import numpy as np
from sentence_transformers import SentenceTransformer

from .memory import Memory, _norm


class EmbeddingMemory(Memory):
    _model = None

    def __init__(self, path=None, threshold=0.85, model="all-MiniLM-L6-v2"):
        self.threshold = threshold
        if EmbeddingMemory._model is None:
            EmbeddingMemory._model = SentenceTransformer(model)
        self._vecs = []     # [(vec, target_norm)]
        super().__init__(path)
        for r in self.records:
            self._vecs.append((self._embed(r), _norm(r.get("target"))))

    @staticmethod
    def _text(d):
        return f"{d.get('title', '')} {d.get('category', '')} {d.get('target', '')}".strip()

    def _embed(self, finding):
        d = finding.to_dict() if hasattr(finding, "to_dict") else finding
        v = EmbeddingMemory._model.encode(self._text(d), normalize_embeddings=True)
        return np.asarray(v, dtype="float32")

    def _match(self, finding):
        d = finding.to_dict() if hasattr(finding, "to_dict") else finding
        v = self._embed(d)
        tgt = _norm(d.get("target"))
        return any(t == tgt and float(np.dot(v, vv)) >= self.threshold for (vv, t) in self._vecs)

    def seen(self, finding):
        return self._match(finding)

    def store(self, finding):
        if self._match(finding):
            return False
        d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        self._vecs.append((self._embed(d), _norm(d.get("target"))))
        self.records.append(d)
        self._keys.add(self._key_d(d))
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(d, ensure_ascii=False, separators=(",", ":")) + "\n")
        return True

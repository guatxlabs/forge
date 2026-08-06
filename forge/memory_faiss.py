# SPDX-License-Identifier: AGPL-3.0-or-later
"""Backend mémoire à EMBEDDINGS (dedup SÉMANTIQUE) — OPTIONNEL, OPT-IN, egress GATÉ.

Dedup par similarité COSINUS >= seuil, restreinte à la MÊME cible (deux findings de cibles
différentes ne fusionnent jamais). Encodage via `sentence-transformers` (all-MiniLM-L6-v2 par défaut,
vecteurs normalisés -> cosinus == produit scalaire), comparaison par balayage linéaire.

GOUVERNANCE — charger un modèle d'embeddings est un EGRESS :
  1. JAMAIS PAR DÉFAUT. `memory.make_memory` ne construit CETTE classe que sur `mode='embeddings'`
     (alias historique `'faiss'`) EXPLICITE. `mode='auto'` — le défaut — reste le repli stdlib
     (`JaccardMemory`) et ne TENTE MÊME PAS cet import : sur une machine où `sentence-transformers`
     se trouve installé pour une autre raison, le défaut ne bascule PAS en silence sur un backend
     qui télécharge un modèle.
  2. HORS-LIGNE PAR DÉFAUT. `allow_download=False` (défaut) charge le modèle sous `HF_HUB_OFFLINE=1`
     / `TRANSFORMERS_OFFLINE=1` : un modèle DÉJÀ EN CACHE local marche, un modèle ABSENT lève au lieu
     d'être téléchargé silencieusement. `allow_download=True` est l'opt-in EXPLICITE qui autorise la
     sortie réseau. L'environnement est restauré à l'identique après le chargement.
  3. DÉGRADATION GRACIEUSE. Dépendance absente, modèle non caché, ou toute autre erreur => l'import
     ou la construction LÈVE, et `memory.make_memory` retombe sur `JaccardMemory` (stdlib). Un backend
     indisponible ne casse JAMAIS un run.

NB : le nom du fichier est HISTORIQUE et la docstring d'origine était FAUSSE — il n'y a PAS d'index
FAISS ici, et il n'y en a jamais eu : la comparaison est un balayage linéaire de produits scalaires.
Pour la volumétrie d'une mémoire d'engagement (centaines à quelques milliers de findings), un index ANN
n'apporterait rien et ajouterait une dépendance lourde ; le coût dominant reste de toute façon la passe
d'encodage. Le balayage est en Python PUR (stdlib) : `numpy` n'est plus une dépendance d'import, si bien
que le module reste chargeable — et TESTABLE hermétiquement, avec un encodeur factice — sans elle.
"""
import json
import os
from contextlib import contextmanager

from .memory import Memory, _norm

# Variables d'environnement HORS-LIGNE honorées par huggingface_hub / transformers (la pile sous
# sentence-transformers) : à `1`, un poids absent du cache local lève au lieu d'être téléchargé.
_OFFLINE_ENV = ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE")

# Cache de modèles PARTAGÉ, clé = nom du modèle. (Auparavant un unique attribut de classe : une
# 2e instance demandant un AUTRE modèle réutilisait silencieusement le PREMIER chargé.)
_MODELS: dict = {}


@contextmanager
def _offline_env(active):
    """Force (ou non) le mode HORS-LIGNE de la pile HuggingFace le temps du chargement du modèle, puis
    RESTAURE l'environnement exactement tel qu'il était (y compris l'ABSENCE d'une variable). `active`
    False = opt-in explicite au téléchargement : on ne touche à rien."""
    if not active:
        yield
        return
    previous = {k: os.environ.get(k) for k in _OFFLINE_ENV}
    try:
        for k in _OFFLINE_ENV:
            os.environ[k] = "1"
        yield
    finally:
        for k, v in previous.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _load_model(name, allow_download):
    """Charge (et mémorise) l'encodeur `name`. Import PARESSEUX de `sentence_transformers` : le coût et
    la dépendance ne sont payés qu'à la construction effective du backend. LÈVE si la dépendance manque
    ou si le modèle n'est pas en cache alors que le téléchargement n'est pas autorisé — l'appelant
    (`memory.make_memory`) traduit cela en repli stdlib."""
    if name in _MODELS:
        return _MODELS[name]                       # déjà chargé -> aucun egress possible
    from sentence_transformers import SentenceTransformer      # ImportError -> repli chez l'appelant
    with _offline_env(not allow_download):
        model = SentenceTransformer(name)
    _MODELS[name] = model
    return model


def _dot(a, b):
    """Produit scalaire de deux vecteurs NORMALISÉS == similarité cosinus. Python pur (stdlib) ;
    `EmbeddingMemory._encode` fournit des listes de float, quelle que soit la forme rendue par
    l'encodeur."""
    return sum(x * y for x, y in zip(a, b))


class EmbeddingMemory(Memory):
    """Mémoire à dedup sémantique. `seen`/`store` remplacent la clé exacte de `Memory` par
    « même cible ET cosinus(titre+catégorie+cible) >= seuil ».

    `self._vecs` est tenu INDEX-ALIGNÉ avec `self.records` (construit au chargement, étendu par
    `store`) : chaque vecteur porte aussi la cible normalisée, qui BORNE la fusion."""

    def __init__(self, path=None, threshold=0.85, model="all-MiniLM-L6-v2", allow_download=False):
        self.threshold = threshold
        self._model = _load_model(model, allow_download)   # lève si indispo -> repli côté fabrique
        self._vecs = []     # [(vec, target_norm)] — aligné sur self.records
        super().__init__(path)
        for r in self.records:
            self._vecs.append((self._embed(r), _norm(r.get("target"))))

    @staticmethod
    def _text(d):
        return f"{d.get('title', '')} {d.get('category', '')} {d.get('target', '')}".strip()

    def _encode(self, text):
        """Encode en liste de float NORMALISÉE. `normalize_embeddings=True` -> le produit scalaire EST
        le cosinus. La conversion en liste de float rend le vecteur indépendant du type rendu par
        l'encodeur (ndarray, tenseur, liste)."""
        return [float(x) for x in self._model.encode(text, normalize_embeddings=True)]

    def _embed(self, finding):
        d = finding.to_dict() if hasattr(finding, "to_dict") else finding
        return self._encode(self._text(d))

    def _match(self, finding):
        d = finding.to_dict() if hasattr(finding, "to_dict") else finding
        v = self._embed(d)
        tgt = _norm(d.get("target"))
        return any(t == tgt and _dot(v, vv) >= self.threshold for (vv, t) in self._vecs)

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

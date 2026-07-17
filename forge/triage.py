# SPDX-License-Identifier: AGPL-3.0-only
"""Triage NATIF des findings — dédup / cluster-bruit / score-bruit / rang (stdlib pure, zéro-egress).

PROBLÈME (T24/T27) : une campagne émet 441 à 1406 findings DOMINÉS par du bruit à haute cardinalité —
URLs d'archive gau (`Endpoint in-scope : <url>` ×des centaines), gabarits « … non testé — config
manquante », missing-headers répétés par service. Le signal (les rares MEDIUM+ réels) se NOIE.

CE MODULE est une COUCHE DE VUE, appliquée APRÈS la collecte (pas dans les oracles) : il ANNOTE et
CLASSE, il ne SUPPRIME JAMAIS un finding. Garanties (miroir du planner coverage-safe + intégrité du
ledger) :

  1. ZÉRO-EGRESS / STDLIB : aucune dépendance, aucun modèle, aucun réseau. Déterministe (même entrée
     -> même sortie ; tri stable par index d'origine).
  2. COVERAGE-SAFE — NE PERD JAMAIS UN FINDING : le triage produit des ANNOTATIONS parallèles + une
     VUE classée qui contient TOUS les findings (bruit relégué en bas, jamais retiré). `len(in) ==
     len(out)`. Les objets Finding NE SONT PAS mutés — le ledger et les enregistrements bruts restent
     intacts et auditables.
  3. TRANSPARENT : chaque finding reçoit `{score, cluster_id, likely_noise, reason}` ; un `summary`
     agrège (N findings -> M actionnables, K bruit/dup, top clusters + raisons). Le rapport SURFACE ces
     deux éléments (section dédiée + annotation par finding). `likely_noise` est un simple DRAPEAU :
     par défaut RIEN n'est masqué (`auto_hide=False`).
  4. CONFIGURABLE : on/off + seuils/poids via le mécanisme `scope.triage` (miroir de `allow_private` —
     lu depuis scope.json, défaut SÛR). `TriageConfig.from_dict` tolère l'absence / les valeurs folles.
  5. LÉGER : normalisation + shingle-Jaccard heuristique (O(N) hachage + comparaisons bornées PAR
     cluster). Aucun calcul lourd par finding, aucune inférence. Rapide sur 1000+ findings.

Le noise-score (0..1) est une somme PONDÉRÉE et DOCUMENTÉE de contributions (voir `NOISE_WEIGHTS`),
clampée. Un finding MEDIUM+ est PLAFONNÉ bas et n'est JAMAIS `likely_noise` (un actionnable ne se
range pas dans le bruit — plancher de sécurité, comme le plancher qualifiant du planner).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .schema import SEVERITIES
from . import resource_profile

# --- sévérités ------------------------------------------------------------------------------------
# Rang de sévérité (INFO=0 .. CRITICAL=4). Un finding >= MEDIUM est « actionnable » par défaut : jamais
# rabattu dans le bruit (plancher de sécurité). Dérivé de la source unique `schema.SEVERITIES`.
_MEDIUM_RANK = SEVERITIES.index("MEDIUM")


def _sev_rank(sev: str) -> int:
    s = (sev or "").strip().upper()
    return SEVERITIES.index(s) if s in SEVERITIES else 0


# --- POIDS DU NOISE-SCORE (documentés, déterministes) ---------------------------------------------
# score = somme des contributions applicables, clampée à [0, 1]. Plus HAUT = plus probablement du bruit.
# Toute la logique de scoring vit ICI (aucune constante magique éparpillée).
NOISE_WEIGHTS: dict[str, float] = {
    # base par sévérité (le bruit est massivement INFO/LOW ; MEDIUM+ est tiré vers 0 puis plafonné)
    "sev_info": 0.45,
    "sev_low": 0.25,
    "sev_medium": -0.40,
    "sev_high": -0.80,
    "sev_critical": -1.00,
    # statut/gabarit dégradé : « non testé / config manquante / non exécuté / aucun hit / skipped »
    "degraded": 0.25,
    # preuve absente ou non actionnable (« aucun résultat », « dégradation gracieuse », vide)
    "no_evidence": 0.15,
    # appartenance à un cluster-bruit (gabarit répété à haute cardinalité)
    "in_noise_cluster": 0.20,
    # duplicat (exact ou quasi-dup shingle) d'un représentant déjà compté
    "duplicate": 0.20,
    # bonus d'UNICITÉ : finding singleton porteur d'une vraie preuve -> tiré vers le bas
    "unique_signal": -0.15,
}

# Plafond du noise-score pour un finding MEDIUM+ : un actionnable ne peut jamais « ressembler à du
# bruit » au point d'être filtré. Il reste sous ce plafond quelles que soient les autres contributions.
_ACTIONABLE_SCORE_CAP = 0.34

# Statuts « prouvés » : un finding confirmé/soumis/accepté n'est jamais du bruit (score forcé bas).
_PROVEN_STATUSES = frozenset({"vulnerable", "submitted", "accepted"})

# Marqueurs textuels de dégradation / non-preuve (normalisés minuscule). Repérés dans titre+preuve.
_DEGRADED_MARKERS = (
    "config manquante", "non testé", "non teste", "non exécuté", "non execute",
    "aucun hit", "aucun résultat", "aucun resultat", "dégradation", "degradation",
    "indisponible", "skipped", "rate-limited", "timeout",
)
_NO_EVIDENCE_MARKERS = (
    "aucun résultat", "aucun resultat", "aucun hit", "config manquante",
    "dégradation gracieuse", "degradation gracieuse", "outil exécuté (in-scope), aucun",
)

# --- normalisation (collapse des parties VARIABLES pour révéler le GABARIT) ------------------------
_URL_RX = re.compile(r"https?://\S+")
_HOSTPORT_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")           # IPv4[:port]
_HEX_RX = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)                     # hash/uuid/hex long
_NUM_RX = re.compile(r"\b\d+\b")
_WS_RX = re.compile(r"\s+")
_TOKEN_RX = re.compile(r"[a-z0-9]+")


def normalize_title(text: str) -> str:
    """Réduit un titre à son GABARIT : URLs/IP[:port]/hex/nombres remplacés par des jetons stables, casse
    et espaces normalisés. `Endpoint in-scope : http://a/x?id=3` et `... http://b/y?id=9` -> MÊME gabarit.
    Pur, ne lève jamais."""
    s = (text or "").lower()
    s = _URL_RX.sub("<url>", s)
    s = _HOSTPORT_RX.sub("<host>", s)
    s = _HEX_RX.sub("<hex>", s)
    s = _NUM_RX.sub("<n>", s)
    return _WS_RX.sub(" ", s).strip()


def normalize_target(target: str) -> str:
    """Endpoint canonique pour la dédup : scheme retiré, query/fragment (params) STRIPPÉS, host[:port]+path
    minuscule. `https://h/a?b=1#f` -> `h/a`. Pur, ne lève jamais."""
    s = (target or "").strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("?", 1)[0].split("#", 1)[0]
    if "@" in s.split("/", 1)[0]:                       # userinfo dans l'authority
        head, _, rest = s.partition("/")
        s = head.rsplit("@", 1)[1] + ("/" + rest if _ else "")
    return s.rstrip("/")


def _technique_key(f: Any) -> str:
    """Clé de TECHNIQUE d'un finding : CWE dédié, sinon category, sinon tool. Normalisée minuscule."""
    for attr in ("cwe", "category", "tool"):
        v = (getattr(f, attr, "") or "").strip()
        if v:
            return v.lower()
    return ""


def template_key(f: Any) -> tuple[str, str, str]:
    """Signature de GABARIT (clé de cluster-bruit) : (sévérité, technique, titre normalisé). Deux findings
    du même gabarit répété (gau, config-manquante, missing-header par service) partagent cette clé."""
    return ((getattr(f, "severity", "") or "").upper(), _technique_key(f),
            normalize_title(getattr(f, "title", "")))


def dedup_key(f: Any) -> tuple[str, str, str, str]:
    """Clé de DÉDUP EXACTE : (sévérité, technique, endpoint param-strippé, titre normalisé). Deux findings
    à clé identique sont des répétitions pures (même technique, même endpoint, même gabarit)."""
    sev, tech, ntitle = template_key(f)
    return (sev, tech, normalize_target(getattr(f, "target", "")), ntitle)


def _shingles(text: str, k: int) -> frozenset[str]:
    """Ensemble de k-shingles de jetons (mots alphanumériques) — pour la similarité Jaccard. `k<=1` ou
    trop peu de jetons -> l'ensemble des jetons unitaires (dégradation propre, jamais vide si texte)."""
    toks = _TOKEN_RX.findall((text or "").lower())
    if not toks:
        return frozenset()
    if k <= 1 or len(toks) < k:
        return frozenset(toks)
    return frozenset(" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1))


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if inter == 0:
        return 0.0
    return inter / len(a | b)


# --- configuration (miroir de allow_private : lu depuis scope.json, défaut SÛR) --------------------
@dataclass
class TriageConfig:
    enabled: bool = True            # triage on/off (défaut ON : annote + classe)
    auto_hide: bool = False         # DÉFAUT SÛR : rien n'est masqué, `likely_noise` reste un drapeau
    cluster_min_size: int = 5       # gabarit répété >= n -> cluster-bruit NOMMÉ
    noise_threshold: float = 0.60   # noise_score >= seuil (et sévérité < MEDIUM) -> likely_noise
    dup_jaccard: float = 0.80       # Jaccard shingle >= seuil (dans un cluster) -> quasi-dup
    shingle_k: int = 3              # taille des k-shingles de jetons

    @classmethod
    def from_dict(cls, data: Any) -> "TriageConfig":
        """Construit depuis `scope.triage` (dict) ou une valeur folle. FAIL-OPEN, TOLÉRANT : toute clé
        absente/illisible retombe sur le défaut sûr. `data` non-dict/None -> défauts. Ne lève jamais."""
        if not isinstance(data, dict):
            return cls()
        d = cls()

        def _b(key: str, default: bool) -> bool:
            v = data.get(key, default)
            return bool(v) if isinstance(v, (bool, int)) else default

        def _i(key: str, default: int, lo: int, hi: int) -> int:
            try:
                return max(lo, min(hi, int(data.get(key, default))))
            except (TypeError, ValueError):
                return default

        def _f(key: str, default: float, lo: float, hi: float) -> float:
            try:
                return max(lo, min(hi, float(data.get(key, default))))
            except (TypeError, ValueError):
                return default

        d.enabled = _b("enabled", d.enabled)
        d.auto_hide = _b("auto_hide", d.auto_hide)
        d.cluster_min_size = _i("cluster_min_size", d.cluster_min_size, 2, 10_000)
        d.noise_threshold = _f("noise_threshold", d.noise_threshold, 0.0, 1.0)
        d.dup_jaccard = _f("dup_jaccard", d.dup_jaccard, 0.0, 1.0)
        d.shingle_k = _i("shingle_k", d.shingle_k, 1, 12)
        return d

    def to_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "auto_hide": self.auto_hide,
                "cluster_min_size": self.cluster_min_size, "noise_threshold": self.noise_threshold,
                "dup_jaccard": self.dup_jaccard, "shingle_k": self.shingle_k}


@dataclass
class TriageResult:
    """Résultat du triage — une VUE parallèle, les Finding d'origine ne sont pas mutés.

    `annotations` : list de dicts alignée sur l'ORDRE d'ENTRÉE (annotations[i] <-> findings[i]).
    `by_id`       : {id(finding): annotation} — lookup O(1) pour le rendu (Finding non hashable).
    `ranked`      : list[Finding] = TOUS les findings, classés actionnable-d'abord (VUE ; jamais tronquée).
    `summary`     : dict agrégé (transparence : N -> M actionnables, K bruit/dup, top clusters).
    `config`      : la config effective utilisée.
    """
    annotations: list[dict[str, Any]] = field(default_factory=list)
    by_id: dict[int, dict[str, Any]] = field(default_factory=dict)
    ranked: list[Any] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    config: TriageConfig = field(default_factory=TriageConfig)

    def annotation_for(self, f: Any) -> dict[str, Any]:
        """Annotation d'un finding (par identité). {} si absent (triage désactivé / finding inconnu)."""
        return self.by_id.get(id(f), {})


def _degraded(text: str) -> bool:
    return any(m in text for m in _DEGRADED_MARKERS)


def _no_evidence(evidence: str, blob: str) -> bool:
    e = (evidence or "").strip()
    if not e:
        return True
    return any(m in blob for m in _NO_EVIDENCE_MARKERS)


def _noise_score(f: Any, *, in_cluster: bool, is_dup: bool, singleton: bool,
                 degraded: bool, no_evidence: bool) -> float:
    """Somme PONDÉRÉE (voir NOISE_WEIGHTS) clampée à [0,1]. Déterministe. Un statut prouvé force 0.0 ;
    un finding MEDIUM+ est PLAFONNÉ à `_ACTIONABLE_SCORE_CAP` (jamais rangé dans le bruit)."""
    status = (getattr(f, "status", "") or "").lower()
    if status in _PROVEN_STATUSES:
        return 0.0
    rank = _sev_rank(getattr(f, "severity", ""))
    w = NOISE_WEIGHTS
    score = {0: w["sev_info"], 1: w["sev_low"], 2: w["sev_medium"],
             3: w["sev_high"], 4: w["sev_critical"]}.get(rank, w["sev_info"])
    if degraded:
        score += w["degraded"]
    if no_evidence:
        score += w["no_evidence"]
    if in_cluster:
        score += w["in_noise_cluster"]
    if is_dup:
        score += w["duplicate"]
    if singleton and not no_evidence and not degraded:
        score += w["unique_signal"]
    score = max(0.0, min(1.0, score))
    if rank >= _MEDIUM_RANK:
        score = min(score, _ACTIONABLE_SCORE_CAP)
    return round(score, 4)


def _cluster_label(f: Any) -> str:
    """Label lisible d'un cluster : le titre normalisé (gabarit), tronqué. Sert d'en-tête de synthèse."""
    lbl = normalize_title(getattr(f, "title", "")) or "(sans titre)"
    return lbl[:80]


def triage(findings: list[Any], config: Any = None) -> TriageResult:
    """Passe de triage POST-collecte. ANNOTE + CLASSE, ne supprime jamais. `len(ranked) == len(findings)`.

    `config` : `TriageConfig`, un dict (`scope.triage`), ou None (défauts sûrs). Déterministe.

    Étapes : (1) groupe par gabarit (`template_key`) -> clusters ; (2) marque les dups exacts
    (`dedup_key`) et quasi-dups (shingle-Jaccard >= seuil, PAR cluster, contre le représentant) ;
    (3) score-bruit pondéré par finding ; (4) drapeau `likely_noise` (seuil, jamais sur MEDIUM+) ;
    (5) rang actionnable-d'abord ; (6) synthèse agrégée. Le représentant d'un cluster = plus petit
    index d'origine.
    """
    cfg = config if isinstance(config, TriageConfig) else TriageConfig.from_dict(config)
    res = TriageResult(config=cfg)
    n = len(findings)

    # --- triage DÉSACTIVÉ : pass-through transparent (annotations neutres, ordre inchangé) ---
    if not cfg.enabled or n == 0:
        for f in findings:
            ann = {"score": 0.0, "cluster_id": None, "likely_noise": False,
                   "reason": "triage désactivé" if not cfg.enabled else "", "is_duplicate": False,
                   "is_representative": True, "cluster_size": 1}
            res.annotations.append(ann)
            res.by_id[id(f)] = ann
        res.ranked = list(findings)
        res.summary = {"enabled": cfg.enabled, "total": n, "actionable": n, "noise": 0,
                       "duplicates": 0, "clusters": [], "top_findings": [], "auto_hide": cfg.auto_hide,
                       "config": cfg.to_dict()}
        return res

    # --- (1) groupement par GABARIT (ordre d'apparition -> cluster_id déterministe) ---
    groups: dict[tuple[str, str, str], list[int]] = {}
    order: list[tuple[str, str, str]] = []
    for i, f in enumerate(findings):
        key = template_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(i)

    cluster_id_of: list[int | None] = [None] * n
    cluster_size_of: list[int] = [1] * n
    representative_of: list[bool] = [True] * n
    cid_counter = 0
    cluster_meta: dict[int, dict[str, Any]] = {}   # cluster_id -> métadonnées de synthèse

    for key in order:
        idxs = groups[key]
        size = len(idxs)
        is_noise_cluster = size >= cfg.cluster_min_size
        cid = cid_counter
        cid_counter += 1
        rep_idx = idxs[0]                            # représentant = plus petit index d'origine
        for j in idxs:
            cluster_id_of[j] = cid
            cluster_size_of[j] = size
            representative_of[j] = (j == rep_idx)
        cluster_meta[cid] = {
            "cluster_id": cid, "label": _cluster_label(findings[rep_idx]), "size": size,
            "severity": (getattr(findings[rep_idx], "severity", "") or "INFO").upper(),
            "representative_title": getattr(findings[rep_idx], "title", ""),
            "example_target": getattr(findings[rep_idx], "target", ""),
            "is_noise_cluster": is_noise_cluster, "members": idxs,
        }

    # --- (2) dédup EXACTE + quasi-dup (shingle-Jaccard, PAR cluster contre le représentant) ---
    is_dup: list[bool] = [False] * n
    dup_reason: list[str] = [""] * n
    seen_exact: dict[tuple[str, str, str, str], int] = {}
    for i, f in enumerate(findings):
        dk = dedup_key(f)
        if dk in seen_exact:
            is_dup[i] = True
            dup_reason[i] = f"répétition exacte de #{seen_exact[dk]}"
        else:
            seen_exact[dk] = i

    # quasi-dup borné : dans chaque cluster, comparer les non-représentants au shingle du représentant.
    for cid, meta in cluster_meta.items():
        idxs = meta["members"]
        if len(idxs) < 2:
            continue
        rep = idxs[0]
        rep_sh = _shingles(f"{getattr(findings[rep], 'title', '')} {getattr(findings[rep], 'evidence', '')}",
                           cfg.shingle_k)
        for j in idxs[1:]:
            if is_dup[j]:
                continue
            sh = _shingles(f"{getattr(findings[j], 'title', '')} {getattr(findings[j], 'evidence', '')}",
                           cfg.shingle_k)
            if _jaccard(rep_sh, sh) >= cfg.dup_jaccard:
                is_dup[j] = True
                dup_reason[j] = f"quasi-dup (Jaccard >= {cfg.dup_jaccard:g}) de #{rep}"

    # --- (3)+(4) score-bruit + drapeau likely_noise + raison ---
    for i, f in enumerate(findings):
        blob = f"{getattr(f, 'title', '')} {getattr(f, 'evidence', '')}".lower()
        degraded = _degraded(blob)
        no_ev = _no_evidence(getattr(f, "evidence", ""), blob)
        cid = cluster_id_of[i]
        in_noise_cluster = bool(cid is not None and cluster_meta[cid]["is_noise_cluster"])
        singleton = cluster_size_of[i] == 1
        score = _noise_score(f, in_cluster=in_noise_cluster, is_dup=is_dup[i], singleton=singleton,
                             degraded=degraded, no_evidence=no_ev)
        rank = _sev_rank(getattr(f, "severity", ""))
        # likely_noise : jamais sur MEDIUM+ (plancher de sécurité). Sinon seuil de score OU dup pur.
        likely_noise = (rank < _MEDIUM_RANK) and (score >= cfg.noise_threshold or is_dup[i])
        reasons = []
        if is_dup[i]:
            reasons.append(dup_reason[i])
        if in_noise_cluster:
            reasons.append(f"cluster-bruit «{cluster_meta[cid]['label']}» ({cluster_size_of[i]} membres)")
        if degraded:
            reasons.append("statut/gabarit dégradé (non testé / config manquante / aucun hit)")
        if no_ev:
            reasons.append("pas de preuve actionnable")
        if rank >= _MEDIUM_RANK:
            reasons.append(f"sévérité {getattr(f, 'severity', '')} — actionnable (jamais bruit)")
        if not reasons:
            reasons.append("finding unique porteur de signal" if singleton else "membre de cluster")
        ann = {
            "score": score,
            "cluster_id": cid,
            "likely_noise": likely_noise,
            "reason": " ; ".join(r for r in reasons if r),
            "is_duplicate": is_dup[i],
            "is_representative": representative_of[i],
            "cluster_size": cluster_size_of[i],
        }
        res.annotations.append(ann)
        res.by_id[id(f)] = ann

    # --- (5) RANG actionnable-d'abord (VUE ; contient TOUS les findings) ---
    #   sévérité desc -> non-bruit d'abord -> score-bruit asc -> non-dup d'abord -> cluster petit d'abord
    #   -> index d'origine (tie-break STABLE => déterminisme).
    idx_sorted = sorted(range(n), key=lambda i: (
        -_sev_rank(getattr(findings[i], "severity", "")),
        res.annotations[i]["likely_noise"],
        res.annotations[i]["score"],
        res.annotations[i]["is_duplicate"],
        res.annotations[i]["cluster_size"],
        i,
    ))
    res.ranked = [findings[i] for i in idx_sorted]

    # --- (6) SYNTHÈSE (transparence) ---
    noise_count = sum(1 for a in res.annotations if a["likely_noise"])
    dup_count = sum(1 for a in res.annotations if a["is_duplicate"])
    actionable = n - noise_count
    # clusters de synthèse : ceux marqués bruit (haute cardinalité), triés par taille desc puis id.
    clusters = [
        {"cluster_id": m["cluster_id"], "label": m["label"], "size": m["size"],
         "severity": m["severity"], "representative_title": m["representative_title"],
         "example_target": m["example_target"]}
        for m in cluster_meta.values() if m["is_noise_cluster"]
    ]
    clusters.sort(key=lambda c: (-c["size"], c["cluster_id"]))
    # CAPS de SYNTHÈSE résolus par profil — bornent la TAILLE du digest (top-findings + clusters), PAS
    # le classement : `res.ranked` / `res.annotations` gardent TOUS les findings (coverage-safe, never-drop
    # INCHANGÉ — la synthèse n'est qu'un résumé). `balanced` == 10 / 20 == défauts -> byte-identique ;
    # `low` allège (5 / 10) le prompt LLM et le rapport. Aucun override existant ici (défaut-code seul).
    max_items = resource_profile.resolve("triage_max_items", default=10)
    max_clusters = resource_profile.resolve("triage_max_clusters", default=20)
    # top findings actionnables (pour la synthèse) : les 1ers du rang qui ne sont pas du bruit.
    top = []
    for f in res.ranked:
        a = res.by_id[id(f)]
        if a["likely_noise"]:
            continue
        top.append({"severity": (getattr(f, "severity", "") or "INFO").upper(),
                    "title": getattr(f, "title", ""), "target": getattr(f, "target", ""),
                    "score": a["score"]})
        if len(top) >= max_items:
            break
    res.summary = {
        "enabled": True, "total": n, "actionable": actionable, "noise": noise_count,
        "duplicates": dup_count, "num_clusters": len(clusters), "clusters": clusters[:max_clusters],
        "top_findings": top, "auto_hide": cfg.auto_hide, "config": cfg.to_dict(),
    }
    return res

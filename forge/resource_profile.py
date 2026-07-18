"""Profil de ressources unifié — `FORGE_RESOURCE_PROFILE=low|balanced|full`.

UN SEUL bouton fixe des DÉFAUTS sains sur TOUS les leviers de ressources à la fois, pour qu'un
opérateur tourne Forge sur une machine cliente FAIBLE (`low`) ou costaude (`full`) sans régler
chaque variable une par une. Le profil ne FORCE rien : il ne fait que fournir un DÉFAUT plus
adapté que le défaut-code. La PRÉCÉDENCE est STRICTE et NON négociable :

    override explicite (env var / setting / module_param)  >  valeur de profil  >  défaut-code

Un opérateur qui choisit `low` peut donc toujours remonter UN levier ponctuellement (ex.
`FORGE_PARALLELISM=8`) : son override GAGNE sur le profil. `balanced` (le DÉFAUT quand la variable
est absente) reproduit EXACTEMENT les défauts-code actuels — un `FORGE_RESOURCE_PROFILE` non défini
est donc un NO-OP (aucun changement de comportement, byte-identique).

Ce module est la SOURCE DE VÉRITÉ des leviers de ressources côté PYTHON (moteur + modules). Le
watchdog Rust (`FORGE_RUN_TIMEOUT`) et le tools-profile Docker (`FORGE_TOOLS_PROFILE`) restent lus
par leurs couches respectives (env/build-arg) ; la table les EXPOSE ici pour DÉRIVER/DOCUMENTER les
valeurs recommandées (auditable, une seule table), pas pour les imposer.

Gouvernance INTOUCHÉE : ce module ne règle QUE des DÉFAUTS de ressources. Il ne touche NI le scope,
NI le ROE, NI le plancher d'exploit, NI la sûreté de couverture. stdlib uniquement (os).
"""

from __future__ import annotations

import os
from typing import Any

# Variable d'environnement (ou clé de setting) qui sélectionne le profil actif.
ENV_VAR = "FORGE_RESOURCE_PROFILE"

# Profil par DÉFAUT quand la variable est absente/vide/illisible (fail-open). `balanced` == défauts
# actuels du code -> un profil non défini ne change RIEN.
DEFAULT_PROFILE = "balanced"


# ---------------------------------------------------------------------------------------------------
# TABLE DES PROFILS — chaque profil -> valeur de chaque levier de ressource.
#
# Poids/valeurs (le STRUCTURE prime ; les nombres sont des défauts raisonnables) :
#   parallelism         pool d'exécution intra-vague (threads de TIR bornés). low=SÉRIEL (1) => chemin
#                       historique byte-identique ; balanced=4 == `engine._DEFAULT_PARALLELISM` ; full=12.
#   action_timeout_secs borne DURE par-action d'un outil (runner.tool). low=60 (coupe vite sur machine
#                       lente/lien mince) ; balanced=120 == défaut `runner.tool` ; full=300.
#   run_timeout_secs    valeur du WATCHDOG (le reaper Rust lit FORGE_RUN_TIMEOUT ; exposé ici pour
#                       DÉRIVER/DOCUMENTER l'env). low=1800, balanced=3600, full=7200. NB : le défaut
#                       Rust reste 1800 via env — cette table ne fait que RECOMMANDER.
#   tools_profile       image d'outils Docker ("mini"=paquet léger / "full"=complet ; documente
#                       FORGE_TOOLS_PROFILE, build-arg). low=mini, balanced/full=full.
#   nuclei_severity     filtre de sévérité par DÉFAUT des templates nuclei. low="medium,high,critical"
#                       (moins de templates => plus léger) ; balanced == `web.Nuclei._DEFAULT_SEV`
#                       (info..critical) ; full = idem (le profil full active EN PLUS des templates via
#                       le param `templates`, hors table — la valeur reste une CSV de sévérités valide).
#   crawl_max_endpoints nb MAX d'endpoints retenus par un module de surface (recon_surface.MAX_ENDPOINTS).
#                       low=10, balanced=25 == défaut, full=50.
#   crawl_max_params    nb MAX de paramètres sondés par endpoint (brain.MAX_PARAMS_PER_ENDPOINT).
#                       low=2, balanced=3 == défaut, full=5.
#   crawl_max_depth     profondeur de traversal `../` (CÂBLÉ R2 : injection.PathTraversal.MAX_DEPTH). low=2,
#                       balanced=8 == défaut-code injection.MAX_DEPTH, full=12 (== plafond du clamp module).
#   content_fanout_max  cap du fan-out cibles×scanners chaînés (brain.MAX_CHAIN_TARGETS : services
#                       découverts × panel de scanners). low=8, balanced=32 == défaut, full=64.
#   discovery_max_fanout cap du fan-out d'un scan de ports (_discovery : services web découverts &
#                       ports sondés en HTTP). low=8, balanced=25 == défauts _MAX_DISCOVERED_SERVICES /
#                       _MAX_PROBED_PORTS, full=50. (Le cap d'ENDPOINTS crawlés passe par crawl_max_endpoints.)
#   llm_max_tokens      borne de génération LLM (llm.LLMConfig.max_tokens ; défaut de scope.llm quand absent).
#                       low=256 (plus léger), balanced=512 == défaut-code, full=2048.
#   llm_num_ctx         fenêtre de contexte LLM (option Ollama, loopback). low=2048 (borne le contexte =>
#                       moins de RAM), balanced=0 == AUCUNE option envoyée (défaut Ollama/modèle inchangé,
#                       payload byte-identique), full=8192. 0 = sentinelle « ne pas envoyer » (no-op).
#   llm_enrich_max_endpoints  nb MAX d'endpoints/params d'injection ENRICHIS par le LLM par vague (R6 :
#                       suggestions de payloads SUPPLÉMENTAIRES, testés/confirmés par l'oracle DÉTERMINISTE).
#                       Borne le nb d'appels LLM (donc l'egress) par vague. low=0 == OFF (aucun appel, aucun
#                       egress) ; balanced=3 (petit) ; full=10. NB : l'enrichissement est de toute façon INERTE
#                       tant que `scope.llm.enabled` est faux (défaut) — ce levier ne fait que le BORNER une
#                       fois le LLM activé (aucun impact quand le LLM est OFF).
#   triage_max_items    cap des top-findings SURFACÉS dans la synthèse de triage (triage.summary.top_findings ;
#                       coverage-safe : res.ranked/annotations gardent TOUT). low=5, balanced=10 == défaut, full=20.
#   triage_max_clusters cap des clusters-bruit surfacés dans la synthèse (triage.summary.clusters ;
#                       jamais un finding supprimé). low=10, balanced=20 == défaut, full=40.
#   rate_per_sec        débit requêtes/s (aligné sur le levier ROE `rate`, défaut 5). low=2 (conservateur),
#                       balanced=5 == défaut ROE, full=20. DOCUMENTATION SEULEMENT (non câblé : le débit reste
#                       porté par le scope/ROE — GOUVERNANCE ; le régler ici ne touche PAS la gouvernance).
#   max_concurrent_procs garde-fou MÉMOIRE : nb max de sous-process outils simultanés tolérés. low=2,
#                       balanced=6, full=16. RÉSOLVABLE (helper `max_concurrent_procs()`) — l'ENFORCEMENT
#                       effectif du plafond arrive en R4 (R2 garantit juste qu'il n'est pas codé en dur).
# ---------------------------------------------------------------------------------------------------
PROFILES: dict[str, dict[str, Any]] = {
    "low": {
        "parallelism": 1,
        "action_timeout_secs": 60,
        "run_timeout_secs": 1800,
        "tools_profile": "mini",
        "nuclei_severity": "medium,high,critical",
        "crawl_max_endpoints": 10,
        "crawl_max_params": 2,
        "crawl_max_depth": 2,
        "content_fanout_max": 8,
        "discovery_max_fanout": 8,
        "llm_max_tokens": 256,
        "llm_num_ctx": 2048,
        "llm_enrich_max_endpoints": 0,
        "triage_max_items": 5,
        "triage_max_clusters": 10,
        "rate_per_sec": 2,
        "max_concurrent_procs": 2,
    },
    "balanced": {  # == défauts-code actuels -> profil non défini == NO-OP (byte-identique).
        "parallelism": 4,
        "action_timeout_secs": 120,
        "run_timeout_secs": 3600,
        "tools_profile": "full",
        "nuclei_severity": "info,low,medium,high,critical",
        "crawl_max_endpoints": 25,
        "crawl_max_params": 3,
        "crawl_max_depth": 8,
        "content_fanout_max": 32,
        "discovery_max_fanout": 25,
        "llm_max_tokens": 512,
        "llm_num_ctx": 0,
        "llm_enrich_max_endpoints": 3,
        "triage_max_items": 10,
        "triage_max_clusters": 20,
        "rate_per_sec": 5,
        "max_concurrent_procs": 6,
    },
    "full": {
        "parallelism": 12,
        "action_timeout_secs": 300,
        "run_timeout_secs": 7200,
        "tools_profile": "full",
        "nuclei_severity": "info,low,medium,high,critical",
        "crawl_max_endpoints": 50,
        "crawl_max_params": 5,
        "crawl_max_depth": 12,
        "content_fanout_max": 64,
        "discovery_max_fanout": 50,
        "llm_max_tokens": 2048,
        "llm_num_ctx": 8192,
        "llm_enrich_max_endpoints": 10,
        "triage_max_items": 20,
        "triage_max_clusters": 40,
        "rate_per_sec": 20,
        "max_concurrent_procs": 16,
    },
}

# Leviers ENTIERS : `resolve()` coerce vers int (les autres restent des chaînes).
_INT_KNOBS = frozenset({
    "parallelism", "action_timeout_secs", "run_timeout_secs", "crawl_max_endpoints",
    "crawl_max_params", "crawl_max_depth", "content_fanout_max", "discovery_max_fanout",
    "llm_max_tokens", "llm_num_ctx", "llm_enrich_max_endpoints", "triage_max_items",
    "triage_max_clusters", "rate_per_sec", "max_concurrent_procs",
})

# Variables d'environnement PRÉEXISTANTES qui priment sur le profil (rétro-compat). Pour l'audit
# (snapshot du run), on lit ces overrides afin de refléter les valeurs RÉELLEMENT en vigueur.
_ENV_OVERRIDES = {
    "parallelism": "FORGE_PARALLELISM",
    "run_timeout_secs": "FORGE_RUN_TIMEOUT",
    "tools_profile": "FORGE_TOOLS_PROFILE",
    # R4 : plafond de sous-process outils ENFORCÉ par `runner._PROC_GATE`. Exposé ici pour que le
    # snapshot d'audit reflète le plafond RÉELLEMENT en vigueur quand l'opérateur pose l'override.
    # Non défini (défaut) -> None -> résout la valeur de profil : snapshot BYTE-IDENTIQUE à avant R4.
    "max_concurrent_procs": "FORGE_MAX_CONCURRENT_PROCS",
}


def _normalize(name: Any) -> str:
    """Valide un nom de profil -> profil connu, sinon le DÉFAUT (fail-open sur garbage/None/vide)."""
    if name is None:
        return DEFAULT_PROFILE
    key = str(name).strip().lower()
    return key if key in PROFILES else DEFAULT_PROFILE


def active_profile(setting: Any = None) -> str:
    """Profil ACTIF : lit `setting` si fourni, sinon la variable d'env `FORGE_RESOURCE_PROFILE`.
    Valide contre la table ; absent/vide/illisible -> `balanced` (fail-open). Ne lève JAMAIS."""
    raw = setting if setting is not None else os.environ.get(ENV_VAR)
    return _normalize(raw)


def _coerce(knob: str, value: Any) -> Any:
    """Coercition de type par levier. Leviers entiers -> int (garbage -> None, pour fail-through vers
    le candidat suivant de la précédence). Autres leviers -> valeur telle quelle. None reste None."""
    if value is None:
        return None
    if knob in _INT_KNOBS:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return value


def resolve(knob: str, *, override: Any = None, profile: Any = None, default: Any = None) -> Any:
    """Résolveur de PRÉCÉDENCE — LE point d'appel unique du moteur/modules pour chaque levier.

        override (env/setting/module_param)  >  valeur de profil  >  default (défaut-code)

    Retourne le PREMIER candidat non-None (après coercition de type). Un override GARBAGE sur un
    levier entier (non coercible) est ignoré et l'on retombe sur le profil puis le défaut (fail-open).
    `profile` : nom de profil explicite (sinon `active_profile()` lit l'env). `default` : le
    défaut-code que l'appelant passe TOUJOURS pour garantir un fallback même hors table."""
    prof = active_profile() if profile is None else _normalize(profile)
    prof_val = PROFILES.get(prof, {}).get(knob)
    for candidate in (override, prof_val, default):
        coerced = _coerce(knob, candidate)
        if coerced is not None:
            return coerced
    return None


def max_concurrent_procs(*, override: Any = None, profile: Any = None) -> int:
    """Plafond RÉSOLU de sous-process outils simultanés (garde-fou MÉMOIRE) — override > profil > défaut.
    R2 EXPOSE ce levier résolvable (helper unique) pour que R4 l'ENFORCE (sémaphore côté runner) sans
    valeur codée en dur. `override` : futur env/param opérateur ; `default` = valeur `balanced` (6).
    Ne règle QU'une ressource — ne touche NI scope NI ROE. Retourne toujours un int >= 1."""
    v = resolve("max_concurrent_procs", override=override, profile=profile,
                default=PROFILES[DEFAULT_PROFILE]["max_concurrent_procs"])
    try:
        return max(1, int(v))
    except (TypeError, ValueError):
        return PROFILES[DEFAULT_PROFILE]["max_concurrent_procs"]


def active_snapshot() -> dict[str, Any]:
    """Instantané AUDITABLE du run : le profil actif + la valeur EFFECTIVE de chaque levier (overrides
    d'env préexistants pris en compte). Émis au ledger (`engine.resource_profile`) et/ou en en-tête de
    rapport pour tracer quelles ressources un run a réellement consommées. Déterministe (pas d'horodatage)."""
    prof = active_profile()
    knobs: dict[str, Any] = {}
    table = PROFILES[prof]
    for knob in table:
        env_name = _ENV_OVERRIDES.get(knob)
        ov = os.environ.get(env_name) if env_name else None
        knobs[knob] = resolve(knob, override=ov, profile=prof, default=table[knob])
    return {"profile": prof, "knobs": knobs}

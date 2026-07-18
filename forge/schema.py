"""Modèle de données rouge de Forge (stdlib only).

Aligné sur la `Finding` de secpipe (réutilisation), + champs orientés engagement :
`status` (machine d'état), `mitre` (clé de jointure de la boucle purple avec Plume),
`target_id`. Target et Campaign donnent la cohérence multi-cible / multi-étape.

ENRICHISSEMENT (LOT SCHEMA/FIX) — remédiation + taxonomie exploitables côté client :
  - `fix` : remédiation par défaut auto-déduite (catégorie/technique -> conseil), JAMAIS au détriment
    d'un `fix` explicite passé par le module (le fix spécifique d'un module PRIME).
  - `cwe` : champ dédié, séparé de `category` (qui restait un fourre-tout CWE/CIS). Rétro-compat :
    si le module n'a passé que `category="CWE-639"`, on en dérive `cwe` automatiquement — `category`
    n'est jamais effacé.
  - `cvss_vector`/`cvss_score` : vecteur/score de BASE par classe d'oracle, dérivé de la sévérité quand
    le module n'en fournit pas (repère grossier de priorisation, pas un calcul CVSS complet).
Tous ces enrichissements sont ADDITIFS et FAIL-OPEN : aucun n'écrase une valeur fournie par le module,
et l'absence de mapping laisse simplement le champ vide (zéro régression de comportement).
"""
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from . import techniques
from .redact import redact_secrets as _redact_secrets

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# machine d'état d'un finding (reprend la logique FAISS du toolkit YWH).
# `reported_by_tool` : un outil tiers (ex: nuclei) a signalé un hit sur sa propre sévérité
# auto-déclarée — ce n'est PAS une vuln confirmée par Forge. On garde la sévérité de l'outil
# pour la priorisation, mais ce statut empêche le sur-classement en `vulnerable` (pas de preuve
# différentielle/manuelle). La promotion en `vulnerable` reste réservée aux oracles de Forge (IDOR,
# origine vérifiée) qui apportent une preuve d'exploitabilité.
# `skipped` : le module n'a PAS pu s'exécuter (source/outil optionnel ou réseau indisponible) et
# se neutralise proprement en émettant un finding INFO explicite plutôt qu'en plantant — discipline
# de dégradation gracieuse (offline-safe) des modules de cartographie de surface passifs.
STATUSES = ["tested", "reported_by_tool", "vulnerable", "not_vulnerable", "submitted", "accepted", "informative", "invalid", "skipped"]

# ---------------------------------------------------------------------------
# Remédiation par défaut — mapping clé (catégorie/CWE/technique normalisée) -> conseil de fix.
# Sert de REPLI : si un module émet un finding sans `fix`, on en déduit une remédiation générique à
# partir de sa `category`/`cwe`. Un `fix` explicite du module PRIME toujours (jamais écrasé).
# Les clés sont normalisées (minuscule, sans espaces autour) ; on tente plusieurs formes (CWE brut,
# label de catégorie type 'origin-exposure', etc.) pour maximiser la couverture sans casser la compat.
#
# SOURCE DE VÉRITÉ : forge/techniques.py. Ce dict est DÉRIVÉ de la table unique (toute clé y portant
# une `remediation`) — plus de recopie/dérive entre schema, planner, brain et les modules.
# ---------------------------------------------------------------------------
DEFAULT_FIXES = techniques.remediation_map()

# ---------------------------------------------------------------------------
# CVSS de base par sévérité — repère grossier de priorisation (PAS un calcul CVSS complet par finding).
# Vecteur CVSS 3.1 « plausible » pour une classe d'impact donnée + score représentatif de la bande.
# Dérivé UNIQUEMENT quand le module ne fournit pas son propre vecteur/score (fail-open, additif).
# ---------------------------------------------------------------------------
CVSS_BASE_BY_SEVERITY = {
    "CRITICAL": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "HIGH":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "MEDIUM":   ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "LOW":      ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "INFO":     ("", 0.0),
}

# Repère un identifiant CWE dans une chaîne (ex: "CWE-639", "cwe_639", "CWE 639").
_CWE_RX = re.compile(r"(?i)\bcwe[\s_-]?(\d+)\b")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def extract_cwe(text):
    """Extrait un identifiant CWE canonique ('CWE-639') d'une chaîne, ou '' si absent. Pur."""
    if not text:
        return ""
    m = _CWE_RX.search(text)
    return f"CWE-{m.group(1)}" if m else ""


def default_fix_for(cwe="", category="", mitre=""):
    """Conseil de remédiation par défaut pour une (cwe/category/mitre). '' si aucun mapping.

    Stratégie de recherche, du plus spécifique au plus large (toutes clés normalisées minuscule) :
      1. le CWE dédié (ex 'cwe-639') ;
      2. un CWE éventuellement niché dans `category` ;
      3. la `category` brute normalisée (ex 'origin-exposure', 'idor', 'cors') ;
      4. chaque token de la `category` (gère 'access_control.idor' -> 'access_control' / 'idor').
    Pur, sans effet de bord. Ne lève jamais.
    """
    cat = (category or "").strip().lower()
    candidates = []
    if cwe:
        candidates.append(cwe.strip().lower())
    nested = extract_cwe(category).lower()
    if nested:
        candidates.append(nested)
    if cat:
        candidates.append(cat)
        # tokens : 'access_control.idor' -> ['access_control', 'idor'] ; 'cors.credentials' -> ...
        for tok in re.split(r"[.\s/_-]+", cat):
            tok = tok.strip()
            if tok and tok not in candidates:
                candidates.append(tok)
    for key in candidates:
        if key in DEFAULT_FIXES:
            return DEFAULT_FIXES[key]
    return ""


def cvss_base_for(severity):
    """(vecteur, score) CVSS de base pour une sévérité. ('', 0.0) si inconnue. Pur."""
    return CVSS_BASE_BY_SEVERITY.get((severity or "").upper(), ("", 0.0))


@dataclass
class Finding:
    target: str
    title: str
    severity: str = "INFO"
    category: str = ""          # CWE / CIS (checklist) — fourre-tout historique, conservé (rétro-compat)
    cwe: str = ""               # CWE dédié (ex 'CWE-639') — séparé de category ; auto-dérivé si vide
    mitre: str = ""             # ATT&CK technique id (T1190...) — jointure boucle purple avec Plume
    status: str = "tested"
    evidence: str = ""
    fix: str = ""               # remédiation — auto-déduite si vide (le fix explicite du module PRIME)
    cvss_vector: str = ""       # vecteur CVSS 3.1 de base (dérivé de la sévérité si vide)
    cvss_score: float = 0.0     # score CVSS de base représentatif (dérivé de la sévérité si vide)
    tool: str = ""
    poc: str = ""               # commande/PoC reproductible
    ts: str = field(default_factory=_now)

    def __post_init__(self):
        # 0) STATUT — validation SCHEMA-ENFORCED (la discipline de preuve n'est plus une simple
        #    convention). Un statut inconnu (typo/plugin hostile/valeur forgée) est ramené fail-closed à
        #    'tested' : jamais de statut arbitraire dans le ledger SIGNÉ ni le rapport. La promotion vers
        #    'vulnerable' (proof-implying) reste gardée EN AMONT par `Module.finding` (elle n'est atteignable
        #    que via le chemin de preuve sanctionné, cf. `Oracle.proof(proven=True)` / marqueur `_proven`).
        if self.status not in STATUSES:
            self.status = "tested"
        # 0bis) SÉVÉRITÉ — validation SCHEMA-ENFORCED fail-closed (miroir du clamp `status`, L16). Une
        #    sévérité hors de `SEVERITIES` (typo, plugin hostile, valeur forgée) fausserait la synthèse
        #    (`sev_rank` -> 0, absente du tri/CVSS) : on la NORMALISE (strip + upper) puis on la RABAT sur
        #    'INFO' si elle reste inconnue. Jamais de crash, jamais de valeur arbitraire propagée dans le
        #    ledger signé ni le rapport. Fait AVANT la dérivation CVSS (§3) qui consomme `self.severity`.
        _sev = str(self.severity or "").strip().upper()
        self.severity = _sev if _sev in SEVERITIES else "INFO"
        # 1) CWE dédié : si non fourni, le dériver de `category` (rétro-compat avec les modules qui
        #    n'utilisaient que `category="CWE-639"`). `category` n'est jamais modifié.
        if not self.cwe:
            self.cwe = extract_cwe(self.category)
        # 2) Remédiation : ne JAMAIS écraser un `fix` explicite (le fix spécifique du module prime).
        #    Sinon, replier sur le mapping par défaut (cwe -> category -> tokens).
        if not self.fix:
            self.fix = default_fix_for(cwe=self.cwe, category=self.category, mitre=self.mitre)
        # 3) CVSS de base : dérivé de la sévérité UNIQUEMENT si le module n'en fournit pas
        #    (fail-open ; INFO -> vecteur vide / score 0.0).
        if not self.cvss_vector and not self.cvss_score:
            self.cvss_vector, self.cvss_score = cvss_base_for(self.severity)

    def sev_rank(self):
        return SEVERITIES.index(self.severity) if self.severity in SEVERITIES else 0

    def to_dict(self):
        # CHOKEPOINT DE RÉDACTION CENTRAL (fail-closed anti-fuite de secret) — TOUT champ texte du
        # finding passe par la surface UNIQUE `redact.redact_secrets` AVANT de quitter l'objet. C'est
        # le point de passage OBLIGÉ vers le ledger SIGNÉ (`engine`.append("finding", f.to_dict())),
        # le graphe en mémoire et l'API `/api/findings/:id` : un secret (Authorization: Bearer …,
        # Cookie: sid=…) construit dans un `poc`/`evidence` par un chemin sibling/historique
        # (IDOR read/write, PrivEsc, ATO pré-R5) est neutralisé ICI, une fois, pour toute la surface.
        # Mirroir EXACT de `report_engagement.redact_finding` (même fonction) -> parité avec le
        # rendu du rapport. Idempotent : les chemins R5 rédigent déjà à la source (défense en
        # profondeur) et une double rédaction ne masque jamais moins. Les champs non-texte
        # (cvss_score, ts) sont conservés tels quels.
        return {k: (_redact_secrets(v) if isinstance(v, str) else v) for k, v in asdict(self).items()}


@dataclass
class Target:
    host: str
    kind: str = "host"          # host | service | url | app
    attrs: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class Campaign:
    name: str
    scope_path: str = ""
    started: str = field(default_factory=_now)
    notes: str = ""

    def to_dict(self):
        return asdict(self)

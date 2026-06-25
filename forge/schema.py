"""Modèle de données rouge de Forge (stdlib only).

Aligné sur la `Finding` de secpipe (réutilisation), + champs orientés engagement :
`status` (machine d'état), `mitre` (clé de jointure de la boucle purple avec Plume),
`target_id`. Target et Campaign donnent la cohérence multi-cible / multi-étape.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# machine d'état d'un finding (reprend la logique FAISS du toolkit YWH).
# `reported_by_tool` : un outil tiers (ex: nuclei) a signalé un hit sur sa propre sévérité
# auto-déclarée — ce n'est PAS une vuln confirmée par Forge. On garde la sévérité de l'outil
# pour la priorisation, mais ce statut empêche le sur-classement en `vulnerable` (pas de preuve
# différentielle/manuelle). La promotion en `vulnerable` reste réservée aux oracles de Forge (IDOR,
# origine vérifiée) qui apportent une preuve d'exploitabilité.
STATUSES = ["tested", "reported_by_tool", "vulnerable", "not_vulnerable", "submitted", "accepted", "informative", "invalid"]


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    target: str
    title: str
    severity: str = "INFO"
    category: str = ""          # CWE / CIS (checklist)
    mitre: str = ""             # ATT&CK technique id (T1190...) — jointure boucle purple avec Plume
    status: str = "tested"
    evidence: str = ""
    fix: str = ""
    tool: str = ""
    poc: str = ""               # commande/PoC reproductible
    ts: str = field(default_factory=_now)

    def sev_rank(self):
        return SEVERITIES.index(self.severity) if self.severity in SEVERITIES else 0

    def to_dict(self):
        return asdict(self)


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

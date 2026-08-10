# SPDX-License-Identifier: AGPL-3.0-or-later
"""Comptage des TROIS métriques — et la troisième est la plus importante.

  · vrais positifs — vulns connues effectivement trouvées, PAR CLASSE ;
  · faux négatifs  — vulns connues manquées, avec la RAISON (oracle absent ? amorçage ? budget ?) ;
  · FAUX POSITIFS  — le point faible démontré de forge (8 HIGH faux sur sa première cible réelle).

Un banc qui ne compterait que les trouvailles ne prouverait rien. Le scorer ne DÉCIDE pas seul
qu'un finding est un faux positif : il produit la LISTE COMPLÈTE des findings ≥ MEDIUM à vérifier à
la main contre la vérité terrain, et n'accepte un verdict que s'il est écrit dans `verdicts.json`.
Un ≥ MEDIUM non vérifié est rapporté comme NON VÉRIFIÉ, jamais comme correct.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from . import groundtruth as gt

SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
PROOF_STATUS = ("vulnerable",)              # forge n'a PROUVÉ que dans cet état
CLAIM_STATUS = ("vulnerable", "reported_by_tool")  # ce sur quoi un opérateur agirait


def module_kind(finding) -> str:
    """Kind du module émetteur, extrait de `tool` (« forge/modules/injection.py:sqli.probe »)."""
    t = str(finding.get("tool", ""))
    if ":" in t:
        return t.rsplit(":", 1)[1]
    return t


def severity_at_least(finding, level="MEDIUM") -> bool:
    return SEV_ORDER.get(str(finding.get("severity", "INFO")).upper(), 0) >= SEV_ORDER[level]


@dataclass
class ClassRow:
    vuln_class: str
    oracle: str | None
    found: bool = False
    status: str = ""
    severity: str = ""
    evidence: str = ""
    reason: str = ""          # pourquoi c'est un faux négatif (rempli à la main / heuristique)
    banned: bool = False
    unclaimed: bool = False


@dataclass
class AppScore:
    app: str
    rows: list = field(default_factory=list)
    fp_candidates: list = field(default_factory=list)
    noise: dict = field(default_factory=dict)
    total_findings: int = 0
    partial: bool = False


# Raisons de faux négatif déduites de la TRACE du finding lui-même (jamais devinées) : forge dit
# explicitement pourquoi il n'a pas jugé, et on relaie CE texte.
_REASON_RX = (
    (re.compile(r"config manquante|requiert params|Requiert ", re.I),
     "amorçage : l'oracle exige une configuration que le banc/le chaînage ne lui a pas fournie"),
    (re.compile(r"skipped|non testé", re.I),
     "l'oracle ne s'est pas exécuté (dépendance/config absente) — abstention, pas un verdict"),
    (re.compile(r"navigateur|browser|DOM", re.I),
     "limite structurelle : exige un rendu navigateur"),
)


def _reason_from(findings_for_oracle) -> str:
    for f in findings_for_oracle:
        blob = f"{f.get('title', '')} {f.get('evidence', '')}"
        for rx, why in _REASON_RX:
            if rx.search(blob):
                return why
    if findings_for_oracle:
        return ("l'oracle s'est exécuté et n'a PAS confirmé (statut « %s ») — verdict négatif, "
                "pas une abstention" % findings_for_oracle[0].get("status", "?"))
    return "l'oracle n'a jamais été proposé/tiré sur cette cible"


def score_app(app: str, findings: list, partial=False) -> AppScore:
    by_kind = defaultdict(list)
    for f in findings:
        by_kind[module_kind(f)].append(f)

    s = AppScore(app=app, total_findings=len(findings), partial=partial)

    for g in gt.for_app(app):
        row = ClassRow(vuln_class=g.vuln_class, oracle=g.oracle,
                       banned=g.banned, unclaimed=(g.oracle is None))
        if g.oracle:
            cands = by_kind.get(g.oracle, [])
            proven = [f for f in cands if f.get("status") in PROOF_STATUS]
            if proven:
                row.found = True
                row.status = proven[0].get("status", "")
                row.severity = proven[0].get("severity", "")
                row.evidence = str(proven[0].get("evidence", ""))[:220]
            else:
                row.reason = _reason_from(cands)
                if cands:
                    row.status = cands[0].get("status", "")
                    row.severity = cands[0].get("severity", "")
                    row.evidence = str(cands[0].get("evidence", ""))[:220]
        s.rows.append(row)

    # candidats faux positifs : TOUT ce sur quoi un opérateur agirait (≥ MEDIUM + statut de
    # revendication). Chacun doit être vérifié À LA MAIN contre la vérité terrain.
    s.fp_candidates = [f for f in findings
                       if severity_at_least(f, "MEDIUM") and f.get("status") in CLAIM_STATUS]

    counts = defaultdict(int)
    for f in findings:
        counts[f"{f.get('severity', '?')}/{f.get('status', '?')}"] += 1
    s.noise = dict(sorted(counts.items()))
    return s


def summary(s: AppScore) -> dict:
    scored = [r for r in s.rows if r.oracle and not r.banned]
    return {
        "app": s.app,
        "opposables": len(scored),
        "vrais_positifs": sum(1 for r in scored if r.found),
        "faux_negatifs": sum(1 for r in scored if not r.found),
        "sans_oracle": sum(1 for r in s.rows if r.unclaimed and not r.banned),
        "bannies": sum(1 for r in s.rows if r.banned),
        "findings_total": s.total_findings,
        "candidats_fp": len(s.fp_candidates),
        "partiel": s.partial,
    }


def markdown_table(s: AppScore) -> str:
    out = [f"### {s.app}", "",
           "| classe de vuln | oracle forge | trouvé | statut | sév. | pourquoi pas (si manqué) |",
           "|---|---|---|---|---|---|"]
    for r in s.rows:
        if r.banned:
            mark, why = "— (bannie)", r.reason or "classe bannie du périmètre"
        elif r.unclaimed:
            mark, why = "— (aucun oracle)", "aucun oracle du dépôt ne revendique cette classe"
        else:
            mark, why = ("**OUI**" if r.found else "NON"), ("" if r.found else r.reason)
        out.append(f"| {r.vuln_class} | {r.oracle or '—'} | {mark} | {r.status or '—'} | "
                   f"{r.severity or '—'} | {why} |")
    return "\n".join(out)

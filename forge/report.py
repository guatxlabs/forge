"""Rapport markdown + section transparence (anti-masquage) — repris de secpipe.

Le rapport prouve ce qui a été tiré, simulé, vétoé, et jamais tenté : zéro lacune
silencieuse. Section dédiée listant chaque verdict ROE.
"""
from .schema import SEVERITIES


def build_report(engine, title="Forge — rapport d'engagement"):
    out = [f"# {title}", ""]
    cov = engine.coverage()

    # --- synthèse findings ---
    by_sev = {s: 0 for s in SEVERITIES}
    for f in engine.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    out += ["## Synthèse", "", "| Sévérité | # |", "|---|---|"]
    for s in reversed(SEVERITIES):
        out.append(f"| {s} | {by_sev.get(s, 0)} |")
    out.append("")

    # --- findings détaillés ---
    out += ["## Findings", ""]
    if not engine.findings:
        out += ["_Aucun finding._", ""]
    for f in sorted(engine.findings, key=lambda x: -x.sev_rank()):
        out += [f"### [{f.severity}] {f.title} — `{f.target}`",
                f"- **Catégorie** : {f.category or '—'}  ·  **ATT&CK** : {f.mitre or '—'}  ·  **Statut** : {f.status}",
                f"- **Outil** : {f.tool or '—'}",
                f"- **Preuve** : {f.evidence or '—'}",
                f"- **PoC** : `{f.poc or '—'}`", ""]

    # --- transparence ROE (anti-masquage) ---
    out += ["## Couverture & transparence (ROE / anti-masquage)", ""]
    out.append(f"- **Tirées (FIRE)** : {len(cov['fired'])}")
    out.append(f"- **Simulées (DRY_RUN)** : {len(cov['dry_run'])}")
    out.append(f"- **Refusées (VETO — hors scope / capacité non autorisée)** : {len(cov['vetoed'])}")
    out.append(f"- **Erreurs / skips** : {len(cov['errors'])}")
    out.append(f"- **Findings dédupliqués (déjà en mémoire)** : {getattr(engine, 'dups', 0)}")
    out.append("")
    for label, key in [("Simulées (non armé/approuvé)", "dry_run"),
                       ("Refusées (VETO)", "vetoed"),
                       ("Erreurs / skips", "errors")]:
        rows = cov[key]
        if rows:
            out.append(f"**{label}**")
            for r in rows:
                out.append(f"- `{r['kind']}` → `{r['target']}` : {' ; '.join(r['reasons'])}")
            out.append("")

    # --- déférées par budget (defer != delete) ---
    deferred = getattr(engine, "skipped_budget", None) or []
    if deferred:
        out.append("**Déférées (budget)**")
        for a in deferred:
            out.append(f"- `{getattr(a, 'kind', '?')}` → `{getattr(a, 'target', '?')}` (classe `{getattr(a, 'cls', '?')}`)")
        out.append("")

    # --- classes jamais tentées (coverage gaps) ---
    gaps = getattr(engine, "coverage_gaps", None) or {}
    if gaps:
        out.append("**Classes jamais tentées**")
        for tgt, miss in gaps.items():
            out.append(f"- `{tgt}` : {', '.join(miss)}")
        out.append("")

    # --- intégrité du ledger ---
    if engine.ledger is not None:
        v = engine.ledger.verify()
        status = "OK ✅" if v["ok"] else f"CASSÉ ❌ (entrée {v['broken']}: {v.get('why','')})"
        out += ["## Ledger d'engagement", "",
                f"- Entrées : {v['entries']}  ·  Intégrité : {status}", ""]

    return "\n".join(out)

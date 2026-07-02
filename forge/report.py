"""Rapport markdown + section transparence (anti-masquage) — repris de secpipe.

Le rapport prouve ce qui a été tiré, simulé, vétoé, et jamais tenté : zéro lacune
silencieuse. Section dédiée listant chaque verdict ROE.

PARITÉ CONSOLE (LOT REPORT-PARITY) — le livrable CLI ne doit plus « perdre » silencieusement le
contenu-moat que le rapport console porte. On ajoute donc, sans casser le squelette existant :
  - un EN-TÊTE d'engagement (périmètre du scope + empreinte d'intégrité du ledger : head + clé
    publique Ed25519 quand disponible) — tout dérivé d'helpers existants, dégradé proprement si absent ;
  - une section « Techniques ATT&CK exercées » rendue depuis les run-records émis par le moteur
    (les identifiants MITRE réellement tirés) ;
  - un POINTEUR bien visible vers le rapport console `GET /api/runs/<id>/report`, qui SEUL peut
    assembler la matrice détecté/raté + MTTD (la jointure des détections Plume est côté console) et
    l'annexe chaîne-de-custody — pour que RIEN ne manque en silence.
"""
from .schema import SEVERITIES
from . import signing


def _engagement_header(engine):
    """En-tête d'engagement : périmètre autorisé (scope) + empreinte d'intégrité (ledger head +
    clé publique Ed25519 si le ledger est signé en asymétrique). Purement DÉRIVÉ des objets déjà
    portés par l'engine ; dégrade proprement (aucune ligne fabriquée) si scope/ledger sont absents."""
    lines = []
    scope = getattr(engine, "scope", None)
    if scope is not None:
        in_scope = ", ".join(str(s) for s in (getattr(scope, "in_scope", None) or [])) or "—"
        out_scope = ", ".join(str(s) for s in (getattr(scope, "out_scope", None) or [])) or "—"
        caps = []
        if getattr(scope, "allow_exploit", False):
            caps.append("exploit")
        if getattr(scope, "allow_destructive", False):
            caps.append("destructif")
        caps_str = ", ".join(caps) if caps else "aucune (lecture seule)"
        lines.append(f"- **Mode** : {getattr(scope, 'mode', '—')}  ·  "
                     f"**Capacités autorisées** : {caps_str}")
        lines.append(f"- **In-scope** : {in_scope}")
        lines.append(f"- **Out-scope** : {out_scope}")
    campaign = getattr(engine, "campaign_id", None)
    run_id = getattr(engine, "run_id", None)
    if campaign or run_id:
        lines.append(f"- **Campagne** : {campaign or '—'}  ·  **Run** : {run_id or '—'}")
    ledger = getattr(engine, "ledger", None)
    if ledger is not None:
        head = getattr(ledger, "head", "") or ""
        alg = getattr(ledger, "alg", "") or "—"
        # clé publique Ed25519 via l'helper de signing (None si repli HMAC — dégrade proprement).
        pub = signing.signer_pubkey_hex(getattr(ledger, "signer", None))
        lines.append(f"- **Ledger (empreinte)** : head `{head or '—'}`  ·  algo `{alg}`")
        if pub:
            lines.append(f"- **Clé publique (Ed25519)** : `{pub}`")
    if not lines:
        return []
    return ["## Engagement", ""] + lines + [""]


def _techniques_section(engine):
    """« Techniques ATT&CK exercées » : agrège les run-records TIRÉS par identifiant MITRE (kinds +
    cibles + nombre de tirs). Rend visible, côté CLI, CE QUI a été exercé (le rapport console, lui,
    corrèle en plus avec la détection Plume). Vide/placeholder si aucun tir taggé ATT&CK."""
    records = [r for r in (getattr(engine, "run_records", None) or [])
               if r.get("fired") and r.get("mitre")]
    out = ["## Techniques ATT&CK exercées", ""]
    if not records:
        out += ["_Aucune technique ATT&CK tirée (engagement non armé, ou aucun tir taggé MITRE)._", ""]
        return out
    agg = {}
    for r in records:
        e = agg.setdefault(r["mitre"], {"kinds": set(), "targets": set(), "n": 0})
        e["kinds"].add(str(r.get("kind", "")))
        e["targets"].add(str(r.get("target", "")))
        e["n"] += 1
    out += ["| ATT&CK | Kind(s) | Cible(s) | Tirs |", "|---|---|---|---|"]
    for mitre in sorted(agg):
        e = agg[mitre]
        kinds = ", ".join(sorted(k for k in e["kinds"] if k)) or "—"
        tgts = ", ".join(sorted(t for t in e["targets"] if t)) or "—"
        out.append(f"| {mitre} | {kinds} | {tgts} | {e['n']} |")
    out.append("")
    return out


def _console_report_pointer(engine):
    """Pointeur PROÉMINENT vers le rapport console. La matrice détecté/raté + MTTD exige la jointure
    des détections Plume, faite CÔTÉ CONSOLE ; l'annexe chaîne-de-custody y est aussi assemblée. On le
    dit explicitement pour qu'aucun contenu ne manque « en silence » dans ce livrable CLI."""
    run_id = getattr(engine, "run_id", None) or "<run-id>"
    return [
        "## Couverture de détection & chaîne de custody — rapport console",
        "",
        "> **Ce rapport CLI ne contient pas la matrice de détection complète.** La corrélation "
        "rouge-tiré ↔ bleu-détecté (**détecté / raté / MTTD**) exige la jointure des détections Plume, "
        "réalisée **côté console** (`GET {PLUME_URL}/api/coverage/detections`). L'**annexe "
        "chaîne-de-custody** (head du ledger, algorithme, clé publique, attribution) est de même "
        "assemblée par la console.",
        ">",
        f"> Rapport complet (matrice purple + MTTD + annexe custody) : "
        f"**`GET /api/runs/{run_id}/report`** — ajouter `?format=html` pour le livrable client brandé.",
        "",
    ]


def build_report(engine, title="Forge — rapport d'engagement"):
    out = [f"# {title}", ""]
    out += _engagement_header(engine)                # en-tête d'engagement (parité console)
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

    # --- techniques ATT&CK exercées (parité console : ce qui a été tiré, par MITRE) ---
    out += _techniques_section(engine)

    # --- pointeur console : matrice détecté/raté + MTTD + annexe custody (jointure Plume côté console) ---
    out += _console_report_pointer(engine)

    # --- intégrité du ledger ---
    if engine.ledger is not None:
        v = engine.ledger.verify()
        status = "OK ✅" if v["ok"] else f"CASSÉ ❌ (entrée {v['broken']}: {v.get('why','')})"
        out += ["## Ledger d'engagement", "",
                f"- Entrées : {v['entries']}  ·  Intégrité : {status}", ""]

    return "\n".join(out)

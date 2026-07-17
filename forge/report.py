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
from . import triage as _triage
from . import llm as _llm


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


def _triage_section(result):
    """Section TRANSPARENCE du triage (miroir du bucket anti-lacune) : dit que le triage a TOURNÉ, combien
    de findings sont actionnables vs bruit/dup, et les top clusters + leurs raisons. Purement DÉRIVÉ du
    `triage_summary` (aucun finding masqué : c'est une VUE). Vide si le triage est désactivé sans bruit."""
    s = result.summary
    out = ["## Triage des findings (dédup / cluster-bruit / rang)", ""]
    if not s.get("enabled"):
        out += ["_Triage désactivé (`scope.triage.enabled=false`) — findings bruts, aucun classement._", ""]
        return out
    out += [
        f"- **{s['total']} findings** → **{s['actionable']} actionnables**, "
        f"**{s['noise']} classés bruit**, **{s['duplicates']} dup(s)** "
        f"(regroupés en **{s.get('num_clusters', 0)} cluster(s)** à haute cardinalité).",
        f"- **Auto-masquage** : {'ACTIVÉ' if s.get('auto_hide') else 'DÉSACTIVÉ (défaut sûr — rien retiré, tout reste auditable)'}.",
        "",
    ]
    clusters = s.get("clusters") or []
    if clusters:
        out += ["**Top clusters-bruit** (gabarit répété → 1 ligne + membres annotés) :", "",
                "| Cluster | Gabarit | Sévérité | Membres | Exemple |", "|---|---|---|---|---|"]
        for c in clusters:
            lbl = str(c.get("label", ""))[:70]
            ex = str(c.get("example_target", ""))[:60]
            out.append(f"| c{c['cluster_id']} | {lbl} | {c['severity']} | {c['size']} | `{ex}` |")
        out.append("")
    top = s.get("top_findings") or []
    if top:
        out += ["**Top findings actionnables (classés)** :", ""]
        for t in top:
            out.append(f"- [{t['severity']}] {t['title']} — `{t['target']}` (bruit={t['score']})")
        out.append("")
    return out


def _assist_section(engine, tr):
    """IA-2 (OPT-IN) — bloc CONSULTATIF enrichissant la triage IA-1 via un LLM OpenAI-compatible.

    OFF PAR DÉFAUT : `scope.llm.enabled` absent/False => renvoie [] (rapport BYTE-IDENTIQUE, aucun appel
    réseau). Activé => `llm.enrich_triage` gère l'egress ledgeré + le gate externe + le fail-open borné,
    et NE TOUCHE NI les findings NI leur ordre NI le ledger des findings. Le bloc rendu est clairement
    étiqueté « advisory » : la triage native (IA-1) fait toujours foi."""
    scope = getattr(engine, "scope", None)
    cfg = _llm.LLMConfig.from_dict(getattr(scope, "llm", None))
    if not cfg.enabled:
        return []                                    # OFF => byte-identique, zéro egress
    block = _llm.enrich_triage(tr, cfg, ledger=getattr(engine, "ledger", None))
    if not block:
        return []                                    # défensif (enrich renvoie None seulement si désactivé)
    host = block.get("endpoint", "?")
    ext = "endpoint EXTERNE" if block.get("external") else "endpoint loopback (local)"
    out = [
        f"## Assist LLM (advisory, endpoint={host} · {ext})",
        "",
        "> _Enrichissement **CONSULTATIF** (IA-2) d'un LLM. Il n'altère NI les findings, NI leur ordre, "
        "NI le ledger : la triage native déterministe (IA-1) fait AUTORITÉ. Le LLM peut se tromper — "
        "à recouper._",
        "",
    ]
    status = block.get("status")
    if status == "gated_external":
        out += [f"- **Egress REFUSÉ** : endpoint externe `{host}` non autorisé "
                f"(`scope.llm.allow_external=false`). AUCUNE donnée envoyée. Autorisez explicitement "
                f"l'egress externe (gate opérateur) pour l'activer.", ""]
    elif status == "unavailable":
        out += [f"- **Assist indisponible** : endpoint `{host}` injoignable / timeout / erreur — "
                f"repli sur la triage native (IA-1), intacte. (fail-open)", ""]
    else:                                            # ok
        out += [block.get("narrative", "") or "_(réponse vide)_", ""]
    return out


def build_report(engine, title="Forge — rapport d'engagement"):
    out = [f"# {title}", ""]
    out += _engagement_header(engine)                # en-tête d'engagement (parité console)
    cov = engine.coverage()

    # TRIAGE (couche de VUE, post-collecte) : dédup + cluster-bruit + score + rang. N'ANNOTE et ne CLASSE
    # que le RENDU — les `engine.findings` bruts et le ledger restent INTACTS (aucune mutation). Config
    # portée par `scope.triage` (défaut sûr : ON, auto_hide OFF). `len(ranked) == len(engine.findings)`.
    tr = _triage.triage(list(engine.findings), getattr(getattr(engine, "scope", None), "triage", None))

    # --- synthèse findings ---
    by_sev = {s: 0 for s in SEVERITIES}
    for f in engine.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    out += ["## Synthèse", "", "| Sévérité | # |", "|---|---|"]
    for s in reversed(SEVERITIES):
        out.append(f"| {s} | {by_sev.get(s, 0)} |")
    out.append("")

    # --- triage : synthèse transparente (dit que le triage a tourné + top clusters/actionnables) ---
    out += _triage_section(tr)

    # --- assist LLM IA-2 (OPT-IN, advisory) : ENRICHIT la synthèse IA-1 sans jamais la réécrire. VIDE
    #     si OFF (défaut) => rapport BYTE-IDENTIQUE ; egress ledgeré + gate externe gérés dans forge/llm.py.
    out += _assist_section(engine, tr)

    # --- findings détaillés (RANG actionnable-d'abord : VUE explicite du triage, PAS un tri silencieux —
    #     chaque finding porte son annotation de triage, et le raw `engine.findings` reste inchangé) ---
    out += ["## Findings", ""]
    if not engine.findings:
        out += ["_Aucun finding._", ""]
    for f in tr.ranked:
        a = tr.annotation_for(f)
        flag = " · **BRUIT probable**" if a.get("likely_noise") else ""
        out += [f"### [{f.severity}] {f.title} — `{f.target}`",
                f"- **Catégorie** : {f.category or '—'}  ·  **ATT&CK** : {f.mitre or '—'}  ·  **Statut** : {f.status}",
                f"- **Triage** : bruit={a.get('score', 0.0)}  ·  cluster={('c%d' % a['cluster_id']) if a.get('cluster_id') is not None else '—'}"
                f"  ·  {a.get('reason', '—') or '—'}{flag}",
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
    not_planned = getattr(engine, "not_planned", None) or {}
    if not_planned:
        # bucket anti-lacune : modules sélectionnés/disponibles que le planner n'a JAMAIS ordonnancés
        # (ni tirés, ni simulés, ni vétoés, ni skippés). Compté ici pour que l'accounting FERME au niveau
        # module : disponibles-non-planifiés + planifiés == sélectionnés (aucune omission silencieuse).
        out.append(f"- **Disponibles non planifiés (jamais ordonnancés)** : {len(not_planned)}")
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

    # --- modules disponibles mais jamais planifiés (bucket anti-lacune, par MODULE) ---
    # Chaque module sélectionné qui n'a pas été planifié (donc jamais tiré/simulé/vétoé/skippé) est listé
    # ICI avec sa raison — dérivée du run (mode/capacités/surface). C'est le trou que le rapport masquait :
    # 35 modules « outil présent mais jamais ordonnancé » n'apparaissaient nulle part. Zéro lacune silencieuse.
    if not_planned:
        out.append(f"**Modules disponibles non planifiés** ({len(not_planned)} — outil présent, "
                   "jamais ordonnancé par le plan)")
        for kind, reason in not_planned.items():
            out.append(f"- `{kind}` : {reason}")
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

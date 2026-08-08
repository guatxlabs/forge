# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rapport markdown + section transparence (anti-masquage).

Le rapport prouve ce qui a été tiré, simulé, vétoé, et jamais tenté : zéro lacune
silencieuse. Section dédiée listant chaque verdict ROE.

ACTIONNABLE-D'ABORD (LOT REPORT-LEAD) — une évaluation réelle a émis **2410 findings : 2404 INFO,
6 LOW, 0 ≥ MEDIUM** et ce module en a fait un rapport de **17 424 lignes** où « rien d'exploitable »
ne se déduisait que d'un défilement. Le triage NATIF (`forge/triage.py`) avait pourtant classé
2410 → 77 actionnables / 2333 bruit : il TOURNAIT, mais son verdict n'était consommé QUE pour
ORDONNER `tr.ranked` — que ce module rendait ensuite EN ENTIER. `auto_hide` était lu, rangé dans la
synthèse, IMPRIMÉ comme étiquette… et jamais consommé (knob mort). Corrigé ici :

  - le rapport OUVRE sur **Verdict** (une ligne : actionnable ou « rien d'actionnable trouvé »), puis
    **Findings actionnables** à la forme attendue par un triager (titre, sévérité, CWE, CVSS, endpoint
    + méthode, reproduction, COMMANDE REJOUABLE, observation, correctif) — assemblés depuis les champs
    que le dépôt produisait DÉJÀ (`poc`/`evidence`/`cwe`/`cvss_vector`/`fix`) et que ce rapport jetait ;
  - les **`skipped`** (trous de couverture) MONTENT dans leur propre section, avant tout le bruit —
    ils étaient pénalisés par le poids `degraded` du noise-score et enterrés en bas du rang ;
  - le bruit de reconnaissance DESCEND en **annexe**, jamais supprimé : la vue `pentest` (DÉFAUT) la
    rend EXHAUSTIVE, la vue `bounty` replie les répétitions de gabarit en les COMPTANT et en disant
    où les récupérer. Le plan d'annexe porte un invariant de PARTITION vérifié et RENDU (fail-loud).

La sévérité vient TOUJOURS du finding : aucune section ne relève un item pour paraître utile.

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
from . import report_view as _view


def _interruption_banner(engine, interruption):
    """EN-TÊTE D'HONNÊTETÉ D'UN RAPPORT PARTIEL — la toute première chose lue, avant l'engagement.

    RAISON D'ÊTRE. Deux campagnes réelles ont été tuées par un timeout externe sans rien rendre. Le
    remède (arrêt gracieux + rendu garanti) crée un risque NEUF et pire que le mal : un rapport
    TRONQUÉ qui ressemble à un rapport COMPLET. Un opérateur y lirait « rien d'actionnable » et
    conclurait « cible saine », alors que la moitié du plan n'a jamais tourné. Cette bannière est la
    contre-mesure, et elle est NON NÉGOCIABLE : tant qu'un run est partiel, il le DIT — en tête, avec
    sa CAUSE (budget / signal externe / exception) et ses COMPTEURS (exécutées sur planifiées, jamais
    tentées, vagues).

    Rend [] sur un run complet : le rapport d'un run normal est byte-identique à avant ce lot."""
    if not interruption:
        return []
    cause = interruption.get("label") or "arrêt anticipé"
    detail = str(interruption.get("detail") or "").strip()
    lines = [
        f"> ⚠️ **RAPPORT PARTIEL — RUN INTERROMPU ({cause}).**",
        f"> {_view.coverage_ratio(interruption)}"
        + (f" · **{interruption['waves']} vague(s)** exécutée(s)."
           if interruption.get("waves") else "."),
    ]
    if detail:
        lines.append(f"> Cause exacte : {detail}.")
    if interruption.get("budget_secs"):
        lines.append(f"> Budget demandé : **{interruption['budget_secs']}s** · écoulé : "
                     f"**{interruption.get('elapsed_secs', '?')}s**.")
    lines += [
        "> **Ce rapport ne couvre QUE ce qui a tourné.** Une absence de finding n'y vaut **pas** une "
        "absence de vulnérabilité : ce qui n'a pas été tenté est listé en §« Couverture NON vérifiée "
        "(trous de couverture) », et aucun verdict — surtout pas négatif — n'a été émis pour ces actions.",
        "",
    ]
    err = getattr(engine, "coverage_finalize_error", "")
    if err:
        lines.insert(1, f"> ⚠️ **Accounting de couverture INCOMPLET** (`{err}`) — les compteurs "
                        f"ci-dessous peuvent sous-estimer les trous. Traiter le ledger comme source "
                        f"de vérité et signaler ce bug.")
    return lines


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
    # PROFIL DE RESSOURCES (audit) : trace le profil actif + les leviers effectifs du run. Dégrade
    # proprement (aucune ligne) si la campagne n'a pas rempli le snapshot (run() direct).
    rp = getattr(engine, "resource_profile", None)
    if isinstance(rp, dict) and rp.get("profile"):
        knobs = rp.get("knobs") or {}
        knob_str = "  ·  ".join(f"{k}={knobs[k]}" for k in sorted(knobs))
        lines.append(f"- **Profil ressources** : `{rp['profile']}`"
                     + (f"  ({knob_str})" if knob_str else ""))
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


def _triage_section(result, view=_view.DEFAULT_VIEW):
    """Section TRANSPARENCE du triage (miroir du bucket anti-lacune) : dit que le triage a TOURNÉ, combien
    de findings sont actionnables vs bruit/dup, et les top clusters + leurs raisons. Purement DÉRIVÉ du
    `triage_summary` (aucun finding masqué : c'est une VUE). Vide si le triage est désactivé sans bruit.

    `view` est rendu ICI aussi : le lecteur doit pouvoir savoir, sans quitter la section, QUELLE vue a
    produit l'annexe et comment obtenir l'autre — une vue non annoncée serait un masquage silencieux."""
    s = result.summary
    out = ["## Triage des findings (dédup / cluster-bruit / rang)", ""]
    other = _view.VIEW_PENTEST if view == _view.VIEW_BOUNTY else _view.VIEW_BOUNTY
    out += [f"- **Vue de rendu** : `{view}` "
            + ("(annexe EXHAUSTIVE — tous les findings rendus)" if view == _view.VIEW_PENTEST
               else "(annexe REPLIÉE aux représentants — repli compté et nommé)")
            + f". Autre vue : `--view {other}` / `FORGE_REPORT_VIEW={other}`.", ""]
    if not s.get("enabled"):
        out += ["_Triage désactivé (`scope.triage.enabled=false`) — findings bruts, aucun classement._", ""]
        return out
    out += [
        f"- **{s['total']} findings** → **{s['actionable']} actionnables**, "
        f"**{s['noise']} classés bruit**, **{s['duplicates']} dup(s)** "
        f"(regroupés en **{s.get('num_clusters', 0)} cluster(s)** à haute cardinalité).",
        f"- **Auto-masquage** : {'ACTIVÉ (`auto_hide=true` → vue `bounty` : les répétitions de gabarit sont repliées, COMPTÉES et NOMMÉES en annexe)' if s.get('auto_hide') else 'DÉSACTIVÉ (défaut sûr — rien retiré, tout reste auditable)'}.",
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
    elif status == "gated_private":
        out += [f"- **Egress REFUSÉ** : endpoint `{host}` résout vers une adresse privée/link-local "
                f"(RFC1918 / métadonnées cloud). AUCUNE donnée envoyée. Défense-en-profondeur SSRF : "
                f"posez `scope.llm.allow_private=true` explicitement si l'endpoint interne est voulu.", ""]
    elif status == "unavailable":
        out += [f"- **Assist indisponible** : endpoint `{host}` injoignable / timeout / erreur — "
                f"repli sur la triage native (IA-1), intacte. (fail-open)", ""]
    else:                                            # ok
        out += [block.get("narrative", "") or "_(réponse vide)_", ""]
    return out


def _scope_line(engine):
    """Périmètre autorisé en une chaîne courte, pour l'étape 1 des reproductions. '' si pas de scope."""
    scope = getattr(engine, "scope", None)
    items = [str(s) for s in (getattr(scope, "in_scope", None) or [])] if scope is not None else []
    return ", ".join(f"`{s}`" for s in items[:6]) + (" …" if len(items) > 6 else "")


def _lead_sections(engine, findings, tr, view, interruption=None):
    """L'EN-TÊTE ACTIONNABLE — ce qu'un opérateur (pentester ou chasseur) doit lire EN PREMIER.

    Renvoie `(lignes, buckets, keep_idxs)`. IDENTIQUE dans les deux vues : le public change la longueur
    de l'ANNEXE, pas la tête du rapport. `keep_idxs` = les indices déjà présentés ici (actionnables +
    non vérifiés) — la vue `bounty` ne les repliera jamais."""
    buckets = _view.bucket_findings(findings, tr)
    items = {k: _view.group_items(findings, buckets[k]) for k in ("exploitable", "qualify")}
    scope_line = _scope_line(engine)

    out = _view.render_verdict(findings, buckets, items, view, interruption=interruption)
    lines, nxt = _view.render_actionable(
        findings, items["exploitable"], "## Actionnable — à reporter",
        "_Aucun finding de sévérité ≥ MEDIUM et aucune exploitabilité prouvée. "
        "**Rien d'actionnable à reporter.** Aucun item n'est relevé en sévérité pour combler la section._",
        scope_line, start=1)
    out += lines
    lines, _ = _view.render_actionable(
        findings, items["qualify"], "## Signal à qualifier (exploitabilité NON démontrée)",
        "_Aucun finding LOW ni hit d'outil tiers._", scope_line, start=nxt)
    out += lines
    out += _view.render_unverified(findings, buckets["unverified"],
                                   not_attempted=getattr(engine, "not_attempted", None),
                                   interruption=interruption)
    keep = list(buckets["exploitable"]) + list(buckets["qualify"]) + list(buckets["unverified"])
    return out, buckets, keep


def build_report(engine, title="Forge — rapport d'engagement", view=None, interruption=None):
    """Rapport markdown d'un run. `view` : `pentest` (défaut, annexe EXHAUSTIVE) ou `bounty` (annexe
    repliée aux représentants, repli COMPTÉ et NOMMÉ). Voir `report_view.resolve_view` pour la
    précédence (argument > `$FORGE_REPORT_VIEW` > `scope.triage.view` > `scope.triage.auto_hide`).

    `interruption` : fiche d'un run COUPÉ (`interrupt.interruption_record`). Explicite d'abord, sinon
    REPRISE SUR LE MOTEUR (`engine.interruption`, posée par `Engine._check_stop`) — pour qu'un
    appelant qui ne connaît pas ce lot (console, script, test) rende malgré tout un rapport HONNÊTE
    plutôt qu'un rapport tronqué muet. None des deux côtés => run complet => rendu inchangé."""
    if interruption is None:
        interruption = getattr(engine, "interruption", None)
    out = [f"# {title}", ""]
    out += _interruption_banner(engine, interruption)  # PARTIEL ? le dire AVANT tout le reste
    out += _engagement_header(engine)                # en-tête d'engagement (parité console)
    cov = engine.coverage()

    # TRIAGE (couche de VUE, post-collecte) : dédup + cluster-bruit + score + rang. N'ANNOTE et ne CLASSE
    # que le RENDU — les `engine.findings` bruts et le ledger restent INTACTS (aucune mutation). Config
    # portée par `scope.triage` (défaut sûr : ON, auto_hide OFF). `len(ranked) == len(engine.findings)`.
    scope_triage = getattr(getattr(engine, "scope", None), "triage", None)
    findings = list(engine.findings)
    tr = _triage.triage(findings, scope_triage)
    view = _view.resolve_view(view, scope_triage)

    # --- EN-TÊTE ACTIONNABLE : verdict -> actionnables -> à qualifier -> couverture NON vérifiée.
    #     Le bruit de reconnaissance vient APRÈS (annexe), jamais avant. Les `skipped` REMONTENT :
    #     un « je n'ai pas pu vérifier » borne ce que l'absence de finding permet de conclure.
    lead, buckets, keep_idxs = _lead_sections(engine, findings, tr, view, interruption)
    out += lead

    # --- synthèse findings ---
    by_sev = {s: 0 for s in SEVERITIES}
    for f in engine.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    out += ["## Synthèse", "", "| Sévérité | # |", "|---|---|"]
    for s in reversed(SEVERITIES):
        out.append(f"| {s} | {by_sev.get(s, 0)} |")
    out.append("")

    # --- triage : synthèse transparente (dit que le triage a tourné + top clusters/actionnables) ---
    out += _triage_section(tr, view)

    # --- assist LLM IA-2 (OPT-IN, advisory) : ENRICHIT la synthèse IA-1 sans jamais la réécrire. VIDE
    #     si OFF (défaut) => rapport BYTE-IDENTIQUE ; egress ledgeré + gate externe gérés dans forge/llm.py.
    out += _assist_section(engine, tr)

    # --- ANNEXE : findings détaillés (RANG actionnable-d'abord : VUE explicite du triage, PAS un tri
    #     silencieux — chaque finding porte son annotation de triage, et le raw `engine.findings` reste
    #     inchangé). Le PLAN d'annexe décide quoi rendre/replier et porte l'invariant de PARTITION ;
    #     `render_annex_accounting` l'IMPRIME (fail-loud) — rendus + repliés == total, toujours dit.
    plan = _view.annex_plan(findings, tr, view, keep_idxs=keep_idxs)
    out += [f"## Findings — annexe complète ({len(findings)} émis, vue `{view}`)", ""]
    out += _view.render_annex_accounting(plan)
    if not engine.findings:
        out += ["_Aucun finding._", ""]
    for i in plan.rendered:
        f = findings[i]
        a = tr.annotation_for(f)
        flag = " · **BRUIT probable**" if a.get("likely_noise") else ""
        # RÉDACTION (défense en profondeur) : `Finding.to_dict()` est le chokepoint du LEDGER, mais le
        # rapport lit les ATTRIBUTS bruts — un finding construit hors du chemin `Module.finding` (plugin,
        # importateur, test) faisait donc FUIR `evidence`/`poc` non rédigés dans le markdown. Tout champ
        # texte passe désormais par la surface unique `forge.redact` (idempotent, jamais moins masquant).
        out += [f"### [{f.severity}] {_view._txt(f.title)} — `{_view._txt(f.target)}`",
                f"- **Catégorie** : {_view._txt(f.category) or '—'}  ·  **ATT&CK** : {_view._txt(f.mitre) or '—'}  ·  **Statut** : {f.status}",
                f"- **Triage** : bruit={a.get('score', 0.0)}  ·  cluster={('c%d' % a['cluster_id']) if a.get('cluster_id') is not None else '—'}"
                f"  ·  {a.get('reason', '—') or '—'}{flag}",
                f"- **Outil** : {_view._txt(f.tool) or '—'}",
                f"- **Preuve** : {_view._txt(f.evidence) or '—'}",
                f"- **PoC** : `{_view._txt(f.poc) or '—'}`", ""]

    # --- transparence ROE (anti-masquage) ---
    out += ["## Couverture & transparence (ROE / anti-masquage)", ""]
    out.append(f"- **Tirées (FIRE)** : {len(cov['fired'])}")
    out.append(f"- **Simulées (DRY_RUN)** : {len(cov['dry_run'])}")
    out.append(f"- **Refusées (VETO — hors scope / capacité non autorisée)** : {len(cov['vetoed'])}")
    out.append(f"- **Erreurs / skips** : {len(cov['errors'])}")
    out.append(f"- **Findings dédupliqués (déjà en mémoire)** : {getattr(engine, 'dups', 0)}")
    pending = getattr(engine, "not_attempted", None) or []
    if pending:
        # Ferme l'accounting AU NIVEAU ACTION sur un run coupé : planifiées == appliquées + non tentées.
        # Sans cette ligne, les actions ordonnées et jamais atteintes ne seraient dans AUCUN compteur.
        out.append(f"- **Planifiées jamais tentées (run interrompu)** : {len(pending)} "
                   f"(sur {getattr(engine, 'planned_total', 0)} ordonnée(s) — détail en "
                   f"§« Couverture NON vérifiée »)")
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

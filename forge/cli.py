# SPDX-License-Identifier: AGPL-3.0-only
"""CLI Forge — `forge <commande>`.

Commandes :
  scope-check <target> --scope S      verdict d'appartenance (in/out scope)
  plan --scope S [--actions A]        liste les actions et leur verdict ROE (sans rien tirer)
  run  --scope S [--actions A] [--arm] [--approve KIND:TARGET ...] [--mode propose|auto]
                 [--ledger L] [--report R]
  ledger verify --ledger L [--pubkey HEX]  recalcule la chaîne et vérifie l'intégrité
                                           (--pubkey -> vérif externe par clé publique seule)
  ledger pubkey --ledger L            imprime la clé publique Ed25519 brute (hex) du ledger
  ledger keygen --ledger L [--force]  crée/rotationne DÉLIBÉRÉMENT la paire Ed25519 du ledger
  modules                             liste les modules enregistrés
  doctor [--purple]                   diagnostic : modules opérationnels (ou préflight boucle purple)
  demo                                démonstration bout-en-bout, sans aucune cible réelle

Sûreté : par défaut INERTE. `run` simule (DRY_RUN) tant que --arm ET --approve ne sont pas
posés. VETO (hors scope / capacité non autorisée) ne peut jamais être tiré.
"""
import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from .roe import Scope, Roe, Action
from .ledger import Ledger
from .engine import Engine
from .report import build_report
from .schema import Target
from .brain import HeuristicBrain, AutoPentestBrain
from .planner import Planner
from .memory import Memory
from . import purple
from . import signing
from . import console_client
from . import collectors
from . import modules as mods
from . import techniques
from . import workflows


def _load_actions(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for i, a in enumerate(data):
        try:
            out.append(Action(kind=a["kind"], target=a["target"],
                              exploit=a.get("exploit", False), destructive=a.get("destructive", False),
                              desc=a.get("desc", ""), params=a.get("params", {})))
        except KeyError as e:                          # champ requis manquant -> message clair (pas un KeyError brut)
            raise SystemExit(f"actions[{i}] : champ requis manquant {e} dans {path} "
                             f"(chaque action exige 'kind' et 'target')")
    return out


def _demo_actions(scope):
    # une action par cible littérale du scope (les globs/CIDR sont ignorés ici)
    tgts = [t for t in scope.in_scope if "*" not in t and "/" not in t] or ["demo.local"]
    return [Action(kind="demo.fingerprint", target=t, desc="demo") for t in tgts]


def cmd_scope_check(args):
    scope = Scope.load(args.scope)
    verdict = "IN SCOPE ✅" if scope.is_in_scope(args.target) else "HORS SCOPE ⛔"
    print(f"{args.target} : {verdict}")
    print(f"  mode={scope.mode} allow_exploit={scope.allow_exploit} allow_destructive={scope.allow_destructive}")
    return 0 if scope.is_in_scope(args.target) else 1


def cmd_plan(args):
    scope = Scope.load(args.scope)
    roe = Roe(scope)                       # pas armé : tout sera VETO ou DRY_RUN
    actions = _load_actions(args.actions) if args.actions else _demo_actions(scope)
    print(f"# Plan ({len(actions)} actions) — non armé, aucune action ne sera tirée\n")
    for a in actions:
        d = roe.decide(a)
        print(f"  [{d.verdict:7}] {a.kind} → {a.target}   ({' ; '.join(d.reasons)})")
    return 0


def cmd_run(args):
    scope = Scope.load(args.scope)
    ledger = Ledger(args.ledger) if args.ledger else None
    memory = Memory(args.memory) if args.memory else None
    engine = Engine(scope, ledger=ledger, mode=args.mode, memory=memory)
    if args.arm:
        engine.arm(f"forge run --arm ({args.reason or 'cli'})")
    for ap in (args.approve or []):
        engine.approve(ap)
    actions = _load_actions(args.actions) if args.actions else _demo_actions(scope)
    engine.run(actions)
    if ledger is not None:                 # scelle la fin de run : checkpoint (ancré si anchor configuré)
        ledger.checkpoint(note="forge run end")
    cov = engine.coverage()
    print(f"Tirées={len(cov['fired'])}  Simulées={len(cov['dry_run'])}  "
          f"Refusées={len(cov['vetoed'])}  Erreurs={len(cov['errors'])}  Findings={len(engine.findings)}")
    rep = build_report(engine)
    if args.report:
        Path(args.report).write_text(rep, encoding="utf-8")
        print(f"Rapport -> {args.report}")
    else:
        print("\n" + rep)
    return 0


def _load_targets(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for i, t in enumerate(data):
        try:
            out.append(Target(host=t["host"], kind=t.get("kind", "host"), attrs=t.get("attrs", {})))
        except KeyError as e:                          # 'host' manquant -> message clair (pas un KeyError brut)
            raise SystemExit(f"targets[{i}] : champ requis manquant {e} dans {path} "
                             f"(chaque cible exige 'host')")
    return out


def _workflows_path(args):
    """Chemin du fichier de workflows UTILISATEUR : `--workflows PATH` sinon env `FORGE_WORKFLOWS_FILE`
    sinon "" (builtins seuls — WorkflowStore.load tolère un chemin absent). Les workflows INTÉGRÉS sont
    toujours disponibles sans fichier (dérivés du registre)."""
    return getattr(args, "workflows", None) or os.environ.get("FORGE_WORKFLOWS_FILE", "")


def cmd_campaign(args):
    scope = Scope.load(args.scope)
    ledger = Ledger(args.ledger) if args.ledger else None
    memory = Memory(args.memory) if args.memory else None
    engine = Engine(scope, ledger=ledger, mode=args.mode, memory=memory)
    if args.arm:
        engine.arm(f"forge campaign --arm ({args.reason or 'cli'})")
    for ap in (args.approve or []):
        engine.approve(ap)
    targets = _load_targets(args.targets)
    planner = Planner(budget=args.budget, exhaustive=args.exhaustive)
    # --modules kind1,kind2 : RESTREINT le plan aux kinds demandés (sélection UI/console).
    # Absent/vide -> plan complet du cerveau (comportement inchangé).
    modules = [m.strip() for m in (args.modules or "").split(",") if m.strip()] or None
    # params par-module globaux : exposés par Scope (plus de double-lecture du scope.json) ;
    # les params par-cible vivent dans targets.json[].attrs.module_params (chargés via _load_targets).
    module_params = dict(scope.module_params or {})
    auto_pentest = getattr(args, "auto_pentest", False)
    # --workflow NAME : lance EXACTEMENT les étapes d'un workflow SAUVEGARDÉ (pipeline composé sans code).
    # Un workflow est une PROPOSITION : ses kinds RESTREIGNENT le plan (--modules) et ses params par-étape
    # enrichissent module_params, MAIS le scope-guard + la sélection par-scope restent seuls JUGES —
    # `resolve()` FILTRE les étapes par l'ensemble EFFECTIF activé du scope (une étape hors-scope/
    # désactivée est LARGUÉE, fail-closed), et l'engine ré-enforce `enabled_kinds` + ROE au tir (défense
    # en profondeur). On force le balayage auto-pentest pour que CHAQUE étape activée soit bien proposée.
    if getattr(args, "workflow", None):
        store = workflows.WorkflowStore.load(_workflows_path(args))
        wf = store.get(args.workflow)
        if wf is None:
            raise SystemExit(f"forge campaign : workflow inconnu '{args.workflow}' "
                             f"(disponibles : {', '.join(sorted(store.list()))})")
        enabled = scope.effective_technique_kinds()
        kept, dropped = workflows.resolve(wf, enabled)
        modules = workflows.step_kinds(wf) or None     # la PROPOSITION (l'engine larguera les désactivées)
        for kind, p in workflows.workflow_module_params(wf).items():
            merged = dict(module_params.get(kind, {})); merged.update(p or {}); module_params[kind] = merged
        auto_pentest = True
        print(f"# Workflow '{wf['name']}' — {len(kept)} étape(s) activée(s) pour ce scope, "
              f"{len(dropped)} larguée(s) (hors-scope/désactivée, fail-closed).")
        if kept:
            print("  Activées : " + ", ".join(s["kind"] for s in kept))
        if dropped:
            print("  Larguées : " + ", ".join(s["kind"] for s in dropped))
    # --auto-pentest : MODE PENTEST AUTOMATISÉ — balaie TOUTES les techniques ACTIVÉES du scope à
    # travers la surface découverte (recon -> chaînage -> oracles), gouverné à l'identique (scope-guard,
    # plancher exploit, ledger). Sinon cerveau heuristique standard. L'ensemble balayé = l'effective set
    # du scope (profil + toggles) -> respecte la sélection par-scope sans câblage par-technique.
    brain = (AutoPentestBrain(scope.effective_technique_kinds())
             if auto_pentest else HeuristicBrain())
    engine.campaign(targets, brain, planner,
                    modules=modules, module_params=module_params)
    if ledger is not None:                 # scelle la fin de campagne : checkpoint (ancré si anchor configuré)
        ledger.checkpoint(note="forge campaign end")
    cov = engine.coverage()
    print(f"Tirées={len(cov['fired'])}  Simulées={len(cov['dry_run'])}  Refusées={len(cov['vetoed'])}  "
          f"Erreurs={len(cov['errors'])}  Déférées(budget)={len(engine.skipped_budget)}  "
          f"Findings={len(engine.findings)}  Dups={engine.dups}  Run-records={len(engine.run_records)}")
    if engine.coverage_gaps:
        print("Lacunes de couverture (classes jamais tentées) :")
        for tgt, miss in engine.coverage_gaps.items():
            print(f"  {tgt}: {', '.join(miss)}")
    if args.purple and engine.run_records:
        n = purple.emit(args.purple, engine.run_records)
        print(f"Run-records ATT&CK -> {args.purple} ({n})")
    if args.console:
        from . import console_client
        try:
            st, resp = console_client.ingest(
                args.campaign, engine.findings, engine.run_records,
                url=args.console, token=args.console_token,
                run_id=args.run_id, roe_decisions=engine.roe_decisions(),
                coverage=cov, coverage_gaps=engine.coverage_gaps,
                skipped_budget=engine.skipped_budget)
            print(f"Console <- ingest (HTTP {st}): {resp}")
        except Exception as e:  # noqa: BLE001
            print(f"Console: échec ingest ({e!r})")
    rep = build_report(engine)
    if args.report:
        Path(args.report).write_text(rep, encoding="utf-8")
        print(f"Rapport -> {args.report}")
    else:
        print("\n" + rep)
    return 0


def cmd_ledger_verify(args):
    # --pubkey HEX : vérification EXTERNE (tiers) par la SEULE clé publique Ed25519, sans aucun secret
    # (non-répudiation). Sinon vérif locale par le signeur du host.
    if getattr(args, "pubkey", None):
        v = Ledger(args.ledger).verify_external(args.pubkey)
        if v["ok"]:
            print(f"Ledger OK ✅ (vérif externe, clé publique seule) — {v['entries']} entrées")
            return 0
        print(f"Ledger CASSÉ ❌ (vérif externe) — entrée {v.get('broken')} : {v.get('why','')}")
        return 1
    v = Ledger(args.ledger).verify()
    if v["ok"]:
        print(f"Ledger OK ✅ — {v['entries']} entrées, alg={v.get('alg','?')}, "
              f"pub={v.get('pub','')}, head={v.get('head','')[:16]}…")
        return 0
    print(f"Ledger CASSÉ ❌ — entrée {v['broken']} : {v.get('why','')} (alg={v.get('alg','?')})")
    return 1


def cmd_ledger_pubkey(args):
    """Imprime la clé publique Ed25519 BRUTE (hex) qui signe ce ledger, alg en 2e ligne.
    Résout la clé EXACTEMENT comme le chemin `ledger verify` (Ledger(path) -> make_signer :
    lit `<path>.ed25519` s'il existe, sinon auto-gen). Le hex imprimé est directement réutilisable
    en vérif externe : `forge ledger verify --ledger L --pubkey <hex>`."""
    led = Ledger(args.ledger)
    hexkey = signing.signer_pubkey_hex(led.signer)
    if hexkey:
        print(hexkey)                                  # ligne 1 : clé publique brute (64 hex)
        print(f"# alg={led.signer.alg}")               # ligne 2 : algorithme (ed25519)
        return 0
    # repli HMAC (cryptography absent) : pas de clé publique asymétrique de non-répudiation.
    print(f"# pas de clé publique Ed25519 — ledger signé en {led.signer.alg} "
          f"(installer 'cryptography' pour la non-répudiation asymétrique)")
    print(f"# public_id={led.signer.public_id()}")
    return 1


def cmd_ledger_keygen(args):
    """Crée/rotationne DÉLIBÉRÉMENT la paire Ed25519 du ledger (<path>.ed25519, 0600), au lieu de
    l'auto-gen paresseux. Sûreté : refuse d'écraser une clé existante sans --force (une rotation
    invalide les signatures ed25519 déjà écrites -> `verify` casserait). Imprime la clé publique."""
    if not signing._HAVE_ED:
        print("# 'cryptography' absent — impossible de générer une clé Ed25519 (repli HMAC seul)")
        return 1
    kp = Path(str(args.ledger) + ".ed25519")
    if kp.exists() and not args.force:
        print(f"# clé déjà présente : {kp}")
        print("# --force requis pour ROTATION (invalide les signatures ed25519 déjà écrites)")
        return 1
    rotated = kp.exists()
    signer = signing.generate_ed25519_keypair(args.ledger)
    print(signing.signer_pubkey_hex(signer))
    print(f"# alg=ed25519 — clé {'ROTATIONNÉE' if rotated else 'créée'} dans {kp} (0600)")
    return 0


def cmd_modules(args):
    mods  # noqa (déjà importé -> enregistré)
    rows = []
    for k in mods.kinds():
        m = mods.get(k)
        # web_allowed : un module sans déclaration explicite est dérivé comme la console
        # (recon/scan pur = web ; exploit ou destructif => hors plancher web par défaut).
        web_allowed = bool(getattr(m, "web_allowed", not (m.exploit or m.destructive)))
        # Taxonomie de consolidation DÉRIVÉE de forge/techniques.py (source unique) : la console/UI
        # groupe le catalogue par `vuln_class` et filtre par profil SANS câblage par-technique — un
        # nouveau module @register apparaît automatiquement classé. Champs ADDITIFS (rétro-compat :
        # les consommateurs existants lisent champ par champ et ignorent ceux qu'ils ne connaissent pas).
        t = techniques.technique_for(k)
        rows.append({"kind": k, "cls": k.split(".")[-1],
                     "exploit": bool(m.exploit), "destructive": bool(m.destructive),
                     "web_allowed": web_allowed,
                     "available": bool(getattr(m, "available", True)),
                     "mitre": getattr(m, "mitre", "") or "",
                     "descr": getattr(m, "description", "") or "",
                     "vuln_class": (t.vuln_class if t else ""),
                     "bug_bounty_eligible": bool(t.bug_bounty_eligible) if t else False,
                     "pentest_only": bool(t.pentest_only) if t else False,
                     "profiles": list(t.default_profiles) if t else [],
                     "stage": (t.stage if t else ""),
                     "tools": (list(t.tools) if t else []),
                     "depends_on": (list(t.depends_on) if t else [])})
    if getattr(args, "json", False):
        print(json.dumps(rows))
        return 0
    print("Modules enregistrés :")
    for r in rows:
        print(f"  {r['kind']:24} exploit={r['exploit']} destructive={r['destructive']} "
              f"available={r['available']}")
    return 0


def _load_technique_selection(args):
    """Résout la SÉLECTION de techniques par-scope (profil + toggles) pour `forge techniques` :
    `--selection` (env:NOM | @fichier | JSON littéral), sinon env `FORGE_TECHNIQUE_SELECTION`, sinon
    vide (défaut profil bug_bounty). Tolère `techniques`/`techniques_enabled` et `categories`/
    `categories_enabled` (alias). Ne lève jamais (JSON illisible -> sélection vide)."""
    raw = getattr(args, "selection", None)
    text = None
    if raw:
        if raw.startswith("env:"):
            text = os.environ.get(raw[4:], "")
        elif raw.startswith("@"):
            try:
                text = Path(raw[1:]).read_text(encoding="utf-8")
            except OSError:
                text = None
        else:
            text = raw
    if text is None:
        text = os.environ.get("FORGE_TECHNIQUE_SELECTION", "")
    sel = {}
    if text:
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                sel = data
        except ValueError:
            sel = {}
    return {
        "profile": sel.get("profile"),
        "techniques": sel.get("techniques", sel.get("techniques_enabled")),
        "categories": sel.get("categories", sel.get("categories_enabled")),
    }


def cmd_techniques(args):
    """Catalogue des TECHNIQUES GROUPÉ par catégorie (vuln_class), DÉRIVÉ de la table unique — c'est la
    vue « catalogue + sélection » consommée par `GET /api/techniques` et l'opérateur. Reflète l'état
    ACTIVÉ (`enabled_for_current_scope`) pour une SÉLECTION par-scope (profil + toggles ; défaut profil
    bug_bounty) résolue par `techniques.resolve_enabled_kinds` (SOURCE UNIQUE partagée avec l'enforcement).
    Sortie JSON : {profile, profiles, selection, enabled:[...], groups:{catégorie:[{kind,tools,...}]}}."""
    sel = _load_technique_selection(args)
    profile = sel.get("profile") or "bug_bounty"
    enabled = techniques.resolve_enabled_kinds(
        profile=profile, techniques_enabled=sel.get("techniques"),
        categories_enabled=sel.get("categories"))
    groups = {}
    for cat, kinds_ in techniques.by_vuln_class().items():
        rows = []
        for k in sorted(kinds_):
            t = techniques.technique_for(k)
            rows.append({
                "kind": k, "vuln_class": cat, "tools": list(t.tools),
                "bug_bounty_eligible": bool(t.bug_bounty_eligible),
                "pentest_only": bool(t.pentest_only),
                "mitre": t.mitre or "", "cwe": t.cwe or "",
                "phase": t.phase or "", "stage": t.stage or "",
                "enabled_for_current_scope": k in enabled,
            })
        groups[cat] = rows
    out = {"profile": profile, "profiles": list(techniques.PROFILE_NAMES),
           "selection": sel, "enabled": sorted(enabled),
           "groups": {c: groups[c] for c in sorted(groups)}}
    print(json.dumps(out))
    return 0


def cmd_workflows(args):
    """Workflows sauvegardés (pipelines composés) — DÉRIVÉS du registre pour les INTÉGRÉS + fichier
    UTILISATEUR optionnel. C'est LA vue consommée par `GET /api/workflows` (la console) et l'opérateur
    CLI. Chaque workflow porte {name, description, builtin, steps:[{kind, params}], step_kinds}.
    Sortie JSON : {builtins:[...], workflows:[...]} (builtins = intégrés dérivés ; workflows = utilisateur).
    Avec `--resolve @scope.json`, ajoute par workflow `kept`/`dropped` (l'aperçu fail-closed : quelles
    étapes seraient activées/larguées pour ce scope)."""
    store = workflows.WorkflowStore.load(_workflows_path(args))
    enabled = None
    if getattr(args, "resolve", None):
        try:
            enabled = Scope.load(args.resolve.lstrip("@")).effective_technique_kinds()
        except Exception:                              # noqa: BLE001 — scope illisible -> pas d'aperçu
            enabled = None

    def _row(wf):
        row = {"name": wf["name"], "description": wf.get("description", ""),
               "builtin": bool(wf.get("builtin")), "steps": wf.get("steps", []),
               "step_kinds": workflows.step_kinds(wf), "step_count": len(wf.get("steps", []))}
        if enabled is not None:
            kept, dropped = workflows.resolve(wf, enabled)
            row["kept"] = [s["kind"] for s in kept]
            row["dropped"] = [s["kind"] for s in dropped]
        return row

    builtins = workflows.builtin_workflows()
    out = {
        "builtins": [_row(builtins[n]) for n in sorted(builtins)],
        "workflows": [_row(store.user[n]) for n in sorted(store.user)],
    }
    print(json.dumps(out))
    return 0


# Pour chaque kind de module : (dépendance attendue, astuce d'installation/config).
# Sert UNIQUEMENT au diagnostic `forge doctor` (lisibilité opérateur) ; la vérité sur la
# disponibilité reste la property `.available` du module (sonde binaire/docker/service).
_DOCTOR_HINTS = {
    "recon.httpx":   ("binaire httpx ou docker projectdiscovery/httpx",
                      "go install github.com/projectdiscovery/httpx/cmd/httpx@latest  (ou docker)"),
    "recon.nmap":    ("binaire nmap ou docker instrumentisto/nmap",
                      "apt install nmap  (ou docker run instrumentisto/nmap)"),
    "web.nuclei":    ("binaire nuclei ou docker projectdiscovery/nuclei",
                      "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  (ou docker)"),
    "origin.find":   ("binaires subfinder + httpx (ou leurs images docker)",
                      "go install .../subfinder + .../httpx  (ou docker projectdiscovery/{subfinder,httpx})"),
    "access_control.idor": ("aucune — urllib stdlib (toujours disponible)",
                      "rien à installer ; fournir params.accounts (>=2) et params.urls"),
    "demo.fingerprint": ("aucune — finding synthétique, zéro I/O",
                      "rien à installer (module de démonstration)"),
    "evasion.xhr":   ("service browser-automation (défaut http://localhost:8080)",
                      "lancer toolkit/browser-automation (port 8080) ; override via FORGE_BROWSER_URL"),
    "evasion.turnstile": ("service browser-automation (défaut http://localhost:8080)",
                      "lancer toolkit/browser-automation (port 8080) ; override via FORGE_BROWSER_URL"),
    "evasion.idor_intercept": ("service browser-automation (défaut http://localhost:8080)",
                      "lancer toolkit/browser-automation (port 8080) ; override via FORGE_BROWSER_URL"),
    "msf.module":    ("service msfrpcd (RPC msgpack, défaut 127.0.0.1:55553 SSL)",
                      "msfrpcd -U msf -P <pass> ; config via MSF_RPC_HOST/PORT/USER/PASS/SSL ou MSF_RPC_TOKEN"),
    "burp.scan":     ("REST API Burp Suite Pro/Enterprise (défaut http://127.0.0.1:1337)",
                      "activer la REST API Burp ; config via BURP_API_URL et BURP_API_KEY"),
    "recon.subdomains": ("aucune — urllib stdlib (crt.sh CT) ; passive DNS optionnel via params",
                      "rien à installer ; source injoignable -> finding status=skipped (offline-safe)"),
    "recon.dns":     ("aucune requise — socket stdlib (A/AAAA) ; dnspython/dig optionnels (tous types)",
                      "pip install dnspython OU apt install dnsutils pour CNAME/MX/TXT/NS (sinon A/AAAA seul)"),
    "recon.js_endpoints": ("aucune — urllib stdlib (fetch page + JS in-scope, extraction regex)",
                      "rien à installer ; page injoignable -> finding status=skipped (offline-safe)"),
    "recon.urls":    ("aucune — urllib stdlib (Wayback CDX) ; CommonCrawl optionnel via params",
                      "rien à installer ; archive injoignable -> finding status=skipped (offline-safe)"),
    "recon.tech":    ("aucune requise — urllib stdlib (headers/cookies/meta) ; httpx optionnel (tech-detect)",
                      "rien à installer ; httpx (binaire/docker) enrichit le fingerprint s'il est présent"),
    "recon.content": ("binaire ffuf (local) — la wordlist locale n'est pas montable en docker",
                      "installer ffuf (go install github.com/ffuf/ffuf/v2@latest) ; absent -> finding status=skipped"),
    "recon.secrets": ("binaire trufflehog OU gitleaks (local) — scan d'un dossier d'assets local",
                      "installer trufflehog ou gitleaks ; absent/réseau KO -> finding status=skipped (offline-safe)"),
    "recon.waf":     ("aucune requise — urllib stdlib (en-têtes/cookies/Server) ; wafw00f optionnel",
                      "rien à installer ; wafw00f (binaire local) enrichit le fingerprint s'il est présent"),
    # LOT SCALE — nouvelles classes de vuln (self-describing) : toutes stdlib sauf xss.stored (browser).
    "access_control.privesc": ("aucune — urllib stdlib ; exige allow_exploit (atteint une fonction admin-only)",
                      "rien à installer ; fournir params.accounts (bas-priv + admin, comptes OPÉRATEUR) et params.admin_urls"),
    "xxe.probe":     ("aucune — urllib stdlib ; mode OOB (collecteur opérateur) OU canari bénin in-band",
                      "rien à installer ; fournir un collecteur (callback_base + callback_check_url) OU un canari bénin (canary_url + canary_marker)"),
    "rfi.probe":     ("aucune — urllib stdlib ; ressource marqueur BÉNIGNE hébergée par l'opérateur",
                      "rien à installer ; fournir params.marker_url (ressource bénigne) + params.marker + params.param"),
    "ssrf.xspa":     ("aucune — urllib stdlib (différentiel de réponse/timing) ; scan de la cible in-scope",
                      "rien à installer ; fournir params.param (SSRF-able) ; internal_host défaut = hôte cible / loopback"),
    "xss.stored":    ("service browser-automation (défaut http://localhost:8080) — rendu DOM requis",
                      "lancer toolkit/browser-automation (port 8080) ; absent -> finding status=skipped (offline-safe)"),
    "rce.probe":     ("aucune — urllib stdlib ; PENTEST-ONLY, gardé par le plancher exploit/fort-impact",
                      "rien à installer ; exige allow_exploit/allow_high_impact armé + params.param"),
    "business_logic.scan": ("aucune — urllib stdlib ; PENTEST-ONLY, scaffold semi-automatisé",
                      "rien à installer ; fournir params.probes[<check>] (sonde DEVIS non destructive) pour automatiser, sinon note manual-review"),
}


# Une « technique » ATT&CK : Txxxx éventuellement suivie d'un sous-technique .yyy (ex T1190, T1059.001).
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Marqueurs de la checklist purple (aligné sur le style "OK ✅"/"INDISPONIBLE ⛔" de doctor).
_PURPLE_MARK = {"ok": "OK ✅", "fail": "FAIL ❌", "na": "N/A ➖", "info": "INFO ℹ️"}


def _purple_get(url, basic_b64=None, timeout=8.0):
    """GET en LECTURE SEULE, tolérant aux pannes (ne lève JAMAIS). Retourne (status, body, err) :
      - (200, "<body>", None)              réponse OK ;
      - (<code>, "<body>", None)           réponse HTTP reçue (même 401/500) -> service JOIGNABLE ;
      - (None, "", "<repr err>")           injoignable (DNS, refus de connexion, timeout...).
    `basic_b64` (base64 de user:pass) -> en-tête `Authorization: Basic ...` (comme la console Rust)."""
    headers = {}
    if basic_b64:
        headers["Authorization"] = "Basic " + basic_b64
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:                # service joignable mais réponse d'erreur HTTP
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:                              # noqa: BLE001
            body = ""
        return e.code, body, None
    except Exception as e:                             # noqa: BLE001 — injoignable (URLError, timeout, ...)
        return None, "", repr(e)


def _parse_detections(body):
    """Extrait la liste de détections de la réponse Plume. Tolère `{"detections":[...]}` (forme
    nominale, cf. console Rust) et un tableau nu `[...]`. Retourne None si le JSON est illisible."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if isinstance(data, dict):
        arr = data.get("detections", [])
        return list(arr) if isinstance(arr, list) else None
    if isinstance(data, list):
        return data
    return None


def _count_mitre_tagged(detections):
    """Nombre de détections portant un champ technique de forme Txxxx (`mitre` ou `technique`)."""
    n = 0
    for d in detections:
        if not isinstance(d, dict):
            continue
        val = d.get("mitre") or d.get("technique") or ""
        if isinstance(val, str) and _TECHNIQUE_RE.search(val):
            n += 1
    return n


def _doctor_source_preflight(args, source):
    """Préflight GÉNÉRALISÉ à la source de détection CONFIGURÉE (kind ≠ plume/legacy). LECTURE SEULE :
    GET console `/health` + `collector.doctor()` (sonde de joignabilité) + une collecte de sonde pour
    compter détections/tags MITRE. Dégrade gracieusement (FAIL/N/A, jamais de crash). Critiques =
    console joignable + source joignable/configurée. Le secret n'apparaît jamais (détails rédigés)."""
    console_url = console_client.base_url()
    timeout = getattr(args, "timeout", None) or 8.0
    lines = []
    critical_ok = True

    st, body, err = _purple_get(console_url + "/health", timeout=timeout)
    if st == 200:
        lines.append(("ok", "console-reachable", f"{console_url}/health -> 200 {body.strip()[:16]}"))
    elif st is not None:
        lines.append(("fail", "console-reachable", f"{console_url}/health -> HTTP {st}")); critical_ok = False
    else:
        lines.append(("fail", "console-reachable", f"{console_url}/health injoignable ({err})")); critical_ok = False

    col = collectors.get_collector(source)
    if col is None:
        lines.append(("fail", "source-configured", f"kind inconnu: {source.get('kind')}")); critical_ok = False
        for lbl in ("source-reachable", "detections-returned", "mitre-tagged"):
            lines.append(("na", lbl, "kind inconnu"))
    else:
        cfg_err = col.config_error()
        if cfg_err:
            lines.append(("fail", "source-configured", collectors.safe_error(ValueError(cfg_err), source)))
            critical_ok = False
        else:
            lines.append(("ok", "source-configured", collectors.describe(source)))
        rows = col.fetch(0)                    # sonde LECTURE SEULE (ne lève jamais)
        if col.reachable:
            lines.append(("ok", "source-reachable", col.doctor().get("detail", "")))
            n = len(rows)
            lines.append(("ok" if n else "info", "detections-returned", f"{n} technique(s)"))
            if n == 0:
                lines.append(("na", "mitre-tagged", "aucune détection à inspecter"))
            else:
                tagged = _count_mitre_tagged(rows)
                state = "ok" if tagged else "info"
                lines.append((state, "mitre-tagged", f"champ technique Txxxx présent ({tagged}/{n})"))
        else:
            lines.append(("fail", "source-reachable", col.error_detail())); critical_ok = False
            for lbl in ("detections-returned", "mitre-tagged"):
                lines.append(("na", lbl, "source injoignable"))

    if getattr(args, "json", False):
        print(json.dumps({"ok": critical_ok,
                          "checks": [{"check": lbl, "state": state, "detail": detail}
                                     for state, lbl, detail in lines]}))
        return 0 if critical_ok else 1
    verdict = "PRÊTE ✅" if critical_ok else "INCOMPLÈTE ⛔"
    print(f"=== forge doctor --purple — boucle purple {verdict} (source: {source.get('kind')}) ===\n")
    for state, lbl, detail in lines:
        print(f"  [{_PURPLE_MARK.get(state, state):8}] {lbl:20} {detail}")
    print("\nNote : lecture seule — aucun tir, ni scope ni ledger touchés. Critiques = console joignable "
          "+ source configurée/joignable. Détections/MITRE sont informatifs (0 détection = SOC frais).")
    return 0 if critical_ok else 1


def cmd_doctor_purple(args):
    """Préflight de la boucle purple (LECTURE SEULE, ne tire rien, ne touche ni scope ni ledger) :
    GET console `/health` + sonde de la SOURCE DE DÉTECTION configurée. Imprime une checklist claire
    et DÉGRADE GRACIEUSEMENT si une dépendance est injoignable (ligne FAIL/N/A, jamais de crash).

    Si une source NON-legacy est configurée (env `FORGE_DETECTION_SOURCE`, kind ≠ plume/none) ->
    préflight généralisé via le collecteur. Sinon -> chemin legacy `PLUME_URL`/`PLUME_TOKEN` INCHANGÉ
    (rétro-compat : GET Plume `/api/coverage/detections?since=0`, Basic auth)."""
    src = _configured_source()
    if src is not None and str(src.get("kind", "")).strip() not in ("", "none", "plume"):
        return _doctor_source_preflight(args, src)

    console_url = console_client.base_url()            # respecte FORGE_CONSOLE_URL (défaut 127.0.0.1:7100)
    plume_url = os.environ.get("PLUME_URL", "").rstrip("/")
    plume_token = os.environ.get("PLUME_TOKEN", "")    # base64 de user:pass -> Authorization: Basic
    timeout = getattr(args, "timeout", None) or 8.0

    lines = []                                         # (state, label, detail)
    critical_ok = True

    # --- 1) console joignable (GET /health, non authentifié) ---
    st, body, err = _purple_get(console_url + "/health", timeout=timeout)
    if st == 200:
        lines.append(("ok", "console-reachable", f"{console_url}/health -> 200 {body.strip()[:16]}"))
    elif st is not None:
        lines.append(("fail", "console-reachable", f"{console_url}/health -> HTTP {st}"))
        critical_ok = False
    else:
        lines.append(("fail", "console-reachable", f"{console_url}/health injoignable ({err})"))
        critical_ok = False

    # --- 2) plume joignable + 3) auth-ok + 4) détections + 5) tag MITRE ---
    if not plume_url:
        lines.append(("fail", "plume-reachable", "PLUME_URL non configuré"))
        for lbl in ("auth-ok", "detections-returned", "mitre-tagged"):
            lines.append(("na", lbl, "PLUME_URL non configuré"))
        critical_ok = False
    else:
        purl = plume_url + "/api/coverage/detections?since=0"
        st, body, err = _purple_get(purl, basic_b64=(plume_token or None), timeout=timeout)
        if st is None:                                 # injoignable -> le reste est N/A (pas mesurable)
            lines.append(("fail", "plume-reachable", f"{purl} injoignable ({err})"))
            for lbl in ("auth-ok", "detections-returned", "mitre-tagged"):
                lines.append(("na", lbl, "Plume injoignable"))
            critical_ok = False
        else:
            lines.append(("ok", "plume-reachable", f"{purl} -> HTTP {st}"))
            if st in (401, 403):
                lines.append(("fail", "auth-ok", f"HTTP {st} — vérifier PLUME_TOKEN (base64 user:pass)"))
                for lbl in ("detections-returned", "mitre-tagged"):
                    lines.append(("na", lbl, "auth échouée"))
                critical_ok = False
            elif st != 200:
                lines.append(("fail", "auth-ok", f"HTTP {st} inattendu"))
                for lbl in ("detections-returned", "mitre-tagged"):
                    lines.append(("na", lbl, f"HTTP {st}"))
                critical_ok = False
            else:
                lines.append(("ok", "auth-ok", "HTTP 200 (Basic accepté)"))
                dets = _parse_detections(body)
                if dets is None:
                    lines.append(("fail", "detections-returned", "réponse JSON illisible"))
                    lines.append(("na", "mitre-tagged", "réponse illisible"))
                    critical_ok = False
                else:
                    n = len(dets)
                    # 0 détection = état valide (SOC frais) : informatif, pas un échec critique.
                    lines.append(("ok" if n else "info", "detections-returned", f"{n} règle(s)"))
                    if n == 0:
                        lines.append(("na", "mitre-tagged", "aucune détection à inspecter"))
                    else:
                        tagged = _count_mitre_tagged(dets)
                        if tagged:
                            lines.append(("ok", "mitre-tagged",
                                          f"champ technique Txxxx présent ({tagged}/{n})"))
                        else:
                            lines.append(("info", "mitre-tagged",
                                          "aucun champ technique Txxxx détecté"))

    if getattr(args, "json", False):
        print(json.dumps({"ok": critical_ok,
                          "checks": [{"check": lbl, "state": state, "detail": detail}
                                     for state, lbl, detail in lines]}))
        return 0 if critical_ok else 1

    verdict = "PRÊTE ✅" if critical_ok else "INCOMPLÈTE ⛔"
    print(f"=== forge doctor --purple — boucle purple {verdict} ===\n")
    for state, lbl, detail in lines:
        print(f"  [{_PURPLE_MARK.get(state, state):8}] {lbl:20} {detail}")
    print("\nNote : lecture seule — aucun tir, ni scope ni ledger touchés. Critiques = console/Plume "
          "joignables + auth. Détections/MITRE sont informatifs (0 détection = SOC frais, pas un échec).")
    return 0 if critical_ok else 1


def cmd_detections(args):
    """Collecteur de détections (délégué par la console pour les sources « messy »). Lit la SOURCE
    (`--source env:NOM` | `@fichier` | JSON littéral), INSTANCIE le collecteur du bon `kind`, et
    imprime `{"detections":[{mitre,count,first_ts}]}` sur stdout.

    CONTRAT fail-open lisible (ce que la console spawne et interprète) :
    - source JOIGNABLE (même 0 détection) -> stdout `{"detections":[...]}`, code 0 (reachable=True) ;
    - source INJOIGNABLE / mal configurée / kind inconnu -> code non nul + message RÉDIGÉ du secret
      sur stderr, stdout VIDE -> la console bascule en `source_reachable:false` sans rien fabriquer.
    Le secret d'auth n'est JAMAIS imprimé. `fetch()` du collecteur ne lève jamais ; c'est `reachable`
    qui distingue « joignable mais vide » de « injoignable »."""
    source = None
    try:
        source = collectors.load_source(args.source)
    except Exception as e:  # noqa: BLE001 — spec illisible : fail-open, message rédigé
        sys.stderr.write(collectors.safe_error(e, source) + "\n")
        return 1
    col = collectors.get_collector(source)
    if col is None:
        sys.stderr.write("kind de source non pris en charge par le collecteur Python: "
                         + str(source.get("kind", "none")) + "\n")
        return 1
    rows = col.fetch(args.since)              # ne lève jamais : [] sur erreur, positionne reachable
    if not col.reachable:
        sys.stderr.write(col.error_detail() + "\n")   # rédigé du secret
        return 1
    print(json.dumps({"detections": rows}, ensure_ascii=False, separators=(",", ":")))
    return 0


def _configured_source():
    """Résout la source de détection VISIBLE par la CLI (diagnostic) : env `FORGE_DETECTION_SOURCE`
    (JSON posé par la console), sinon repli rétro-compat `PLUME_URL`/`PLUME_TOKEN` -> preset `plume`,
    sinon None (non configurée -> boucle purple INERTE). Ne lève jamais."""
    raw = os.environ.get("FORGE_DETECTION_SOURCE", "").strip()
    if raw:
        try:
            return collectors.load_source("env:FORGE_DETECTION_SOURCE")
        except Exception:  # noqa: BLE001 — JSON illisible -> traité comme non configuré
            return None
    url = os.environ.get("PLUME_URL", "").strip()
    if url:
        return {"kind": "plume", "endpoint": url.rstrip("/"),
                "auth": {"type": "basic", "secret": os.environ.get("PLUME_TOKEN", "")}}
    return None


def _parse_map(spec):
    """Parse un mapping de colonnes générique 'target=host,title=name,severity=risk' -> dict.
    None/'' -> None (aucun remappage). Ignore les entrées mal formées (fail-safe, jamais de crash)."""
    if not spec:
        return None
    out = {}
    for pair in str(spec).split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            k, v = k.strip(), v.strip()
            if k and v:
                out[k] = v
    return out or None


def cmd_import(args):
    """`forge import` — ingère une SORTIE DE SCANNER EXISTANTE (nmap/nuclei/burp/httpx/ffuf/hosts/
    generic-json/generic-csv) en findings Forge ORIENTÉS PREUVE (jamais `vulnerable` : scanner ->
    `reported_by_tool`, recon -> `tested`). Auto-détecte le format (`--format auto`/défaut). Les secrets
    du fichier sont RÉDIGÉS avant tout finding. Avec `--scope`, applique le SCOPE-GUARD (`roe.Scope`) :
    les findings HORS périmètre sont JETÉS (défaut) ou MARQUÉS (`--flag-out-of-scope`, status=skipped).

    Sortie : `--json` -> enveloppe {format, counts, findings} ; sinon résumé lisible. `--console URL`
    (+ `--console-token`) ingère aussi les findings dans la console (POST /api/ingest). PUR DATA — zéro
    exécution, zéro I/O réseau de scan (le fichier est déjà produit). Codes : 0 OK, 2 erreur."""
    from . import importers
    path = Path(args.file)
    if not path.exists():
        raise SystemExit(f"forge import : fichier introuvable: {args.file}")
    try:
        fmt, findings = importers.parse_file(path, fmt=(args.format or "auto"),
                                             mapping=_parse_map(getattr(args, "map", None)))
    except ValueError as e:
        raise SystemExit(f"forge import : {e}")
    counts = {"parsed": len(findings), "in_scope": None, "out_of_scope": None, "emitted": len(findings)}
    if args.scope:
        scope = Scope.load(args.scope)
        findings, counts = importers.scope_filter(
            findings, scope, flag_out_of_scope=getattr(args, "flag_out_of_scope", False))
    envelope = {"format": fmt, "counts": counts, "findings": [f.to_dict() for f in findings]}
    if args.console:
        try:
            st, _resp = console_client.ingest(args.campaign, findings, [],
                                              url=args.console, token=args.console_token)
            envelope["console"] = {"status": st}
        except Exception as e:  # noqa: BLE001 — l'ingest console ne doit pas faire échouer le parse
            envelope["console"] = {"error": repr(e)}
    if getattr(args, "json", False):
        print(json.dumps(envelope))
        return 0
    print(f"# forge import — format={fmt} fichier={args.file}")
    print(f"parsed={counts['parsed']} in_scope={counts['in_scope']} "
          f"out_of_scope={counts['out_of_scope']} emitted={counts['emitted']}")
    for f in findings[:500]:
        print(f"  [{f.severity:8}] {f.status:16} {f.tool:16} {f.target}  {f.title}")
    if "console" in envelope:
        print(f"Console <- ingest: {envelope['console']}")
    return 0


def cmd_doctor(args):
    """Diagnostic : pour chaque module, dit s'il est OPÉRATIONNEL (sonde `.available`) et
    rappelle l'outil/service attendu + l'astuce d'install/config. Ne tire RIEN, ne touche pas
    le scope ni le ledger : sondes en lecture seule (which/docker, TCP connect, GET /health).

    `--purple` : bascule vers le préflight de la boucle purple (console /health + Plume détections)."""
    if getattr(args, "purple", False):
        return cmd_doctor_purple(args)
    mods  # noqa (déjà importé -> modules enregistrés)
    rows = []
    for k in mods.kinds():
        m = mods.get(k)
        dep, tip = _DOCTOR_HINTS.get(k, ("(dépendance non documentée)", ""))
        rows.append({"kind": k, "available": bool(getattr(m, "available", True)),
                     "dep": dep, "tip": tip})
    det_row = _detection_health_row()      # santé de la source de détection configurée (collecteur)
    if getattr(args, "json", False):
        print(json.dumps(rows + [det_row]))
        return 0
    ok = sum(1 for r in rows if r["available"])
    print(f"=== forge doctor — {ok}/{len(rows)} modules opérationnels ===\n")
    for r in rows:
        mark = "OK ✅" if r["available"] else "INDISPONIBLE ⛔"
        print(f"  [{mark:16}] {r['kind']}")
        print(f"      attendu : {r['dep']}")
        if not r["available"] and r["tip"]:
            print(f"      install : {r['tip']}")
    dmark = "OK ✅" if det_row["available"] else "INERTE / KO ⛔"
    print(f"\n  [{dmark:16}] {det_row['kind']}")
    print(f"      source  : {det_row['dep']}")
    print(f"      état    : {det_row['tip']}")
    print("\nNote : un module INDISPONIBLE est simplement auto-neutralisé (jamais tiré). Une source de "
          "détection INERTE (non configurée/injoignable) -> couverture purple fail-open lisible "
          "(source_reachable:false), jamais de métrique inventée. La gate ROE reste fail-closed.")
    return 0


def _detection_health_row():
    """Ligne de santé de la source de détection configurée, au format des rangées `doctor` (kind /
    available / dep / tip). Utilise `collector.doctor()` (LECTURE SEULE, ne lève jamais). Non configurée
    -> available:False + note « inerte » (état VALIDE, pas une erreur)."""
    src = _configured_source()
    if src is None:
        return {"kind": "detection.source", "available": False,
                "dep": "settings.detection_source / env FORGE_DETECTION_SOURCE / legacy PLUME_URL",
                "tip": "non configurée — couverture purple INERTE (fail-open lisible, aucune métrique inventée)"}
    col = collectors.get_collector(src)
    if col is None:
        return {"kind": "detection.source", "available": False,
                "dep": collectors.describe(src),
                "tip": f"kind inconnu du collecteur Python: {src.get('kind')}"}
    d = col.doctor()
    return {"kind": "detection.source", "available": bool(d.get("ok")),
            "dep": collectors.describe(src), "tip": d.get("detail", "")}


def cmd_demo(args):
    print("=== FORGE DEMO — aucune cible réelle, aucun I/O réseau ===\n")
    scope = Scope({"mode": "grey", "in_scope": ["demo.local"], "allow_exploit": False})
    tmp = Path(tempfile.mkdtemp(prefix="forge-demo-"))
    ledger = Ledger(tmp / "engagement.jsonl")
    eng = Engine(scope, ledger=ledger)
    action = Action(kind="demo.fingerprint", target="demo.local")
    oos = Action(kind="demo.fingerprint", target="not-in-scope.example")

    print("1) Hors scope -> VETO (jamais simulé ni tiré) :")
    print("   ", eng.execute(oos)["verdict"], "\n")

    print("2) In-scope mais NON armé -> DRY_RUN (simulation, aucun effet) :")
    r = eng.execute(action)
    print("   ", r["verdict"], "|", r["output"], "\n")

    print("3) Armement + approbation conscients -> FIRE :")
    eng.arm("demo"); eng.approve(action.id, "demo")
    r = eng.execute(action)
    print("   ", r["verdict"], "| findings:", len(eng.findings), "\n")

    print("4) Intégrité du ledger :")
    print("   ", ledger.verify(), "\n")

    print("5) Altération d'une ligne du ledger -> verify DOIT casser :")
    p = tmp / "engagement.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[-1]); rec["detail"] = {"tampered": True}
    lines[-1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("   ", ledger.verify())
    print(f"\n(ledger de démo : {tmp})")
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="forge", description="Forge — moteur red-team gated par ROE (sûreté d'abord).")
    # --version : source de vérité unique (fichier VERSION à la racine, via forge.__version__).
    # L'action `version` sort AVANT la vérif du sous-parseur requis -> `forge --version` seul marche.
    p.add_argument("--version", action="version", version=f"forge {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scope-check"); sc.add_argument("target"); sc.add_argument("--scope", required=True); sc.set_defaults(fn=cmd_scope_check)
    pl = sub.add_parser("plan"); pl.add_argument("--scope", required=True); pl.add_argument("--actions"); pl.set_defaults(fn=cmd_plan)
    rn = sub.add_parser("run")
    rn.add_argument("--scope", required=True); rn.add_argument("--actions")
    rn.add_argument("--arm", action="store_true"); rn.add_argument("--approve", nargs="*")
    rn.add_argument("--mode", choices=["propose", "auto"], default="propose")
    rn.add_argument("--ledger"); rn.add_argument("--report"); rn.add_argument("--reason"); rn.add_argument("--memory")
    rn.set_defaults(fn=cmd_run)
    cp = sub.add_parser("campaign")
    cp.add_argument("--scope", required=True); cp.add_argument("--targets", required=True)
    cp.add_argument("--arm", action="store_true"); cp.add_argument("--approve", nargs="*")
    cp.add_argument("--mode", choices=["propose", "auto"], default="propose")
    cp.add_argument("--budget", type=float); cp.add_argument("--exhaustive", action="store_true")
    cp.add_argument("--auto-pentest", dest="auto_pentest", action="store_true",
                    help="mode pentest automatisé : balaie TOUTES les techniques ACTIVÉES du scope (profil+toggles) sur la surface découverte, gouverné à l'identique")
    cp.add_argument("--modules", help="liste de kinds (séparés par des virgules) restreignant le plan ; vide = plan complet du cerveau")
    cp.add_argument("--workflow", help="nom d'un workflow SAUVEGARDÉ : lance EXACTEMENT ses étapes (techniques+params), filtrées par l'ensemble activé du scope + ROE (fail-closed)")
    cp.add_argument("--workflows", help="fichier JSON de workflows utilisateur (sinon env FORGE_WORKFLOWS_FILE ; les workflows intégrés sont toujours disponibles)")
    cp.add_argument("--ledger"); cp.add_argument("--report"); cp.add_argument("--purple")
    cp.add_argument("--reason"); cp.add_argument("--memory")
    cp.add_argument("--campaign", default="default"); cp.add_argument("--console"); cp.add_argument("--console-token")
    cp.add_argument("--run-id", dest="run_id")
    cp.set_defaults(fn=cmd_campaign)
    lv = sub.add_parser("ledger"); lvs = lv.add_subparsers(dest="lcmd", required=True)
    lvv = lvs.add_parser("verify"); lvv.add_argument("--ledger", required=True)
    lvv.add_argument("--pubkey", help="clé publique Ed25519 (hex) -> vérification externe sans secret (verify_external)")
    lvv.set_defaults(fn=cmd_ledger_verify)
    lvp = lvs.add_parser("pubkey"); lvp.add_argument("--ledger", required=True)
    lvp.set_defaults(fn=cmd_ledger_pubkey)
    lvk = lvs.add_parser("keygen"); lvk.add_argument("--ledger", required=True)
    lvk.add_argument("--force", action="store_true", help="ROTATION : écrase une clé existante (invalide les signatures déjà écrites)")
    lvk.set_defaults(fn=cmd_ledger_keygen)
    md = sub.add_parser("modules"); md.add_argument("--json", action="store_true"); md.set_defaults(fn=cmd_modules)
    tq = sub.add_parser("techniques", help="catalogue des techniques groupé par catégorie + état activé pour une sélection par-scope (JSON)")
    tq.add_argument("--json", action="store_true", help="sortie JSON (défaut : toujours JSON pour cette commande)")
    tq.add_argument("--selection", help="sélection par-scope : env:NOM | @fichier | JSON littéral {profile,techniques,categories} ; sinon env FORGE_TECHNIQUE_SELECTION")
    tq.set_defaults(fn=cmd_techniques)
    wf = sub.add_parser("workflows", help="workflows sauvegardés (pipelines composés) : intégrés (dérivés du registre) + fichier utilisateur (JSON)")
    wf.add_argument("--json", action="store_true", help="sortie JSON (défaut : toujours JSON pour cette commande)")
    wf.add_argument("--workflows", help="fichier JSON de workflows utilisateur (sinon env FORGE_WORKFLOWS_FILE)")
    wf.add_argument("--resolve", help="@scope.json : ajoute par workflow l'aperçu kept/dropped pour ce scope (fail-closed)")
    wf.set_defaults(fn=cmd_workflows)
    dc = sub.add_parser("doctor"); dc.add_argument("--json", action="store_true")
    dc.add_argument("--purple", action="store_true", help="préflight boucle purple : console /health + Plume /api/coverage/detections (lecture seule)")
    dc.add_argument("--timeout", type=float, default=8.0, help="timeout (s) des sondes HTTP du préflight --purple")
    dc.set_defaults(fn=cmd_doctor)
    im = sub.add_parser("import", help="ingère une sortie de scanner existante (nmap/nuclei/burp/httpx/ffuf/hosts/generic) en findings orientés preuve")
    im.add_argument("--format", default="auto", help="nmap|nuclei|burp|httpx|ffuf|hosts|generic-json|generic-csv|auto (défaut: auto-détection)")
    im.add_argument("--file", required=True, help="chemin du fichier de scan à importer")
    im.add_argument("--scope", help="scope.json : applique le scope-guard (findings hors périmètre jetés, ou marqués avec --flag-out-of-scope)")
    im.add_argument("--flag-out-of-scope", dest="flag_out_of_scope", action="store_true", help="conserver les findings hors-scope en les NEUTRALISANT (status=skipped, marqués) au lieu de les jeter")
    im.add_argument("--campaign", default="default", help="nom de campagne (pour --console)")
    im.add_argument("--map", help="mapping de colonnes générique: 'target=host,title=name,severity=risk,cwe=weakness'")
    im.add_argument("--json", action="store_true", help="sortie JSON enveloppe {format, counts, findings}")
    im.add_argument("--console", help="URL console pour ingérer aussi les findings (POST /api/ingest)")
    im.add_argument("--console-token", dest="console_token", help="token bearer console (sinon env FORGE_CONSOLE_TOKEN)")
    im.set_defaults(fn=cmd_import)
    dm = sub.add_parser("demo"); dm.set_defaults(fn=cmd_demo)
    de = sub.add_parser("detections")
    de.add_argument("--source", required=True, help="config de source : env:NOM | @fichier | JSON littéral (voie privilégiée: env, pour ne pas fuiter le secret via argv)")
    de.add_argument("--since", type=int, default=0, help="borne basse epoch (s) transmise à la source (0 = tout)")
    de.set_defaults(fn=cmd_detections)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

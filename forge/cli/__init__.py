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

Ce paquet remplace l'ancien module monolithique `forge/cli.py` : les commandes sont réparties par
domaine (`engine`, `ledger`, `purple`, `catalog`) et re-exportées ici pour préserver les chemins
d'import publics (`forge.cli.cmd_*`, `forge.cli.main`) et `python -m forge.cli`.
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

from .. import __version__
from ..roe import Scope, Action
from ..ledger import Ledger
from ..engine import Engine
from .. import modules as mods
from .. import techniques
from .. import collectors

from .engine import (_load_actions, _demo_actions, _load_targets, _workflows_path,  # noqa: F401
                     cmd_plan, cmd_run, cmd_campaign)
from .ledger import cmd_ledger_verify, cmd_ledger_pubkey, cmd_ledger_keygen
from .purple import (_purple_get, _parse_detections, _count_mitre_tagged,  # noqa: F401
                     _configured_source, _doctor_source_preflight, cmd_doctor_purple)
from .catalog import (_load_technique_selection, _parse_map,  # noqa: F401
                      cmd_techniques, cmd_workflows, cmd_detections, cmd_import)


def cmd_scope_check(args):
    scope = Scope.load(args.scope)
    verdict = "IN SCOPE ✅" if scope.is_in_scope(args.target) else "HORS SCOPE ⛔"
    print(f"{args.target} : {verdict}")
    print(f"  mode={scope.mode} allow_exploit={scope.allow_exploit} allow_destructive={scope.allow_destructive}")
    return 0 if scope.is_in_scope(args.target) else 1


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
        # SCHÉMA DE PARAMS servi à l'UI (formulaire de lancement dynamique) : liste de descripteurs
        # {name,type,label,flag,allowed?,default?}. ADDITIF (défaut [] : un module sans schéma est ignoré
        # par le renderer, comportement inchangé). Source unique : la classe du module (natifs = PARAMS_SCHEMA,
        # wrappers ToolSpec = spec.params_schema, tous deux exposés en attribut de classe PARAMS_SCHEMA).
        schema = getattr(m, "PARAMS_SCHEMA", None) or []
        params_schema = [dict(d) for d in schema if isinstance(d, dict)]
        # ALLOWLIST de drapeaux pour les extra_args (défense en profondeur server-side) : liste de flags.
        flag_allowlist = [str(f) for f in (getattr(m, "FLAG_ALLOWLIST", None) or ())]
        rows.append({"kind": k, "cls": k.split(".")[-1],
                     "exploit": bool(m.exploit), "destructive": bool(m.destructive),
                     "web_allowed": web_allowed,
                     "params_schema": params_schema,
                     "flag_allowlist": flag_allowlist,
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

    # Parent parser (add_help=False) des drapeaux d'ENGAGEMENT communs à `run` et `campaign` :
    # --scope/--arm/--approve/--mode/--ledger/--report/--reason/--memory sont IDENTIQUES (mêmes options,
    # mêmes propriétés) sur ces deux sous-commandes -> factorisés ici. Chaque sous-commande n'ajoute que
    # ses drapeaux propres. (--console/--console-token/--json restent en ligne : leurs propriétés — aide,
    # présence — diffèrent selon la sous-commande, donc non factorisables sans changer le comportement.)
    engage = argparse.ArgumentParser(add_help=False)
    engage.add_argument("--scope", required=True)
    engage.add_argument("--arm", action="store_true"); engage.add_argument("--approve", nargs="*")
    engage.add_argument("--mode", choices=["propose", "auto"], default="propose")
    engage.add_argument("--ledger"); engage.add_argument("--report")
    engage.add_argument("--reason"); engage.add_argument("--memory")
    engage.add_argument("--toolspec", action="append", default=[], metavar="FILE",
                        help="charge un ToolSpec déclaratif (JSON/YAML) et l'enregistre comme module gouverné "
                             "AVANT le plan ; répétable. Fail-CLOSED : spec invalide -> erreur nommant le fichier. "
                             "(voie env équivalente et fail-soft : FORGE_TOOLSPECS=<dossier>)")

    sc = sub.add_parser("scope-check"); sc.add_argument("target"); sc.add_argument("--scope", required=True); sc.set_defaults(fn=cmd_scope_check)
    pl = sub.add_parser("plan"); pl.add_argument("--scope", required=True); pl.add_argument("--actions"); pl.set_defaults(fn=cmd_plan)
    rn = sub.add_parser("run", parents=[engage])
    rn.add_argument("--actions")
    rn.set_defaults(fn=cmd_run)
    cp = sub.add_parser("campaign", parents=[engage])
    cp.add_argument("--targets", required=True)
    cp.add_argument("--budget", type=float); cp.add_argument("--exhaustive", action="store_true")
    cp.add_argument("--auto-pentest", dest="auto_pentest", action="store_true",
                    help="mode pentest automatisé : balaie TOUTES les techniques ACTIVÉES du scope (profil+toggles) sur la surface découverte, gouverné à l'identique")
    cp.add_argument("--modules", help="liste de kinds (séparés par des virgules) restreignant le plan ; vide = plan complet du cerveau")
    cp.add_argument("--workflow", help="nom d'un workflow SAUVEGARDÉ : lance EXACTEMENT ses étapes (techniques+params), filtrées par l'ensemble activé du scope + ROE (fail-closed)")
    cp.add_argument("--workflows", help="fichier JSON de workflows utilisateur (sinon env FORGE_WORKFLOWS_FILE ; les workflows intégrés sont toujours disponibles)")
    cp.add_argument("--purple")
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

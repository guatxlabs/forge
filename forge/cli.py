"""CLI Forge — `forge <commande>`.

Commandes :
  scope-check <target> --scope S      verdict d'appartenance (in/out scope)
  plan --scope S [--actions A]        liste les actions et leur verdict ROE (sans rien tirer)
  run  --scope S [--actions A] [--arm] [--approve KIND:TARGET ...] [--mode propose|auto]
                 [--ledger L] [--report R]
  ledger verify --ledger L [--pubkey HEX]  recalcule la chaîne et vérifie l'intégrité
                                           (--pubkey -> vérif externe par clé publique seule)
  modules                             liste les modules enregistrés
  doctor                              diagnostic : modules opérationnels + outil/service attendu
  demo                                démonstration bout-en-bout, sans aucune cible réelle

Sûreté : par défaut INERTE. `run` simule (DRY_RUN) tant que --arm ET --approve ne sont pas
posés. VETO (hors scope / capacité non autorisée) ne peut jamais être tiré.
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

from .roe import Scope, Roe, Action, VETO, DRY_RUN, FIRE
from .ledger import Ledger
from .engine import Engine
from .report import build_report
from .schema import Target
from .brain import HeuristicBrain
from .planner import Planner
from .memory import Memory
from . import purple
from . import modules as mods


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
    module_params = scope.module_params
    engine.campaign(targets, HeuristicBrain(), planner,
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


def cmd_modules(args):
    mods  # noqa (déjà importé -> enregistré)
    rows = []
    for k in mods.kinds():
        m = mods.get(k)
        rows.append({"kind": k, "cls": k.split(".")[-1],
                     "exploit": bool(m.exploit), "destructive": bool(m.destructive),
                     "available": bool(getattr(m, "available", True)),
                     "mitre": getattr(m, "mitre", "") or "",
                     "descr": getattr(m, "description", "") or ""})
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
}


def cmd_doctor(args):
    """Diagnostic : pour chaque module, dit s'il est OPÉRATIONNEL (sonde `.available`) et
    rappelle l'outil/service attendu + l'astuce d'install/config. Ne tire RIEN, ne touche pas
    le scope ni le ledger : sondes en lecture seule (which/docker, TCP connect, GET /health)."""
    mods  # noqa (déjà importé -> modules enregistrés)
    rows = []
    for k in mods.kinds():
        m = mods.get(k)
        dep, tip = _DOCTOR_HINTS.get(k, ("(dépendance non documentée)", ""))
        rows.append({"kind": k, "available": bool(getattr(m, "available", True)),
                     "dep": dep, "tip": tip})
    if getattr(args, "json", False):
        print(json.dumps(rows))
        return 0
    ok = sum(1 for r in rows if r["available"])
    print(f"=== forge doctor — {ok}/{len(rows)} modules opérationnels ===\n")
    for r in rows:
        mark = "OK ✅" if r["available"] else "INDISPONIBLE ⛔"
        print(f"  [{mark:16}] {r['kind']}")
        print(f"      attendu : {r['dep']}")
        if not r["available"] and r["tip"]:
            print(f"      install : {r['tip']}")
    print("\nNote : un module INDISPONIBLE est simplement auto-neutralisé (jamais tiré). "
          "La gate ROE reste fail-closed indépendamment de la disponibilité des outils.")
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
    cp.add_argument("--modules", help="liste de kinds (séparés par des virgules) restreignant le plan ; vide = plan complet du cerveau")
    cp.add_argument("--ledger"); cp.add_argument("--report"); cp.add_argument("--purple")
    cp.add_argument("--reason"); cp.add_argument("--memory")
    cp.add_argument("--campaign", default="default"); cp.add_argument("--console"); cp.add_argument("--console-token")
    cp.add_argument("--run-id", dest="run_id")
    cp.set_defaults(fn=cmd_campaign)
    lv = sub.add_parser("ledger"); lvs = lv.add_subparsers(dest="lcmd", required=True)
    lvv = lvs.add_parser("verify"); lvv.add_argument("--ledger", required=True)
    lvv.add_argument("--pubkey", help="clé publique Ed25519 (hex) -> vérification externe sans secret (verify_external)")
    lvv.set_defaults(fn=cmd_ledger_verify)
    md = sub.add_parser("modules"); md.add_argument("--json", action="store_true"); md.set_defaults(fn=cmd_modules)
    dc = sub.add_parser("doctor"); dc.add_argument("--json", action="store_true"); dc.set_defaults(fn=cmd_doctor)
    dm = sub.add_parser("demo"); dm.set_defaults(fn=cmd_demo)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

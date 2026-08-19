# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banc de détection multi-applications — point d'entrée.

    python3 -m bench.detection.run_bench --workdir /chemin/travail [--apps dvwa,vampi,...]
                                         [--track a|b|both] [--budget 900] [--keep-up]

DEUX PISTES, mesurées SÉPARÉMENT parce qu'elles ne disent pas la même chose :
  A  oracles AMORCÉS à la main sur la vuln connue  -> mesure le JUGEMENT (détection pure) ;
  B  campagne autonome (`--auto-pentest`)          -> mesure la CHAÎNE (découverte + jugement)
                                                      ET produit le volume où se comptent les FP.

SÛRETÉ : loopback strict (vérifié avant d'armer), périmètre borné au port de chaque application,
et modules interrogeant un tiers exclus (leur liste est écrite dans le rapport).

DÉMONTAGE SYSTÉMATIQUE. Les applications levées sont DÉLIBÉRÉMENT vulnérables : le démontage est
dans un `finally` et couvre TOUT ce qui porte le préfixe du banc — y compris un conteneur levé mais
resté muet, que l'ancien code retirait de sa propre liste de démontage. `--keep-up` permet de les
laisser debout ; c'est un choix explicite de l'opérateur, plus le défaut.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import groundtruth as gt
from . import harness, provision, seeded

FORGE_ROOT = Path(__file__).resolve().parents[2]


def scope_check(scope: Path, target: str) -> tuple[int, str]:
    p = subprocess.run(["python3", "-m", "forge.cli", "scope-check", target, "--scope", str(scope)],
                       cwd=FORGE_ROOT, capture_output=True, text=True)
    return p.returncode, harness.ANSI.sub("", p.stdout).strip()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--apps", default="dvwa,vampi,dvga,juiceshop")
    ap.add_argument("--track", default="both", choices=["a", "b", "both"])
    ap.add_argument("--budget", type=int, default=900, help="budget par campagne (s)")
    ap.add_argument("--no-bring-up", action="store_true")
    ap.add_argument("--keep-up", action="store_true",
                    help="NE PAS démonter en sortant (défaut : démontage systématique, y compris "
                         "sur erreur ou interruption)")
    ap.add_argument("--teardown", action="store_true",
                    help=argparse.SUPPRESS)     # conservé : le démontage est désormais le défaut
    args = ap.parse_args(argv)

    try:
        return _run(args)
    finally:
        # Le démontage appartient au `finally`, PAS à la fin du chemin heureux. Il était opt-in
        # (`--teardown`) et placé après la boucle : toute interruption — délai dépassé, exception,
        # Ctrl-C, refus de périmètre — laissait quatre applications délibérément vulnérables
        # levées. Mesuré le 2026-08-11 : un conteneur DVWA écoutait encore après coup.
        if not args.keep_up:
            # Aucune liste de ports passée ici : `teardown()` DÉRIVE les siens des conteneurs
            # qu'il retire. Lui donner les ports de toutes les applications connues revenait à
            # s'accuser d'un socket tenu par un conteneur étranger (mesuré le 2026-08-11).
            ok, restes = provision.teardown()
            if not ok:
                print(f"[!] DÉMONTAGE INCOMPLET — subsiste : {restes}", file=sys.stderr)


def _run(args):
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)
    apps = [a.strip() for a in args.apps.split(",") if a.strip()]

    if not args.no_bring_up:
        up = provision.bring_up(apps)
        missing = [a for a in apps if a not in up]
        if missing:
            print(f"[!] applications injoignables : {missing}", file=sys.stderr)
        apps = up

    ports = [gt.APPS[a].host_port.split(":")[1] for a in apps]
    ok, lines = provision.verify_loopback_only(ports)
    print("[*] sockets d'écoute du banc :")
    for ln in lines:
        print("     ", ln.strip())
    if not ok:
        print("[!] REFUS : une application du banc écoute hors de la boucle locale.", file=sys.stderr)
        return 2

    safe = harness.loopback_safe_modules(provision.THIRD_PARTY_MODULES)
    (work / "modules_loopback_safe.json").write_text(
        json.dumps({"exclus_tiers": list(provision.THIRD_PARTY_MODULES), "retenus": safe},
                   indent=2, ensure_ascii=False), encoding="utf-8")

    manifest = {"apps": {}, "modules_exclus_tiers": list(provision.THIRD_PARTY_MODULES),
                "budget_par_campagne_s": args.budget}

    for name in apps:
        app = gt.APPS[name]
        wd = work / name
        wd.mkdir(parents=True, exist_ok=True)
        print(f"\n=== {name} ({app.stack}) ===")

        auth = provision.prime(name)
        scope_p = wd / "scope.json"
        targets_p = wd / "targets.json"
        provision.write_scope(app, auth, scope_p, allow_exploit=True)
        provision.write_targets(app, targets_p)

        rc, verdict = scope_check(scope_p, app.base_url)
        print(f"[*] scope-check {app.base_url} -> rc={rc} {verdict.splitlines()[0] if verdict else ''}")
        if rc != 0:
            print(f"[!] {name} : cible hors périmètre — on n'arme pas.", file=sys.stderr)
            continue
        rc_out, _ = scope_check(scope_p, "http://example.com")
        print(f"[*] scope-check contre-épreuve (example.com) -> rc={rc_out} (1 attendu)")

        entry = {"stack": app.stack, "truth_source": app.truth_source,
                 "primed": auth.declared, "scope": json.loads(scope_p.read_text()),
                 "scope_check_in": rc, "scope_check_out": rc_out, "tracks": {}}
        entry["scope"].pop("session", None)          # jamais de secret dans le manifeste
        entry["scope"].pop("auth", None)

        if args.track in ("a", "both"):
            acts = seeded.build(app, auth)
            acts_p = wd / "actions.json"
            acts_p.write_text(json.dumps(acts, indent=2, ensure_ascii=False), encoding="utf-8")
            r = harness.run_forge("A", name, wd, scope_p, actions=acts_p, timeout_s=args.budget)
            print(f"[A] rc={r.returncode} {r.seconds:.0f}s findings={len(r.findings)} "
                  f"partiel={r.partial}")
            print("   ", r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "")
            entry["tracks"]["A"] = {"seconds": round(r.seconds, 1), "rc": r.returncode,
                                    "findings": len(r.findings), "partial": r.partial,
                                    "actions": len(acts), "stdout": r.stdout.strip()[-800:]}

        if args.track in ("b", "both"):
            r = harness.run_forge("B", name, wd, scope_p, targets=targets_p, modules=safe,
                                  auto_pentest=True, timeout_s=args.budget)
            print(f"[B] rc={r.returncode} {r.seconds:.0f}s findings={len(r.findings)} "
                  f"partiel={r.partial}")
            print("   ", r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "")
            entry["tracks"]["B"] = {"seconds": round(r.seconds, 1), "rc": r.returncode,
                                    "findings": len(r.findings), "partial": r.partial,
                                    "stdout": r.stdout.strip()[-2000:]}

        manifest["apps"][name] = entry
        (work / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False),
                                            encoding="utf-8")

    print(f"\n[*] manifeste -> {work / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Driver de démo — FIRE le module synthétique demo.fingerprint puis ingère vers la console.

NE MODIFIE PAS le code source Forge : réutilise Scope/Engine/Action + console_client tels quels.
Voie non-exploit, non-destructive, zéro I/O réseau (demo.fingerprint produit un finding synthétique).
Équivalent de `forge campaign --console` mais avec une liste d'actions explicite (le brain par défaut
ne propose pas demo.fingerprint).
"""
import os
import sys

from forge.roe import Scope, Action
from forge.engine import Engine
from forge import console_client


def main():
    scope = Scope.load("scope.json")
    engine = Engine(scope, mode="propose")
    engine.arm("demo_ingest: populate console UI (authorized own domain)")
    actions = [Action(kind="demo.fingerprint", target="guatx.com", desc="demo synthetic fingerprint")]
    for a in actions:
        engine.approve(a.id, "demo_ingest approval")
    engine.run(actions)

    cov = engine.coverage()
    print(f"Tirées={len(cov['fired'])} Simulées={len(cov['dry_run'])} "
          f"Refusées={len(cov['vetoed'])} Findings={len(engine.findings)} "
          f"Run-records={len(engine.run_records)}")

    token = os.environ.get("FORGE_CONSOLE_TOKEN", "")
    url = os.environ.get("FORGE_CONSOLE_URL", "http://127.0.0.1:7101")
    st, resp = console_client.ingest("demo-guatx", engine.findings, engine.run_records,
                                     url=url, token=token)
    print(f"Console <- ingest (HTTP {st}): {resp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

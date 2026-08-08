# SPDX-License-Identifier: AGPL-3.0-or-later
"""BANC — mutualisation `web.nuclei` par hôte : invocations et temps, AVANT / APRÈS.

Ce banc mesure l'**ORCHESTRATION**, pas nuclei : le binaire est DOUBLÉ par un script qui dort le
temps modélisé puis émet du JSONL. Aucun réseau, aucun binaire externe, aucun docker (`shutil.which`
est doublé pour ne trouver QUE le faux nuclei).

MODÈLE DE COÛT — calibré sur le binaire RÉEL (`projectdiscovery/nuclei` v3.11.0, `docker run --rm`,
cibles mortes en loopback, `-severity info,low,medium,high,critical`) :

    1 cible  -> 26,0 s        20 cibles -> 23,7 s
    5 cibles -> 27,0 s        => coût FIXE ~25 s, cible marginale DANS LE BRUIT

⚠️ PORTÉE DE CE CALIBRAGE — CIBLES MORTES SEULEMENT (mesuré, 2026-08-08). Les chiffres ci-dessus
viennent de cibles en loopback qui ne répondent PAS : nuclei n'y fait que charger ses templates,
d'où le coût fixe. Contre un hôte VIVANT, le coût marginal par cible est du même ORDRE que
l'allocation `_TIMEOUT_PER_TARGET` (120 s) : sur le run réel, les lots de 6, 11 et 17 ont TOUS été
tués à leur mur (1202,67 s pour 1200 · 1802,61 s pour 1800 · 2521,68 s pour 2520). Le gain
d'ORCHESTRATION que ce banc mesure reste vrai — c'est bien le rechargement de templates qu'on
économise — mais il ne faut PAS en déduire qu'un gros lot tient dans son budget : il ne le tient pas.
C'est ce qui a coûté +26 % de dépassement au run du 2026-08-08 (cf. `bench_run_budget_overshoot.py`).

Le coût d'une invocation nuclei est donc quasi ENTIÈREMENT fixe (chargement de la base de templates).
Le banc tourne à deux ratios `marginal/fixe` :
  · `0.00` — le ratio MESURÉ ci-dessus ;
  · `0.20` — un ratio DÉLIBÉRÉMENT défavorable au regroupement (on suppose une cible marginale à 20 %
    d'une invocation entière), pour montrer que le gain ne dépend pas d'une hypothèse optimiste.
Les durées sont mises à l'échelle 1/100 (fixe = 0,25 s) pour que le banc tourne en secondes.

Usage :
    python3 tests/bench_nuclei_batch.py [--repeat 3] [--pool 4]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forge import runner                                        # noqa: E402
from forge.modules import web as webmod                         # noqa: E402
from forge.modules.web import NucleiScan, coalesce_nuclei, norm_target   # noqa: E402
from forge.roe import Action                                    # noqa: E402

#: coût FIXE d'une invocation nuclei, mis à l'échelle 1/100 du réel mesuré (25 s -> 0,25 s).
FIXED_SECS = 0.25
#: échelle appliquée aux mesures pour extrapoler au réel.
SCALE = 100

#: les 65 cibles `web.nuclei` RÉELLEMENT tirées par la campagne (ledger signé gxrun2, verdicts FIRE).
from tests.test_web_nuclei_batch import _REAL_CAMPAIGN_TARGETS   # noqa: E402


def corpus_43():
    """43 URLs / plusieurs hôtes — la forme demandée, taillée dans le corpus RÉEL (préfixe stable)."""
    return _REAL_CAMPAIGN_TARGETS[:43]


FAKE = """#!/usr/bin/env python3
import sys, time, json
argv = sys.argv[1:]
targets = argv[argv.index("-u") + 1].split(",") if "-u" in argv else []
time.sleep({fixed} + {per} * len(targets))
for t in targets:
    if t.endswith("/"):                      # un hit sur une cible sur deux, de forme réaliste
        print(json.dumps({{"template-id": "robots-txt-endpoint",
                           "matched-at": t + "robots.txt",
                           "info": {{"name": "robots.txt", "severity": "info"}}}}))
"""


class _Bench:
    def __init__(self, per_target_ratio):
        # Ce banc n'est PAS un TestCase (pas d'`addCleanup`) : la suppression est garantie par le
        # `__exit__` du gestionnaire de contexte ci-dessous, appelé en toutes circonstances
        # (`with _Bench(...)`), exception comprise.
        self.dir = tempfile.mkdtemp(prefix="nucbench-", dir=os.environ.get("TMPDIR") or None)  # tmpdir-ok
        path = os.path.join(self.dir, "nuclei")
        with open(path, "w") as fh:
            fh.write(FAKE.format(fixed=FIXED_SECS, per=FIXED_SECS * per_target_ratio))
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        self.path = path
        self.calls = 0

    def __enter__(self):
        self._orig_which = runner.shutil.which
        bench = self

        def which(name):                     # ni docker, ni nuclei système : SEUL le double existe
            bench.calls += 0
            return bench.path if name == "nuclei" else None

        runner.shutil.which = which
        return self

    def __exit__(self, *exc):
        runner.shutil.which = self._orig_which
        shutil.rmtree(self.dir, ignore_errors=True)
        return False


def scoped(target, targets=None):
    p = {"in_scope": ["*.com"], "out_scope": []}
    if targets:
        p["targets"] = list(targets)
    return Action("web.nuclei", target, params=p)


def _run(actions, pool):
    mod = NucleiScan()
    if pool <= 1:
        return [f for a in actions for f in mod.fire(a)]
    with ThreadPoolExecutor(max_workers=pool) as ex:
        return [f for chunk in ex.map(mod.fire, actions) for f in chunk]


def covered_urls(findings, urls):
    """URLs du corpus qu'un jeu de findings COUVRE — même notion de surface que le module :
    une URL est couverte dès qu'un finding porte SA surface normalisée, ou une surface qui en
    DESCEND (`…/robots.txt` couvre `…/`). C'est l'invariant que le banc doit voir INCHANGÉ entre
    l'avant et l'après : mutualiser ne doit pas acheter du temps avec des trous."""
    surfaces = [norm_target(f.target) for f in findings]
    out = set()
    for u in urls:
        n = norm_target(u)
        if any(s == n or s.startswith(n + "/") or s.startswith(n + "?") or s.startswith(n + ":")
               for s in surfaces):
            out.add(u)
    return out


def measure(urls, pool, per_ratio, repeat):
    """(avant, après) — chacun : (invocations, secondes, findings, URLs couvertes)."""
    out = []
    for coalesced in (False, True):
        best = None
        for _ in range(repeat):
            actions = ([scoped(u) for u in urls] if not coalesced
                       else coalesce_nuclei([scoped(u) for u in urls], max_batch=100))
            with _Bench(per_ratio):
                t0 = time.monotonic()
                findings = _run(actions, pool)
                dt = time.monotonic() - t0
            row = (len(actions), dt, len(findings), len(covered_urls(findings, urls)))
            best = row if best is None or row[1] < best[1] else best
        out.append(best)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repeat", type=int, default=3, help="répétitions (on garde la plus rapide)")
    ap.add_argument("--pool", type=int, default=4, help="parallélisme intra-vague (profil balanced=4)")
    args = ap.parse_args()

    print(f"double nuclei : coût fixe {FIXED_SECS}s == {FIXED_SECS * SCALE:.0f}s réels "
          f"(mesuré : 1 cible=26,0s · 5=27,0s · 20=23,7s)\n")
    for label, urls in (("43 URLs (forme demandée)", corpus_43()),
                        ("65 URLs (corpus RÉEL gxrun2)", _REAL_CAMPAIGN_TARGETS)):
        hosts = len({webmod.host_of(u) for u in urls})
        print(f"=== {label} — {len(urls)} URLs, {hosts} hôtes ===")
        for per_ratio in (0.00, 0.20):
            for pool in (1, args.pool):
                (n0, t0, f0, c0), (n1, t1, f1, c1) = measure(urls, pool, per_ratio, args.repeat)
                print(f"  marginal/fixe={per_ratio:.2f}  pool={pool}")
                print(f"     AVANT : {n0:3d} invocations  {t0:6.2f}s  "
                      f"(~{t0 * SCALE / 60:5.1f} min réels)  {f0} findings  {c0}/{len(urls)} URLs couvertes")
                print(f"     APRÈS : {n1:3d} invocations  {t1:6.2f}s  "
                      f"(~{t1 * SCALE / 60:5.1f} min réels)  {f1} findings  {c1}/{len(urls)} URLs couvertes")
                print(f"     GAIN  : -{n0 - n1} invocations ({(1 - n1 / n0) * 100:.0f} %)  "
                      f"| temps x{t0 / t1:.1f}  (-{(1 - t1 / t0) * 100:.0f} %)  "
                      f"| ~{(t0 - t1) * SCALE / 60:.1f} min réels économisées")
                assert c1 == c0 == len(urls), (
                    f"COUVERTURE PERDUE : {c0} URLs couvertes avant, {c1} après "
                    f"(sur {len(urls)}) — le gain serait payé en trous invisibles")
        print()
    print(json.dumps({"note": "temps = orchestration seule ; nuclei est doublé. "
                              "Le gain en INVOCATIONS est exact et indépendant du modèle de coût."}))


if __name__ == "__main__":
    main()

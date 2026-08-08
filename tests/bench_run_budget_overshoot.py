# SPDX-License-Identifier: AGPL-3.0-or-later
"""BANC — DÉPASSEMENT du budget de temps, AVANT / APRÈS la gate de budget.

CE QU'ON MESURE, ET POURQUOI PAS AUTRE CHOSE. Un test qui vérifie « le timeout est bien calculé » ne
dit RIEN du dépassement. La seule grandeur qui intéresse un exploitant est celle-ci :

    dépassement = (écoulé réel à l'arrêt) − (budget demandé)

Ce banc la produit sur un scénario qui reproduit la FORME du run réel du 2026-08-08 : une action
LONGUE démarrée peu avant l'échéance, alors qu'il ne reste PLUS ASSEZ de budget pour elle.

CALIBRAGE — les chiffres du scénario 1 sont ceux du run réel, pas des valeurs choisies :

    budget demandé                          6000 s   (`--run-timeout 100m`)
    tout ce qui a tourné avant le tir fatal 5054,3 s (dernière action appliquée à t=5055 s)
    budget restant au moment du tir          945,7 s
    borne DURE du tir (lot nuclei de 17)     2520 s   (`600 + 120*(17-1)`)
    durée mesurée du tir                     2521,68 s -> il a été TUÉ à son mur (rc=124)
    -> dépassement observé                   1575,7 s, soit +26,3 %  (ledger : 7576 s pour 6000 s)

LE TEMPS EST INJECTÉ, JAMAIS ATTENDU (scénario 1). L'horloge est VIRTUELLE : elle n'avance que du
travail MODÉLISÉ par les modules (`VClock.spend`), et `Budget` la reçoit par injection. Le banc
mesure donc l'arithmétique du moteur à pleine échelle (6000 s de budget) en quelques millisecondes.

Le scénario 2 mesure la MÊME chose en temps RÉEL sur le chemin PARALLÈLE (vrai `ThreadPoolExecutor`,
vrais `sleep`), à l'échelle 1/1000 — parce qu'une horloge virtuelle n'a pas de sens quand quatre
tirs avancent le temps en même temps, et qu'il faut quand même prouver le gain sous l'ordonnanceur
réel. Un banc a le droit de dormir ; les TESTS, eux, n'attendent jamais (cf. `test_run_budget_gate`).

Usage :
    python3 tests/bench_run_budget_overshoot.py [--repeat 3] [--pool 4]
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forge.engine import Engine                                    # noqa: E402
from forge.interrupt import Budget, GracefulStop, Terminate        # noqa: E402
from forge.modules import registry                                 # noqa: E402
from forge.roe import Action, Scope                                # noqa: E402

HOST = "bench.budget.test"
KIND = "bench.work"

# --- chiffres du run réel (ledger signé gxrun3 + sidecar .durations) -------------------------------
REAL_BUDGET = 6000.0
REAL_BEFORE_FATAL = 5054.3        # tout ce qui a tourné avant le tir fatal
REAL_FATAL_BOUND = 2520.0         # 600 + 120*(17-1) — la borne DURE du lot de 17
REAL_OVERSHOOT = 1575.7           # mesuré : 7575,7 s écoulées pour 6000 s demandées


class VClock:
    """Horloge VIRTUELLE : le temps n'est pas ATTENDU, il est AVANCÉ par le travail modélisé.

    C'est ce qui permet de mesurer un budget de 100 minutes en quelques millisecondes, SANS jamais
    dormir et sans dépendre de la charge de la machine — la mesure est exacte et reproductible."""

    def __init__(self):
        self.t = 0.0
        self._lk = threading.Lock()

    def __call__(self):
        return self.t

    def spend(self, secs):
        with self._lk:
            self.t += float(secs)


class _Modelled(registry.Module):
    """Module de banc : `bound` est la borne DURE qu'il DÉCLARE, `d` la durée qu'il CONSOMME.

    Modéliser `d == bound` (défaut) reproduit exactement le cas mesuré : un outil TUÉ à son mur,
    donc une action qui coûte sa borne entière. Aucun réseau, aucun sous-process."""

    kind = KIND
    exploit = False
    web_allowed = True
    mitre = "T9999"
    clock = None                              # VClock | None (None -> temps RÉEL, scénario 2)

    def max_runtime(self, action):
        return action.params.get("bound")     # None => module SANS borne déclarée (non gaté)

    def dry(self, action):
        return "# bench dry"

    def fire(self, action):
        d = float(action.params.get("d", action.params.get("bound") or 0.0))
        if _Modelled.clock is not None:
            _Modelled.clock.spend(d)          # temps VIRTUEL : instantané
        else:
            time.sleep(d)                     # temps RÉEL (scénario 2)
        return []


class _registered:
    def __enter__(self):
        self._prev = registry.REGISTRY.get(KIND)
        registry.REGISTRY[KIND] = _Modelled
        return self

    def __exit__(self, *exc):
        if self._prev is None:
            registry.REGISTRY.pop(KIND, None)
        else:
            registry.REGISTRY[KIND] = self._prev
        return False


def _act(name, bound, d=None):
    p = {"bound": bound}
    if d is not None:
        p["d"] = d
    a = Action(KIND, HOST, desc=name, params=p)
    a.id = f"{KIND}:{name}"                   # id unique (sinon kind:target pour toutes)
    return a


def _run(actions, budget_secs, clock, gated):
    """Exécute `actions` sous un budget, avec ou SANS la gate. Rend (écoulé, résultats)."""
    budget = Budget(budget_secs, clock=clock) if clock is not None else Budget(budget_secs)
    stop = GracefulStop(budget=budget)
    scope = Scope({"mode": "grey", "in_scope": [HOST], "allow_exploit": True,
                   "allow_destructive": False})
    eng = Engine(scope, mode="auto", stop=stop.reason,
                 remaining=(budget.remaining if gated else None))
    eng.arm("bench")
    try:
        eng.run(list(actions))
    except Terminate:
        pass
    return budget.elapsed(), eng.results


def _tally(results):
    fired = sum(1 for r in results if r["verdict"] == "FIRE")
    skipped = [r for r in results if r["verdict"] == "SKIP"]
    return fired, skipped


# ===================================================================================================
def scenario_virtual(pool):
    """SCÉNARIO 1 — horloge VIRTUELLE, chemin SÉRIEL, à l'échelle du run réel.

    Le chemin sériel est le bon modèle du run réel : la vague y était drainée PAR INDICE, et le tir
    fatal était en TÊTE — le moteur est resté bloqué dessus 2515 s sans appliquer quoi que ce soit
    (mesuré au ledger : aucune action appliquée entre t=5055 s et t=7570 s)."""
    os.environ["FORGE_PARALLELISM"] = "1"
    plan = [
        _act("bulk", REAL_BEFORE_FATAL),          # tout ce qui a tourné avant le tir fatal
        _act("nuclei-lot-17", REAL_FATAL_BOUND),  # le lot de 17, tué à son mur de 2520 s
    ] + [_act(f"suite-{i}", 90.0) for i in range(10)]   # du travail COURT derrière lui

    out = {}
    for gated in (False, True):
        clock = VClock()
        _Modelled.clock = clock
        try:
            elapsed, results = _run(plan_copy(plan), REAL_BUDGET, clock, gated)
        finally:
            _Modelled.clock = None
        fired, skipped = _tally(results)
        out["APRÈS" if gated else "AVANT"] = (elapsed, fired, skipped)
    return out


def plan_copy(plan):
    return [_act(a.desc, a.params["bound"], a.params.get("d")) for a in plan]


def scenario_wallclock(pool, repeat):
    """SCÉNARIO 2 — temps RÉEL, chemin PARALLÈLE (`FORGE_PARALLELISM`), échelle 1/1000.

    Même forme : beaucoup de travail court, puis UNE action longue qui ne tient plus dans ce qu'il
    reste, puis encore du travail court. Les durées sont divisées par 1000 (budget 6,0 s) pour que le
    banc tourne en secondes ; le RATIO borne/budget restant est celui du run réel."""
    os.environ["FORGE_PARALLELISM"] = str(pool)
    S = 1 / 1000.0
    filler = [_act(f"f{i}", 0.5, 0.5) for i in range(40)]
    plan = filler + [_act("nuclei-lot-17", REAL_FATAL_BOUND * S, REAL_FATAL_BOUND * S)] \
        + [_act(f"g{i}", 0.5, 0.5) for i in range(20)]

    out = {}
    for gated in (False, True):
        best = None
        for _ in range(repeat):
            _Modelled.clock = None            # temps RÉEL
            elapsed, results = _run(plan_copy(plan), 6.0, None, gated)
            fired, skipped = _tally(results)
            if best is None or elapsed < best[0]:
                best = (elapsed, fired, skipped)
        out["APRÈS" if gated else "AVANT"] = best
    return out


def _report(title, budget, data):
    print(f"\n=== {title} (budget demandé : {budget:g}s) ===")
    print(f"  {'':<7} {'écoulé':>11} {'dépassement':>14} {'%':>8} {'tirées':>8} {'skip budget':>12}")
    for label in ("AVANT", "APRÈS"):
        elapsed, fired, skipped = data[label]
        over = elapsed - budget
        nb = sum(1 for s in skipped if "budget de temps restant" in " ".join(s["reasons"]))
        print(f"  {label:<7} {elapsed:>10.1f}s {over:>+13.1f}s {100*over/budget:>+7.1f}% "
              f"{fired:>8} {nb:>12}")
    for label in ("AVANT", "APRÈS"):
        for s in data[label][2]:
            if "budget de temps restant" in " ".join(s["reasons"]):
                print(f"  [{label}] SKIP NOMMÉ -> {s['action']}\n           {s['reasons'][0]}")
                break


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--pool", type=int, default=4)
    args = ap.parse_args()
    saved = os.environ.get("FORGE_PARALLELISM")
    with _registered():
        try:
            print("RÉFÉRENCE — run réel du 2026-08-08 (ledger signé gxrun3) : "
                  f"{REAL_BUDGET + REAL_OVERSHOOT:.0f}s écoulées pour {REAL_BUDGET:.0f}s demandées "
                  f"(+{100*REAL_OVERSHOOT/REAL_BUDGET:.1f} %)")
            _report("SCÉNARIO 1 — horloge injectée, chemin SÉRIEL, échelle réelle",
                    REAL_BUDGET, scenario_virtual(args.pool))
            _report(f"SCÉNARIO 2 — temps réel, chemin PARALLÈLE (pool={args.pool}), échelle 1/1000",
                    6.0, scenario_wallclock(args.pool, args.repeat))
        finally:
            if saved is None:
                os.environ.pop("FORGE_PARALLELISM", None)
            else:
                os.environ["FORGE_PARALLELISM"] = saved
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

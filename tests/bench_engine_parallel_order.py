# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banc — ORDRE DE SOUMISSION intra-vague (longest-processing-time-first).

CE QUE CE BANC MESURE. `engine._run_parallel` applique les résultats SÉRIELLEMENT, dans l'ordre
d'action, mais SOUMET les tirs à un pool borné via une fenêtre glissante de `2 x pool`. La fenêtre
a supprimé le blocage de TÊTE ; elle ne dit RIEN de l'ORDRE dans lequel le travail est soumis. Or
le planner trie par EV = value*confidence/cost : un coût ÉLEVÉ (== une action LENTE, cf. la table
`brain._CONTENT_SCANNER_EV` qui annote littéralement « LENT » / « TRÈS LENT ») donne une EV BASSE,
donc une place en FIN DE VAGUE. Les actions les plus longues arrivent systématiquement en dernier :
quand elles démarrent, il ne reste plus rien pour occuper les autres workers, qui se vident.

Ce banc chiffre ce trou sur trois FORMES de vague, à stubs de durée FIXÉE (aucun réseau, aucun DNS :
les cibles sont des IP littérales publiques RFC5737) :

  A. `straggler`  — la forme RÉELLE d'une vague ordonnée par le planner : beaucoup d'actions courtes
                    devant, une poignée de très lentes (testssl/nikto/feroxbuster) en QUEUE.
  B. `queue-large` — la queue lente contient AU MOINS `pool` actions : elles remplissent le pool à
                    elles seules. CONTRÔLE : l'ordonnancement ne peut pas y gagner grand-chose.
  C. `uniform`    — toutes les actions ont la même durée ET le même coût. CONTRÔLE NÉGATIF : aucun
                    ordonnancement possible, donc AUCUNE régression tolérée.

STRATÉGIES COMPARÉES. Le banc pilote le seam `Engine._preheat_order` (le SEUL point qui décide de
QUOI est mis au four d'avance ; l'ordre d'APPLICATION n'en dépend jamais) :

  - `index`    : préchauffage VIDE -> `_fill` retombe sur la fenêtre glissante en ordre d'indice,
                 c'est-à-dire le comportement AVANT ce chantier. C'est à la fois la MESURE DE
                 RÉFÉRENCE et la MUTATION (retirer l'ordonnancement doit faire disparaître le gain).
  - `duration` : le seam LIVRÉ — les paliers de `action.cost` les plus élevés, palier complet ou rien.
  - `serial`   : `FORGE_PARALLELISM=1`, le plancher sériel, pour situer les deux autres.

CHIFFRES MESURÉS (pool=4, 5 répétitions, médiane) — `index -> duration` :
  straggler    2,45 s -> 1,83 s  (-25 %) | 1,36x -> 1,02x le plancher travail/pool | sériel 7,24 s
  queue-large  3,08 s -> 3,08 s  (no-op) | déjà à 1,03x du plancher : rien à gagner, rien à perdre
  uniform      1,21 s -> 1,21 s  (no-op) | coût unique -> aucun préchauffage, chemin historique
À pool=8 le gain s'étend : straggler -19 %, queue-large -15 % (à 8 workers, la queue lente ne
remplit plus le pool à elle seule). À pool=2 tout est déjà au plancher : no-op partout.

Le banc n'est PAS collecté par pytest/unittest (préfixe `bench_`, pas `test_`) : il se lance à la
main, il dort pour de vrai, et un chiffre au wall-clock n'a rien à faire dans une suite. Les tests
de non-régression correspondants sont STRUCTURELS (ordre de DÉMARRAGE observé), dans
`tests/test_engine_parallel.py`.

Usage :
    python3 tests/bench_engine_parallel_order.py                  # 3 formes, pool=4, 3 répétitions
    python3 tests/bench_engine_parallel_order.py --repeat 5 --pool 8
    python3 tests/bench_engine_parallel_order.py --shape straggler --no-serial
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.engine import Engine                              # noqa: E402
from forge.modules import registry                           # noqa: E402
from forge.planner import Planner                            # noqa: E402
from forge.roe import Action, Scope                          # noqa: E402
from forge.schema import Finding                             # noqa: E402

# --- table de durées par kind ------------------------------------------------------------------
# `cost` reprend VERBATIM `brain._CONTENT_SCANNER_EV` (la table que le dépôt porte déjà) ; `secs` est
# la durée SIMULÉE, choisie pour respecter le même ordre de grandeur relatif que l'annotation de cette
# table (« quasi-instantané » / « LENT » / « TRÈS LENT »), divisée pour que le banc tienne en ~1 min.
#                     kind                    value  conf  cost   secs
KINDS = {
    "recon.httpx":          {"ev": (0.9, 0.9, 1.0), "secs": 0.03},   # 1 requête, fingerprint
    "web.security_headers": {"ev": (0.9, 0.85, 1.0), "secs": 0.03},  # 1 GET
    "web.nuclei":           {"ev": (0.9, 0.8, 1.0), "secs": 0.20},   # templates medium+
    "recon.tech":           {"ev": (0.8, 0.75, 1.0), "secs": 0.03},
    "recon.waf":            {"ev": (0.6, 0.6, 1.0), "secs": 0.03},
    "recon.content":        {"ev": (0.4, 0.4, 2.0), "secs": 0.60},   # feroxbuster/ffuf — LENT
    "web.nikto":            {"ev": (0.35, 0.4, 2.0), "secs": 0.60},  # LENT
    "web.testssl":          {"ev": (0.3, 0.4, 3.0), "secs": 1.20},   # TRÈS LENT
}

# cibles = IP LITTÉRALES publiques (RFC5737 TEST-NET-2/3) -> `resolve_target_ips` court-circuite,
# ZÉRO DNS, ZÉRO réseau : le wall-clock ne mesure que l'ordonnancement.
_HOSTS = [f"198.51.100.{i}" for i in range(1, 41)] + [f"203.0.113.{i}" for i in range(1, 41)]

_SECS: dict[str, float] = {}          # (kind, target) aplati en "kind|target" -> durée du fire()


class _SleepModule(registry.Module):
    """Stub : `fire()` DORT la durée fixée pour (kind, cible) puis rend un finding déterministe.
    `time.sleep` libère le GIL — c'est exactement le profil d'un tir réel (sous-process / I/O)."""

    exploit = False
    mitre = "T1190"

    def dry(self, action):
        return f"# dry {self.kind} {action.target}"

    def fire(self, action):
        s = _SECS.get(f"{self.kind}|{action.target}", 0.0)
        if s:
            time.sleep(s)
        return [Finding(target=action.target, title=f"{self.kind}:{action.target}",
                        severity="LOW", category=self.kind, mitre="T1190")]


class _swap:
    """Substitue les modules des kinds utilisés, restaure à la sortie (aucune fuite de registre)."""

    def __init__(self, kinds):
        self.kinds = list(kinds)
        self._saved = {}

    def __enter__(self):
        for kind in self.kinds:
            self._saved[kind] = registry.REGISTRY.get(kind)
            registry.REGISTRY[kind] = type(f"Bench_{kind.replace('.', '_')}",
                                           (_SleepModule,), {"kind": kind})
        return self

    def __exit__(self, *exc):
        for kind, prev in self._saved.items():
            if prev is None:
                registry.REGISTRY.pop(kind, None)
            else:
                registry.REGISTRY[kind] = prev
        return False


# --- formes de vague ---------------------------------------------------------------------------
# (kind, nb de cibles) — l'ordre de cette liste n'a AUCUNE importance : la vague est ensuite triée
# par le VRAI `Planner`, exactement comme en production.
SHAPES = {
    # A — la forme réelle : masse d'actions courtes, poignée de très lentes rejetées en queue par l'EV.
    "straggler":   [("recon.httpx", 10), ("web.security_headers", 10), ("recon.tech", 10),
                    ("recon.waf", 10), ("web.nuclei", 6),
                    ("recon.content", 2), ("web.nikto", 2), ("web.testssl", 2)],
    # B — CONTRÔLE : la queue lente remplit le pool à elle seule (>= pool actions lentes).
    "queue-large": [("recon.httpx", 10), ("web.security_headers", 10), ("recon.tech", 10),
                    ("recon.waf", 10), ("web.nuclei", 6),
                    ("recon.content", 4), ("web.nikto", 4), ("web.testssl", 4)],
    # C — CONTRÔLE NÉGATIF : durée ET coût uniformes -> aucun ordonnancement possible.
    "uniform":     [("web.nuclei", 24)],
}


def _scope(targets):
    return Scope({"mode": "grey", "in_scope": list(targets),
                  "allow_exploit": True, "allow_destructive": False})


def build_wave(shape):
    """Construit la vague d'une forme, ORDONNÉE PAR LE VRAI PLANNER (c'est l'ordre de production).
    Retourne (actions, targets, kinds, travail_total_secondes)."""
    _SECS.clear()
    acts, targets, kinds, work = [], [], [], 0.0
    for kind, count in SHAPES[shape]:
        v, c, cost = KINDS[kind]["ev"]
        secs = KINDS[kind]["secs"]
        kinds.append(kind)
        for host in _HOSTS[:count]:
            _SECS[f"{kind}|{host}"] = secs
            work += secs
            if host not in targets:
                targets.append(host)
            acts.append(Action(kind, host, value=v, confidence=c, cost=cost))
    ordered, skipped = Planner().order(acts)      # EV décroissante == ordre de production
    assert not skipped, "budget None -> aucune action déférée"
    return ordered, targets, kinds, work


# --- stratégies de soumission --------------------------------------------------------------------
def _order_index(_self, _actions, _capacity):
    """MUTATION / RÉFÉRENCE : AUCUN préchauffage -> `_fill` retombe sur la fenêtre glissante en ordre
    d'indice, c'est-à-dire EXACTEMENT le comportement d'avant ce chantier."""
    return []


def _measure(shape, pool, strategy):
    """Un run chronométré. `strategy` ∈ {'index', 'duration', 'serial'}. Rend (wall, nb_findings)."""
    actions, targets, kinds, _work = build_wave(shape)
    # `_preheat_order` peut être ABSENT (mesure AVANT, seam pas encore posé) : l'ordre d'action est
    # alors DÉJÀ le comportement — rien à neutraliser, la stratégie 'index' est le code tel quel.
    saved_order = getattr(Engine, "_preheat_order", None)
    prev_env = os.environ.get("FORGE_PARALLELISM")
    os.environ["FORGE_PARALLELISM"] = "1" if strategy == "serial" else str(pool)
    if strategy == "index" and saved_order is not None:
        Engine._preheat_order = _order_index          # neutralise le seam (mutation)
    try:
        with _swap(kinds):
            eng = Engine(_scope(targets), mode="auto")
            eng.arm("bench ordonnancement")
            t0 = time.monotonic()
            eng.run(list(actions))
            wall = time.monotonic() - t0
        return wall, len(eng.findings), len(actions)
    finally:
        if saved_order is not None:
            Engine._preheat_order = saved_order
        if prev_env is None:
            os.environ.pop("FORGE_PARALLELISM", None)
        else:
            os.environ["FORGE_PARALLELISM"] = prev_env


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pool", type=int, default=4, help="taille du pool (défaut 4 == profil balanced)")
    ap.add_argument("--repeat", type=int, default=3, help="répétitions par stratégie (médiane)")
    ap.add_argument("--shape", action="append", choices=sorted(SHAPES),
                    help="limiter à une/des forme(s) (défaut : toutes)")
    ap.add_argument("--no-serial", action="store_true", help="ne pas mesurer le plancher sériel")
    args = ap.parse_args()

    shapes = args.shape or list(SHAPES)
    strategies = ["index", "duration"] + ([] if args.no_serial else ["serial"])
    has_seam = hasattr(Engine, "_preheat_order")
    print(f"pool={args.pool}  répétitions={args.repeat}  "
          f"seam _preheat_order={'PRÉSENT' if has_seam else 'ABSENT (mesure AVANT)'}")
    if not has_seam:
        strategies = [s for s in strategies if s != "duration"]

    for shape in shapes:
        _a, _t, _k, work = build_wave(shape)
        floor = work / args.pool
        print(f"\n=== forme « {shape} » — {len(_a)} actions, travail total {work:.2f}s, "
              f"plancher théorique (travail/pool) {floor:.2f}s ===")
        results = {}
        for strat in strategies:
            walls = []
            for _ in range(args.repeat):
                wall, nfind, nact = _measure(shape, args.pool, strat)
                assert nfind == nact, f"{nfind} findings pour {nact} actions — résultat INCOMPLET"
                walls.append(wall)
            results[strat] = statistics.median(walls)
            print(f"  {strat:<9} médiane {results[strat]:6.2f}s   "
                  f"(min {min(walls):.2f} / max {max(walls):.2f})")
        if "index" in results and "duration" in results:
            before, after = results["index"], results["duration"]
            gain = (before - after) / before * 100 if before else 0.0
            print(f"  --> gain ordonnancement : {before:.2f}s -> {after:.2f}s  ({gain:+.1f}%)  "
                  f"| distance au plancher : {before / floor:.2f}x -> {after / floor:.2f}x")


if __name__ == "__main__":
    main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banc — ORDRE DE SOUMISSION intra-vague (longest-processing-time-first).

CE QUE CE BANC MESURE. `engine._run_parallel` applique les résultats SÉRIELLEMENT, dans l'ordre
d'action, mais SOUMET les tirs à un pool borné via une fenêtre glissante de `2 x pool`. La fenêtre
a supprimé le blocage de TÊTE ; elle ne dit RIEN de l'ORDRE dans lequel le travail est soumis. Or
le planner trie par EV = value*confidence/cost : un coût ÉLEVÉ (== une action LENTE, cf. la table
`brain._CONTENT_SCANNER_EV` qui annote littéralement « LENT » / « TRÈS LENT ») donne une EV BASSE,
donc une place en FIN DE VAGUE. Les actions les plus longues arrivent systématiquement en dernier :
quand elles démarrent, il ne reste plus rien pour occuper les autres workers, qui se vident.

Ce banc chiffre ce trou sur quatre FORMES de vague, à stubs de durée FIXÉE (aucun réseau, aucun DNS :
les cibles sont des IP littérales publiques RFC5737) :

  A. `straggler`  — la forme RÉELLE d'une vague ordonnée par le planner : beaucoup d'actions courtes
                    devant, une poignée de très lentes (testssl/nikto/feroxbuster) en QUEUE. Les coûts
                    y DISENT VRAI (ils viennent de la table annotée du cerveau).
  B. `queue-large` — la queue lente contient AU MOINS `pool` actions : elles remplissent le pool à
                    elles seules. CONTRÔLE : l'ordonnancement ne peut pas y gagner grand-chose.
  C. `uniform`    — toutes les actions ont la même durée ET le même coût. CONTRÔLE NÉGATIF : aucun
                    ordonnancement possible, donc AUCUNE régression tolérée.
  D. `cost-lies`  — LE CAS QUI SÉPARE `cost` DE LA DURÉE MESURÉE, et il n'a rien d'artificiel : le
                    cerveau ne renseigne un `cost` explicite que pour les kinds de sa table ; TOUT LE
                    RESTE part au DÉFAUT 1.0, y compris des modules réellement lents. La forme met donc
                    en scène (1) un kind LENT resté à `cost=1.0` (non annoté) et (2) un kind RAPIDE
                    sur-annoté `cost=3.0` — leurres exacts l'un de l'autre. `cost` y désigne les
                    MAUVAISES actions à préchauffer ; la durée observée désigne les bonnes.

STRATÉGIES COMPARÉES. Le banc pilote le seam `Engine._preheat_order` / `Engine._preheat_key` (les
SEULS points qui décident de QUOI est mis au four d'avance ; l'ordre d'APPLICATION n'en dépend jamais) :

  - `index`    : préchauffage VIDE -> `_fill` retombe sur la fenêtre glissante en ordre d'indice,
                 c'est-à-dire le comportement AVANT tout ordonnancement. C'est à la fois la MESURE DE
                 RÉFÉRENCE et la MUTATION (retirer l'ordonnancement doit faire disparaître le gain).
  - `cost`     : préchauffage sur les paliers de `action.cost` (palier complet ou rien) — l'état livré
                 AVANT l'instrumentation de durée. (Cette stratégie s'appelait `duration` ; renommée
                 parce que c'est précisément ce qu'elle N'EST PAS.)
  - `observed` : préchauffage sur la DURÉE MESURÉE par kind (`forge/durations.py`). Le magasin est
                 rempli honnêtement — par des runs de CHAUFFE réels, chronométrés puis JETÉS, jusqu'à
                 ce que chaque kind de la vague ait franchi le seuil de confiance. Aucune valeur n'est
                 injectée à la main : c'est le chemin `record -> save -> load` du produit.
  - `serial`   : `FORGE_PARALLELISM=1`, le plancher sériel, pour situer les autres.

CHIFFRES MESURÉS (pool=4, 5 répétitions, médiane ; DEUX invocations indépendantes, dispersion
intra-série <= 1,3 % et écart inter-série <= 0,01 s — les deux séries sont données quand elles
diffèrent) :
  straggler    index 2,46 s -> cost 1,84 s (-25 %)  -> observed 1,83/1,84 s  (+0,1/+0,3 % vs cost)
  queue-large  index 3,09 s -> cost 3,09 s (no-op)  -> observed 3,09 s       (-0,1/-0,0 % vs cost)
  uniform      index 1,21 s -> cost 1,21/1,22 s     -> observed 1,21 s       (+0,1/+0,2 % vs cost)
  cost-lies    index 1,88 s -> cost 1,92 s (-2,1 %) -> observed 1,60 s       (+16,8 % vs cost)
                              ^^^ préchauffer par COÛT y est PIRE que ne rien faire
  plancher sériel : straggler 7,28 s · queue-large 12,07 s · uniform 4,83 s · cost-lies 6,15 s
LECTURE HONNÊTE : sur les trois formes où `cost` dit vrai, la durée observée ne rapporte RIEN — elle
retrouve exactement le même ordre, au bruit près. Elle ne rapporte que là où `cost` MENT, et c'est le
seul endroit où elle prétend rapporter quelque chose. Le résidu levé n'est donc pas « le préchauffage
va plus vite », c'est « le préchauffage ne dépend plus d'une donnée qui n'a jamais promis d'être une
durée ». Voir aussi `--overhead` : le prix de l'instrumentation, mesuré au lieu d'être affirmé.

Le banc n'est PAS collecté par pytest/unittest (préfixe `bench_`, pas `test_`) : il se lance à la
main, il dort pour de vrai, et un chiffre au wall-clock n'a rien à faire dans une suite. Les tests
de non-régression correspondants sont STRUCTURELS (ordre de DÉMARRAGE observé, repli exact, gardes du
magasin), dans `tests/test_engine_parallel.py` et `tests/test_engine_durations.py`.

Usage :
    python3 tests/bench_engine_parallel_order.py                  # 4 formes, pool=4, 3 répétitions
    python3 tests/bench_engine_parallel_order.py --repeat 5 --pool 8
    python3 tests/bench_engine_parallel_order.py --shape cost-lies --no-serial
    python3 tests/bench_engine_parallel_order.py --overhead        # prix de l'instrumentation
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.durations import DurationStore                    # noqa: E402
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

# Table de la forme `cost-lies` — MÊMES kinds, MÊMES durées, COÛTS MENTEURS. Le mensonge n'est pas
# inventé pour le banc : `web.testssl` y garde le `cost=1.0` PAR DÉFAUT que le cerveau donne à tout
# kind absent de sa table (alors qu'il est le plus lent), et `recon.content` porte un `cost=3.0`
# alors qu'il répond ici en 30 ms. Les `value*confidence` restent BAS pour les deux, donc l'EV les
# rejette tous deux en QUEUE de vague — exactement la situation où le préchauffage doit trancher.
COST_LIES = {
    "web.testssl":   {"ev": (0.3, 0.4, 1.0), "secs": 1.20},   # LENT, mais coût laissé au DÉFAUT
    "recon.content": {"ev": (0.2, 0.3, 3.0), "secs": 0.03},   # RAPIDE, mais coût SUR-annoté
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
    # D — `cost` MENT : les 3 actions réellement lentes (testssl) sont à `cost=1.0`, les 3 leurres
    #     rapides (content) à `cost=3.0`. Le préchauffage par coût vise les leurres ; par durée, juste.
    "cost-lies":   [("recon.httpx", 10), ("web.security_headers", 10), ("recon.tech", 10),
                    ("recon.waf", 10), ("web.nuclei", 6),
                    ("web.testssl", 3), ("recon.content", 3)],
}

# Formes dont les coûts sont RÉÉCRITS par `COST_LIES` (les durées, elles, ne changent pas).
LYING_SHAPES = frozenset({"cost-lies"})


def _scope(targets):
    return Scope({"mode": "grey", "in_scope": list(targets),
                  "allow_exploit": True, "allow_destructive": False})


def build_wave(shape):
    """Construit la vague d'une forme, ORDONNÉE PAR LE VRAI PLANNER (c'est l'ordre de production).
    Retourne (actions, targets, kinds, travail_total_secondes)."""
    _SECS.clear()
    table = dict(KINDS)
    if shape in LYING_SHAPES:                     # coûts menteurs, durées inchangées
        table.update(COST_LIES)
    acts, targets, kinds, work = [], [], [], 0.0
    for kind, count in SHAPES[shape]:
        v, c, cost = table[kind]["ev"]
        secs = table[kind]["secs"]
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


def _run_once(shape, pool, strategy, store=None):
    """UN run chronométré. `strategy` ∈ {'index', 'cost', 'observed', 'serial'} ; `store` est le magasin
    de durées branché sur le moteur (obligatoire pour 'observed', utilisé aussi par la CHAUFFE).
    Rend (wall, nb_findings, nb_actions)."""
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
            eng = Engine(_scope(targets), mode="auto", durations=store)
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


def _warm_store(shape, pool, path, max_rounds=6):
    """Remplit le magasin PAR DES RUNS RÉELS, chronométrés puis JETÉS, jusqu'à ce que CHAQUE kind de la
    vague ait franchi le seuil de confiance. Aucune durée n'est écrite à la main : on emprunte le
    chemin du produit (`record` pendant le tir -> `save` -> `load` au run suivant). Rend le magasin
    rechargé, ou lève si le seuil reste hors d'atteinte (un banc qui mesure un magasin vide mentirait)."""
    _a, _t, kinds, _w = build_wave(shape)
    for _ in range(max_rounds):
        store = DurationStore.load(path)
        if all(store.estimate(k) is not None for k in kinds):
            return store
        _run_once(shape, pool, "observed", store=store)     # run de CHAUFFE (temps ignoré)
        store.save()
    store = DurationStore.load(path)
    missing = [k for k in kinds if store.estimate(k) is None]
    raise AssertionError(f"chauffe insuffisante : {missing} sans estimation après {max_rounds} runs")


def _measure(shape, pool, strategy, workdir):
    """Un point de mesure. Pour 'observed', la CHAUFFE précède et n'est PAS comptée."""
    if strategy != "observed":
        return _run_once(shape, pool, strategy)
    path = Path(workdir) / f"{shape}.durations"
    store = _warm_store(shape, pool, path)
    return _run_once(shape, pool, "observed", store=store)


# --- prix de l'instrumentation (mesuré, pas affirmé) ---------------------------------------------
def bench_overhead(pool, repeat):
    """LE COÛT DE MESURER. Deux chiffres, parce qu'ils répondent à deux questions différentes :

      (1) `record()` seul, en boucle serrée — le prix BRUT d'une observation (verrou + anneau) ;
      (2) la MÊME vague jouée avec et sans magasin branché, magasin VIDE des deux côtés : le
          préchauffage est alors IDENTIQUE (aucune estimation), donc l'écart de mur-à-mur ne contient
          QUE l'instrumentation. La forme `uniform` est choisie exprès : elle ne préchauffe rien.
    """
    print(f"pool={pool}  répétitions={repeat}\n=== prix de l'instrumentation ===")
    store = DurationStore()
    n = 200_000
    t0 = time.monotonic()
    for _ in range(n):
        store.record("web.nuclei", 0.123)
    per_call = (time.monotonic() - t0) / n
    print(f"  record() seul            {per_call * 1e9:8.0f} ns/appel  ({n} appels)")

    off, on = [], []
    for _ in range(repeat):
        off.append(_run_once("uniform", pool, "cost")[0])
        on.append(_run_once("uniform", pool, "cost", store=DurationStore())[0])
    m_off, m_on = statistics.median(off), statistics.median(on)
    _a, _t, _k, work = build_wave("uniform")
    print(f"  vague sans magasin       {m_off:8.3f}s  (min {min(off):.3f} / max {max(off):.3f})")
    print(f"  vague avec magasin       {m_on:8.3f}s  (min {min(on):.3f} / max {max(on):.3f})")
    print(f"  --> écart {(m_on - m_off) * 1000:+.1f} ms sur {len(_a)} tirs "
          f"({(m_on - m_off) / max(len(_a), 1) * 1e6:+.1f} µs/tir) — à comparer au travail réel "
          f"({work / len(_a) * 1000:.0f} ms/tir dans ce banc, des SECONDES pour un vrai outil)")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pool", type=int, default=4, help="taille du pool (défaut 4 == profil balanced)")
    ap.add_argument("--repeat", type=int, default=3, help="répétitions par stratégie (médiane)")
    ap.add_argument("--shape", action="append", choices=sorted(SHAPES),
                    help="limiter à une/des forme(s) (défaut : toutes)")
    ap.add_argument("--no-serial", action="store_true", help="ne pas mesurer le plancher sériel")
    ap.add_argument("--overhead", action="store_true",
                    help="mesurer le PRIX de l'instrumentation au lieu des formes de vague")
    args = ap.parse_args()

    if args.overhead:
        bench_overhead(args.pool, args.repeat)
        return

    shapes = args.shape or list(SHAPES)
    strategies = ["index", "cost", "observed"] + ([] if args.no_serial else ["serial"])
    has_seam = hasattr(Engine, "_preheat_order")
    print(f"pool={args.pool}  répétitions={args.repeat}  "
          f"seam _preheat_order={'PRÉSENT' if has_seam else 'ABSENT (mesure AVANT)'}")
    if not has_seam:
        strategies = [s for s in strategies if s not in ("cost", "observed")]

    with tempfile.TemporaryDirectory(prefix="forge-bench-durations-") as workdir:
        for shape in shapes:
            _a, _t, _k, work = build_wave(shape)
            floor = work / args.pool
            print(f"\n=== forme « {shape} » — {len(_a)} actions, travail total {work:.2f}s, "
                  f"plancher théorique (travail/pool) {floor:.2f}s ===")
            results = {}
            for strat in strategies:
                walls = []
                for _ in range(args.repeat):
                    wall, nfind, nact = _measure(shape, args.pool, strat, workdir)
                    assert nfind == nact, f"{nfind} findings pour {nact} actions — résultat INCOMPLET"
                    walls.append(wall)
                results[strat] = statistics.median(walls)
                spread = (max(walls) - min(walls)) / results[strat] * 100 if results[strat] else 0.0
                print(f"  {strat:<9} médiane {results[strat]:6.2f}s   "
                      f"(min {min(walls):.2f} / max {max(walls):.2f}, dispersion {spread:.1f}%)")
            _report_gain(results, "index", "cost", "ordonnancement par coût", floor)
            _report_gain(results, "cost", "observed", "durée observée vs coût", floor)


def _report_gain(results, before_key, after_key, label, floor):
    """Une ligne de comparaison entre deux stratégies mesurées (no-op si l'une manque)."""
    if before_key not in results or after_key not in results:
        return
    before, after = results[before_key], results[after_key]
    gain = (before - after) / before * 100 if before else 0.0
    print(f"  --> {label} : {before:.2f}s -> {after:.2f}s  ({gain:+.1f}%)  "
          f"| distance au plancher : {before / floor:.2f}x -> {after / floor:.2f}x")


if __name__ == "__main__":
    main()

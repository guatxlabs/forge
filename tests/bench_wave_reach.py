# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banc — PORTÉE D'UNE CAMPAGNE À BUDGET ÉGAL : actions exécutées, URLs distinctes, vagues.

CE QUE CE BANC MESURE, ET POURQUOI PAS « L'ORDRE EST CORRECT »
--------------------------------------------------------------
Un test qui vérifie que l'ordre est correct ne prouve RIEN sur la portée : c'est exactement l'erreur
qui a laissé passer la régression. Le dépôt portait déjà une intention d'ordre DÉCLARÉE
(`brain._CONTENT_SCANNER_EV`, « AVANT les ÉNUMÉRATEURS LENTS ») et deux tests qui la vérifiaient —
et la campagne réelle a quand même perdu 93 % de ses actions et 100 % de sa surface. Le livrable
est donc un CHIFFRE : actions exécutées, URLs distinctes atteintes, vagues complétées.

LA FORME EST CELLE DU RUN RÉEL, PAS UNE FORME INVENTÉE
------------------------------------------------------
Tout ce qui suit est REPRIS des artefacts de la campagne du 2026-08-10 (programme H1 public `kong`,
3 cibles, `--run-timeout 60m`, `rate=2`, profil `balanced`) :

  · `DURATIONS`  — VERBATIM du sidecar `ledger.jsonl.durations` : pour chaque kind, les 3 durées
    observées, une par cible, dans l'ordre. `web.testssl` y vaut 600,96 / 282,47 / 600,24 s (deux
    tirs TUÉS À LEUR MUR de 600 s), `web.nuclei` 279,75 / 377,52 / 415,72 s, `origin.find`
    32,43 / 32,86 / 1799,08 s. Aucune valeur n'est arrondie ni inventée.
  · `YIELD`      — VERBATIM du ledger : le nombre d'assets que CHAQUE action de découverte a
    RÉELLEMENT émis (`recon.gau` 25 endpoints par cible, `evasion.discover` 25, `recon.js_endpoints`
    25 sur 2 cibles, `recon.katana` 12 et 1, `recon.urls` 25 sur 2 cibles). Le run a donc bel et bien
    DÉCOUVERT 263 endpoints — il ne les a jamais replanifiés.
  · `UNAVAILABLE` — les 7 kinds dont l'outil manquait (`[SKIP] module indisponible` au `run.log`).
  · les BORNES d'exécution déclarées sont lues sur les VRAIS specs du registre (600 s pour
    nikto/testssl/wpscan/zap/sqlmap), pas redéclarées ici.
Seules les CHAÎNES d'URL découvertes sont synthétiques (dérivées du host réel) : le ledger en porte
263, les recopier n'apprendrait rien de plus que leur NOMBRE et leur ÉMETTEUR, qui sont exacts.

LE TEMPS EST INJECTÉ, JAMAIS ATTENDU
-------------------------------------
Horloge VIRTUELLE : `forge.engine.time` est substitué par une horloge que les modules stub font
AVANCER de la durée mesurée du kind. Le moteur chronomètre donc (et la porte de budget consulte)
exactement les durées du run réel, en quelques secondes de mur-à-mur et de façon REPRODUCTIBLE.
`FORGE_PARALLELISM=1` : le temps virtuel n'a de sens qu'en série, et l'ordonnancement — le sujet —
ne dépend pas du pool. Le préchauffage parallèle est mesuré ailleurs
(`tests/bench_engine_parallel_order.py`) ; il ne peut de toute façon pas expliquer la régression
(plafonné à `pool - 1` slots de SOUMISSION, il ne touche jamais l'ordre d'APPLICATION).

LES QUATRE CONFIGURATIONS — l'ablation EST la preuve par mutation
-----------------------------------------------------------------
  before   ordre EV seul          + part par kind DÉSACTIVÉE   <- l'état d'avant ce lot
  order    ordre (étage, EV)      + part DÉSACTIVÉE            <- apport de l'étage seul
  share    ordre EV seul          + part 1/3                   <- apport de la part seule
  after    ordre (étage, EV)      + part 1/3                   <- l'état livré

`before` est obtenu en RESTAURANT le comportement historique — clé de tri `-EV` seule ET aucune coupe
de vague : c'est la MUTATION exacte du correctif, et elle doit faire retomber les chiffres.

LE BUDGET PAR DÉFAUT EST CELUI DU RUN RÉEL, CONVERTI EN SECONDES SÉRIELLES
--------------------------------------------------------------------------
Le run de référence tournait à `FORGE_PARALLELISM=4` et a exécuté **7 683 s de travail mesuré en
4 674 s de mur** — une accélération EFFECTIVE de 1,64x (et non 4x : un tir de 1 799 s en fin de
course, deux murs de 600 s). Son budget de 3 600 s de mur vaut donc **5 918 s de capacité sérielle**,
et c'est le défaut de ce banc. `--budget` accepte n'importe quelle autre valeur ; le lot a été
mesuré à 2 400 / 3 600 / 5 918 s.

CHIFFRES MESURÉS (banc du 2026-08-10, `after` vs `before`, à budget ÉGAL)
-------------------------------------------------------------------------
    budget sériel   actions            URLs distinctes    vagues     kinds tirés
    2 400 s         222 -> 1 234 (x5,6)   0 -> 32          0 -> 1     54 -> 49
    3 600 s         156 -> 1 285 (x8,2)   0 -> 32          0 -> 1     53 -> 53
    5 918 s (réf.)  225 -> 1 292 (x5,7)   0 -> 32          0 -> 1     58 -> 58
32 est le PLAFOND de fan-out du cerveau (`content_fanout_max`, profil `balanced`), pas une limite du
lot : la campagne atteint le maximum de cibles dérivées que sa propre garde anti-runaway autorise.
Au budget de RÉFÉRENCE, **aucun kind ne disparaît** (58 -> 58) : les scanners lents tournent toujours,
mais sur une surface découverte. Aux budgets plus serrés, ce qui n'est pas atteint est COMPTÉ et LISTÉ
(`not_attempted`), jamais transformé en verdict.

Usage :
    python3 tests/bench_wave_reach.py                    # 4 configurations, budget de référence
    python3 tests/bench_wave_reach.py --budget 2400      # budget plus serré
    python3 tests/bench_wave_reach.py --config after --verbose
"""
from __future__ import annotations

import argparse
import os
import sys
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import engine as engine_mod                        # noqa: E402
from forge import interrupt as interrupt_mod                  # noqa: E402
from forge import planner as planner_mod                      # noqa: E402
from forge.brain import AutoPentestBrain                      # noqa: E402
from forge.engine import Engine                               # noqa: E402
from forge.modules import registry                            # noqa: E402
from forge.planner import Planner                             # noqa: E402
from forge.roe import Scope                                   # noqa: E402
from forge.schema import Finding, Target                      # noqa: E402
from forge import techniques                                  # noqa: E402

HOSTS = ["konghq.com", "developer.konghq.com", "cloud.konghq.com"]

# --- VERBATIM `ledger.jsonl.durations` du run réel (une entrée par cible, dans l'ordre) -----------
DURATIONS: dict[str, list[float]] = {
    "business_logic.scan": [0.0003, 0.0001, 0.0001],
    "cache_poisoning.probe": [2.5723, 7.4259, 2.5577],
    "cmdi.probe": [0.0003, 0.0001, 0.0002],
    "csrf.state_change": [0.0003, 0.0001, 0.0001],
    "demo.fingerprint": [0.0001, 0.0001, 0.0],
    "evasion.discover": [9.4882, 9.0833, 9.2578],
    "evasion.turnstile": [0.2373, 15.1053, 1.2686],
    "evasion.xhr": [0.0148, 0.0126, 0.0374],
    "framework.exposure": [12.5637, 26.2246, 1.0616],
    "fuzz.wfuzz": [0.5323, 0.4529, 0.7141],
    "graphql.access": [0.0002, 0.0001, 0.0001],
    "header_injection.probe": [2.5708, 5.517, 2.5602],
    "jwt.weakness": [0.0001, 0.0001, 0.0001],
    "lucene.probe": [0.0001, 0.0001, 0.0001],
    "nosql.probe": [0.0001, 0.0001, 0.0001],
    "oauth.flow": [0.0002, 0.0001, 0.0001],
    "origin.find": [32.4308, 32.8566, 1799.0833],
    "path.traversal": [0.0001, 0.0001, 0.0001],
    "prototype_pollution.probe": [0.0001, 0.0001, 0.0001],
    "race.condition": [0.0002, 0.0001, 0.0001],
    "recon.amass": [301.3942, 56.1558, 65.7529],
    "recon.content": [0.0016, 0.001, 0.0019],
    "recon.curl": [0.0782, 0.4307, 0.1198],
    "recon.dig": [0.0513, 0.0808, 8.2277],
    "recon.dns": [3.4804, 0.3457, 8.5764],
    "recon.dnsx": [0.0003, 0.0006, 0.0006],
    "recon.feroxbuster": [19.59, 305.1359, 27.5118],
    "recon.gau": [91.4258, 74.5227, 78.8962],
    "recon.gobuster_dns": [0.0064, 0.0013, 0.0128],
    "recon.httpx": [14.4194, 17.0137, 17.5143],
    "recon.js_endpoints": [1.2302, 0.2033, 20.1152],
    "recon.katana": [11.8014, 300.8621, 30.5647],
    "recon.naabu": [13.3113, 11.3911, 15.5703],
    "recon.nmap": [18.0933, 18.1084, 85.5895],
    "recon.secrets": [0.0116, 0.0059, 0.0062],
    "recon.subdomains": [0.1746, 0.6156, 0.4729],
    "recon.subfinder": [56.6132, 31.2324, 45.0831],
    "recon.tech": [18.0121, 23.3401, 29.6365],
    "recon.urls": [5.4121, 10.6886, 14.767],
    "recon.waf": [0.4531, 1.2591, 4.5817],
    "redirect.open": [0.0001, 0.0001, 0.0001],
    "request_smuggling.probe": [0.593, 8.9164, 0.5506],
    "rfi.probe": [0.0001, 0.0001, 0.0001],
    "sqli.probe": [0.0003, 0.0001, 0.0001],
    "ssrf.cloud_metadata": [0.0001, 0.0001, 0.0002],
    "ssrf.xspa": [0.0001, 0.0001, 0.0001],
    "ssti.eval": [0.0001, 0.0001, 0.0001],
    "subdomain.takeover": [0.3382, 0.1287, 0.0829],
    "web.nikto": [95.4045, 82.5419, 115.24],
    "web.nuclei": [279.7464, 377.5206, 415.7183],
    "web.security_headers": [6.7372, 30.2015, 0.1985],
    "web.testssl": [600.9628, 282.4698, 600.2356],
    "web.wpscan": [5.6235, 32.1174, 6.2431],
    "web.zap_baseline": [110.2399, 127.166, 59.5199],
    "xss.dalfox": [294.0718, 21.4949, 295.3914],
    "xss.reflected": [0.0002, 0.0001, 0.0001],
    "xss.stored": [0.0001, 0.0001, 0.0001],
    "xxe.probe": [0.0001, 0.0001, 0.0001],
}

# --- VERBATIM du ledger : assets RÉELLEMENT émis par chaque action de découverte -------------------
# (kind, host) -> (marqueur, n). 263 endpoints/URLs au total — découverts, jamais replanifiés.
YIELD: dict[tuple[str, str], tuple[str, int]] = {
    ("evasion.discover", "konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 25),
    ("evasion.discover", "developer.konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 25),
    ("evasion.discover", "cloud.konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 25),
    ("recon.gau", "konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 25),
    ("recon.gau", "developer.konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 25),
    ("recon.gau", "cloud.konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 25),
    ("recon.js_endpoints", "konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 25),
    ("recon.js_endpoints", "cloud.konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 25),
    ("recon.katana", "konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 1),
    ("recon.katana", "cloud.konghq.com"): (techniques.DISCOVERY_ENDPOINT_MARKER, 12),
    ("recon.urls", "developer.konghq.com"): (techniques.DISCOVERY_HISTORICAL_URL_MARKER, 25),
    ("recon.urls", "cloud.konghq.com"): (techniques.DISCOVERY_HISTORICAL_URL_MARKER, 25),
}

# outils absents au run réel (`[SKIP] module indisponible`) — reproduits à l'identique.
UNAVAILABLE = frozenset({"burp.scan", "mobile.apk", "msf.module", "network.ftp",
                         "recon.wafw00f", "recon.whatweb", "sqli.sqlmap"})

#: Budget SÉRIEL équivalent au run réel : 3 600 s de mur à `FORGE_PARALLELISM=4`, converti par
#: l'accélération MESURÉE de ce run (7 683 s de travail / 4 674 s de mur = 1,64x). Cf. l'en-tête.
DEFAULT_BUDGET = 5918.0


class _Clock:
    """Horloge MONOTONE virtuelle. `advance` est la seule façon dont le temps passe ici."""

    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += max(0.0, float(seconds))


CLOCK = _Clock()


def _host_of(target: str) -> str:
    """Host racine d'une cible (endpoint dérivé -> son hôte), pour indexer les durées par cible."""
    s = str(target)
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    return s.split(":", 1)[0]


def _secs_for(kind: str, target: str) -> float:
    """Durée MESURÉE du kind sur CETTE cible (par index d'hôte), médiane sinon. 0 si jamais observé."""
    samples = DURATIONS.get(kind)
    if not samples:
        return 0.0
    host = _host_of(target)
    if host in HOSTS:
        return samples[HOSTS.index(host) % len(samples)]
    return sorted(samples)[len(samples) // 2]


class _VirtualModule(registry.Module):
    """Stub : `fire()` fait AVANCER l'horloge virtuelle de la durée mesurée, puis émet les assets que
    l'action a RÉELLEMENT émis au run de référence. Zéro I/O, zéro sommeil, zéro réseau."""

    exploit = False
    destructive = False
    web_allowed = True
    mitre = "T1595"
    available = True
    _bound = None                                     # borne déclarée (lue sur le VRAI spec)

    def max_runtime(self, action):                    # protocole lu par `Engine._runtime_bound`
        return self._bound

    def dry(self, action):
        return f"# dry {self.kind} {action.target}"

    def fire(self, action):
        CLOCK.advance(_secs_for(self.kind, action.target))
        out = [Finding(target=action.target, title=f"{self.kind} : constat", status="tested",
                       severity="INFO", category="recon", mitre=self.mitre)]
        marker_n = YIELD.get((self.kind, action.target))
        if marker_n:
            marker, n = marker_n
            for i in range(n):
                url = f"https://{action.target}/d/{self.kind.replace('.', '-')}/{i}?q={i}"
                out.append(Finding(target=url, title=f"{marker} : {url}", status="tested",
                                   severity="INFO", category="recon", mitre=self.mitre))
        return out


class _virtual_registry:
    """Substitue TOUS les kinds enregistrés par leur stub virtuel ; restaure à la sortie.

    DEUX PROPRIÉTÉS SONT REPRISES DU VRAI MODULE, et il a fallu les deux (l'oubli de la seconde a
    d'abord fait mesurer 32 actions au lieu de 1 290 — le banc mentait, pas le moteur) :
      · la BORNE d'exécution déclarée (`spec.timeout`, ou 600 s pour `web.nuclei` dont `max_runtime`
        vaut `_timeout_for(1)` sur une cible unique) -> la porte de budget voit les bornes de prod ;
      · le fait d'être PRODUCTEUR de surface (`spec.asset_hits` / `emit_*_discovery`), reporté sur le
        stub via l'attribut `asset_hits` que `planner.surface_producers()` duck-type -> l'étage
        classe les 8 outils de découverte comme en prod. Sans lui, seuls les 7 producteurs NATIFS
        étaient reconnus et le banc mesurait un moteur qui n'existe pas."""

    def __init__(self) -> None:
        self._saved: dict[str, object] = {}

    def __enter__(self) -> "_virtual_registry":
        for kind, module in list(registry.REGISTRY.items()):
            self._saved[kind] = module
            spec = getattr(module, "spec", None)
            bound = getattr(spec, "timeout", None) if spec is not None else None
            if kind == "web.nuclei":
                bound = 600.0
            produces = bool(spec is not None and (getattr(spec, "asset_hits", False)
                                                  or getattr(spec, "emit_endpoint_discovery", False)
                                                  or getattr(spec, "emit_service_discovery", False)))
            registry.REGISTRY[kind] = type(
                f"Virt_{kind.replace('.', '_')}", (_VirtualModule,),
                {"kind": kind, "_bound": bound, "asset_hits": produces,
                 "available": kind not in UNAVAILABLE})
        planner_mod.reset_surface_producers_cache()
        return self

    def __exit__(self, *exc) -> bool:
        for kind, prev in self._saved.items():
            registry.REGISTRY[kind] = prev
        planner_mod.reset_surface_producers_cache()
        return False


# --- clé de tri HISTORIQUE (la mutation) ----------------------------------------------------------
def _legacy_rank_key(self, action):
    """`Planner.rank_key` d'AVANT ce lot : l'EV seule, sans étage. C'est la MUTATION du correctif."""
    return (0, -self.ev(action))


def _legacy_split(ordered, wave_index):
    """`Engine._split_discovery_first` d'AVANT ce lot : aucune coupe, une vague = un `run()`."""
    return list(ordered), []


def run_config(name: str, budget: float, staged: bool, share: float,
               verbose: bool = False) -> dict:
    """Exécute UNE campagne virtuelle et rend ses compteurs de portée."""
    CLOCK.t = 0.0
    sc = Scope({"mode": "grey", "in_scope": list(HOSTS), "out_scope": [],
                "allow_exploit": False, "allow_destructive": False, "rate": 2})
    targets = [Target(host=h, kind="host", attrs={"url": f"https://{h}/"}) for h in HOSTS]

    def remaining():
        return budget - CLOCK.t

    def stop():
        if CLOCK.t >= budget:
            return interrupt_mod.Terminate(interrupt_mod.CAUSE_BUDGET,
                                           f"échéance atteinte : {CLOCK.t:.0f}s / {budget:.0f}s")
        return None

    env = {"FORGE_PARALLELISM": "1", "FORGE_KIND_BUDGET_SHARE": str(share)}
    patches = [mock.patch.object(engine_mod, "time", CLOCK),
               mock.patch.dict(os.environ, env, clear=False),
               _virtual_registry()]
    if not staged:
        # « la découverte d'abord » = DEUX mécanismes solidaires (l'étage de tri + la frontière de
        # replanification). La configuration `before` les retire TOUS LES DEUX : c'est l'état d'avant
        # le lot, et c'est la mutation dont on attend qu'elle fasse retomber les chiffres.
        patches.append(mock.patch.object(Planner, "rank_key", _legacy_rank_key))
        patches.append(mock.patch.object(Engine, "_split_discovery_first",
                                         staticmethod(_legacy_split)))

    eng = Engine(sc, mode="auto", stop=stop, remaining=remaining,
                 progress=(lambda line: print("   " + line)) if verbose else None)
    eng.arm("banc portée — évaluation virtuelle, aucun paquet émis")
    stack = []
    try:
        for p in patches:
            p.__enter__()
            stack.append(p)
        try:
            eng.campaign(targets, AutoPentestBrain(), Planner(), max_waves=4)
        except interrupt_mod.Terminate:
            pass
    finally:
        for p in reversed(stack):
            p.__exit__(None, None, None)

    seeds = set(HOSTS)
    touched = {r["target"] for r in eng.results}
    fired = {r["target"] for r in eng.results if r["verdict"] == "FIRE"}
    kinds_fired = {r["kind"] for r in eng.results if r["verdict"] == "FIRE"}
    share_skips = [r for r in eng.results
                   if r["verdict"] == "SKIP" and any("part de budget" in x for x in r["reasons"])]
    return {
        "config": name,
        "actions": len(eng.results),
        "urls": len(touched - seeds),
        "urls_fired": len(fired - seeds),
        "waves": eng.waves,
        "planned": eng.planned_total,
        "not_attempted": len(eng.not_attempted),
        "elapsed": CLOCK.t,
        "kinds_fired": len(kinds_fired),
        "share_skips": len(share_skips),
        "findings": len(eng.findings),
        "engine": eng,
    }


CONFIGS = {                     # nom -> (étage structurel, part par kind)
    "before": (False, 0.0),
    "order": (True, 0.0),
    "share": (False, 1.0 / 3.0),
    "after": (True, 1.0 / 3.0),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--budget", type=float, default=DEFAULT_BUDGET, help="budget de temps (s)")
    ap.add_argument("--config", choices=sorted(CONFIGS), action="append",
                    help="ne mesurer que cette/ces configuration(s)")
    ap.add_argument("--verbose", action="store_true", help="tracer chaque action")
    args = ap.parse_args()

    names = args.config or ["before", "order", "share", "after"]
    print(f"# Banc PORTÉE — budget {args.budget:.0f}s, {len(HOSTS)} cibles, durées du run réel "
          f"(kong 2026-08-10), horloge VIRTUELLE, FORGE_PARALLELISM=1")
    print(f"{'config':8s} {'actions':>8s} {'URLs':>6s} {'URLs tirées':>12s} {'vagues':>7s} "
          f"{'planifiées':>11s} {'non tentées':>12s} {'kinds tirés':>12s} {'skips part':>11s} "
          f"{'écoulé':>8s}")
    rows = []
    for name in names:
        staged, share = CONFIGS[name]
        r = run_config(name, args.budget, staged, share, verbose=args.verbose)
        rows.append(r)
        print(f"{r['config']:8s} {r['actions']:8d} {r['urls']:6d} {r['urls_fired']:12d} "
              f"{r['waves']:7d} {r['planned']:11d} {r['not_attempted']:12d} "
              f"{r['kinds_fired']:12d} {r['share_skips']:11d} {r['elapsed']:7.0f}s")
    if len(rows) > 1 and rows[0]["config"] == "before":
        base, last = rows[0], rows[-1]
        print(f"\n{last['config']} vs before : actions x{last['actions'] / max(base['actions'], 1):.1f}, "
              f"URLs {base['urls']} -> {last['urls']}, vagues {base['waves']} -> {last['waves']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

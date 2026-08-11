# SPDX-License-Identifier: AGPL-3.0-or-later
"""PLAFOND DE DÉBIT AU NIVEAU DU RUN (`throttle.RunCap`) + DÉCLARATION D'EGRESS TIERS.

CE QUI EST MESURÉ ICI, ET POURQUOI CE FICHIER EXISTE
====================================================
`throttle` bornait le débit d'une **ACTION**, jamais d'un **RUN** — c'était consigné dans la doc et
non corrigé. Le trou se voit en une mesure : le seau est reconstruit à CHAQUE `fire()` et vit en
**thread-local**, donc le premier tir de chaque action trouve son créneau LIBRE et ne dort jamais, et
le plafond effectif est en plus multiplié par le parallélisme.

Le coût est mesuré, avec horodatage : Juice Shop, levée en même temps que trois autres applications
mais testée EN DERNIER, a vécu **34 min sans être ciblée (102 -> 21 Mio, stable)** ; campagne lancée
à 13:12:42 -> **3,78 Gio à 13:13:24** -> `Exited(139)` à 13:14:47. Mettre une cible à genoux viole
« avoid service degradation », clause de la quasi-totalité des programmes — motif d'exclusion.

DEUX HORLOGES, ET C'EST DÉLIBÉRÉ (aucun test ne dort : le temps est INJECTÉ)
---------------------------------------------------------------------------
  · `_VirtualClock` — le temps n'avance QUE quand on dort. Exact, déterministe, zéro sommeil réel :
    c'est l'horloge des ASSERTIONS (une mutation doit les tuer sans jamais flaker). En sériel, la
    somme des sommeils EST la durée écoulée, donc le débit se calcule exactement.
  · `_FastClock` — l'horloge RÉELLE, ACCÉLÉRÉE ×50 (`now = monotonic*50`, `sleep(s) = sleep(s/50)`).
    Vrais threads, vraie concurrence, vraie contention de seau — mais 7 s de débit simulé coûtent
    140 ms réels. C'est l'horloge des MESURES parallèles : une horloge purement virtuelle ne peut
    PAS mesurer un débit inter-threads (le temps y avancerait de la SOMME des sommeils concurrents
    au lieu de leur recouvrement, ce qui fabriquerait un chiffre faux).

Le harnais tire par le VRAI chemin : `Engine.run` -> gate ROE -> `_decide_blocking` -> `throttle.using`
-> `module.fire` -> `Oracle._http`. Seuls les DEUX seams de socket bas-niveau (`_raw_open`,
`_pinned_open`) sont substitués — aucun paquet n'est émis, tout le reste est le code de production.

CE QUE CHAQUE SECTION PROUVE
----------------------------
  A. LE TROU, tel qu'il est : sans plafond de run, 30 requêtes sur 30 actions à `rate=5` -> **0 s
     d'attente**, débit NON BORNÉ. C'est le témoin de régression du DÉFAUT et du DÉFAUT PAR DÉFAUT.
  B. LE PLAFOND : le même travail sous `run_rate=5` -> 29 intervalles, débit observé **5,0 req/s**.
  C. LE PARALLÉLISME : pool=4, avant/après, à l'horloge accélérée. C'est LÀ que le seau thread-local
     échouait le plus fort.
  D. LE PLAFOND NE REMPLACE PAS LE DÉBIT PAR-ACTION : les deux étages sont CHAÎNÉS, pas arbitrés.
  E. LE DÉFAUT RESTE INERTE : sans réglage, `using()` lie exactement ce qu'il liait avant.
  F. LA VISIBILITÉ : un run bridé le DIT (progression + ledger + `coverage()`), il ne ralentit pas
     mystérieusement.
  I. LE FREIN DES OUTILS ARRIVE VRAIMENT : 4 outils déclaraient un drapeau de débit sans jamais le
     recevoir (katana/dnsx/subfinder/wpscan) — liste manuelle qui avait dérivé du catalogue.
  H. LE MARQUEUR 429 reste juste sous plafond (« débit 0/s » se lirait comme « aucun throttle »).
  G. L'EGRESS TIERS : un module qui sort vers un tiers le DÉCLARE, l'opérateur peut le REFUSER, et le
     constat est dit MÊME quand c'est autorisé (l'egress httpx -> huggingface.co n'a pas échappé à une
     interdiction : il a échappé au REGARD).

LE CHIFFRE — débit du RUN observé, `rate: 5` déclaré des deux côtés
------------------------------------------------------------------
                                        AVANT              APRÈS (run_rate=5)
    sériel   30 actions × 1 requête     NON BORNÉ (0 s)    5,00 req/s
    sériel   12 actions × 3 requêtes    7,29 req/s         5,00 req/s
    sériel   24 actions × 2 requêtes    9,79 req/s         5,00 req/s
    pool=4   24 actions × 2 requêtes    33,5 req/s         5,00 req/s   (médiane de 5)
    pool=8   24 actions × 2 requêtes    59,0 req/s         5,00 req/s

`rate: 5` délivrait donc jusqu'à 11,8× le débit annoncé, et l'écart croît avec le pool — la signature
même d'un seau thread-local. Reproductible : `python3 -m pytest tests/test_run_rate_cap.py -s`.
"""
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests._dns import setUpModule, tearDownModule            # noqa: F401,E402
from tests._tmp import temp_dir                               # noqa: E402
from forge import throttle                                    # noqa: E402
from forge.engine import Engine                               # noqa: E402
from forge.ledger import Ledger                               # noqa: E402
from forge.modules import registry                            # noqa: E402
from forge.modules.oracle import Oracle                       # noqa: E402
from forge.roe import Action, Scope                           # noqa: E402

#: cibles = IP LITTÉRALES PUBLIQUES -> `resolve_target_ips` court-circuite (zéro DNS, zéro paquet),
#: et `_target_endpoint` rend None faute de port -> la gate de liveness ne sonde RIEN non plus.
_IPS = ["93.184.216.34", "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "198.51.100.7",
        "199.7.83.42", "192.0.47.59", "204.61.216.4", "45.90.28.190", "76.76.2.0", "94.140.14.14"]


# =================================================================================================
# HARNAIS — horloges injectées, seams réseau substitués, module de charge
# =================================================================================================
class _VirtualClock:
    """Le temps n'avance QUE quand on dort. Exact et déterministe ; valable en SÉRIEL uniquement."""

    def __init__(self):
        self.t = 0.0
        self.slept = 0.0

    def sleep(self, s):
        self.slept += s
        self.t += s

    def now(self):
        return self.t


class _FastClock:
    """Horloge RÉELLE accélérée ×`SCALE` : vraie concurrence, coût réel divisé par `SCALE`.

    `now()` rend des secondes VIRTUELLES (monotone réel × SCALE) et `sleep(s)` dort `s/SCALE`
    seconde réelle. Un plafond de 5 req/s se mesure donc en 1/50e du temps qu'il coûterait vraiment,
    sans rien changer à l'arithmétique du seau ni à l'entrelacement des threads."""

    SCALE = 50.0

    def __init__(self):
        self.slept = 0.0
        self._lock = threading.Lock()

    def sleep(self, s):
        with self._lock:
            self.slept += s
        time.sleep(s / self.SCALE)

    def now(self):
        return time.monotonic() * self.SCALE


class _clock:
    """Substitue les seams horaires de `throttle` (et les repose)."""

    def __init__(self, clock):
        self.clock = clock

    def __enter__(self):
        self._saved = (throttle._sleep, throttle._now)
        throttle._sleep, throttle._now = self.clock.sleep, self.clock.now
        return self.clock

    def __exit__(self, *a):
        throttle._sleep, throttle._now = self._saved
        return False


class _FakeResp:
    status = 200
    headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=None):
        return b"ok"


class _wire:
    """Substitue les DEUX seams de socket de l'oracle et HORODATE chaque requête sortante.

    Les deux, parce que l'engine ÉPINGLE l'IP au fire-time (anti-rebinding) : `Oracle._http` passe
    alors par `_pinned_open`, pas par `_raw_open`. Ne patcher que le second mesurerait zéro requête.
    Descripteur BRUT sauvegardé/reposé (`__dict__[...]`) — cf. `tests/test_seam_restoration.py`."""

    def __init__(self):
        self.stamps = []
        self._lock = threading.Lock()

    def _hit(self):
        with self._lock:
            self.stamps.append(throttle._now())
        return _FakeResp()

    def __enter__(self):
        self._saved = {n: Oracle.__dict__[n] for n in ("_raw_open", "_pinned_open")}
        Oracle._raw_open = staticmethod(lambda req, timeout=15: self._hit())
        Oracle._pinned_open = staticmethod(lambda req, pin_ip, timeout=15: self._hit())
        return self

    def __exit__(self, *a):
        for name, descriptor in self._saved.items():
            setattr(Oracle, name, descriptor)
        return False

    # --- LE CHIFFRE ------------------------------------------------------------------------------
    def observed(self):
        """`(requêtes, fenêtre, débit)` du flux VU DU RÉSEAU, tous threads et toutes actions confondus.

        `débit = (n-1)/fenêtre` : N requêtes cadencées à R req/s occupent (N-1) intervalles, donc
        cette division rend R exactement quand un plafond mord. Fenêtre nulle (rien n'a jamais
        attendu) -> débit `None`, c'est-à-dire NON BORNÉ — le mot juste, pas un grand nombre."""
        with self._lock:
            stamps = sorted(self.stamps)
        if len(stamps) < 2:
            return len(stamps), 0.0, None
        span = stamps[-1] - stamps[0]
        return len(stamps), span, ((len(stamps) - 1) / span if span > 0 else None)


class _Pulse(registry.Module):
    """Module de charge : `fire()` émet `params['hits']` requêtes par le VRAI `Oracle._http`."""

    exploit = False
    mitre = "T1190"

    def dry(self, action):
        return f"# dry {action.target}"

    def fire(self, action):
        for _ in range(int(action.params.get("hits", 1))):
            Oracle._http(f"http://{action.target}/probe")
        return []


class _swap:
    """Enregistre des modules de test le temps d'un bloc (miroir de `tests/test_engine_parallel`)."""

    def __init__(self, mapping):
        self.mapping = mapping
        self._saved = {}

    def __enter__(self):
        for kind, cls in self.mapping.items():
            self._saved[kind] = registry.REGISTRY.get(kind)
            registry.REGISTRY[kind] = type(f"Stub_{kind.replace('.', '_')}", (cls,), {"kind": kind})
        return self

    def __exit__(self, *exc):
        for kind, prev in self._saved.items():
            if prev is None:
                registry.REGISTRY.pop(kind, None)
            else:
                registry.REGISTRY[kind] = prev
        return False


class _parallelism:
    """Force `FORGE_PARALLELISM` (et le restaure) — le levier qui décide sériel vs pool de threads."""

    def __init__(self, pool):
        self.pool = pool

    def __enter__(self):
        import os
        self._os = os
        self._saved = os.environ.get("FORGE_PARALLELISM")
        os.environ["FORGE_PARALLELISM"] = str(self.pool)
        return self

    def __exit__(self, *a):
        if self._saved is None:
            self._os.environ.pop("FORGE_PARALLELISM", None)
        else:
            self._os.environ["FORGE_PARALLELISM"] = self._saved
        return False


def _scope(**extra):
    data = {"mode": "grey", "in_scope": list(_IPS), "allow_exploit": True, "rate": 5}
    data.update(extra)
    return Scope(data)


def _campaign(clock, *, pool=1, actions=12, hits=1, action_rate=5, ledger=None, progress=None,
              **scope_extra):
    """Joue une vague RÉELLE et rend `(engine, wire)`. Aucun paquet, aucun DNS, aucun sommeil réel
    au-delà de ce que l'horloge injectée décide.

    `action_rate` est POSÉ DANS `action.params['rate']` — c'est-à-dire à l'endroit exact où
    `Engine._prepare` le pose pour un kind à oracle (`_RATE_LIMITED_KINDS`). Il faut le poser à la
    main ici pour deux raisons mesurées : (1) `_prepare` n'est appelé que par `campaign()`, jamais par
    `run()` ; (2) le module de charge n'est pas une sous-classe d'`Oracle`, il n'entrerait donc pas
    dans `_RATE_LIMITED_KINDS`. Sans ce param, le seau d'ACTION vaudrait 0 et la mesure ne
    comparerait plus deux étages mais un seul — le harnais mentirait dans le sens qui arrange."""
    engine = Engine(_scope(**scope_extra), ledger=ledger, mode="auto", progress=progress)
    engine.arm("mesure de débit")
    wave = [Action("bench.pulse", _IPS[i % len(_IPS)], desc=f"a{i}",
                   params={"hits": hits, "rate": action_rate})
            for i in range(actions)]
    with _swap({"bench.pulse": _Pulse}), _parallelism(pool), _clock(clock), _wire() as wire:
        engine.run(wave)
    return engine, wire


# =================================================================================================
# A + B — LE TROU, PUIS LE PLAFOND (sériel, horloge virtuelle : exact et déterministe)
# =================================================================================================
class TestRunLevelThroughputSerial(unittest.TestCase):

    def test_A_without_run_cap_a_run_is_not_bounded_at_all(self):
        """LE DÉFAUT, tel qu'il est aujourd'hui PAR DÉFAUT : 30 requêtes réparties sur 30 actions à
        `rate=5` n'attendent PAS UNE SECONDE. Le seau d'action est neuf à chaque `fire()`, donc son
        premier (et ici unique) tir trouve toujours le créneau libre. Débit du run : NON BORNÉ."""
        clock = _VirtualClock()
        engine, wire = _campaign(clock, pool=1, actions=30, hits=1)
        n, span, rate = wire.observed()

        self.assertEqual(n, 30, "les 30 requêtes doivent être parties (mesure non vacue)")
        self.assertEqual(clock.slept, 0.0, "aucune attente : le débit du RUN n'est borné par RIEN")
        self.assertIsNone(rate, "débit NON BORNÉ (fenêtre nulle) — c'est le défaut mesuré")
        self.assertEqual(engine.coverage()["run_rate"], {}, "aucun plafond armé par défaut")
        self.assertEqual(span, 0.0)

    def test_B_run_cap_bounds_the_whole_run(self):
        """LE MÊME travail sous `run_rate=5` : 29 intervalles de 0,2 s, débit observé 5,0 req/s."""
        clock = _VirtualClock()
        engine, wire = _campaign(clock, pool=1, actions=30, hits=1, run_rate=5)
        n, span, rate = wire.observed()

        self.assertEqual(n, 30)
        self.assertAlmostEqual(clock.slept, 29 * 0.2, places=6,
                               msg="29 intervalles imposés par le plafond de run")
        self.assertAlmostEqual(span, 29 * 0.2, places=6)
        self.assertAlmostEqual(rate, 5.0, places=6, msg="le RUN est cadencé à 5 req/s")
        report = engine.coverage()["run_rate"]
        self.assertEqual(report["cap"], 5.0)
        self.assertEqual(report["requests"], 30)
        self.assertAlmostEqual(report["rate"], 5.0, places=3)
        self.assertGreater(report["waited"], 0.0, "le plafond DIT ce qu'il a coûté")

    def test_B2_rate_explicit_arms_the_run_cap_from_the_existing_lever(self):
        """`rate_explicit` — le levier qui EXISTE et qui dit « bride tout, cet engagement l'exige » —
        arme le plafond à `scope.rate` sans réglage nouveau. C'est le seul armement automatique."""
        clock = _VirtualClock()
        engine, wire = _campaign(clock, pool=1, actions=30, hits=1, rate=4, rate_explicit=True)
        n, _span, rate = wire.observed()
        self.assertEqual(n, 30)
        self.assertAlmostEqual(rate, 4.0, places=6)
        self.assertEqual(engine.coverage()["run_rate"]["source"], "scope.rate (rate_explicit)")

    def test_B3_run_rate_zero_disarms_even_under_rate_explicit(self):
        """`run_rate: 0` PRIME : un opérateur doit pouvoir désarmer le plafond sans renoncer aux
        drapeaux de débit des outils (`rate_explicit`), qui sont un réglage DIFFÉRENT."""
        clock = _VirtualClock()
        engine, wire = _campaign(clock, pool=1, actions=30, hits=1, rate=4,
                                 rate_explicit=True, run_rate=0)
        self.assertEqual(clock.slept, 0.0)
        self.assertIsNone(wire.observed()[2])
        self.assertEqual(engine.coverage()["run_rate"], {})

    def test_A2_per_action_pacing_alone_still_overshoots_the_declared_rate(self):
        """Contre-mesure : même avec PLUSIEURS requêtes par action (le cas où le seau d'action dort
        vraiment), le débit du RUN dépasse le `rate` déclaré — parce que le premier tir de chaque
        action reste gratuit. `rate=5` promet 5 req/s et en délivre 7,3."""
        clock = _VirtualClock()
        _engine, wire = _campaign(clock, pool=1, actions=12, hits=3)
        n, _span, rate = wire.observed()
        self.assertEqual(n, 36)
        self.assertGreater(rate, 5.0, "le `rate` déclaré n'est PAS le débit du run")
        self.assertAlmostEqual(rate, 35 / (12 * 2 * 0.2), places=6)   # 7,29 req/s pour rate=5


# =================================================================================================
# C — LE PARALLÉLISME (horloge réelle accélérée : vrais threads, vraie contention)
# =================================================================================================
class TestRunLevelThroughputParallel(unittest.TestCase):
    """Le seau d'action est THREAD-LOCAL : c'est en parallèle qu'il échoue le plus fort. Le plafond
    de run est UN SEUL objet partagé par tous les workers — la seule structure qui puisse borner."""

    POOL = 4
    CAP = 5.0

    def _measure(self, **scope_extra):
        clock = _FastClock()
        engine, wire = _campaign(clock, pool=self.POOL, actions=24, hits=2, **scope_extra)
        return engine, wire.observed()

    def test_C_parallel_before_and_after(self):
        _e0, (n0, span0, before) = self._measure()
        _e1, (n1, _span1, after) = self._measure(run_rate=self.CAP)

        self.assertEqual((n0, n1), (48, 48), "mêmes 48 requêtes des deux côtés (mesure comparable)")
        self.assertIsNotNone(after, "le plafond doit produire une fenêtre mesurable")
        # AVANT : le débit du run n'est pas borné par `rate=5` — il est multiplié par le pool, plus
        # le tir gratuit de chaque action. On exige seulement qu'il DÉPASSE largement le plafond
        # (la valeur exacte dépend de la machine ; c'est le DÉPASSEMENT qui est la propriété).
        self.assertTrue(before is None or before > 3 * self.CAP,
                        f"sans plafond, le run parallèle devrait dépasser {3 * self.CAP} req/s "
                        f"(observé {before})")
        # APRÈS : cadencé au plafond. Borne haute stricte (c'est la GARANTIE), borne basse lâche
        # (l'ordonnanceur de l'OS ne peut que RALENTIR, jamais accélérer au-delà du plafond).
        self.assertLessEqual(after, self.CAP * 1.25,
                             f"le run parallèle doit être borné à ~{self.CAP} req/s (observé {after})")
        self.assertGreater(after, self.CAP * 0.4,
                           f"borné, pas étranglé (observé {after})")
        print(f"\n[MESURE parallèle pool={self.POOL}] 48 requêtes / 24 actions — "
              f"AVANT : {'non borné' if before is None else f'{before:.1f} req/s'} "
              f"(fenêtre {span0:.3f}s) | APRÈS (run_rate={self.CAP:g}) : {after:.2f} req/s")

    def test_C2_the_cap_is_ONE_object_shared_by_every_worker(self):
        """La propriété STRUCTURELLE derrière la mesure : chaque worker lie le MÊME `RunCap`. Un
        plafond thread-local serait multiplié par le pool — exactement le défaut qu'on corrige."""
        engine = Engine(_scope(run_rate=5))
        seen, done = [], threading.Barrier(3)

        def worker():
            with throttle.using(5, run=engine._run_cap):
                seen.append(throttle.current().run)
            done.wait(timeout=5)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        done.wait(timeout=5)
        for t in threads:
            t.join(timeout=5)
        self.assertEqual(len(seen), 2)
        self.assertIs(seen[0], seen[1], "les workers doivent partager le MÊME seau de run")
        self.assertIs(seen[0], engine._run_cap)


# =================================================================================================
# D — LE PLAFOND DE RUN NE REMPLACE PAS LE DÉBIT PAR-ACTION
# =================================================================================================
class TestTwoStagesAreChainedNotSubstituted(unittest.TestCase):

    def test_D_action_pacing_survives_a_wide_run_cap(self):
        """`rate=2` (serré) sous `run_rate=1000` (large) : la RAFALE D'UNE ACTION reste cadencée à
        2 req/s. Si le plafond de run se SUBSTITUAIT au seau d'action, elle partirait à ~1000 req/s.

        C'est la moitié la moins évidente du contrat : les deux étages ont des rôles distincts (le
        premier lisse une rafale et repart à neuf, le second se souvient de tout le run)."""
        clock = _VirtualClock()
        _engine, wire = _campaign(clock, pool=1, actions=3, hits=5, action_rate=2, run_rate=1000)
        stamps = sorted(wire.stamps)
        self.assertEqual(len(stamps), 15)
        # les 5 requêtes d'UNE action sont les 5 premières (sériel, une action à la fois)
        intra = stamps[4] - stamps[0]
        self.assertAlmostEqual(4 / intra, 2.0, places=3,
                               msg="la rafale intra-action reste cadencée au `rate` de l'action")

    def test_D2_run_cap_wins_when_it_is_the_tighter_of_the_two(self):
        """Symétrique : `rate=1000` (large) sous `run_rate=5` -> c'est le RUN qui borne. Le débit
        résultant est celui du plus SERRÉ des deux étages, jamais la moyenne ni le dernier posé."""
        clock = _VirtualClock()
        _engine, wire = _campaign(clock, pool=1, actions=6, hits=5, action_rate=1000, run_rate=5)
        _n, _span, rate = wire.observed()
        self.assertAlmostEqual(rate, 5.0, places=3)


# =================================================================================================
# E — LE DÉFAUT RESTE INERTE (byte-identique)
# =================================================================================================
class TestDefaultIsInert(unittest.TestCase):

    def test_E_using_binds_exactly_what_it_bound_before(self):
        """Sans plafond de run, `using()` lie EXACTEMENT ce qu'il liait : None à rate<=0, un `Bucket`
        nu sinon — pas de chaîne, pas d'objet nouveau sur le chemin des oracles."""
        self.assertIsNone(throttle.using(0).bucket)
        self.assertIsNone(throttle.using(None).bucket)
        with throttle.using(0) as bucket:
            self.assertIsNone(bucket)
            self.assertIsNone(throttle.current())
        with throttle.using(3) as bucket:
            self.assertIsInstance(bucket, throttle.Bucket)
            self.assertIs(throttle.current(), bucket, "aucune chaîne sans plafond de run")

    def test_E2_run_returns_a_per_action_blocked_counter_not_a_run_total(self):
        """Sous plafond, `using()` rend toujours le seau d'ACTION : son compteur `blocked` reste
        PAR ACTION. Sans cette précaution, l'engine relirait le cumul du RUN et rééditerait le
        marqueur « rate-limited » à chaque action suivant le premier 429 du run."""
        cap = throttle.RunCap(5)
        with throttle.using(0, run=cap) as bucket:
            self.assertIsInstance(bucket, throttle.Bucket)
            self.assertNotIsInstance(bucket, throttle.RunCap)
            throttle.current().mark_blocked()
            self.assertEqual(bucket.blocked, 1)
        self.assertEqual(cap.blocked, 1, "le run compte AUSSI le blocage (visibilité du run)")
        with throttle.using(0, run=cap) as second:
            self.assertEqual(second.blocked, 0, "l'action suivante repart d'un compteur VIERGE")

    def test_E4_the_chain_keeps_the_attribute_surface_of_the_bucket_it_replaces(self):
        """CONTRAT DE COMPATIBILITÉ, et il vient d'une mutation restée VERTE. `current()` rendait
        TOUJOURS un `Bucket` ; sous plafond il rend une `_Chain`. Tout consommateur qui lisait
        `.rate` / `.blocked` sur ce que rend `current()` casserait si la chaîne ne les portait pas —
        et rien, dans le dépôt, ne l'aurait vu : `Oracle._http` n'appelle que `wait()` et
        `mark_blocked()`. La surface est donc un contrat AVANT d'être une commodité ; elle est
        épinglée ici plutôt que laissée à la bonne foi.

        `rate` retombe sur le plafond de RUN quand l'action n'en a pas : « 0 » se lirait comme
        « aucun throttle », l'inverse de la vérité sur un run bridé."""
        cap = throttle.RunCap(5)
        with throttle.using(0, run=cap):
            chain = throttle.current()
            self.assertNotIsInstance(chain, throttle.Bucket, "c'est bien la CHAÎNE qui est liée")
            for attr in ("wait", "mark_blocked", "rate", "blocked"):
                self.assertTrue(hasattr(chain, attr), f"la chaîne doit porter `{attr}` comme un seau")
            self.assertEqual(chain.rate, 5.0, "sans débit d'action, `rate` = celui du RUN")
            self.assertEqual(chain.blocked, 0)
        with throttle.using(2, run=cap):
            self.assertEqual(throttle.current().rate, 2.0, "le débit de l'ACTION prime quand il existe")

    def test_E3_scope_without_any_rate_setting_arms_nothing(self):
        for data in ({}, {"rate": 7}, {"rate": 0}, {"rate_explicit": False, "rate": 9},
                     {"run_rate": "boom", "rate": 3}):
            with self.subTest(scope=data):
                scope = Scope(dict(data, in_scope=["1.1.1.1"]))
                self.assertEqual(scope.run_rate, 0.0)
                self.assertIsNone(Engine(scope)._run_cap)


# =================================================================================================
# F — UN RUN BRIDÉ LE DIT (progression + ledger + coverage)
# =================================================================================================
class TestThrottledRunAnnouncesItself(unittest.TestCase):

    def _lines_and_ledger(self, **scope_extra):
        lines = []
        path = temp_dir(self, "forge-runcap-") / "ledger.jsonl"
        ledger = Ledger(path)
        engine, _wire = _campaign(_VirtualClock(), pool=1, actions=4, hits=1, ledger=ledger,
                                  progress=lines.append, **scope_extra)
        entries = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        return engine, lines, entries

    def test_F_capped_run_says_so_before_firing(self):
        engine, lines, entries = self._lines_and_ledger(run_rate=5)
        said = [ln for ln in lines if "[DÉBIT RUN]" in ln]
        self.assertEqual(len(said), 1, "annoncé UNE fois, pas à chaque action")
        self.assertIn("5 req/s", said[0])
        self.assertIn("scope.run_rate", said[0], "la CAUSE est nommée, pas seulement l'effet")
        fired = [i for i, ln in enumerate(lines) if ln.startswith("[FIRE]")]
        self.assertTrue(fired and lines.index(said[0]) < fired[0],
                        "l'annonce précède le premier tir")
        self.assertEqual(sum('"engine.run_rate"' in e for e in entries), 1,
                         "l'annonce est AUDITABLE (ledger), pas seulement affichée")
        self.assertEqual(engine.coverage()["run_rate"]["cap"], 5.0)

    def test_F2_uncapped_run_says_nothing(self):
        engine, lines, entries = self._lines_and_ledger()
        self.assertEqual([ln for ln in lines if "[DÉBIT RUN]" in ln], [])
        self.assertEqual(sum('"engine.run_rate"' in e for e in entries), 0)
        self.assertEqual(engine.coverage()["run_rate"], {})


# =================================================================================================
# I — UN OUTIL QUI SAIT RECEVOIR UN DÉBIT LE REÇOIT (la liste manuelle avait dérivé)
# =================================================================================================
class TestEveryToolThatDeclaresARateGetsOne(unittest.TestCase):
    """LE TROU MESURÉ : `_RATE_FLAG_KINDS` était tenue À LA MAIN et avait dérivé du catalogue.
    QUATRE outils déclaraient `{param:rate}` dans leur argv **sans jamais recevoir de débit** —
    `recon.katana`, `recon.dnsx`, `recon.subfinder`, `web.wpscan`. Le groupe de gabarit étant
    simplement ABANDONNÉ quand le param manque, la dérive était SILENCIEUSE : l'opérateur armait
    `rate_explicit`, l'UI affichait un champ « rate-limit (-rl req/s) » pour katana, et katana —
    un CRAWLER HTTP, en vol pendant qu'une campagne faisait passer une cible de 165 Mio à
    4,78 Gio en 100 s — crawlait à plein régime.

    La liste est désormais DÉRIVÉE du registre. Ce test est le garde-fou qui interdit de rediverger :
    il compare l'ensemble EFFECTIF à ce que les gabarits DÉCLARENT, sans recopier aucune liste."""

    def _declaring_kinds(self):
        from forge import modules as mods
        from forge.engine import _RATE_PARAM_TOKENS, _flatten
        out = set()
        for kind in mods.kinds():
            template = getattr(getattr(mods.get(kind), "spec", None), "argv_template", None)
            if template and any(tok in part
                                for part in _flatten(template) for tok in _RATE_PARAM_TOKENS):
                out.add(kind)
        return out

    def test_I_no_tool_declares_a_rate_flag_without_receiving_one(self):
        from forge.engine import _RATE_FLAG_KINDS
        declaring = self._declaring_kinds()
        self.assertGreaterEqual(len(declaring), 8, "catalogue vide -> contrôle vacue")
        self.assertEqual(sorted(declaring - _RATE_FLAG_KINDS), [],
                         "des outils DÉCLARENT un drapeau de débit et ne le reçoivent jamais "
                         "(groupe de gabarit abandonné en silence)")
        for kind in ("recon.katana", "recon.dnsx", "recon.subfinder", "web.wpscan"):
            with self.subTest(kind=kind):
                self.assertIn(kind, _RATE_FLAG_KINDS, "les 4 trous mesurés doivent rester couverts")

    def test_I2_the_rate_reaches_the_action_only_under_rate_explicit(self):
        """Le comportement, pas seulement l'ensemble : sous `rate_explicit` le débit ARRIVE dans
        `action.params`; sans lui, l'argv reste BYTE-IDENTIQUE au défaut (aucun param posé)."""
        for explicit, expected in ((False, None), (True, 5)):
            with self.subTest(rate_explicit=explicit):
                engine = Engine(Scope({"mode": "grey", "in_scope": ["app.test"], "rate": 5,
                                       "rate_explicit": explicit}))
                action = engine._prepare([Action("recon.katana", "app.test")], None, {}, {})[0]
                self.assertEqual(action.params.get("rate"), expected)


# =================================================================================================
# H — LE MARQUEUR « rate-limited » RESTE JUSTE SOUS PLAFOND DE RUN
# =================================================================================================
class _Wall429:
    """Les deux seams de socket répondent 429 EN PERMANENCE -> le back-off borné de `Oracle._http`
    s'épuise et marque le seau. Chemin de production intégral, zéro paquet."""

    def __enter__(self):
        import io
        import urllib.error

        def boom(req, *a, **k):
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many", {}, io.BytesIO(b""))

        self._saved = {n: Oracle.__dict__[n] for n in ("_raw_open", "_pinned_open")}
        Oracle._raw_open = staticmethod(boom)
        Oracle._pinned_open = staticmethod(boom)
        return self

    def __exit__(self, *a):
        for name, descriptor in self._saved.items():
            setattr(Oracle, name, descriptor)
        return False


class TestRateLimitedMarkerUnderRunCap(unittest.TestCase):

    def test_H_marker_reports_the_RUN_rate_when_the_action_has_none(self):
        """Une action SANS débit propre, sous un run bridé, qui se fait jeter en 429 : le marqueur
        doit dire le débit du RUN. « débit 0/s » se lirait comme « aucun throttle » — c'est-à-dire
        l'inverse de la vérité — et enverrait l'opérateur baisser un réglage déjà à zéro."""
        engine = Engine(_scope(run_rate=5), mode="auto")
        engine.arm("marqueur 429")
        wave = [Action("bench.pulse", _IPS[0], params={"hits": 1, "rate": 0})]
        with _swap({"bench.pulse": _Pulse}), _parallelism(1), _clock(_VirtualClock()), _Wall429():
            results = engine.run(wave)
        reasons = " ".join(results[0]["reasons"])
        self.assertIn("rate-limited: 1 réponse(s) 429/WAF", reasons)
        self.assertIn("débit 5/s", reasons, "le marqueur nomme le débit EFFECTIF (celui du run)")
        self.assertEqual(engine._run_cap.blocked, 1, "le run compte le blocage pour tout le run")


# =================================================================================================
# G — EGRESS TIERS : DÉCLARÉ PAR LE MODULE, AUTORISÉ (OU NON) PAR L'ENGAGEMENT
# =================================================================================================
class _EgressOptional(registry.Module):
    """Module qui SORT vers un tiers mais sait s'en passer — la forme de `recon.httpx` (seul son
    drapeau `-tech-detect` sort). Il lit `_egress_allowed` et DÉGRADE au lieu d'être écarté."""

    egress = ("huggingface.co",)
    egress_required = False
    seen = []

    def dry(self, action):
        return "# dry"

    def fire(self, action):
        _EgressOptional.seen.append(action.params.get("_egress_allowed"))
        return []


class _EgressRequired(registry.Module):
    """Module qui ne peut RIEN faire d'honnête sans son egress -> VETO nommé plutôt qu'un tir muet."""

    egress = ("huggingface.co", "cdn-lfs.huggingface.co")
    egress_required = True

    def dry(self, action):
        return "# dry"

    def fire(self, action):                                   # pragma: no cover — jamais atteint sans autorisation
        return []


class _NoEgress(registry.Module):
    """Le cas de TOUS les modules d'aujourd'hui : aucune déclaration -> la porte est inerte."""

    def dry(self, action):
        return "# dry"

    def fire(self, action):
        _NoEgress.seen.append("_egress_allowed" in action.params)
        return []

    seen = []


class TestThirdPartyEgressDeclaration(unittest.TestCase):

    def setUp(self):
        _EgressOptional.seen = []
        _NoEgress.seen = []

    def _run(self, kind, cls, **scope_extra):
        path = temp_dir(self, "forge-egress-") / "ledger.jsonl"
        ledger = Ledger(path)
        engine = Engine(_scope(**scope_extra), ledger=ledger, mode="auto")
        engine.arm("test egress")
        with _swap({kind: cls}), _parallelism(1):
            engine.run([Action(kind, _IPS[0]), Action(kind, _IPS[1])])
        entries = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        return engine, entries

    def test_G_undeclared_egress_is_refused_and_the_module_degrades(self):
        """DÉFAUT (aucun `allow_tool_egress`) : le module TIRE quand même — il sait dégrader — mais
        il reçoit `_egress_allowed=False`, et le CONSTAT est dit une fois."""
        engine, entries = self._run("egress.opt", _EgressOptional)
        self.assertEqual(len(engine.coverage()["fired"]), 2, "un module dégradable n'est pas écarté")
        self.assertEqual(_EgressOptional.seen, [False, False], "l'egress est REFUSÉ au module")
        self.assertEqual(engine.coverage()["tool_egress"],
                         {"egress.opt": {"hosts": ["huggingface.co"], "allowed": False}})
        self.assertEqual(sum('"engine.tool_egress"' in e for e in entries), 1,
                         "constat dit UNE fois pour deux actions du même kind")

    def test_G2_authorized_egress_is_still_announced(self):
        """AUTORISÉ ne veut pas dire INVISIBLE. L'egress httpx -> huggingface.co (92,6 Mio × 4 tirs)
        n'a pas échappé à une interdiction : il a échappé au REGARD."""
        engine, entries = self._run("egress.opt", _EgressOptional, allow_tool_egress=True)
        self.assertEqual(_EgressOptional.seen, [True, True])
        self.assertEqual(engine.coverage()["tool_egress"]["egress.opt"]["allowed"], True)
        self.assertEqual(sum('"engine.tool_egress"' in e for e in entries), 1)

    def test_G3_required_egress_without_authorization_is_a_named_VETO(self):
        engine, _entries = self._run("egress.req", _EgressRequired)
        vetoed = engine.coverage()["vetoed"]
        self.assertEqual(len(vetoed), 2)
        self.assertEqual(len(engine.coverage()["fired"]), 0, "rien n'a tiré, donc rien n'est sorti")
        reason = " ".join(vetoed[0]["reasons"])
        self.assertIn("allow_tool_egress", reason, "le refus NOMME le réglage qui le lève")
        self.assertIn("huggingface.co", reason, "… et l'hôte tiers en cause")

    def test_G4_allowlist_authorizes_by_host_pattern(self):
        engine, _e = self._run("egress.req", _EgressRequired,
                               allow_tool_egress=["*.huggingface.co", "huggingface.co"])
        self.assertEqual(len(engine.coverage()["fired"]), 2)
        engine2, _e2 = self._run("egress.req", _EgressRequired, allow_tool_egress=["example.test"])
        self.assertEqual(len(engine2.coverage()["fired"]), 0, "allowlist qui ne couvre pas -> VETO")

    def test_G5_a_module_that_declares_nothing_is_untouched(self):
        engine, entries = self._run("egress.none", _NoEgress)
        self.assertEqual(len(engine.coverage()["fired"]), 2)
        self.assertEqual(_NoEgress.seen, [False, False], "aucun param `_egress_allowed` injecté")
        self.assertEqual(engine.coverage()["tool_egress"], {})
        self.assertEqual(sum('"engine.tool_egress"' in e for e in entries), 0)

    def test_G6_scope_policy_shapes(self):
        """La grammaire de `allow_tool_egress`, fail-closed sur tout ce qui n'est pas explicite."""
        cases = [(None, False), (False, False), (True, True), ([], False), ({}, False), (5, False),
                 ("huggingface.co", True), (["*.co"], True), (["other.test"], False)]
        for policy, expected in cases:
            with self.subTest(policy=policy):
                scope = Scope({"in_scope": ["1.1.1.1"], "allow_tool_egress": policy})
                self.assertIs(scope.egress_allowed(["huggingface.co"]), expected)
        self.assertTrue(Scope({"in_scope": ["1.1.1.1"]}).egress_allowed([]),
                        "rien de déclaré -> rien à autoriser")
        partial = Scope({"in_scope": ["1.1.1.1"], "allow_tool_egress": ["a.test"]})
        self.assertTrue(partial.egress_allowed(["a.test"]))
        self.assertFalse(partial.egress_allowed(["a.test", "b.test"]),
                         "TOUS les hôtes déclarés doivent être couverts, pas seulement un")


if __name__ == "__main__":
    unittest.main()

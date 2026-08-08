# SPDX-License-Identifier: AGPL-3.0-or-later
"""GATE DE BUDGET — on ne coupe pas ce qui tourne, on ne DÉMARRE pas ce qui ne tient pas.

LE DÉFAUT REPRODUIT ICI (run réel du 2026-08-08, `--run-timeout 100m`, ledger signé gxrun3) :
**7576 s écoulées pour 6000 s demandées, +26,3 %**. Une SEULE action a enjambé l'échéance — un lot
`web.nuclei` de 17 URLs — et le ledger le montre à la seconde : rien d'appliqué entre t=5055 s et
t=7570 s. Sa durée mesurée, **2521,68 s**, vaut sa borne `600 + 120*(17-1)` = **2520 s** : elle n'a
pas « duré longtemps », elle a été **TUÉE À SON MUR** (rc=124). Dépassement = borne − budget restant
au démarrage = 2520 − 945,7. Le moteur avait démarré un tir 2,66× plus long que ce qu'il lui restait.

CE QUE CES TESTS VERROUILLENT :

  1. GATE       — une action dont la borne DÉCLARÉE dépasse le budget restant n'est pas DÉMARRÉE ;
                  prouvé sur les DEUX chemins d'exécution (sériel ET parallèle : une garde qui ne
                  tiendrait qu'en parallèle laisserait `FORGE_PARALLELISM=1` / profil `low` à nu).
  2. NON-VERDICT— une action non démarrée ne produit NI finding, NI run-record, NI verdict FIRE :
                  un SKIP NOMMÉ, c'est-à-dire « je n'ai pas vérifié », jamais « rien trouvé ».
  3. FAIL-OPEN  — sans budget, sans borne déclarée, ou avec un hook en défaut, RIEN ne change.
  4. NUCLEI     — la borne annoncée au moteur est CELLE qui part au runner (source unique), le lot
                  se RÉDUIT au budget restant au lieu d'être écarté en entier, et chaque cible
                  retirée est NOMMÉE.
  5. TRONCATURE — un scan TUÉ à son mur (rc=124) ne rend plus « aucun hit » pour les cibles qu'il
                  n'a jamais atteintes. C'est le trou MESURÉ sur le run réel : 4 cibles y sont
                  sorties en `tested` d'un scan tué, et la reproduction à l'unité en fabrique 15
                  sur 17. Raboter le timeout d'un tir en vol — la piste « évidente » — n'aurait fait
                  qu'en fabriquer davantage : c'est la raison pour laquelle elle a été écartée.
  6. DÉPASSEMENT— le CHIFFRE, avant/après, sur la forme exacte du run réel (horloge INJECTÉE).

Hermétique : aucun réseau, aucun sous-process, aucune ATTENTE (le temps est injecté, jamais dormi).
"""
import os
import sys
import unittest
import unittest.mock as _mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.engine import Engine                                     # noqa: E402
from forge.interrupt import (ACTION_BUDGET_PARAM, Budget,           # noqa: E402
                             GracefulStop, Terminate)
from forge.modules import registry                                  # noqa: E402
from forge.modules import web as webmod                             # noqa: E402
from forge.modules.web import NucleiScan                            # noqa: E402
from forge.roe import Action, Scope                                 # noqa: E402
from forge.cli import build_parser                                  # noqa: E402
from forge.cli import engine as cli_engine                          # noqa: E402
from tests._dns import setUpModule, tearDownModule  # noqa: F401,E402

HOST = "gate.budget.test"
KIND = "gate.work"


# --- module de test : il DÉCLARE une borne, et note s'il a été TIRÉ --------------------------------
class _Bounded(registry.Module):
    kind = KIND
    exploit = False
    web_allowed = True
    mitre = "T9999"
    fired = []                                # cibles/ids réellement tirés (partagé, réinitialisé)
    bound_attr = True                         # False -> module SANS borne déclarée

    def max_runtime(self, action):
        if not _Bounded.bound_attr:
            return None
        return action.params.get("bound")

    def dry(self, action):
        return "# dry"

    def fire(self, action):
        _Bounded.fired.append(action.id)
        return []


class _SpecBacked(_Bounded):
    """Module « ToolSpec » : sa borne vit dans `spec.timeout` (toolcatalog, `--toolspec`)."""
    kind = "gate.spec"
    bound_attr = False

    class spec:                               # noqa: N801 — mime `ExternalToolModule.spec`
        timeout = 600

    def max_runtime(self, action):
        return None                           # aucune borne PROPRE -> repli sur spec.timeout


class _GateHarness(unittest.TestCase):
    """Monte un moteur armé + un registre stubé. `remaining` est un STUB : aucune horloge réelle."""

    def setUp(self):
        _Bounded.fired = []
        _Bounded.bound_attr = True
        for cls in (_Bounded, _SpecBacked):
            prev = registry.REGISTRY.get(cls.kind)
            registry.REGISTRY[cls.kind] = cls
            self.addCleanup(self._restore, cls.kind, prev)

    @staticmethod
    def _restore(kind, prev):
        if prev is None:
            registry.REGISTRY.pop(kind, None)
        else:
            registry.REGISTRY[kind] = prev

    def engine(self, remaining=None):
        scope = Scope({"mode": "grey", "in_scope": [HOST], "allow_exploit": True,
                       "allow_destructive": False})
        eng = Engine(scope, mode="auto", remaining=remaining)
        eng.arm("test")
        return eng

    @staticmethod
    def act(name, bound=None, kind=KIND):
        a = Action(kind, HOST, desc=name, params=({"bound": bound} if bound is not None else {}))
        a.id = f"{kind}:{name}"
        return a

    def run_both_paths(self, make_actions, remaining, callback):
        """Exécute la MÊME preuve sur le chemin SÉRIEL et sur le chemin PARALLÈLE.

        Le piège déjà rencontré dans ce dépôt : une garde cassée UNIQUEMENT sur le chemin sériel
        restait verte parce que la suite ne tournait qu'en parallèle. Les deux sont donc exercés,
        et `subTest` nomme lequel a lâché."""
        for pool in (1, 4):
            with self.subTest(parallelism=pool):
                with _mock.patch.dict(os.environ, {"FORGE_PARALLELISM": str(pool)}, clear=False):
                    _Bounded.fired = []
                    eng = self.engine(remaining=remaining)
                    results = eng.run(make_actions())
                    callback(eng, results, list(_Bounded.fired))

    @staticmethod
    def budget_skips(results):
        return [r for r in results
                if r["verdict"] == "SKIP"
                and any("budget de temps restant" in x for x in r["reasons"])]


# ===================================================================================================
#  1. LA GATE — une action trop longue pour ce qu'il reste n'est PAS DÉMARRÉE
# ===================================================================================================
class TestGateEngages(_GateHarness):

    def test_action_longer_than_remaining_is_never_started(self):
        def check(eng, results, fired):
            self.assertNotIn(f"{KIND}:long", fired,
                             "une action dont la borne dépasse le budget restant a été DÉMARRÉE — "
                             "c'est exactement le tir qui a coûté +26 % sur le run réel")
            self.assertIn(f"{KIND}:court", fired, "une action qui TIENT doit tirer normalement")
        self.run_both_paths(
            lambda: [self.act("court", 100.0), self.act("long", 2520.0)],
            remaining=lambda: 945.7, callback=check)

    def test_the_exact_shape_of_the_real_run(self):
        """Borne 2520 s, budget restant 945,7 s — les chiffres du tir fautif, à l'identique."""
        def check(eng, results, fired):
            self.assertEqual(fired, [], "le lot nuclei de 17 URLs ne doit PAS être démarré")
            skips = self.budget_skips(results)
            self.assertEqual(len(skips), 1)
            self.assertIn("2520s", skips[0]["reasons"][0])
            self.assertIn("946s", skips[0]["reasons"][0])
        self.run_both_paths(lambda: [self.act("nuclei-17", 2520.0)],
                            remaining=lambda: 945.7, callback=check)

    def test_short_durations_keep_a_decimal_so_the_reason_is_not_absurd(self):
        """Constaté sur un run RÉEL : arrondie à l'entier, la raison affichait « 1s > 1s » — une
        gate PARFAITEMENT correcte qui se lit comme un bug. Sous 10 s, deux décimales : une seule
        aurait encore rendu « 1.0s > 1.0s » pour une borne de 1,0 s et un reste de 0,96 s."""
        def check(eng, results, fired):
            reason = self.budget_skips(results)[0]["reasons"][0]
            self.assertIn("1.00s", reason)
            self.assertIn("0.96s", reason)
            self.assertNotIn("1.00s > 1.00s", reason,
                             "les deux durées doivent rester DISTINGUABLES à l'affichage")
        self.run_both_paths(lambda: [self.act("court-mais-trop-long", 1.0)],
                            remaining=lambda: 0.96, callback=check)

    def test_boundary_is_inclusive_an_action_that_exactly_fits_still_fires(self):
        """`bound == remaining` TIENT. Une borne stricte (`>=`) écarterait du travail réalisable."""
        def check(eng, results, fired):
            self.assertEqual(fired, [f"{KIND}:pile"],
                             "une action dont la borne vaut EXACTEMENT le reste doit tirer")
        self.run_both_paths(lambda: [self.act("pile", 600.0)],
                            remaining=lambda: 600.0, callback=check)


# ===================================================================================================
#  2. NON-VERDICT — non démarrée n'est ni « testée » ni « rien trouvé »
# ===================================================================================================
class TestNoFabricatedVerdict(_GateHarness):

    def test_the_skip_is_named_never_silent(self):
        def check(eng, results, fired):
            skips = self.budget_skips(results)
            self.assertEqual(len(skips), 1, "l'action écartée doit apparaître dans results")
            reason = skips[0]["reasons"][0]
            for fragment in ("non démarrée", "borne d'exécution déclarée", "budget de temps restant",
                             "AUCUN verdict"):
                self.assertIn(fragment, reason,
                              f"la raison du SKIP doit dire « {fragment} » — un SKIP muet est "
                              f"indiscernable d'un « rien trouvé »")
        self.run_both_paths(lambda: [self.act("long", 2520.0)],
                            remaining=lambda: 100.0, callback=check)

    def test_no_finding_no_run_record_no_fire_verdict(self):
        def check(eng, results, fired):
            self.assertEqual(eng.findings, [], "une action non démarrée ne produit AUCUN finding")
            self.assertEqual(eng.run_records, [], "…ni run-record ATT&CK (elle n'a rien exécuté)")
            self.assertEqual([r["verdict"] for r in results], ["SKIP"],
                             "le verdict d'une action non démarrée ne peut pas être FIRE")
        self.run_both_paths(lambda: [self.act("long", 2520.0)],
                            remaining=lambda: 100.0, callback=check)

    def test_it_lands_in_the_coverage_errors_bucket_so_the_report_lists_it(self):
        def check(eng, results, fired):
            cov = eng.coverage()
            self.assertEqual(len(cov["errors"]), 1,
                             "un SKIP de budget doit être COMPTÉ dans le seau `errors` — sinon il "
                             "disparaît du rapport et redevient une lacune silencieuse")
            self.assertEqual(cov["fired"], [])
        self.run_both_paths(lambda: [self.act("long", 2520.0)],
                            remaining=lambda: 100.0, callback=check)


# ===================================================================================================
#  3. FAIL-OPEN — sans budget / sans borne / hook cassé, RIEN ne change
# ===================================================================================================
class TestFailOpen(_GateHarness):

    def test_no_budget_means_no_gate_at_all(self):
        def check(eng, results, fired):
            self.assertEqual(fired, [f"{KIND}:long"],
                             "sans budget posé, la gate doit être un NO-OP STRICT (byte-identique)")
            self.assertEqual(self.budget_skips(results), [])
        self.run_both_paths(lambda: [self.act("long", 999999.0)],
                            remaining=None, callback=check)

    def test_no_budget_means_no_param_is_injected(self):
        """Sans budget, `action.params` ne doit pas même être TOUCHÉ (aucun chemin nouveau)."""
        a = self.act("long", 999999.0)
        self.engine(remaining=None).run([a])
        self.assertNotIn(ACTION_BUDGET_PARAM, a.params)

    def test_module_without_a_declared_bound_is_never_gated(self):
        """LIMITE ASSUMÉE ET ANNONCÉE : oracles Python / recon natif ne déclarent pas de borne.
        Les gater sur une borne FICTIVE supprimerait de la couverture pour rien (durées mesurées :
        ≤ 65,7 s tous kinds hors nuclei confondus)."""
        _Bounded.bound_attr = False
        def check(eng, results, fired):
            self.assertEqual(fired, [f"{KIND}:sans-borne"],
                             "un module SANS borne déclarée doit tirer (fail-open documenté)")
        self.run_both_paths(lambda: [self.act("sans-borne")],
                            remaining=lambda: 0.5, callback=check)

    def test_a_remaining_hook_that_raises_never_blocks_a_fire(self):
        def boom():
            raise RuntimeError("horloge en vrac")
        def check(eng, results, fired):
            self.assertEqual(fired, [f"{KIND}:long"],
                             "un hook de budget en défaut ne doit JAMAIS empêcher un tir")
        self.run_both_paths(lambda: [self.act("long", 2520.0)], remaining=boom, callback=check)

    def test_a_max_runtime_that_raises_never_blocks_a_fire(self):
        def check(eng, results, fired):
            self.assertEqual(fired, [f"{KIND}:long"])
        with _mock.patch.object(_Bounded, "max_runtime",
                                lambda self, a: (_ for _ in ()).throw(ValueError("borne folle"))):
            self.run_both_paths(lambda: [self.act("long", 2520.0)],
                                remaining=lambda: 1.0, callback=check)

    def test_a_nan_remaining_is_treated_as_no_information(self):
        def check(eng, results, fired):
            self.assertEqual(fired, [f"{KIND}:long"], "NaN n'est pas une borne : fail-open")
        self.run_both_paths(lambda: [self.act("long", 2520.0)],
                            remaining=lambda: float("nan"), callback=check)

    def test_toolspec_modules_are_gated_on_their_spec_timeout(self):
        """Les modules ToolSpec (nikto/wpscan/testssl/sqlmap/zap) portent 600 s dans leur spec."""
        def check(eng, results, fired):
            self.assertEqual(fired, [], "un module ToolSpec à 600s ne tient pas dans 100s restantes")
            self.assertEqual(len(self.budget_skips(results)), 1)
            self.assertIn("600s", self.budget_skips(results)[0]["reasons"][0])
        self.run_both_paths(lambda: [self.act("spec", kind="gate.spec")],
                            remaining=lambda: 100.0, callback=check)

    def test_dry_run_and_veto_paths_are_untouched_by_the_gate(self):
        """La gate est POSTÉRIEURE au verdict ROE : une campagne non armée (que du DRY_RUN, coût
        nul par contrat) ne doit RIEN se voir écarter pour cause de budget."""
        scope = Scope({"mode": "grey", "in_scope": [HOST], "allow_exploit": True})
        eng = Engine(scope, mode="propose", remaining=lambda: 0.001)   # PAS armé -> DRY_RUN
        results = eng.run([self.act("long", 2520.0)])
        self.assertEqual([r["verdict"] for r in results], ["DRY_RUN"],
                         "la gate de budget ne doit pas manger un DRY_RUN (qui ne coûte rien)")
        self.assertEqual(self.budget_skips(results), [])


# ===================================================================================================
#  4. NUCLEI — borne annoncée == borne appliquée, lot RÉDUIT plutôt qu'écarté
# ===================================================================================================
class _NucleiHarness(unittest.TestCase):
    SCOPE = {"in_scope": ["*.test", "app.test"], "out_scope": []}

    def double(self, rc=0, out="", err=""):
        calls = []

        def _tool(*a, **k):
            calls.append({"args": list(a[2] if len(a) > 2 else k.get("args") or []),
                          "timeout": k.get("timeout")})
            return (rc, out, err)
        orig = webmod.runner.tool
        webmod.runner.tool = _tool
        self.addCleanup(lambda: setattr(webmod.runner, "tool", orig))
        return calls

    def batched(self, n, remaining=None):
        targets = [f"https://app.test/p{i}" for i in range(n)]
        p = dict(self.SCOPE, targets=targets)
        if remaining is not None:
            p[ACTION_BUDGET_PARAM] = remaining
        return Action("web.nuclei", targets[0], params=p)


class TestNucleiDeclaredBound(_NucleiHarness):

    def test_declared_bound_is_the_one_actually_passed_to_the_runner(self):
        """SOURCE UNIQUE. Si `max_runtime` annonçait moins que ce que `fire()` passe au runner, la
        gate du moteur laisserait passer un tir plus long que le budget restant — et le dépassement
        reviendrait, en silence. Les deux valeurs sont donc comparées pour plusieurs tailles."""
        for n in (1, 2, 8, 17, 25):
            with self.subTest(batch=n):
                calls = self.double(0, "")
                a = self.batched(n)
                announced = NucleiScan().max_runtime(a)
                NucleiScan().fire(a)
                self.assertEqual(announced, calls[0]["timeout"],
                                 "la borne ANNONCÉE au moteur diverge de celle passée au runner")

    def test_the_real_run_batch_of_17_declares_2520s(self):
        self.assertEqual(NucleiScan().max_runtime(self.batched(17)), 2520,
                         "le lot fautif du run réel portait une borne de 600+120*16 = 2520 s")

    def test_single_target_bound_is_the_historical_600(self):
        a = Action("web.nuclei", "https://app.test", params={})
        self.assertEqual(NucleiScan().max_runtime(a), 600)


class TestNucleiShrinksToTheBudget(_NucleiHarness):

    def test_batch_is_reduced_to_what_fits(self):
        """946 s restantes -> `600 + 120*(k-1) <= 946` -> k = 3. 3 cibles scannées, 14 nommées."""
        calls = self.double(0, "")
        a = self.batched(17, remaining=945.7)
        NucleiScan().fire(a)
        argv = calls[0]["args"]
        scanned = argv[argv.index("-u") + 1].split(",")
        self.assertEqual(len(scanned), 3, "le lot doit être réduit au plus grand qui TIENNE")
        self.assertLessEqual(calls[0]["timeout"], 945.7,
                             "un lot réduit doit tenir dans le budget restant — sinon il ne sert à rien")

    def test_the_reduced_bound_is_what_the_engine_is_told(self):
        a = self.batched(17, remaining=945.7)
        self.assertEqual(NucleiScan().max_runtime(a), 840,
                         "la borne annoncée doit être celle du lot RÉDUIT (sinon la gate l'écarte)")

    def test_every_dropped_target_is_named_never_silently_dropped(self):
        self.double(0, "")
        findings = NucleiScan().fire(self.batched(17, remaining=945.7))
        named = [f for f in findings if "lot réduit au budget" in f.title]
        self.assertEqual(len(named), 14, "les 14 cibles retirées doivent chacune sortir NOMMÉES")
        self.assertTrue(all(f.status == "skipped" for f in named),
                        "une cible retirée est `skipped` (non vérifiée), jamais `tested`")
        covered = {f.target for f in findings}
        for i in range(17):
            self.assertIn(f"https://app.test/p{i}", covered,
                          "aucune cible du lot ne doit DISPARAÎTRE du rapport")

    def test_head_is_kept_even_when_nothing_fits(self):
        """Reste < 600 s : plus rien ne tient. Le module garde la TÊTE (seule cible gatée par le
        ROE) et le MOTEUR écartera l'action entière — c'est lui qui décide, pas le module."""
        a = self.batched(17, remaining=10.0)
        self.assertEqual(NucleiScan().max_runtime(a), 600)

    def test_without_a_budget_the_batch_is_untouched(self):
        calls = self.double(0, "")
        a = self.batched(17)
        NucleiScan().fire(a)
        argv = calls[0]["args"]
        self.assertEqual(len(argv[argv.index("-u") + 1].split(",")), 17,
                         "sans budget posé, le lot doit être BYTE-IDENTIQUE à l'historique")
        self.assertEqual(calls[0]["timeout"], 2520)


# ===================================================================================================
#  5. TRONCATURE — un scan tué à son mur ne dit jamais « aucun hit »
# ===================================================================================================
class TestTruncatedScanNeverClaimsCoverage(_NucleiHarness):
    """LE TROU MESURÉ. Tir final du run réel : lot de 17, mur à 2520 s, durée 2521,68 s -> rc=124.
    nuclei avait DÉJÀ émis du JSONL, donc `findings` n'était pas vide, donc le `tool_failed` n'a
    jamais été atteint — et 4 cibles jamais scannées sont sorties en `tested` « aucun hit »."""

    PARTIAL = ('{"template-id":"waf","matched-at":"https://app.test/p0",'
               '"info":{"name":"WAF","severity":"info"}}')

    def test_timeout_with_partial_output_yields_skipped_not_tested(self):
        self.double(124, self.PARTIAL)
        findings = NucleiScan().fire(self.batched(17))
        lying = [f for f in findings if f.title == "nuclei: aucun hit"]
        self.assertEqual(lying, [],
                         "un scan TUÉ à son mur ne peut pas certifier « aucun hit » pour des cibles "
                         "qu'il n'a jamais atteintes — c'est un verdict négatif FABRIQUÉ")
        truncated = [f for f in findings if "TRONQUÉ" in f.title]
        self.assertEqual(len(truncated), 16, "les 16 cibles non atteintes doivent être NOMMÉES")
        self.assertTrue(all(f.status == "skipped" for f in truncated))

    def test_the_truncation_says_why_and_at_which_deadline(self):
        self.double(124, self.PARTIAL)
        findings = NucleiScan().fire(self.batched(17))
        reason = next(f for f in findings if "TRONQUÉ" in f.title).title
        self.assertIn("2520s", reason, "la troncature doit dire l'échéance qui l'a causée")
        self.assertIn("rc=124", reason)

    def test_the_hit_it_did_find_is_still_reported(self):
        self.double(124, self.PARTIAL)
        findings = NucleiScan().fire(self.batched(17))
        self.assertTrue(any(f.title.startswith("nuclei: WAF") for f in findings),
                        "un tir tronqué garde ce qu'il a TROUVÉ — on ne jette pas le travail fait")

    def test_a_successful_scan_still_says_no_hit(self):
        """NON-RÉGRESSION : rc=0 == le scan est allé au bout, « aucun hit » est alors la VÉRITÉ."""
        self.double(0, self.PARTIAL)
        findings = NucleiScan().fire(self.batched(17))
        self.assertEqual(len([f for f in findings if f.title == "nuclei: aucun hit"]), 16)
        self.assertEqual([f for f in findings if "TRONQUÉ" in f.title], [])

    def test_a_total_timeout_still_takes_the_tool_failed_path(self):
        """rc=124 SANS aucune sortie : le chemin historique `tool_failed` reste seul maître."""
        self.double(124, "")
        findings = NucleiScan().fire(self.batched(17))
        self.assertEqual([f for f in findings if "TRONQUÉ" in f.title], [],
                         "sans sortie du tout, c'est `tool_failed` qui parle, pas la troncature")
        self.assertTrue(findings, "un échec total doit quand même produire des findings d'échec")


# ===================================================================================================
#  6. LE CHIFFRE — dépassement avant/après, sur la forme exacte du run réel
# ===================================================================================================
class _VClock:
    """Horloge VIRTUELLE : elle n'avance QUE du travail modélisé. Le temps est injecté, pas attendu."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def spend(self, secs):
        self.t += float(secs)


class _Timed(registry.Module):
    kind = "gate.timed"
    exploit = False
    web_allowed = True
    mitre = "T9999"
    clock = None

    def max_runtime(self, action):
        return action.params.get("bound")

    def dry(self, action):
        return "# dry"

    def fire(self, action):
        _Timed.clock.spend(action.params["bound"])       # tué à son mur == il coûte sa borne
        return []


class TestOvershootMeasured(unittest.TestCase):
    """LES CHIFFRES DU RUN RÉEL, REJOUÉS À PLEINE ÉCHELLE. `tests/bench_run_budget_overshoot.py`
    produit le tableau ; ce test en verrouille la conclusion pour qu'une régression la casse."""

    BUDGET = 6000.0
    BEFORE_FATAL = 5054.3          # tout ce qui avait tourné avant le tir fautif
    FATAL_BOUND = 2520.0           # 600 + 120*(17-1)

    def setUp(self):
        prev = registry.REGISTRY.get(_Timed.kind)
        registry.REGISTRY[_Timed.kind] = _Timed
        self.addCleanup(lambda: registry.REGISTRY.__setitem__(_Timed.kind, prev) if prev
                        else registry.REGISTRY.pop(_Timed.kind, None))

    def _plan(self):
        out = []
        for name, bound in [("bulk", self.BEFORE_FATAL), ("nuclei-17", self.FATAL_BOUND)] \
                + [(f"suite-{i}", 90.0) for i in range(10)]:
            a = Action(_Timed.kind, HOST, desc=name, params={"bound": bound})
            a.id = f"{_Timed.kind}:{name}"
            out.append(a)
        return out

    def _measure(self, gated):
        clock = _VClock()
        _Timed.clock = clock
        self.addCleanup(lambda: setattr(_Timed, "clock", None))
        budget = Budget(int(self.BUDGET), clock=clock)
        stop = GracefulStop(budget=budget)
        scope = Scope({"mode": "grey", "in_scope": [HOST], "allow_exploit": True})
        eng = Engine(scope, mode="auto", stop=stop.reason,
                     remaining=(budget.remaining if gated else None))
        eng.arm("measure")
        with _mock.patch.dict(os.environ, {"FORGE_PARALLELISM": "1"}, clear=False):
            try:
                eng.run(self._plan())
            except Terminate:
                pass
        return budget.elapsed(), eng.results

    def test_before_the_gate_the_budget_is_overshot_by_a_quarter(self):
        elapsed, results = self._measure(gated=False)
        over = elapsed - self.BUDGET
        self.assertGreater(over, 1500.0,
                           f"le contrefactuel doit REPRODUIRE le défaut (mesuré : +1575,7 s) — "
                           f"il n'a dépassé que de {over:.1f}s, le scénario ne mord plus")
        self.assertAlmostEqual(over, self.FATAL_BOUND - (self.BUDGET - self.BEFORE_FATAL), places=1)

    def test_after_the_gate_the_budget_is_respected(self):
        elapsed, results = self._measure(gated=True)
        self.assertLessEqual(elapsed, self.BUDGET,
                             f"le budget doit être TENU : {elapsed:.1f}s pour {self.BUDGET:.0f}s")

    def test_the_budget_freed_is_spent_on_work_that_fits_not_lost(self):
        """Écarter la longue ne doit pas ARRÊTER le run : le temps restant sert au travail court.
        Sans ça, la gate échangerait un dépassement contre une perte de couverture."""
        _, before = self._measure(gated=False)
        _, after = self._measure(gated=True)
        n_before = sum(1 for r in before if r["verdict"] == "FIRE")
        n_after = sum(1 for r in after if r["verdict"] == "FIRE")
        self.assertGreater(n_after, n_before,
                           f"la gate doit LIBÉRER du budget pour d'autres actions "
                           f"({n_before} tirées avant, {n_after} après)")


# ===================================================================================================
#  7. CÂBLAGE CLI — le hook n'existe QUE s'il y a un budget, et le lancement l'ANNONCE
# ===================================================================================================
class TestCliWiring(unittest.TestCase):

    def test_hook_is_the_budget_remaining_when_a_budget_exists(self):
        stop = GracefulStop(budget=Budget(120))
        hook = cli_engine._remaining_hook(stop)
        self.assertIsNotNone(hook)
        self.assertLessEqual(hook(), 120.0)

    def test_hook_is_none_without_a_budget(self):
        self.assertIsNone(cli_engine._remaining_hook(GracefulStop(budget=None)),
                          "sans budget, le moteur ne doit recevoir AUCUN hook (no-op strict)")

    def test_launch_banner_announces_both_the_guarantee_and_its_residual(self):
        """(c) du cahier des charges : SUPPRIMER LA SURPRISE. L'opérateur apprend au LANCEMENT ce
        qui est garanti et ce qui ne l'est pas — pas en comparant deux nombres dans le rapport."""
        lines = []
        args = build_parser().parse_args(["campaign", "--scope", "s.json", "--targets", "t.json"])
        args.run_timeout = 6000
        cli_engine._make_stop(args, lines.append)
        text = "\n".join(lines)
        self.assertIn("6000s", text)
        self.assertIn("ne sera DÉMARRÉE", text, "la GARANTIE doit être annoncée")
        self.assertIn("Dépassement résiduel possible", text,
                      "la LIMITE doit être annoncée aussi — une garantie partielle tue si on la "
                      "croit totale")

    def test_no_banner_extras_without_a_budget(self):
        lines = []
        args = build_parser().parse_args(["campaign", "--scope", "s.json", "--targets", "t.json"])
        cli_engine._make_stop(args, lines.append)
        self.assertEqual(lines, [], "sans budget, aucune ligne de budget ne doit être émise")


if __name__ == "__main__":
    unittest.main()

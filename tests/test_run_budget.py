# SPDX-License-Identifier: AGPL-3.0-or-later
"""LOT BUDGET/INTERRUPTION — un run coupé REND son livrable, et ce livrable DIT qu'il est partiel.

CE QUI EST REPRODUIT ICI. Deux campagnes réelles contre une cible autorisée ont été tuées par un
timeout externe (90 min, puis 4 h). À chaque fois : **aucun `report.md`** alors que `--report` était
passé, **aucun sidecar `.durations`**, et un ledger COMPLET (5 646 puis 11 407 lignes, 5 318
findings). Cause mesurée : le handler de signal et le `checkpoint` qui menaient à l'arrêt gracieux
n'étaient installés QUE sous `--console` ; les deux campagnes tournaient en CLI directe (leur
`run.log` ne porte aucune ligne `Console <- ingest`). SIGTERM tombait donc sur le handler par défaut
de Python, et le process mourait AVANT le `build_report` et le `save()` des durées, tous deux placés
après la boucle.

CE QUE PROUVENT CES TESTS (tous HERMÉTIQUES : modules stubés, cerveau stubé, NXDOMAIN forcé, aucun
octet sur le réseau — et aucune ATTENTE : l'échéance est prouvée en INJECTANT l'horloge, jamais en
dormant) :

  1. BUDGET (interne)    — à l'échéance, le run s'arrête à une frontière d'action et le rapport
                           EXISTE, avec le sidecar `.durations`.
  2. SIGTERM (externe)   — un VRAI signal, délivré au process pendant la boucle, produit le même
                           rendu. C'est le scénario exact des deux campagnes perdues.
  3. EXCEPTION           — une exception non rattrapée rend le rapport PUIS continue de remonter
                           (le code de sortie reste honnête).
  4. HONNÊTETÉ           — le rapport partiel s'ANNONCE partiel : cause, X actions sur Y planifiées,
                           et ce qui n'a PAS été tenté, dans la section « Couverture NON vérifiée ».
  5. VERDICT NON TROMPEUR— un run coupé sans finding actionnable ne dit JAMAIS platement « Rien
                           d'actionnable trouvé » (la conclusion fausse qui ferait clore une cible).
  6. ACQUIS PRÉSERVÉ     — une action non tirée faute de budget ne produit AUCUN verdict : ni
                           finding, ni résultat, ni entrée de ledger. Elle est COMPTÉE comme non
                           tentée, jamais conclue négative.
  7. ACCOUNTING          — les buckets anti-lacune (déférées/classes jamais tentées/modules non
                           planifiés) sont produits MÊME sur un run coupé (ils étaient sautés).
  8. RUN COMPLET INTACT  — aucun marqueur de partialité n'apparaît sur une fin normale.
"""
import os
import signal
import sys
import unittest
import unittest.mock as _mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                             # noqa: E402
from forge.engine import Engine                                 # noqa: E402
from forge.brain import Brain                                   # noqa: E402
from forge.schema import Target, Finding                        # noqa: E402
from forge.modules import registry                              # noqa: E402
from forge.planner import Planner                               # noqa: E402
from forge.report import build_report                           # noqa: E402
from forge import interrupt as _interrupt                       # noqa: E402
from forge.interrupt import (Budget, GracefulStop, Terminate,   # noqa: E402
                             parse_run_timeout, resolve_run_timeout)
from forge.cli import build_parser                              # noqa: E402
from forge.cli import engine as cli_engine                      # noqa: E402
from tests._tmp import temp_dir                                 # noqa: E402
from tests._dns import setUpModule, tearDownModule  # noqa: F401,E402


# --- horloge INJECTÉE : une échéance se prouve en avançant le temps, jamais en l'attendant ---------
class FakeClock:
    """Horloge monotone factice : chaque lecture avance de `step`. Déterministe et instantanée."""

    def __init__(self, step=1.0):
        self.t = 0.0
        self.step = step

    def __call__(self):
        self.t += self.step
        return self.t


# --- stubs moteur (mêmes que test_engine_durability : zéro réseau) ---------------------------------
class _StubModule(registry.Module):
    exploit = False
    web_allowed = True
    mitre = "T9999"
    _findings = []

    def dry(self, action):
        return f"# stub dry {self.kind} {action.target}"

    def fire(self, action):
        f = self._findings
        return list(f(action)) if callable(f) else list(f)


class _swap_registry:
    def __init__(self, mapping):
        self.mapping = mapping
        self._saved = {}

    def __enter__(self):
        for kind, findings in self.mapping.items():
            self._saved[kind] = registry.REGISTRY.get(kind)
            attr = staticmethod(findings) if callable(findings) else findings
            cls = type(f"Stub_{kind.replace('.', '_')}", (_StubModule,),
                       {"kind": kind, "_findings": attr})
            registry.REGISTRY[kind] = cls
        return self

    def __exit__(self, *exc):
        for kind, prev in self._saved.items():
            if prev is None:
                registry.REGISTRY.pop(kind, None)
            else:
                registry.REGISTRY[kind] = prev
        return False


class _WaveBrain(Brain):
    """Cerveau déterministe : la vague i à chaque appel, puis [] (point fixe)."""

    def __init__(self, waves):
        self._waves = list(waves)
        self._i = 0

    def propose(self, graph_state):
        if self._i < len(self._waves):
            acts = self._waves[self._i]
            self._i += 1
            return acts
        return []


def _hit(action):
    return [Finding(target=action.target, title=f"hit:{action.target}", status="reported_by_tool",
                    severity="LOW", category="demo", mitre="T1190")]


def _info(action):
    """Findings INFO seulement : de quoi qualifier le verdict « rien d'actionnable » (preuve n°5)."""
    return [Finding(target=action.target, title=f"info:{action.target}", status="tested",
                    severity="INFO", category="demo")]


def _scope(hosts):
    return Scope({"mode": "grey", "in_scope": list(hosts),
                  "allow_exploit": True, "allow_destructive": False})


def _hosts(n, tag="b"):
    return [f"h{i}.{tag}.test" for i in range(n)]


# ===================================================================================================
class TestBudgetSurface(unittest.TestCase):
    """Le LEVIER : `run_timeout_secs`, celui qui existait déjà (profils + `FORGE_RUN_TIMEOUT` +
    bornes validées console). On lui ajoute l'échelon « override explicite » et son exécution
    in-process ; on ne crée pas un second réglage."""

    def test_parse_accepts_seconds_and_units(self):
        self.assertEqual(parse_run_timeout("5400"), 5400)
        self.assertEqual(parse_run_timeout("90m"), 5400)
        self.assertEqual(parse_run_timeout("2h"), 7200)
        self.assertEqual(parse_run_timeout("45s"), 45)

    def test_parse_is_fail_closed(self):
        for bad in ("bogus", "", "-1", "0", "9999999999", "1d", None, "1.5m"):
            with self.assertRaises(ValueError, msg=f"'{bad}' aurait dû être refusé"):
                parse_run_timeout(bad)

    def test_precedence_explicit_over_env_over_nothing(self):
        with _mock.patch.dict(os.environ, {"FORGE_RUN_TIMEOUT": "600"}, clear=False):
            self.assertEqual(resolve_run_timeout(None), 600, "env lue quand aucun drapeau")
            self.assertEqual(resolve_run_timeout(30), 30, "le drapeau explicite PRIME sur l'env")
        with _mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(resolve_run_timeout(None),
                              "AUCUN budget par défaut : un budget est une décision d'opérateur")

    def test_garbage_env_is_fail_open_not_fatal(self):
        """Un env pollué ne doit pas empêcher un run de démarrer (miroir de resource_profile)."""
        with _mock.patch.dict(os.environ, {"FORGE_RUN_TIMEOUT": "n'importe quoi"}, clear=False):
            self.assertIsNone(resolve_run_timeout(None))

    def test_cli_flag_is_wired_and_fail_closed(self):
        p = build_parser()
        args = p.parse_args(["campaign", "--scope", "s.json", "--targets", "t.json",
                             "--run-timeout", "90m"])
        self.assertEqual(args.run_timeout, 5400)
        with self.assertRaises(SystemExit):
            p.parse_args(["campaign", "--scope", "s.json", "--targets", "t.json",
                          "--run-timeout", "bogus"])


class TestGracefulStopSemantics(unittest.TestCase):
    def test_budget_expiry_yields_a_terminate_with_the_budget_cause(self):
        stop = GracefulStop(budget=Budget(3, clock=FakeClock(step=1.0)))
        self.assertIsNone(stop.reason(), "t=2 < échéance 4 : pas d'arrêt")
        self.assertIsNone(stop.reason(), "t=3 < échéance 4")
        term = stop.reason()                                     # t=4 >= échéance
        self.assertIsInstance(term, Terminate)
        self.assertEqual(term.cause, _interrupt.CAUSE_BUDGET)

    def test_signal_beats_budget(self):
        stop = GracefulStop(budget=Budget(1, clock=FakeClock(step=100.0)))
        stop.signalled = signal.SIGTERM
        self.assertEqual(stop.reason().cause, _interrupt.CAUSE_SIGNAL,
                         "un ordre EXTERNE prime la décision interne")

    def test_second_signal_restores_default_and_re_raises(self):
        """Un opérateur qui refait Ctrl-C DOIT pouvoir tuer le process : le 2e signal rend la main."""
        stop = GracefulStop()
        with stop:
            self.assertIsNot(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
            stop._handler(signal.SIGTERM, None)                  # 1er : gracieux
            self.assertEqual(stop.signalled, signal.SIGTERM)
            with _mock.patch("signal.raise_signal") as raiser:
                stop._handler(signal.SIGTERM, None)              # 2e : dur
            self.assertTrue(raiser.called, "le 2e signal doit être re-délivré à l'OS")

    def test_handlers_are_restored_on_exit(self):
        before = signal.getsignal(signal.SIGTERM)
        with GracefulStop():
            pass
        self.assertIs(signal.getsignal(signal.SIGTERM), before)


# ===================================================================================================
class _CampaignHarness(unittest.TestCase):
    """Monte une campagne CLI RÉELLE (parseur -> `cmd_campaign` -> moteur) sans réseau."""

    def setUp(self):
        self.dir = temp_dir(self, "forge-budget-")
        self.scope_path = self.dir / "scope.json"
        self.targets_path = self.dir / "targets.json"
        self.report_path = self.dir / "report.md"
        self.ledger_path = self.dir / "ledger.jsonl"

    def _write_inputs(self, hosts):
        import json
        self.scope_path.write_text(json.dumps({
            "mode": "grey", "in_scope": list(hosts),
            "allow_exploit": True, "allow_destructive": False}), encoding="utf-8")
        self.targets_path.write_text(json.dumps([{"host": hosts[0]}]), encoding="utf-8")

    def _args(self, extra=()):
        argv = ["campaign", "--scope", str(self.scope_path), "--targets", str(self.targets_path),
                "--arm", "--mode", "auto", "--report", str(self.report_path),
                "--ledger", str(self.ledger_path)]
        return build_parser().parse_args(argv + list(extra))

    def _run_campaign(self, waves, findings=_hit, budget_secs=None, clock_step=1.0,
                      extra_args=(), brain=None):
        """Lance `cmd_campaign` avec cerveau + registre stubés. Rend (rc, exception|None)."""
        args = self._args(extra_args)
        the_brain = brain if brain is not None else _WaveBrain(waves)
        patches = [
            _mock.patch.object(cli_engine, "HeuristicBrain", lambda *a, **k: the_brain),
            _mock.patch.object(cli_engine, "AutoPentestBrain", lambda *a, **k: the_brain),
        ]
        if budget_secs is not None:
            clock = FakeClock(step=clock_step)
            patches.append(_mock.patch.object(
                cli_engine, "Budget", lambda secs, clock=clock: Budget(secs, clock=clock)))
            args.run_timeout = budget_secs
        stack = []
        try:
            for p in patches:
                p.start()
                stack.append(p)
            with _swap_registry({"demo.probe": findings}):
                try:
                    return cli_engine.cmd_campaign(args), None
                except BaseException as e:                       # noqa: BLE001 — la preuve n°3 l'inspecte
                    return None, e
        finally:
            for p in reversed(stack):
                p.stop()

    # --- assertions partagées ---------------------------------------------------------------------
    def assertPartialReport(self, cause_fragment):
        self.assertTrue(self.report_path.exists(),
                        "AUCUN rapport écrit — c'est EXACTEMENT le dommage des deux campagnes réelles")
        rep = self.report_path.read_text(encoding="utf-8")
        self.assertIn("RAPPORT PARTIEL", rep,
                      "un rapport partiel DOIT s'annoncer partiel — sinon il fait conclure à tort")
        self.assertIn(cause_fragment, rep, "la CAUSE de l'interruption doit être dite")
        return rep


class TestBudgetDeadline(_CampaignHarness):
    """PREUVE 1 — l'échéance du budget (cause interne)."""

    def test_deadline_stops_cleanly_and_still_renders_report_and_durations(self):
        hosts = _hosts(20)
        self._write_inputs(hosts)
        waves = [[Action("demo.probe", h) for h in hosts]]
        # budget = 5 « secondes » d'horloge injectée, une lecture par frontière d'action.
        rc, exc = self._run_campaign(waves, budget_secs=5, clock_step=1.0)
        self.assertIsNone(exc, "l'échéance du budget est un arrêt PROPRE, pas une exception qui fuit")
        self.assertEqual(rc, 0, "un run qui respecte son budget n'est pas un échec")

        rep = self.assertPartialReport("budget de temps épuisé")
        # COMPTEURS : « X actions sur Y planifiées », et le reste explicitement non tenté.
        self.assertRegex(rep, r"\*\*\d+ action\(s\) exécutée\(s\) sur 20 planifiée\(s\)\*\*")
        self.assertIn("jamais tentée(s)", rep)
        self.assertIn("action(s) PLANIFIÉE(S) JAMAIS TENTÉE(S)", rep)
        # SIDECAR DE DURÉES : perdu pour la même raison que le rapport, sauvé par le même chemin.
        self.assertTrue(Path(str(self.ledger_path) + ".durations").exists(),
                        "le sidecar .durations doit survivre à l'interruption")

    def test_budget_cut_actions_produce_no_verdict_at_all(self):
        """PREUVE 6 — l'ACQUIS : zéro faux positif. Une action non tirée n'a AUCUN verdict.

        Sur les campagnes réelles (2 410 puis 5 318 findings) aucun faux positif n'a été émis parce
        qu'un module qui n'a pas pu vérifier rend `skipped`. Une action coupée par le budget est le
        même cas, en plus radical : le module n'a même pas démarré. Elle ne doit donc apparaître ni
        dans les findings, ni dans les résultats (donc ni au ledger), ni dans le rapport — SAUF dans
        la liste des non tentées."""
        hosts = _hosts(20, "nv")
        self._write_inputs(hosts)
        waves = [[Action("demo.probe", h) for h in hosts]]
        eng_seen = {}
        real_engine = cli_engine.Engine

        def _capture(*a, **k):
            eng_seen["e"] = real_engine(*a, **k)
            return eng_seen["e"]

        with _mock.patch.object(cli_engine, "Engine", _capture):
            rc, exc = self._run_campaign(waves, budget_secs=4, clock_step=1.0)
        self.assertIsNone(exc)
        eng = eng_seen["e"]
        rep = self.report_path.read_text(encoding="utf-8")
        ledger_txt = self.ledger_path.read_text(encoding="utf-8")
        untouched = [a.target for a in eng.not_attempted]
        self.assertGreater(len(eng.results), 0, "des actions ont bien tourné avant l'échéance")
        self.assertTrue(untouched, "et le run a bien été coupé avant la fin")
        touched = {r["target"] for r in eng.results}
        for h in untouched:
            self.assertNotIn(h, touched, f"verdict émis pour une action jamais tirée : {h}")
            self.assertNotIn(f"hit:{h}", rep, f"finding fabriqué pour une action jamais tirée : {h}")
            self.assertNotIn(f"hit:{h}", ledger_txt, f"finding ledgeré sans tir : {h}")
        self.assertEqual([f for f in eng.findings if f.target in untouched], [],
                         "aucun finding ne porte une cible jamais tentée")

    def test_interrupted_run_still_computes_the_anti_gap_accounting(self):
        """PREUVE 7 — le bucket anti-lacune était SAUTÉ par l'arrêt gracieux : un run coupé annonçait
        « aucune lacune, aucune classe non tentée » alors que la moitié du plan n'avait pas tourné."""
        hosts = _hosts(12, "acc")
        self._write_inputs(hosts)
        waves = [[Action("demo.probe", h) for h in hosts]]
        eng_seen = {}
        real_engine = cli_engine.Engine

        def _capture(*a, **k):
            eng_seen["e"] = real_engine(*a, **k)
            return eng_seen["e"]

        with _mock.patch.object(cli_engine, "Engine", _capture):
            self._run_campaign(waves, budget_secs=3, clock_step=1.0)
        eng = eng_seen["e"]
        self.assertTrue(eng.coverage_gaps, "les classes jamais tentées doivent être calculées")
        self.assertTrue(eng.not_planned, "les modules disponibles non planifiés aussi")
        self.assertEqual(eng.coverage_finalize_error, "", "l'accounting ne doit pas avoir échoué")
        self.assertGreater(eng.planned_total, 0)
        self.assertTrue(eng.not_attempted, "les actions ordonnées non atteintes doivent être listées")
        self.assertEqual(eng.planned_total, len(eng.results) + len(eng.not_attempted),
                         "accounting FERMÉ : planifiées == appliquées + jamais tentées")


class TestExternalSignal(_CampaignHarness):
    """PREUVE 2 — le SIGTERM externe : le scénario EXACT des deux campagnes perdues."""

    def test_real_sigterm_during_the_loop_still_renders_report_and_durations(self):
        hosts = _hosts(12, "sig")
        self._write_inputs(hosts)
        waves = [[Action("demo.probe", h) for h in hosts]]
        fired = {"n": 0}

        def _fire_then_signal(action):
            fired["n"] += 1
            if fired["n"] == 3:
                # VRAI signal, VRAI handler : on emprunte le chemin de production de bout en bout
                # (c'est ce que fait `timeout(1)` / le watchdog console `kill_group`).
                os.kill(os.getpid(), signal.SIGTERM)
            return _hit(action)

        rc, exc = self._run_campaign(waves, findings=_fire_then_signal)
        self.assertIsNone(exc, "un SIGTERM doit être un arrêt PROPRE, pas une mort du process")
        self.assertEqual(rc, 0)
        rep = self.assertPartialReport("signal d'arrêt externe")
        self.assertIn("SIGTERM", rep, "le rapport doit nommer le signal reçu")
        self.assertIn("action(s) PLANIFIÉE(S) JAMAIS TENTÉE(S)", rep)
        self.assertTrue(Path(str(self.ledger_path) + ".durations").exists())
        # Le drapeau de handler est bien retiré à la sortie (pas de fuite dans le process de test).
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)


class TestUncaughtException(_CampaignHarness):
    """PREUVE 3 — l'exception non rattrapée : rendu D'ABORD, propagation ENSUITE."""

    def test_report_is_written_then_the_exception_propagates(self):
        hosts = _hosts(10, "exc")
        self._write_inputs(hosts)

        class _BoomBrain(Brain):
            def __init__(self):
                self.n = 0

            def propose(self, graph_state):
                self.n += 1
                if self.n == 1:
                    return [Action("demo.probe", h) for h in hosts[:4]]
                raise RuntimeError("le cerveau a explosé en vague 2")

        rc, exc = self._run_campaign(None, brain=_BoomBrain())
        self.assertIsNone(rc, "l'exception DOIT continuer de remonter (code de sortie honnête)")
        self.assertIsInstance(exc, RuntimeError)
        rep = self.assertPartialReport("exception non rattrapée")
        self.assertIn("RuntimeError", rep, "le rapport doit nommer l'exception")
        self.assertTrue(Path(str(self.ledger_path) + ".durations").exists())


class TestHonestyOfThePartialReport(_CampaignHarness):
    """PREUVE 4+5 — la LIGNE ROUGE : un rapport tronqué qui ressemble à un rapport complet serait
    PIRE que pas de rapport."""

    def test_verdict_never_plainly_says_nothing_actionable_on_a_partial_run(self):
        hosts = _hosts(20, "verdict")
        self._write_inputs(hosts)
        waves = [[Action("demo.probe", h) for h in hosts]]
        # findings INFO seulement -> zéro actionnable : le cas où la phrase serait dangereuse.
        rc, exc = self._run_campaign(waves, findings=_info, budget_secs=5, clock_step=1.0)
        self.assertIsNone(exc)
        rep = self.report_path.read_text(encoding="utf-8")
        self.assertNotIn("**Rien d'actionnable trouvé.**", rep,
                         "conclusion FAUSSE sur un run dont le plan n'a pas tourné en entier")
        self.assertIn("Rien d'actionnable DANS LA FRACTION DU PLAN QUI A TOURNÉ", rep)
        self.assertIn("Ne pas en conclure « rien trouvé »", rep)

    def test_not_attempted_actions_land_in_the_existing_coverage_section(self):
        """On ÉTEND « Couverture NON vérifiée », on n'invente pas un second mécanisme."""
        hosts = _hosts(20, "cov")
        self._write_inputs(hosts)
        waves = [[Action("demo.probe", h) for h in hosts]]
        self._run_campaign(waves, budget_secs=5, clock_step=1.0)
        rep = self.report_path.read_text(encoding="utf-8")
        head = rep.index("## Couverture NON vérifiée (trous de couverture)")
        nxt = rep.index("## ", head + 10)
        section = rep[head:nxt]
        self.assertIn("PLANIFIÉE(S) JAMAIS TENTÉE(S)", section,
                      "les actions non tentées appartiennent à la section des trous de couverture")
        self.assertIn("aucun verdict n'a été émis", section)

    def test_partial_banner_carries_cause_and_counters(self):
        hosts = _hosts(20, "banner")
        self._write_inputs(hosts)
        waves = [[Action("demo.probe", h) for h in hosts]]
        self._run_campaign(waves, budget_secs=6, clock_step=1.0)
        rep = self.report_path.read_text(encoding="utf-8")
        head = rep.split("## Engagement")[0]              # la bannière précède TOUT le reste
        self.assertIn("RAPPORT PARTIEL", head)
        self.assertIn("budget de temps épuisé", head)
        self.assertRegex(head, r"\d+ action\(s\) exécutée\(s\) sur \d+ planifiée\(s\)")
        self.assertIn("Couverture NON vérifiée", head, "la bannière doit dire OÙ lire les trous")


class TestCompleteRunIsUnchanged(_CampaignHarness):
    """PREUVE 8 — aucune régression de rendu : une fin NORMALE ne porte aucun marqueur de partialité."""

    def test_normal_run_has_no_partial_marker(self):
        hosts = _hosts(4, "ok")
        self._write_inputs(hosts)
        waves = [[Action("demo.probe", h) for h in hosts]]
        rc, exc = self._run_campaign(waves)
        self.assertIsNone(exc)
        self.assertEqual(rc, 0)
        rep = self.report_path.read_text(encoding="utf-8")
        for marker in ("RAPPORT PARTIEL", "JAMAIS TENTÉE(S)", "Plan INCOMPLET",
                       "DANS LA FRACTION DU PLAN"):
            self.assertNotIn(marker, rep, f"marqueur de partialité sur un run COMPLET : {marker}")
        self.assertIn("Aucun module n'a échoué à s'exécuter", rep)

    def test_engine_without_stop_hook_is_untouched(self):
        """Sans prédicat d'arrêt (tests, appelants programmatiques) : aucun appel, aucun changement."""
        with _swap_registry({"demo.probe": _hit}):
            eng = Engine(_scope(["a.test", "b.test"]), mode="auto")
            eng.arm("test")
            res = eng.run([Action("demo.probe", "a.test"), Action("demo.probe", "b.test")])
        self.assertEqual(len(res), 2)
        self.assertIsNone(eng.interruption)
        self.assertEqual(eng.not_attempted, [])


class TestEngineStopHook(unittest.TestCase):
    """Le hook au niveau MOTEUR : consulté à CHAQUE action (et non tous les 25 checkpoints).

    LES DEUX CHEMINS D'EXÉCUTION SONT ÉPROUVÉS SÉPARÉMENT, et ce n'est pas du zèle : le moteur a un
    chemin SÉRIEL (`FORGE_PARALLELISM<=1`, c'est le profil de ressources `low`) et un chemin
    PARALLÈLE (défaut 4). Une première version de ces tests ne couvrait QUE le parallèle — la
    mutation qui SUPPRIMAIT la frontière d'arrêt du chemin sériel restait VERTE. Un opérateur en
    profil `low` aurait donc eu un budget silencieusement inopérant."""

    def _run_with_pool(self, pool, stop, hosts, expect_terminate=False):
        """Exécute une vague avec un pool IMPOSÉ. Renvoie l'engine (inspectable même sur arrêt)."""
        with _mock.patch.dict(os.environ, {"FORGE_PARALLELISM": str(pool)}, clear=False):
            with _swap_registry({"demo.probe": _hit}):
                eng = Engine(_scope(hosts), mode="auto", stop=stop)
                eng.arm("test")
                actions = [Action("demo.probe", h) for h in hosts]
                if expect_terminate:
                    with self.assertRaises(Terminate):
                        eng.run(actions)
                else:
                    eng.run(actions)
                return eng

    def test_stop_is_consulted_at_every_action_boundary_serial(self):
        calls = {"n": 0}

        def _stop():
            calls["n"] += 1
            return None

        self._run_with_pool(1, _stop, _hosts(5, "hookser"))
        self.assertEqual(calls["n"], 5, "chemin SÉRIEL : une consultation par action appliquée")

    def test_stop_is_consulted_at_every_action_boundary_parallel(self):
        calls = {"n": 0}

        def _stop():
            calls["n"] += 1
            return None

        self._run_with_pool(4, _stop, _hosts(5, "hookpar"))
        self.assertEqual(calls["n"], 5, "chemin PARALLÈLE : une consultation par action APPLIQUÉE")

    def test_stop_raises_at_a_boundary_serial(self):
        state = {"n": 0}

        def _stop():
            state["n"] += 1
            return Terminate(_interrupt.CAUSE_BUDGET, "échéance de test") if state["n"] == 2 else None

        eng = self._run_with_pool(1, _stop, _hosts(6, "brkser"), expect_terminate=True)
        self.assertEqual(len(eng.results), 2, "chemin SÉRIEL : arrêt À LA FRONTIÈRE, 2 actions")
        self.assertEqual(len(eng.findings), 2, "aucun finding pour les 4 actions non tirées")

    def test_stop_raises_at_a_boundary_and_records_the_interruption(self):
        state = {"n": 0}

        def _stop():
            state["n"] += 1
            return Terminate(_interrupt.CAUSE_BUDGET, "échéance de test") if state["n"] == 2 else None

        with _swap_registry({"demo.probe": _hit}):
            eng = Engine(_scope(_hosts(6, "brk")), mode="auto", stop=_stop)
            eng.arm("test")
            with self.assertRaises(Terminate):
                eng.run([Action("demo.probe", h) for h in _hosts(6, "brk")])
        self.assertEqual(len(eng.results), 2, "arrêt À LA FRONTIÈRE : 2 actions complètes, pas 2,5")
        self.assertEqual(len(eng.findings), 2, "aucun finding fabriqué pour les 4 actions non tirées")
        self.assertIsNotNone(eng.interruption)
        self.assertEqual(eng.interruption["cause"], _interrupt.CAUSE_BUDGET)

    def test_campaign_finalizes_coverage_even_when_the_stop_fires(self):
        hosts = _hosts(8, "camp")
        state = {"n": 0}

        def _stop():
            state["n"] += 1
            return Terminate(_interrupt.CAUSE_SIGNAL, "SIGTERM de test") if state["n"] == 3 else None

        with _swap_registry({"demo.probe": _hit}):
            eng = Engine(_scope(hosts), mode="auto", stop=_stop)
            eng.arm("test")
            with self.assertRaises(Terminate):
                eng.campaign([Target(hosts[0], "url")],
                             _WaveBrain([[Action("demo.probe", h) for h in hosts]]), Planner())
        self.assertEqual(eng.planned_total, len(hosts))
        self.assertEqual(len(eng.not_attempted), len(hosts) - len(eng.results))
        self.assertTrue(eng.coverage_gaps, "les lacunes DOIVENT être calculées sur un run coupé")
        self.assertTrue(eng.not_planned)


class TestReportFallsBackToEngineInterruption(unittest.TestCase):
    """Un appelant qui ignore ce lot (console, script, test) rend quand même un rapport HONNÊTE :
    `build_report` reprend `engine.interruption` quand l'argument n'est pas passé."""

    def test_build_report_reads_engine_interruption_without_being_told(self):
        eng = Engine(_scope(["x.test"]))
        eng.interruption = {"cause": _interrupt.CAUSE_BUDGET,
                            "label": "budget de temps épuisé", "detail": "échéance",
                            "ran": 3, "planned": 10, "not_attempted": 7, "waves": 1}
        rep = build_report(eng)
        self.assertIn("RAPPORT PARTIEL", rep)
        self.assertIn("3 action(s) exécutée(s) sur 10 planifiée(s)", rep)


if __name__ == "__main__":
    unittest.main(verbosity=2)

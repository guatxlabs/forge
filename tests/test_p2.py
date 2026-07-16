"""P2 — preuves planner coverage-safe, cerveau, runner, campagne gatée, boucle purple."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action, FIRE, DRY_RUN          # noqa: E402
from forge.planner import Planner, QUALIFYING               # noqa: E402
from forge.brain import HeuristicBrain                      # noqa: E402
from forge.engine import Engine                             # noqa: E402
from forge.schema import Target                             # noqa: E402
from forge import runner, purple, report                    # noqa: E402


def scope(in_scope=("app.test",), exploit=False):
    return Scope({"mode": "grey", "in_scope": list(in_scope), "allow_exploit": exploit})


class TestPlanner(unittest.TestCase):
    def test_underrated_qualifying_not_starved(self):
        idor = Action("access_control.idor", "app.test", cls="access_control", value=.1, confidence=.1, cost=3)
        scan = Action("web.nuclei", "app.test", value=.9, confidence=.9, cost=1)
        ordered, skipped = Planner(budget=1.0).order([scan, idor])
        self.assertIn(idor, ordered)                         # plancher : jamais affamé
        self.assertNotIn(idor, skipped)

    def test_nonqualifying_overbudget_deferred_not_deleted(self):
        a = Action("web.nuclei", "app.test", value=.5, confidence=.5, cost=5)
        b = Action("recon.httpx", "app.test", value=.9, confidence=.9, cost=1)
        ordered, skipped = Planner(budget=1.0).order([a, b])
        self.assertIn(b, ordered)
        self.assertIn(a, skipped)                            # déféré, mais préservé (visible)

    def test_coverage_gaps_listed(self):
        gaps = Planner().coverage_gaps([Action("recon.httpx", "app.test")], ["app.test"])
        self.assertIn("app.test", gaps)
        self.assertIn("access_control", gaps["app.test"])    # jamais tenté -> lacune visible

    def test_qualifying_action_does_not_consume_budget(self):
        # RÉGRESSION : le budget ne borne QUE le non-qualifiant. Une action qualifiante COÛTEUSE,
        # ordonnée en premier (EV plancher), ne doit pas vider le budget et affamer un non-qualifiant.
        idor = Action("access_control.idor", "app.test", cls="access_control",
                      value=.9, confidence=.9, cost=10)        # qualifiant, très cher, EV élevée -> 1er
        scan = Action("web.nuclei", "app.test", cls="web", value=.5, confidence=.5, cost=1)  # non-qualifiant
        ordered, skipped = Planner(budget=2.0).order([idor, scan])
        self.assertIn(idor, ordered)                           # qualifiant : toujours gardé
        self.assertIn(scan, ordered)                           # non-qualifiant : tient car l'IDOR n'a rien dépensé
        self.assertEqual(skipped, [])                          # rien déféré (cost IDOR non imputé au budget)


class TestBrain(unittest.TestCase):
    def test_proposes_qualifying_for_web(self):
        actions = HeuristicBrain().propose([Target("app.test", "url")])
        self.assertTrue(any(a.cls in QUALIFYING for a in actions))


class TestRunner(unittest.TestCase):
    def test_echo_runs(self):
        rc, out, err = runner.tool("echo", args=["forge-ok"])
        self.assertEqual(rc, 0)
        self.assertIn("forge-ok", out)

    def test_missing_tool_reports_unavailable(self):
        rc, out, err = runner.tool("definitely-not-a-real-binary-xyz", docker_image=None)
        self.assertEqual(rc, 127)


class TestCampaignGated(unittest.TestCase):
    def test_unarmed_campaign_fires_nothing(self):
        eng = Engine(scope(exploit=True))                    # in-scope mais NON armé
        eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner())
        cov = eng.coverage()
        self.assertEqual(len(cov["fired"]), 0)               # rien tiré
        self.assertEqual(len(eng.run_records), 0)
        self.assertTrue(len(cov["dry_run"]) >= 1)            # tout simulé

    def test_idor_vetoed_without_allow_exploit(self):
        # armé mais exploit interdit ; on N'APPROUVE RIEN -> aucun module ne tire (hermétique).
        # la couche capacité (3) vétoe l'IDOR AVANT armement/approbation, donc le verdict tient.
        eng = Engine(scope(exploit=False)); eng.arm()
        eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner())
        idor = [r for r in eng.results if r["kind"] == "access_control.idor"]
        self.assertTrue(idor and idor[0]["verdict"] == "VETO")   # exploit non autorisé -> VETO dur
        self.assertEqual(len(eng.coverage()["fired"]), 0)        # rien tiré (recon en DRY_RUN)


class TestModuleSelection(unittest.TestCase):
    """Plomberie console->moteur : la sélection de modules RESTREINT le plan ; les params arrivent."""

    def test_no_modules_plans_full_brain(self):
        # modules=None -> plan complet (httpx + nuclei + idor pour une cible web), inchangé.
        eng = Engine(scope(exploit=False))
        eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner())
        kinds = {r["kind"] for r in eng.results}
        self.assertIn("recon.httpx", kinds)
        self.assertIn("web.nuclei", kinds)
        self.assertIn("access_control.idor", kinds)

    def test_modules_restrict_plan_to_selected_kind(self):
        # modules=["recon.httpx"] -> SEUL httpx est planifié (plus de nuclei ni idor).
        eng = Engine(scope(exploit=False))
        eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(),
                     modules=["recon.httpx"])
        kinds = {r["kind"] for r in eng.results}
        self.assertEqual(kinds, {"recon.httpx"})

    def test_empty_modules_list_is_full_plan(self):
        # liste vide == None : pas de restriction (la console n'émet --modules que si non vide).
        eng = Engine(scope(exploit=False))
        eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), modules=[])
        kinds = {r["kind"] for r in eng.results}
        self.assertIn("web.nuclei", kinds)

    def test_scope_module_params_reach_action_params(self):
        # module_params globaux (issus du scope) -> action.params (lu par le module via params.get).
        captured = {}
        eng = Engine(scope(exploit=False))
        orig_run = eng.run
        def spy(actions):
            for a in actions:
                captured[a.kind] = dict(a.params)
            return orig_run(actions)
        eng.run = spy
        eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(),
                     modules=["web.nuclei"],
                     module_params={"web.nuclei": {"severity": "critical"}})
        self.assertEqual(captured.get("web.nuclei", {}).get("severity"), "critical")

    def test_target_attrs_module_params_reach_action_params(self):
        # target.attrs.module_params[kind] -> action.params, capté en interceptant run().
        captured = {}
        sc = scope(exploit=False)
        eng = Engine(sc)
        orig_run = eng.run
        def spy(actions):
            for a in actions:
                captured[a.kind] = dict(a.params)
            return orig_run(actions)
        eng.run = spy
        tgt = Target("app.test", "url",
                     attrs={"module_params": {"recon.httpx": {"flag": "x", "ports": "80,443"}}})
        eng.campaign([tgt], HeuristicBrain(), Planner(), modules=["recon.httpx"])
        self.assertEqual(captured.get("recon.httpx", {}).get("flag"), "x")
        self.assertEqual(captured.get("recon.httpx", {}).get("ports"), "80,443")


class TestNucleiSeverityParam(unittest.TestCase):
    """web.nuclei CONSOMME le param `severity` (mapping UI->module effectif), filtré fail-safe."""

    def _module(self):
        from forge import modules as mods
        return mods.get("web.nuclei")

    def test_param_severity_used_in_cmdline(self):
        m = self._module()
        a = Action("web.nuclei", "app.test", params={"severity": "critical"})
        self.assertEqual(m._severity(a), "critical")
        self.assertIn("critical", m.dry(a))                  # reflété dans le PoC/dry

    def test_param_severity_list_form(self):
        m = self._module()
        a = Action("web.nuclei", "app.test", params={"severity": ["high", "critical"]})
        self.assertEqual(m._severity(a), "high,critical")

    def test_absent_or_invalid_severity_falls_back_to_default(self):
        m = self._module()
        self.assertEqual(m._severity(Action("web.nuclei", "app.test")), "medium,high,critical")
        # aucun token n'est une sévérité valide ("info; rm -rf" != "info") -> repli défaut,
        # et de toute façon jamais concaténé à un shell (runner exécute argv, pas une string).
        bad = Action("web.nuclei", "app.test", params={"severity": "pwn,info; rm -rf"})
        self.assertEqual(m._severity(bad), "medium,high,critical")
        # une liste contenant un token valide ne garde QUE le valide :
        ok = Action("web.nuclei", "app.test", params={"severity": ["info", "bogus"]})
        self.assertEqual(m._severity(ok), "info")


class TestReport(unittest.TestCase):
    """Le rapport anti-masquage expose skipped_budget / coverage_gaps / dups (zéro lacune silencieuse)."""

    def _engine_with_transparency(self):
        # campagne NON armée -> tout en DRY_RUN (hermétique), puis on injecte les traces anti-masquage
        eng = Engine(scope(exploit=True))
        eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner())
        # déférée par budget (defer != delete)
        eng.skipped_budget = [Action("web.nuclei", "app.test", cls="web", value=.1, cost=9)]
        # classe jamais tentée
        eng.coverage_gaps = {"app.test": ["business_logic", "ssrf"]}
        # findings dédupliqués
        eng.dups = 2
        return eng

    def test_report_lists_skipped_budget(self):
        md = report.build_report(self._engine_with_transparency())
        self.assertIn("Déférées (budget)", md)
        self.assertIn("web.nuclei", md)

    def test_report_lists_coverage_gaps(self):
        md = report.build_report(self._engine_with_transparency())
        self.assertIn("Classes jamais tentées", md)
        self.assertIn("business_logic", md)
        self.assertIn("ssrf", md)

    def test_report_reports_dups_count(self):
        md = report.build_report(self._engine_with_transparency())
        self.assertIn("dédupliqués", md)
        self.assertIn("2", md)                               # dups=2 affiché

    def test_report_has_transparency_section(self):
        md = report.build_report(self._engine_with_transparency())
        self.assertIn("anti-masquage", md)
        self.assertIn("Simulées (DRY_RUN)", md)

    def test_report_without_transparency_omits_optional_sections(self):
        # engine vierge (pas de skipped/gaps/dups) -> sections optionnelles absentes, pas de crash
        md = report.build_report(Engine(scope()))
        self.assertNotIn("Déférées (budget)", md)
        self.assertNotIn("Classes jamais tentées", md)
        self.assertIn("Synthèse", md)                        # le squelette reste là

    def test_report_parity_header_techniques_and_console_pointer(self):
        # PARITÉ CONSOLE : un run armé/approuvé qui tire une technique doit exposer, dans le rapport CLI,
        # (a) l'en-tête d'engagement (périmètre scope), (b) la section « Techniques ATT&CK exercées »
        # avec le MITRE tiré, (c) le pointeur vers le rapport console /api/runs/<id>/report.
        eng = Engine(scope(), run_id="run-xyz")
        eng.arm()
        a = Action("demo.fingerprint", "app.test", params={"mitre": "T1190"})
        eng.approve(a.id)
        eng.execute(a)
        md = report.build_report(eng)
        # (a) en-tête d'engagement — périmètre dérivé du scope
        self.assertIn("## Engagement", md)
        self.assertIn("In-scope", md)
        self.assertIn("app.test", md)
        self.assertIn("**Run** : run-xyz", md)               # run_id reflété dans l'en-tête
        # (b) techniques ATT&CK exercées — le MITRE réellement tiré est listé
        self.assertIn("Techniques ATT&CK exercées", md)
        self.assertIn("T1190", md)
        # (c) pointeur console — matrice détecté/raté + MTTD + annexe custody vivent côté console
        self.assertIn("/api/runs/run-xyz/report", md)
        self.assertIn("MTTD", md)
        self.assertIn("détecté / raté", md)

    def test_report_parity_degrades_without_run_or_ledger(self):
        # sans run_id ni tir : en-tête présent (scope), techniques en placeholder, pointeur générique.
        md = report.build_report(Engine(scope()))
        self.assertIn("## Engagement", md)
        self.assertIn("Aucune technique ATT&CK tirée", md)   # placeholder, pas de crash
        self.assertIn("/api/runs/<run-id>/report", md)       # pointeur générique quand run_id absent


class TestCoverageAccounting(unittest.TestCase):
    """Anti-lacune silencieuse — chaque module SÉLECTIONNÉ est comptabilisé : soit planifié
    (fired/dry/vetoed/errors, entré dans results), soit listé dans `not_planned` avec une raison.
    `not_planned ∪ planifiés == selected` : aucun module disponible ne disparaît du rapport (le trou
    des 35 « outil présent mais jamais ordonnancé »)."""

    def _run(self, exploit=False):
        # scope legacy (aucune sélection technique) -> univers « select-all » = TOUS les modules
        # enregistrés ; le HeuristicBrain n'en planifie qu'une poignée -> le reste = disponibles non
        # planifiés (reproduit fidèlement le bucket manquant sur des données réelles).
        eng = Engine(scope(exploit=exploit))
        eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner())
        return eng

    def test_accounting_closes_selected_equals_planned_plus_not_planned(self):
        eng = self._run()
        planned = {r["kind"] for r in eng.results}
        not_planned = set(eng.not_planned)
        # (1) partition : disponibles-non-planifiés et planifiés sont DISJOINTS…
        self.assertTrue(not_planned.isdisjoint(planned), "un module ne peut être à la fois planifié et non-planifié")
        # (2) …et leur union RECOUVRE EXACTEMENT l'univers sélectionné -> zéro omission silencieuse.
        self.assertEqual(not_planned | planned, eng.selected_modules)
        # (3) le run reproduit bien le trou : des modules disponibles n'ont PAS été planifiés.
        self.assertTrue(not_planned, "des modules disponibles auraient dû rester non planifiés")

    def test_not_planned_reasons_are_truthful(self):
        # un module non-exploit disponible mais non planifié porte la raison « hors périmètre du plan » ;
        # un module exploit sous un scope lecture-seule porte la raison capacité-exploit (dérivée, non fabriquée).
        eng = self._run(exploit=False)
        # business_logic.scan : disponible, non-exploit, jamais proposé par le brain heuristique ->
        # raison « hors périmètre du plan » (dérivée : surface non concordante / capacités engagement).
        self.assertIn("business_logic.scan", eng.not_planned)
        self.assertIn("non planifié", eng.not_planned["business_logic.scan"])
        # rce.probe : module exploit -> sous allow_exploit=false, raison = capacité exploit non autorisée.
        self.assertIn("rce.probe", eng.not_planned)
        self.assertIn("exploit", eng.not_planned["rce.probe"])

    def test_report_lists_not_planned_modules_with_reasons(self):
        eng = self._run()
        md = report.build_report(eng)
        self.assertIn("Modules disponibles non planifiés", md)
        self.assertIn("Disponibles non planifiés", md)         # compteur dans la synthèse transparence
        # un module concret disponible-non-planifié figure NOMMÉMENT avec sa raison.
        self.assertIn("web.nikto", md)

    def test_ingest_payload_carries_not_planned(self):
        from forge import console_client
        eng = self._run()
        payload = console_client.build_payload(
            "camp", eng.findings, eng.run_records, not_planned=eng.not_planned)
        self.assertIn("not_planned", payload)                  # additif : nouveau champ JSON
        self.assertEqual(payload["not_planned"], {k: str(v) for k, v in eng.not_planned.items()})

    def test_no_not_planned_section_when_all_selected_planned(self):
        # rétro-compat : engine vierge (aucune campagne) -> not_planned vide -> section absente, pas de crash.
        md = report.build_report(Engine(scope()))
        self.assertNotIn("Modules disponibles non planifiés", md)


class TestPurple(unittest.TestCase):
    def test_runrecord_emitted_on_fire(self):
        # module demo (no-op) armé+approuvé -> un FIRE -> un run-record
        eng = Engine(scope()); eng.arm()
        a = Action("demo.fingerprint", "app.test", params={"mitre": "T1190"})
        eng.approve(a.id)
        eng.execute(a)
        self.assertEqual(len(eng.run_records), 1)
        self.assertEqual(eng.run_records[0]["mitre"], "T1190")
        d = Path(tempfile.mkdtemp(prefix="forge-purple-"))
        n = purple.emit(d / "rr.jsonl", eng.run_records)
        self.assertEqual(n, 1)
        self.assertTrue((d / "rr.jsonl").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)

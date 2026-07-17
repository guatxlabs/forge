"""R1 — PROFIL DE RESSOURCES UNIFIÉ (`FORGE_RESOURCE_PROFILE=low|balanced|full`).

UN bouton fixe les DÉFAUTS de tous les leviers de ressources. Preuves :

  (a) PRÉCÉDENCE `resolve()` : override > profil > défaut, prouvée sur un levier ;
  (b) `active_profile()` lit l'env, défaut `balanced`, fail-open sur garbage ;
  (c) `low` => pool=1, timeouts courts, tools mini, petits caps ; `full` => plus haut ;
  (d) RÉTRO-COMPAT : `FORGE_PARALLELISM=8` (env) PRIME toujours sur profil=low (override) ;
  (e) les leviers CÂBLÉS reflètent le profil (`engine._parallelism()` = 1 sous low sans env, 8 avec) ;
  (f) le profil actif est ENREGISTRÉ dans le run (ledger `engine.resource_profile` + rapport) ;
  (g) `balanced` == défauts-code actuels -> `FORGE_RESOURCE_PROFILE` non défini == NO-OP (byte-identique).
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import resource_profile as rp                       # noqa: E402
from forge import engine as engmod                             # noqa: E402
from forge import runner                                       # noqa: E402
from forge.roe import Scope                                    # noqa: E402
from forge.engine import Engine                                # noqa: E402
from forge.ledger import Ledger                                # noqa: E402
from forge.report import build_report                          # noqa: E402
from forge.schema import Target                                # noqa: E402
from forge.planner import Planner                              # noqa: E402
from forge.modules.web import NucleiScan as Nuclei             # noqa: E402
from forge.roe import Action                                   # noqa: E402


class _EnvGuard:
    """Sauvegarde/restaure les variables d'env de ressources autour d'un test (isolation stricte)."""
    _VARS = ("FORGE_RESOURCE_PROFILE", "FORGE_PARALLELISM", "FORGE_RUN_TIMEOUT", "FORGE_TOOLS_PROFILE")

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in self._VARS}
        for k in self._VARS:
            os.environ.pop(k, None)
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


class _NullBrain:
    def propose(self, graph_state):
        return []                                             # aucune action -> campagne = amorçage seul


# ===================================================================================================
class TestResolvePrecedence(unittest.TestCase):
    """(a) override > profil > défaut — LE contrat du résolveur."""

    def test_override_beats_profile_beats_default(self):
        with _EnvGuard():
            # override GAGNE sur profil ET défaut
            self.assertEqual(rp.resolve("parallelism", override=8, profile="low", default=4), 8)
            # sans override : profil GAGNE sur défaut
            self.assertEqual(rp.resolve("parallelism", profile="low", default=4), 1)
            self.assertEqual(rp.resolve("parallelism", profile="full", default=4), 12)
            # sans override ni valeur de profil connue : défaut
            self.assertEqual(rp.resolve("levier_inconnu", profile="low", default=99), 99)

    def test_override_none_falls_through(self):
        with _EnvGuard():
            # None N'EST PAS un override : on tombe sur le profil
            self.assertEqual(rp.resolve("parallelism", override=None, profile="low", default=4), 1)

    def test_int_knobs_coerced(self):
        with _EnvGuard():
            # override chaîne "8" (typique d'une var d'env) -> int 8
            self.assertEqual(rp.resolve("parallelism", override="8", profile="low", default=4), 8)
            self.assertIsInstance(rp.resolve("parallelism", override="8", profile="low", default=4), int)
            # override entier GARBAGE -> fail-through vers le profil (fail-open)
            self.assertEqual(rp.resolve("parallelism", override="abc", profile="low", default=4), 1)


# ===================================================================================================
class TestActiveProfile(unittest.TestCase):
    """(b) `active_profile()` lit l'env, défaut balanced, fail-open sur garbage."""

    def test_unset_defaults_balanced(self):
        with _EnvGuard():
            self.assertEqual(rp.active_profile(), "balanced")

    def test_reads_env(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            self.assertEqual(rp.active_profile(), "low")
            os.environ["FORGE_RESOURCE_PROFILE"] = "FULL"     # insensible à la casse
            self.assertEqual(rp.active_profile(), "full")

    def test_fail_open_on_garbage(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "wibble"
            self.assertEqual(rp.active_profile(), "balanced")
            os.environ["FORGE_RESOURCE_PROFILE"] = ""
            self.assertEqual(rp.active_profile(), "balanced")

    def test_setting_arg_beats_env(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "full"
            self.assertEqual(rp.active_profile(setting="low"), "low")


# ===================================================================================================
class TestProfileShape(unittest.TestCase):
    """(c) low réduit les ressources ; full les augmente ; balanced == défauts."""

    def test_low_reduces_resources(self):
        low = rp.PROFILES["low"]
        self.assertEqual(low["parallelism"], 1)               # SÉRIEL
        self.assertEqual(low["tools_profile"], "mini")        # image d'outils légère
        self.assertLess(low["action_timeout_secs"], rp.PROFILES["balanced"]["action_timeout_secs"])
        self.assertLess(low["crawl_max_endpoints"], rp.PROFILES["balanced"]["crawl_max_endpoints"])
        self.assertLess(low["crawl_max_params"], rp.PROFILES["balanced"]["crawl_max_params"])
        self.assertLess(low["content_fanout_max"], rp.PROFILES["balanced"]["content_fanout_max"])
        self.assertEqual(low["nuclei_severity"], "medium,high,critical")

    def test_full_increases_resources(self):
        full, bal = rp.PROFILES["full"], rp.PROFILES["balanced"]
        self.assertGreater(full["parallelism"], bal["parallelism"])
        self.assertGreater(full["action_timeout_secs"], bal["action_timeout_secs"])
        self.assertGreater(full["crawl_max_endpoints"], bal["crawl_max_endpoints"])
        self.assertGreater(full["content_fanout_max"], bal["content_fanout_max"])

    def test_balanced_matches_todays_code_defaults(self):
        """(g) balanced == défauts-code AUJOURD'HUI -> profil non défini = NO-OP byte-identique."""
        bal = rp.PROFILES["balanced"]
        # engine pool par défaut
        self.assertEqual(bal["parallelism"], engmod._DEFAULT_PARALLELISM)
        # borne d'action par défaut de runner.tool
        self.assertEqual(bal["action_timeout_secs"], runner._DEFAULT_ACTION_TIMEOUT)
        # sévérité nuclei par défaut
        self.assertEqual(bal["nuclei_severity"], Nuclei._DEFAULT_SEV)
        # caps de crawl/fan-out par défaut
        from forge.modules.recon_surface import PassiveSurface
        from forge.brain import HeuristicBrain
        self.assertEqual(bal["crawl_max_endpoints"], PassiveSurface.MAX_ENDPOINTS)
        self.assertEqual(bal["crawl_max_params"], HeuristicBrain.MAX_PARAMS_PER_ENDPOINT)
        self.assertEqual(bal["content_fanout_max"], HeuristicBrain.MAX_CHAIN_TARGETS)


# ===================================================================================================
class TestWiredKnobs(unittest.TestCase):
    """(d)(e) les leviers CÂBLÉS reflètent le profil, et les overrides d'env préexistants PRIMENT."""

    def test_engine_parallelism_reflects_profile(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            self.assertEqual(engmod._parallelism(), 1)        # (e) low sans env -> 1
            os.environ["FORGE_RESOURCE_PROFILE"] = "full"
            self.assertEqual(engmod._parallelism(), 12)       # full -> 12

    def test_backward_compat_env_beats_profile(self):
        """(d) RÉTRO-COMPAT : FORGE_PARALLELISM=8 (env) PRIME sur profil=low."""
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            os.environ["FORGE_PARALLELISM"] = "8"
            self.assertEqual(engmod._parallelism(), 8)        # l'override d'env GAGNE (pas 1)

    def test_unset_profile_is_noop_for_parallelism(self):
        with _EnvGuard():
            # aucun profil, aucun env -> défaut-code historique 4 (byte-identique)
            self.assertEqual(engmod._parallelism(), engmod._DEFAULT_PARALLELISM)

    def test_nuclei_severity_reflects_profile_and_param_override(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            n = Nuclei()
            # profil low -> sévérité restreinte
            self.assertEqual(n._severity(Action("web.nuclei", "app.test")), "medium,high,critical")
            # param explicite (override) GAGNE sur le profil
            self.assertEqual(
                n._severity(Action("web.nuclei", "app.test", params={"severity": "info,low"})),
                "info,low")

    def test_nuclei_severity_balanced_is_default(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "balanced"
            n = Nuclei()
            self.assertEqual(n._severity(Action("web.nuclei", "app.test")), Nuclei._DEFAULT_SEV)


# ===================================================================================================
class TestRunRecording(unittest.TestCase):
    """(f) le profil actif est ENREGISTRÉ dans le run (ledger + rapport)."""

    def _scope(self):
        return Scope({"in_scope": ["app.test"]})

    def test_profile_recorded_in_ledger_and_report(self):
        with _EnvGuard(), tempfile.TemporaryDirectory() as tmp:
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            ledger = Ledger(Path(tmp) / "engagement.jsonl")
            eng = Engine(self._scope(), ledger=ledger)
            eng.campaign([Target("app.test", "app")], _NullBrain(), Planner())

            # (1) snapshot exposé sur l'engine
            self.assertIsInstance(eng.resource_profile, dict)
            self.assertEqual(eng.resource_profile["profile"], "low")
            self.assertEqual(eng.resource_profile["knobs"]["parallelism"], 1)

            # (2) événement de ledger émis
            text = (Path(tmp) / "engagement.jsonl").read_text(encoding="utf-8")
            kinds = [json.loads(l)["kind"] for l in text.splitlines() if l.strip()]
            self.assertIn("engine.resource_profile", kinds)
            evt = next(json.loads(l) for l in text.splitlines()
                       if l.strip() and json.loads(l)["kind"] == "engine.resource_profile")
            self.assertEqual(evt["detail"]["profile"], "low")
            # la chaîne append-only reste vérifiable
            self.assertTrue(ledger.verify())

            # (3) en-tête de rapport
            report = build_report(eng)
            self.assertIn("Profil ressources", report)
            self.assertIn("`low`", report)

    def test_backward_compat_env_override_recorded(self):
        with _EnvGuard(), tempfile.TemporaryDirectory() as tmp:
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            os.environ["FORGE_PARALLELISM"] = "8"
            ledger = Ledger(Path(tmp) / "engagement.jsonl")
            eng = Engine(self._scope(), ledger=ledger)
            eng.campaign([Target("app.test", "app")], _NullBrain(), Planner())
            # le snapshot reflète l'override d'env EFFECTIF (8), pas la valeur de profil (1)
            self.assertEqual(eng.resource_profile["knobs"]["parallelism"], 8)

    def test_no_ledger_no_crash_and_still_snapshotted(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "full"
            eng = Engine(self._scope())                       # PAS de ledger
            eng.campaign([Target("app.test", "app")], _NullBrain(), Planner())
            self.assertEqual(eng.resource_profile["profile"], "full")


if __name__ == "__main__":
    unittest.main()

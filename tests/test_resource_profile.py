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


# ===================================================================================================
# R2 — BALAYAGE ANTI-HARD-CODE : leviers de ressources RESTANTS câblés au résolveur.
#   crawl_max_depth (injection.MAX_DEPTH) · llm_max_tokens/llm_num_ctx (llm.LLMConfig) · triage caps
#   (triage.summary) · discovery_max_fanout (_discovery) · helper max_concurrent_procs (expose→R4).
# Pour CHAQUE : (a) précédence override>profil>défaut ; (b) balanced == défaut-code AUJOURD'HUI (no-op) ;
# (c) low ALLÈGE ; + gardes de câblage (le profil actif change la valeur EFFECTIVE au call-site).
# ===================================================================================================
from forge.llm import LLMConfig                                 # noqa: E402
from forge.llm import LLMClient                                 # noqa: E402
from forge.modules.injection import PathTraversal, _TRAVERSAL_TOKENS  # noqa: E402
from forge import triage as T                                   # noqa: E402
from forge.modules import _discovery                            # noqa: E402
from forge.schema import Finding                                # noqa: E402


class TestR2NewKnobsPrecedenceAndShape(unittest.TestCase):
    """(a)(b)(c) au niveau TABLE/résolveur pour chaque levier R2 nouvellement câblé."""

    _NEW = ("crawl_max_depth", "discovery_max_fanout", "llm_max_tokens",
            "llm_num_ctx", "triage_max_items", "triage_max_clusters")

    def test_precedence_override_beats_profile_beats_default(self):
        with _EnvGuard():
            for knob in self._NEW:
                # override GAGNE partout
                self.assertEqual(rp.resolve(knob, override=7, profile="low", default=999), 7)
                # sans override : profil GAGNE sur défaut
                self.assertEqual(rp.resolve(knob, profile="low", default=999),
                                 rp.PROFILES["low"][knob])
                # override chaîne d'env coercée en int
                self.assertEqual(rp.resolve(knob, override="7", profile="low", default=999), 7)

    def test_balanced_equals_todays_literals(self):
        """(b) balanced == littéraux d'AUJOURD'HUI -> profil non défini = NO-OP byte-identique."""
        bal = rp.PROFILES["balanced"]
        self.assertEqual(bal["crawl_max_depth"], PathTraversal.MAX_DEPTH)          # 8
        self.assertEqual(bal["discovery_max_fanout"], _discovery._MAX_DISCOVERED_SERVICES)   # 25
        self.assertEqual(bal["discovery_max_fanout"], _discovery._MAX_PROBED_PORTS)          # 25
        self.assertEqual(bal["llm_max_tokens"], LLMConfig().max_tokens)            # 512
        self.assertEqual(bal["llm_num_ctx"], LLMConfig().num_ctx)                  # 0 (= non envoyé)
        self.assertEqual(bal["triage_max_items"], 10)
        self.assertEqual(bal["triage_max_clusters"], 20)

    def test_low_reduces_each_knob(self):
        low, bal = rp.PROFILES["low"], rp.PROFILES["balanced"]
        # numériquement réduits : depth, fan-out, max_tokens, triage caps
        for knob in ("crawl_max_depth", "discovery_max_fanout", "llm_max_tokens",
                     "triage_max_items", "triage_max_clusters"):
            self.assertLess(low[knob], bal[knob], knob)
        # num_ctx : balanced=0 (aucune borne, défaut modèle) ; low IMPOSE une fenêtre FINIE (=> plus léger).
        self.assertEqual(bal["llm_num_ctx"], 0)
        self.assertGreater(low["llm_num_ctx"], 0)

    def test_full_increases_each_knob(self):
        full, bal = rp.PROFILES["full"], rp.PROFILES["balanced"]
        for knob in self._NEW:
            self.assertGreater(full[knob], bal[knob], knob)


class TestR2InjectionDepthWiring(unittest.TestCase):
    """crawl_max_depth CÂBLÉ dans injection.PathTraversal._payloads (call-site guard)."""

    def _depth_of(self, payloads):
        return len(payloads) // len(_TRAVERSAL_TOKENS)

    def test_balanced_is_todays_depth(self):
        with _EnvGuard():                                        # aucun profil -> balanced
            n = self._depth_of(PathTraversal()._payloads(Action("path.traversal", "https://app.test/f")))
            self.assertEqual(n, PathTraversal.MAX_DEPTH)         # 8 -> byte-identique

    def test_low_reduces_depth(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            n = self._depth_of(PathTraversal()._payloads(Action("path.traversal", "https://app.test/f")))
            self.assertEqual(n, rp.PROFILES["low"]["crawl_max_depth"])   # 2 < 8
            self.assertLess(n, PathTraversal.MAX_DEPTH)

    def test_explicit_param_override_wins_over_profile(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"          # profil low
            a = Action("path.traversal", "https://app.test/f", params={"max_depth": 5})
            self.assertEqual(self._depth_of(PathTraversal()._payloads(a)), 5)   # param GAGNE


class TestR2LLMWiring(unittest.TestCase):
    """llm_max_tokens / llm_num_ctx CÂBLÉS dans LLMConfig.from_dict + payload (call-site guard)."""

    def _body(self, cfg):
        req = LLMClient(cfg)._build_request([{"role": "user", "content": "u"}])
        return json.loads(req.data)

    def test_balanced_is_byte_identical(self):
        with _EnvGuard():                                        # balanced
            cfg = LLMConfig.from_dict({"enabled": True})         # ni max_tokens ni num_ctx fournis
            self.assertEqual(cfg.max_tokens, 512)                # défaut-code
            self.assertEqual(cfg.num_ctx, 0)
            body = self._body(cfg)
            self.assertEqual(body["max_tokens"], 512)
            self.assertNotIn("options", body)                    # num_ctx NON envoyé -> payload inchangé

    def test_low_lightens_llm(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            cfg = LLMConfig.from_dict({"enabled": True})         # loopback par défaut
            self.assertEqual(cfg.max_tokens, 256)                # < 512
            self.assertEqual(cfg.num_ctx, 2048)
            body = self._body(cfg)
            self.assertEqual(body["max_tokens"], 256)
            self.assertEqual(body["options"]["num_ctx"], 2048)   # borne de contexte appliquée (loopback)

    def test_explicit_scope_keys_win_over_profile(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            cfg = LLMConfig.from_dict({"enabled": True, "max_tokens": 999, "num_ctx": 4096})
            self.assertEqual(cfg.max_tokens, 999)                # override scope GAGNE sur profil
            self.assertEqual(cfg.num_ctx, 4096)

    def test_num_ctx_not_sent_to_external_endpoint(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            cfg = LLMConfig.from_dict({"enabled": True, "base_url": "https://api.openai.com",
                                       "allow_external": True})
            self.assertEqual(cfg.num_ctx, 2048)
            self.assertNotIn("options", self._body(cfg))         # jamais de param inconnu vers OpenAI strict


class TestR2TriageCapsWiring(unittest.TestCase):
    """triage_max_items / triage_max_clusters CÂBLÉS dans triage.triage() — coverage-safe INCHANGÉ."""

    def _actionables(self, k):
        return [Finding(target=f"h{i}.example.com/x{i}", title=f"IDOR distinct #{i}", severity="MEDIUM",
                        category="CWE-639", status="tested", tool="oracle",
                        evidence=f"preuve unique {i}") for i in range(k)]

    def test_balanced_top_cap_is_ten(self):
        with _EnvGuard():
            res = T.triage(self._actionables(15))
            self.assertEqual(len(res.summary["top_findings"]), 10)   # défaut-code
            self.assertEqual(len(res.ranked), 15)                    # NEVER-DROP : tout conservé

    def test_low_reduces_top_cap(self):
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            res = T.triage(self._actionables(15))
            self.assertEqual(len(res.summary["top_findings"]), 5)    # allégé
            self.assertEqual(len(res.ranked), 15)                    # NEVER-DROP préservé sous low


class TestR2DiscoveryFanoutWiring(unittest.TestCase):
    """discovery_max_fanout / crawl_max_endpoints CÂBLÉS dans _discovery (call-site guard)."""

    def test_probe_cap_reflects_profile(self):
        ports = list(range(8000, 8060))                          # 60 ports « ouverts »
        fetch = lambda url: 200                                  # tout parle HTTP
        with _EnvGuard():                                        # balanced -> 25
            self.assertEqual(len(_discovery.http_confirmed_ports(fetch, "app.test", ports)),
                             _discovery._MAX_PROBED_PORTS)
        with _EnvGuard():
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"         # low -> 8
            self.assertEqual(len(_discovery.http_confirmed_ports(fetch, "app.test", ports)),
                             rp.PROFILES["low"]["discovery_max_fanout"])


class TestR2MaxConcurrentProcsHelper(unittest.TestCase):
    """max_concurrent_procs() — levier RÉSOLVABLE exposé pour l'enforcement R4 (pas codé en dur)."""

    def test_resolves_per_profile_and_override(self):
        with _EnvGuard():
            self.assertEqual(rp.max_concurrent_procs(), 6)       # balanced (défaut-code)
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            self.assertEqual(rp.max_concurrent_procs(), 2)       # low allège
            os.environ["FORGE_RESOURCE_PROFILE"] = "full"
            self.assertEqual(rp.max_concurrent_procs(), 16)
            # override GAGNE sur le profil, et plancher >= 1 garanti
            self.assertEqual(rp.max_concurrent_procs(override=3), 3)
            self.assertEqual(rp.max_concurrent_procs(override="garbage"), 16)   # fail-through -> profil


class TestR2GovernanceUntouched(unittest.TestCase):
    """GOUVERNANCE : rate_per_sec reste DOCUMENTATION-ONLY (aucun câblage débit via le profil)."""

    def test_rate_per_sec_is_documentation_only(self):
        # présent dans la table (audit/doc) mais AUCUN module ne lit `rate_per_sec` : le débit reste
        # porté par le scope/ROE. On garde la table cohérente sans jamais brancher la gouvernance.
        self.assertIn("rate_per_sec", rp.PROFILES["balanced"])
        self.assertEqual(rp.PROFILES["balanced"]["rate_per_sec"], 5)   # aligné défaut ROE, non imposé


if __name__ == "__main__":
    unittest.main()

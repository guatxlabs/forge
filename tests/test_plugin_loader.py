"""DROP-IN plugin system — auto-découverte in-tree + FORGE_PLUGINS + ToolSpec JSON/YAML (loader.py).

Garanties prouvées (aucune I/O réelle — subprocess/scope mockés) :
  (A) AUTO-DÉCOUVERTE : le scan du package importe EXACTEMENT les modules-plugins que l'ancien
      `__init__.py` listait à la main (aucun manquant, aucun infra importé par erreur) ; l'invariant
      global `set(mods.kinds()) == technique_kinds()` tient ; le set de kinds ne RÉGRESSE pas.
  (B) FORGE_PLUGINS `.py` : un plugin utilisateur ajoute un nouveau kind, dispatché par l'engine.
  (C) FORGE_TOOLSPECS / --toolspec JSON : un spec déclaratif enregistre un outil externe GOUVERNÉ
      (ExternalToolModule) ; fail-closed sur spec invalide (message nommant le fichier).
  (D) FAIL-SOFT : un plugin cassé est IGNORÉ avec un warning journalisé (nommant le fichier) — le
      moteur démarre quand même ; un bon plugin dans le même dossier se charge toujours.
  (E) GOUVERNANCE : un plugin ciblant un hôte HORS périmètre est VETO/skippé par le dispatch engine
      -> roe.decide, ZÉRO processus lancé (défense en profondeur identique à un module natif).

Isolement : chaque test SNAPSHOTTE puis RESTAURE le registre + les tables techniques (un kind ajouté
ne fuit JAMAIS vers les autres fichiers de test, dont l'invariant global de test_toolspec_catalog)."""
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import modules as mods                              # noqa: E402
from forge import techniques                                  # noqa: E402
from forge import runner                                      # noqa: E402
from forge.modules import loader                              # noqa: E402
from forge.modules.registry import REGISTRY                   # noqa: E402
from forge.modules.toolspec import ExternalToolModule         # noqa: E402
from forge.roe import Scope, Action                           # noqa: E402
from forge.engine import Engine                               # noqa: E402

# Les 28 modules-fichiers que l'ANCIEN __init__.py importait explicitement (pin « no missing module »).
OLD_EXPLICIT_MODULES = {
    "demo", "recon", "recon_surface", "recon_active", "web", "access_control", "ssrf", "auth",
    "cors", "injection", "injection_probes", "httpflow", "xxe", "rfi", "clientflow", "tokenapi",
    "race", "oauth", "rce", "business_logic", "origin", "takeover", "exposure", "evasion", "msf",
    "burp", "pentest", "toolcatalog",
}
# Un kind représentatif par module livré (échantillon « no regression » indépendant de toolcatalog).
REPRESENTATIVE_KINDS = {
    "demo.fingerprint", "recon.httpx", "recon.subdomains", "recon.content", "web.nuclei",
    "access_control.idor", "ssrf.callback", "auth.takeover", "cors.credentials", "ssti.eval",
    "nosql.probe", "request_smuggling.probe", "xxe.probe", "rfi.probe", "xss.reflected",
    "jwt.weakness", "race.condition", "oauth.flow", "rce.probe", "business_logic.scan",
    "origin.find", "subdomain.takeover", "framework.exposure", "evasion.xhr", "msf.module",
    "burp.scan", "network.smb", "recon.subfinder",
}
# Modules d'infrastructure qui NE DOIVENT JAMAIS être traités comme plugins.
INFRA_NEVER_PLUGIN = {"registry", "toolspec", "oracle", "_scopeguard", "loader", "contrib", "__init__"}


class _Registry:
    """Snapshot/restore du registre + tables techniques (isolement inter-tests fail-closed)."""

    def __enter__(self):
        self._reg = dict(REGISTRY)
        self._tech = dict(techniques.TECHNIQUES)
        self._cat = dict(techniques.CATALOG)
        self._env = {k: os.environ.get(k) for k in ("FORGE_PLUGINS", "FORGE_TOOLSPECS")}
        return self

    def __exit__(self, *a):
        REGISTRY.clear(); REGISTRY.update(self._reg)
        techniques.TECHNIQUES.clear(); techniques.TECHNIQUES.update(self._tech)
        techniques.CATALOG.clear(); techniques.CATALOG.update(self._cat)
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _boom(*a, **k):
    raise AssertionError("runner.tool lancé alors que la gouvernance aurait dû court-circuiter (zéro I/O)")


# =================================================================================================
class TestAutoDiscovery(unittest.TestCase):
    """(A) l'auto-découverte == l'ancienne liste explicite, sans régression ni fuite d'infra."""

    def test_all_old_explicit_modules_are_loaded(self):
        loaded = set(mods._LOADED["intree"])
        self.assertTrue(OLD_EXPLICIT_MODULES.issubset(loaded),
                        f"modules manquants: {OLD_EXPLICIT_MODULES - loaded}")

    def test_no_infra_module_loaded_as_plugin(self):
        loaded = set(mods._LOADED["intree"])
        self.assertEqual(loaded & INFRA_NEVER_PLUGIN, set(),
                         "un module d'infrastructure a été importé comme plugin")

    def test_representative_kinds_all_registered(self):
        missing = REPRESENTATIVE_KINDS - set(mods.kinds())
        self.assertEqual(missing, set(), f"kinds régressés/absents: {missing}")

    def test_global_invariant_kinds_equals_technique_kinds(self):
        # le contrat structurel : registre == kinds-techniques (les tool-specs se foldent dans les deux).
        self.assertEqual(set(mods.kinds()), set(techniques.technique_kinds()))

    def test_discover_intree_is_idempotent(self):
        # re-scanner ne double rien (register écrase par kind ; re-import sûr).
        before = set(mods.kinds())
        again = loader.discover_intree(mods.__path__, mods.__name__)
        self.assertEqual(set(mods.kinds()), before)
        self.assertTrue(OLD_EXPLICIT_MODULES.issubset(set(again)))

    def test_infra_names_are_excluded_by_predicate(self):
        for name in INFRA_NEVER_PLUGIN:
            self.assertTrue(loader._is_infra(name), f"{name} devrait être exclu")
        self.assertFalse(loader._is_infra("toolcatalog"))   # se register lui-même -> DOIT être importé
        self.assertFalse(loader._is_infra("ssrf"))


# =================================================================================================
class TestForgePluginsPy(unittest.TestCase):
    """(B) un plugin `.py` FORGE_PLUGINS ajoute un nouveau kind, dispatché par l'engine."""

    PLUGIN = textwrap.dedent("""
        from forge.modules.registry import register, Module
        @register("plugintest.native")
        class P(Module):
            kind = "plugintest.native"
            description = "plugin natif de test"
            def dry(self, action): return "echo dry"
            def fire(self, action):
                return [self.finding(target=action.target, title="native plugin fired",
                                     severity="INFO", category="Recon", status="tested",
                                     tool="plugintest")]
    """)

    def test_env_py_plugin_adds_kind_and_is_dispatchable(self):
        with _Registry():
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "myplug.py").write_text(self.PLUGIN, encoding="utf-8")
                os.environ["FORGE_PLUGINS"] = d
                loaded = loader.load_env_plugins()
                self.assertEqual(len(loaded), 1)
                self.assertIn("plugintest.native", mods.kinds())
                # le kind est réellement dispatchable via l'engine (in-scope -> tiré). Scope SANS
                # sélection par-technique -> enabled_kinds=None (rétro-compat) : le kind natif tire.
                eng = Engine(Scope({"in_scope": ["good.test"]}))
                eng.arm(); eng.approve("plugintest.native:good.test")
                res = eng.execute(Action("plugintest.native", "good.test"))
                self.assertEqual(res["verdict"], "FIRE")
        self.assertNotIn("plugintest.native", mods.kinds())   # nettoyé (aucune fuite)

    def test_single_file_path_imported_directly(self):
        with _Registry():
            with tempfile.TemporaryDirectory() as d:
                f = Path(d) / "single.py"
                f.write_text(self.PLUGIN, encoding="utf-8")
                os.environ["FORGE_PLUGINS"] = str(f)          # fichier, pas dossier
                loader.load_env_plugins()
                self.assertIn("plugintest.native", mods.kinds())

    def test_plugin_can_override_kind_loaded_after_intree(self):
        # un plugin chargé APRÈS peut surcharger un kind natif (register écrase par kind).
        override = textwrap.dedent("""
            from forge.modules.registry import register, Module
            @register("demo.fingerprint")
            class Over(Module):
                kind = "demo.fingerprint"
                description = "OVERRIDDEN"
                def dry(self, a): return "x"
                def fire(self, a): return []
        """)
        with _Registry():
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "over.py").write_text(override, encoding="utf-8")
                os.environ["FORGE_PLUGINS"] = d
                loader.load_env_plugins()
                self.assertEqual(mods.get("demo.fingerprint").description, "OVERRIDDEN")


# =================================================================================================
class TestToolspecLoader(unittest.TestCase):
    """(C) un ToolSpec déclaratif JSON enregistre un outil externe GOUVERNÉ ; fail-closed sur spec KO."""

    GOOD = {
        "kind": "recon.plugintool", "vuln_class": "Recon", "binary": "mytool",
        "argv_template": ["-silent", "-u", "{target_url}"], "cwe": "CWE-200", "mitre": "T1595",
        "phase": "recon", "parser": "lines", "hit_status": "tested", "hit_is_asset": False,
    }

    def _write(self, obj, suffix=".json"):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
        json.dump(obj, f); f.close()
        return f.name

    def test_json_toolspec_registers_governed_external_module(self):
        with _Registry():
            path = self._write(self.GOOD)
            kind = loader.load_toolspec_file(path)
            os.unlink(path)
            self.assertEqual(kind, "recon.plugintool")
            m = mods.get(kind)
            self.assertIsInstance(m, ExternalToolModule)      # gouverné : base scope-guardée
            self.assertIn(kind, techniques.technique_kinds()) # foldé dans la table
            self.assertEqual(m.mitre, "T1595")

    def test_env_toolspecs_dir_loads_json(self):
        with _Registry():
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "t.json").write_text(json.dumps(self.GOOD), encoding="utf-8")
                os.environ["FORGE_TOOLSPECS"] = d
                kinds = loader.load_env_toolspecs()
                self.assertEqual(kinds, ["recon.plugintool"])
                self.assertIn("recon.plugintool", mods.kinds())

    def test_status_clamped_never_vulnerable(self):
        # même un spec malveillant (hit_status='vulnerable') est CLAMPÉ à reported_by_tool.
        bad_status = dict(self.GOOD, kind="recon.clamp", hit_status="vulnerable")
        with _Registry():
            path = self._write(bad_status)
            loader.load_toolspec_file(path); os.unlink(path)
            m = mods.get("recon.clamp")

            saved_tool, saved_avail = runner.tool, runner.available
            runner.tool = lambda *a, **k: (0, "hit-line\n", "")
            runner.available = lambda *a, **k: True            # binaire présent -> atteint le parsing
            try:
                f = m.fire(Action("recon.clamp", "good.test", params={"in_scope": ["good.test"]}))
            finally:
                runner.tool, runner.available = saved_tool, saved_avail
            for x in f:
                self.assertNotEqual(x.status, "vulnerable")

    def test_unknown_field_fail_closed_names_file(self):
        with _Registry():
            path = self._write(dict(self.GOOD, bogus=1))
            with self.assertRaises(loader.SpecError) as cm:
                loader.load_toolspec_file(path)
            os.unlink(path)
            self.assertIn(path, str(cm.exception))
            self.assertIn("inconnu", str(cm.exception))

    def test_missing_required_field_fail_closed(self):
        bad = {"kind": "x.y", "vuln_class": "X"}               # binary + argv_template manquants
        with _Registry():
            path = self._write(bad)
            with self.assertRaises(loader.SpecError) as cm:
                loader.load_toolspec_file(path)
            os.unlink(path)
            self.assertIn("requis manquant", str(cm.exception))

    def test_invalid_json_fail_closed(self):
        with _Registry():
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            f.write("{not json"); f.close()
            with self.assertRaises(loader.SpecError):
                loader.load_toolspec_file(f.name)
            os.unlink(f.name)

    def test_yaml_optional_no_hard_dep(self):
        # YAML n'est chargé QUE si pyyaml présent ; sinon SpecError clair (jamais un ImportError dur).
        with _Registry():
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
            f.write("kind: recon.yamltool\nvuln_class: Recon\nbinary: y\nargv_template: ['{target_url}']\n")
            f.close()
            if loader._try_yaml() is None:
                with self.assertRaises(loader.SpecError) as cm:
                    loader.load_toolspec_file(f.name)
                self.assertIn("pyyaml", str(cm.exception))
            else:
                kind = loader.load_toolspec_file(f.name)
                self.assertEqual(kind, "recon.yamltool")
            os.unlink(f.name)


# =================================================================================================
class TestFailSoft(unittest.TestCase):
    """(D) plugin cassé -> ignoré AVEC warning journalisé ; le moteur démarre ; un bon plugin passe."""

    BROKEN = "raise RuntimeError('plugin explodes at import')\n"
    GOOD = textwrap.dedent("""
        from forge.modules.registry import register, Module
        @register("plugintest.good")
        class G(Module):
            kind = "plugintest.good"
            def dry(self, a): return "x"
            def fire(self, a): return []
    """)

    def test_broken_plugin_skipped_with_logged_warning(self):
        with _Registry():
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "broken.py").write_text(self.BROKEN, encoding="utf-8")
                os.environ["FORGE_PLUGINS"] = d
                with self.assertLogs("forge.modules.loader", level="WARNING") as cm:
                    loaded = loader.load_env_plugins()
                self.assertEqual(loaded, [])                   # rien chargé
                self.assertTrue(any("broken.py" in m for m in cm.output))  # cause journalisée, nommée
                self.assertTrue(any("RuntimeError" in m for m in cm.output))

    def test_good_plugin_loads_despite_sibling_broken(self):
        with _Registry():
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "a_broken.py").write_text(self.BROKEN, encoding="utf-8")
                (Path(d) / "b_good.py").write_text(self.GOOD, encoding="utf-8")
                os.environ["FORGE_PLUGINS"] = d
                with self.assertLogs("forge.modules.loader", level="WARNING"):
                    loaded = loader.load_env_plugins()
                self.assertEqual(len(loaded), 1)               # le bon est chargé, le cassé ignoré
                self.assertIn("plugintest.good", mods.kinds())

    def test_nonexistent_path_logged_not_crash(self):
        with _Registry():
            os.environ["FORGE_PLUGINS"] = "/no/such/path/xyz"
            with self.assertLogs("forge.modules.loader", level="WARNING"):
                self.assertEqual(loader.load_env_plugins(), [])

    def test_broken_toolspec_dir_skipped_soft(self):
        # FORGE_TOOLSPECS fail-soft par fichier (miroir de FORGE_PLUGINS) : spec KO -> warning, boot OK.
        with _Registry():
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "bad.json").write_text('{"kind":"x","bogus":1}', encoding="utf-8")
                (Path(d) / "good.json").write_text(json.dumps(
                    {"kind": "recon.softgood", "vuln_class": "Recon", "binary": "b",
                     "argv_template": ["{target_url}"]}), encoding="utf-8")
                os.environ["FORGE_TOOLSPECS"] = d
                with self.assertLogs("forge.modules.loader", level="WARNING"):
                    kinds = loader.load_env_toolspecs()
                self.assertIn("recon.softgood", kinds)         # le bon passe malgré le cassé


# =================================================================================================
class TestGovernancePreserved(unittest.TestCase):
    """(E) un plugin hors périmètre est VETO/skippé par l'engine, ZÉRO processus lancé."""

    def test_out_of_scope_plugin_vetoed_zero_process(self):
        spec_obj = {
            "kind": "recon.evilprobe", "vuln_class": "Recon", "binary": "mytool",
            "argv_template": ["-u", "{target_url}"], "phase": "recon", "parser": "lines",
        }
        with _Registry():
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            json.dump(spec_obj, f); f.close()
            loader.load_toolspec_file(f.name); os.unlink(f.name)
            self.assertIn("recon.evilprobe", mods.kinds())

            # Scope in = good.test UNIQUEMENT ; la cible du plugin est HORS périmètre.
            eng = Engine(Scope({"in_scope": ["good.test"]}))
            eng.arm(); eng.approve("recon.evilprobe:evil.attacker.com")
            saved = runner.tool
            runner.tool = _boom                                # aucun processus ne doit être lancé
            try:
                res = eng.execute(Action("recon.evilprobe", "evil.attacker.com"))
            finally:
                runner.tool = saved
            # VETO par le ROE (hors scope) OU SKIP par la sélection par-scope — jamais FIRE, jamais d'I/O.
            self.assertIn(res["verdict"], ("VETO", "SKIP"))
            self.assertNotEqual(res["verdict"], "FIRE")

    def test_module_level_scope_guard_defense_in_depth(self):
        # défense en profondeur : même appelé DIRECTEMENT, le module scope-garde (skipped, zéro I/O).
        spec_obj = {
            "kind": "recon.evilprobe2", "vuln_class": "Recon", "binary": "mytool",
            "argv_template": ["-u", "{target_url}"], "phase": "recon", "parser": "lines",
        }
        with _Registry():
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            json.dump(spec_obj, f); f.close()
            loader.load_toolspec_file(f.name); os.unlink(f.name)
            m = mods.get("recon.evilprobe2")
            saved_tool, saved_avail = runner.tool, runner.available
            runner.tool = _boom
            runner.available = lambda *a, **k: True
            try:
                out = m.fire(Action("recon.evilprobe2", "evil.attacker.com",
                                    params={"in_scope": ["good.test"]}))
            finally:
                runner.tool, runner.available = saved_tool, saved_avail
            self.assertEqual(out[0].status, "skipped")
            self.assertIn("hors périmètre", out[0].title)


if __name__ == "__main__":
    unittest.main(verbosity=2)

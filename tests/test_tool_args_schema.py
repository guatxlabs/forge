"""FEATURE A — arguments d'outils RICHES et SÛRS par-run pilotés par un SCHÉMA servi à l'UI.

Garanties prouvées (subprocess MOCKÉ — zéro I/O réel) :
  (A) nmap PLEINEMENT CUSTOM depuis l'UI : ports (-p), top_ports (--top-ports), scripts (--script),
      timing (-T0..5), extra_args (allowlist) produisent l'argv attendu ; défaut inchangé sinon.
  (B) EXTRA_ARGS gouvernés par une ALLOWLIST de drapeaux, FAIL-CLOSED : un flag hors liste (-oN,
      --script=<rce>) ou une chaîne non-liste -> REFUS, ZÉRO processus lancé.
  (C) `{args}` s'EXPAND dans build_argv depuis extra_args VALIDÉS (chaque token = 1 argv, no-shell) ;
      les placeholders `{param:X}` historiques marchent toujours.
  (D) `forge modules --json` porte `params_schema` + `flag_allowlist` (servis à la console/UI).
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import cli                                                          # noqa: E402
from forge import runner                                                       # noqa: E402
from forge import modules as mods                                             # noqa: E402
from forge.roe import Action                                                   # noqa: E402
from forge.modules.toolspec import (ToolSpec, build_argv, check_extra_args,    # noqa: E402
                                    unsafe_extra_args, safe_value)


class _Patch:
    def __init__(self, **attrs):
        self.attrs, self.saved = attrs, {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(runner, k)
            setattr(runner, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(runner, k, v)


def _boom(*a, **k):
    raise AssertionError("runner.tool appelé alors que le garde-fou aurait dû court-circuiter")


def _rows_json():
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.cmd_modules(type("A", (), {"json": True})())
    assert rc == 0
    return {r["kind"]: r for r in json.loads(buf.getvalue())}


# =================================================================================================
class TestNmapCustomArgs(unittest.TestCase):
    def _argv(self, params):
        m = mods.get("recon.nmap")
        return m._args(Action("recon.nmap", "scan.test", params=params))

    def test_default_when_unset(self):
        argv = self._argv({})
        self.assertEqual(argv, ["-sV", "-Pn", "--top-ports", "1000", "scan.test"])

    def test_fully_custom_argv(self):
        argv = self._argv({"ports": "1-65535", "scripts": "http-*", "timing": 2,
                           "extra_args": ["--max-rate", "50"]})
        # -p prime sur top-ports ; --script ; -T2 concaténé ; extra allowlistés ; cible en dernier.
        self.assertIn("-p", argv)
        self.assertIn("1-65535", argv)
        self.assertIn("--script", argv)
        self.assertIn("http-*", argv)
        self.assertIn("-T2", argv)
        self.assertIn("--max-rate", argv)
        self.assertIn("50", argv)
        self.assertEqual(argv[-1], "scan.test")
        self.assertNotIn("--top-ports", argv)          # -p remplace le défaut top-ports

    def test_allowlisted_p_dash_via_extra(self):
        argv = self._argv({"extra_args": ["-p-"]})
        self.assertIn("-p-", argv)                     # -p- est dans l'allowlist nmap

    def test_top_ports_when_no_ports(self):
        argv = self._argv({"top_ports": 500})
        self.assertIn("--top-ports", argv)
        self.assertIn("500", argv)

    def test_hostile_port_value_ignored(self):
        # une valeur commençant par '-' (option smuggling) est REJETÉE -> repli sur le défaut.
        argv = self._argv({"ports": "-oN"})
        self.assertEqual(argv, ["-sV", "-Pn", "--top-ports", "1000", "scan.test"])

    def test_timing_out_of_range_ignored(self):
        argv = self._argv({"timing": 9})
        self.assertFalse(any(t.startswith("-T") for t in argv))


class TestNmapFailClosed(unittest.TestCase):
    """Un extra_arg interdit -> fire() REFUSE fail-closed, ZÉRO processus lancé (runner.tool = _boom)."""

    def _fire(self, params):
        m = mods.get("recon.nmap")
        with _Patch(available=lambda *a, **k: True, tool=_boom):
            return m.fire(Action("recon.nmap", "scan.test", params=params))

    def test_disallowed_flag_refused(self):
        f = self._fire({"extra_args": ["-oN", "/tmp/out"]})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("refusé", f[0].title.lower())

    def test_equals_form_script_refused(self):
        f = self._fire({"extra_args": ["--script=<rce-ish>"]})
        self.assertEqual(f[0].status, "skipped")

    def test_extra_args_string_refused(self):
        # extra_args DOIT être une liste — une chaîne est REFUSÉE (jamais de découpe shell).
        f = self._fire({"extra_args": "-sV -oN /tmp/x"})
        self.assertEqual(f[0].status, "skipped")

    def test_positional_target_dash_refused(self):
        m = mods.get("recon.nmap")
        with _Patch(available=lambda *a, **k: True, tool=_boom):
            f = m.fire(Action("recon.nmap", "-oN", params={}))
        self.assertEqual(f[0].status, "skipped")

    def test_allowed_flag_runs(self):
        m = mods.get("recon.nmap")
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, "PORT 80/tcp open", "")):
            f = m.fire(Action("recon.nmap", "scan.test", params={"extra_args": ["--max-rate", "50"]}))
        self.assertEqual(f[0].status, "tested")


class TestNucleiCustomArgs(unittest.TestCase):
    def _argv(self, params):
        m = mods.get("web.nuclei")
        return m._args(Action("web.nuclei", "http://scan.test", params=params))

    def test_templates_tags_severity(self):
        argv = self._argv({"severity": "high", "templates": "cves/2021", "tags": "cve,rce"})
        self.assertIn("-severity", argv)
        self.assertIn("high", argv)
        self.assertIn("-t", argv)
        self.assertIn("cves/2021", argv)
        self.assertIn("-tags", argv)
        self.assertIn("cve,rce", argv)

    def test_disallowed_extra_refused(self):
        m = mods.get("web.nuclei")
        with _Patch(available=lambda *a, **k: True, tool=_boom):
            f = m.fire(Action("web.nuclei", "http://scan.test", params={"extra_args": ["-o", "/tmp/x"]}))
        self.assertEqual(f[0].status, "skipped")


class TestExtraArgsHelper(unittest.TestCase):
    ALLOW = ("-p", "-p-", "--max-rate")

    def test_none_is_noop(self):
        self.assertEqual(check_extra_args(None, self.ALLOW), (None, []))

    def test_string_rejected(self):
        reason, toks = check_extra_args("-p 80", self.ALLOW)
        self.assertIsNotNone(reason)
        self.assertEqual(toks, [])

    def test_disallowed_flag_rejected(self):
        reason, _ = check_extra_args(["-oN"], self.ALLOW)
        self.assertIsNotNone(reason)

    def test_value_tokens_pass(self):
        reason, toks = check_extra_args(["-p", "80", "--max-rate", "50"], self.ALLOW)
        self.assertIsNone(reason)
        self.assertEqual(toks, ["-p", "80", "--max-rate", "50"])

    def test_nul_rejected(self):
        reason, _ = check_extra_args(["80\x00"], self.ALLOW)
        self.assertIsNotNone(reason)

    def test_safe_value(self):
        self.assertTrue(safe_value("1-65535"))
        self.assertTrue(safe_value("http-*"))
        self.assertFalse(safe_value("-oN"))
        self.assertFalse(safe_value(""))
        self.assertFalse(safe_value("a b"))


class TestToolSpecArgsExpansion(unittest.TestCase):
    def _spec(self):
        return ToolSpec(
            kind="test.args", vuln_class="Recon", binary="fakebin",
            argv_template=("-u", "{target_url}", "{args}"),
            flag_allowlist=("--rate", "-x"),
            params_schema=({"name": "extra_args", "type": "list", "label": "extra", "flag": ""},))

    def test_args_expands_valid_tokens(self):
        spec = self._spec()
        argv = build_argv(spec, "good.test", {"extra_args": ["--rate", "10"]})
        self.assertEqual(argv, ["-u", "http://good.test", "--rate", "10"])

    def test_args_drops_when_invalid(self):
        # build_argv ne lève jamais : un extra_args invalide n'expand RIEN (le garde-fou fire() refuse).
        spec = self._spec()
        argv = build_argv(spec, "good.test", {"extra_args": ["-oN"]})
        self.assertEqual(argv, ["-u", "http://good.test"])

    def test_unsafe_extra_args_reports_reason(self):
        spec = self._spec()
        self.assertIsNotNone(unsafe_extra_args(spec, {"extra_args": ["-oN"]}))
        self.assertIsNone(unsafe_extra_args(spec, {"extra_args": ["--rate", "5"]}))

    def test_param_placeholder_still_works(self):
        spec = ToolSpec(kind="test.p", vuln_class="Recon", binary="fakebin",
                        argv_template=("-w", "{param:wordlist}", "{target_host}"))
        argv = build_argv(spec, "http://good.test/x", {"wordlist": "list.txt"})
        self.assertEqual(argv, ["-w", "list.txt", "good.test"])


class TestModulesJsonSchema(unittest.TestCase):
    def test_nmap_schema_served(self):
        rows = _rows_json()
        self.assertIn("recon.nmap", rows)
        schema = rows["recon.nmap"]["params_schema"]
        names = {d["name"] for d in schema}
        self.assertLessEqual({"ports", "top_ports", "scripts", "timing", "extra_args"}, names)
        allow = rows["recon.nmap"]["flag_allowlist"]
        self.assertIn("--max-rate", allow)
        self.assertIn("-p-", allow)

    def test_nuclei_schema_served(self):
        rows = _rows_json()
        schema = rows["web.nuclei"]["params_schema"]
        names = {d["name"] for d in schema}
        self.assertLessEqual({"severity", "templates", "tags", "extra_args"}, names)

    def test_every_row_carries_schema_fields(self):
        for r in _rows_json().values():
            self.assertIn("params_schema", r)
            self.assertIn("flag_allowlist", r)
            self.assertIsInstance(r["params_schema"], list)


if __name__ == "__main__":
    unittest.main()

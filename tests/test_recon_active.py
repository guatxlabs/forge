"""LOT REACHABILITY ACTIVE — modules recon.content / recon.secrets / recon.waf.

Modules ACTIFS mais STRICTEMENT gouvernés : scope-locked (fail-closed), rate-limités, lecture/
énumération seule (aucune exploitation), et DÉGRADANT proprement (`status='skipped'`) quand l'outil
externe (ffuf / trufflehog / gitleaks / wafw00f) ou le réseau est indisponible.

Trois axes (calqués sur test_recon_surface.py) :
  (A) enregistrement + métadonnées (kind/mitre alignés sur techniques.py, non-exploit, non-destructif) ;
  (B) scope-guard : refus fail-closed d'une cible hors périmètre (AUCUN sous-processus / réseau émis),
      injection du périmètre + du débit ROE par l'engine, veto engine hors-scope ;
  (C) comportement + dégradation gracieuse : sortie d'outil parsée en Finding ; outil/réseau absent
      -> `status='skipped'` (offline-safe).

HERMÉTIQUE : les seams sous-processus (`_tool_available`/`_run_ffuf`/`_pick_scanner`/`_scan`/
`_wafw00f_available`/`_run_wafw00f`) et réseau (`_http_get`) sont mockés — AUCUN binaire réel,
AUCUNE requête réelle n'est émise.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import schema, techniques                          # noqa: E402
from forge import modules as mods                             # noqa: E402
from forge.roe import Scope, Action                           # noqa: E402
from forge.engine import Engine                               # noqa: E402
from forge.modules.recon_active import (                      # noqa: E402
    ContentDiscovery, SecretScan, WafIdentify,
)

KINDS = ("recon.content", "recon.secrets", "recon.waf")


def _patch(cls, name, fn):
    """Remplace `cls.<name>` par une staticmethod `fn` et renvoie un restaurateur. Gère l'héritage
    (attribut défini sur la base) : restauration par delattr pour retomber sur la base (cf. recon_surface)."""
    had = name in cls.__dict__
    orig = cls.__dict__.get(name)
    setattr(cls, name, staticmethod(fn))

    def restore():
        if had:
            setattr(cls, name, orig)
        else:
            delattr(cls, name)
    return restore


def _http(mapping, default=(None, "", {})):
    """Fabrique un faux `_http_get` : 1ère valeur dont la clé (sous-chaîne) est dans l'URL."""
    def fake(url, headers=None, timeout=20, maxlen=500000):
        for needle, resp in mapping.items():
            if needle in url:
                return resp
        return default
    return fake


# --- (A) enregistrement + métadonnées -------------------------------------------------------------
class TestRegistration(unittest.TestCase):
    def test_all_registered(self):
        for k in KINDS:
            self.assertIn(k, mods.kinds(), f"{k} non enregistré")

    def test_flags(self):
        for k in KINDS:
            m = mods.get(k)
            self.assertFalse(m.exploit, f"{k} ne doit pas être exploit")
            self.assertFalse(m.destructive, f"{k} ne doit pas être destructif")
            self.assertTrue(getattr(m, "web_allowed", False), f"{k} devrait être web_allowed")
            self.assertTrue(m.available, f"{k} available=True (dégrade à runtime, pas au catalogue)")

    def test_mitre_matches_table(self):
        # anti-drift : le mitre déclaré par le module == la table unique techniques.py.
        for k in KINDS:
            self.assertTrue(mods.get(k).mitre, f"{k} mitre vide")
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")

    def test_expected_attck_ids(self):
        want = {"recon.content": "T1595.003", "recon.secrets": "T1552.001", "recon.waf": "T1590"}
        for k, mitre in want.items():
            self.assertEqual(mods.get(k).mitre, mitre, k)

    def test_dry_emits_string_no_side_effect(self):
        for k in KINDS:
            s = mods.get(k).dry(Action(k, "app.test", params={"in_scope": ["app.test"]}))
            self.assertIsInstance(s, str)
            self.assertTrue(s)

    def test_module_kinds_in_technique_table(self):
        # chaque nouveau kind est une entrée pointée de TECHNIQUES (phasée recon).
        for k in KINDS:
            t = techniques.technique_for(k)
            self.assertIsNotNone(t, k)
            self.assertEqual(t.phase, "recon", k)
            self.assertIn(t.capability, ("active", "passive"), k)


# --- (B) scope-guard : refus hors périmètre, sans sous-processus ni réseau -------------------------
class TestScopeGuard(unittest.TestCase):
    def test_content_out_of_scope_skipped_no_subprocess(self):
        boom_avail = _patch(ContentDiscovery, "_tool_available", lambda: (_ for _ in ()).throw(AssertionError("avail")))
        boom_run = _patch(ContentDiscovery, "_run_ffuf",
                          lambda *a, **k: (_ for _ in ()).throw(AssertionError("ffuf émis hors scope")))
        try:
            f = ContentDiscovery().fire(Action("recon.content", "evil.example.com", params={"in_scope": ["app.test"]}))
        finally:
            boom_run(); boom_avail()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_secrets_out_of_scope_skipped_no_scan(self):
        boom_pick = _patch(SecretScan, "_pick_scanner", lambda: (_ for _ in ()).throw(AssertionError("pick")))
        try:
            f = SecretScan().fire(Action("recon.secrets", "evil.example.com", params={"in_scope": ["app.test"]}))
        finally:
            boom_pick()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_waf_out_of_scope_skipped_no_network(self):
        boom = _patch(WafIdentify, "_http_get",
                      lambda url, headers=None, timeout=20, maxlen=500000: (_ for _ in ()).throw(AssertionError("net")))
        try:
            f = WafIdentify().fire(Action("recon.waf", "evil.example.com", params={"in_scope": ["app.test"]}))
        finally:
            boom()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_engine_vetoes_out_of_scope(self):
        for k in KINDS:
            eng = Engine(Scope({"in_scope": ["app.test"]}))
            eng.arm()
            a = Action(k, "evil.example.com")
            eng.approve(a.id)
            res = eng.execute(a)
            self.assertEqual(res["verdict"], "VETO", k)
            self.assertIsNone(res["output"], k)

    def test_engine_injects_perimeter_and_rate(self):
        eng = Engine(Scope({"in_scope": ["app.test"], "out_scope": ["dev.app.test"], "rate": 7}))
        prepared = eng._prepare([Action("recon.content", "app.test"),
                                 Action("recon.secrets", "app.test"),
                                 Action("recon.waf", "app.test")], None, {}, {})
        for a in prepared:
            self.assertEqual(a.params.get("in_scope"), ["app.test"], a.kind)
            self.assertEqual(a.params.get("out_scope"), ["dev.app.test"], a.kind)
            self.assertEqual(a.params.get("rate"), 7, a.kind)          # débit ROE injecté


# --- (C) recon.content ----------------------------------------------------------------------------
class TestContentDiscovery(unittest.TestCase):
    FFUF_OBJ = json.dumps({"results": [
        {"input": {"FUZZ": "admin"}, "url": "https://app.test/admin", "status": 200, "length": 1234, "redirectlocation": ""},
        {"input": {"FUZZ": "login"}, "url": "https://app.test/login", "status": 302, "length": 0, "redirectlocation": "/dash"},
        {"input": {"FUZZ": "x"}, "url": "https://evil.example.com/x", "status": 200, "length": 10, "redirectlocation": ""},
    ]})

    def _fire(self, params, ffuf_out="", rc=0, available=True, capture=None):
        def run(url, wordlist, rate, threads, timeout, **kw):
            if capture is not None:
                capture.update(url=url, wordlist=wordlist, rate=rate, threads=threads, timeout=timeout, **kw)
            return (rc, ffuf_out, "")
        r_av = _patch(ContentDiscovery, "_tool_available", lambda: available)
        r_run = _patch(ContentDiscovery, "_run_ffuf", run)
        try:
            return ContentDiscovery().fire(Action("recon.content", "app.test", params=params))
        finally:
            r_run(); r_av()

    def test_ffuf_absent_is_skipped(self):
        f = self._fire({"in_scope": ["app.test"]}, available=False)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("ffuf indisponible", f[0].title)

    def test_discovers_routes_and_filters_out_of_scope(self):
        f = self._fire({"in_scope": ["app.test"]}, ffuf_out=self.FFUF_OBJ)
        targets = {x.target for x in f}
        self.assertIn("https://app.test/admin", targets)
        self.assertIn("https://app.test/login", targets)
        self.assertNotIn("https://evil.example.com/x", targets)       # verrou périmètre (redirection hors-scope)
        summary = f[0]
        self.assertEqual(summary.status, "tested")
        self.assertEqual(summary.severity, "INFO")
        self.assertIn("2 in-scope", summary.title)
        self.assertIn("hors périmètre écartée", summary.evidence)
        for x in f:                                                   # jamais promu vulnerable (pas d'exploitation)
            self.assertEqual(x.status, "tested")

    def test_no_route_found_is_tested_not_skipped(self):
        f = self._fire({"in_scope": ["app.test"]}, ffuf_out=json.dumps({"results": []}), rc=0)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucune route", f[0].title)

    def test_ffuf_error_no_output_is_skipped(self):
        f = self._fire({"in_scope": ["app.test"]}, ffuf_out="", rc=1)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("ffuf a échoué", f[0].title)

    def test_rate_is_honored_from_params(self):
        cap = {}
        self._fire({"in_scope": ["app.test"], "rate": 3}, ffuf_out=json.dumps({"results": []}), capture=cap)
        self.assertEqual(cap["rate"], 3)
        self.assertLessEqual(cap["threads"], 3)                       # concurrence <= débit (pas de flood)

    def test_parse_ffuf_object_and_jsonl(self):
        obj = ContentDiscovery._parse_ffuf(self.FFUF_OBJ)
        self.assertEqual(len(obj), 3)
        self.assertEqual(obj[0]["url"], "https://app.test/admin")
        self.assertEqual(obj[1]["redirect"], "/dash")
        jsonl = ('{"url":"https://app.test/api","status":200,"length":50}\n'
                 '{"url":"https://app.test/config.json","status":200,"length":80}')
        rows = ContentDiscovery._parse_ffuf(jsonl)
        self.assertEqual({r["url"] for r in rows}, {"https://app.test/api", "https://app.test/config.json"})

    def test_parse_ffuf_garbage_never_raises(self):
        self.assertEqual(ContentDiscovery._parse_ffuf("not json at all"), [])
        self.assertEqual(ContentDiscovery._parse_ffuf(""), [])


# --- (C) recon.secrets ----------------------------------------------------------------------------
class TestSecretScan(unittest.TestCase):
    PAGE = ('<html><head><script src="/static/app.js"></script>'
            '<script src="https://cdn.evil.com/x.js"></script></head><body>hi</body></html>')
    TRUFFLE = ('{"DetectorName":"AWS","Verified":true,"Raw":"AKIAIOSFODNN7EXAMPLE",'
               '"SourceMetadata":{"Data":{"Filesystem":{"file":"app.js","line":12}}}}\n'
               '{"DetectorName":"Slack","Verified":false,"Raw":"xoxb-123456789012-abcdefghij",'
               '"SourceMetadata":{"Data":{"Filesystem":{"file":"config.json","line":3}}}}')
    GITLEAKS = json.dumps([
        {"RuleID": "generic-api-key", "Secret": "sk_live_51H8supersecretkeyvalue", "File": "app.js", "StartLine": 7},
    ])

    def _fire(self, params, scanner=("trufflehog", "trufflehog"), scan_out="", scan_rc=0,
              http=None, fetched=None):
        def pick():
            return scanner
        def scan(name, path):
            return (scan_rc, scan_out, "")
        def _http_get(url, headers=None, timeout=20, maxlen=500000):
            if fetched is not None:
                fetched.append(url)
            if http is not None:
                return http(url)
            # défaut : page cible sert PAGE, tout le reste vide
            if "app.test" in url and url.rstrip("/").endswith("app.test"):
                return (200, self.PAGE, {})
            return (None, "", {})
        r_pick = _patch(SecretScan, "_pick_scanner", pick)
        r_scan = _patch(SecretScan, "_scan", scan)
        r_http = _patch(SecretScan, "_http_get", _http_get)
        try:
            return SecretScan().fire(Action("recon.secrets", "app.test", params=params))
        finally:
            r_http(); r_scan(); r_pick()

    def test_no_scanner_is_skipped(self):
        f = self._fire({"in_scope": ["app.test"]}, scanner=(None, None))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("aucun scanner", f[0].title)

    def test_trufflehog_verified_secret_reported_and_redacted(self):
        f = self._fire({"in_scope": ["app.test"]}, scanner=("trufflehog", "trufflehog"),
                       scan_out=self.TRUFFLE,
                       http=lambda url: (200, self.PAGE, {}) if url.rstrip("/").endswith("app.test") else (None, "", {}))
        # summary + 2 secrets
        self.assertGreaterEqual(len(f), 2)
        self.assertIn("Secrets EXPOSÉS", f[0].title)
        verified = [x for x in f if "AWS" in x.title]
        self.assertTrue(verified)
        v = verified[0]
        self.assertEqual(v.status, "tested")                         # jamais vulnerable (pas d'exploitation)
        self.assertEqual(v.severity, "MEDIUM")                       # secret VÉRIFIÉ exposé
        self.assertIn("VÉRIFIÉ", v.title)
        self.assertTrue(v.fix, "un finding de secret doit porter une remédiation (révoquer/rotate)")
        # REDACTION : la valeur complète du secret ne doit JAMAIS apparaître dans l'evidence.
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", v.evidence)
        self.assertIn("AKIA", v.evidence)                            # préfixe masqué visible

    def test_gitleaks_leak_rc1_is_not_a_failure(self):
        # gitleaks rend rc=1 QUAND il trouve des leaks -> doit être REPORTÉ (tested), pas skipped.
        f = self._fire({"in_scope": ["app.test"]}, scanner=("gitleaks", "gitleaks"),
                       scan_out=self.GITLEAKS, scan_rc=1,
                       http=lambda url: (200, self.PAGE, {}) if url.rstrip("/").endswith("app.test") else (None, "", {}))
        leaks = [x for x in f if "generic-api-key" in x.title]
        self.assertTrue(leaks)
        self.assertEqual(leaks[0].status, "tested")
        self.assertEqual(leaks[0].severity, "LOW")                   # gitleaks : pas de vérification live
        self.assertNotIn("sk_live_51H8supersecretkeyvalue", leaks[0].evidence)

    def test_assets_unreachable_is_skipped(self):
        f = self._fire({"in_scope": ["app.test"]}, scanner=("trufflehog", "trufflehog"),
                       http=lambda url: (None, "", {}))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignables", f[0].title)

    def test_no_secret_found_is_tested(self):
        f = self._fire({"in_scope": ["app.test"]}, scanner=("trufflehog", "trufflehog"), scan_out="",
                       http=lambda url: (200, self.PAGE, {}) if url.rstrip("/").endswith("app.test") else (None, "", {}))
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucun secret", f[0].title)

    def test_out_of_scope_asset_url_not_fetched(self):
        fetched = []
        self._fire({"in_scope": ["app.test"], "asset_urls": ["https://evil.example.com/leak.js"]},
                   scanner=("trufflehog", "trufflehog"), scan_out="", fetched=fetched,
                   http=lambda url: (200, self.PAGE, {}) if url.rstrip("/").endswith("app.test") else (None, "", {}))
        self.assertFalse(any("evil.example.com" in u for u in fetched),
                         "un asset hors périmètre a été récupéré (fail-closed violé)")
        self.assertTrue(any("app.test" in u for u in fetched))       # la cible in-scope EST récupérée

    def test_external_js_not_fetched(self):
        fetched = []
        self._fire({"in_scope": ["app.test"]}, scanner=("trufflehog", "trufflehog"), scan_out="",
                   fetched=fetched,
                   http=lambda url: (200, self.PAGE, {}) if url.rstrip("/").endswith("app.test") else (200, "x", {}))
        self.assertFalse(any("cdn.evil.com" in u for u in fetched),
                         "un JS externe (hors périmètre) a été récupéré")

    def test_parse_secrets_pure(self):
        thog = SecretScan._parse_secrets("trufflehog", self.TRUFFLE)
        self.assertEqual({s["detector"] for s in thog}, {"AWS", "Slack"})
        self.assertTrue(thog[0]["verified"])
        gl = SecretScan._parse_secrets("gitleaks", self.GITLEAKS)
        self.assertEqual(gl[0]["detector"], "generic-api-key")
        self.assertFalse(gl[0]["verified"])
        self.assertEqual(SecretScan._parse_secrets("trufflehog", "garbage"), [])

    def test_redact_never_leaks_full_value(self):
        self.assertNotIn("supersecretvalue", SecretScan._redact("supersecretvalue"))
        self.assertEqual(SecretScan._redact("abc"), "***")           # trop court -> tout masqué


# --- (C) recon.waf --------------------------------------------------------------------------------
class TestWafIdentify(unittest.TestCase):
    def _fire(self, params, http, wafw00f_avail=False, wafw00f_out="", wafw00f_rc=0):
        r_http = _patch(WafIdentify, "_http_get", http)
        r_av = _patch(WafIdentify, "_wafw00f_available", lambda: wafw00f_avail)
        r_run = _patch(WafIdentify, "_run_wafw00f", lambda url: (wafw00f_rc, wafw00f_out, ""))
        try:
            return WafIdentify().fire(Action("recon.waf", "app.test", params=params))
        finally:
            r_run(); r_av(); r_http()

    def test_heuristic_from_headers_and_cookies(self):
        headers = {"CF-RAY": "abc123-CDG", "Server": "cloudflare",
                   "Set-Cookie": "__cfduid=deadbeef; path=/; HttpOnly"}
        f = self._fire({"in_scope": ["app.test"]}, _http({"app.test": (200, "<html></html>", headers)}))
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")                      # fingerprint informatif uniquement
        self.assertIn("Cloudflare", f[0].title)

    def test_incapsula_cookie_signature(self):
        headers = {"Set-Cookie": "visid_incap_123=xyz; incap_ses_1=abc"}
        f = self._fire({"in_scope": ["app.test"]}, _http({"app.test": (200, "", headers)}))
        self.assertIn("Imperva Incapsula", f[0].title)

    def test_wafw00f_enriches_detection(self):
        waf_json = json.dumps([{"url": "https://app.test", "detected": True, "firewall": "Imperva SecureSphere"}])
        f = self._fire({"in_scope": ["app.test"]}, _http({"app.test": (200, "", {})}),
                       wafw00f_avail=True, wafw00f_out=waf_json)
        self.assertIn("Imperva SecureSphere", f[0].title)
        self.assertEqual(f[0].status, "tested")

    def test_no_signature_still_informative(self):
        f = self._fire({"in_scope": ["app.test"]}, _http({"app.test": (200, "<html></html>", {"Server": "nginx"})}))
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucune signature", f[0].title.lower())

    def test_unreachable_and_no_wafw00f_is_skipped(self):
        f = self._fire({"in_scope": ["app.test"]}, _http({}, default=(None, "", {})), wafw00f_avail=False)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignable", f[0].title)

    def test_never_promotes_to_vulnerable(self):
        headers = {"CF-RAY": "x", "Set-Cookie": "__cf_bm=1"}
        f = self._fire({"in_scope": ["app.test"]}, _http({"app.test": (200, "", headers)}))
        for x in f:
            self.assertNotEqual(x.status, "vulnerable")
            self.assertEqual(x.severity, "INFO")

    def test_parse_wafw00f_pure(self):
        out = json.dumps([{"detected": True, "firewall": "Cloudflare"},
                          {"detected": False, "firewall": "None"},
                          {"detected": True, "firewall": "Generic"}])
        fws = WafIdentify._parse_wafw00f(out)
        self.assertIn("Cloudflare", fws)
        self.assertNotIn("None", fws)
        self.assertNotIn("Generic", fws)                             # 'generic' ignoré (pas un WAF précis)
        self.assertEqual(WafIdentify._parse_wafw00f("garbage"), set())


# --- statut connu ---------------------------------------------------------------------------------
class TestStatusKnown(unittest.TestCase):
    def test_skipped_is_known_status(self):
        self.assertIn("skipped", schema.STATUSES)


if __name__ == "__main__":
    unittest.main(verbosity=2)

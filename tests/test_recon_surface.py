"""LOT SURFACE PASSIVE — modules de cartographie de surface d'attaque en lecture seule.

Couvre les 5 modules passifs (recon.subdomains / recon.dns / recon.js_endpoints / recon.urls /
recon.tech) sur trois axes :
  (A) enregistrement + métadonnées cohérentes (kind/mitre alignés sur techniques.py, non-exploit,
      non-destructif, web_allowed) ;
  (B) scope-guard : verrou STRICT aux racines déclarées sur les hôtes DÉCOUVERTS/DÉRIVÉS, refus
      fail-closed d'une cible hors périmètre (AUCUN réseau émis), et injection du périmètre par l'engine ;
  (C) dégradation gracieuse : source/outil/réseau indisponible -> finding status='skipped' (offline-safe).

Tous les tests sont HERMÉTIQUES : le réseau est mocké au niveau du seam (`_http_get` / `_resolve_all`).
Aucun test ne fait de requête réelle (crt.sh, wayback, DNS…).
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import schema, techniques                         # noqa: E402
from forge import modules as mods                            # noqa: E402
from forge.roe import Scope, Action                          # noqa: E402
from forge.engine import Engine                              # noqa: E402
from forge.modules.recon_surface import (                    # noqa: E402
    PassiveSurface, SubdomainEnum, DnsRecords, JsEndpoints, HistoricalUrls, TechFingerprint,
)

KINDS = ("recon.subdomains", "recon.dns", "recon.js_endpoints", "recon.urls", "recon.tech")


def _patch(cls, name, fn):
    """Remplace `cls.<name>` par une staticmethod `fn` et renvoie un restaurateur. Gère le cas où
    l'attribut est HÉRITÉ (défini sur la base) : restauration par delattr pour retomber sur la base."""
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
    """Fabrique un faux `_http_get` : renvoie la 1ère valeur dont la clé (sous-chaîne) est dans l'URL."""
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

    def test_flags_are_passive_and_web(self):
        for k in KINDS:
            m = mods.get(k)
            self.assertFalse(m.exploit, f"{k} ne doit pas être exploit")
            self.assertFalse(m.destructive, f"{k} ne doit pas être destructif")
            self.assertTrue(getattr(m, "web_allowed", False), f"{k} devrait être web_allowed")
            self.assertTrue(m.available, f"{k} devrait être disponible (stdlib)")

    def test_mitre_matches_table(self):
        # anti-drift : le mitre déclaré par le module == la table unique techniques.py.
        for k in KINDS:
            self.assertTrue(mods.get(k).mitre, f"{k} mitre vide")
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")

    def test_expected_attck_ids(self):
        want = {"recon.subdomains": "T1590", "recon.dns": "T1590.002",
                "recon.js_endpoints": "T1594", "recon.urls": "T1596", "recon.tech": "T1592.002"}
        for k, mitre in want.items():
            self.assertEqual(mods.get(k).mitre, mitre, k)

    def test_dry_emits_no_side_effect_shape(self):
        for k in KINDS:
            s = mods.get(k).dry(Action(k, "app.test", params={"in_scope": ["app.test"]}))
            self.assertIsInstance(s, str)
            self.assertTrue(s)

    def test_skipped_is_known_status(self):
        self.assertIn("skipped", schema.STATUSES)


# --- (B) scope-guard commun (refus cible hors périmètre, sans réseau) ------------------------------
class TestScopeGuardFailClosed(unittest.TestCase):
    def _no_net(self, cls):
        """Patch `_http_get` pour lever si jamais appelé (prouve qu'aucun réseau ne part)."""
        def boom(url, headers=None, timeout=20, maxlen=500000):
            raise AssertionError(f"réseau émis hors scope: {url}")
        return _patch(cls, "_http_get", boom)

    def test_out_of_scope_target_is_skipped_no_network(self):
        cases = [(SubdomainEnum, "recon.subdomains"), (JsEndpoints, "recon.js_endpoints"),
                 (HistoricalUrls, "recon.urls"), (TechFingerprint, "recon.tech")]
        for cls, kind in cases:
            r = self._no_net(cls)
            try:
                f = cls().fire(Action(kind, "evil.example.com", params={"in_scope": ["app.test"]}))
            finally:
                r()
            self.assertEqual(f[0].status, "skipped", kind)
            self.assertIn("hors périmètre", f[0].title, kind)

    def test_dns_out_of_scope_target_is_skipped(self):
        def boom(host, rtypes):
            raise AssertionError("résolution hors scope")
        r = _patch(DnsRecords, "_resolve_all", boom)
        try:
            f = DnsRecords().fire(Action("recon.dns", "evil.example.com", params={"in_scope": ["app.test"]}))
        finally:
            r()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_engine_vetoes_out_of_scope_for_new_kinds(self):
        # défense en profondeur : la gate ROE de l'engine refuse la cible hors scope AVANT fire().
        eng = Engine(Scope({"in_scope": ["app.test"]}))
        eng.arm()
        a = Action("recon.subdomains", "evil.example.com")
        eng.approve(a.id)
        res = eng.execute(a)
        self.assertEqual(res["verdict"], "VETO")
        self.assertIsNone(res["output"])

    def test_engine_injects_perimeter_into_params(self):
        # l'engine injecte in_scope/out_scope dans action.params pour la re-validation runtime.
        eng = Engine(Scope({"in_scope": ["app.test"], "out_scope": ["dev.app.test"]}))
        prepared = eng._prepare([Action("recon.subdomains", "app.test"),
                                 Action("recon.dns", "app.test"),
                                 Action("recon.js_endpoints", "app.test"),
                                 Action("recon.urls", "app.test"),
                                 Action("recon.tech", "app.test")], None, {}, {})
        for a in prepared:
            self.assertEqual(a.params.get("in_scope"), ["app.test"], a.kind)
            self.assertEqual(a.params.get("out_scope"), ["dev.app.test"], a.kind)


# --- (B/C) recon.subdomains -----------------------------------------------------------------------
class TestSubdomains(unittest.TestCase):
    CRT = json.dumps([
        {"name_value": "api.app.test\nwww.app.test"},
        {"common_name": "admin.app.test"},
        {"name_value": "*.app.test"},
        {"name_value": "evil.example.com"},          # HORS périmètre -> jamais émis
    ])

    def _fire(self, http, params):
        r = _patch(SubdomainEnum, "_http_get", http)
        try:
            return SubdomainEnum().fire(Action("recon.subdomains", "app.test", params=params))
        finally:
            r()

    def test_discovers_in_scope_and_strictly_filters_out_of_scope(self):
        f = self._fire(_http({"crt.sh": (200, self.CRT, {})}), {"in_scope": ["app.test"]})
        targets = {x.target for x in f}
        self.assertIn("api.app.test", targets)
        self.assertIn("www.app.test", targets)
        self.assertIn("admin.app.test", targets)
        self.assertNotIn("evil.example.com", targets)            # verrou STRICT : hors racine
        # tous les findings sont informatifs (surface), jamais 'vulnerable'
        for x in f:
            self.assertEqual(x.status, "tested")
            self.assertEqual(x.severity, "INFO")
        summary = f[0]
        self.assertIn("in-scope", summary.title)
        self.assertIn("hors périmètre écarté", summary.evidence)

    def test_source_unreachable_is_skipped(self):
        f = self._fire(_http({}, default=(None, "", {})), {"in_scope": ["app.test"]})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignables", f[0].title)

    def test_no_scope_emits_nothing_in_scope_failclosed(self):
        # appel direct SANS périmètre injecté -> aucun hôte n'est considéré in-scope (fail-closed).
        f = self._fire(_http({"crt.sh": (200, self.CRT, {})}), {})
        per_host = [x for x in f if x.target != "app.test"]
        self.assertEqual(per_host, [], "sans scope, aucun hôte découvert ne doit être émis")

    def test_out_scope_exclusion_wins(self):
        f = self._fire(_http({"crt.sh": (200, self.CRT, {})}),
                       {"in_scope": ["app.test"], "out_scope": ["admin.app.test"]})
        targets = {x.target for x in f}
        self.assertIn("api.app.test", targets)
        self.assertNotIn("admin.app.test", targets)             # exclusion out_scope l'emporte


# --- recon.dns ------------------------------------------------------------------------------------
class TestDns(unittest.TestCase):
    RECORDS = {"A": ["93.184.216.34"], "AAAA": [], "CNAME": ["edge.app.test."],
               "MX": ["10 mail.app.test."], "TXT": ["v=spf1 -all"], "NS": ["ns1.app.test."]}

    def _fire(self, resolve, params):
        r = _patch(DnsRecords, "_resolve_all", resolve)
        try:
            return DnsRecords().fire(Action("recon.dns", "app.test", params=params))
        finally:
            r()

    def test_resolves_records_tested(self):
        f = self._fire(lambda host, rtypes: (self.RECORDS, "dnspython", True), {"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "tested")
        self.assertIn("93.184.216.34", f[0].evidence)
        self.assertIn("backend=dnspython", f[0].evidence)
        self.assertIn("MX:", f[0].evidence)

    def test_resolution_unavailable_is_skipped(self):
        f = self._fire(lambda host, rtypes: ({}, "socket", False), {"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("indisponible", f[0].title)

    def test_extra_hosts_out_of_scope_are_skipped_not_resolved(self):
        seen = {"hosts": []}

        def resolve(host, rtypes):
            seen["hosts"].append(host)
            return (self.RECORDS, "dig", True)
        r = _patch(DnsRecords, "_resolve_all", resolve)
        try:
            f = DnsRecords().fire(Action("recon.dns", "app.test",
                                         params={"in_scope": ["app.test"], "hosts": ["evil.example.com"]}))
        finally:
            r()
        by_target = {x.target: x for x in f}
        self.assertEqual(by_target["app.test"].status, "tested")
        self.assertEqual(by_target["evil.example.com"].status, "skipped")
        self.assertNotIn("evil.example.com", seen["hosts"])       # jamais résolu (fail-closed)


# --- recon.js_endpoints ---------------------------------------------------------------------------
class TestJsEndpoints(unittest.TestCase):
    HTML = ('<html><head><script src="/static/app.js"></script>'
            '<script src="https://cdn.evil.com/track.js"></script></head>'
            '<body><script>var a="/api/v1/users";fetch("https://app.test/api/orders");'
            'fetch("https://evil.example.com/collect");</script></body></html>')
    JS = 'const p="/api/v2/secret"; const g="https://app.test/graphql";'

    def _fire(self, params):
        http = _http({"/static/app.js": (200, self.JS, {}),
                      "app.test": (200, self.HTML, {})})
        r = _patch(JsEndpoints, "_http_get", http)
        try:
            return JsEndpoints().fire(Action("recon.js_endpoints", "app.test", params=params))
        finally:
            r()

    def test_extracts_paths_and_classifies_urls(self):
        f = self._fire({"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "tested")
        ev = f[0].evidence
        self.assertIn("/api/v1/users", ev)
        self.assertIn("/api/v2/secret", ev)                       # extrait du JS in-scope récupéré
        self.assertIn("https://app.test/api/orders", ev)          # URL in-scope
        self.assertIn("https://app.test/graphql", ev)
        self.assertIn("https://evil.example.com/collect", ev)     # listée en EXTERNE (jamais appelée)

    def test_external_url_not_counted_in_scope(self):
        f = self._fire({"in_scope": ["app.test"]})
        ev = f[0].evidence
        # l'URL externe apparaît dans la section "externes non appelées", pas dans "in-scope".
        inscope_section = ev.split("URLs externes")[0]
        self.assertNotIn("evil.example.com", inscope_section)

    def test_page_unreachable_is_skipped(self):
        r = _patch(JsEndpoints, "_http_get", _http({}, default=(None, "", {})))
        try:
            f = JsEndpoints().fire(Action("recon.js_endpoints", "app.test", params={"in_scope": ["app.test"]}))
        finally:
            r()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignable", f[0].title)

    def test_external_js_not_fetched(self):
        # le <script src> CDN hors périmètre ne doit JAMAIS être récupéré (verrou fail-closed).
        fetched = {"urls": []}

        def http(url, headers=None, timeout=20, maxlen=500000):
            fetched["urls"].append(url)
            if "/static/app.js" in url:
                return (200, self.JS, {})
            return (200, self.HTML, {})
        r = _patch(JsEndpoints, "_http_get", http)
        try:
            JsEndpoints().fire(Action("recon.js_endpoints", "app.test", params={"in_scope": ["app.test"]}))
        finally:
            r()
        self.assertFalse(any("cdn.evil.com" in u for u in fetched["urls"]),
                         "un JS hors périmètre a été récupéré")


# --- recon.urls -----------------------------------------------------------------------------------
class TestHistoricalUrls(unittest.TestCase):
    WB = json.dumps([
        ["original"],                                    # ligne d'en-tête CDX
        ["https://app.test/page1"],
        ["https://app.test/admin/panel"],
        ["https://evil.example.com/x"],                  # HORS périmètre -> filtré
    ])

    def _fire(self, http, params):
        r = _patch(HistoricalUrls, "_http_get", http)
        try:
            return HistoricalUrls().fire(Action("recon.urls", "app.test", params=params))
        finally:
            r()

    def test_discovers_and_filters_urls(self):
        f = self._fire(_http({"web.archive.org": (200, self.WB, {})}), {"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "tested")
        ev = f[0].evidence
        self.assertIn("https://app.test/page1", ev)
        self.assertIn("2 URL(s) in-scope", ev)                    # les 2 app.test, pas l'externe
        self.assertNotIn("evil.example.com", ev)

    def test_archives_unreachable_is_skipped(self):
        f = self._fire(_http({}, default=(None, "", {})), {"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignables", f[0].title)


# --- recon.tech -----------------------------------------------------------------------------------
class TestTech(unittest.TestCase):
    HEADERS = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2",
               "Set-Cookie": "PHPSESSID=deadbeef; path=/; HttpOnly"}
    BODY = '<html><head><link href="/wp-content/themes/x/style.css"></head></html>'

    def _fire(self, http, params):
        r = _patch(TechFingerprint, "_http_get", http)
        try:
            return TechFingerprint().fire(Action("recon.tech", "app.test", params=params))
        finally:
            r()

    def test_fingerprints_from_headers_cookies_body(self):
        f = self._fire(_http({"app.test": (200, self.BODY, self.HEADERS)}),
                       {"in_scope": ["app.test"], "use_httpx": False})
        self.assertEqual(f[0].status, "tested")
        ev = f[0].evidence
        self.assertIn("nginx/1.18.0", ev)
        self.assertIn("PHP", ev)                                  # cookie PHPSESSID -> PHP
        self.assertIn("WordPress", ev)                            # wp-content -> WordPress

    def test_unreachable_and_no_httpx_is_skipped(self):
        f = self._fire(_http({}, default=(None, "", {})),
                       {"in_scope": ["app.test"], "use_httpx": False})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignable", f[0].title)


# --- parsers purs (robustesse, sans réseau) -------------------------------------------------------
class TestParsersPure(unittest.TestCase):
    def test_subdomain_parse_handles_legacy_line_json(self):
        legacy = '{"name_value":"a.app.test"}\n{"name_value":"b.app.test"}'
        hosts = SubdomainEnum._parse(legacy)
        self.assertEqual(hosts, {"a.app.test", "b.app.test"})

    def test_subdomain_parse_generic_text(self):
        hosts = SubdomainEnum._parse("a.app.test\nb.app.test\n# not-a-host")
        self.assertIn("a.app.test", hosts)
        self.assertIn("b.app.test", hosts)

    def test_urls_parse_skips_header_and_non_http(self):
        urls = HistoricalUrls._parse(json.dumps([["original"], ["https://x.test/a"], ["ftp://y"]]))
        self.assertEqual(urls, {"https://x.test/a"})

    def test_base_http_get_never_raises_on_bad_url(self):
        # le seam réel doit renvoyer (None, "", {}) sur transport KO, jamais lever.
        st, body, hdrs = PassiveSurface._http_get("http://127.0.0.1:1/definitely-closed", timeout=1)
        self.assertIsNone(st)
        self.assertEqual(body, "")
        self.assertEqual(hdrs, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)

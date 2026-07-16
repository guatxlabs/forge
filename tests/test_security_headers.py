"""LOT F3 — oracle `web.security_headers` : audit des en-têtes HTTP de sécurité + cookies.

Contrat (aligné sur les modules Forge, cf. test_oracles) :
  - observation de CONFIG -> status='tested' (INFO/LOW), JAMAIS 'vulnerable' (pas d'exploitation) ;
  - cible durcie (tous les en-têtes présents) -> ZÉRO finding (aucun bruit) ;
  - HSTS signalé UNIQUEMENT sur cible https (N/A en http clair : pas de faux positif) ;
  - cookie sans Secure/HttpOnly/SameSite -> LOW ; cookie durci -> aucun ;
  - échec réseau -> finding 'skipped' dégradé, JAMAIS « tout manquant ».

Tests HERMÉTIQUES : on monkeypatch `SecurityHeaders._fetch` (zéro réseau).
"""
import email
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                    # noqa: E402
from forge import modules as mods                               # noqa: E402
from forge import techniques                                    # noqa: E402
from forge.modules.security_headers import SecurityHeaders      # noqa: E402


def _headers(pairs):
    """Construit un HTTPMessage-like (email.message.Message) depuis une liste (nom, valeur).
    Autorise plusieurs Set-Cookie (get_all) — comme une vraie réponse HTTP."""
    msg = email.message.Message()
    for k, v in pairs:
        msg[k] = v
    return msg


def _patch(fn):
    orig = SecurityHeaders._fetch
    SecurityHeaders._fetch = staticmethod(fn)
    return lambda: setattr(SecurityHeaders, "_fetch", orig)


ALL_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("Permissions-Policy", "geolocation=(), camera=()"),
]


def _fire(target, status=200, body="", headers_pairs=()):
    restore = _patch(lambda url, headers=None, timeout=15: (status, body, _headers(headers_pairs)))
    try:
        return SecurityHeaders().fire(Action("web.security_headers", target))
    finally:
        restore()


def _titles(findings):
    return [f.title for f in findings]


class TestRegistration(unittest.TestCase):
    def test_registered_and_flags(self):
        self.assertIn("web.security_headers", mods.kinds())
        m = mods.get("web.security_headers")
        self.assertFalse(m.exploit)
        self.assertFalse(m.destructive)
        self.assertTrue(m.web_allowed)
        self.assertTrue(m.available)

    def test_mitre_non_empty_and_matches_table(self):
        m = mods.get("web.security_headers")
        self.assertTrue(m.mitre, "mitre de module vide")
        # aucune dérive : le module déclare EXACTEMENT le mitre de la table unique (techniques.py).
        self.assertEqual(m.mitre, techniques.mitre_for("web.security_headers"))

    def test_dry_mentions_curl_no_side_effect(self):
        s = mods.get("web.security_headers").dry(Action("web.security_headers", "https://app.test/"))
        self.assertIn("curl", s)


class TestMissingHeaders(unittest.TestCase):
    def test_all_missing_http(self):
        # (a) réponse SANS aucun en-tête, cible http -> CSP/clickjacking/nosniff/Referrer/Permissions.
        #     PAS de HSTS (http). Aucun cookie, aucune fuite de version.
        f = _fire("http://app.test/", headers_pairs=[])
        by_sev = {x.title: x.severity for x in f}
        self.assertIn("Content-Security-Policy absent", by_sev)
        self.assertEqual(by_sev["Content-Security-Policy absent"], "INFO")
        self.assertEqual(by_sev["Clickjacking — X-Frame-Options absent (et pas de CSP frame-ancestors)"], "LOW")
        self.assertEqual(by_sev["X-Content-Type-Options: nosniff absent"], "INFO")
        self.assertEqual(by_sev["Referrer-Policy absent"], "INFO")
        self.assertEqual(by_sev["Permissions-Policy absent"], "INFO")
        # HSTS ABSENT du set (http) — invariant anti-faux-positif.
        self.assertNotIn("Strict-Transport-Security absent (HTTPS)", by_sev)
        # tous status=tested, jamais vulnerable.
        self.assertTrue(all(x.status == "tested" for x in f))
        self.assertTrue(all(x.severity in ("INFO", "LOW") for x in f))
        self.assertEqual(len(f), 5)

    def test_all_missing_https_adds_hsts(self):
        # (a2) idem mais cible https -> HSTS s'ajoute (6 findings).
        f = _fire("https://app.test/", headers_pairs=[])
        self.assertIn("Strict-Transport-Security absent (HTTPS)", _titles(f))
        self.assertEqual(len(f), 6)

    def test_clickjacking_suppressed_by_csp_frame_ancestors(self):
        # X-Frame-Options absent MAIS CSP porte frame-ancestors -> pas de finding clickjacking.
        f = _fire("http://app.test/", headers_pairs=[
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "geolocation=()"),
        ])
        self.assertNotIn("Clickjacking — X-Frame-Options absent (et pas de CSP frame-ancestors)", _titles(f))
        self.assertEqual(f, [])

    def test_csp_meta_only_noted(self):
        # CSP absent des en-têtes HTTP mais présent en <meta http-equiv> -> noté (plus faible).
        body = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
        f = _fire("http://app.test/", body=body, headers_pairs=[
            ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"), ("Permissions-Policy", "geolocation=()"),
        ])
        titles = _titles(f)
        self.assertIn("Content-Security-Policy absent (meta seulement)", titles)


class TestHardenedTarget(unittest.TestCase):
    def test_all_present_zero_findings(self):
        # (b) réponse avec TOUS les en-têtes (comme la console après F1) -> ZÉRO finding.
        f = _fire("https://app.test/", headers_pairs=ALL_HEADERS)
        self.assertEqual(f, [], f"attendu 0 finding, obtenu: {_titles(f)}")


class TestHstsHttpVsHttps(unittest.TestCase):
    def test_hsts_not_flagged_on_http(self):
        # (c) http SANS HSTS mais tout le reste présent -> aucun finding (HSTS N/A en http).
        present = [p for p in ALL_HEADERS if p[0] != "Strict-Transport-Security"]
        f = _fire("http://app.test/", headers_pairs=present)
        self.assertEqual(f, [], f"http ne doit jamais signaler HSTS ; obtenu: {_titles(f)}")

    def test_hsts_flagged_on_https(self):
        # (c) https SANS HSTS mais tout le reste présent -> exactement 1 finding HSTS INFO.
        present = [p for p in ALL_HEADERS if p[0] != "Strict-Transport-Security"]
        f = _fire("https://app.test/", headers_pairs=present)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].title, "Strict-Transport-Security absent (HTTPS)")
        self.assertEqual(f[0].severity, "INFO")


class TestCookies(unittest.TestCase):
    def test_insecure_cookie_low(self):
        # (d) Set-Cookie sans Secure/HttpOnly/SameSite -> 1 finding LOW.
        f = _fire("https://app.test/", headers_pairs=ALL_HEADERS + [("Set-Cookie", "sid=abc; Path=/")])
        cookie = [x for x in f if x.title.startswith("Cookie non sécurisé")]
        self.assertEqual(len(cookie), 1)
        self.assertEqual(cookie[0].severity, "LOW")
        for flag in ("Secure", "HttpOnly", "SameSite"):
            self.assertIn(flag, cookie[0].title)

    def test_secure_cookie_none(self):
        # (d) cookie durci Secure; HttpOnly; SameSite=Strict -> aucun finding cookie.
        f = _fire("https://app.test/",
                  headers_pairs=ALL_HEADERS + [("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict")])
        self.assertEqual([x for x in f if x.title.startswith("Cookie non sécurisé")], [])
        self.assertEqual(f, [])

    def test_multiple_cookies_each_evaluated(self):
        # plusieurs Set-Cookie : un durci (ok) + un non sécurisé -> 1 seul finding cookie.
        f = _fire("https://app.test/", headers_pairs=ALL_HEADERS + [
            ("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "b=2; Path=/"),
        ])
        cookie = [x for x in f if x.title.startswith("Cookie non sécurisé")]
        self.assertEqual(len(cookie), 1)
        self.assertIn("b", cookie[0].title)


class TestVersionLeakAndNetwork(unittest.TestCase):
    def test_server_version_leak_info(self):
        f = _fire("https://app.test/", headers_pairs=ALL_HEADERS + [("Server", "nginx/1.25.3")])
        leak = [x for x in f if x.title.startswith("Fuite de version")]
        self.assertEqual(len(leak), 1)
        self.assertEqual(leak[0].severity, "INFO")

    def test_server_without_version_no_leak(self):
        # 'Server: nginx' sans chiffre -> pas de fuite de version.
        f = _fire("https://app.test/", headers_pairs=ALL_HEADERS + [("Server", "nginx")])
        self.assertEqual([x for x in f if x.title.startswith("Fuite de version")], [])

    def test_network_failure_degrades_not_all_missing(self):
        # échec réseau (status None) -> 1 finding 'skipped' dégradé, PAS « tout manquant ».
        restore = _patch(lambda url, headers=None, timeout=15: (None, "", None))
        try:
            f = SecurityHeaders().fire(Action("web.security_headers", "https://app.test/"))
        finally:
            restore()
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "skipped")
        self.assertNotIn("absent", f[0].title.lower())


class TestScopeGuard(unittest.TestCase):
    def test_out_of_scope_refused_no_network(self):
        # cible hors périmètre injecté -> finding 'skipped', aucun réseau (défense en profondeur).
        called = {"net": False}

        def spy(url, headers=None, timeout=15):
            called["net"] = True
            return 200, "", _headers([])
        restore = _patch(spy)
        try:
            a = Action("web.security_headers", "https://evil.test/",
                       params={"in_scope": ["app.test"]})
            f = SecurityHeaders().fire(a)
        finally:
            restore()
        self.assertFalse(called["net"], "aucun réseau ne doit partir hors périmètre")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "skipped")


if __name__ == "__main__":
    unittest.main(verbosity=2)

# SPDX-License-Identifier: AGPL-3.0-or-later
"""LOT ROUTAGE DU FRANCHISSEMENT — « forge franchit le défi, puis le moteur voit enfin le site ».

CE QUI EST MESURÉ ICI, ET POURQUOI
----------------------------------
Sur une évaluation RÉELLE (cible autorisée derrière Cloudflare) : `curl` rendait
`403 cf-mitigated: challenge` ; `evasion.turnstile` FRANCHISSAIT le défi (25 tirs,
`{'found': True, 'clicked': True, 'method': 'os/xdotool'}`) ; et le moteur a tout de même émis
**1573 actions pour 9 URLs distinctes atteintes** (accueil, favicon, URLs de défi) — le contenu du
site n'a JAMAIS été vu, 2410 findings, 0 vulnérable. La capacité de franchissement existait ; elle
n'était pas ROUTÉE vers les modules HTTP.

La métrique de ce lot est donc le **NOMBRE D'URLs DISTINCTES DONT LE MOTEUR OBTIENT LE CONTENU**
(200 + corps réel), pas « le cookie a bien été copié » — un test de copie ne prouverait rien.

LE HARNAIS
----------
Un serveur HTTP LOOPBACK (hermétique, aucun réseau sortant) qui se comporte comme la vraie cible :
il rend `403` + `cf-mitigated: challenge` À MOINS que la requête ne porte À LA FOIS le cookie
`cf_clearance` attendu ET le **User-Agent EXACT** du navigateur. Ce double critère n'est pas
décoratif : un `cf_clearance` est lié à l'UA (et à l'IP) qui l'a obtenu, et le rejouer sous l'UA
d'urllib le rend inopérant — c'est le piège classique, et le harnais le REPRODUIT (cf.
`TestUserAgentIsLoadBearing`).

Le service browser est un DOUBLE en mémoire (aucun port 8080 requis). Preuves couvertes :
  (1) PORTÉE      — 0 page avant / N pages après, par le chokepoint que ~40 modules partagent ;
  (2) SCOPE-GUARD — la clearance ne s'attache JAMAIS à un hôte hors périmètre ;
  (3) NON-FEINTE  — franchissement raté => `skipped` (« pas vérifié »), JAMAIS `tested` ;
  (4) UA          — sans l'UA exact, le matériel est refusé (pas de fausse route) ;
  (5) FUSION      — l'authentification déclarée par l'opérateur SURVIT à l'adoption ;
  (6) SECRET      — aucune valeur de cookie/UA dans un finding ;
  (7) BOUT-EN-BOUT— campagne `Engine` réelle (ROE armé, gate à 4 couches) : 0 page -> N pages.
"""
import http.server
import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import clearance, session                              # noqa: E402
from forge.brain import HeuristicBrain                            # noqa: E402
from forge.engine import Engine                                   # noqa: E402
from forge.graph import EngagementGraph                           # noqa: E402
from forge.modules import evasion as evasionmod                   # noqa: E402
from forge.modules.clientflow import XssReflected                 # noqa: E402
from forge.modules.evasion import EvasionDiscover, EvasionTurnstile, _EvasionBase  # noqa: E402
from forge.modules.httpflow import RequestSmugglingProbe          # noqa: E402
from forge.modules.oracle import Oracle                           # noqa: E402
from forge.planner import Planner                                 # noqa: E402
from forge.roe import Action, Scope                               # noqa: E402
from forge.schema import Target                                   # noqa: E402
from tests._dns import setUpModule, tearDownModule                # noqa: F401,E402

# --- constantes du harnais -------------------------------------------------------------------------
CLEARANCE_TOKEN = "cf-clearance-value-that-must-never-be-logged"
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 CamoufoxForge/128.0 Safari/537.36"
OPERATOR_COOKIE = "operator-session-value-that-must-never-be-logged"
CONTENT_TOKEN = "FORGE-REAL-APPLICATION-CONTENT"
PRIVATE_TOKEN = "FORGE-OPERATOR-ONLY-CONTENT"

# les pages de l'application — invisibles tant que le défi n'est pas routé.
PATHS = ("/", "/dashboard", "/profile", "/api/orders", "/api/cart")

# rendu que le navigateur voit APRÈS franchissement : liens/forms in-scope + un lien HORS-scope.
RENDERED_HTML = (
    '<html><body>'
    '<a href="/dashboard">dash</a>'
    '<a href="/profile">profile</a>'
    '<form action="/api/orders"></form>'
    '<a href="https://evil.example.com/track">tiers</a>'
    '<script>fetch("/api/cart");</script>'
    '</body></html>'
)


class _ChallengeHandler(http.server.BaseHTTPRequestHandler):
    """Cible qui SE COMPORTE comme la vraie : 403 + `cf-mitigated: challenge` sans le couple
    (cookie de clearance, User-Agent exact) ; le CONTENU avec. Une page `/private` exige EN PLUS le
    cookie d'auth de l'opérateur — c'est elle qui prouve que l'adoption FUSIONNE au lieu d'écraser."""

    protocol_version = "HTTP/1.0"

    def log_message(self, *_a):                          # silencieux (pas de bruit dans la suite)
        pass

    def _cookies(self):
        raw = self.headers.get("Cookie") or ""
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _challenge(self):
        body = b"<html><head><title>Just a moment...</title></head><body>cf-chl</body></html>"
        self.send_response(403)
        self.send_header("cf-mitigated", "challenge")    # EXACTEMENT ce qui a été mesuré sur la cible
        self.send_header("Server", "cloudflare")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ok(self, body):
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):                                    # noqa: N802
        cookies = self._cookies()
        cleared = (cookies.get("cf_clearance") == CLEARANCE_TOKEN
                   and self.headers.get("User-Agent") == BROWSER_UA)
        if not cleared:
            return self._challenge()
        if self.path.startswith("/private"):
            if cookies.get("sid") != OPERATOR_COOKIE:    # clearance OK mais auth opérateur perdue
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            return self._ok(f"<html>{PRIVATE_TOKEN}</html>")
        return self._ok(f"<html>{CONTENT_TOKEN} {self.path}</html>")

    do_POST = do_GET


class _FakeBrowser:
    """DOUBLE du service browser-automation (aucun port 8080, aucun réseau). Reproduit les formes de
    réponse réelles : `/cookies` -> liste de dicts avec `domain`, `/evaluate` -> l'UA en clair."""

    DEFAULT_TAB = "forge"

    def __init__(self, host, *, crossed=True, give_ua=True, third_party_only=False):
        self.host = host
        self.crossed = crossed
        self.give_ua = give_ua
        self.third_party_only = third_party_only
        self.calls = []

    def base_url(self):
        return "http://fake-browser.invalid:8080"

    def health(self, timeout=2):
        return True

    def capture_start(self, types=None, tab=DEFAULT_TAB, timeout=30):
        self.calls.append(("capture_start", tab))
        return 200, {}

    def capture_dump(self, url_contains=None, tab=DEFAULT_TAB, timeout=30):
        return 200, []

    def goto(self, url, tab=DEFAULT_TAB, wait=5, timeout=45):
        self.calls.append(("goto", url))
        return 200, {}

    def vision_click_os(self, strategy="turnstile", threshold=0.55, tab=DEFAULT_TAB, timeout=60):
        self.calls.append(("vision_click_os", strategy))
        if self.crossed:
            return 200, {"found": True, "clicked": True, "method": "os/xdotool"}
        return 200, {"found": False, "clicked": False}

    def content(self, max_length=50000, tab=DEFAULT_TAB, timeout=30):
        return (200, RENDERED_HTML) if self.crossed else (200, "")

    def cookies(self, timeout=30):
        """Le navigateur porte le cookie de clearance de l'hôte ET des cookies de TIERS — ces
        derniers ne doivent JAMAIS partir vers la cible (filtre par domaine)."""
        third = [{"name": "adtracker", "value": "tiers-ne-doit-pas-partir", "domain": ".ads.example"}]
        if not self.crossed or self.third_party_only:
            return 200, third
        return 200, [{"name": "cf_clearance", "value": CLEARANCE_TOKEN, "domain": self.host}] + third

    def evaluate(self, script, tab=DEFAULT_TAB, timeout=30):
        self.calls.append(("evaluate", script))
        return (200, BROWSER_UA) if self.give_ua else (200, "")


class _ClearanceHarness(unittest.TestCase):
    """Base : serveur loopback + double browser + scope, montés/démontés par test (hermétique)."""

    THIRD_PARTY_ONLY = False
    CROSSED = True
    GIVE_UA = True

    def setUp(self):
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ChallengeHandler)
        self.srv.socket.settimeout(1.0)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.hostport = f"127.0.0.1:{self.port}"
        self.base = f"http://{self.hostport}"
        self.urls = [self.base + p for p in PATHS]
        self.fake = _FakeBrowser("127.0.0.1", crossed=self.CROSSED, give_ua=self.GIVE_UA,
                                 third_party_only=self.THIRD_PARTY_ONLY)
        self._swap_browser(self.fake)

    def _stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)

    def _swap_browser(self, fake):
        orig = evasionmod.bc
        evasionmod.bc = fake
        _EvasionBase._health_cache.clear()               # la sonde de santé est memoïsée par base_url
        self.addCleanup(_EvasionBase._health_cache.clear)
        self.addCleanup(lambda: setattr(evasionmod, "bc", orig))

    # --- LA MÉTRIQUE : combien d'URLs distinctes le moteur obtient-il VRAIMENT ? -------------------
    def pages_reached(self, urls=None):
        """URLs dont le moteur obtient le CONTENU (200, non-challenge, corps applicatif réel), lues
        par `Oracle._http` — le chokepoint HTTP que partagent ~40 modules. C'est la mesure de la
        mission : « le moteur voit-il le site ? », pas « le cookie a-t-il été copié ? »."""
        got = set()
        for u in (urls if urls is not None else self.urls):
            st, body, hdrs = Oracle._http(u, timeout=5)
            if st == 200 and not clearance.response_is_challenge(st, body, hdrs) and CONTENT_TOKEN in body:
                got.add(u)
        return got

    def scope(self, **extra):
        data = {"mode": "grey", "in_scope": [self.hostport], "allow_private": True}
        data.update(extra)
        return Scope(data)

    def discover_action(self, scope=None):
        return Action("evasion.discover", self.base + "/",
                      params={"in_scope": [self.hostport], "out_scope": []})


# =================================================================================================
class TestReachBeforeAndAfter(_ClearanceHarness):
    """(1) LA PREUVE DE PORTÉE : 0 page avant, TOUTES après — par le chemin de tir réel des modules."""

    def test_zero_pages_before_routing(self):
        """Sans routage, le moteur ne voit RIEN : c'est l'état mesuré sur la cible réelle."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            self.assertEqual(self.pages_reached(), set())

    def test_all_pages_after_routing(self):
        """Après `evasion.discover` (qui franchit ET récolte), le moteur obtient TOUTES les pages."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionDiscover().fire(self.discover_action())
            self.assertEqual(self.pages_reached(), set(self.urls))

    def test_reach_goes_from_zero_to_five_in_one_run(self):
        """La transition 0 -> N dans UNE séquence (la mesure avant/après de la mission)."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            before = self.pages_reached()
            EvasionDiscover().fire(self.discover_action())
            after = self.pages_reached()
        self.assertEqual(len(before), 0)
        self.assertEqual(len(after), len(PATHS))

    def test_turnstile_also_routes_and_reports_reach(self):
        """`evasion.turnstile` — celui qui réussissait son clic 25 fois sans que rien n'en profite."""
        store = session.SessionStore.from_scope(self.scope())
        a = Action("evasion.turnstile", self.base + "/", params={"in_scope": [self.hostport]})
        with session.using(store):
            f = EvasionTurnstile().fire(a)[0]
            self.assertEqual(len(self.pages_reached()), len(PATHS))
        self.assertEqual(f.status, "tested")
        self.assertIn("cf_clearance", f.evidence)        # NOM du cookie routé
        self.assertEqual(store.clearance_state(self.base), store.CLEARED)

    def test_discovered_endpoints_are_emitted_and_in_scope_only(self):
        """La découverte reste elle-même correcte : endpoints in-scope émis, tiers écartés."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            findings = EvasionDiscover().fire(self.discover_action())
        targets = {f.target for f in findings}
        self.assertIn(self.base + "/dashboard", targets)
        self.assertFalse([t for t in targets if "evil.example.com" in t])


# =================================================================================================
class TestUserAgentIsLoadBearing(_ClearanceHarness):
    """(4) LE PIÈGE NOMMÉ : un cookie de clearance SANS l'UA exact est inopérant. Le harnais l'exige,
    et `material_for_host` REFUSE de produire du matériel sans UA plutôt que d'ouvrir une fausse route."""

    def test_cookies_without_browser_ua_reach_nothing(self):
        """Adoption FORCÉE des cookies seuls (sans UA) : le serveur refuse toujours -> 0 page.
        C'est la mesure qui interdit de croire qu'un cookie suffit."""
        store = session.SessionStore.from_scope(self.scope())
        store.adopt_clearance(self.base, {"cookies": {"cf_clearance": CLEARANCE_TOKEN}})
        with session.using(store):
            self.assertEqual(self.pages_reached(), set())

    def test_cookies_with_browser_ua_reach_everything(self):
        """Le MÊME cookie, plus l'UA exact : toutes les pages. Le delta est l'UA, et rien d'autre."""
        store = session.SessionStore.from_scope(self.scope())
        store.adopt_clearance(self.base, {"cookies": {"cf_clearance": CLEARANCE_TOKEN},
                                          "headers": {"User-Agent": BROWSER_UA}})
        with session.using(store):
            self.assertEqual(self.pages_reached(), set(self.urls))

    def test_material_refused_without_readable_ua(self):
        """`material_for_host` rend None sans UA lisible — refus explicite, pas de route illusoire."""
        payload = [{"name": "cf_clearance", "value": CLEARANCE_TOKEN, "domain": "127.0.0.1"}]
        self.assertIsNone(clearance.material_for_host(payload, "", "127.0.0.1"))
        self.assertIsNotNone(clearance.material_for_host(payload, BROWSER_UA, "127.0.0.1"))


class TestUaMissingDegrades(_ClearanceHarness):
    """Le navigateur ne rend pas d'UA : on n'adopte RIEN et on ne prétend PAS avoir franchi."""

    GIVE_UA = False

    def test_no_adoption_and_no_reach(self):
        store = session.SessionStore.from_scope(self.scope())
        a = Action("evasion.turnstile", self.base + "/", params={"in_scope": [self.hostport]})
        with session.using(store):
            f = EvasionTurnstile().fire(a)[0]
            self.assertEqual(self.pages_reached(), set())
        self.assertEqual(f.status, "skipped")
        self.assertEqual(store.clearance_state(self.base), store.CHALLENGED)


# =================================================================================================
class TestScopeGuardOnClearance(_ClearanceHarness):
    """(2) Le matériel de franchissement obéit AU MÊME scope-guard que le matériel d'auth : un cookie
    de clearance qui partirait vers un tiers serait une FUITE DE SESSION vers un hôte non autorisé."""

    def test_adoption_refused_for_out_of_scope_host(self):
        store = session.SessionStore.from_scope(self.scope())
        ok = store.adopt_clearance("https://evil.example.com/",
                                   {"cookies": {"cf_clearance": CLEARANCE_TOKEN},
                                    "headers": {"User-Agent": BROWSER_UA}})
        self.assertFalse(ok)

    def test_no_material_leaks_to_out_of_scope_host(self):
        """Le test qui compte : même après adoption, `headers_for` d'un tiers reste VIDE."""
        store = session.SessionStore.from_scope(self.scope())
        store.adopt_clearance(self.base, {"cookies": {"cf_clearance": CLEARANCE_TOKEN},
                                          "headers": {"User-Agent": BROWSER_UA}})
        self.assertEqual(store.headers_for("https://evil.example.com/collect"), {})

    def test_module_adoption_is_scope_guarded(self):
        """Le chemin MODULE (pas seulement l'API du store) : cible hors périmètre -> aucune adoption."""
        store = session.SessionStore.from_scope(Scope({"mode": "grey", "in_scope": ["other.test"]}))
        with session.using(store):
            telemetry = EvasionDiscover()._adopt_clearance(self.base + "/", "forge")
        self.assertFalse(telemetry["adopted"])
        self.assertEqual(store.headers_for(self.base + "/"), {})

    def test_third_party_cookies_are_not_harvested(self):
        """Un cookie de TIERS présent dans le navigateur ne rejoint jamais la cible (filtre domaine)."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionDiscover().fire(self.discover_action())
        cookie_header = store.headers_for(self.base + "/").get("Cookie", "")
        self.assertIn("cf_clearance", cookie_header)
        self.assertNotIn("adtracker", cookie_header)


# =================================================================================================
class TestOperatorAuthSurvivesAdoption(_ClearanceHarness):
    """(5) FUSION, pas écrasement : adopter la clearance NE DOIT PAS détruire l'authentification
    déclarée par l'opérateur — sinon les oracles d'accès redeviennent anonymes et rendent « rien
    trouvé » (rapport propre et vide : le mode d'échec le plus cher du dépôt)."""

    def _store_with_operator_session(self):
        return session.SessionStore.from_scope(
            self.scope(session={"cookies": f"sid={OPERATOR_COOKIE}"}))

    def test_operator_cookie_still_reaches_private_page(self):
        """La page qui exige LES DEUX cookies : clearance + session opérateur. Elle n'est servie que
        si l'adoption a FUSIONNÉ le matériel récolté SOUS celui de l'opérateur."""
        store = self._store_with_operator_session()
        with session.using(store):
            EvasionDiscover().fire(self.discover_action())
            st, body, _h = Oracle._http(self.base + "/private", timeout=5)
        self.assertEqual(st, 200)
        self.assertIn(PRIVATE_TOKEN, body)

    def test_merged_cookie_header_carries_both(self):
        store = self._store_with_operator_session()
        with session.using(store):
            EvasionDiscover().fire(self.discover_action())
        cookie_header = store.headers_for(self.base + "/").get("Cookie", "")
        self.assertIn("sid=", cookie_header)
        self.assertIn("cf_clearance=", cookie_header)

    def test_operator_explicit_header_wins_over_harvested(self):
        """« L'explicite prime » : un opérateur qui fixe SON User-Agent le garde (choix jamais renversé)."""
        store = session.SessionStore.from_scope(
            self.scope(session={"headers": {"User-Agent": "operator-ua"}}))
        store.adopt_clearance(self.base, {"cookies": {"cf_clearance": CLEARANCE_TOKEN},
                                          "headers": {"User-Agent": BROWSER_UA}})
        self.assertEqual(store.headers_for(self.base)["User-Agent"], "operator-ua")


# =================================================================================================
class TestNeverPretend(_ClearanceHarness):
    """(3) L'ACQUIS À NE PAS CASSER : « je n'ai pas pu vérifier » (`skipped`) ne doit JAMAIS devenir
    « j'ai vérifié, rien trouvé » (`tested`). Portée VOLONTAIREMENT étroite : un 403 NU reste un
    verdict applicatif sur lequel l'oracle conclut."""

    def _oracle_action(self):
        return Action("xss.reflected", self.base + "/",
                      params={"param": "q", "in_scope": [self.hostport], "out_scope": []})

    def test_oracle_behind_challenge_returns_skipped(self):
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            f = XssReflected().fire(self._oracle_action())[0]
        self.assertEqual(f.status, "skipped")

    def test_oracle_behind_challenge_never_says_tested(self):
        """Assertion ISOLÉE (une assertion antérieure ne doit pas pouvoir l'avorter sous mutation)."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            f = XssReflected().fire(self._oracle_action())[0]
        self.assertNotEqual(f.status, "tested")

    def test_same_oracle_concludes_once_routed(self):
        """Une fois le franchissement routé, l'oracle VOIT l'app et rend un verdict légitime."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionDiscover().fire(self.discover_action())
            f = XssReflected().fire(self._oracle_action())[0]
        self.assertEqual(f.status, "tested")

    def test_plain_403_still_yields_a_verdict(self):
        """ANTI-ÉLARGISSEMENT : un 403 SANS signature de challenge n'est PAS une cécité — l'oracle
        conclut comme avant. Sans cette borne, tout 403 applicatif deviendrait un `skipped` de
        complaisance et la portée du garde-fou serait cassée."""
        self.assertFalse(clearance.response_is_challenge(403, "", {"Server": "nginx"}))
        self.assertFalse(clearance.response_is_challenge(429, "", {}))
        self.assertTrue(clearance.response_is_challenge(403, "", {"cf-mitigated": "challenge"}))
        self.assertTrue(clearance.response_is_challenge(200, "<title>Just a moment...</title>", {}))

    def test_challenged_host_is_marked_for_bodyless_modules(self):
        """L'oracle qui a VU la signature marque l'hôte -> les modules sans corps (sonde de TIMING du
        smuggling) s'abstiennent au lieu d'affirmer « aucun hang, rien trouvé »."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            XssReflected().fire(self._oracle_action())
            self.assertEqual(store.clearance_state(self.base), store.CHALLENGED)
            f = RequestSmugglingProbe().fire(
                Action("request_smuggling.probe", self.base + "/",
                       params={"in_scope": [self.hostport], "out_scope": []}))[0]
        self.assertEqual(f.status, "skipped")


class TestCrossingFailedNeverPretends(_ClearanceHarness):
    """Le franchissement ÉCHOUE (le navigateur n'obtient pas de clearance) : rien n'est affirmé."""

    CROSSED = False

    def test_discover_reports_skipped(self):
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            findings = EvasionDiscover().fire(self.discover_action())
        self.assertEqual(findings[0].status, "skipped")

    def test_discover_marks_host_challenged(self):
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionDiscover().fire(self.discover_action())
        self.assertEqual(store.clearance_state(self.base), store.CHALLENGED)

    def test_no_pages_are_claimed(self):
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionDiscover().fire(self.discover_action())
            self.assertEqual(self.pages_reached(), set())


class TestOnlyThirdPartyCookiesNeverPretends(_ClearanceHarness):
    """Le navigateur a bien navigué mais ne porte AUCUN cookie de l'hôte : aucune adoption fantôme."""

    THIRD_PARTY_ONLY = True

    def test_turnstile_reports_skipped(self):
        store = session.SessionStore.from_scope(self.scope())
        a = Action("evasion.turnstile", self.base + "/", params={"in_scope": [self.hostport]})
        with session.using(store):
            f = EvasionTurnstile().fire(a)[0]
        self.assertEqual(f.status, "skipped")


# =================================================================================================
class TestSecrecy(_ClearanceHarness):
    """(6) SECRET : le matériel routé ne doit apparaître NULLE PART dans un finding."""

    def test_no_cookie_or_ua_value_in_findings(self):
        store = session.SessionStore.from_scope(
            self.scope(session={"cookies": f"sid={OPERATOR_COOKIE}"}))
        a = Action("evasion.turnstile", self.base + "/", params={"in_scope": [self.hostport]})
        with session.using(store):
            findings = EvasionDiscover().fire(self.discover_action())
            findings += EvasionTurnstile().fire(a)
        blob = " ".join(f"{f.title} {f.evidence} {f.poc}" for f in findings)
        self.assertNotIn(CLEARANCE_TOKEN, blob)
        self.assertNotIn(OPERATOR_COOKIE, blob)
        self.assertNotIn(BROWSER_UA, blob)

    def test_store_repr_leaks_nothing(self):
        store = session.SessionStore.from_scope(self.scope())
        store.adopt_clearance(self.base, {"cookies": {"cf_clearance": CLEARANCE_TOKEN},
                                          "headers": {"User-Agent": BROWSER_UA}})
        self.assertNotIn(CLEARANCE_TOKEN, repr(store) + str(store.clearance_census())
                         + repr(store.hosts_with_session()))


# =================================================================================================
class TestFullEngineCampaign(_ClearanceHarness):
    """(7) BOUT-EN-BOUT : une campagne `Engine` RÉELLE (ROE armé, gate à 4 couches, `session.using`
    posé par le moteur autour de chaque fire). C'est la chaîne complète, pas un appel de module."""

    def _engine(self):
        eng = Engine(self.scope(mode="auto"), mode="auto", graph=EngagementGraph())
        eng.roe.arm("test")
        return eng

    def test_campaign_reaches_pages_it_could_not_reach_before(self):
        eng = self._engine()
        with session.using(eng.sessions):
            before = self.pages_reached()
        eng.execute(Action("evasion.discover", self.base + "/",
                           params={"in_scope": [self.hostport], "out_scope": []}))
        with session.using(eng.sessions):
            after = self.pages_reached()
        self.assertEqual(len(before), 0)
        self.assertEqual(len(after), len(PATHS))

    def test_campaign_wires_clearance_into_engine_store(self):
        eng = self._engine()
        eng.execute(Action("evasion.discover", self.base + "/",
                           params={"in_scope": [self.hostport], "out_scope": []}))
        self.assertEqual(eng.sessions.clearance_state(self.base), eng.sessions.CLEARED)

    def test_targets_campaign_end_to_end(self):
        """Campagne complète depuis une `Target` : le cerveau propose, le ROE gate, les modules tirent."""
        eng = self._engine()
        eng.campaign([Target(host=self.hostport, kind="app", attrs={"protected": True})],
                     HeuristicBrain(), Planner(),
                     modules=["evasion.discover", "evasion.turnstile"])
        with session.using(eng.sessions):
            self.assertEqual(len(self.pages_reached()), len(PATHS))


if __name__ == "__main__":
    unittest.main(verbosity=2)

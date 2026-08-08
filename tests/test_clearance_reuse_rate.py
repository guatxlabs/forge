# SPDX-License-Identifier: AGPL-3.0-or-later
"""TAUX DE FRANCHISSEMENT — la mesure, pas l'intention.

CE QUE LES TRACES RÉELLES DISENT (ledger `gxrun2`, cible autorisée derrière Cloudflare)
--------------------------------------------------------------------------------------
Le run a compté **51 tirs `evasion.turnstile` + 52 tirs `evasion.discover` = 103 franchissements
tentés en 48 min**, et le rapport annonçait « 8 réussites / 51 = 16 % ». Le dépouillement des
findings du ledger dit autre chose :

  1. `clearance_adoptée=False` dans **103/103**. Pas UNE clearance routée. Le vrai taux est **0 %**.
  2. Les 8 « réussites » sont TOUTES des graphies de `www.guatx.com`, TOUTES en **HTTP 301** (la règle
     d'edge www→apex de Cloudflare, servie AVANT tout défi), et **2 des 8 portent
     `{'found': False, 'clicked': False}`** — la case n'a même pas été cliquée. Le prédicat
     `200 <= status < 400 and not challenge` comptait une simple redirection comme « le moteur voit
     le site ». C'était un `tested` MENSONGER : la ligne rouge du dépôt.
  3. Les 51 tirs visaient **9 hôtes distincts** : la clé de tir était la CHAÎNE de cible brute
     (`guatx.com`, `https://guatx.com`, `guatx.com:443`, `http://guatx.com:8080`, `https://guatx.com/`…)
     — 16 graphies pour le seul `guatx.com`, 16 pour `www.guatx.com`. Chaque module re-tentait le défi
     pour son propre compte : 16× le coût, 16× la dégradation de réputation IP, pour UN hôte.

CE QUI EST MESURÉ ICI
---------------------
Le harnais reproduit la FORME du run : **16 demandes d'accès successives au MÊME hôte, écrites des
16 façons relevées dans le ledger**, plus la graphie qui répond 301 comme le faisait `www`.

  - `tentatives`  = appels `/vision-click-os` réellement dépensés (l'opération coûteuse ET risquée :
                    « 1 SEUL essai sur IP propre — marteler = Cloudflare flague l'IP ») ;
  - `servies`     = demandes après lesquelles le moteur obtient VRAIMENT le contenu applicatif, lu par
                    `Oracle._http`, le chokepoint que ~40 modules partagent ;
  - `mensonges`   = findings `status='tested'` émis SANS que le contenu soit joignable.

Le double du service navigateur est FIDÈLE au service mesuré : `GET /cookies` y rend **HTTP 500**
(`AttributeError: 'Browser' object has no attribute 'cookies'`, api.py:224 — vérifié en direct sur
le service qui tourne), et `/evaluate` rend l'UA dans `{"result": …}`. C'est la fidélité qui manquait :
l'ancien double rendait des cookies, donc les tests étaient verts pendant que le terrain était à 0.
Hermétique : aucun réseau sortant, aucun port 8080.
"""
import http.server
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import clearance, session                              # noqa: E402
from forge.modules import evasion as evasionmod                   # noqa: E402
from forge.modules.evasion import EvasionDiscover, EvasionTurnstile, _EvasionBase  # noqa: E402
from forge.modules.oracle import Oracle                           # noqa: E402
from forge.roe import Action, Scope                               # noqa: E402
from tests._dns import setUpModule, tearDownModule                # noqa: F401,E402

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0"
CONTENT_TOKEN = "FORGE-REAL-APPLICATION-CONTENT"
REDIRECT_PATH = "/edge-redirect"                 # la règle d'edge qui a fabriqué les 8 faux succès


class _EdgeHandler(http.server.BaseHTTPRequestHandler):
    """Cible qui SE COMPORTE comme l'edge Cloudflare mesuré.

    - `REDIRECT_PATH` -> **301 inconditionnel**, servi par l'edge AVANT tout défi : c'est ce que
      `www.guatx.com` rendait, et c'est ce que l'ancien prédicat prenait pour une réussite ;
    - partout ailleurs -> `403 cf-mitigated: challenge`, SAUF si la requête porte le couple
      (cookie `cf_clearance` **encore valide côté serveur**, User-Agent EXACT du navigateur).

    `valid_tokens` est une classe-variable : un test la vide pour RÉVOQUER la clearance en vol (ce
    qu'un edge fait quand elle expire) et vérifier que le moteur ne fait pas semblant après coup."""

    protocol_version = "HTTP/1.0"
    valid_tokens = set()
    # FIDÉLITÉ AU TERRAIN : sur les 51 tirs du run, `response_is_challenge` a rendu **False pour les
    # 20 réponses 403** — l'edge ne renvoyait PAS `cf-mitigated` sur ce chemin, et `Oracle._http`
    # rend un corps VIDE sur HTTPError. Le blocage était donc INDISCERNABLE d'un 403 applicatif par
    # le seul prédicat de challenge. `bare_403 = True` reproduit exactement ça.
    bare_403 = False

    def log_message(self, *_a):
        pass

    def _cookies(self):
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def do_GET(self):                                    # noqa: N802
        if self.path.startswith(REDIRECT_PATH):
            self.send_response(301)
            self.send_header("Location", "https://apex.invalid/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        tok = self._cookies().get("cf_clearance")
        if tok not in type(self).valid_tokens or self.headers.get("User-Agent") != BROWSER_UA:
            bare = type(self).bare_403
            body = b"" if bare else (
                b"<html><head><title>Just a moment...</title></head><body>cf-chl</body></html>")
            self.send_response(403)
            if not bare:
                self.send_header("cf-mitigated", "challenge")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return None
        raw = f"<html>{CONTENT_TOKEN} {self.path}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_POST = do_GET


class _FieldBrowser:
    """DOUBLE FIDÈLE du service browser-automation tel qu'il TOURNE (mesuré en direct).

    `cookie_mode` :
      - `"broken500"` : `GET /cookies` -> `(500, "Internal Server Error")` — l'état RÉEL du service
        pendant le run mesuré (api.py:224 appelle `context.cookies()` sur un objet `Browser`) ;
      - `"ok"`        : le service réparé rend la liste de cookies du contexte.

    Compte les `/vision-click-os` : c'est la TENTATIVE de franchissement, la seule opération dont le
    dépôt sait qu'elle brûle la réputation IP quand on la martèle."""

    DEFAULT_TAB = "forge"

    def __init__(self, host, *, cookie_mode="broken500", crossed=True, token="tok-1"):
        self.host = host
        self.cookie_mode = cookie_mode
        self.crossed = crossed
        self.token = token
        self.attempts = 0                                # /vision-click-os dépensés
        self.gotos = 0

    def base_url(self):
        return "http://fake-browser.invalid:8080"

    def health(self, timeout=2):
        return True

    def capture_start(self, types=None, tab=DEFAULT_TAB, timeout=30):
        return 200, {}

    def capture_dump(self, url_contains=None, tab=DEFAULT_TAB, timeout=30):
        return 200, []

    def goto(self, url, tab=DEFAULT_TAB, wait=5, timeout=45):
        self.gotos += 1
        return 200, {}

    def vision_click_os(self, strategy="turnstile", threshold=0.55, tab=DEFAULT_TAB, timeout=60):
        self.attempts += 1
        if self.crossed:
            _EdgeHandler.valid_tokens.add(self.token)    # le défi est réellement franchi côté edge
            return 200, {"found": True, "clicked": True, "method": "os/xdotool",
                         "page_xy": [315.0, 337.0], "screen_xy": [315, 398]}
        return 200, {"found": False, "clicked": False}

    def content(self, max_length=50000, tab=DEFAULT_TAB, timeout=30):
        return (200, f"<html><a href='/dashboard'>d</a>{CONTENT_TOKEN}</html>") if self.crossed else (200, "")

    def cookies(self, timeout=30):
        if self.cookie_mode == "broken500":              # ce que le service RENVOIE aujourd'hui
            return 500, "Internal Server Error"
        return 200, {"cookies": [{"name": "cf_clearance", "value": self.token,
                                  "domain": self.host, "path": "/"}]}

    def evaluate(self, script, tab=DEFAULT_TAB, timeout=30):
        return 200, {"tab": tab, "result": BROWSER_UA}   # forme EXACTE du service réel


# --- les 16 graphies d'UN SEUL hôte relevées dans le ledger pour `guatx.com` ------------------------
def spellings(host, port):
    """Les graphies que le planner a réellement produites pour un seul hôte (ledger gxrun2)."""
    hp = f"{host}:{port}"
    return [hp, f"http://{hp}", f"https://{hp}", f"https://{hp}/", f"http://{hp}/",
            f"https://{hp}/favicon.ico", f"http://{hp}/favicon.ico", hp, f"https://{hp}",
            f"http://{hp}", f"https://{hp}/", hp, f"http://{hp}/", f"https://{hp}",
            f"https://{hp}/favicon.ico", f"http://{hp}"]


class _RateHarness(unittest.TestCase):
    """Serveur loopback + double fidèle, montés/démontés par test. Zéro réseau sortant."""

    COOKIE_MODE = "broken500"
    CROSSED = True

    def setUp(self):
        _EdgeHandler.valid_tokens = set()
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _EdgeHandler)
        self.srv.socket.settimeout(1.0)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.hostport = f"127.0.0.1:{self.port}"
        self.base = f"http://{self.hostport}"
        self.fake = _FieldBrowser("127.0.0.1", cookie_mode=self.COOKIE_MODE, crossed=self.CROSSED)
        orig = evasionmod.bc
        evasionmod.bc = self.fake
        _EvasionBase._health_cache.clear()
        self.addCleanup(_EvasionBase._health_cache.clear)
        self.addCleanup(lambda: setattr(evasionmod, "bc", orig))
        self.addCleanup(lambda: setattr(_EdgeHandler, "valid_tokens", set()))

    def _stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)

    def scope(self):
        return Scope({"mode": "grey", "in_scope": [self.hostport], "allow_private": True})

    def sees_content(self, url=None):
        """Le moteur obtient-il le CONTENU applicatif par le chokepoint partagé ? (pas « le cookie
        est copié », pas « ce n'est pas un challenge » : le CONTENU.)"""
        st, body, hdrs = Oracle._http(url or (self.base + "/"), timeout=5)
        return st == 200 and CONTENT_TOKEN in (body or "")

    def measure(self, module_cls=EvasionTurnstile, kind="evasion.turnstile"):
        """LA MESURE : 16 demandes successives d'accès au même hôte (16 graphies), puis
        {tentatives, servies, mensonges, findings}."""
        store = session.SessionStore.from_scope(self.scope())
        servies = mensonges = 0
        findings = []
        with session.using(store):
            for spell in spellings("127.0.0.1", self.port):
                url = f"http://{spell}" if "://" not in spell else spell
                act = Action(kind, url, params={"in_scope": [self.hostport], "out_scope": []})
                fs = module_cls().fire(act)
                findings += fs
                served = self.sees_content()
                servies += 1 if served else 0
                if not served and any(f.status == "tested" and "Turnstile" in f.title for f in fs):
                    mensonges += 1
        return {"tentatives": self.fake.attempts, "servies": servies,
                "mensonges": mensonges, "findings": findings, "store": store}


# =================================================================================================
class TestFieldShapeIsReproduced(_RateHarness):
    """Le harnais reproduit-il bien ce que le ledger montre ? (sinon la mesure ne vaut rien)"""

    def test_service_cookie_failure_is_the_measured_one(self):
        """`GET /cookies` -> 500 : c'est CE payload que `clearance` doit savoir nommer."""
        st, payload = self.fake.cookies()
        self.assertEqual(st, 500)
        self.assertEqual(clearance.cookies_for_host(payload, "127.0.0.1"), {})

    def test_browser_ua_is_readable_so_it_is_not_the_culprit(self):
        """L'UA, lui, est PARFAITEMENT lisible — l'évidence du run l'accusait à tort."""
        _st, payload = self.fake.evaluate("navigator.userAgent")
        self.assertEqual(clearance.user_agent_from(payload), BROWSER_UA)


# =================================================================================================
class TestCrossingRateBrokenService(_RateHarness):
    """SERVICE CASSÉ (l'état RÉEL du run) — la clearance ne peut pas être récoltée.

    Ce que le correctif doit changer ICI n'est PAS le nombre de pages vues (impossible sans cookie) :
    c'est le COÛT (16 tentatives -> 1) et l'HONNÊTETÉ (0 `tested` menteur, raison correctement
    imputée au service et non à l'UA)."""

    COOKIE_MODE = "broken500"

    def test_one_attempt_per_host_not_one_per_spelling(self):
        """RÉUTILISER PLUTÔT QUE RETENTER : 16 demandes, 1 seul défi tenté."""
        m = self.measure()
        self.assertEqual(m["servies"], 0)                # sans cookie, rien n'est joignable — et on le DIT
        self.assertEqual(m["tentatives"], 1,
                         f"16 graphies d'UN hôte ont coûté {m['tentatives']} franchissements")

    def test_never_claims_tested_without_content(self):
        """LIGNE ROUGE : aucun `tested` quand le contenu n'est pas joignable."""
        m = self.measure()
        self.assertEqual(m["mensonges"], 0)
        self.assertTrue(all(f.status == "skipped" for f in m["findings"]))

    def test_failure_is_imputed_to_the_service_not_to_the_user_agent(self):
        """L'évidence du run accusait « User-Agent illisible » alors que l'UA était bon. Plus jamais."""
        m = self.measure()
        ev = m["findings"][0].evidence
        self.assertIn("500", ev)
        self.assertNotIn("User-Agent illisible", ev)

    def test_host_is_marked_challenged_so_downstream_abstains(self):
        m = self.measure()
        store = m["store"]
        self.assertEqual(store.clearance_state(self.base), store.CHALLENGED)


# =================================================================================================
class TestCrossingRateWorkingService(_RateHarness):
    """SERVICE RÉPARÉ (`/cookies` rend le contexte) — la mesure qui compte pour la mission."""

    COOKIE_MODE = "ok"

    def test_all_spellings_served_by_a_single_crossing(self):
        """16 demandes servies pour **1** franchissement dépensé."""
        m = self.measure()
        self.assertEqual(m["servies"], 16)
        self.assertEqual(m["tentatives"], 1)
        self.assertEqual(m["mensonges"], 0)

    def test_discover_reuses_the_clearance_taken_by_turnstile(self):
        """Un AUTRE module ne re-tente pas : il CONSOMME la clearance déjà valide."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionTurnstile().fire(Action("evasion.turnstile", self.base + "/",
                                           params={"in_scope": [self.hostport]}))
            after_first = self.fake.attempts
            EvasionDiscover().fire(Action("evasion.discover", self.base + "/",
                                          params={"in_scope": [self.hostport], "out_scope": []}))
            self.assertTrue(self.sees_content())
        self.assertEqual(after_first, 1)
        self.assertEqual(self.fake.attempts, 1, "evasion.discover a re-tenté un défi déjà franchi")


# =================================================================================================
class TestEdgeRedirectIsNeverASuccess(_RateHarness):
    """LES 8 FAUX SUCCÈS — une 301 d'edge n'est PAS « le moteur voit le site »."""

    COOKIE_MODE = "broken500"

    def test_301_is_not_reported_as_crossed(self):
        store = session.SessionStore.from_scope(self.scope())
        url = self.base + REDIRECT_PATH
        with session.using(store):
            f = EvasionTurnstile().fire(Action("evasion.turnstile", url,
                                               params={"in_scope": [self.hostport]}))[0]
        self.assertEqual(f.status, "skipped", "une 301 d'edge a été comptée comme un franchissement")
        self.assertNotIn("franchi", f.title)

    def test_reach_predicate_rejects_every_3xx(self):
        """Le refus tient sur le STATUT SEUL : on donne un corps NON VIDE, sinon la garde
        « corps vide » suffirait à faire passer le test et la garde de statut ne serait pas
        éprouvée (mutation M1 restée verte à la première passe)."""
        for st in (301, 302, 303, 307, 308):
            with self.subTest(status=st):
                self.assertFalse(clearance.reach_is_content(
                    st, "<html><body>Moved Permanently. Redirecting to /</body></html>", {}))
        self.assertTrue(clearance.reach_is_content(200, "<html>hello</html>", {}))

    def test_reach_predicate_rejects_a_2xx_without_bytes(self):
        """Pas d'octets, pas de preuve : un `200`/`204` à corps vide ne montre AUCUNE application."""
        for st, body in ((200, ""), (204, ""), (200, None)):
            with self.subTest(status=st, body=body):
                self.assertFalse(clearance.reach_is_content(st, body, {}))

    def test_reach_predicate_rejects_a_2xx_that_is_a_challenge_page(self):
        """Un défi servi en 200 (interstitiel « Just a moment ») n'est pas l'application."""
        self.assertFalse(clearance.reach_is_content(
            200, "<html><head><title>Just a moment...</title></head></html>", {}))


# =================================================================================================
class TestClickNotFoundIsNeverASuccess(_RateHarness):
    """2 des 8 « réussites » du run portaient `found=False` : la case n'avait pas été cliquée."""

    COOKIE_MODE = "broken500"
    CROSSED = False

    def test_not_found_never_tested(self):
        m = self.measure()
        self.assertEqual(m["mensonges"], 0)
        self.assertTrue(all(f.status == "skipped" for f in m["findings"]))


# =================================================================================================
class TestExpiredClearanceNeverPretends(_RateHarness):
    """UNE CLEARANCE PÉRIMÉE REJOUÉE SERAIT LE PIRE MODE D'ÉCHEC : la cible rendrait des pages de
    défi que les oracles prendraient pour du contenu applicatif."""

    COOKIE_MODE = "ok"

    def test_expired_material_is_no_longer_served_and_state_is_not_cleared(self):
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionTurnstile().fire(Action("evasion.turnstile", self.base + "/",
                                           params={"in_scope": [self.hostport]}))
            self.assertTrue(self.sees_content())
            self.assertEqual(store.clearance_state(self.base), store.CLEARED)
            store.expire_clearance(self.base)            # TTL écoulé
            self.assertNotEqual(store.clearance_state(self.base), store.CLEARED)
            self.assertEqual(store.headers_for(self.base), {})
            self.assertFalse(self.sees_content())

    def test_ttl_expiry_stops_serving_the_material(self):
        """LA DURÉE DE VIE EST RÉELLE, pas décorative : c'est le TTL lui-même qui retire le matériel
        (et non un appel explicite à `expire_clearance`). Un `ttl` nul/négatif = déjà morte."""
        store = session.SessionStore.from_scope(self.scope())
        material = {"cookies": {"cf_clearance": "x"}, "headers": {"User-Agent": BROWSER_UA}}
        self.assertTrue(store.adopt_clearance(self.base, material, ttl=600))
        self.assertNotEqual(store.headers_for(self.base), {})
        self.assertEqual(store.clearance_state(self.base), store.CLEARED)
        self.assertTrue(store.adopt_clearance(self.base, material, ttl=-1))   # échue d'emblée
        self.assertEqual(store.headers_for(self.base), {},
                         "du matériel PÉRIMÉ est encore envoyé à la cible")
        self.assertEqual(store.clearance_state(self.base), store.CHALLENGED)

    def test_ttl_expiry_reopens_a_crossing_attempt(self):
        """Une fois le TTL écoulé, le gate REDONNE le droit de tenter (ré-acquisition), sans quoi
        le moteur resterait aveugle pour le restant du run."""
        store = session.SessionStore.from_scope(self.scope())
        material = {"cookies": {"cf_clearance": "x"}, "headers": {"User-Agent": BROWSER_UA}}
        store.adopt_clearance(self.base, material, ttl=600)
        self.assertFalse(store.should_attempt_crossing(self.base)[0])         # encore valide -> réutiliser
        later = __import__("time").time() + 3600
        self.assertTrue(store.should_attempt_crossing(self.base, now=later)[0])

    def test_bare_403_without_challenge_header_still_revokes(self):
        """LA MESURE COMMANDE : sur les 51 tirs du run, `response_is_challenge` a rendu **False pour
        les 20 réponses 403** (pas d'en-tête `cf-mitigated` sur ce chemin, corps vide sur HTTPError).
        Se fier au seul en-tête laisserait une clearance MORTE en place. Un 403 nu doit révoquer."""
        store = session.SessionStore.from_scope(self.scope())
        material = {"cookies": {"cf_clearance": "x"}, "headers": {"User-Agent": BROWSER_UA}}
        store.adopt_clearance(self.base, material, ttl=600)
        _EdgeHandler.bare_403 = True                                          # l'edge du run mesuré
        self.addCleanup(lambda: setattr(_EdgeHandler, "bare_403", False))
        st, body, hdrs = Oracle._http(self.base + "/", timeout=5)
        self.assertEqual(st, 403)
        self.assertFalse(clearance.response_is_challenge(st, body, hdrs),
                         "le harnais n'est pas fidèle : ce 403 est détectable comme un défi")
        with session.using(store):
            f = EvasionTurnstile().fire(Action("evasion.turnstile", self.base + "/",
                                               params={"in_scope": [self.hostport]}))[0]
        self.assertEqual(f.status, "skipped")
        self.assertEqual(store.headers_for(self.base), {},
                         "un 403 nu a laissé en place une clearance qui ne marche plus")

    def test_clearance_revoked_by_the_edge_never_produces_tested(self):
        """LE MODE D'ÉCHEC À ÉVITER, par le chemin RÉEL : la clearance est encore « valide » selon
        NOTRE TTL, mais l'edge l'a RÉVOQUÉE. La cible re-sert des pages de défi. Le moteur ne doit
        NI les prendre pour du contenu, NI continuer à tirer avec ce matériel mort."""
        store = session.SessionStore.from_scope(self.scope())
        act = Action("evasion.turnstile", self.base + "/", params={"in_scope": [self.hostport]})
        with session.using(store):
            first = EvasionTurnstile().fire(act)[0]
            self.assertEqual(first.status, "tested")     # franchissement RÉEL et prouvé par le contenu
            _EdgeHandler.valid_tokens.clear()            # l'edge révoque (TTL côté Cloudflare)
            self.fake.crossed = False                    # et le défi ne repasse plus
            second = EvasionTurnstile().fire(act)[0]
            self.assertEqual(second.status, "skipped", "une clearance morte a produit un `tested`")
            self.assertFalse(self.sees_content())
            self.assertEqual(store.headers_for(self.base), {},
                             "le matériel révoqué est encore envoyé à la cible")
            self.assertEqual(store.clearance_state(self.base), store.CHALLENGED)

    def test_reacquisition_is_allowed_after_expiry_without_hammering(self):
        """Périmée -> on RE-ACQUIERT (1 tentative de plus), on ne martèle pas (pas 16)."""
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionTurnstile().fire(Action("evasion.turnstile", self.base + "/",
                                           params={"in_scope": [self.hostport]}))
            store.expire_clearance(self.base)
            self.fake.token = "tok-2"                    # l'edge délivre une NOUVELLE clearance
            for spell in spellings("127.0.0.1", self.port):
                url = f"http://{spell}" if "://" not in spell else spell
                EvasionTurnstile().fire(Action("evasion.turnstile", url,
                                               params={"in_scope": [self.hostport]}))
            self.assertTrue(self.sees_content())
        self.assertEqual(self.fake.attempts, 2, "la ré-acquisition a martelé au lieu de re-tenter 1 fois")


# =================================================================================================
class TestScopeGuardHoldsOnReuse(_RateHarness):
    """LE MATÉRIEL RÉUTILISÉ NE FUIT PAS : une clearance mise en cache pour un hôte in-scope ne peut
    pas être rejouée vers un autre hôte."""

    COOKIE_MODE = "ok"

    def test_cached_clearance_never_leaks_to_another_host(self):
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionTurnstile().fire(Action("evasion.turnstile", self.base + "/",
                                           params={"in_scope": [self.hostport]}))
            self.assertNotEqual(store.headers_for(self.base), {})
            self.assertEqual(store.headers_for("https://evil.example.com/"), {})
            self.assertEqual(store.headers_for("http://other.invalid/"), {})

    def test_reuse_decision_is_scope_guarded(self):
        store = session.SessionStore.from_scope(self.scope())
        with session.using(store):
            EvasionTurnstile().fire(Action("evasion.turnstile", self.base + "/",
                                           params={"in_scope": [self.hostport]}))
        ok, _why = store.should_attempt_crossing("https://evil.example.com/")
        self.assertFalse(ok, "un hôte hors périmètre ne doit jamais être franchi")

    def test_no_secret_in_any_evidence(self):
        m = self.measure()
        blob = " ".join(f.evidence + f.poc + f.title for f in m["findings"])
        self.assertNotIn(self.fake.token, blob)
        self.assertNotIn(BROWSER_UA, blob)


if __name__ == "__main__":
    unittest.main()

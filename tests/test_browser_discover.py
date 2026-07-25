"""LOT DÉCOUVERTE BACKED-BROWSER — `evasion.discover` (forge/modules/evasion.py).

Comble le trou « cible derrière WAF -> recon HTTP challengée -> 0 endpoint -> 0 oracle » : une voie
de découverte gouvernée qui, UNIQUEMENT pour une cible IN-SCOPE, pilote le browser-automation pour
franchir le challenge managé, PUIS extrait les endpoints du rendu (DOM/JS/XHR) et les émet avec le
MÊME DISCOVERY_ENDPOINT_MARKER que recon.js_endpoints — pour que la chaîne discovery->oracle tire.

Tout est HERMÉTIQUE : le client browser (`bc`) est MOCKÉ (swap de `evasion.bc`). Aucun réseau réel,
aucun service browser requis. Preuves :

  (1) SCOPE-GUARD — cible hors périmètre => skipped/refusé SANS AUCUN appel browser ;
  (2) PAGE CHALLENGÉE — endpoints extraits + émis avec le marqueur de découverte (in-scope SEULS,
      endpoints hors-scope écartés) ; le franchissement du challenge (vision-click-os) est tenté ;
  (3) DÉGRADATION — service browser indisponible => status='skipped' (offline-safe), aucune navigation ;
  (4) SESSION SECRÈTE — le matériel de session (en-têtes/cookies des requêtes capturées) n'apparaît
      JAMAIS dans un finding ;
  (5) CHAÎNAGE — les endpoints émis alimentent le cerveau -> oracles CIBLÉS proposés (edge e) ;
  (6) BORNÉ + registre/catalogue/CLI cohérents + injection du périmètre par l'engine.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action, Scope                          # noqa: E402
from forge.engine import Engine                              # noqa: E402
from forge.brain import HeuristicBrain                       # noqa: E402
from forge.graph import EngagementGraph                      # noqa: E402
from forge import modules as mods                            # noqa: E402
from forge import techniques                                 # noqa: E402
from forge import cli                                        # noqa: E402
from forge.modules import evasion as evasionmod              # noqa: E402
from forge.modules.evasion import EvasionDiscover            # noqa: E402

EP = techniques.DISCOVERY_ENDPOINT_MARKER

# --- rendu MOCKÉ : DOM (liens/forms) + routes JS + XHR/fetch capturés, mélange in-scope / hors-scope ---
HTML = (
    '<html><head><script src="/static/app.js"></script></head><body>'
    '<a href="/dashboard">dash</a>'                              # in-scope (relatif)
    '<a href="https://app.test/profile">profile</a>'            # in-scope (absolu)
    '<a href="https://evil.example.com/track">track</a>'        # HORS-scope -> écarté
    '<form action="/api/checkout" method="post"></form>'        # in-scope (form action)
    '<script>var u="/api/v1/users";'                            # route JS in-scope
    'fetch("https://app.test/graphql");'                        # URL JS in-scope
    'fetch("https://evil.example.com/collect");</script>'       # HORS-scope -> écarté
    '</body></html>'
)
# requêtes capturées — les en-têtes portent du matériel de SESSION SECRET qui ne doit JAMAIS fuiter.
SECRET_TOKEN = "SECRET-TOKEN-XYZ"
SECRET_COOKIE = "SECRET-COOKIE-123"
CAPTURED = [
    {"url": "https://app.test/api/orders", "method": "GET",
     "headers": {"Authorization": f"Bearer {SECRET_TOKEN}", "Cookie": f"sid={SECRET_COOKIE}"}},
    {"request": {"url": "https://app.test/api/cart"}},           # forme nichée {request:{url}}
    {"url": "https://evil.example.com/beacon"},                  # HORS-scope -> écarté
    "https://app.test/api/ping",                                # URL nue (str)
]


class _FakeBrowser:
    """Double mockable du client `browser_client` : enregistre les appels, réponses configurables.
    Swappe `evasion.bc` en entier (le module lit `bc.health/base_url/capture_*/goto/vision_click_os/
    content/DEFAULT_TAB`). raise_all=True prouve qu'AUCUN appel browser ne part (scope-guard)."""

    DEFAULT_TAB = "forge"

    def __init__(self, health=True, content=(200, ""), captured=(200, None), raise_all=False):
        self.calls = []
        self._health = health
        self._content = content
        self._captured = captured
        self._raise_all = raise_all

    def _rec(self, name, **kw):
        if self._raise_all:
            raise AssertionError(f"appel browser INTERDIT (scope-guard violé): {name}")
        self.calls.append(name)

    def names(self):
        return list(self.calls)

    # signatures alignées sur forge/browser_client.py
    def base_url(self):
        return "http://fake-browser:8080"

    def health(self, timeout=2):
        self._rec("health")
        return self._health

    def capture_start(self, types=None, tab="forge", timeout=30):
        self._rec("capture_start")
        return (200, {"ok": True})

    def goto(self, url, tab="forge", wait=5, timeout=45):
        self._rec("goto")
        return (200, {"ok": True})

    def vision_click_os(self, strategy="turnstile", threshold=0.55, tab="forge", timeout=60):
        self._rec("vision_click_os")
        return (200, {"clicked": True})

    def content(self, max_length=50000, tab="forge", timeout=30):
        self._rec("content")
        return self._content

    def capture_dump(self, url_contains=None, tab="forge", timeout=30):
        self._rec("capture_dump")
        return self._captured


class _Args:
    """Stand-in argparse.Namespace pour cli.cmd_modules (seul `json` est lu)."""
    def __init__(self, json=False):
        self.json = json


class _BrowserDiscoverBase(unittest.TestCase):
    def setUp(self):
        # le cache de santé est partagé (clé = base_url) : on le vide pour un état déterministe.
        evasionmod._EvasionBase._health_cache.clear()
        self.addCleanup(evasionmod._EvasionBase._health_cache.clear)

    def _fire(self, fake, params, target="app.test"):
        """Fire le module avec `evasion.bc` swappé par le fake (restauré ensuite)."""
        orig = evasionmod.bc
        evasionmod.bc = fake
        evasionmod._EvasionBase._health_cache.clear()
        try:
            return EvasionDiscover().fire(Action("evasion.discover", target, params=params))
        finally:
            evasionmod.bc = orig


# --- (0) registre / catalogue / CLI ---------------------------------------------------------------
class TestRegistrationAndCatalog(_BrowserDiscoverBase):
    def test_registered_with_expected_flags(self):
        self.assertIn("evasion.discover", mods.kinds())
        m = mods.get("evasion.discover")
        self.assertFalse(m.exploit, "découverte navigate/extract -> jamais exploit")
        self.assertFalse(m.destructive, "lecture seule -> jamais destructif")
        self.assertTrue(getattr(m, "web_allowed", False))

    def test_mitre_matches_table(self):
        # anti-drift : le mitre déclaré == la table unique techniques.py (source de vérité).
        self.assertEqual(mods.get("evasion.discover").mitre, techniques.mitre_for("evasion.discover"))
        self.assertEqual(mods.get("evasion.discover").mitre, "T1594")

    def test_cli_modules_json_lists_new_kind(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_modules(_Args(json=True))
        self.assertEqual(rc, 0)
        rows = json.loads(buf.getvalue())
        row = next((r for r in rows if r["kind"] == "evasion.discover"), None)
        self.assertIsNotNone(row, "evasion.discover absent de `modules --json`")
        self.assertFalse(row["exploit"])
        self.assertFalse(row["destructive"])
        self.assertTrue(row["web_allowed"])
        self.assertEqual(row["mitre"], "T1594")

    def test_dry_builds_call_without_network(self):
        fake = _FakeBrowser(raise_all=True)                     # dry ne doit émettre AUCUN appel
        orig = evasionmod.bc
        evasionmod.bc = fake
        try:
            s = EvasionDiscover().dry(Action("evasion.discover", "app.test"))
        finally:
            evasionmod.bc = orig
        self.assertIsInstance(s, str)
        self.assertIn("/goto", s)
        self.assertIn("/capture-dump", s)
        self.assertEqual(fake.names(), [])                     # dry = zéro effet de bord


# --- (1) SCOPE-GUARD : cible hors périmètre => skipped, AUCUN appel browser ------------------------
class TestScopeGuardFailClosed(_BrowserDiscoverBase):
    def test_out_of_scope_target_skipped_no_browser_call(self):
        fake = _FakeBrowser(raise_all=True)                    # tout appel browser lèverait
        f = self._fire(fake, {"in_scope": ["app.test"]}, target="evil.example.com")
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)
        self.assertEqual(fake.names(), [], "un appel browser est parti sur une cible hors-scope")

    def test_engine_vetoes_out_of_scope_before_fire(self):
        # défense en profondeur : module DISPONIBLE (santé forcée) -> la gate ROE de l'engine VÉTOe la
        # cible hors-scope AVANT fire() (aucune navigation browser). NB : si le service est indisponible,
        # la garde d'availability rendrait SKIP en amont — on force health=True pour tester la voie ROE.
        fake = _FakeBrowser(health=True)
        orig = evasionmod.bc
        evasionmod.bc = fake
        evasionmod._EvasionBase._health_cache.clear()
        try:
            eng = Engine(Scope({"in_scope": ["app.test"]}))
            eng.arm()
            a = Action("evasion.discover", "evil.example.com")
            eng.approve(a.id)
            res = eng.execute(a)
        finally:
            evasionmod.bc = orig
            evasionmod._EvasionBase._health_cache.clear()
        self.assertEqual(res["verdict"], "VETO")
        self.assertIsNone(res["output"])
        # la gate ROE refuse AVANT toute navigation : aucune requête browser (goto/content/dump).
        for forbidden in ("goto", "content", "capture_dump", "vision_click_os", "capture_start"):
            self.assertNotIn(forbidden, fake.names())


# --- (2) PAGE CHALLENGÉE : extraction + émission avec le marqueur, in-scope SEULS ------------------
class TestChallengedPageDiscovery(_BrowserDiscoverBase):
    def _findings(self):
        fake = _FakeBrowser(content=(200, HTML), captured=(200, CAPTURED))
        return fake, self._fire(fake, {"in_scope": ["app.test"]})

    def test_extracts_and_emits_discovery_marker_in_scope_only(self):
        fake, f = self._findings()
        marker_findings = [x for x in f if EP in x.title]
        self.assertTrue(marker_findings, "aucun endpoint émis avec le marqueur de découverte")
        targets = {x.target for x in marker_findings}
        # sources multiples : DOM (liens/forms) + routes JS + XHR/fetch capturés — tous in-scope.
        for want in ("https://app.test/dashboard",           # DOM <a> relatif
                     "https://app.test/profile",             # DOM <a> absolu
                     "https://app.test/api/checkout",        # DOM <form action>
                     "https://app.test/api/v1/users",        # route JS
                     "https://app.test/graphql",             # URL JS
                     "https://app.test/api/orders",          # XHR capturé (dict.url)
                     "https://app.test/api/cart",            # XHR capturé (request.url)
                     "https://app.test/api/ping"):           # XHR capturé (str nue)
            self.assertIn(want, targets, f"endpoint in-scope manquant: {want}")
        # AUCUN endpoint hors-scope n'est émis (verrou fail-closed au niveau du module).
        for x in marker_findings:
            self.assertNotIn("evil.example.com", x.target)
        # chaque finding par-endpoint porte bien le marqueur EXACT partagé avec le cerveau.
        for x in marker_findings:
            self.assertTrue(x.title.startswith(EP))
            self.assertEqual(x.status, "tested")

    def test_challenge_pass_attempted_and_capture_before_goto(self):
        fake, f = self._findings()
        names = fake.names()
        self.assertIn("vision_click_os", names, "le franchissement du challenge n'a pas été tenté")
        self.assertIn("goto", names)
        self.assertIn("capture_dump", names)
        # capture armée AVANT la navigation (sinon le trafic de la page n'est pas observé).
        self.assertLess(names.index("capture_start"), names.index("goto"))

    def test_summary_finding_does_not_carry_marker(self):
        # le finding de synthèse (target=page) ne doit PAS être pris pour un endpoint à chaîner.
        fake, f = self._findings()
        summary = f[0]
        self.assertEqual(summary.target, "app.test")
        self.assertNotIn(EP, summary.title)
        self.assertIn("endpoint(s) in-scope", summary.title)

    def test_no_in_scope_endpoint_returns_tested_not_skipped(self):
        # page rendue mais uniquement des endpoints hors-scope -> finding 'tested' explicite (pas skipped).
        html = '<html><body><a href="https://evil.example.com/x">x</a></body></html>'
        fake = _FakeBrowser(content=(200, html), captured=(200, []))
        f = self._fire(fake, {"in_scope": ["app.test"]})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucun endpoint in-scope", f[0].title)


# --- (3) DÉGRADATION GRACIEUSE : service browser indisponible => skipped ---------------------------
class TestGracefulDegradation(_BrowserDiscoverBase):
    def test_service_down_is_skipped_no_navigation(self):
        fake = _FakeBrowser(health=False)                      # /health répond faux
        f = self._fire(fake, {"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("indisponible", f[0].title)
        # aucune navigation/extraction n'a été tentée (seule la sonde de santé est permise).
        for forbidden in ("goto", "content", "capture_dump", "vision_click_os", "capture_start"):
            self.assertNotIn(forbidden, fake.names(), f"{forbidden} appelé alors que le service est down")

    def test_empty_render_is_skipped(self):
        # service up mais rendu vide + aucune requête capturée -> skipped (challenge non franchi).
        fake = _FakeBrowser(content=(200, ""), captured=(200, []))
        f = self._fire(fake, {"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("rendu vide", f[0].title)

    def test_module_available_reflects_service_health(self):
        # `available` (property _EvasionBase) reflète la santé du service (engine SKIP si down).
        for health, expected in ((True, True), (False, False)):
            evasionmod._EvasionBase._health_cache.clear()
            orig = evasionmod.bc
            evasionmod.bc = _FakeBrowser(health=health)
            try:
                self.assertEqual(EvasionDiscover().available, expected)
            finally:
                evasionmod.bc = orig


# --- (4) SESSION SECRÈTE : le matériel de session n'apparaît JAMAIS dans un finding ----------------
class TestSessionSecrecy(_BrowserDiscoverBase):
    def test_session_material_never_leaks_into_findings(self):
        fake = _FakeBrowser(content=(200, HTML), captured=(200, CAPTURED))
        f = self._fire(fake, {"in_scope": ["app.test"]})
        blob = json.dumps([x.to_dict() for x in f])
        # les requêtes capturées portaient un bearer + un cookie de session -> jamais dans un finding.
        self.assertNotIn(SECRET_TOKEN, blob, "un jeton de session a fuité dans un finding")
        self.assertNotIn(SECRET_COOKIE, blob, "un cookie de session a fuité dans un finding")
        self.assertNotIn("Authorization", blob)
        self.assertNotIn("Cookie", blob)
        # l'URL de l'endpoint (elle) est bien émise (on extrait l'URL, pas les en-têtes).
        self.assertIn("https://app.test/api/orders", blob)


# --- (5) CHAÎNAGE : les endpoints émis alimentent le cerveau -> oracles CIBLÉS ---------------------
class TestFeedsOracleChain(_BrowserDiscoverBase):
    def test_emitted_endpoints_feed_oracle_chain(self):
        fake = _FakeBrowser(content=(200, HTML), captured=(200, CAPTURED))
        f = self._fire(fake, {"in_scope": ["app.test"]})
        marker_findings = [x for x in f if EP in x.title]
        self.assertTrue(marker_findings)
        # injecte les findings de découverte au graphe puis laisse le cerveau proposer (edge e).
        g = EngagementGraph()
        g.add_host("app.test", kind="app")
        for x in marker_findings:
            g.add_finding(x)
        ep = next(x.target for x in marker_findings if x.target == "https://app.test/api/v1/users")
        onep = {a.kind for a in HeuristicBrain().propose(g) if a.target == ep}
        # oracles CIBLÉS sur l'endpoint découvert (IDOR/access-control, SQLi, XSS reflected).
        self.assertIn("access_control.idor", onep)
        self.assertIn("sqli.probe", onep)
        self.assertIn("xss.reflected", onep)

    def test_proposed_for_protected_target_not_unprotected(self):
        # le cerveau propose evasion.discover sur une cible PROTÉGÉE (WAF), pas sur une cible ordinaire.
        gp = EngagementGraph(); gp.add_host("app.test", kind="app", protected=True)
        self.assertIn("evasion.discover", {a.kind for a in HeuristicBrain().propose(gp)})
        gu = EngagementGraph(); gu.add_host("app.test", kind="app")
        self.assertNotIn("evasion.discover", {a.kind for a in HeuristicBrain().propose(gu)})


# --- (6) BORNÉ + injection du périmètre par l'engine ----------------------------------------------
class TestBoundedAndPerimeterInjection(_BrowserDiscoverBase):
    def test_endpoint_fanout_capped(self):
        # 60 endpoints in-scope -> le nombre de findings par-endpoint émis est plafonné (MAX_ENDPOINTS).
        captured = [{"url": f"https://app.test/api/item{i}"} for i in range(60)]
        fake = _FakeBrowser(content=(200, "<html></html>"), captured=(200, captured))
        f = self._fire(fake, {"in_scope": ["app.test"]})
        marker_findings = [x for x in f if EP in x.title]
        self.assertLessEqual(len(marker_findings), EvasionDiscover.MAX_ENDPOINTS)
        self.assertTrue(marker_findings)

    def test_engine_injects_perimeter_into_params(self):
        # l'engine injecte in_scope/out_scope pour que le module RE-VALIDE fail-closed les endpoints.
        eng = Engine(Scope({"in_scope": ["app.test"], "out_scope": ["dev.app.test"]}))
        prepared = eng._prepare([Action("evasion.discover", "app.test")], None, {}, {})
        self.assertEqual(prepared[0].params.get("in_scope"), ["app.test"])
        self.assertEqual(prepared[0].params.get("out_scope"), ["dev.app.test"])

    def test_out_scope_endpoint_dropped_even_if_in_scope_root(self):
        # un endpoint sur un sous-domaine EXCLU (out_scope) est écarté malgré la racine in-scope.
        html = ('<html><body><a href="https://app.test/ok">ok</a>'
                '<a href="https://dev.app.test/secret">no</a></body></html>')
        fake = _FakeBrowser(content=(200, html), captured=(200, []))
        f = self._fire(fake, {"in_scope": ["app.test", "*.app.test"], "out_scope": ["dev.app.test"]})
        targets = {x.target for x in f if EP in x.title}
        self.assertIn("https://app.test/ok", targets)
        self.assertNotIn("https://dev.app.test/secret", targets)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""LOT PONT CHALLENGE -> DÉCOUVERTE BACKED-BROWSER — le trou « WAF -> 0 endpoint -> 0 oracle » comblé.

Quand la recon plain-HTTP d'un host IN-SCOPE est CHALLENGÉE par un WAF/challenge managé (Cloudflare
« Just a moment », 403 en nappe…), elle ne découvre AUCUN endpoint et la chaîne discovery->oracle
propose 0 oracle. Ce lot prouve le PONT qui répare ça :

  1. les émetteurs de découverte HTTP (recon.js_endpoints / recon.content) SIGNALENT le blocage via le
     marqueur partagé techniques.DISCOVERY_CHALLENGE_MARKER (0 endpoint + signature de challenge/403) ;
  2. le cerveau (edge f) détecte ce marqueur et AUTO-PROPOSE la SEULE `evasion.discover` (voie
     backed-browser) sur ce host in-scope — EXACTEMENT une, dédupliquée entre les edges ;
  3. les endpoints découverts par le browser (DISCOVERY_ENDPOINT_MARKER) ré-alimentent la chaîne
     discovery->oracle EXISTANTE (edge e) -> les oracles reçoivent enfin des cibles in-scope ;
  4. GARANTIES : scope-locked (un endpoint hors périmètre n'est PAS poursuivi), BORNÉ (aucune boucle
     evasion->evasion : la sortie d'evasion.discover ne re-déclenche jamais evasion.discover), et le
     PLANCHER des classes qualifiantes tient même à budget nul.

Tout est HERMÉTIQUE : modules stubés au registre, `_http_get`/ffuf mockés au seam — ZÉRO I/O réel.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action, Scope, FIRE, VETO             # noqa: E402
from forge.engine import Engine                             # noqa: E402
from forge.brain import HeuristicBrain                      # noqa: E402
from forge.planner import Planner                           # noqa: E402
from forge.graph import EngagementGraph                     # noqa: E402
from forge.schema import Target, Finding                    # noqa: E402
from forge import techniques                                # noqa: E402
from forge.modules import registry                          # noqa: E402
from forge.modules.recon_surface import JsEndpoints         # noqa: E402
from forge.modules.recon_active import ContentDiscovery     # noqa: E402

CH = techniques.DISCOVERY_CHALLENGE_MARKER                  # marqueur « recon HTTP challengée »
EP = techniques.DISCOVERY_ENDPOINT_MARKER                   # marqueur endpoint découvert (-> oracles)


# --- fabriques de findings (comme émis par les modules réels) -------------------------------------
def _challenge_finding(host="app.test", emitter="recon.js_endpoints"):
    """Finding tel qu'émis par recon.js_endpoints / recon.content quand la recon plain-HTTP est
    challengée (0 endpoint + signature) : titre porteur du marqueur de challenge, target = le host."""
    return Finding(target=host, title=f"{emitter} — {CH}", severity="INFO",
                   category="recon", status="tested")


def _endpoint_finding(url, host_hint=None):
    """Finding par-endpoint (comme émis par evasion.discover / recon.js_endpoints) : marqueur
    DISCOVERY_ENDPOINT_MARKER, target = l'URL de l'endpoint découvert (chaîné vers les oracles)."""
    return Finding(target=url, title=f"{EP} : {url}", severity="INFO", category="recon", status="tested")


def _waf_finding(host="app.test"):
    return Finding(target=host, title="WAF/CDN identifié : Cloudflare", severity="INFO",
                   category="recon", status="tested")


# --- infra de stubs hermétique (self-contained — n'importe RIEN d'un autre module de test) ---------
def _patch(cls, name, fn):
    """Remplace cls.<name> par une staticmethod, restaure (delattr si l'attribut était HÉRITÉ)."""
    had = name in cls.__dict__
    orig = cls.__dict__.get(name)
    setattr(cls, name, staticmethod(fn))

    def restore():
        if had:
            setattr(cls, name, orig)
        else:
            delattr(cls, name)
    return restore


# tous les kinds que le cerveau peut proposer sur un host web challengé + endpoints — stubés à []
# (aucun réseau) ; on surcharge les quelques kinds pertinents par test. INCLUT evasion.discover /
# recon.content pour que le VRAI module (browser/ffuf) ne parte jamais.
ALL_KINDS = (
    "recon.httpx", "web.nuclei", "access_control.idor", "ssrf.callback", "auth.takeover",
    "cors.credentials", "origin.find", "recon.nmap", "recon.subdomains", "recon.js_endpoints",
    "recon.urls", "recon.tech", "recon.waf", "recon.content", "sqli.probe", "xss.reflected",
    "evasion.xhr", "evasion.turnstile", "evasion.discover",
)


class _StubModule(registry.Module):
    """fire() renvoie des Finding fixés (liste OU callable(action)->list). Zéro I/O. Disponible."""
    exploit = False
    web_allowed = True
    mitre = "T9999"
    _findings = []

    def dry(self, action):
        return f"# stub dry {self.kind} {action.target}"

    def fire(self, action):
        f = self._findings
        return list(f(action)) if callable(f) else list(f)


class _swap_registry:
    """Remplace des kinds du REGISTRY par des stubs, restaure à la sortie."""
    def __init__(self, mapping):
        self.mapping = mapping
        self._saved = {}

    def __enter__(self):
        for kind, findings in self.mapping.items():
            self._saved[kind] = registry.REGISTRY.get(kind)
            attr = staticmethod(findings) if callable(findings) else findings
            cls = type(f"Stub_{kind.replace('.', '_')}", (_StubModule,),
                       {"kind": kind, "_findings": attr})
            registry.REGISTRY[kind] = cls
        return self

    def __exit__(self, *exc):
        for kind, prev in self._saved.items():
            if prev is None:
                registry.REGISTRY.pop(kind, None)
            else:
                registry.REGISTRY[kind] = prev
        return False


def _stubs(**override):
    m = {k: [] for k in ALL_KINDS}
    m.update(override)
    return m


def _scope(in_scope=("app.test",), out_scope=(), exploit=True, **extra):
    d = {"mode": "grey", "in_scope": list(in_scope), "out_scope": list(out_scope),
         "allow_exploit": exploit}
    d.update(extra)
    return Scope(d)


def _armed_auto(sc, **kw):
    eng = Engine(sc, mode="auto", **kw)
    eng.arm("test")
    return eng


# =================================================================================================
# (A) BRAIN edge (f) — un host CHALLENGE-GATÉ auto-propose EXACTEMENT une evasion.discover
# =================================================================================================
class TestChallengeGatedProposal(unittest.TestCase):
    def test_challenge_gated_host_triggers_exactly_one_evasion_discover(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        g.add_finding(_challenge_finding("app.test"))          # recon plain-HTTP challengée (0 endpoint)
        actions = HeuristicBrain().propose(g)
        discover = [a for a in actions if a.kind == "evasion.discover"]
        self.assertEqual(len(discover), 1, "un host challengé doit auto-proposer UNE evasion.discover")
        self.assertEqual(discover[0].target, "app.test")
        # edge (f) ne force QUE la découverte : pas les autres enablers d'évasion (réservés au host
        # explicitement PROTÉGÉ). Le host n'est pas marqué protégé -> ni xhr ni turnstile.
        kinds = {a.kind for a in actions}
        self.assertNotIn("evasion.xhr", kinds)
        self.assertNotIn("evasion.turnstile", kinds)

    def test_unchallenged_host_gets_no_evasion_discover(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")                     # aucun finding de challenge
        self.assertNotIn("evasion.discover", {a.kind for a in HeuristicBrain().propose(g)})

    def test_recon_content_challenge_marker_also_triggers_discover(self):
        # le marqueur émis par recon.content (challenge en nappe ffuf) déclenche le MÊME edge (f).
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        g.add_finding(_challenge_finding("app.test", emitter="recon.content"))
        discover = [a for a in HeuristicBrain().propose(g) if a.kind == "evasion.discover"]
        self.assertEqual(len(discover), 1)
        self.assertEqual(discover[0].target, "app.test")

    def test_protected_waf_and_challenge_dedup_to_single_discover(self):
        # host protégé (base) + WAF identifié (edge c) + challenge (edge f) proposent tous
        # evasion.discover:app.test -> l'id stable dédup -> EXACTEMENT une dans le plan.
        g = EngagementGraph()
        g.add_host("app.test", kind="app", protected=True)
        g.add_finding(_waf_finding("app.test"))
        g.add_finding(_challenge_finding("app.test"))
        discover = [a for a in HeuristicBrain().propose(g) if a.kind == "evasion.discover"]
        self.assertEqual(len(discover), 1, "les edges multiples ne doivent PAS dupliquer evasion.discover")

    def test_challenge_marker_not_treated_as_derived_discovery(self):
        # le marqueur de CHALLENGE marque un host CHALLENGE-GATÉ (cible primaire), PAS une cible
        # DÉCOUVERTE -> _discovery_marker l'ignore (il ne doit pas tomber dans le fan-out bound).
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        g.add_finding(_challenge_finding("app.test"))
        self.assertEqual(HeuristicBrain()._discovery_marker(g, "app.test"), "")

    def test_challenge_edge_not_fired_on_endpoint_url(self):
        # garde _is_endpoint : même si un marqueur de challenge apparaissait sur une URL à chemin,
        # evasion.discover n'est PAS proposé dessus (ce serait absurde de « découvrir » une URL).
        g = EngagementGraph()
        ep = "https://app.test/api/v1/users"
        g.add_host("app.test", kind="url")
        g.add_finding(Finding(target=ep, title=f"recon.js_endpoints — {CH}", severity="INFO",
                              category="recon", status="tested"))
        self.assertFalse(any(a.kind == "evasion.discover" and a.target == ep
                             for a in HeuristicBrain().propose(g)))


# =================================================================================================
# (B) CHAÎNAGE — les endpoints découverts par le browser alimentent les oracles CIBLÉS (edge e)
# =================================================================================================
class TestDiscoveredEndpointsChainToOracles(unittest.TestCase):
    def test_browser_discovered_endpoint_chains_targeted_oracles(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        ep = "https://app.test/api/v1/users?id=5"
        g.add_finding(_endpoint_finding(ep))                   # émis par evasion.discover
        onep = {a.kind for a in HeuristicBrain().propose(g) if a.target == ep}
        self.assertIn("access_control.idor", onep)
        self.assertIn("sqli.probe", onep)
        self.assertIn("xss.reflected", onep)
        # l'endpoint découvert n'est PAS re-semé de découverte ni ne re-déclenche evasion.discover.
        self.assertNotIn("evasion.discover", onep)
        self.assertNotIn("recon.js_endpoints", onep)


# =================================================================================================
# (C) ÉMISSION — recon.js_endpoints / recon.content posent le marqueur de challenge (0 endpoint + sig)
# =================================================================================================
class TestReconEmitsChallengeMarker(unittest.TestCase):
    def _js_fire(self, http_ret, params=None):
        r = _patch(JsEndpoints, "_http_get",
                   lambda url, headers=None, timeout=20, maxlen=500000: http_ret)
        try:
            return JsEndpoints().fire(Action("recon.js_endpoints", "app.test",
                                             params=params or {"in_scope": ["app.test"]}))
        finally:
            r()

    def test_js_403_empty_body_emits_challenge_marker(self):
        f = self._js_fire((403, "", {}))
        self.assertEqual(len(f), 1)
        self.assertIn(CH, f[0].title)
        self.assertEqual(f[0].status, "tested")

    def test_js_interstitial_body_emits_challenge_marker(self):
        # 200 mais interstitiel Cloudflare « Just a moment » + 0 endpoint -> signature de challenge.
        html = "<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>"
        f = self._js_fire((200, html, {}))
        self.assertIn(CH, f[0].title)

    def test_js_benign_empty_page_is_not_a_challenge(self):
        # page joignable, 0 endpoint, AUCUNE signature -> « aucun endpoint extrait », PAS le marqueur.
        f = self._js_fire((200, "<html><body>hello world</body></html>", {}))
        self.assertNotIn(CH, f[0].title)
        self.assertIn("aucun endpoint extrait", f[0].title)

    def test_js_challenge_status_but_endpoints_found_is_not_flagged(self):
        # 403 MAIS des endpoints ont quand même été extraits -> découverte réussie, PAS de marqueur
        # (le marqueur exige 0 endpoint : « returned 0 endpoints while a challenge was observed »).
        html = '<html><body><script>var u="/api/v1/users";</script></body></html>'
        f = self._js_fire((403, html, {}))
        self.assertFalse(any(CH in x.title for x in f), "marqueur émis alors que des endpoints existent")
        self.assertTrue(any(EP in x.title for x in f), "les endpoints extraits doivent être émis")

    def _content_fire(self, ffuf_out, rc=0, params=None):
        r_av = _patch(ContentDiscovery, "_tool_available", lambda: True)
        r_run = _patch(ContentDiscovery, "_run_ffuf",
                       lambda url, wordlist, rate, threads, timeout: (rc, ffuf_out, ""))
        try:
            return ContentDiscovery().fire(Action("recon.content", "app.test",
                                                  params=params or {"in_scope": ["app.test"]}))
        finally:
            r_run(); r_av()

    def test_content_blanket_403_emits_challenge_marker(self):
        import json
        out = json.dumps({"results": [
            {"input": {"FUZZ": "admin"}, "url": "https://app.test/admin", "status": 403, "length": 12},
            {"input": {"FUZZ": "login"}, "url": "https://app.test/login", "status": 403, "length": 12},
            {"input": {"FUZZ": "api"}, "url": "https://app.test/api", "status": 429, "length": 12},
        ]})
        f = self._content_fire(out)
        self.assertEqual(len(f), 1)
        self.assertIn(CH, f[0].title)
        self.assertEqual(f[0].status, "tested")

    def test_content_mixed_statuses_is_normal_discovery_not_challenge(self):
        import json
        out = json.dumps({"results": [
            {"input": {"FUZZ": "admin"}, "url": "https://app.test/admin", "status": 200, "length": 99},
            {"input": {"FUZZ": "login"}, "url": "https://app.test/login", "status": 403, "length": 12},
            {"input": {"FUZZ": "api"}, "url": "https://app.test/api", "status": 302, "length": 0},
        ]})
        f = self._content_fire(out)
        self.assertFalse(any(CH in x.title for x in f), "un mélange de statuts n'est PAS un challenge")
        self.assertIn("Routes découvertes", f[0].title)

    def test_content_isolated_403_below_threshold_is_not_challenge(self):
        # une route protégée isolée (1 x 403) reste une découverte légitime (< seuil de nappe).
        import json
        out = json.dumps({"results": [
            {"input": {"FUZZ": "admin"}, "url": "https://app.test/admin", "status": 403, "length": 12},
        ]})
        f = self._content_fire(out)
        self.assertFalse(any(CH in x.title for x in f))


# =================================================================================================
# (D) INTÉGRATION MULTI-VAGUE — pont complet, bornage anti-boucle, scope-lock
# =================================================================================================
class TestChallengeToDiscoveryCampaign(unittest.TestCase):
    EP1 = "https://app.test/api/v1/users"
    EP2 = "https://app.test/dashboard"

    def _run(self, discover_fn, in_scope=("app.test",), out_scope=(), max_waves=6):
        def js(action):
            return [_challenge_finding("app.test")] if action.target == "app.test" else []
        with _swap_registry(_stubs(**{"recon.js_endpoints": js, "evasion.discover": discover_fn})):
            eng = _armed_auto(_scope(in_scope=in_scope, out_scope=out_scope))
            eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), max_waves=max_waves)
        return eng

    def test_challenge_leads_to_browser_discovery_then_oracles(self):
        def discover(action):
            # evasion.discover franchit le challenge et émet des endpoints in-scope (marqueur EP).
            return [_endpoint_finding(self.EP1), _endpoint_finding(self.EP2)] if action.target == "app.test" else []
        eng = self._run(discover)
        # evasion.discover a TIRÉ (le browser a été piloté sur le host challengé)
        disc_res = [r for r in eng.results if r["kind"] == "evasion.discover"]
        self.assertTrue(disc_res, "evasion.discover n'a jamais tiré sur le host challengé")
        self.assertTrue(any(r["verdict"] == FIRE for r in disc_res))
        # les endpoints backed-browser ont bien chaîné les oracles CIBLÉS (edge e) sur chaque endpoint
        for ep in (self.EP1, self.EP2):
            ep_kinds = {r["kind"] for r in eng.results if r["target"] == ep}
            self.assertIn("access_control.idor", ep_kinds, ep)
            self.assertIn("sqli.probe", ep_kinds, ep)
            self.assertIn("xss.reflected", ep_kinds, ep)
            # la sonde SQLi (non-exploit) a réellement tiré sur l'endpoint découvert
            self.assertTrue(any(r["kind"] == "sqli.probe" and r["target"] == ep and r["verdict"] == FIRE
                                for r in eng.results))

    def test_no_evasion_to_evasion_loop_discover_fires_exactly_once(self):
        def discover(action):
            return [_endpoint_finding(self.EP1)] if action.target == "app.test" else []
        eng = self._run(discover)
        disc_res = [r for r in eng.results if r["kind"] == "evasion.discover"]
        # BORNÉ : evasion.discover tire EXACTEMENT une fois (id stable + dédup inter-vagues) — jamais
        # de boucle. Et JAMAIS sur un endpoint découvert (sa sortie ne re-déclenche pas la découverte).
        self.assertEqual(len(disc_res), 1, "evasion.discover a bouclé (evasion->evasion)")
        self.assertEqual(disc_res[0]["target"], "app.test")
        self.assertFalse(any(r["kind"] == "evasion.discover" and r["target"] != "app.test"
                             for r in eng.results))
        self.assertLessEqual(eng.waves, 6)                     # la campagne s'arrête (point fixe/borne)

    def test_out_of_scope_discovered_endpoint_is_not_pursued(self):
        evil = "https://evil.example.com/api/orders"

        def discover(action):
            # DÉFENSE EN PROFONDEUR : un module fautif émet un endpoint HORS-scope dans le graphe.
            return [_endpoint_finding(evil)] if action.target == "app.test" else []
        eng = self._run(discover, in_scope=("app.test",))
        evil_res = [r for r in eng.results if r["target"] == evil]
        self.assertTrue(evil_res, "les oracles chaînés hors-scope doivent être évalués puis vétoés")
        self.assertTrue(all(r["verdict"] == VETO for r in evil_res), "un endpoint hors-scope a été poursuivi")
        self.assertFalse(any(r["verdict"] == FIRE for r in evil_res))


# =================================================================================================
# (E) COVERAGE-SAFE — le plancher qualifiant tient sur les endpoints challenge-dérivés, budget nul
# =================================================================================================
class TestQualifyingFloorHoldsOnChallengeChain(unittest.TestCase):
    def test_challenge_derived_endpoint_oracles_never_starved(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        g.add_finding(_challenge_finding("app.test"))          # host challengé
        ep = "https://app.test/api/users?id=5"
        g.add_finding(_endpoint_finding(ep))                   # endpoint backed-browser -> oracles
        actions = HeuristicBrain().propose(g)
        ordered, skipped = Planner(budget=0.0).order(actions)
        ordered_ids = {(a.kind, a.target) for a in ordered}
        skipped_kinds = {a.kind for a in skipped}
        # IDOR (access_control) + SQLi (sqli) chaînés sur l'endpoint challenge-dérivé = QUALIFIANTS ->
        # jamais déférés même à budget nul (plancher anti-starvation).
        self.assertIn(("access_control.idor", ep), ordered_ids)
        self.assertIn(("sqli.probe", ep), ordered_ids)
        self.assertNotIn("access_control.idor", skipped_kinds)
        self.assertNotIn("sqli.probe", skipped_kinds)
        # sanity : le budget nul MORD (des non-qualifiantes SONT déférées, defer != delete).
        self.assertTrue(skipped, "budget=0 aurait dû déférer des actions non-qualifiantes")


if __name__ == "__main__":
    unittest.main(verbosity=2)

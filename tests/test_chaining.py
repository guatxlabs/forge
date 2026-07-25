"""LOT CHAÎNAGE discovery -> verification — la campagne S'AUTO-ALIMENTE, scope-locked et bornée.

Preuves (toutes HERMÉTIQUES — modules stubés / réseau mocké au seam, ZÉRO I/O réel) :

  (A) BRAIN — les edges de chaînage produisent la BONNE action de suivi :
      - sous-domaine découvert (recon.subdomains)  -> recon.tech + recon.waf + oracles web sur le NOUVEL
        hôte in-scope (edge d + actions de base sur le nœud découvert) ;
      - endpoint découvert (recon.js_endpoints / recon.urls) -> oracles CIBLÉS (IDOR/SQLi/XSS) sur
        l'endpoint (edge e), avec le paramètre de query porté aux sondes d'injection ; PAS de recon/
        origin/nmap semés sur une URL (edge exclusif).
  (B) ENGINE — chaîne MULTI-HOP réelle sur une campagne : vague 1 découvre, vague 2 vérifie, gatée par
      le ROE à CHAQUE vague (rien ne tire sans FIRE).
  (C) SCOPE-LOCKED — un hôte/endpoint découvert HORS PÉRIMÈTRE n'est JAMAIS poursuivi : le module ne
      l'émet pas, et même injecté de force dans le graphe (défense en profondeur) la gate ROE le VÉTOe.
  (D) BORNÉ — fan-out plafonné (MAX_CHAIN_TARGETS) et profondeur bornée (pas de re-semis de découverte
      sur un hôte déjà découvert ; engine.max_waves).
  (E) COVERAGE-SAFE — le plancher des classes qualifiantes tient : IDOR/SQLi chaînés sur une cible
      découverte ne sont JAMAIS affamés, même à budget nul.
  (F) SESSION GOUVERNÉE portée À TRAVERS LA CHAÎNE — un hôte/endpoint dérivé in-scope HÉRITE la session
      par-hôte de sa source (scope-guardé) ; le matériel reste SECRET (jamais dans finding/graphe/
      résultats) ; un hôte dérivé HORS-SCOPE n'hérite RIEN (aucune fuite).
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action, FIRE, VETO            # noqa: E402
from forge.engine import Engine                            # noqa: E402
from forge.brain import HeuristicBrain                     # noqa: E402
from forge.planner import Planner                          # noqa: E402
from forge.graph import EngagementGraph                    # noqa: E402
from forge.schema import Target, Finding                   # noqa: E402
from forge.session import SessionStore                     # noqa: E402
from forge import techniques                               # noqa: E402
from forge.modules import registry                         # noqa: E402
from forge.modules.recon_surface import JsEndpoints, HistoricalUrls  # noqa: E402

SUB = techniques.DISCOVERY_SUBDOMAIN_MARKER
EP = techniques.DISCOVERY_ENDPOINT_MARKER
HU = techniques.DISCOVERY_HISTORICAL_URL_MARKER

# Tous les kinds que le cerveau peut proposer — stubés à [] par défaut (aucun réseau) ; on surcharge
# les quelques kinds pertinents par test.
ALL_KINDS = (
    "recon.httpx", "web.nuclei", "access_control.idor", "ssrf.callback", "auth.takeover",
    "cors.credentials", "origin.find", "recon.nmap", "recon.subdomains", "recon.js_endpoints",
    "recon.urls", "recon.tech", "recon.waf", "sqli.probe", "xss.reflected",
    "evasion.xhr", "evasion.turnstile",
)


def _disc(target, marker):
    """Finding de découverte (comme émis par recon_surface) : titre porteur du marqueur, target = la
    cible découverte, informatif (status tested / INFO)."""
    return Finding(target=target, title=f"{marker} : {target}", severity="INFO",
                   category="recon", status="tested")


def scope(in_scope=("app.test",), out_scope=(), exploit=True, **extra):
    d = {"mode": "grey", "in_scope": list(in_scope), "out_scope": list(out_scope),
         "allow_exploit": exploit}
    d.update(extra)
    return Scope(d)


class _StubModule(registry.Module):
    """fire() renvoie des Finding fixés (liste OU callable(action)->list). Zéro I/O."""
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
    """Dict stubant TOUS les kinds à [] (aucun réseau), surchargé par `override`."""
    m = {k: [] for k in ALL_KINDS}
    m.update(override)
    return m


def _armed_auto(sc, **kw):
    eng = Engine(sc, mode="auto", **kw)
    eng.arm("test")
    return eng


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


# =================================================================================================
# (A) BRAIN — les edges de chaînage produisent la BONNE action de suivi
# =================================================================================================
class TestBrainChainingEdges(unittest.TestCase):
    def test_discovered_subdomain_chains_fingerprint_and_web_oracles(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        g.add_finding(_disc("api.app.test", SUB))            # sous-domaine découvert par recon.subdomains
        kinds = {a.kind for a in HeuristicBrain().propose(g) if a.target == "api.app.test"}
        # edge (d) : fingerprint techno + WAF chaînés sur le nouvel hôte
        self.assertIn("recon.tech", kinds)
        self.assertIn("recon.waf", kinds)
        # oracles web (le nœud découvert reçoit les actions de base) — dont les qualifiants
        self.assertIn("access_control.idor", kinds)
        self.assertIn("ssrf.callback", kinds)

    def test_discovered_endpoint_chains_targeted_oracles_with_query_param(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        ep = "https://app.test/api/v1/users?id=5"
        g.add_finding(_disc(ep, EP))                         # endpoint découvert (recon.js_endpoints)
        actions = HeuristicBrain().propose(g)
        onep = {a.kind for a in actions if a.target == ep}
        # edge (e) : oracles CIBLÉS sur l'endpoint (IDOR/access-control, SQLi, XSS reflected)
        self.assertIn("access_control.idor", onep)
        self.assertIn("sqli.probe", onep)
        self.assertIn("xss.reflected", onep)
        # edge EXCLUSIF : un endpoint (URL à chemin) n'est PAS semé de recon/origin/nmap (ce serait
        # absurde de lancer subfinder/nmap sur une URL) — seul le chaînage d'oracles s'applique.
        for noise in ("origin.find", "recon.httpx", "recon.subdomains", "recon.nmap", "web.nuclei"):
            self.assertNotIn(noise, onep, noise)
        # le paramètre de query est porté aux sondes d'injection (sonde RÉELLE au lieu de dégrader)
        sqli = next(a for a in actions if a.kind == "sqli.probe" and a.target == ep)
        xss = next(a for a in actions if a.kind == "xss.reflected" and a.target == ep)
        self.assertEqual(sqli.params.get("param"), "id")
        self.assertEqual(xss.params.get("param"), "id")
        # l'IDOR chaîné cible bien l'endpoint (urls=[endpoint])
        idor = next(a for a in actions if a.kind == "access_control.idor" and a.target == ep)
        self.assertEqual(idor.params.get("urls"), [ep])

    def test_historical_url_also_chains_oracles(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        ep = "https://app.test/legacy/download"
        g.add_finding(_disc(ep, HU))                         # URL historique découverte (recon.urls)
        onep = {a.kind for a in HeuristicBrain().propose(g) if a.target == ep}
        self.assertTrue({"access_control.idor", "sqli.probe", "xss.reflected"} <= onep)

    def test_endpoint_without_query_param_degrades_not_crashes(self):
        # pas de query -> les sondes d'injection sont proposées SANS param (elles dégraderont en
        # `tested` côté module — jamais de crash ni de faux positif).
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        ep = "https://app.test/api/orders"
        g.add_finding(_disc(ep, EP))
        sqli = [a for a in HeuristicBrain().propose(g) if a.kind == "sqli.probe" and a.target == ep]
        self.assertEqual(len(sqli), 1)
        self.assertNotIn("param", sqli[0].params)


# =================================================================================================
# (B) ENGINE — chaîne MULTI-HOP réelle sur une campagne, gatée par le ROE à chaque vague
# =================================================================================================
class TestMultiHopCampaign(unittest.TestCase):
    def test_subdomain_discovery_feeds_verification_next_wave(self):
        sub = "api.app.test"

        def subs(action):
            return [_disc(sub, SUB)] if action.target == "app.test" else []
        # recon.tech ne « répond » que sur le sous-domaine chaîné -> un finding recon.tech sur `sub`
        # PROUVE que la 2e vague a réellement tiré la vérification sur l'hôte découvert.
        def tech(action):
            if action.target == sub:
                return [Finding(target=sub, title="tech: fingerprint sur sous-domaine",
                                severity="INFO", category="recon", status="tested")]
            return []
        with _swap_registry(_stubs(**{"recon.subdomains": subs, "recon.tech": tech})):
            eng = _armed_auto(scope(in_scope=("app.test", sub)))
            eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), max_waves=4)
        self.assertGreaterEqual(eng.waves, 2)                # au moins découverte + vérification
        sub_res = [r for r in eng.results if r["target"] == sub]
        self.assertTrue(sub_res, "aucune vérification chaînée sur le sous-domaine découvert")
        kinds = {r["kind"] for r in sub_res}
        self.assertIn("recon.tech", kinds)                   # edge (d)
        self.assertIn("recon.waf", kinds)                    # edge (d)
        self.assertIn("access_control.idor", kinds)          # oracle web sur le nœud découvert
        # gouvernance : toutes les actions chaînées sur le sous-domaine in-scope ont été FIRE
        self.assertTrue(all(r["verdict"] == FIRE for r in sub_res))
        # la chaîne a réellement tiré la vérification sur l'hôte découvert
        self.assertTrue(any(f.target == sub and "fingerprint" in f.title for f in eng.findings))

    def test_endpoint_discovery_feeds_injection_oracles_next_wave(self):
        ep = "https://app.test/search?q=1"

        def js(action):
            return [_disc(ep, EP)] if action.target == "app.test" else []
        def sqli(action):
            if action.target == ep:
                return [Finding(target=ep, title="sqli: sonde sur endpoint", severity="INFO",
                                category="recon", status="tested")]
            return []
        with _swap_registry(_stubs(**{"recon.js_endpoints": js, "sqli.probe": sqli})):
            eng = _armed_auto(scope(in_scope=("app.test",)))
            eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), max_waves=4)
        ep_res = [r for r in eng.results if r["target"] == ep]
        self.assertTrue(ep_res, "aucun oracle chaîné sur l'endpoint découvert")
        self.assertIn("sqli.probe", {r["kind"] for r in ep_res})
        self.assertTrue(any(f.target == ep and "sonde" in f.title for f in eng.findings))


# =================================================================================================
# (C) SCOPE-LOCKED — un hôte/endpoint découvert HORS PÉRIMÈTRE n'est JAMAIS poursuivi
# =================================================================================================
class TestScopeLockedChaining(unittest.TestCase):
    def test_out_of_scope_discovered_host_is_vetoed_not_fired(self):
        # DÉFENSE EN PROFONDEUR : un module fautif « découvre » un hôte HORS-SCOPE et l'émet quand même.
        # Le graphe l'accueille, le cerveau propose des actions chaînées dessus, mais la gate ROE de
        # l'engine les VÉTOe (fail-closed) : rien ne tire, aucune donnée dérivée.
        evil = "evil.example.com"

        def subs(action):
            return [_disc(evil, SUB)] if action.target == "app.test" else []
        with _swap_registry(_stubs(**{"recon.subdomains": subs})):
            eng = _armed_auto(scope(in_scope=("app.test",)))   # evil HORS-scope
            eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), max_waves=4)
        evil_res = [r for r in eng.results if r["target"] == evil]
        self.assertTrue(evil_res, "les actions chaînées hors-scope auraient dû être évaluées (puis vétoées)")
        self.assertTrue(all(r["verdict"] == VETO for r in evil_res))   # fail-closed
        self.assertFalse(any(r["verdict"] == FIRE for r in evil_res))  # rien n'a tiré hors périmètre
        # out_scope l'emporte aussi explicitement
        with _swap_registry(_stubs(**{"recon.subdomains": subs})):
            eng2 = _armed_auto(scope(in_scope=("app.test", "*.example.com"), out_scope=("evil.example.com",)))
            eng2.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), max_waves=3)
        self.assertTrue(all(r["verdict"] == VETO for r in eng2.results if r["target"] == evil))

    def test_module_never_emits_out_of_scope_endpoint(self):
        # recon.js_endpoints n'émet de finding PAR-ENDPOINT que pour des cibles in-scope (verrou
        # fail-closed au niveau du module — l'URL externe reste listée informativement, jamais chaînée).
        html = ('<html><body><script>var a="/api/v1/users";'
                'fetch("https://app.test/api/orders");'
                'fetch("https://evil.example.com/collect");</script></body></html>')

        def fake(url, headers=None, timeout=20, maxlen=500000):
            return (200, html, {}) if ("app.test" in url and "evil" not in url) else (None, "", {})
        r = _patch(JsEndpoints, "_http_get", fake)
        try:
            f = JsEndpoints().fire(Action("recon.js_endpoints", "app.test", params={"in_scope": ["app.test"]}))
        finally:
            r()
        eps = [x for x in f if EP in x.title]
        self.assertTrue(eps)                                 # des endpoints in-scope émis
        for x in eps:
            self.assertIn("app.test", x.target)
            self.assertNotIn("evil.example.com", x.target)   # jamais l'externe
        targets = {x.target for x in eps}
        self.assertIn("https://app.test/api/orders", targets)          # URL absolue in-scope
        self.assertIn("https://app.test/api/v1/users", targets)        # chemin relatif rattaché à la racine


# =================================================================================================
# (D) BORNÉ — fan-out plafonné + profondeur bornée (pas de re-semis de découverte)
# =================================================================================================
class TestChainingIsBounded(unittest.TestCase):
    def test_fanout_capped_at_max_chain_targets(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        n = HeuristicBrain.MAX_CHAIN_TARGETS
        for i in range(n + 25):                              # bien plus de cibles dérivées que le plafond
            g.add_finding(_disc(f"h{i:03d}.app.test", SUB))
        actions = HeuristicBrain().propose(g)
        derived = {a.target for a in actions if a.target != "app.test" and a.target.endswith(".app.test")}
        self.assertLessEqual(len(derived), n, "fan-out non borné (runaway possible)")
        self.assertEqual(len(derived), n)                    # exactement le plafond (déterministe)

    def test_discovery_not_reseeded_on_discovered_host_bounds_depth(self):
        # PROFONDEUR : la racine SÈME la découverte ; un hôte DÉJÀ découvert ne relance PAS l'énumération
        # (sinon découverte récursive infinie). recon.subdomains/js_endpoints/urls -> racine seulement.
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        sub = "api.app.test"
        g.add_finding(_disc(sub, SUB))
        actions = HeuristicBrain().propose(g)
        root_kinds = {a.kind for a in actions if a.target == "app.test"}
        sub_kinds = {a.kind for a in actions if a.target == sub}
        for seed in ("recon.subdomains", "recon.js_endpoints", "recon.urls"):
            self.assertIn(seed, root_kinds, f"{seed} devrait être semé sur la racine")
            self.assertNotIn(seed, sub_kinds, f"{seed} NE doit PAS être re-semé sur l'hôte découvert")

    def test_campaign_terminates_within_max_waves(self):
        # même avec de la découverte à chaque vague, la campagne s'arrête (point fixe ou max_waves).
        sub = "api.app.test"

        def subs(action):
            return [_disc(sub, SUB)] if action.target == "app.test" else []
        with _swap_registry(_stubs(**{"recon.subdomains": subs})):
            eng = _armed_auto(scope(in_scope=("app.test", sub)))
            eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), max_waves=3)
        self.assertLessEqual(eng.waves, 3)                   # jamais au-delà du garde-fou


# =================================================================================================
# (E) COVERAGE-SAFE — le plancher des classes qualifiantes tient sur les cibles chaînées
# =================================================================================================
class TestQualifyingFloorHolds(unittest.TestCase):
    def test_chained_qualifying_oracles_never_starved_at_zero_budget(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        ep = "https://app.test/api/users?id=5"
        g.add_finding(_disc(ep, EP))
        g.add_finding(_disc("api.app.test", SUB))
        actions = HeuristicBrain().propose(g)
        ordered, skipped = Planner(budget=0.0).order(actions)
        ordered_ids = {(a.kind, a.target) for a in ordered}
        skipped_kinds = {a.kind for a in skipped}
        # IDOR (access_control) + SQLi (sqli) chaînés sur l'endpoint = QUALIFIANTS -> jamais déférés
        self.assertIn(("access_control.idor", ep), ordered_ids)
        self.assertIn(("sqli.probe", ep), ordered_ids)
        self.assertNotIn("access_control.idor", skipped_kinds)
        self.assertNotIn("sqli.probe", skipped_kinds)
        # sanity : le budget nul MORD bien (des non-qualifiantes SONT déférées, defer != delete)
        self.assertTrue(skipped, "budget=0 aurait dû déférer des actions non-qualifiantes")
        self.assertTrue(skipped_kinds & {"recon.tech", "recon.waf", "recon.subdomains", "xss.reflected",
                                         "recon.httpx", "web.nuclei", "recon.js_endpoints"})

    def test_prepare_injects_creds_but_keeps_chained_endpoint_url(self):
        # l'engine injecte comptes/mitre (setdefault) SANS écraser l'urls=[endpoint] posé par le chaînage.
        eng = Engine(scope(in_scope=("app.test",),
                           known_creds=[{"headers": {"Cookie": "a=1"}}, {"headers": {"Cookie": "b=2"}}],
                           idor_targets=["https://app.test/o/1"]))
        ep = "https://app.test/api/users?id=5"
        a_chained = Action("access_control.idor", ep, cls="access_control", params={"urls": [ep]})
        a_base = Action("access_control.idor", "app.test", cls="access_control")
        eng._prepare([a_chained, a_base], None, {}, {})
        self.assertEqual(a_chained.params["urls"], [ep])         # endpoint chaîné PRÉSERVÉ
        self.assertEqual(len(a_chained.params["accounts"]), 2)   # comptes injectés depuis le scope
        self.assertEqual(a_base.params["urls"], ["https://app.test/o/1"])  # base : idor_targets du scope


# =================================================================================================
# (F) SESSION GOUVERNÉE portée À TRAVERS LA CHAÎNE — scope-guardée + SECRÈTE
# =================================================================================================
SECRET = "sess-secret-abc123XYZ"


class TestSessionCarriedThroughChain(unittest.TestCase):
    def test_derived_in_scope_host_inherits_session_secret_stays_hidden(self):
        sc = scope(in_scope=("app.test", "*.app.test"),
                   sessions={"app.test": {"cookies": {"sid": SECRET}}})
        sub = "api.app.test"

        def subs(action):
            return [_disc(sub, SUB)] if action.target == "app.test" else []
        with _swap_registry(_stubs(**{"recon.subdomains": subs})):
            eng = _armed_auto(sc)
            eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), max_waves=3)
        # (1) le sous-domaine dérivé in-scope a HÉRITÉ la session par-hôte de la racine (scope-guardée)
        hdrs = eng.sessions.headers_for(f"https://{sub}/")
        self.assertIn(SECRET, hdrs.get("Cookie", ""))
        # (2) le secret ne fuit NULLE PART : ni dans un finding, ni dans le graphe, ni dans les résultats
        blob = json.dumps([f.to_dict() for f in eng.findings]) + eng.graph.to_dict().__repr__() \
            + json.dumps(eng.results, default=str) + json.dumps(eng.roe_decisions(), default=str)
        self.assertNotIn(SECRET, blob)
        # (3) le nœud de graphe du sous-domaine ne porte AUCUN matériel de session
        node = eng.graph.nodes.get(("host", sub), {})
        self.assertNotIn(SECRET, json.dumps(node))

    def test_out_of_scope_derived_host_never_inherits(self):
        store = SessionStore(Scope({"in_scope": ["app.test", "*.app.test"],
                                    "out_scope": ["blocked.app.test"]}),
                             per_host={"app.test": {"cookies": {"sid": SECRET}}})
        # dérivé in-scope -> hérite, matériel disponible pour les requêtes chaînées in-scope
        self.assertTrue(store.inherit("app.test", "api.app.test"))
        self.assertIn(SECRET, store.headers_for("https://api.app.test/")["Cookie"])
        # dérivé HORS in-scope -> aucun héritage, aucune fuite (scope-guard fail-closed)
        self.assertFalse(store.inherit("app.test", "attacker.evil.test"))
        self.assertEqual(store.headers_for("https://attacker.evil.test/"), {})
        # dérivé explicitement out_scope -> refusé aussi
        self.assertFalse(store.inherit("app.test", "blocked.app.test"))
        self.assertEqual(store.headers_for("https://blocked.app.test/"), {})

    def test_inherit_never_overrides_existing_or_default_session(self):
        # n'écrase pas une session par-hôte déjà configurée pour la cible
        store = SessionStore(Scope({"in_scope": ["*.app.test", "app.test"]}),
                             per_host={"app.test": {"cookies": {"sid": "A"}},
                                       "api.app.test": {"cookies": {"sid": "B"}}})
        self.assertFalse(store.inherit("app.test", "api.app.test"))
        self.assertIn("sid=B", store.headers_for("https://api.app.test/")["Cookie"])
        # une source SANS session par-hôte (seulement défaut global) -> rien à aliaser (le défaut couvre déjà)
        store2 = SessionStore(Scope({"in_scope": ["*.app.test", "app.test"]}),
                              default={"cookies": {"sid": "D"}})
        self.assertFalse(store2.inherit("app.test", "api.app.test"))
        self.assertIn("sid=D", store2.headers_for("https://api.app.test/")["Cookie"])  # via défaut, pas alias


if __name__ == "__main__":
    unittest.main(verbosity=2)

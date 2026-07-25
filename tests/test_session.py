"""Session authentifiée GOUVERNÉE (forge/session.py + câblage engine/oracle/recon).

Prouve les trois garanties DURES du support de session (le matériel d'auth est SECRET) :
  (1) SCOPE-GUARD : la session n'est attachée QU'AUX requêtes in-scope ; une URL hors-scope ne la
      reçoit JAMAIS — même une URL dérivée à runtime (collecteur/redirection) sur un module in-scope.
  (2) RÉDACTION : le matériel secret ne fuit ni dans le ledger, ni dans le rapport, ni dans le graphe,
      ni dans une représentation lisible (repr/str) de Session/SessionStore.
  (3) OFFLINE-SAFE : sans session configurée, le store est inerte (no-op) — la suite reste verte.

Plus : les modules d'évasion (evasion.*) sont désormais PLANNER-SELECTABLE pour les cibles protégées.

Hermétique : on monkeypatch `urllib.request.urlopen` (capture des en-têtes de requête, zéro réseau)
et les seams des modules — AUCUN I/O réel."""
import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import session as sessionmod                       # noqa: E402
from forge.session import Session, SessionStore               # noqa: E402
from forge.roe import Scope, Action                           # noqa: E402
from forge.engine import Engine                               # noqa: E402
from forge.ledger import Ledger                               # noqa: E402
from forge.report import build_report                         # noqa: E402
from forge.schema import Target, Finding                      # noqa: E402
from forge.graph import EngagementGraph                       # noqa: E402
from forge.brain import HeuristicBrain                        # noqa: E402
from forge.planner import Planner                             # noqa: E402
from forge import modules as mods                             # noqa: E402
from forge import techniques                                  # noqa: E402
from forge.modules.oracle import Oracle                       # noqa: E402
from forge.modules.recon_surface import PassiveSurface        # noqa: E402

SECRET = "S3CR3T-forge-9f8e7d"                                # jeton témoin unique, cherché partout


class _Capture:
    """Fake urlopen : enregistre les en-têtes (valeurs) par URL puis dégrade (URLError) -> le module
    renvoie proprement (None, ...). Les clés d'en-tête sont capitalisées par urllib mais les VALEURS
    (donc le secret) restent intactes -> on cherche le secret dans les valeurs."""
    def __init__(self):
        self.by_url = {}      # url -> " ".join(header values)

    def __call__(self, req, timeout=None, *a, **k):
        self.by_url[req.full_url] = " ".join(str(v) for v in req.headers.values())
        raise urllib.error.URLError("captured (no network in test)")

    def values_for(self, url):
        return self.by_url.get(url, "")

    def saw(self, url):
        return url in self.by_url


# =================================================================================================
class TestSessionMaterial(unittest.TestCase):
    def test_cookies_from_dict_and_string(self):
        self.assertEqual(Session({"cookies": {"sid": "a", "x": "b"}}).request_headers()["Cookie"],
                         "sid=a; x=b")
        self.assertEqual(Session({"cookies": "sid=a; x=b"}).request_headers()["Cookie"], "sid=a; x=b")

    def test_bearer_becomes_authorization(self):
        self.assertEqual(Session({"bearer": "TOK"}).request_headers()["Authorization"], "Bearer TOK")
        self.assertEqual(Session({"token": "TOK"}).request_headers()["Authorization"], "Bearer TOK")

    def test_raw_headers_passthrough(self):
        self.assertEqual(Session({"headers": {"X-CSRF": "z"}}).request_headers()["X-CSRF"], "z")

    def test_explicit_header_beats_derived_within_session(self):
        # un Authorization explicite dans headers prime sur le bearer dérivé (pas d'écrasement)
        s = Session({"headers": {"Authorization": "Bearer explicit"}, "bearer": "TOK"})
        self.assertEqual(s.request_headers()["Authorization"], "Bearer explicit")

    def test_is_empty(self):
        self.assertTrue(Session().is_empty())
        self.assertTrue(Session({"cookies": ""}).is_empty())
        self.assertFalse(Session({"bearer": "x"}).is_empty())

    def test_redaction_repr_hides_secret(self):
        s = Session({"cookies": f"sid={SECRET}", "bearer": SECRET, "headers": {"X": SECRET}})
        self.assertNotIn(SECRET, repr(s))
        self.assertNotIn(SECRET, str(s))
        self.assertIn("cookies=1", repr(s))              # compteur, pas de valeur


# =================================================================================================
class TestSessionStoreScopeGuard(unittest.TestCase):
    def _store(self, **kw):
        scope = Scope({"in_scope": ["app.test", "*.api.test"], "out_scope": ["evil.test"]})
        return SessionStore(scope, **kw)

    def test_in_scope_receives_default_session(self):
        st = self._store(default={"cookies": f"sid={SECRET}"})
        self.assertIn(SECRET, st.headers_for("https://app.test/x")["Cookie"])

    def test_out_of_scope_never_receives_session(self):
        st = self._store(default={"cookies": f"sid={SECRET}"})
        self.assertEqual(st.headers_for("https://evil.test/x"), {})        # out_scope explicite
        self.assertEqual(st.headers_for("https://other.test/x"), {})       # inconnu (fail-closed)
        self.assertIsNone(st.session_for("https://evil.test/x"))

    def test_per_host_beats_default(self):
        st = self._store(default={"bearer": "DEFAULT"},
                         per_host={"app.test": {"bearer": SECRET}})
        self.assertEqual(st.headers_for("https://app.test/")["Authorization"], f"Bearer {SECRET}")
        # un autre hôte in-scope sans entrée par-hôte retombe sur le défaut
        self.assertEqual(st.headers_for("https://foo.api.test/")["Authorization"], "Bearer DEFAULT")

    def test_per_host_glob_match(self):
        st = self._store(per_host={"*.api.test": {"cookies": f"t={SECRET}"}})
        self.assertIn(SECRET, st.headers_for("https://foo.api.test/")["Cookie"])

    def test_per_host_entry_out_of_scope_is_still_guarded(self):
        # même si un per_host cible un hôte hors-scope (mauvaise config), le scope-guard FAIT FOI.
        scope = Scope({"in_scope": ["app.test"], "out_scope": []})
        st = SessionStore(scope, per_host={"evil.test": {"bearer": SECRET}})
        self.assertEqual(st.headers_for("https://evil.test/"), {})

    def test_from_scope_reads_session_keys(self):
        scope = Scope({"in_scope": ["app.test"], "session": {"cookies": f"sid={SECRET}"},
                       "sessions": {"app.test": {"bearer": SECRET}}})
        st = SessionStore.from_scope(scope)
        self.assertEqual(st.headers_for("https://app.test/")["Authorization"], f"Bearer {SECRET}")

    def test_inert_when_no_session(self):
        scope = Scope({"in_scope": ["app.test"]})
        st = SessionStore.from_scope(scope)
        self.assertEqual(st.headers_for("https://app.test/"), {})

    def test_store_repr_hides_secret(self):
        st = self._store(default={"bearer": SECRET})
        self.assertNotIn(SECRET, repr(st))
        self.assertNotIn(SECRET, str(st))
        # résumé sûr : pas de valeur secrète
        self.assertNotIn(SECRET, json.dumps(st.hosts_with_session()))


# =================================================================================================
class TestOracleHttpInjection(unittest.TestCase):
    """Le chokepoint Oracle._http fusionne la session scope-guardée dans la requête SORTANTE seule."""

    def _scope(self):
        return Scope({"in_scope": ["app.test"], "out_scope": ["collector.test"]})

    def test_attaches_only_in_scope(self):
        store = SessionStore(self._scope(), default={"cookies": f"sid={SECRET}"})
        cap = _Capture()
        # le seam réseau des oracles est `Oracle._raw_open` (opener no-follow), PAS `urlopen`.
        with patch("forge.modules.oracle.Oracle._raw_open", cap), sessionmod.using(store):
            Oracle._http("https://app.test/obj")                 # in-scope
            Oracle._http("https://collector.test/seen")          # hors-scope (ex: collecteur SSRF)
        self.assertIn(SECRET, cap.values_for("https://app.test/obj"))
        self.assertNotIn(SECRET, cap.values_for("https://collector.test/seen"))

    def test_caller_header_wins_over_session(self):
        store = SessionStore(self._scope(), default={"cookies": "sid=session"})
        cap = _Capture()
        with patch("forge.modules.oracle.Oracle._raw_open", cap), sessionmod.using(store):
            Oracle._http("https://app.test/obj", headers={"Cookie": "caller=1"})
        self.assertIn("caller=1", cap.values_for("https://app.test/obj"))
        self.assertNotIn("sid=session", cap.values_for("https://app.test/obj"))

    def test_noop_without_bound_store(self):
        cap = _Capture()
        with patch("forge.modules.oracle.Oracle._raw_open", cap):  # AUCUN store lié
            Oracle._http("https://app.test/obj", headers={"X-Caller": "1"})
        vals = cap.values_for("https://app.test/obj")
        self.assertIn("1", vals)
        self.assertNotIn(SECRET, vals)


# =================================================================================================
class TestReconHttpInjection(unittest.TestCase):
    """Le chokepoint PassiveSurface._http_get (recon passif + actif) applique le même scope-guard."""

    def test_attaches_only_in_scope(self):
        scope = Scope({"in_scope": ["app.test"], "out_scope": ["cdn.evil.test"]})
        store = SessionStore(scope, default={"bearer": SECRET})
        cap = _Capture()
        with patch("urllib.request.urlopen", cap), sessionmod.using(store):
            PassiveSurface._http_get("https://app.test/")            # in-scope
            PassiveSurface._http_get("https://cdn.evil.test/asset.js")  # hors-scope (asset dérivé)
        self.assertIn(SECRET, cap.values_for("https://app.test/"))
        self.assertNotIn(SECRET, cap.values_for("https://cdn.evil.test/asset.js"))

    def test_noop_without_store_keeps_default_ua(self):
        cap = _Capture()
        with patch("urllib.request.urlopen", cap):
            PassiveSurface._http_get("https://app.test/")
        self.assertIn("forge-surface", cap.values_for("https://app.test/"))
        self.assertNotIn(SECRET, cap.values_for("https://app.test/"))


# =================================================================================================
class TestEngineBindsAndRedacts(unittest.TestCase):
    """Bout-en-bout : le moteur LIE le store autour de fire() ; le secret est attaché aux requêtes
    in-scope MAIS n'apparaît nulle part dans le ledger ni le rapport (rédaction)."""

    def _engine(self, tmp):
        scope = Scope({"in_scope": ["app.test"], "out_scope": ["evil.test"],
                       "session": {"cookies": f"sid={SECRET}", "headers": {"X-Auth": SECRET}}})
        ledger = Ledger(Path(tmp) / "engagement.jsonl")
        eng = Engine(scope, ledger=ledger)
        return eng, ledger

    def test_session_attached_in_scope_and_redacted_everywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng, ledger = self._engine(tmp)
            eng.arm("test")
            act = Action("recon.waf", "app.test")
            eng.approve(act.id, "test")
            cap = _Capture()
            with patch("urllib.request.urlopen", cap):
                res = eng.execute(act)                    # FIRE -> recon.waf -> _http_get(app.test)
            self.assertEqual(res["verdict"], "FIRE")
            # (1) la session a bien été attachée à la requête in-scope pendant le fire
            self.assertIn(SECRET, cap.values_for("https://app.test"))
            # (2) RÉDACTION : le secret n'est NI dans le ledger NI dans le rapport
            ledger_text = (Path(tmp) / "engagement.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(SECRET, ledger_text)
            self.assertNotIn(SECRET, build_report(eng))
            # le store du moteur est bien câblé (config wired) mais scope-guardé
            self.assertIn(SECRET, eng.sessions.headers_for("https://app.test")["Cookie"])
            self.assertEqual(eng.sessions.headers_for("https://evil.test"), {})

    def test_out_of_scope_target_never_receives_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng, _ = self._engine(tmp)
            eng.arm("test")
            act = Action("recon.waf", "evil.test")
            eng.approve(act.id, "test")
            cap = _Capture()
            with patch("urllib.request.urlopen", cap):
                res = eng.execute(act)                    # VETO -> le module ne fire jamais
            self.assertEqual(res["verdict"], "VETO")
            self.assertFalse(cap.saw("https://evil.test"))   # aucune requête émise du tout

    def test_store_not_bound_outside_fire(self):
        # le store n'est lié QUE le temps du fire : hors execute(), current() est None (pas de fuite ambiante)
        with tempfile.TemporaryDirectory() as tmp:
            eng, _ = self._engine(tmp)
            eng.arm("test")
            act = Action("recon.waf", "app.test")
            eng.approve(act.id, "test")
            with patch("urllib.request.urlopen", _Capture()):
                eng.execute(act)
            self.assertIsNone(sessionmod.current())


# =================================================================================================
class TestCampaignPerTargetSession(unittest.TestCase):
    """Une session par-cible (targets.json[].attrs.session) est versée dans le store, scope-guardée,
    et RETIRÉE des attrs poussés au graphe (le secret n'entre jamais dans le world-model)."""

    class _NullBrain:
        def propose(self, graph_state):
            return []                                    # aucune action -> campagne = amorçage seul

    def test_per_target_session_folded_and_stripped_from_graph(self):
        scope = Scope({"in_scope": ["app.test"]})
        eng = Engine(scope)
        target = Target("app.test", "app", attrs={"service": "http", "protected": True,
                                                  "session": {"cookies": f"sid={SECRET}"}})
        eng.campaign([target], self._NullBrain(), Planner())
        # (1) la session par-cible est utilisable (in-scope)
        self.assertIn(SECRET, eng.sessions.headers_for("https://app.test/")["Cookie"])
        # (2) le secret N'EST PAS dans les attrs du nœud de graphe
        node = eng.graph.nodes.get(("host", "app.test"), {})
        self.assertNotIn("session", node)
        self.assertNotIn(SECRET, json.dumps(node))
        self.assertEqual(node.get("service"), "http")    # les autres attrs survivent
        self.assertTrue(node.get("protected"))


# =================================================================================================
class TestEvasionPlannerSelectable(unittest.TestCase):
    """evasion.* est planner-selectable pour les cibles PROTÉGÉES (marqueur attrs ou fingerprint WAF)."""

    EVASION = {"evasion.xhr", "evasion.turnstile"}

    def _kinds(self, graph):
        return {a.kind for a in HeuristicBrain().propose(graph)}

    def test_registered_and_in_catalog(self):
        for k in ("evasion.xhr", "evasion.turnstile", "evasion.idor_intercept"):
            self.assertIn(k, mods.kinds())
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k))    # source de vérité unique
        self.assertEqual(techniques.action_class("evasion.xhr"), "evasion")
        self.assertFalse(techniques.action_exploit("evasion.xhr"))
        self.assertTrue(techniques.action_exploit("evasion.idor_intercept"))

    def test_proposed_for_protected_target(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="app", protected=True)
        self.assertTrue(self.EVASION <= self._kinds(g))

    def test_not_proposed_for_unprotected_target(self):
        # régression : une cible web ordinaire ne déclenche PAS d'évasion (comportement de base inchangé)
        g = EngagementGraph()
        g.add_host("app.test", kind="app")
        self.assertFalse(self.EVASION & self._kinds(g))

    def test_chained_from_waf_fingerprint(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="app")
        g.add_finding(Finding(target="app.test", title="WAF/CDN identifié : Cloudflare",
                              severity="INFO", category="recon", status="tested"))
        self.assertTrue(self.EVASION <= self._kinds(g))

    def test_planner_keeps_evasion_actions(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="app", protected=True)
        actions = [a for a in HeuristicBrain().propose(g) if a.kind in self.EVASION]
        ordered, skipped = Planner().order(actions)
        self.assertEqual({a.kind for a in ordered}, self.EVASION)
        self.assertFalse(skipped)


if __name__ == "__main__":
    unittest.main(verbosity=2)

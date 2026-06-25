"""P2 (suite) — évasion (browser-automation) + mémoire/dedup. Hermétique (aucun service réel)."""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                       # noqa: E402
from forge.engine import Engine                           # noqa: E402
from forge.memory import Memory                           # noqa: E402
from forge.schema import Finding                          # noqa: E402
from forge import modules as mods                         # noqa: E402
from forge import browser_client as bc                    # noqa: E402
from forge.modules.registry import Module                 # noqa: E402
from forge.modules.web import IdorDifferential            # noqa: E402

# pointe le client browser vers un port mort -> available() == False (connection refused, instantané)
os.environ["FORGE_BROWSER_URL"] = "http://127.0.0.1:1"


class TestEvasion(unittest.TestCase):
    def test_registered(self):
        for k in ("evasion.xhr", "evasion.turnstile", "evasion.idor_intercept"):
            self.assertIn(k, mods.kinds())

    def test_idor_intercept_is_exploit(self):
        self.assertTrue(mods.get("evasion.idor_intercept").exploit)        # exige allow_exploit
        self.assertFalse(mods.get("evasion.xhr").exploit)                  # enabler d'accès

    def test_unavailable_when_service_down(self):
        self.assertFalse(mods.get("evasion.xhr").available)                # service injoignable

    def test_dry_builds_call_without_network(self):
        a = Action("evasion.idor_intercept", "https://app.test/graphql",
                   params={"find": "orders/1", "replace": "orders/2", "target": "url"})
        s = mods.get("evasion.idor_intercept").dry(a)
        self.assertIn("intercept-modify", s)
        self.assertIn("orders/2", s)

    def test_evasion_vetoed_or_skipped_unarmed(self):
        # in-scope, allow_exploit, mais NON armé -> jamais FIRE (donc aucun appel réseau)
        eng = Engine(Scope({"mode": "grey", "in_scope": ["app.test"], "allow_exploit": True}))
        a = Action("evasion.xhr", "app.test")
        r = eng.execute(a)
        self.assertIn(r["verdict"], ("DRY_RUN", "SKIP"))                   # pas de FIRE
        self.assertEqual(len(eng.coverage()["fired"]), 0)


class TestMemory(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="forge-mem-"))

    def _f(self, target="app.test", title="IDOR"):
        return Finding(target=target, title=title, severity="HIGH")

    def test_store_and_dedup(self):
        m = Memory(self.dir / "m.jsonl")
        self.assertTrue(m.store(self._f()))                               # nouveau
        self.assertFalse(m.store(self._f()))                              # même clé -> dedup
        self.assertEqual(m.stats()["records"], 1)

    def test_persists_across_instances(self):
        Memory(self.dir / "m.jsonl").store(self._f())
        m2 = Memory(self.dir / "m.jsonl")                                 # recharge depuis disque
        self.assertTrue(m2.seen(self._f()))
        self.assertFalse(m2.store(self._f()))

    def test_search(self):
        m = Memory(self.dir / "m.jsonl")
        m.store(self._f(title="IDOR sur /orders"))
        m.store(self._f(target="other.test", title="SSRF metadata"))
        self.assertEqual(len(m.search("idor")), 1)

    def test_dedup_key_stable_across_verdict(self):
        # RÉGRESSION : le même finding logique re-rapporté avec un statut différent (tested ->
        # vulnerable) ne doit PAS échapper à la dedup. La clé retire le token de verdict du titre.
        m = Memory(self.dir / "m.jsonl")
        self.assertTrue(m.store(self._f(title="IDOR /orders tested")))
        self.assertFalse(m.store(self._f(title="IDOR /orders vulnerable")))   # même finding -> dédupé
        self.assertFalse(m.store(self._f(title="IDOR /orders submitted")))
        self.assertEqual(m.stats()["records"], 1)
        # un finding réellement différent (autre titre) reste distinct
        self.assertTrue(m.store(self._f(title="SSRF metadata")))

    def test_engine_dedups_on_fire(self):
        m = Memory(self.dir / "m.jsonl")
        # pré-vu : même clé que ce que demo.fingerprint.fire() émet (target+category+title)
        pre = Finding(target="app.test", title="DEMO — module de démonstration tiré",
                      severity="HIGH", category="DEMO")
        m.store(pre)
        eng = Engine(Scope({"mode": "grey", "in_scope": ["app.test"]}), memory=m)
        eng.arm()
        a = Action("demo.fingerprint", "app.test"); eng.approve(a.id)
        eng.execute(a)                                                    # FIRE -> finding déjà vu
        self.assertEqual(eng.dups, 1)
        self.assertEqual(len(eng.findings), 0)                            # dédupliqué
        self.assertEqual(len(eng.run_records), 1)                         # technique exécutée quand même


# --- stub HTTP stdlib du service browser-automation ---------------------------------------

class _BrowserStub(BaseHTTPRequestHandler):
    """Émule le service browser-automation. Enregistre chaque requête (path + query) dans la
    liste de classe REQUESTS. Vérifie le transport RÉEL du client : query params, aucun body JSON."""
    REQUESTS = []                                          # [(method, path, query_dict, body_len)]

    def log_message(self, *a):                            # silence
        pass

    def _record_and_reply(self, method):
        parsed = urllib.parse.urlparse(self.path)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        _BrowserStub.REQUESTS.append((method, parsed.path, query, len(body)))
        payload = json.dumps({"ok": True, "path": parsed.path, "query": query}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record_and_reply("GET")

    def do_POST(self):
        self._record_and_reply("POST")


class TestBrowserClientWiring(unittest.TestCase):
    """Le VRAI fire() des modules évasion parle au stub HTTP : on prouve le transport.
    Hermétique — un seul serveur stdlib en thread, jamais de réseau externe."""

    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _BrowserStub)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()
        os.environ["FORGE_BROWSER_URL"] = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        os.environ["FORGE_BROWSER_URL"] = "http://127.0.0.1:1"   # restaure le port mort

    def setUp(self):
        _BrowserStub.REQUESTS.clear()

    def _paths(self):
        return [p for (_m, p, _q, _b) in _BrowserStub.REQUESTS]

    def test_health_reaches_stub(self):
        self.assertTrue(bc.health(timeout=5))                    # service "joignable"
        self.assertIn("/health", self._paths())

    def test_xhr_fire_uses_query_params_no_json_body(self):
        # le vrai fire() de evasion.xhr -> capture-start + goto + capture-dump
        mod = mods.get("evasion.xhr")
        mod.fire(Action("evasion.xhr", "https://app.test/api",
                        params={"types": "xhr", "tab": "forge"}))
        # AUCUNE requête ne porte de body (tout en query string)
        for (_m, path, _q, body_len) in _BrowserStub.REQUESTS:
            self.assertEqual(body_len, 0, f"{path} a envoyé un body ({body_len}o) — devrait être en query")
        paths = self._paths()
        self.assertIn("/capture-start", paths)
        self.assertIn("/goto", paths)
        self.assertIn("/capture-dump", paths)
        # le goto a bien passé l'URL cible EN QUERY PARAM (pas en JSON)
        goto = [q for (_m, p, q, _b) in _BrowserStub.REQUESTS if p == "/goto"][0]
        self.assertEqual(goto.get("url"), "https://app.test/api")

    def test_xhr_endpoint_never_called(self):
        # /xhr n'existe pas côté service : le module DOIT passer par capture-start/dump.
        mods.get("evasion.xhr").fire(Action("evasion.xhr", "https://app.test/api"))
        self.assertNotIn("/xhr", self._paths())

    def test_intercept_modify_sends_pattern_in_query(self):
        mod = mods.get("evasion.idor_intercept")
        mod.fire(Action("evasion.idor_intercept", "https://app.test/graphql",
                        params={"find": "orders/1", "replace": "orders/2",
                                "pattern": "*/graphql*", "target": "url"}))
        modify = [(q, b) for (_m, p, q, b) in _BrowserStub.REQUESTS if p == "/intercept-modify"]
        self.assertEqual(len(modify), 1)
        q, body_len = modify[0]
        self.assertEqual(body_len, 0)                            # query string, pas de JSON
        self.assertEqual(q.get("pattern"), "*/graphql*")         # 'pattern' REQUIS et transmis
        self.assertEqual(q.get("find"), "orders/1")
        self.assertEqual(q.get("replace"), "orders/2")
        self.assertEqual(q.get("target"), "url")


class TestToolFailedHelper(unittest.TestCase):
    """Helper registry.Module.tool_failed sur ses 4 branches (rc 0/127/124/autre)."""

    def setUp(self):
        self.mod = Module()
        self.action = Action("x", "app.test")

    def test_rc_zero_returns_none(self):
        self.assertIsNone(self.mod.tool_failed(self.action, 0, "ok", "", "sometool"))

    def test_rc_127_is_unavailable(self):
        f = self.mod.tool_failed(self.action, 127, "", "", "sometool")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "INFO")
        self.assertIn("indisponible", f.title)
        self.assertEqual(f.tool, "sometool")

    def test_rc_124_is_timeout(self):
        f = self.mod.tool_failed(self.action, 124, "", "", "sometool")
        self.assertIn("timeout", f.title)

    def test_other_rc_is_generic_failure(self):
        f = self.mod.tool_failed(self.action, 3, "", "boom", "sometool", category="origin")
        self.assertIn("rc=3", f.title)
        self.assertEqual(f.category, "origin")
        self.assertEqual(f.evidence, "boom")                     # err remonté dans la preuve


class TestIdorOracleDifferential(unittest.TestCase):
    """Oracle différentiel access_control.idor : monkeypatch _fetch (zéro réseau)."""

    def _run_with_fetch(self, fetch_map):
        mod = IdorDifferential()
        # fetch_map: (url, role) -> (status, body) ; role = 'A'|'B'|'anon'
        def fake_fetch(url, headers, timeout=15):
            role = (headers or {}).get("X-Role", "anon")
            return fetch_map[(url, role)]
        orig = IdorDifferential._fetch
        IdorDifferential._fetch = staticmethod(fake_fetch)
        try:
            action = Action("access_control.idor", "https://app.test/obj/1",
                            params={"accounts": [{"headers": {"X-Role": "A"}},
                                                 {"headers": {"X-Role": "B"}}],
                                    "urls": ["https://app.test/obj/1"]})
            return mod.fire(action)
        finally:
            IdorDifferential._fetch = orig

    def test_vulnerable_when_b_reads_a_and_anon_refused(self):
        u = "https://app.test/obj/1"
        same = "X" * 600                                         # corps identique A et B
        findings = self._run_with_fetch({
            (u, "A"): (200, same),
            (u, "B"): (200, same),
            (u, "anon"): (401, ""),
        })
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].status, "vulnerable")
        self.assertIn("IDOR PROBABLE", findings[0].title)

    def test_not_vulnerable_when_b_refused(self):
        u = "https://app.test/obj/1"
        findings = self._run_with_fetch({
            (u, "A"): (200, "X" * 600),
            (u, "B"): (403, ""),                                 # B correctement refusé
            (u, "anon"): (401, ""),
        })
        self.assertEqual(findings[0].severity, "INFO")
        self.assertEqual(findings[0].status, "not_vulnerable")
        self.assertIn("non confirmé", findings[0].title)

    def test_not_vulnerable_when_anon_also_allowed(self):
        # anon obtient aussi 200 -> ressource publique, pas un IDOR (oracle exige anon refusé)
        u = "https://app.test/obj/1"
        same = "X" * 600
        findings = self._run_with_fetch({
            (u, "A"): (200, same),
            (u, "B"): (200, same),
            (u, "anon"): (200, same),
        })
        self.assertEqual(findings[0].status, "not_vulnerable")

    def test_missing_config_is_info_skip(self):
        mod = IdorDifferential()
        findings = mod.fire(Action("access_control.idor", "https://app.test",
                                   params={"accounts": [{"headers": {}}], "urls": []}))
        self.assertEqual(findings[0].severity, "INFO")
        self.assertIn("non testé", findings[0].title)


if __name__ == "__main__":
    unittest.main(verbosity=2)

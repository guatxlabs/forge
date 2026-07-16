"""ANTI-REBINDING END-TO-END (T8) — preuves que les chokepoints de CONNEXION se connectent à l'IP
ÉPINGLÉE par le ROE au fire-time, au lieu de re-résoudre le hostname (fenêtre de DNS-rebinding).

Prouvé AU NIVEAU SOCKET/CONNEXION (pas seulement en prose) :
  1. `forge/pin.py` — sémantique du contexte (pick/ip_for/using) + honnêteté redirection cross-origin.
  2. httpflow `RequestSmugglingProbe._timed` — (a) `socket.create_connection` reçoit l'IP ÉPINGLÉE, PAS
     le hostname ; (b) serveur RÉEL 127.0.0.1 atteint via un target `pinned.invalid` NON RÉSOLVABLE +
     `_pinned_ips=["127.0.0.1"]` (si ça connecte, c'est QUE le pin a court-circuité la résolution) ; le
     `Host:` de la requête reste l'hôte d'origine.
  3. Oracle `_http` — serveur HTTP RÉEL atteint via `pinned.invalid` + `pin.using` (Host = hôte d'origine) ;
     SANS pin, `pinned.invalid` ne résout pas -> échec (contraste). Preuve socket : `create_connection`
     reçoit l'IP épinglée.
  4. HTTPS SNI — `wrap_socket(server_hostname=...)` reçoit l'HÔTE D'ORIGINE (pas l'IP) quand on connecte
     par-IP : la validation du certificat N'EST PAS affaiblie.
  5. BACKWARD-COMPAT — pin absent => `ip_for()` None => `Oracle._raw_open` (byte-identique) ; aucune
     connexion par-IP.
  6. WIRING moteur — `Engine.execute` lie `pin.using(target, action.params["_pinned_ips"])` autour du
     fire à partir de la Decision du ROE (résolution mockée).

Hermétique : serveurs RÉELS bornés à 127.0.0.1 (loopback, aucun réseau externe) ou mocks socket/ssl.
"""
import http.server
import socket
import ssl
import sys
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import pin                                            # noqa: E402
from forge.roe import Action, Scope, FIRE                        # noqa: E402
from forge.modules.oracle import Oracle                          # noqa: E402
from forge.modules.httpflow import RequestSmugglingProbe        # noqa: E402
from forge.engine import Engine                                  # noqa: E402


# =================================================================================================
#  1. Contexte de pin (forge/pin.py)
# =================================================================================================
class TestPinContext(unittest.TestCase):
    def test_pick_first_non_empty(self):
        self.assertEqual(pin.pick(["93.184.216.34", "127.0.0.1"]), "93.184.216.34")
        self.assertEqual(pin.pick("127.0.0.1"), "127.0.0.1")
        self.assertIsNone(pin.pick([]))
        self.assertIsNone(pin.pick(None))
        self.assertIsNone(pin.pick(["", "  "]))

    def test_ip_for_none_without_context(self):
        self.assertIsNone(pin.ip_for("http://app.test/"))

    def test_using_binds_and_restores(self):
        self.assertIsNone(pin.current())
        with pin.using("http://app.test:8080/x?y=1", ["203.0.113.9"]):
            self.assertEqual(pin.ip_for("http://app.test:8080/x"), "203.0.113.9")
            self.assertEqual(pin.ip_for("https://app.test/other"), "203.0.113.9")  # même hôte, autre chemin/scheme
        self.assertIsNone(pin.current())                          # restauré en sortie

    def test_cross_host_not_pinned_redirect_honesty(self):
        # HONNÊTETÉ : une redirection vers un AUTRE hôte re-résout (le pin ne couvre que l'hôte d'origine).
        with pin.using("http://app.test/", ["203.0.113.9"]):
            self.assertEqual(pin.ip_for("http://app.test/"), "203.0.113.9")
            self.assertIsNone(pin.ip_for("http://other.example/"))

    def test_using_empty_ips_is_noop(self):
        with pin.using("http://app.test/", []):
            self.assertIsNone(pin.current())
            self.assertIsNone(pin.ip_for("http://app.test/"))


# =================================================================================================
#  2. httpflow _timed — connexion PAR-IP épinglée
# =================================================================================================
class TestHttpflowPinSocketLayer(unittest.TestCase):
    """Preuve SOCKET : `socket.create_connection` reçoit l'IP épinglée, jamais le hostname re-résolu."""

    def _run_timed(self, target, params):
        captured = {}

        def _fake_create_connection(addr, timeout=None, source_address=None):
            captured["addr"] = addr
            raise OSError("court-circuit après capture (aucune connexion réelle)")

        action = Action("request_smuggling.probe", target, params=params)
        httpflowmod = sys.modules["forge.modules.httpflow"]
        with mock.patch.object(httpflowmod.socket, "create_connection", _fake_create_connection):
            RequestSmugglingProbe._timed(action, "baseline", 8)
        return captured.get("addr")

    def test_connects_to_pinned_ip_not_hostname(self):
        addr = self._run_timed("http://evil.example:8080/", {"_pinned_ips": ["127.0.0.1"]})
        self.assertEqual(addr, ("127.0.0.1", 8080), "doit dialer l'IP ÉPINGLÉE, pas le hostname")

    def test_without_pin_connects_to_hostname(self):
        addr = self._run_timed("http://evil.example:8080/", {})
        self.assertEqual(addr, ("evil.example", 8080), "sans pin : résolution NORMALE (byte-identique)")


class TestHttpflowPinRealServer(unittest.TestCase):
    """Preuve BOUT-EN-BOUT : un target `pinned.invalid` NON RÉSOLVABLE + pin 127.0.0.1 atteint un serveur
    RÉEL sur 127.0.0.1. Si la connexion réussit, c'est QUE le pin a court-circuité la résolution DNS."""

    def test_pinned_reaches_loopback_and_host_header_preserved(self):
        received = {}
        srv = socket.create_server(("127.0.0.1", 0))
        srv.settimeout(5)
        port = srv.getsockname()[1]

        def _serve():
            try:
                conn, _ = srv.accept()
                with conn:
                    conn.settimeout(5)
                    data = conn.recv(4096)
                    received["raw"] = data
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            except Exception:                                     # noqa: BLE001
                pass

        th = threading.Thread(target=_serve, daemon=True)
        th.start()
        try:
            target = f"http://pinned.invalid:{port}/"
            action = Action("request_smuggling.probe", target, params={"_pinned_ips": ["127.0.0.1"]})
            elapsed, status = RequestSmugglingProbe._timed(action, "baseline", 5)
        finally:
            th.join(6)
            srv.close()
        self.assertEqual(status, "ok", "le serveur loopback a répondu -> le pin a bien connecté par-IP")
        self.assertIn(b"Host: pinned.invalid", received.get("raw", b""),
                      "le Host header doit rester l'hôte d'ORIGINE (pas l'IP)")


# =================================================================================================
#  3. Oracle._http — connexion PAR-IP épinglée (serveur RÉEL + preuve socket)
# =================================================================================================
class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    hosts = []

    def do_GET(self):                                             # noqa: N802
        _RecordingHandler.hosts.append(self.headers.get("Host", ""))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):                                    # silencieux
        pass


class TestOracleHttpPinRealServer(unittest.TestCase):
    def setUp(self):
        _RecordingHandler.hosts = []
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), _RecordingHandler)
        self.port = self.httpd.server_address[1]
        self.th = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.th.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.th.join(5)

    def test_pinned_hostname_reaches_loopback(self):
        # `pinned.invalid` ne résout PAS : sans pin, _http échoue. Avec pin -> connecte 127.0.0.1.
        target = f"http://pinned.invalid:{self.port}/"
        with pin.using(target, ["127.0.0.1"]):
            st, body, _hdrs = Oracle._http(target)
        self.assertEqual(st, 200, "le pin a connecté au serveur loopback malgré un hostname non résolvable")
        self.assertEqual(body, "ok")
        self.assertTrue(_RecordingHandler.hosts, "le serveur a reçu la requête")
        self.assertEqual(_RecordingHandler.hosts[-1], f"pinned.invalid:{self.port}",
                         "Host header = hôte d'ORIGINE (pas l'IP)")

    def test_without_pin_unresolvable_host_fails(self):
        # CONTRASTE : sans pin, `pinned.invalid` n'est pas résolvable -> transport échoue (None).
        target = f"http://pinned.invalid:{self.port}/"
        st, body, _hdrs = Oracle._http(target)
        self.assertIsNone(st, "sans pin, aucune connexion (hostname non résolvable) — comportement historique")


class TestOracleHttpPinSocketLayer(unittest.TestCase):
    """Preuve SOCKET fine sur `_pinned_open` : `create_connection` reçoit l'IP épinglée."""

    def test_pinned_open_dials_pinned_ip(self):
        oraclemod = sys.modules["forge.modules.oracle"]
        captured = {}

        def _fake_cc(addr, timeout=None, source_address=None):
            captured["addr"] = addr
            raise OSError("court-circuit après capture")

        import urllib.request
        req = urllib.request.Request("http://evil.example:8080/")
        with mock.patch.object(oraclemod.socket, "create_connection", _fake_cc):
            with self.assertRaises(Exception):                    # URLError enveloppe l'OSError
                Oracle._pinned_open(req, "127.0.0.1", timeout=5)
        self.assertEqual(captured.get("addr"), ("127.0.0.1", 8080))


# =================================================================================================
#  4. HTTPS SNI — server_hostname = hôte d'ORIGINE (validation cert NON affaiblie)
# =================================================================================================
class TestHttpsSniPreserved(unittest.TestCase):
    def test_sni_is_original_host_when_pinned(self):
        oraclemod = sys.modules["forge.modules.oracle"]
        captured = {}

        class _FakeSock:
            def close(self):
                pass

        def _fake_cc(addr, timeout=None, source_address=None):
            captured["addr"] = addr
            return _FakeSock()

        def _fake_wrap(self, sock, server_hostname=None, **kw):
            captured["server_hostname"] = server_hostname
            raise ssl.SSLError("court-circuit après capture du SNI (aucun handshake)")

        import urllib.request
        req = urllib.request.Request("https://secure.invalid/api")
        with mock.patch.object(oraclemod.socket, "create_connection", _fake_cc), \
                mock.patch.object(ssl.SSLContext, "wrap_socket", _fake_wrap):
            with self.assertRaises(Exception):
                Oracle._pinned_open(req, "127.0.0.1", timeout=5)
        self.assertEqual(captured.get("addr"), ("127.0.0.1", 443), "connexion par-IP épinglée")
        self.assertEqual(captured.get("server_hostname"), "secure.invalid",
                         "SNI + validation cert = hôte d'ORIGINE, jamais l'IP")


# =================================================================================================
#  5. Backward-compat — pin absent => _raw_open (byte-identique), jamais de connexion par-IP
# =================================================================================================
class TestBackwardCompatNoPin(unittest.TestCase):
    def test_http_uses_raw_open_when_no_pin(self):
        calls = {"raw": 0, "pinned": 0}
        real_raw = Oracle._raw_open

        class _Resp:
            status = 204
            headers = {}

            def read(self, *a):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def _spy_raw(req, timeout=15):
            calls["raw"] += 1
            return _Resp()

        def _spy_pinned(req, pin_ip, timeout=15):
            calls["pinned"] += 1
            return _Resp()

        with mock.patch.object(Oracle, "_raw_open", staticmethod(_spy_raw)), \
                mock.patch.object(Oracle, "_pinned_open", staticmethod(_spy_pinned)):
            Oracle._http("http://app.test/")                      # AUCUN pin lié
        self.assertEqual(calls["raw"], 1, "sans pin : _raw_open (seam historique monkeypatché par les tests)")
        self.assertEqual(calls["pinned"], 0, "sans pin : JAMAIS _pinned_open")
        _ = real_raw                                              # sanity : le seam d'origine existe


# =================================================================================================
#  6. Wiring moteur — Engine.execute lie pin.using(target, _pinned_ips) autour du fire
# =================================================================================================
class TestEngineBindsPin(unittest.TestCase):
    def test_execute_binds_pin_context_from_decision(self):
        seen = {}

        # module stub : capture l'IP épinglée VUE par le contexte pendant fire (via action.params + pin).
        from forge.modules import registry

        class _PinSpy(registry.Module):
            kind = "pinspy.probe"
            web_allowed = True
            available = True
            mitre = "T9999"

            def dry(self, action):
                return "# dry"

            def fire(self, action):
                seen["params"] = list(action.params.get("_pinned_ips") or [])
                seen["ctx_ip"] = pin.ip_for(action.target)
                return []

        registry.REGISTRY["pinspy.probe"] = _PinSpy
        try:
            sc = Scope({"mode": "grey", "in_scope": ["rebind.example"], "allow_private": False})
            eng = Engine(sc, mode="auto")
            eng.arm("test")
            fake = [(2, 1, 6, "", ("93.184.216.34", 0))]
            with mock.patch.object(sys.modules["forge.roe"].socket, "getaddrinfo", return_value=fake):
                res = eng.execute(Action("pinspy.probe", "rebind.example"))
        finally:
            registry.REGISTRY.pop("pinspy.probe", None)
        self.assertEqual(res["verdict"], FIRE)
        self.assertEqual(seen.get("params"), ["93.184.216.34"], "l'IP résolue est exposée via action.params")
        self.assertEqual(seen.get("ctx_ip"), "93.184.216.34",
                         "Engine.execute a lié pin.using -> le module voit l'IP épinglée par le contexte")


if __name__ == "__main__":
    unittest.main()

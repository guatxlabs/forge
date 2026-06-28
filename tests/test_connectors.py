"""P2 (connecteurs) — Metasploit (msfrpcd) + Burp Suite REST. Hermétique : aucun service RÉEL.

Deux stubs HTTP stdlib (http.server en thread) :
  - _MsfRpcStub  : simule msfrpcd (msgpack-RPC sur POST /api/) — auth.login -> token,
                   module.execute -> {job_id|error}. On décode/encode avec NOTRE codec msgpack
                   (forge.modules.msf) — donc le test prouve aussi la compat fil du codec.
  - _BurpStub    : simule la REST API Burp (POST /v0.1/scan -> Location ; GET /v0.1/scan/{id}
                   -> scan_status + issue_events).

On exerce le VRAI fire() des deux modules contre ces stubs et on prouve :
  - les Findings sont bien construits (titre/sévérité/status/tool corrects) ;
  - les flags de contrat (exploit/destructive/web_allowed) sont corrects ;
  - available() SONDE le service (down quand port mort, up quand le stub répond) — PAS figé.
"""
import os
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action, Scope                         # noqa: E402
from forge.engine import Engine                             # noqa: E402
from forge import modules as mods                           # noqa: E402
from forge.modules import msf as msfmod                     # noqa: E402
from forge.modules import burp as burpmod                   # noqa: E402
from forge.modules.msf import MsfModule, mp_pack, mp_unpack # noqa: E402
from forge.modules.burp import BurpScan                     # noqa: E402


# =============================================================================================
# Contrat des modules (flags) — lus tels que l'engine/le catalogue les liront.
# =============================================================================================
class TestConnectorContract(unittest.TestCase):
    def test_both_registered(self):
        self.assertIn("msf.module", mods.kinds())
        self.assertIn("burp.scan", mods.kinds())

    def test_msf_flags(self):
        m = mods.get("msf.module")
        self.assertTrue(m.exploit)                 # un module MSF peut être un exploit -> exige allow_exploit
        self.assertFalse(m.destructive)
        self.assertFalse(m.web_allowed)            # opérateur opt-in, PAS surface web recon
        self.assertEqual(m.mitre, "T1210")
        self.assertTrue(m.description)

    def test_burp_flags(self):
        b = mods.get("burp.scan")
        self.assertFalse(b.exploit)                # scan actif web -> pas un exploit ciblé
        self.assertFalse(b.destructive)
        self.assertTrue(b.web_allowed)             # activité de scan web in-scope -> plancher web
        self.assertEqual(b.mitre, "T1595.002")
        self.assertTrue(b.description)

    def test_msf_exploit_floor_by_type(self):
        # auxiliary/scanner/post n'ont pas BESOIN d'opt-in fort-impact ; seul 'exploit' l'élève.
        self.assertTrue(MsfModule._exploit_for("exploit"))
        self.assertFalse(MsfModule._exploit_for("auxiliary"))
        self.assertFalse(MsfModule._exploit_for("scanner"))
        self.assertFalse(MsfModule._exploit_for("post"))
        self.assertFalse(MsfModule._exploit_for(None))


# =============================================================================================
# msgpack codec — round-trip + wire-compat (le transport msfrpcd repose dessus).
# =============================================================================================
class TestMsgpackCodec(unittest.TestCase):
    def test_round_trip(self):
        for obj in (None, True, False, 0, 1, 127, -1, -32, 255, 65535, 70000,
                    -200, -40000, "x", "é" * 40, ["a", 1, None],
                    {"token": "t", "result": "success", "job_id": 7}):
            self.assertEqual(mp_unpack(mp_pack(obj)), obj)

    def test_nested(self):
        obj = {"a": [1, {"b": True, "c": None}], "d": "deep"}
        self.assertEqual(mp_unpack(mp_pack(obj)), obj)


# =============================================================================================
# Stub msfrpcd : msgpack-RPC sur POST /api/
# =============================================================================================
class _MsfRpcStub(BaseHTTPRequestHandler):
    CALLS = []                                              # [(method, args...)]
    FAIL_AUTH = False
    EXEC_RESULT = {"job_id": 42, "uuid": "deadbeef", "result": "success"}
    # session.list renvoie cette map. {} = aucune session (exploit lancé mais pas de shell).
    # Pour simuler une compromission RÉELLE, on y met une session corrélée à l'uuid du job.
    SESSIONS = {}

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        req = mp_unpack(body)                              # NOTRE codec décode ce que le client a packé
        method = req[0] if isinstance(req, list) and req else None
        _MsfRpcStub.CALLS.append(tuple(req) if isinstance(req, list) else (req,))
        if method == "auth.login":
            resp = ({"error": True, "error_message": "bad creds"} if _MsfRpcStub.FAIL_AUTH
                    else {"result": "success", "token": "TEMP-TOKEN-123"})
        elif method == "module.execute":
            resp = dict(_MsfRpcStub.EXEC_RESULT)
        elif method == "session.list":
            resp = {str(k): dict(v) for k, v in _MsfRpcStub.SESSIONS.items()}
        else:
            resp = {"error": True, "error_message": f"unknown {method}"}
        payload = mp_pack(resp)
        self.send_response(200)
        self.send_header("Content-Type", "binary/message-pack")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


# =============================================================================================
# Stub Burp REST : POST /v0.1/scan + GET /v0.1/scan/{id}
# =============================================================================================
class _BurpStub(BaseHTTPRequestHandler):
    ISSUES = [{"name": "SQL injection", "severity": "high", "confidence": "certain",
               "origin": "https://app.test", "path": "/q"},
              {"name": "Cacheable HTTPS response", "severity": "info", "origin": "https://app.test"}]
    LAST_SCAN_BODY = {}

    def log_message(self, *a):
        pass

    def _send(self, status, body_bytes, extra_headers=None):
        self.send_response(status)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.endswith("/v0.1/"):                 # sonde available()
            return self._send(200, b'{"version":"2024"}')
        if "/v0.1/scan/" in parsed.path:                   # poll d'un scan
            import json
            events = [{"issue": iss} for iss in _BurpStub.ISSUES]
            body = json.dumps({"scan_status": "succeeded", "issue_events": events}).encode()
            return self._send(200, body)
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if parsed.path.endswith("/v0.1/scan"):             # lancement -> Location avec id
            return self._send(201, b'{"scan_id": 7}',
                              extra_headers={"Location": parsed.path + "/7"})
        return self._send(404, b'{"error":"not found"}')


def _start(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


# =============================================================================================
# Metasploit connector contre le stub msfrpcd
# =============================================================================================
class TestMsfAgainstStub(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.port = _start(_MsfRpcStub)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self):
        _MsfRpcStub.CALLS.clear()
        _MsfRpcStub.FAIL_AUTH = False
        _MsfRpcStub.EXEC_RESULT = {"job_id": 42, "uuid": "deadbeef", "result": "success"}
        _MsfRpcStub.SESSIONS = {}                           # par défaut : aucune session ouverte
        # pointe la config vers le stub local (HTTP, pas SSL)
        os.environ["MSF_RPC_HOST"] = "127.0.0.1"
        os.environ["MSF_RPC_PORT"] = str(self.port)
        os.environ["MSF_RPC_SSL"] = "false"
        os.environ["MSF_RPC_USER"] = "msf"
        os.environ["MSF_RPC_PASS"] = "pw"
        os.environ.pop("MSF_RPC_TOKEN", None)

    def tearDown(self):
        for k in ("MSF_RPC_HOST", "MSF_RPC_PORT", "MSF_RPC_SSL", "MSF_RPC_USER", "MSF_RPC_PASS"):
            os.environ.pop(k, None)

    def _action(self, **params):
        return Action("msf.module", "app.test", params=params)

    def test_available_probes_running_service(self):
        # available() SONDE (TCP connect) — le stub écoute -> True ; pas figé au catalogue.
        self.assertTrue(mods.get("msf.module").available)

    def test_available_false_when_service_down(self):
        os.environ["MSF_RPC_PORT"] = "1"                   # port mort -> connect refusé
        self.assertFalse(mods.get("msf.module").available)

    def test_exploit_with_session_maps_vulnerable_with_proof(self):
        # COMPROMISSION RÉELLE : le poll session.list voit une NOUVELLE session corrélée à l'uuid
        # du job -> PREUVE -> vulnerable, avec le session-id dans l'evidence.
        _MsfRpcStub.SESSIONS = {"3": {"type": "meterpreter", "exploit_uuid": "deadbeef",
                                      "session_host": "10.0.0.5"}}
        f = MsfModule().fire(self._action(
            msf_module="exploit/multi/http/example", msf_type="exploit",
            msf_options={"RHOSTS": "app.test"}, max_polls=3, poll_interval=0))
        self.assertEqual(len(f), 1)
        fin = f[0]
        # transport : auth.login -> session.list (snapshot pré-tir) -> module.execute -> session.list (poll)
        methods = [c[0] for c in _MsfRpcStub.CALLS]
        self.assertEqual(methods[0], "auth.login")
        self.assertIn("module.execute", methods)
        self.assertIn("session.list", methods)
        self.assertLess(methods.index("session.list"), methods.index("module.execute"))  # snapshot d'abord
        # le token retourné est réinjecté dans module.execute
        exec_call = next(c for c in _MsfRpcStub.CALLS if c[0] == "module.execute")
        self.assertEqual(exec_call[1], "TEMP-TOKEN-123")
        self.assertEqual(exec_call[2], "exploit")
        self.assertEqual(exec_call[3], "exploit/multi/http/example")
        # mapping : session obtenue -> vulnerable, sévérité HIGH, session-id en evidence
        self.assertEqual(fin.status, "vulnerable")
        self.assertEqual(fin.severity, "HIGH")
        self.assertIn("exploit/multi/http/example", fin.tool)
        self.assertEqual(fin.mitre, "T1210")
        self.assertIn("session 3", fin.title)
        self.assertIn("session 3", fin.evidence)
        self.assertIn("10.0.0.5", fin.evidence)

    def test_exploit_without_session_is_reported_by_tool_not_vulnerable(self):
        # FIX FAUX-POSITIF : job lancé (job_id rendu) MAIS aucune session dans le budget de poll
        # -> PAS de preuve de shell -> reported_by_tool, JAMAIS vulnerable.
        _MsfRpcStub.SESSIONS = {}                            # aucune session n'apparaît
        f = MsfModule().fire(self._action(
            msf_module="exploit/multi/http/example", msf_type="exploit",
            msf_options={"RHOSTS": "app.test"}, max_polls=2, poll_interval=0))[0]
        self.assertEqual(f.status, "reported_by_tool")      # surtout PAS "vulnerable"
        self.assertNotEqual(f.status, "vulnerable")
        self.assertIn("sans session", f.title)
        self.assertIn("job_id=42", f.evidence)
        # le poll a bien interrogé session.list (au moins une fois après module.execute)
        methods = [c[0] for c in _MsfRpcStub.CALLS]
        self.assertGreaterEqual(methods.count("session.list"), 2)  # snapshot + >=1 poll

    def test_exploit_session_uncorrelated_preexisting_is_ignored(self):
        # Une session PRÉ-EXISTANTE (présente avant le tir, non corrélée à l'uuid) ne doit PAS
        # être prise pour une preuve : sinon faux positif par session d'une autre campagne.
        _MsfRpcStub.SESSIONS = {"1": {"type": "shell", "exploit_uuid": "OTHER-JOB",
                                      "session_host": "192.168.0.9"}}
        f = MsfModule().fire(self._action(
            msf_module="exploit/multi/http/example", msf_type="exploit",
            msf_options={"RHOSTS": "app.test"}, max_polls=2, poll_interval=0))[0]
        # la session 1 existe AVANT module.execute (snapshot la capture) et n'est pas corrélée
        # à l'uuid "deadbeef" -> aucune session nouvelle -> reported_by_tool.
        self.assertEqual(f.status, "reported_by_tool")

    def test_auxiliary_module_is_reported_by_tool_not_vulnerable(self):
        # auxiliary lancé -> reported_by_tool (l'OUTIL a tourné, pas de promotion en vulnerable).
        # Même si des sessions traînent, un auxiliary n'ouvre pas de session -> AUCUN poll.
        _MsfRpcStub.SESSIONS = {"9": {"type": "shell", "exploit_uuid": "deadbeef"}}
        f = MsfModule().fire(self._action(
            msf_module="auxiliary/scanner/http/title", msf_type="auxiliary"))[0]
        self.assertEqual(f.status, "reported_by_tool")
        self.assertEqual(f.severity, "LOW")
        methods = [c[0] for c in _MsfRpcStub.CALLS]
        self.assertNotIn("session.list", methods)           # pas de poll pour un non-exploit

    def test_token_skips_login(self):
        os.environ["MSF_RPC_TOKEN"] = "PERM-TOKEN"
        f = MsfModule().fire(self._action(msf_module="auxiliary/x", msf_type="auxiliary"))[0]
        methods = [c[0] for c in _MsfRpcStub.CALLS]
        self.assertEqual(methods, ["module.execute"])      # pas de auth.login
        self.assertEqual(_MsfRpcStub.CALLS[0][1], "PERM-TOKEN")
        self.assertEqual(f.status, "reported_by_tool")

    def test_framework_error_maps_not_vulnerable(self):
        _MsfRpcStub.EXEC_RESULT = {"error": True, "error_message": "module failed"}
        f = MsfModule().fire(self._action(msf_module="exploit/x", msf_type="exploit"))[0]
        self.assertEqual(f.status, "not_vulnerable")
        self.assertIn("module failed", f.evidence)

    def test_auth_failure_maps_info_finding(self):
        _MsfRpcStub.FAIL_AUTH = True
        f = MsfModule().fire(self._action(msf_module="exploit/x", msf_type="exploit"))[0]
        self.assertEqual(f.severity, "INFO")
        self.assertEqual(f.status, "tested")               # échec RPC -> finding INFO traçable

    def test_missing_module_param(self):
        f = MsfModule().fire(self._action())[0]
        self.assertEqual(f.status, "tested")
        self.assertIn("manquant", f.title)

    def test_dry_builds_call_without_network(self):
        _MsfRpcStub.CALLS.clear()
        s = MsfModule().dry(self._action(msf_module="exploit/y", msf_type="exploit"))
        self.assertIn("module.execute", s)
        self.assertIn("exploit/y", s)
        self.assertEqual(_MsfRpcStub.CALLS, [])            # dry() ne touche pas le réseau

    def test_engine_vetoes_exploit_without_optin(self):
        # gouvernance : msf.module est exploit=True -> SANS allow_exploit, l'engine VETO (jamais fire).
        eng = Engine(Scope({"mode": "grey", "in_scope": ["app.test"]}))  # allow_exploit absent
        eng.arm()
        a = self._action(msf_module="exploit/x", msf_type="exploit"); eng.approve(a.id)
        r = eng.execute(a)
        self.assertEqual(r["verdict"], "VETO")
        self.assertEqual(_MsfRpcStub.CALLS, [])            # aucun appel RPC parti

    def test_poll_budget_bounded_no_wasted_final_sleep(self):
        # BUDGET BORNÉ : sans session, le poll sonde max_polls fois mais ne dort PAS après la
        # dernière sonde (gaspillage d'un `interval` pour rien). On compte les sleeps : exactement
        # max_polls-1, et chaque sleep utilise l'intervalle demandé. Réactivité + temps borné.
        _MsfRpcStub.SESSIONS = {}                            # aucune session n'apparaît jamais
        sleeps = []
        orig_sleep = msfmod.time.sleep
        msfmod.time.sleep = lambda s: sleeps.append(s)       # capture sans dormir réellement
        try:
            f = MsfModule().fire(self._action(
                msf_module="exploit/multi/http/example", msf_type="exploit",
                msf_options={"RHOSTS": "app.test"}, max_polls=4, poll_interval=0.5))[0]
        finally:
            msfmod.time.sleep = orig_sleep
        self.assertEqual(f.status, "reported_by_tool")       # pas de session -> jamais vulnerable
        self.assertEqual(len(sleeps), 3)                     # max_polls-1, pas de sleep final gaspillé
        self.assertTrue(all(s == 0.5 for s in sleeps))       # l'intervalle demandé est respecté


# =============================================================================================
# Burp connector contre le stub REST
# =============================================================================================
class TestBurpAgainstStub(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.port = _start(_BurpStub)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self):
        _BurpStub.ISSUES = [{"name": "SQL injection", "severity": "high", "confidence": "certain",
                             "origin": "https://app.test", "path": "/q"},
                            {"name": "Cacheable HTTPS response", "severity": "info",
                             "origin": "https://app.test"}]
        os.environ["BURP_API_URL"] = f"http://127.0.0.1:{self.port}"
        os.environ.pop("BURP_API_KEY", None)

    def tearDown(self):
        os.environ.pop("BURP_API_URL", None)

    def _action(self, **params):
        params.setdefault("urls", ["https://app.test/"])
        params.setdefault("poll_interval", 0)              # pas d'attente dans les tests
        params.setdefault("max_polls", 2)
        return Action("burp.scan", "https://app.test/", params=params)

    def test_available_probes_running_service(self):
        self.assertTrue(mods.get("burp.scan").available)   # le stub répond sur /v0.1/

    def test_available_false_when_service_down(self):
        os.environ["BURP_API_URL"] = "http://127.0.0.1:1"  # port mort
        self.assertFalse(mods.get("burp.scan").available)

    def test_scan_maps_issues_to_findings(self):
        f = BurpScan().fire(self._action())
        titles = [x.title for x in f]
        self.assertIn("Burp: SQL injection", titles)
        sqli = next(x for x in f if x.title == "Burp: SQL injection")
        self.assertEqual(sqli.severity, "HIGH")
        # politique anti-sur-classement (comme nuclei) : HIGH/MEDIUM/CRIT -> reported_by_tool
        self.assertEqual(sqli.status, "reported_by_tool")
        self.assertIn("burp-rest:scan/7", sqli.tool)
        self.assertEqual(sqli.mitre, "T1595.002")
        # une issue 'info' reste 'tested'
        info = next(x for x in f if "Cacheable" in x.title)
        self.assertEqual(info.severity, "INFO")
        self.assertEqual(info.status, "tested")

    def test_scan_no_issues(self):
        _BurpStub.ISSUES = []
        f = BurpScan().fire(self._action())
        self.assertEqual(len(f), 1)
        self.assertIn("aucune issue", f[0].title)
        self.assertEqual(f[0].status, "tested")

    def test_dry_builds_call_without_network(self):
        s = BurpScan().dry(self._action())
        self.assertIn("/v0.1/scan", s)
        self.assertIn("app.test", s)

    def test_engine_fires_web_scan_with_optin_arm_approve(self):
        # burp.scan est exploit=False/web_allowed=True : in-scope + armé + approuvé -> FIRE.
        eng = Engine(Scope({"mode": "grey", "in_scope": ["app.test"]}))
        eng.arm()
        a = self._action(); eng.approve(a.id)
        r = eng.execute(a)
        self.assertEqual(r["verdict"], "FIRE")
        self.assertTrue(any("Burp:" in fnd.title for fnd in eng.findings))


if __name__ == "__main__":
    unittest.main()

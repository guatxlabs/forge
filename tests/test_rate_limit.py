"""FEATURE B — conscience & contrôle du débit (rate-limit) : throttle scope.rate + drapeaux de débit
par-outil + back-off 429/Retry-After.

Garanties prouvées (zéro I/O réel — horloge/sommeil mockés, `_raw_open` patché) :
  (A) THROTTLE : `Bucket`/`Oracle._http` respectent un min-interval (1/rate) ; rate<=0/absent => no-op.
  (B) DRAPEAUX : `rate` -> nmap --max-rate, nuclei -rl, httpx -rl, naabu -rate, masscan --rate (≠1000),
      feroxbuster --rate-limit, sqlmap/wfuzz/dalfox/gobuster --delay (dérivés) ; absent => aucun drapeau.
  (C) BACK-OFF : un 429 avec Retry-After déclenche un sommeil borné puis un ré-essai ; un 429 PERSISTANT
      marque le bucket (`blocked`) -> l'engine surface « rate-limited ».
  (D) INJECTION MOTEUR : scope.rate injecté aux oracles (throttle) ; aux OUTILS uniquement sur override
      explicite (`rate_explicit`) -> argv byte-identique au défaut sinon.
"""
import io
import sys
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import throttle                                                     # noqa: E402
from forge import modules as mods                                             # noqa: E402
from forge.engine import Engine                                               # noqa: E402
from forge.roe import Action, Scope                                           # noqa: E402
from forge.modules.oracle import Oracle, _MAX_BACKOFF                          # noqa: E402
from forge.modules.toolspec import build_argv                                  # noqa: E402


class _Clock:
    """Seams horloge/sommeil mockés pour throttle : sommeil enregistré, horloge avance du temps dormi."""
    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s

    def now(self):
        return self.t


class _ThrottleSeam:
    def __enter__(self):
        self.saved = (throttle._sleep, throttle._now)
        self.clock = _Clock()
        throttle._sleep, throttle._now = self.clock.sleep, self.clock.now
        return self.clock

    def __exit__(self, *a):
        throttle._sleep, throttle._now = self.saved


# =================================================================================================
class TestBucket(unittest.TestCase):
    def test_min_interval_serializes(self):
        with _ThrottleSeam() as clock:
            b = throttle.Bucket(5)                    # 0.2 s d'intervalle
            self.assertEqual(b.min_interval, 0.2)
            self.assertEqual(b.wait(), 0.0)           # 1er tir : aucun sommeil
            self.assertAlmostEqual(b.wait(), 0.2)     # 2e immédiat : dort 1 intervalle
            self.assertEqual(clock.sleeps, [0.2])

    def test_zero_rate_no_throttle(self):
        with _ThrottleSeam() as clock:
            b = throttle.Bucket(0)
            self.assertEqual(b.min_interval, 0.0)
            self.assertEqual(b.wait(), 0.0)
            self.assertEqual(b.wait(), 0.0)
            self.assertEqual(clock.sleeps, [])

    def test_using_none_when_unset(self):
        self.assertIsNone(throttle.using(0).bucket)
        self.assertIsNone(throttle.using(None).bucket)
        self.assertIsNotNone(throttle.using(3).bucket)


class TestHttpThrottleAndBackoff(unittest.TestCase):
    def _patch_raw(self, fn):
        self._saved_raw = Oracle._raw_open
        Oracle._raw_open = staticmethod(fn)

    def tearDown(self):
        if hasattr(self, "_saved_raw"):
            Oracle._raw_open = self._saved_raw

    def test_http_throttles_between_requests(self):
        class _Resp:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return b"ok"
        self._patch_raw(lambda req, timeout=15: _Resp())
        with _ThrottleSeam() as clock, throttle.using(5):
            Oracle._http("http://good.test")
            Oracle._http("http://good.test")
        self.assertEqual(clock.sleeps, [0.2])         # 2e requête throttlée d'un intervalle

    def test_no_throttle_without_context(self):
        class _Resp:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return b"ok"
        self._patch_raw(lambda req, timeout=15: _Resp())
        with _ThrottleSeam() as clock:                # AUCUN throttle.using -> byte-identique
            Oracle._http("http://good.test")
            Oracle._http("http://good.test")
        self.assertEqual(clock.sleeps, [])

    def test_429_retry_after_backoff_then_marker(self):
        calls = []

        def raise_429(req, timeout=15):
            calls.append(1)
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many", {"Retry-After": "2"}, io.BytesIO(b""))
        self._patch_raw(raise_429)
        with _ThrottleSeam() as clock, throttle.using(0) as bucket:   # rate 0 -> isole le back-off
            st, body, hdrs = Oracle._http("http://good.test")
        self.assertEqual(st, 429)
        self.assertEqual(len(calls), 1 + _MAX_BACKOFF)               # tir initial + ré-essais bornés
        self.assertEqual(clock.sleeps, [2.0] * _MAX_BACKOFF)         # Retry-After honoré (borné cap)
        # rate 0 -> pas de bucket -> pas de marqueur ; on re-teste le marqueur avec un bucket.
        self.assertIsNone(bucket)

    def test_429_marks_bucket_blocked(self):
        self._patch_raw(lambda req, timeout=15: (_ for _ in ()).throw(
            urllib.error.HTTPError(req.full_url, 429, "x", {}, io.BytesIO(b""))))
        with _ThrottleSeam(), throttle.using(1000) as bucket:        # rate haut -> throttle négligeable
            st, _, _ = Oracle._http("http://good.test")
        self.assertEqual(st, 429)
        self.assertEqual(bucket.blocked, 1)                          # 429 persistant marqué


class TestNativeRateFlags(unittest.TestCase):
    def test_nmap_max_rate(self):
        m = mods.get("recon.nmap")
        argv = m._args(Action("recon.nmap", "scan.test", params={"rate": 50}))
        self.assertIn("--max-rate", argv)
        self.assertIn("50", argv)

    def test_nmap_no_rate_flag_by_default(self):
        m = mods.get("recon.nmap")
        argv = m._args(Action("recon.nmap", "scan.test", params={}))
        self.assertNotIn("--max-rate", argv)          # byte-identique : aucun drapeau de débit

    def test_nuclei_rl(self):
        m = mods.get("web.nuclei")
        argv = m._args(Action("web.nuclei", "http://scan.test", params={"rate": 20}))
        self.assertIn("-rl", argv)
        self.assertIn("20", argv)

    def test_httpx_rl(self):
        m = mods.get("recon.httpx")
        argv = m._args(Action("recon.httpx", "scan.test", params={"rate": 7}))
        self.assertIn("-rl", argv)
        self.assertIn("7", argv)


class TestWrapperRateFlags(unittest.TestCase):
    def _spec(self, kind):
        return mods.get(kind).spec

    def test_masscan_override_replaces_1000(self):
        argv = build_argv(self._spec("recon.masscan"), "host.test", {"rate": 500})
        self.assertIn("500", argv)
        self.assertNotIn("1000", argv)

    def test_masscan_default_keeps_1000(self):
        argv = build_argv(self._spec("recon.masscan"), "host.test", {})
        self.assertIn("1000", argv)                   # byte-identique : défaut masscan préservé

    def test_naabu_rate(self):
        argv = build_argv(self._spec("recon.naabu"), "host.test", {"rate": 30})
        self.assertIn("-rate", argv)
        self.assertIn("30", argv)

    def test_feroxbuster_rate_limit(self):
        argv = build_argv(self._spec("recon.feroxbuster"), "http://host.test", {"rate": 12})
        self.assertIn("--rate-limit", argv)
        self.assertIn("12", argv)

    def test_delay_tools_use_derived_param(self):
        # sqlmap --delay (secondes), dalfox --delay (ms) — pilotés par les dérivées d'unité.
        argv = build_argv(self._spec("sqli.sqlmap"), "http://host.test/?id=1",
                          {"rate_delay_s": "0.200"})
        self.assertIn("--delay", argv)
        self.assertIn("0.200", argv)
        argv2 = build_argv(self._spec("xss.dalfox"), "http://host.test/?q=1",
                           {"rate_delay_ms": "200"})
        self.assertIn("--delay", argv2)
        self.assertIn("200", argv2)

    def test_no_rate_no_flag(self):
        for kind, flag in (("recon.naabu", "-rate"), ("recon.feroxbuster", "--rate-limit"),
                           ("sqli.sqlmap", "--delay")):
            argv = build_argv(self._spec(kind), "http://host.test", {})
            self.assertNotIn(flag, argv, f"{kind} ne doit pas émettre {flag} sans rate")


class TestEngineRateInjection(unittest.TestCase):
    def _scope(self, **extra):
        d = {"mode": "grey", "in_scope": ["scan.test"], "allow_exploit": True}
        d.update(extra)
        return Scope(d)

    def _prepare(self, scope, kind):
        eng = Engine(scope)
        actions = [Action(kind, "scan.test")]
        return eng._prepare(actions, None, {}, {})[0]

    def test_oracle_gets_scope_rate(self):
        a = self._prepare(self._scope(rate=8), "access_control.idor")
        self.assertEqual(a.params.get("rate"), 8)     # oracle throttlé au débit du scope
        self.assertIn("rate_delay_s", a.params)       # dérivées d'unité présentes

    def test_tool_no_rate_without_explicit(self):
        a = self._prepare(self._scope(rate=8), "recon.nmap")
        self.assertIsNone(a.params.get("rate"))       # OUTIL : pas d'injection sans override -> byte-identique

    def test_tool_gets_rate_with_explicit(self):
        a = self._prepare(self._scope(rate=8, rate_explicit=True), "recon.nmap")
        self.assertEqual(a.params.get("rate"), 8)     # override explicite -> l'outil reçoit le débit


if __name__ == "__main__":
    unittest.main()

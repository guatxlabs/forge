"""LOT ORACLES — oracles à PREUVE self-contained (ssrf.callback, auth.takeover, cors.credentials).

Contrat commun (calqué sur access_control.idor) :
  - PREUVE obtenue  -> status='vulnerable' + sévérité HIGH/CRITICAL ;
  - PAS de preuve    -> status='tested' (jamais 'vulnerable' à l'aveugle) ;
  - config manquante -> finding INFO 'non testé', jamais de réseau ;
  - flags exploit/destructive/web_allowed cohérents ; mitre NON VIDE par défaut.

Tous les tests sont HERMÉTIQUES : on monkeypatch le `_fetch` de chaque module (zéro réseau).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                          # noqa: E402
from forge import modules as mods                            # noqa: E402
from forge import purple                                     # noqa: E402
from forge.modules.ssrf import SsrfCallback                  # noqa: E402
from forge.modules.auth import AuthTakeover                  # noqa: E402
from forge.modules.cors import CorsCredentials               # noqa: E402


def _patch(cls, fn):
    """Remplace cls._fetch par fn (staticmethod) et renvoie un restaurateur."""
    orig = cls._fetch
    cls._fetch = staticmethod(fn)
    return lambda: setattr(cls, "_fetch", orig)


class TestModuleRegistration(unittest.TestCase):
    KINDS = ("ssrf.callback", "auth.takeover", "cors.credentials")

    def test_all_registered(self):
        for k in self.KINDS:
            self.assertIn(k, mods.kinds())

    def test_default_mitre_non_empty(self):
        # chaque nouveau kind a un repli ATT&CK non vide (contrat FORGE-MITRE)
        for k in self.KINDS:
            self.assertTrue(purple.mitre_for_kind(k), f"{k} a un repli mitre vide")
            self.assertTrue(mods.get(k).mitre, f"{k} a un mitre de module vide")

    def test_distinct_techniques(self):
        # techniques ATT&CK distinctes et justes (pas de copier-coller)
        self.assertEqual(mods.get("ssrf.callback").mitre, "T1190")
        self.assertEqual(mods.get("auth.takeover").mitre, "T1212")
        self.assertEqual(mods.get("cors.credentials").mitre, "T1539")

    def test_capability_flags_coherent(self):
        # tous les oracles d'exploitation -> exploit=True (derrière l'opt-in fort-impact du ROE)
        for k in self.KINDS:
            self.assertTrue(mods.get(k).exploit, f"{k} devrait être exploit=True")
            self.assertTrue(getattr(mods.get(k), "web_allowed", False), f"{k} devrait être web_allowed")
        # destructif : seul l'ATO (reset/forge de credential mute la victime) est destructif
        self.assertTrue(mods.get("auth.takeover").destructive)
        self.assertFalse(mods.get("ssrf.callback").destructive)
        self.assertFalse(mods.get("cors.credentials").destructive)

    def test_dry_emits_no_finding_shape_and_mentions_token(self):
        a = Action("ssrf.callback", "https://app.test/fetch",
                   params={"param": "url", "callback_base": "http://cb.test",
                           "callback_check_url": "http://cb.test/seen"})
        s = mods.get("ssrf.callback").dry(a)
        self.assertIn("forge", s)            # le token déterministe apparaît dans le dry


class TestSsrfCallbackOracle(unittest.TestCase):
    BASE = {"param": "url", "callback_base": "http://cb.test",
            "callback_check_url": "http://cb.test/seen"}

    def _fire(self, target_resp, check_resp):
        """target_resp/check_resp : (status, body) renvoyés par _fetch selon l'URL."""
        token = SsrfCallback._token("https://app.test/fetch", "url")
        calls = {"injected": False}

        def fake_fetch(url, headers=None, timeout=15, method="GET", data=None):
            if "cb.test/seen" in url:
                return check_resp
            calls["injected"] = True
            return target_resp

        restore = _patch(SsrfCallback, fake_fetch)
        try:
            f = SsrfCallback().fire(Action("ssrf.callback", "https://app.test/fetch", params=self.BASE))
            return f, token, calls
        finally:
            restore()

    def test_vulnerable_when_callback_received(self):
        token = SsrfCallback._token("https://app.test/fetch", "url")
        f, _, calls = self._fire((200, "ok"), (200, f"seen ids: {token}"))
        self.assertTrue(calls["injected"])               # la cible a bien été sollicitée
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertIn("SSRF CONFIRMÉ", f[0].title)
        self.assertEqual(f[0].mitre, "T1190")

    def test_tested_when_no_callback(self):
        # collecteur n'a PAS vu le token -> jamais de verdict aveugle -> tested
        f, _, _ = self._fire((200, "ok"), (200, "no callbacks here"))
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("aucun callback reçu", f[0].title)

    def test_tested_when_collector_error(self):
        f, _, _ = self._fire((200, "ok"), (None, ""))       # collecteur injoignable
        self.assertEqual(f[0].status, "tested")

    def test_missing_config_is_info_skip(self):
        f = SsrfCallback().fire(Action("ssrf.callback", "https://app.test", params={"param": "url"}))
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)


class TestAuthTakeoverOracle(unittest.TestCase):
    def _fire(self, whoami_resp, params):
        def fake_fetch(url, headers=None, timeout=15, method="GET", data=None):
            return whoami_resp                               # whoami (et bypass) -> même stub
        restore = _patch(AuthTakeover, fake_fetch)
        try:
            return AuthTakeover().fire(Action("auth.takeover", "https://app.test", params=params))
        finally:
            restore()

    def test_vulnerable_when_whoami_is_victim(self):
        # whoami renvoie l'identité VICTIME (et pas l'attaquant) -> ATO prouvé
        f = self._fire(
            (200, '{"email":"victim@corp.test","id":777}', {}),
            {"whoami_url": "https://app.test/me", "victim_marker": "victim@corp.test",
             "attacker_marker": "attacker@corp.test",
             "attacker_session_headers": {"Cookie": "s=forged"}})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertIn("ATO CONFIRMÉ", f[0].title)
        self.assertEqual(f[0].mitre, "T1212")

    def test_tested_when_whoami_is_attacker_self(self):
        # whoami ne renvoie QUE l'attaquant -> on lit sa propre session -> faux positif évité -> tested
        f = self._fire(
            (200, '{"email":"attacker@corp.test"}', {}),
            {"whoami_url": "https://app.test/me", "victim_marker": "victim@corp.test",
             "attacker_marker": "attacker@corp.test"})
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")

    def test_tested_when_whoami_denied(self):
        f = self._fire(
            (401, "", {}),
            {"whoami_url": "https://app.test/me", "victim_marker": "victim@corp.test"})
        self.assertEqual(f[0].status, "tested")

    def test_victim_present_and_no_attacker_marker_is_proof(self):
        # sans attacker_marker fourni : la présence du marqueur victime suffit
        f = self._fire(
            (200, "Welcome, victim@corp.test", {}),
            {"whoami_url": "https://app.test/me", "victim_marker": "victim@corp.test"})
        self.assertEqual(f[0].status, "vulnerable")

    def test_missing_config_is_info_skip(self):
        f = AuthTakeover().fire(Action("auth.takeover", "https://app.test", params={}))
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)


class TestCorsCredentialsOracle(unittest.TestCase):
    TGT = "https://api.app.test/account"
    ORIGIN = "https://attacker.example"

    def _fire(self, resp, params=None):
        def fake_fetch(url, headers=None, timeout=15):
            return resp
        restore = _patch(CorsCredentials, fake_fetch)
        try:
            p = {"attacker_origin": self.ORIGIN}
            if params:
                p.update(params)
            return CorsCredentials().fire(Action("cors.credentials", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_when_origin_reflected_with_credentials(self):
        f = self._fire((200, '{"balance":42}', {
            "access-control-allow-origin": self.ORIGIN,
            "access-control-allow-credentials": "true"}))
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertIn("CORS exploitable", f[0].title)
        self.assertEqual(f[0].mitre, "T1539")

    def test_critical_when_session_marker_present(self):
        f = self._fire((200, '{"email":"victim@corp.test"}', {
            "access-control-allow-origin": self.ORIGIN,
            "access-control-allow-credentials": "true"}),
            params={"session_marker": "victim@corp.test",
                    "auth_headers": {"Cookie": "s=victim"}})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "CRITICAL")

    def test_tested_when_wildcard_origin(self):
        # ACAO='*' + credentials est refusé par les navigateurs -> non exploitable -> tested
        f = self._fire((200, "{}", {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true"}))
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")

    def test_tested_when_no_credentials(self):
        # reflet de l'origine mais SANS credentials -> non exploitable (pas de session lisible) -> tested
        f = self._fire((200, "{}", {
            "access-control-allow-origin": self.ORIGIN}))
        self.assertEqual(f[0].status, "tested")

    def test_missing_config_is_info_skip(self):
        f = CorsCredentials().fire(Action("cors.credentials", self.TGT, params={}))
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)


if __name__ == "__main__":
    unittest.main(verbosity=2)

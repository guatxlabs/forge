"""LOT CLIENT-FLOW — oracles de VÉRIFICATION client-side / flux de requête à PREUVE MINIMALE
(`xss.reflected`, `redirect.open`, `csrf.state_change`).

Contrat commun (calqué sur les oracles à preuve existants + garde-fous de la tâche) :
  (1) SCOPE-GUARD : une cible hors périmètre est REFUSÉE avant tout réseau (`status='skipped'`,
      AUCUNE requête émise — le seam `_fetch` monkeypatché lève si appelé) ;
  (2) PREUVE MINIMALE, BÉNIGNE & IMPACTANTE : une fixture positive -> `status='vulnerable'` avec preuve
      concrète ET réellement impactante (reflet exécutable non échappé / redirection attaquant chaînée /
      action critique sans contrôle) ; une fixture négative (reflet échappé, redirection non chaînée,
      action non critique, contrôle présent) -> `status='tested'` (jamais de verdict à l'aveugle) ;
  (3) NON DESTRUCTIF : exploit=False, destructive=False ; redirections NON suivies ; probe CSRF = GET seul ;
  (4) SESSION SECRÈTE : le matériel d'auth gouverné attaché aux requêtes IN-SCOPE ne fuite ni dans
      l'evidence ni dans le PoC du finding ;
  (5) DÉGRADATION GRACIEUSE : réseau indisponible -> `status='skipped'` (offline-safe).

Tous les tests sont HERMÉTIQUES : on monkeypatch le `_fetch` de chaque module (zéro réseau), sauf le
test de secret de session qui monkeypatch `urllib.request.urlopen` pour capturer les en-têtes sortants.
"""
import email.message
import html
import io
import json
import sys
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                     # noqa: E402
from forge import modules as mods                                # noqa: E402
from forge import techniques                                     # noqa: E402
from forge import cli                                            # noqa: E402
from forge import session as sessionmod                          # noqa: E402
from forge.roe import Scope                                      # noqa: E402
from forge.session import SessionStore                           # noqa: E402
from forge.modules.oracle import Oracle, ScopeGuardedOracle      # noqa: E402
from forge.modules.clientflow import (                           # noqa: E402
    ClientFlowOracle, XssReflected, OpenRedirect, CsrfStateChange, _XSS_PROBE)

SECRET = "S3CR3T-cf-9d1e0f"                                      # jeton témoin de session, cherché partout


def _patch(cls, fn):
    """Remplace cls._fetch par fn (staticmethod) et renvoie un restaurateur.

    `_fetch` est un @staticmethod HÉRITÉ de ClientFlowOracle (aucune sous-classe ne le redéfinit). On
    lit le DESCRIPTEUR BRUT via `cls.__dict__` (et non `cls._fetch`, qui déréférence le staticmethod en
    fonction nue) : la restauration doit soit reposer le descripteur d'origine, soit — si la sous-classe
    n'avait pas d'override propre — SUPPRIMER l'attribut pour restaurer l'héritage. Sans ça, `setattr`
    reposait une fonction NUE sur la sous-classe : `self._fetch(...)` la liait alors comme méthode
    d'instance (self capturé en 1er positionnel) -> `TypeError: got multiple values for argument
    'headers'` polluant les tests suivants (ex: TestSessionSecrecy) qui ne repatchent pas `_fetch`."""
    orig = cls.__dict__.get("_fetch")            # descripteur staticmethod propre à cls, ou None si hérité
    cls._fetch = staticmethod(fn)

    def restore():
        if orig is None:
            del cls._fetch                       # retire l'override -> restaure le staticmethod hérité
        else:
            setattr(cls, "_fetch", orig)         # repose le descripteur d'origine tel quel
    return restore


def _boom(*a, **k):
    raise AssertionError("réseau émis alors qu'aucun ne devait l'être (scope-guard / config)")


# =================================================================================================
class TestClientFlowRegistration(unittest.TestCase):
    KINDS = ("xss.reflected", "redirect.open", "csrf.state_change")

    def test_all_registered(self):
        for k in self.KINDS:
            self.assertIn(k, mods.kinds())
            self.assertIsInstance(mods.get(k), ClientFlowOracle, f"{k} devrait hériter de ClientFlowOracle")
            self.assertIsInstance(mods.get(k), ScopeGuardedOracle, f"{k} devrait hériter de ScopeGuardedOracle")
            self.assertIsInstance(mods.get(k), Oracle, f"{k} devrait hériter d'Oracle")

    def test_mitre_and_cwe_match_table(self):
        # aucune dérive : le module déclare EXACTEMENT le mitre/cwe de la table unique (techniques.py).
        for k in self.KINDS:
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")
            self.assertEqual(mods.get(k).cwe, techniques.cwe_for(k), f"cwe dérive pour {k}")
        self.assertEqual(mods.get("xss.reflected").cwe, "CWE-79")
        self.assertEqual(mods.get("xss.reflected").mitre, "T1059")
        self.assertEqual(mods.get("redirect.open").cwe, "CWE-601")
        self.assertEqual(mods.get("csrf.state_change").cwe, "CWE-352")

    def test_capability_flags_benign_non_destructive(self):
        for k in self.KINDS:
            m = mods.get(k)
            self.assertFalse(m.exploit, f"{k} est une sonde bénigne -> exploit=False")
            self.assertFalse(m.destructive, f"{k} lecture/vérif seule -> destructive=False")
            self.assertTrue(getattr(m, "web_allowed", False), f"{k} devrait être web_allowed")

    def test_catalog_phase_and_capability(self):
        for k in self.KINDS:
            t = techniques.technique_for(k)
            self.assertIsNotNone(t, k)
            self.assertEqual(t.phase, "access", k)
            self.assertEqual(t.capability, "active", k)
            self.assertTrue(t.proof_required, f"{k} doit exiger une preuve pour être promu")
            self.assertIn(k, techniques.by_capability("active"))
            self.assertIn(k, techniques.by_phase("access"))

    def test_listed_in_cli_modules_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_modules(type("A", (), {"json": True})())
        self.assertEqual(rc, 0)
        rows = {r["kind"]: r for r in json.loads(buf.getvalue())}
        for k in self.KINDS:
            self.assertIn(k, rows, f"{k} absent de `forge modules --json`")
            self.assertTrue(rows[k]["web_allowed"], k)
            self.assertFalse(rows[k]["exploit"], k)


# =================================================================================================
class TestXssReflectedOracle(unittest.TestCase):
    TGT = "https://app.test/search"
    BASE = {"param": "q", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None, target=None):
        restore = _patch(XssReflected, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return XssReflected().fire(Action("xss.reflected", target or self.TGT, params=p))
        finally:
            restore()

    def _marker(self):
        return XssReflected._marker(self.TGT, "q", "xss")

    def test_vulnerable_in_script_context(self):
        marker = self._marker()

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            # marqueur réfléchi NON échappé DANS un bloc <script> -> contexte JS-exécutable
            return (200, f"<html><script>var t={marker}{_XSS_PROBE};</script></html>", [])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-79")
        self.assertEqual(f[0].mitre, "T1059")
        self.assertIn("CONFIRMÉ", f[0].title)
        self.assertIn("script", f[0].title)
        # NOTE d'honnêteté : exécution/chaînabilité renvoyées au module navigateur/évasion.
        self.assertIn("navigateur/évasion", f[0].evidence)

    def test_vulnerable_in_event_handler_context(self):
        marker = self._marker()

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (200, f"<a href=\"#\" onclick=\"log('{marker}{_XSS_PROBE}')\">x</a>", [])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("event-handler", f[0].title)

    def test_vulnerable_in_dom_sink_context(self):
        marker = self._marker()

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            # reflet NON échappé à portée d'un DOM sink connu (location.href), hors <script>/on*=
            return (200, f"config: location.href={marker}{_XSS_PROBE} ;", [])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("dom-sink", f[0].title)

    def test_tested_when_reflection_escaped(self):
        marker = self._marker()

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            # l'app ÉCHAPPE la ponctuation -> le marqueur revient mais neutralisé (aucun char brut).
            return (200, f"<script>var t='{html.escape(marker + _XSS_PROBE, quote=True)}';</script>", [])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non confirmé", f[0].title)

    def test_tested_when_reflection_in_non_executable_html_context(self):
        marker = self._marker()

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            # reflet NON échappé mais en contenu HTML visible (PAS un contexte JS-exécutable) -> tested.
            return (200, f"<p>Résultats pour : {marker}{_XSS_PROBE}</p>", [])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucun", f[0].evidence)             # contexte_exécutable=aucun

    def test_scope_guard_out_of_scope(self):
        f = self._fire(_boom, params={"in_scope": ["app.test"]}, target="https://evil.example/x")
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        restore = _patch(XssReflected, _boom)
        try:
            f = XssReflected().fire(Action("xss.reflected", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)

    def test_network_unavailable_degrades_to_skipped(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (None, "", [])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)

    def test_marker_deterministic_and_benign(self):
        m1 = XssReflected._marker(self.TGT, "q", "xss")
        m2 = XssReflected._marker(self.TGT, "q", "xss")
        self.assertEqual(m1, m2)                           # reproductible
        self.assertTrue(m1.startswith("forge") and m1.isalnum())   # marqueur bénin (alphanumérique)
        self.assertNotEqual(XssReflected._marker(self.TGT, "other", "xss"), m1)


# =================================================================================================
class TestOpenRedirectOracle(unittest.TestCase):
    TGT = "https://app.test/go"
    BASE = {"param": "next", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None, target=None):
        restore = _patch(OpenRedirect, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return OpenRedirect().fire(Action("redirect.open", target or self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_when_controllable_and_chainable_explicit(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            # NON DESTRUCTIF / SÛRETÉ : l'oracle ne DOIT PAS suivre la redirection (hôte attaquant).
            assert follow_redirects is False, "l'oracle open-redirect doit demander follow_redirects=False"
            return (302, "", [("Location", "https://attacker.example/x")])
        f = self._fire(fake, params={"attacker_url": "https://attacker.example/x", "chainable": True})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-601")
        self.assertIn("CONFIRMÉ", f[0].title)

    def test_vulnerable_via_sensitive_flow_context(self):
        tgt = "https://app.test/oauth/authorize"
        marker = OpenRedirect._marker(tgt, "redirect_uri", "redir")
        attacker = f"https://forge-redirect.example/{marker}"

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (302, "", [("Location", attacker)])
        # contexte OAuth détecté dans la cible -> chaînable sans affirmation opérateur.
        f = self._fire(fake, params={"param": "redirect_uri"}, target=tgt)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("oauth", f[0].evidence.lower())

    def test_vulnerable_via_client_side_meta_refresh(self):
        tgt = "https://app.test/sso/callback"
        marker = OpenRedirect._marker(tgt, "returnTo", "redir")
        attacker = f"https://forge-redirect.example/{marker}"

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (200, f'<meta http-equiv="refresh" content="0;url={attacker}">', [])
        f = self._fire(fake, params={"param": "returnTo"}, target=tgt)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("client-side", f[0].evidence)

    def test_tested_when_controllable_but_not_chainable(self):
        # redirection ouverte SIMPLE (aucun sink sensible, aucune affirmation) -> reste tested.
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            marker = OpenRedirect._marker(self.TGT, "next", "redir")
            return (302, "", [("Location", f"https://forge-redirect.example/{marker}")])
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("NON chaînée", f[0].title)

    def test_tested_when_not_attacker_controllable(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            # la cible NE redirige PAS vers l'hôte attaquant -> non contrôlable.
            return (302, "", [("Location", "https://app.test/home")])
        f = self._fire(fake, params={"chainable": True})
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)

    def test_scope_guard_out_of_scope(self):
        f = self._fire(_boom, target="https://evil.example/x")
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        restore = _patch(OpenRedirect, _boom)
        try:
            f = OpenRedirect().fire(Action("redirect.open", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)

    def test_network_unavailable_degrades_to_skipped(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (None, "", [])
        f = self._fire(fake, params={"chainable": True})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)


# =================================================================================================
class TestCsrfStateChangeOracle(unittest.TestCase):
    TGT = "https://app.test/account/password"
    BASE = {"in_scope": ["app.test"]}

    def _fire(self, fake, params=None, target=None):
        restore = _patch(CsrfStateChange, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return CsrfStateChange().fire(Action("csrf.state_change", target or self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_critical_no_csrf_no_samesite(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            # NON DESTRUCTIF : le probe DOIT être un GET (aucune requête mutante).
            assert method == "GET", "le probe CSRF doit être un GET non destructif"
            return (200, "<form action='/account/password'><input name='new'></form>",
                    [("Set-Cookie", "session=abc; Path=/; HttpOnly")])
        f = self._fire(fake, params={"critical": True})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-352")
        self.assertIn("CONFIRMÉ", f[0].title)
        self.assertIn("NON DESTRUCTIF", f[0].evidence)

    def test_vulnerable_critical_detected_from_action_hint(self):
        # la criticité est détectée depuis params.action (satisfait aussi la config) sans params.critical.
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (200, "<form><input name='new'></form>", [("Set-Cookie", "sid=xyz; Path=/")])
        f = self._fire(fake, params={"action": "password_change"})
        self.assertEqual(f[0].status, "vulnerable")

    def test_vulnerable_via_operator_set_cookie_sample(self):
        # le SameSite est prouvé absent depuis un échantillon Set-Cookie fourni par l'opérateur.
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (200, "<form><input name='new'></form>", [])   # aucun Set-Cookie dans le probe
        f = self._fire(fake, params={"critical": True, "set_cookie": "sid=xyz; Path=/",
                                     "session_cookie": "sid"})
        self.assertEqual(f[0].status, "vulnerable")

    def test_tested_when_samesite_present(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (200, "<form><input name='new'></form>",
                    [("Set-Cookie", "session=abc; SameSite=Lax; HttpOnly")])
        f = self._fire(fake, params={"critical": True})
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non promu", f[0].title.lower())

    def test_tested_when_csrf_token_present(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (200, "<form><input type='hidden' name='csrfmiddlewaretoken' value='t'></form>",
                    [("Set-Cookie", "session=abc; Path=/")])
        f = self._fire(fake, params={"critical": True})
        self.assertEqual(f[0].status, "tested")

    def test_tested_when_action_declared_non_critical(self):
        # tout absent MAIS action déclarée NON critique -> reste tested (règle: CSRF only if critical).
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (200, "<form><input name='x'></form>", [("Set-Cookie", "session=abc; Path=/")])
        f = self._fire(fake, params={"critical": False})
        self.assertEqual(f[0].status, "tested")

    def test_tested_when_samesite_unconfirmed(self):
        # aucun Set-Cookie observable -> absence de SameSite NON confirmée -> pas de promotion (tested).
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (200, "<form><input name='new'></form>", [])
        f = self._fire(fake, params={"critical": True})
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmée", f[0].evidence.lower())

    def test_scope_guard_out_of_scope(self):
        f = self._fire(_boom, params={"critical": True}, target="https://evil.example/x")
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        # ni params.critical ni params.action -> l'action n'est pas caractérisée -> skip (aucun réseau).
        restore = _patch(CsrfStateChange, _boom)
        try:
            f = CsrfStateChange().fire(Action("csrf.state_change", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)

    def test_network_unavailable_degrades_to_skipped(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (None, "", [])
        f = self._fire(fake, params={"critical": True})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)


# =================================================================================================
class TestSessionSecrecy(unittest.TestCase):
    """Garde-fou (4) : le matériel d'auth gouverné, attaché aux requêtes IN-SCOPE par `Oracle._http`,
    ne fuite JAMAIS dans l'evidence ni le PoC du finding. On exerce le VRAI chemin `_http` (urlopen
    monkeypatché) : le secret DOIT être attaché à la requête in-scope mais ABSENT du finding."""

    class _Capture:
        def __init__(self):
            self.by_url = {}

        def __call__(self, req, timeout=None, *a, **k):
            self.by_url[req.full_url] = " ".join(str(v) for v in req.headers.values())
            raise urllib.error.URLError("captured (no network in test)")

    def test_session_material_attached_but_not_leaked(self):
        cap = self._Capture()
        scope = Scope({"in_scope": ["app.test"]})
        store = SessionStore(scope, default={"bearer": SECRET})
        with patch("forge.modules.oracle.Oracle._raw_open", cap), sessionmod.using(store):
            f = XssReflected().fire(Action("xss.reflected", "https://app.test/search",
                                           params={"param": "q", "in_scope": ["app.test"]}))
        # le secret a bien été attaché à AU MOINS une requête in-scope (session gouvernée active)
        self.assertTrue(any(SECRET in v for v in cap.by_url.values()),
                        "le matériel de session aurait dû être attaché aux requêtes in-scope")
        # ... mais il ne fuite NULLE PART dans le finding (evidence / poc / title)
        for fd in f:
            blob = f"{fd.title} {fd.evidence} {fd.poc}"
            self.assertNotIn(SECRET, blob, "le secret de session a fuité dans le finding")


# =================================================================================================
class _FakeResp:
    def __init__(self, status, body, headers):
        self.status = status
        self._body = body.encode("utf-8")
        m = email.message.Message()
        for k, v in headers:
            m[k] = v
        self.headers = m

    def read(self, n=-1):
        return self._body[:n] if (n is not None and n >= 0) else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestNoFollowHttpWiring(unittest.TestCase):
    """Le VRAI chemin `Oracle._http(follow_redirects=False)` : la 3xx est LUE sans être suivie (sûreté +
    scope), via un opener local `_NoRedirect` — JAMAIS via le seam global `urllib.request.urlopen`."""

    def test_no_follow_reads_location_without_touching_urlopen(self):
        opened = {}

        class _FakeOpener:
            def open(self, req, timeout=None):
                opened["url"] = req.full_url
                return _FakeResp(302, "", [("Location", "https://attacker.example/x")])

        def _boom_urlopen(*a, **k):
            raise AssertionError("follow_redirects=False ne doit PAS passer par urllib.request.urlopen")

        with patch("urllib.request.build_opener", return_value=_FakeOpener()) as bo, \
                patch("urllib.request.urlopen", _boom_urlopen):
            st, body, pairs = ClientFlowOracle._fetch("https://app.test/go?next=x", follow_redirects=False)
        self.assertTrue(bo.called, "l'opener no-follow (build_opener) aurait dû être utilisé")
        self.assertEqual(st, 302)
        self.assertEqual(ClientFlowOracle._get(pairs, "Location"), "https://attacker.example/x")
        self.assertEqual(opened["url"], "https://app.test/go?next=x")


if __name__ == "__main__":
    unittest.main(verbosity=2)

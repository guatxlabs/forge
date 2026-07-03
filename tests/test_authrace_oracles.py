"""LOT AUTH-FLOW / RACE — oracles de VÉRIFICATION `race.condition` (Race/TOCTOU) et `oauth.flow`
(faiblesses de flux OAuth/OIDC).

Contrat commun (calqué sur les oracles à preuve existants + garde-fous de la tâche) :
  (1) SCOPE-GUARD : une cible hors périmètre est REFUSÉE avant tout réseau (`status='skipped'`, AUCUNE
      requête émise — le seam `_fetch` monkeypatché lève s'il est appelé) ;
  (2) PREUVE MINIMALE, BÉNIGNE & COMPTE/FLUX-OPÉRATEUR : une fixture positive (quota d'usage limité
      DÉPASSÉ sur la ressource PROPRE / redirect_uri attaquant accepté ET chaînable / code émis sans
      state/PKCE) -> `status='vulnerable'` ; une fixture négative -> `status='tested'` (jamais de verdict
      à l'aveugle). JAMAIS un tiers ;
  (3) NON DESTRUCTIF / BORNÉ : exploit=False, destructive=False ; la rafale race est PLAFONNÉE (jamais un
      DoS) ; oauth ne suit PAS les redirections ;
  (4) DÉGRADATION GRACIEUSE : transport indisponible -> `status='skipped'` (offline-safe) ;
  (5) MEMBERSHIP : profils/vuln_class dérivés de la table unique (`forge/techniques.py`).

Tests HERMÉTIQUES : on monkeypatch le `_fetch` de chaque module (zéro réseau).
"""
import io
import json
import sys
import threading
import unittest
import urllib.parse
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                     # noqa: E402
from forge import modules as mods                                # noqa: E402
from forge import techniques                                     # noqa: E402
from forge import cli                                            # noqa: E402
from forge.modules.oracle import Oracle, ScopeGuardedOracle      # noqa: E402
from forge.modules.clientflow import ClientFlowOracle            # noqa: E402
from forge.modules import race as racemod                        # noqa: E402
from forge.modules.race import RaceCondition                     # noqa: E402
from forge.modules.oauth import OAuthFlow                        # noqa: E402


def _patch(cls, fn):
    """Remplace cls._fetch par fn (staticmethod) et restaure PROPREMENT (delattr si hérité)."""
    had = "_fetch" in cls.__dict__
    orig = cls.__dict__.get("_fetch")
    cls._fetch = staticmethod(fn)

    def restore():
        if had:
            cls._fetch = orig
        else:
            try:
                delattr(cls, "_fetch")
            except AttributeError:
                pass
    return restore


def _boom(*a, **k):
    raise AssertionError("réseau émis alors qu'aucun ne devait l'être (scope-guard / config)")


# =================================================================================================
class TestAuthRaceRegistration(unittest.TestCase):
    KINDS = ("race.condition", "oauth.flow")

    def test_all_registered_and_typed(self):
        self.assertIsInstance(mods.get("race.condition"), ScopeGuardedOracle)
        self.assertIsInstance(mods.get("race.condition"), Oracle)
        self.assertIsInstance(mods.get("oauth.flow"), ClientFlowOracle)
        self.assertIsInstance(mods.get("oauth.flow"), ScopeGuardedOracle)
        self.assertIsInstance(mods.get("oauth.flow"), Oracle)
        for k in self.KINDS:
            self.assertIn(k, mods.kinds())

    def test_mitre_and_cwe_match_table(self):
        for k in self.KINDS:
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")
            self.assertEqual(mods.get(k).cwe, techniques.cwe_for(k), f"cwe dérive pour {k}")
        self.assertEqual(mods.get("race.condition").cwe, "CWE-362")
        self.assertEqual(mods.get("race.condition").mitre, "T1190")
        self.assertEqual(mods.get("oauth.flow").cwe, "CWE-601")
        self.assertEqual(mods.get("oauth.flow").mitre, "T1528")

    def test_capability_flags_benign_non_destructive(self):
        for k in self.KINDS:
            m = mods.get(k)
            self.assertFalse(m.exploit, f"{k} sonde bénigne -> exploit=False")
            self.assertFalse(m.destructive, f"{k} -> destructive=False (plancher exploit/destructif OFF)")
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

    def test_profile_and_vuln_class_membership(self):
        # bug_bounty_eligible -> présent dans bug_bounty ET pentest, et groupé sous sa catégorie.
        for k in self.KINDS:
            t = techniques.technique_for(k)
            self.assertTrue(t.bug_bounty_eligible, f"{k} devrait être bug_bounty_eligible")
            self.assertFalse(t.pentest_only, f"{k} ne devrait pas être pentest_only")
            self.assertIn(k, techniques.profile_set("bug_bounty"))
            self.assertIn(k, techniques.profile_set("pentest"))
            self.assertIn("bug_bounty", t.default_profiles)
            self.assertIn("pentest", t.default_profiles)
        bvc = techniques.by_vuln_class()
        self.assertIn("race.condition", bvc.get("RaceCondition", []))
        self.assertIn("oauth.flow", bvc.get("OAuthFlow", []))
        # présent dans le pipeline pentest ordonné et filtré par profil bug_bounty.
        self.assertIn("race.condition", techniques.techniques_for("bug_bounty"))
        self.assertIn("oauth.flow", techniques.techniques_for("bug_bounty"))

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
class TestRaceConditionOracle(unittest.TestCase):
    TGT = "https://app.test/redeem"
    MARK = "REDEEMED-ok-7f3a"
    BASE = {"success_marker": MARK, "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _patch(RaceCondition, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return RaceCondition().fire(Action("race.condition", self.TGT, params=p))
        finally:
            restore()

    def _limited_server(self, n_success):
        """`_fetch` mocké : compte atomiquement les requêtes concurrentes et n'accorde le succès qu'aux
        `n_success` PREMIÈRES (ordonnancement indifférent : le NOMBRE de succès est déterministe)."""
        lock = threading.Lock()
        state = {"n": 0}

        def fake(url, headers=None, timeout=15, method="POST", data=None):
            with lock:
                state["n"] += 1
                i = state["n"]
            if i <= n_success:
                return (200, f'{{"status":"{self.MARK}"}}')
            return (409, '{"error":"already used"}')
        return fake

    # --- positif : la course est GAGNÉE (plus de succès que le quota) ---
    def test_vulnerable_more_successes_than_limit(self):
        f = self._fire(self._limited_server(3))       # 3 redemptions concurrentes réussissent, quota=1
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-362")
        self.assertEqual(f[0].mitre, "T1190")
        self.assertIn("CONFIRMÉ", f[0].title)
        self.assertIn("succès comptés=3", f[0].evidence)
        self.assertIn("PROPRE", f[0].evidence)         # ressource propre de l'opérateur, jamais un tiers

    # --- négatif : le quota est RESPECTÉ (une seule redemption réussit) ---
    def test_tested_when_limit_respected(self):
        f = self._fire(self._limited_server(1))        # exactement 1 succès, quota=1 -> pas de course
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non confirmé", f[0].title.lower())

    def test_tested_when_successes_equal_explicit_limit(self):
        # limite explicite : 3 succès pour un quota de 3 -> pas de dépassement -> tested.
        f = self._fire(self._limited_server(3), params={"limit": 3})
        self.assertEqual(f[0].status, "tested")

    def test_success_codes_without_marker(self):
        # détection par code seul (pas de marqueur) : 3 x HTTP 200 -> 3 succès > quota 1 -> vulnerable.
        def fake(url, headers=None, timeout=15, method="POST", data=None):
            return (200, "ok")
        restore = _patch(RaceCondition, fake)
        try:
            f = RaceCondition().fire(Action("race.condition", self.TGT,
                                            params={"success_codes": [200], "in_scope": ["app.test"],
                                                    "burst": 4}))
        finally:
            restore()
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("succès comptés=4", f[0].evidence)

    # --- rafale BORNÉE (jamais un DoS) ---
    def test_burst_is_bounded(self):
        calls = []
        lock = threading.Lock()

        def fake(url, headers=None, timeout=15, method="POST", data=None):
            with lock:
                calls.append(1)
            return (409, "no")                          # aucun succès : on ne teste QUE le nombre de tirs
        restore = _patch(RaceCondition, fake)
        try:
            f = RaceCondition().fire(Action("race.condition", self.TGT,
                                            params=dict(self.BASE, burst=9999)))
        finally:
            restore()
        self.assertEqual(len(calls), racemod._MAX_BURST, "la rafale doit être plafonnée (anti-DoS)")
        self.assertEqual(f[0].status, "tested")         # 0 succès -> non concluant

    def test_burst_size_clamps(self):
        mk = lambda **p: Action("race.condition", self.TGT, params=p)
        self.assertEqual(RaceCondition()._burst_size(mk(burst=9999)), racemod._MAX_BURST)
        self.assertEqual(RaceCondition()._burst_size(mk(burst=1)), racemod._MIN_BURST)
        self.assertEqual(RaceCondition()._burst_size(mk()), racemod._DEFAULT_BURST)
        self.assertEqual(RaceCondition()._burst_size(mk(burst="x")), racemod._DEFAULT_BURST)

    # --- garde-fous ---
    def test_scope_guard_out_of_scope(self):
        restore = _patch(RaceCondition, _boom)
        try:
            f = RaceCondition().fire(Action("race.condition", "https://evil.example/redeem",
                                            params=dict(self.BASE)))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        restore = _patch(RaceCondition, _boom)
        try:
            f = RaceCondition().fire(Action("race.condition", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)
        self.assertIn("config manquante", f[0].title)

    def test_network_down_degrades_to_skipped(self):
        def fake(url, headers=None, timeout=15, method="POST", data=None):
            return (None, "")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)


# =================================================================================================
class TestOAuthFlowOracle(unittest.TestCase):
    TGT = "https://app.test/oauth/authorize"
    LEGIT = "https://app.test/cb"
    ATTACKER = OAuthFlow._DEFAULT_ATTACKER
    BASE = {"client_id": "operator-client-123", "legit_redirect": LEGIT, "in_scope": ["app.test"]}

    def _fire(self, fake, params=None, target=None):
        restore = _patch(OAuthFlow, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return OAuthFlow().fire(Action("oauth.flow", target or self.TGT, params=p))
        finally:
            restore()

    @staticmethod
    def _host(u):
        return u.split("://", 1)[-1].split("/", 1)[0] if u else ""

    def _server(self, *, accept_attacker_redirect, issue_without_binding):
        """`_fetch` mocké header-aware -> (status, body, pairs). Simule l'endpoint d'autorisation :
          - redirect_uri vers l'hôte attaquant : accepté (302 + code) ou rejeté (400) ;
          - redirect_uri légitime SANS state/PKCE : code émis (302) ou rejeté (400) selon l'imposition."""
        att_host = self._host(self.ATTACKER)

        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            redirect = (q.get("redirect_uri") or [""])[0]
            has_state = "state" in q
            has_pkce = "code_challenge" in q
            if self._host(redirect) == att_host:
                if accept_attacker_redirect:
                    return (302, "", [("Location", f"{redirect}?code=att123&state=s")])
                return (400, '{"error":"invalid redirect_uri"}', [])
            # redirect_uri légitime : impose-t-on une liaison anti-CSRF (state ou PKCE) ?
            if (not has_state or not has_pkce) and not issue_without_binding:
                return (400, '{"error":"invalid_request"}', [])
            return (302, "", [("Location", f"{redirect}?code=leg456&state=s")])
        return fake

    @staticmethod
    def _by_cwe(findings, cwe):
        return next(x for x in findings if x.cwe == cwe)

    # --- redirect_uri bypass (CWE-601) ---
    def test_vulnerable_redirect_uri_bypass_chainable(self):
        f = self._fire(self._server(accept_attacker_redirect=True, issue_without_binding=False))
        self.assertEqual(len(f), 3)                     # redirect + state + pkce
        redir = self._by_cwe(f, "CWE-601")
        self.assertEqual(redir.status, "vulnerable")
        self.assertEqual(redir.severity, "HIGH")
        self.assertIn("CONFIRMÉ", redir.title)
        self.assertIn("attaquant_contrôlable=True", redir.evidence)
        # les deux autres restent tested (le back-end refuse le code sans liaison).
        self.assertEqual(self._by_cwe(f, "CWE-352").status, "tested")
        self.assertEqual(self._by_cwe(f, "CWE-287").status, "tested")

    def test_redirect_controllable_but_not_chainable_stays_tested(self):
        # destination attaquant acceptée MAIS chaînabilité NIÉE par l'opérateur -> non promu (règle
        # workspace « open redirect only if chained »).
        f = self._fire(self._server(accept_attacker_redirect=True, issue_without_binding=False),
                       params={"chainable": False})
        redir = self._by_cwe(f, "CWE-601")
        self.assertEqual(redir.status, "tested")
        self.assertIn("NON promu", redir.title)

    def test_redirect_not_controllable_is_tested(self):
        f = self._fire(self._server(accept_attacker_redirect=False, issue_without_binding=False))
        self.assertEqual(self._by_cwe(f, "CWE-601").status, "tested")

    # --- state manquant (CWE-352) + PKCE downgrade (CWE-287) ---
    def test_vulnerable_state_and_pkce_missing(self):
        f = self._fire(self._server(accept_attacker_redirect=False, issue_without_binding=True))
        state = self._by_cwe(f, "CWE-352")
        pkce = self._by_cwe(f, "CWE-287")
        self.assertEqual(state.status, "vulnerable")
        self.assertEqual(state.severity, "HIGH")
        self.assertIn("CONFIRMÉ", state.title)
        self.assertEqual(pkce.status, "vulnerable")
        self.assertEqual(pkce.severity, "MEDIUM")
        # le redirect (attaquant rejeté) reste tested.
        self.assertEqual(self._by_cwe(f, "CWE-601").status, "tested")

    def test_state_suppressed_when_client_validates_state(self):
        # l'opérateur atteste que SON client valide le state -> pas de promotion CSRF (mais PKCE reste).
        f = self._fire(self._server(accept_attacker_redirect=False, issue_without_binding=True),
                       params={"client_validates_state": True})
        self.assertEqual(self._by_cwe(f, "CWE-352").status, "tested")
        self.assertEqual(self._by_cwe(f, "CWE-287").status, "vulnerable")

    def test_pkce_suppressed_when_confidential_client(self):
        # client confidentiel (public_client=False) -> pas de downgrade PKCE promu (mais state reste).
        f = self._fire(self._server(accept_attacker_redirect=False, issue_without_binding=True),
                       params={"public_client": False})
        self.assertEqual(self._by_cwe(f, "CWE-287").status, "tested")
        self.assertEqual(self._by_cwe(f, "CWE-352").status, "vulnerable")

    def test_all_tested_when_flow_hardened(self):
        f = self._fire(self._server(accept_attacker_redirect=False, issue_without_binding=False))
        for x in f:
            self.assertEqual(x.status, "tested", f"{x.cwe} devrait rester tested sur un flux durci")

    # --- garde-fous ---
    def test_scope_guard_out_of_scope(self):
        restore = _patch(OAuthFlow, _boom)
        try:
            f = OAuthFlow().fire(Action("oauth.flow", "https://evil.example/oauth/authorize",
                                        params=dict(self.BASE)))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_client_id_is_skip(self):
        restore = _patch(OAuthFlow, _boom)
        try:
            f = OAuthFlow().fire(Action("oauth.flow", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)
        self.assertIn("config manquante", f[0].title)

    def test_network_down_degrades_to_skipped(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (None, "", [])
        f = self._fire(fake)
        self.assertTrue(any(x.status == "skipped" for x in f))
        deg = next(x for x in f if x.status == "skipped")
        self.assertIn("réseau indisponible", deg.title)


if __name__ == "__main__":
    unittest.main(verbosity=2)

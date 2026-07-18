"""Remédiation d'audit (A1 rédaction centrale · B3 union idor_targets∪urls · dédup attacker-headers).

Preuves (toutes HERMÉTIQUES — `_fetch`/réseau mocké au seam, ZÉRO I/O réel) :

  (FIX 1 / A1) CHOKEPOINT DE RÉDACTION à `Finding.to_dict()` : un secret (Authorization: Bearer …,
      Cookie: sid=…) construit dans un `poc`/`evidence` par N'IMPORTE QUEL chemin (IDOR read/write,
      PrivEsc, ATO pré-R5 config-driven) est neutralisé à `to_dict()` -> absent de `json.dumps(to_dict())`
      ET du ledger SIGNÉ (qui appende `f.to_dict()`). Un PoC SANS secret n'est PAS altéré (pas de
      sur-rédaction).
  (FIX 3 / B3) UNION : une action IDOR chaînée portant `urls=[endpoint découvert]` ET des `idor_targets`
      injectés -> les DEUX surfaces sont testées (l'endpoint découvert est bien fetché).
  (FIX 4) DÉDUP : `session.attacker_headers_from_params` est la SOURCE UNIQUE ; les deux oracles y
      délèguent et produisent une sélection byte-identique à l'ancienne logique par-oracle.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                                   # noqa: E402
from forge.ledger import Ledger                                       # noqa: E402
from forge.schema import Finding                                      # noqa: E402
from forge.session import attacker_headers_from_params               # noqa: E402
from forge.modules.access_control import IdorDifferential, PrivEsc    # noqa: E402
from forge.modules.auth import AuthTakeover                           # noqa: E402

BEARER = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.S3cr3t-SIGN-9a8b7c6d5e4f"
COOKIE = "V1CT1M-cookie-sid-1f2e3d4c5b"
MARKER = "victim-identity-marker-xyz-42"


def _secret_headers():
    return {"Authorization": f"Bearer {BEARER}", "Cookie": f"sid={COOKIE}"}


def _params(**extra):
    p = {"in_scope": ["app.test"], "out_scope": []}
    p.update(extra)
    return p


def _patch(cls, fn):
    orig = cls._fetch
    cls._fetch = staticmethod(fn)
    return lambda: setattr(cls, "_fetch", orig)


def _assert_clean(testcase, finding):
    """to_dict() ne porte AUCUN secret et le secret n'est plus dans son JSON sérialisé."""
    blob = json.dumps(finding.to_dict())
    testcase.assertNotIn(BEARER, blob)
    testcase.assertNotIn(COOKIE, blob)
    return finding.to_dict()


# =================================================================================================
#  FIX 1 — rédaction centrale : chaque chemin qui bâtit un PoC avec en-têtes secrets est nettoyé
# =================================================================================================
class TestCentralRedactionAllPaths(unittest.TestCase):
    def test_idor_read_path_redacted_in_dict_and_ledger(self):
        # A propriétaire, B attaquant (en-têtes SECRETS) ; le poc du chemin read est bâti depuis B.
        A = {"label": "victim", "headers": {"Cookie": "sid=owner"}}
        B = {"label": "attacker", "headers": _secret_headers()}

        def fake(url, headers, timeout=15, method="GET", body=None):
            if headers.get("Authorization") or headers.get("Cookie"):
                return 200, '{"order": 1, "secret": "data"}', "application/json"
            return 403, "", ""                             # anon refusé -> IDOR prouvé (poc = B secret)

        r = _patch(IdorDifferential, fake)
        try:
            out = IdorDifferential().fire(Action("access_control.idor", "app.test", cls="access_control",
                  params=_params(accounts=[A, B], urls=["https://app.test/api/orders/1"])))
        finally:
            r()
        f = out[0]
        d = _assert_clean(self, f)
        self.assertEqual(d["status"], "vulnerable")        # chemin promouvant (contrôle : le poc porte le secret)
        self.assertIn("[REDACTED]", d["poc"])
        # LEDGER SIGNÉ : l'engine appende EXACTEMENT f.to_dict() -> le secret n'y entre jamais.
        with tempfile.TemporaryDirectory() as td:
            led = Ledger(Path(td) / "l.jsonl")
            led.append("finding", f.to_dict())
            raw = (Path(td) / "l.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(BEARER, raw)
            self.assertNotIn(COOKIE, raw)
            self.assertIn("[REDACTED]", raw)

    def test_idor_write_path_redacted(self):
        A = {"label": "victim", "headers": {"Cookie": "sid=owner"}}
        B = {"label": "attacker", "headers": _secret_headers()}
        state = {"n": 0}

        def fake(url, headers, timeout=15, method="GET", body=None):
            if method == "GET":
                return 200, f'{{"v": {state["n"]}}}', "application/json"
            state["n"] += 1                                 # B mute l'objet de A
            return 200, "", "application/json"

        act = Action("access_control.idor", "app.test", cls="access_control",
                     params=_params(accounts=[A, B], urls=["https://app.test/api/orders/1"], method="PATCH"))
        act.destructive = True
        r = _patch(IdorDifferential, fake)
        try:
            out = IdorDifferential().fire(act)
        finally:
            r()
        d = _assert_clean(self, out[0])
        self.assertIn("[REDACTED]", d["poc"])

    def test_privesc_path_redacted(self):
        low = {"label": "low", "headers": _secret_headers()}   # le poc privesc est bâti depuis le bas-priv
        admin = {"label": "admin", "headers": {"Cookie": "sid=admin"}}

        def fake(url, headers, timeout=15, method="GET", body=None):
            if headers.get("Authorization") or headers.get("Cookie"):
                return 200, '{"admin_panel": true}', "application/json"
            return 403, "", ""

        r = _patch(PrivEsc, fake)
        try:
            out = PrivEsc().fire(Action("access_control.privesc", "app.test", cls="access_control",
                  params=_params(accounts=[low, admin], admin_urls=["https://app.test/admin/panel"])))
        finally:
            r()
        d = _assert_clean(self, out[0])
        self.assertIn("[REDACTED]", d["poc"])

    def test_legacy_ato_path_redacted(self):
        # chemin config-driven historique (pré-R5) : attacker_session_headers SECRETS embarqués dans le poc.
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return 200, f'{{"id": "{MARKER}"}}', {}

        r = _patch(AuthTakeover, fake)
        try:
            out = AuthTakeover().fire(Action("auth.takeover", "app.test", cls="auth", params=_params(
                whoami_url="https://app.test/me", victim_marker=MARKER,
                attacker_session_headers=_secret_headers())))
        finally:
            r()
        f = out[0]
        d = _assert_clean(self, f)
        self.assertEqual(d["status"], "vulnerable")
        self.assertIn("[REDACTED]", d["poc"])

    def test_clean_poc_not_over_redacted(self):
        # PoC SANS secret -> INCHANGÉ (le rédacteur ne masque QUE des motifs de secret).
        clean = "curl -sS 'https://app.test/api/orders/1'"
        f = Finding(target="app.test", title="x", poc=clean,
                    evidence="A=200 B=200 anon=403 même_objet=True")
        self.assertEqual(f.to_dict()["poc"], clean)
        self.assertEqual(f.to_dict()["evidence"], "A=200 B=200 anon=403 même_objet=True")


# =================================================================================================
#  FIX 3 — union idor_targets ∪ urls : la surface découverte (urls) est AUSSI testée
# =================================================================================================
class TestIdorUnionTargetsAndUrls(unittest.TestCase):
    def test_chained_urls_tested_alongside_idor_targets(self):
        discovered = "https://app.test/api/discovered?id=5"
        target_url = "https://app.test/api/orders/1"
        attacker = {"label": "attacker", "headers": _secret_headers()}
        victim = {"label": "victim", "headers": {"Cookie": "sid=victim"}}
        fetched = []

        def fake(url, headers, timeout=15, method="GET", body=None):
            fetched.append(url)
            if headers.get("Authorization") or headers.get("Cookie"):
                return 200, f'{{"u": "{url}"}}', "application/json"
            return 403, "", ""

        # action CHAÎNÉE : urls=[endpoint découvert] (edge C) + idor_targets injectés par l'engine.
        act = Action("access_control.idor", "app.test", cls="access_control", params=_params(
            accounts=[attacker, victim], urls=[discovered],
            idor_targets=[{"url": target_url, "owner": "victim", "marker": MARKER}]))
        r = _patch(IdorDifferential, fake)
        try:
            out = IdorDifferential().fire(act)
        finally:
            r()
        # LES DEUX surfaces ont été fetchées (plus d'early-return sur idor_targets).
        self.assertIn(discovered, fetched)                 # l'endpoint découvert EST testé (le fix)
        self.assertIn(target_url, fetched)                 # l'idor_target l'est toujours
        # et des findings couvrent les deux cibles.
        targets = {f.target for f in out}
        self.assertIn(discovered, targets)
        self.assertIn(target_url, targets)
        # aucun secret ne fuit sur AUCUN des findings émis.
        for f in out:
            _assert_clean(self, f)

    def test_urls_only_still_works_without_idor_targets(self):
        # non-régression : sans idor_targets, le chemin historique urls tire seul.
        attacker = {"label": "attacker", "headers": _secret_headers()}
        victim = {"label": "victim", "headers": {"Cookie": "sid=victim"}}
        fetched = []

        def fake(url, headers, timeout=15, method="GET", body=None):
            fetched.append(url)
            return (200, '{"x": 1}', "application/json") if headers else (403, "", "")

        r = _patch(IdorDifferential, fake)
        try:
            out = IdorDifferential().fire(Action("access_control.idor", "app.test", cls="access_control",
                  params=_params(accounts=[attacker, victim], urls=["https://app.test/api/o/1"])))
        finally:
            r()
        self.assertIn("https://app.test/api/o/1", fetched)
        self.assertEqual(len(out), 1)

    def test_idor_targets_only_no_spurious_config_skip(self):
        # non-régression : avec SEULEMENT des idor_targets (pas d'urls), on renvoie leurs findings,
        # jamais un skip « config manquante » parasite.
        attacker = {"label": "attacker", "headers": _secret_headers()}
        victim = {"label": "victim", "headers": {"Cookie": "sid=victim"}}

        def fake(url, headers, timeout=15, method="GET", body=None):
            if headers.get("Authorization"):
                return 200, f'{{"m": "{MARKER}"}}', "application/json"
            return 403, "", ""

        r = _patch(IdorDifferential, fake)
        try:
            out = IdorDifferential().fire(Action("access_control.idor", "app.test", cls="access_control",
                  params=_params(accounts=[attacker, victim],
                                 idor_targets=[{"url": "https://app.test/api/orders/1",
                                                "owner": "victim", "marker": MARKER}])))
        finally:
            r()
        self.assertEqual(len(out), 1)
        self.assertNotIn("config manquante", out[0].title)
        self.assertEqual(out[0].to_dict()["status"], "vulnerable")   # marqueur victime -> IDOR confirmé


# =================================================================================================
#  FIX 4 — source unique de la sélection « attaquant = labellisé-ou-premier »
# =================================================================================================
class TestAttackerHeadersHelperSingleSource(unittest.TestCase):
    @staticmethod
    def _old_logic(accounts):
        """La logique par-oracle historique (byte-identique dans les deux modules avant extraction)."""
        if not accounts:
            return None
        for a in accounts:
            if str(a.get("label", "")).strip().lower() == "attacker":
                return a.get("headers", {}) or {}
        return accounts[0].get("headers", {}) or {}

    def test_matches_old_logic_and_both_oracles_delegate(self):
        cases = [
            [],
            [{"label": "attacker", "headers": {"a": 1}}],
            [{"label": "victim", "headers": {"v": 1}}, {"label": "attacker", "headers": {"a": 2}}],
            [{"label": "first", "headers": {"f": 1}}, {"label": "second", "headers": {"s": 2}}],  # -> 1er
            [{"label": "ATTACKER", "headers": {"A": 9}}],     # casse insensible
            [{"label": "attacker"}],                          # pas d'en-têtes -> {}
        ]
        for accounts in cases:
            expected = self._old_logic(accounts)
            self.assertEqual(attacker_headers_from_params(accounts), expected, accounts)
            # les deux oracles délèguent -> même sortie que la source unique.
            self.assertEqual(IdorDifferential._attacker_headers(accounts), expected, accounts)
            self.assertEqual(AuthTakeover._attacker_headers(accounts), expected, accounts)


if __name__ == "__main__":
    unittest.main()

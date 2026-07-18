"""R7 — l'oracle ATO/takeover confirme désormais un takeover cross-compte sur PLUSIEURS signaux à
faible taux de faux positifs (au-delà du seul marqueur d'identité de R5b), l'evidence NOMMANT lequel
a tiré :

  (a) STATUS-DELTA : l'attaquant obtient un 2xx là où l'anonyme est refusé (401/403) sur une ressource
      dont le propriétaire n'est PAS l'attaquant (owner ≠ label attaquant) -> ATO confirmé ; l'evidence
      contient « status-delta ».
  (b) DIFFÉRENTIEL DE CONTENU VICTIME-vs-ATTAQUANT : l'attaquant voit la vue PRIVÉE de la victime
      (même corps normalisé que la victime, ABSENT de la vue anonyme) -> ATO confirmé ; l'evidence
      contient « content-differential ».
  (c) PAS de faux positif : attaquant + anon en 200 public -> AUCUN finding vulnerable ; l'attaquant
      lisant SA PROPRE ressource (owner == attaquant) -> AUCUN finding vulnerable.
  (d) le signal MARQUEUR de R5b reste fonctionnel (non-régression).
  (e) scope-guard fail-closed : une cible hors périmètre -> AUCUNE des trois requêtes (victime,
      attaquant, anonyme) n'est émise.
  (f) aucun contexte auth -> chemin config-driven historique, byte-identique (no-op).
  (g) creds RÉDIGÉS dans CHAQUE nouveau chemin d'evidence (bearer/cookie jamais sérialisés).

Hermétique : on monkeypatch le `_fetch` de l'oracle (zéro réseau) — même seam que test_ato_auth_context."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                               # noqa: E402
from forge.session import AuthContext                             # noqa: E402
from forge.modules.auth import AuthTakeover                       # noqa: E402

BEARER = "S3CR3T-bearer-r7-9a8b7c6d5e"
COOKIE_VAL = "V1CT1M-cookie-r7-1f2e3d"
MARKER = "victim-identity-marker-r7-42x"

# corps PRIVÉ de la victime (données spécifiques victime) vs corps public/anon générique.
VICTIM_PRIVATE = '{"account": "victim", "iban": "NL00PRIVATE0001", "balance": 4242}'
ANON_PUBLIC = '{"error": "unauthenticated"}'


def _scope(**extra):
    d = {"mode": "grey", "in_scope": ["app.test"], "out_scope": [], "allow_exploit": True}
    d.update(extra)
    return Scope(d)


def _auth_block(owner="victim", marker=MARKER, url="https://app.test/api/resource"):
    tgt = {"url": url, "owner": owner}
    if marker is not None:
        tgt["marker"] = marker
    return {
        "accounts": [
            {"label": "attacker", "bearer": BEARER},
            {"label": "victim", "cookies": {"sid": COOKIE_VAL}},
        ],
        "idor_targets": [tgt],
    }


def _patch_fetch(fn):
    orig = AuthTakeover._fetch
    AuthTakeover._fetch = staticmethod(fn)
    return lambda: setattr(AuthTakeover, "_fetch", orig)


def _ato_action(scope):
    a = Action("auth.takeover", "app.test", cls="auth")
    ctx = AuthContext.from_scope(scope)
    a.params["accounts"] = ctx.accounts_as_params()
    a.params["idor_targets"] = list(ctx.idor_targets)
    a.params["in_scope"] = scope.in_scope
    a.params["out_scope"] = scope.out_scope
    return a


def _run(scope, fake):
    restore = _patch_fetch(fake)
    try:
        return AuthTakeover().fire(_ato_action(scope))
    finally:
        restore()


def _is_attacker(headers):
    return bool(headers) and headers.get("Authorization") == f"Bearer {BEARER}"


def _is_victim(headers):
    return bool(headers) and "sid=" + COOKIE_VAL in (headers.get("Cookie") or "")


# =================================================================================================
#  (a) STATUS-DELTA : attaquant 2xx / anon refusé, owner ≠ attaquant -> ATO confirmé
# =================================================================================================
class TestStatusDeltaFires(unittest.TestCase):
    def test_attacker_2xx_anon_denied_owner_other_is_ato(self):
        # target SANS marqueur : la seule preuve possible est le status-delta (owner=victim ≠ attacker).
        sc = _scope(auth=_auth_block(marker=None))

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if not headers:                     # contrôle anonyme -> refusé (ressource protégée)
                return 403, "", {}
            return 200, '{"ok": true, "id": 77}', {}   # attaquant (et victime) autorisés

        out = _run(sc, fake)
        f = out[0].to_dict()
        self.assertEqual(f["status"], "vulnerable")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertIn("CONFIRMÉ", f["title"])
        self.assertIn("status-delta", f["evidence"])            # l'evidence NOMME le signal
        self.assertIn("status-delta", f["title"])

    def test_creds_redacted_in_status_delta_evidence(self):
        sc = _scope(auth=_auth_block(marker=None))

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, '{"ok": true}', {}) if headers else (401, "", {})

        f = _run(sc, fake)[0].to_dict()
        blob = json.dumps(f)
        self.assertNotIn(BEARER, blob)
        self.assertNotIn(COOKIE_VAL, blob)
        self.assertIn("[REDACTED]", f["poc"])


# =================================================================================================
#  (b) DIFFÉRENTIEL DE CONTENU : l'attaquant voit la vue PRIVÉE de la victime (absente de l'anon)
# =================================================================================================
class TestContentDifferentialFires(unittest.TestCase):
    def test_attacker_sees_victim_private_view(self):
        # pas de marqueur, et l'anonyme est AUTORISÉ (200) mais ne voit PAS la donnée privée victime ->
        # le seul signal est le différentiel de contenu (attaquant == victime, ≠ anon).
        sc = _scope(auth=_auth_block(marker=None))

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if _is_attacker(headers) or _is_victim(headers):
                return 200, VICTIM_PRIVATE, {}          # attaquant voit EXACTEMENT la vue victime
            return 200, ANON_PUBLIC, {}                 # anon 200 mais vue générique (pas la donnée privée)

        out = _run(sc, fake)
        f = out[0].to_dict()
        self.assertEqual(f["status"], "vulnerable")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertIn("content-differential", f["evidence"])
        self.assertIn("content-differential", f["title"])

    def test_creds_redacted_in_content_differential_evidence(self):
        sc = _scope(auth=_auth_block(marker=None))

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if _is_attacker(headers) or _is_victim(headers):
                return 200, VICTIM_PRIVATE, {}
            return 200, ANON_PUBLIC, {}

        f = _run(sc, fake)[0].to_dict()
        blob = json.dumps(f)
        self.assertNotIn(BEARER, blob)
        self.assertNotIn(COOKIE_VAL, blob)
        self.assertIn("[REDACTED]", f["poc"])


# =================================================================================================
#  (c) PAS DE FAUX POSITIF
# =================================================================================================
class TestNoFalsePositive(unittest.TestCase):
    def test_public_200_both_see_it_no_finding(self):
        # attaquant + anon (+ victime) voient le MÊME 200 public -> aucun signal -> tested.
        sc = _scope(auth=_auth_block(marker=None))

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return 200, '{"public": true, "banner": "hello"}', {}

        f = _run(sc, fake)[0].to_dict()
        self.assertEqual(f["status"], "tested")
        self.assertIn("non confirmé", f["title"])

    def test_attacker_reads_own_resource_no_finding(self):
        # owner == attaquant : status-delta interdit (ressource propre), contenu == anon (pas de diff)
        # -> même si l'anon est refusé, on ne flag JAMAIS l'attaquant lisant SA PROPRE ressource.
        sc = _scope(auth=_auth_block(owner="attacker", marker=None))

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if not headers:
                return 403, "", {}            # anon refusé
            return 200, '{"mine": true}', {}  # attaquant autorisé sur SA ressource

        f = _run(sc, fake)[0].to_dict()
        self.assertEqual(f["status"], "tested")            # owner==attaquant -> pas de status-delta
        self.assertIn("non confirmé", f["title"])
        self.assertIn("owner≠attaquant=False", f["evidence"])


# =================================================================================================
#  (d) NON-RÉGRESSION : le signal MARQUEUR de R5b tire toujours
# =================================================================================================
class TestMarkerSignalRegression(unittest.TestCase):
    def test_victim_marker_still_confirms(self):
        sc = _scope(auth=_auth_block(marker=MARKER))

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if _is_attacker(headers):
                return 200, f'{{"user": "{MARKER}", "role": "member"}}', {}
            return 401, "", {}

        f = _run(sc, fake)[0].to_dict()
        self.assertEqual(f["status"], "vulnerable")
        self.assertIn("marqueur-identité-victime", f["evidence"])


# =================================================================================================
#  (e) SCOPE-GUARD : cible hors périmètre -> AUCUNE des trois requêtes émise
# =================================================================================================
class TestScopeGuardBlocksAllThreeRequests(unittest.TestCase):
    def test_out_of_scope_makes_no_request_of_any_kind(self):
        block = _auth_block(marker=None, url="https://evil.test/api/resource")
        sc = _scope(auth=block)                 # in_scope=app.test ; evil.test HORS scope
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            calls.append((url, dict(headers or {})))    # ne doit JAMAIS être appelé
            return 200, VICTIM_PRIVATE, {}

        out = _run(sc, fake)
        self.assertEqual(calls, [])                       # victime, attaquant ET anon : zéro I/O
        f = out[0].to_dict()
        self.assertEqual(f["status"], "skipped")
        self.assertIn("hors périmètre", f["title"])


# =================================================================================================
#  (f) NO-OP : aucun contexte auth -> chemin config-driven historique byte-identique
# =================================================================================================
class TestInertWithoutAuthContext(unittest.TestCase):
    def test_config_missing_byte_identical(self):
        sc = _scope()
        a = Action("auth.takeover", "app.test", cls="auth",
                   params={"in_scope": sc.in_scope, "out_scope": sc.out_scope})
        out = AuthTakeover().fire(a)
        self.assertEqual(len(out), 1)
        f = out[0].to_dict()
        self.assertEqual(f["status"], "tested")
        self.assertIn("config manquante", f["title"])

    def test_no_network_when_config_missing(self):
        sc = _scope()
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            calls.append(url)
            return 200, "", {}

        a = Action("auth.takeover", "app.test", cls="auth",
                   params={"in_scope": sc.in_scope, "out_scope": sc.out_scope})
        _run_a = _patch_fetch(fake)
        try:
            AuthTakeover().fire(a)
        finally:
            _run_a()
        self.assertEqual(calls, [])                       # config manquante -> AUCUN réseau


if __name__ == "__main__":
    unittest.main()

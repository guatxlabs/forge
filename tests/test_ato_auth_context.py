"""Contexte d'authentification PAR-ENGAGEMENT (R5b) — l'oracle ATO/takeover teste le takeover cross-compte.

Prouve la tranche verticale ATO câblée sur le MÊME bloc `scope.auth` que l'IDOR (R5) :
  (a) une idor_target in-scope dont la réponse (session ATTAQUANT) porte le MARQUEUR D'IDENTITÉ de la
      victime -> finding ATO émis (vulnerable, CRITICAL) — la session attaquant renvoie l'identité d'autrui ;
  (b) une idor_target HORS scope -> refusée par le scope-guard fail-closed, AUCUNE requête émise ;
  (c) aucun bloc `auth` -> l'engine n'injecte rien, l'oracle retombe sur son chemin config-driven
      historique (« config manquante ») : no-op byte-identique à aujourd'hui ;
  (d) creds/token RÉDIGÉS — un bearer/cookie n'apparaît JAMAIS dans le finding sérialisé (PoC/evidence)
      ni le ledger ;
  (e) preuve NETTE : l'ATO ne tire PAS sur « n'importe quel 200 » (marqueur d'identité victime requis) ;
  (f) l'engine injecte les MÊMES comptes labellisés + idor_targets dans l'action auth.takeover et
      journalise la MISE EN USAGE (labels, pas de secret).

Hermétique : on monkeypatch le `_fetch` de l'oracle (zéro réseau) — même seam que test_auth_context.py."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                               # noqa: E402
from forge.session import AuthContext                             # noqa: E402
from forge.engine import Engine                                   # noqa: E402
from forge.ledger import Ledger                                   # noqa: E402
from forge.modules.auth import AuthTakeover                       # noqa: E402

# jeton témoin unique cherché PARTOUT (finding, ledger) — ne doit jamais fuiter.
BEARER = "S3CR3T-bearer-ato-4f8e2a1b9c"
COOKIE_VAL = "V1CT1M-cookie-ato-7d6e5f"
MARKER = "victim-identity-marker-9z8y7x"           # identité de la victime prouvant le takeover cross-compte


def _scope(**extra):
    d = {"mode": "grey", "in_scope": ["app.test"], "out_scope": [], "allow_exploit": True}
    d.update(extra)
    return Scope(d)


def _auth_block():
    return {
        "accounts": [
            {"label": "attacker", "bearer": BEARER},
            {"label": "victim", "cookies": {"sid": COOKIE_VAL}},
        ],
        "idor_targets": [
            {"url": "https://app.test/api/me", "owner": "victim", "marker": MARKER},
        ],
    }


def _patch_fetch(fn):
    """Remplace AuthTakeover._fetch (staticmethod) et renvoie un restaurateur."""
    orig = AuthTakeover._fetch
    AuthTakeover._fetch = staticmethod(fn)
    return lambda: setattr(AuthTakeover, "_fetch", orig)


def _ato_action(scope, target="app.test"):
    """Action auth.takeover AVEC le périmètre + comptes + idor_targets injectés (comme l'engine le fait)
    pour que le scope-guard par-URL de l'oracle enforce et que le slice cross-compte s'active."""
    a = Action("auth.takeover", target, cls="auth")
    ctx = AuthContext.from_scope(scope)
    a.params["accounts"] = ctx.accounts_as_params()
    a.params["idor_targets"] = list(ctx.idor_targets)
    a.params["in_scope"] = scope.in_scope
    a.params["out_scope"] = scope.out_scope
    return a


# =================================================================================================
#  (a) ATO FIRES : la session attaquant renvoie l'identité de la victime -> finding vulnerable CRITICAL
# =================================================================================================
class TestAtoFiresCrossAccount(unittest.TestCase):
    def test_victim_marker_in_attacker_response_is_ato(self):
        sc = _scope(auth=_auth_block())
        seen = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            seen.append((url, dict(headers or {})))
            # session attaquant (Authorization présent) -> 200 + corps portant l'identité VICTIME.
            if headers and headers.get("Authorization"):
                return 200, f'{{"user": "{MARKER}", "role": "member"}}', {}
            return 401, "", {}

        restore = _patch_fetch(fake)
        try:
            out = AuthTakeover().fire(_ato_action(sc))
        finally:
            restore()
        self.assertEqual(len(out), 1)
        f = out[0].to_dict()
        self.assertEqual(f["status"], "vulnerable")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertIn("CONFIRMÉ", f["title"])
        # l'attaquant a bien émis avec SON bearer (session de l'attaquant, jamais celle d'un tiers).
        self.assertTrue(any(h.get("Authorization") == f"Bearer {BEARER}" for _, h in seen))

    def test_no_false_positive_on_public_200(self):
        # attaquant 200 MAIS le corps ne porte PAS le marqueur d'identité victime -> PAS d'ATO (tested).
        sc = _scope(auth=_auth_block())

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return 200, '{"public": true, "user": "someone-else"}', {}

        restore = _patch_fetch(fake)
        try:
            out = AuthTakeover().fire(_ato_action(sc))
        finally:
            restore()
        self.assertEqual(out[0].to_dict()["status"], "tested")

    def test_no_marker_public_endpoint_no_false_positive(self):
        # R7 — sans marqueur, l'oracle n'abandonne PLUS (il évalue status-delta + content-differential),
        # mais un endpoint PUBLIC (l'anonyme voit le MÊME 200 que l'attaquant et la victime) ne tire
        # AUCUN signal : ni marqueur, ni status-delta (anon non refusé), ni différentiel (== anon).
        block = _auth_block()
        block["idor_targets"] = [{"url": "https://app.test/api/me", "owner": "victim"}]
        sc = _scope(auth=block)

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return 200, '{"public": true, "banner": "welcome"}', {}   # identique à tout le monde

        restore = _patch_fetch(fake)
        try:
            out = AuthTakeover().fire(_ato_action(sc))
        finally:
            restore()
        f = out[0].to_dict()
        self.assertEqual(f["status"], "tested")               # public -> non confirmé (jamais un FP)
        self.assertIn("non confirmé", f["title"])


# =================================================================================================
#  (b) SCOPE-GUARD : idor_target HORS périmètre -> refus, AUCUNE requête émise
# =================================================================================================
class TestAtoScopeGuardRefusesOutOfScope(unittest.TestCase):
    def test_out_of_scope_target_makes_no_request(self):
        block = _auth_block()
        block["idor_targets"] = [{"url": "https://evil.test/api/me", "owner": "victim", "marker": MARKER}]
        sc = _scope(auth=block)            # in_scope = app.test uniquement ; evil.test HORS scope
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            calls.append(url)             # NE DOIT JAMAIS être appelé pour l'URL hors scope
            return 200, MARKER, {}

        restore = _patch_fetch(fake)
        try:
            out = AuthTakeover().fire(_ato_action(sc))
        finally:
            restore()
        self.assertEqual(calls, [])                                    # GARDE A TIRÉ : aucun I/O
        f = out[0].to_dict()
        self.assertEqual(f["status"], "skipped")                       # dégradation fail-closed
        self.assertIn("hors périmètre", f["title"])


# =================================================================================================
#  (c) NO-OP : aucun bloc auth -> l'engine n'injecte rien, chemin config-driven historique inchangé
# =================================================================================================
class TestAtoInertWhenNoAuthBlock(unittest.TestCase):
    def test_engine_does_not_inject_when_no_auth(self):
        sc = _scope()                                                  # aucun bloc auth
        self.assertIsNone(AuthContext.from_scope(sc))
        eng = Engine(sc, mode="auto")
        self.assertIsNone(eng.auth_context)
        a = Action("auth.takeover", "app.test", cls="auth")
        eng._prepare([a], None, {}, {})
        self.assertNotIn("accounts", a.params)                         # aucune injection R5b
        self.assertNotIn("idor_targets", a.params)

    def test_legacy_config_missing_skip_unchanged(self):
        # action auth.takeover SANS accounts/idor_targets ni whoami -> chemin historique « config manquante »
        sc = _scope()
        a = Action("auth.takeover", "app.test", cls="auth",
                   params={"in_scope": sc.in_scope, "out_scope": sc.out_scope})
        out = AuthTakeover().fire(a)
        f = out[0].to_dict()
        self.assertEqual(f["status"], "tested")
        self.assertIn("config manquante", f["title"])

    def test_legacy_whoami_path_still_works(self):
        # le chemin config-driven historique (whoami_url/victim_marker) reste fonctionnel INCHANGÉ.
        sc = _scope()
        a = Action("auth.takeover", "app.test", cls="auth", params={
            "in_scope": sc.in_scope, "out_scope": sc.out_scope,
            "whoami_url": "https://app.test/whoami", "victim_marker": MARKER,
            "attacker_session_headers": {"Cookie": "sid=att"},
        })

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return 200, f'{{"id": "{MARKER}"}}', {}

        restore = _patch_fetch(fake)
        try:
            out = AuthTakeover().fire(a)
        finally:
            restore()
        self.assertEqual(out[0].to_dict()["status"], "vulnerable")


# =================================================================================================
#  (d)+(f) ENGINE WIRES + REDACTS : l'engine injecte le contexte dans auth.takeover, journalise l'usage
# =================================================================================================
class TestAtoEngineWiresAndRedacts(unittest.TestCase):
    def test_prepare_injects_auth_context_and_ledgers_use_without_secret(self):
        with tempfile.TemporaryDirectory() as d:
            led = Ledger(Path(d) / "ledger.jsonl")
            sc = _scope(auth=_auth_block())
            eng = Engine(sc, ledger=led, mode="auto")
            self.assertIsNotNone(eng.auth_context)
            a = Action("auth.takeover", "app.test", cls="auth")
            eng._prepare([a], None, {}, {})
            # comptes labellisés + idor_targets structurés injectés dans l'action ATO
            self.assertEqual([x["label"] for x in a.params["accounts"]], ["attacker", "victim"])
            self.assertEqual(len(a.params["idor_targets"]), 1)
            # ledger : événement engine.auth_context avec labels, JAMAIS le secret
            raw = (Path(d) / "ledger.jsonl").read_text(encoding="utf-8")
            self.assertIn("engine.auth_context", raw)
            self.assertIn("attacker", raw)
            self.assertNotIn(BEARER, raw)
            self.assertNotIn(COOKIE_VAL, raw)

    def test_finding_never_leaks_token(self):
        sc = _scope(auth=_auth_block())

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if headers and headers.get("Authorization"):
                return 200, f'{{"user": "{MARKER}"}}', {}
            return 401, "", {}

        restore = _patch_fetch(fake)
        try:
            out = AuthTakeover().fire(_ato_action(sc))
        finally:
            restore()
        f = out[0].to_dict()
        # le finding brut (celui appendé au ledger par l'engine) est DÉJÀ rédigé à la source
        self.assertNotIn(BEARER, json.dumps(f))
        self.assertIn("[REDACTED]", f["poc"])                          # le bearer du PoC est masqué


if __name__ == "__main__":
    unittest.main()

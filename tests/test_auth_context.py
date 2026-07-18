"""Contexte d'authentification PAR-ENGAGEMENT (R5) — l'oracle IDOR teste l'accès cross-compte.

Prouve la tranche verticale IDOR câblée sur le bloc `scope.auth` :
  (a) une idor_target in-scope qui renvoie le MARQUEUR de la victime pour la session de l'attaquant
      -> finding IDOR émis (vulnerable, HIGH) ;
  (b) une idor_target HORS scope -> refusée par le scope-guard fail-closed, AUCUNE requête émise ;
  (c) aucun bloc `auth` -> `AuthContext.from_scope` rend None, l'oracle retombe sur « config
      manquante » (no-op byte-identique à aujourd'hui) ;
  (d) creds/token RÉDIGÉS — un bearer/cookie n'apparaît JAMAIS dans le rapport sérialisé ni le ledger ;
  (e) la MISE EN USAGE du contexte est journalisée (`engine.auth_context`) avec les labels, pas les
      secrets ;
  (f) preuve NETTE : l'IDOR ne tire pas sur « n'importe quel 200 » (écart de statut / marqueur requis).

Hermétique : on monkeypatch le `_fetch` de l'oracle (zéro réseau) — même seam que test_oracles.py."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                               # noqa: E402
from forge.session import AuthContext, AuthAccount                # noqa: E402
from forge.engine import Engine                                   # noqa: E402
from forge.ledger import Ledger                                   # noqa: E402
from forge.modules.access_control import IdorDifferential         # noqa: E402
from forge.report_engagement import normalize                     # noqa: E402

# jeton témoin unique cherché PARTOUT (rapport, ledger, finding) — ne doit jamais fuiter.
BEARER = "S3CR3T-bearer-4f8e2a1b9c"
COOKIE = "sid=V1CT1M-cookie-7d6e5f"
MARKER = "victim-private-marker-9z8y7x"           # « donnée de la victime » prouvant l'accès cross-compte


def _scope(**extra):
    d = {"mode": "grey", "in_scope": ["app.test"], "out_scope": [], "allow_exploit": True}
    d.update(extra)
    return Scope(d)


def _auth_block():
    return {
        "accounts": [
            {"label": "attacker", "bearer": BEARER},
            {"label": "victim", "cookies": {"sid": "V1CT1M-cookie-7d6e5f"}},
        ],
        "idor_targets": [
            {"url": "https://app.test/api/orders/1", "owner": "victim", "marker": MARKER},
        ],
    }


def _patch_fetch(fn):
    """Remplace IdorDifferential._fetch (staticmethod) et renvoie un restaurateur."""
    orig = IdorDifferential._fetch
    IdorDifferential._fetch = staticmethod(fn)
    return lambda: setattr(IdorDifferential, "_fetch", orig)


def _idor_action(scope, target="app.test"):
    """Action IDOR AVEC le périmètre injecté (comme l'engine le fait) pour que le scope-guard par-URL
    de l'oracle enforce (sans in_scope injecté, `_scope` serait permissif dev/test)."""
    a = Action("access_control.idor", target, cls="access_control")
    ctx = AuthContext.from_scope(scope)
    a.params["accounts"] = ctx.accounts_as_params()
    a.params["idor_targets"] = list(ctx.idor_targets)
    a.params["in_scope"] = scope.in_scope
    a.params["out_scope"] = scope.out_scope
    return a


# =================================================================================================
#  (parse) AuthContext.from_scope + rédaction repr + résumé ledger sûr
# =================================================================================================
class TestAuthContextParse(unittest.TestCase):
    def test_parses_labeled_accounts_and_targets(self):
        ctx = AuthContext.from_scope(_scope(auth=_auth_block()))
        self.assertIsNotNone(ctx)
        self.assertEqual([a.label for a in ctx.accounts], ["attacker", "victim"])
        self.assertEqual(len(ctx.idor_targets), 1)
        self.assertEqual(ctx.attacker().headers().get("Authorization"), f"Bearer {BEARER}")

    def test_inert_when_no_auth_block(self):
        self.assertIsNone(AuthContext.from_scope(_scope()))
        self.assertIsNone(AuthContext.from_scope(_scope(auth="not-a-dict")))
        self.assertIsNone(AuthContext.from_scope(_scope(auth={"accounts": [], "idor_targets": []})))

    def test_repr_and_summary_carry_no_secret(self):
        ctx = AuthContext.from_scope(_scope(auth=_auth_block()))
        blob = repr(ctx) + repr(ctx.accounts) + json.dumps(ctx.ledger_summary())
        self.assertNotIn(BEARER, blob)
        self.assertNotIn("V1CT1M-cookie", blob)
        self.assertEqual(ctx.ledger_summary(), {"accounts": ["attacker", "victim"], "idor_targets": 1})


# =================================================================================================
#  (a) IDOR FIRES : l'attaquant obtient le marqueur de la victime -> finding vulnerable HIGH
# =================================================================================================
class TestIdorFiresCrossAccount(unittest.TestCase):
    def test_marker_in_attacker_response_is_idor(self):
        sc = _scope(auth=_auth_block())
        seen = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            seen.append((url, dict(headers or {})))
            # attaquant (Authorization présent) -> 200 + corps contenant le marqueur victime ;
            # anonyme (pas d'Authorization) -> 403.
            if headers and headers.get("Authorization"):
                return 200, f'{{"order": 1, "email": "{MARKER}"}}', "application/json"
            return 403, "", "application/json"

        restore = _patch_fetch(fake)
        try:
            out = IdorDifferential().fire(_idor_action(sc))
        finally:
            restore()
        self.assertEqual(len(out), 1)
        f = out[0].to_dict()
        self.assertEqual(f["status"], "vulnerable")
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("CONFIRMÉ", f["title"])
        # l'attaquant a bien émis avec son bearer ; l'anonyme a été testé comme contrôle
        self.assertTrue(any(h.get("Authorization") == f"Bearer {BEARER}" for _, h in seen))

    def test_status_delta_without_marker_is_idor(self):
        # target sans marqueur : preuve = 2xx attaquant là où l'anon est refusé (401/403)
        block = _auth_block()
        block["idor_targets"] = [{"url": "https://app.test/api/orders/2", "owner": "victim"}]
        sc = _scope(auth=block)

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if headers and headers.get("Authorization"):
                return 200, '{"order": 2}', "application/json"
            return 401, "", "application/json"

        restore = _patch_fetch(fake)
        try:
            out = IdorDifferential().fire(_idor_action(sc))
        finally:
            restore()
        self.assertEqual(out[0].to_dict()["status"], "vulnerable")

    def test_no_false_positive_on_public_200(self):
        # attaquant 200 MAIS anonyme aussi 200 (ressource publique) -> PAS d'IDOR (tested)
        block = _auth_block()
        block["idor_targets"] = [{"url": "https://app.test/api/orders/3", "owner": "victim"}]
        sc = _scope(auth=block)

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return 200, '{"public": true}', "application/json"

        restore = _patch_fetch(fake)
        try:
            out = IdorDifferential().fire(_idor_action(sc))
        finally:
            restore()
        self.assertEqual(out[0].to_dict()["status"], "tested")

    def test_marker_absent_is_not_confirmed(self):
        # marqueur fourni mais ABSENT de la réponse attaquant -> pas de preuve (tested)
        sc = _scope(auth=_auth_block())

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if headers and headers.get("Authorization"):
                return 200, '{"order": 1, "email": "someone-else"}', "application/json"
            return 403, "", "application/json"

        restore = _patch_fetch(fake)
        try:
            out = IdorDifferential().fire(_idor_action(sc))
        finally:
            restore()
        self.assertEqual(out[0].to_dict()["status"], "tested")


# =================================================================================================
#  (b) SCOPE-GUARD : idor_target HORS périmètre -> refus, AUCUNE requête émise
# =================================================================================================
class TestScopeGuardRefusesOutOfScopeTarget(unittest.TestCase):
    def test_out_of_scope_target_makes_no_request(self):
        block = _auth_block()
        block["idor_targets"] = [{"url": "https://evil.test/api/orders/1", "owner": "victim",
                                  "marker": MARKER}]
        sc = _scope(auth=block)            # in_scope = app.test uniquement ; evil.test HORS scope
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            calls.append(url)             # NE DOIT JAMAIS être appelé pour l'URL hors scope
            return 200, MARKER, "application/json"

        restore = _patch_fetch(fake)
        try:
            out = IdorDifferential().fire(_idor_action(sc))
        finally:
            restore()
        self.assertEqual(calls, [])                                    # GARDE A TIRÉ : aucun I/O
        f = out[0].to_dict()
        self.assertEqual(f["status"], "skipped")                       # dégradation fail-closed
        self.assertIn("hors périmètre", f["title"])


# =================================================================================================
#  (c) NO-OP : aucun bloc auth -> chemin historique « config manquante », byte-identique
# =================================================================================================
class TestInertWhenNoAuthBlock(unittest.TestCase):
    def test_legacy_config_missing_skip_unchanged(self):
        sc = _scope()                                                  # aucun bloc auth
        self.assertIsNone(AuthContext.from_scope(sc))
        # action IDOR SANS accounts ni urls ni idor_targets (comme aujourd'hui sans contexte)
        a = Action("access_control.idor", "app.test", cls="access_control",
                   params={"in_scope": sc.in_scope, "out_scope": sc.out_scope})
        out = IdorDifferential().fire(a)
        f = out[0].to_dict()
        self.assertEqual(f["status"], "tested")
        self.assertIn("config manquante", f["title"])

    def test_engine_injects_known_creds_when_no_auth(self):
        # sans bloc auth, l'engine injecte le chemin historique (known_creds), pas idor_targets structurés
        sc = _scope(known_creds=[{"headers": {"Cookie": "a=1"}}, {"headers": {"Cookie": "b=2"}}],
                    idor_targets=["https://app.test/o/1"])
        eng = Engine(sc, mode="auto")
        self.assertIsNone(eng.auth_context)
        a = Action("access_control.idor", "app.test", cls="access_control")
        eng._prepare([a], None, {}, {})
        self.assertEqual(len(a.params["accounts"]), 2)
        self.assertNotIn("idor_targets", a.params)                     # pas de forme structurée injectée
        self.assertEqual(a.params["urls"], ["https://app.test/o/1"])   # historique inchangé


# =================================================================================================
#  (d)+(e) RÉDACTION + LEDGER : engine injecte le contexte, journalise l'usage (labels), pas de secret
# =================================================================================================
class TestEngineWiresAndRedacts(unittest.TestCase):
    def test_prepare_injects_auth_context_and_ledgers_use_without_secret(self):
        with tempfile.TemporaryDirectory() as d:
            led = Ledger(Path(d) / "ledger.jsonl")
            sc = _scope(auth=_auth_block())
            eng = Engine(sc, ledger=led, mode="auto")
            self.assertIsNotNone(eng.auth_context)
            a = Action("access_control.idor", "app.test", cls="access_control")
            eng._prepare([a], None, {}, {})
            # comptes labellisés + idor_targets structurés injectés dans l'action
            self.assertEqual([x["label"] for x in a.params["accounts"]], ["attacker", "victim"])
            self.assertEqual(len(a.params["idor_targets"]), 1)
            # ledger : événement engine.auth_context avec labels + compte, JAMAIS le secret
            raw = (Path(d) / "ledger.jsonl").read_text(encoding="utf-8")
            self.assertIn("engine.auth_context", raw)
            self.assertIn("attacker", raw)
            self.assertNotIn(BEARER, raw)
            self.assertNotIn("V1CT1M-cookie", raw)

    def test_ledgered_once(self):
        with tempfile.TemporaryDirectory() as d:
            led = Ledger(Path(d) / "l.jsonl")
            eng = Engine(_scope(auth=_auth_block()), ledger=led, mode="auto")
            a1 = Action("access_control.idor", "app.test", cls="access_control")
            a2 = Action("access_control.idor", "app.test", cls="access_control")
            eng._prepare([a1], None, {}, {})
            eng._prepare([a2], None, {}, {})
            raw = (Path(d) / "l.jsonl").read_text(encoding="utf-8")
            self.assertEqual(raw.count("engine.auth_context"), 1)

    def test_finding_poc_and_report_never_leak_token(self):
        sc = _scope(auth=_auth_block())

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if headers and headers.get("Authorization"):
                return 200, f'{{"email": "{MARKER}"}}', "application/json"
            return 403, "", "application/json"

        restore = _patch_fetch(fake)
        try:
            out = IdorDifferential().fire(_idor_action(sc))
        finally:
            restore()
        f = out[0].to_dict()
        # le finding brut (celui appendé au ledger par l'engine) est DÉJÀ rédigé à la source
        self.assertNotIn(BEARER, json.dumps(f))
        # et le rapport (redaction de tous les champs texte) ne le porte pas non plus
        report = normalize({"findings": [f]})
        self.assertNotIn(BEARER, json.dumps(report))
        self.assertIn("[REDACTED]", f["poc"])                          # le bearer du PoC est masqué


if __name__ == "__main__":
    unittest.main()

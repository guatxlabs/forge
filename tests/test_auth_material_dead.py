# SPDX-License-Identifier: AGPL-3.0-or-later
"""MATÉRIEL D'AUTHENTIFICATION MORT => AUCUN VERDICT — jumeau de `test_unreachable_no_verdict.py`.

Le bloc `auth` d'un engagement ARME les oracles de contrôle d'accès (`access_control.idor`,
`auth.takeover`, `access_control.privesc`). Quand la session qu'il porte n'authentifie plus, ces
oracles ne PLANTENT pas : toutes leurs conjonctions de preuve s'effondrent à False et
`proof(proven=False, …)` estampille `status='tested'` avec un titre qui AFFIRME l'absence de
vulnérabilité. Le run rend alors un rapport PROPRE et VIDE — indiscernable d'une cible saine. C'est
le mode d'échec le plus cher du projet (il a coûté une campagne), et il est SILENCIEUX là où
« cible injoignable » était seulement MUET.

Ce que le contrat exige :
  - matériel PÉRIMÉ (`exp` lisible et dépassé)     -> `status='skipped'`, AUCUNE requête émise ;
  - matériel INERTE (réponse identique à l'anonyme) -> `status='skipped'`, verdict refusé ;
  - session VIVANTE + réponse réelle                -> `status='tested'` (vrai négatif) ;
  - preuve réelle                                   -> `status='vulnerable'` (promotion intacte).

Les deux derniers points sont les CONTRÔLES NÉGATIFS : sans eux, un oracle qui refuserait TOUJOURS
de conclure passerait ce fichier haut la main — on aurait échangé un faux négatif contre un
aveuglement généralisé.

SECRET : un finding de dégradation ne porte QUE le LABEL du compte, jamais le jeton.
HERMÉTIQUE : `_fetch` est monkeypatché, zéro réseau.
"""
import base64
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests._tmp import temp_dir                                  # noqa: E402
from forge import session as _session                            # noqa: E402
from forge.engine import Engine                                  # noqa: E402
from forge.ledger import Ledger                                  # noqa: E402
from forge.modules.access_control import IdorDifferential, PrivEsc   # noqa: E402
from forge.modules.auth import AuthTakeover                      # noqa: E402
from forge.modules.oracle import Oracle                          # noqa: E402
from forge.roe import Action, Scope                              # noqa: E402
from forge.session import AuthContext                            # noqa: E402

URL = "https://app.test/api/orders/1"
MARKER = "victim-private-marker-9z8y7x"
OPAQUE = "sid=OPAQUE-cookie-no-expiry-4f2a"        # matériel SANS échéance lisible -> « inconnu »


# --- fabrique de jetons : un JWT NON SIGNÉ dont on choisit l'`exp` -------------------------------
def _jwt(exp=None, extra=None):
    """JWT de test (signature bidon — jamais vérifiée : on ne LIT qu'une date auto-déclarée)."""
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    payload = dict(extra or {})
    if exp is not None:
        payload["exp"] = int(exp)
    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg(payload)}.c2ln"


DEAD = _jwt(exp=time.time() - 3600)                # périmé depuis 1 h
LIVE = _jwt(exp=time.time() + 3600)                # valide encore 1 h
DEAD_HDRS = {"Authorization": f"Bearer {DEAD}"}
LIVE_HDRS = {"Authorization": f"Bearer {LIVE}"}


def _patch(cls, fn):
    orig = cls._fetch
    cls._fetch = staticmethod(fn)
    return lambda: setattr(cls, "_fetch", orig)


def _fire(cls, action, fn):
    restore = _patch(cls, fn)
    try:
        return cls().fire(action)
    finally:
        restore()


def _idor_action(accounts, targets=None, urls=None, method="GET", body=None, destructive=False):
    a = Action("access_control.idor", "app.test", cls="access_control",
               params={"accounts": accounts, "in_scope": ["app.test"], "out_scope": [], "method": method})
    if targets is not None:
        a.params["idor_targets"] = targets
    if urls is not None:
        a.params["urls"] = urls
    if body is not None:
        a.params["body"] = body
    a.destructive = destructive
    return a


def _ato_action(accounts, targets):
    return Action("auth.takeover", "app.test", cls="auth",
                  params={"accounts": accounts, "idor_targets": targets,
                          "in_scope": ["app.test"], "out_scope": []})


def _privesc_action(accounts):
    return Action("access_control.privesc", "app.test", cls="access_control",
                  params={"accounts": accounts, "admin_urls": [URL],
                          "in_scope": ["app.test"], "out_scope": []})


TARGETS = [{"url": URL, "owner": "victim", "marker": MARKER}]


# =================================================================================================
#  (1) LECTURE DE LA PÉREMPTION — helpers purs, aucun réseau, aucun secret rendu
# =================================================================================================
class TestExpiryReading(unittest.TestCase):
    def test_reads_exp_from_jwt(self):
        self.assertEqual(_session.jwt_expiry(_jwt(exp=1700000000)), 1700000000)

    def test_unreadable_material_is_unknown_not_expired(self):
        """INCONNU != EXPIRÉ : un cookie opaque ne doit JAMAIS être accusé de péremption (sinon tout
        engagement à cookies deviendrait « non testé » en bloc)."""
        for junk in ("", "opaque-session-value", "not.a.jwt", _jwt(exp=None), "eyJhbGciOiJIUzI1NiJ9"):
            self.assertIsNone(_session.jwt_expiry(junk), junk)
            self.assertFalse(_session.headers_expired({"Cookie": junk}), junk)

    def test_expired_and_live_verdicts(self):
        self.assertTrue(_session.headers_expired(DEAD_HDRS))
        self.assertFalse(_session.headers_expired(LIVE_HDRS))

    def test_finds_token_wrapped_in_cookie_and_takes_earliest(self):
        """Le jeton est ENROBÉ (`sid=<jwt>; theme=dark`) et plusieurs en-têtes peuvent en porter :
        c'est la PLUS PROCHE échéance qui décide."""
        hdrs = {"Cookie": f"sid={DEAD}; theme=dark", "X-Token": LIVE}
        self.assertEqual(_session.headers_expiry(hdrs), _session.jwt_expiry(DEAD))
        self.assertTrue(_session.headers_expired(hdrs))

    def test_grace_delays_the_accusation_never_advances_it(self):
        """La grâce d'horloge pousse la déclaration PLUS TARD (jamais plus tôt) : un jeton périmé de
        10 s n'est pas encore accusé, le même périmé d'une heure l'est."""
        just_dead = {"Authorization": f"Bearer {_jwt(exp=time.time() - 10)}"}
        self.assertFalse(_session.headers_expired(just_dead))
        self.assertTrue(_session.headers_expired(DEAD_HDRS))

    def test_census_and_labels_carry_no_secret(self):
        ctx = AuthContext.from_scope(Scope({
            "mode": "grey", "in_scope": ["app.test"],
            "auth": {"accounts": [{"label": "attacker", "bearer": DEAD},
                                  {"label": "victim", "bearer": LIVE},
                                  {"label": "opaque", "cookies": OPAQUE}],
                     "idor_targets": TARGETS}}))
        self.assertEqual(ctx.expired_labels(), ["attacker"])
        self.assertEqual(ctx.expiry_census(),
                         {"attacker": "expired", "victim": "valid", "opaque": "unknown"})
        blob = json.dumps(ctx.expiry_census()) + json.dumps(ctx.expired_labels())
        self.assertNotIn(DEAD, blob)
        self.assertNotIn(LIVE, blob)


# =================================================================================================
#  (2) MATÉRIEL INERTE — table de vérité du signal lu sur les sondes DÉJÀ tirées
# =================================================================================================
class TestInertTruthTable(unittest.TestCase):
    def test_identical_barrier_response_is_inert(self):
        for st in (401, 403, 302):
            self.assertTrue(Oracle.auth_inert((st, ""), (st, "")), st)

    def test_access_obtained_is_never_inert(self):
        self.assertFalse(Oracle.auth_inert((200, "{}"), (200, "{}")))

    def test_non_barrier_status_is_never_inert(self):
        """404/5xx identiques disent l'OBJET ou le SERVEUR, pas la session — les retenir aurait
        transformé tout vrai négatif en aveuglement (cf. test_unreachable_no_verdict)."""
        for st in (404, 410, 500, 503):
            self.assertFalse(Oracle.auth_inert((st, ""), (st, "")), st)

    def test_difference_with_anon_proves_the_session_is_seen(self):
        self.assertFalse(Oracle.auth_inert((403, ""), (401, "")))
        self.assertFalse(Oracle.auth_inert((403, "forbidden-for-you"), (403, "please log in")))

    def test_unreachable_probe_is_not_inert(self):
        self.assertFalse(Oracle.auth_inert((None, ""), (403, "")))
        self.assertFalse(Oracle.auth_inert((403, ""), (None, "")))

    def test_sibling_that_got_in_forbids_the_inert_verdict(self):
        """GARDE ANTI-FAUX-POSITIF : si un compte du même jeu de sondes ENTRE (2xx), la cible
        DISCRIMINE démontrablement et le refus de l'autre se lit comme une AUTORISATION refusée."""
        probes = [("admin", (200, "panel")), ("low", (403, ""))]
        self.assertIsNone(Oracle.auth_inert_among(probes, (403, "")))
        self.assertEqual(Oracle.auth_inert_among([("low", (403, ""))], (403, "")), "low")


# =================================================================================================
#  (3) IDOR — slice cross-compte (idor_targets) : périmé ET inerte
# =================================================================================================
class TestIdorCrossAccount(unittest.TestCase):
    def test_expired_material_skips_without_any_request(self):
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", body=None):
            calls.append(url)
            return 200, f'{{"email": "{MARKER}"}}', "application/json"

        out = _fire(IdorDifferential,
                    _idor_action([{"label": "attacker", "headers": DEAD_HDRS}], targets=TARGETS), fake)
        self.assertEqual(calls, [], "matériel périmé : AUCUNE requête ne doit partir")
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("EXPIRÉ", out[0].title)

    def test_inert_material_refuses_the_verdict(self):
        def fake(url, headers=None, timeout=15, method="GET", body=None):
            return 401, "", "application/json"          # attaquant ET anonyme : traités pareil

        out = _fire(IdorDifferential,
                    _idor_action([{"label": "attacker", "headers": {"Cookie": OPAQUE}}], targets=TARGETS), fake)
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("SANS EFFET", out[0].title)

    def test_live_session_still_yields_a_verdict(self):
        """CONTRÔLE NÉGATIF : session vivante + réponse réelle sans signal -> `tested`."""
        def fake(url, headers=None, timeout=15, method="GET", body=None):
            if headers and headers.get("Authorization"):
                return 200, '{"order": 1, "email": "someone-else"}', "application/json"
            return 403, "", "application/json"

        out = _fire(IdorDifferential,
                    _idor_action([{"label": "attacker", "headers": LIVE_HDRS}], targets=TARGETS), fake)
        self.assertEqual(out[0].status, "tested")
        self.assertNotIn("EXPIRÉ", out[0].title)

    def test_live_session_still_promotes_a_real_proof(self):
        """CONTRÔLE NÉGATIF : la promotion HIGH reste intacte (la garde n'aveugle pas l'oracle)."""
        def fake(url, headers=None, timeout=15, method="GET", body=None):
            if headers and headers.get("Authorization"):
                return 200, f'{{"email": "{MARKER}"}}', "application/json"
            return 403, "", "application/json"

        out = _fire(IdorDifferential,
                    _idor_action([{"label": "attacker", "headers": LIVE_HDRS}], targets=TARGETS), fake)
        self.assertEqual(out[0].status, "vulnerable")
        self.assertEqual(out[0].severity, "HIGH")

    def test_degraded_finding_names_the_label_never_the_token(self):
        out = _fire(IdorDifferential,
                    _idor_action([{"label": "attacker", "headers": DEAD_HDRS}], targets=TARGETS),
                    lambda *a, **k: (200, "", "application/json"))
        blob = json.dumps(out[0].to_dict())
        self.assertIn("attacker", blob)                      # le LABEL est nommé (actionnable)
        self.assertNotIn(DEAD, blob)                         # le JETON ne fuit pas
        self.assertNotIn(DEAD.split(".")[1], blob)           # ni un de ses fragments


# =================================================================================================
#  (4) IDOR — différentiel 2 comptes (read) et oracle d'effet (write)
# =================================================================================================
class TestIdorTwoAccountPaths(unittest.TestCase):
    LIVE_A = {"label": "A", "headers": LIVE_HDRS}
    DEAD_B = {"label": "B", "headers": DEAD_HDRS}

    def test_read_expired_account_skips_without_request(self):
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", body=None):
            calls.append(url)
            return 200, "same-body", "application/json"

        out = _fire(IdorDifferential, _idor_action([self.LIVE_A, self.DEAD_B], urls=[URL]), fake)
        self.assertEqual(calls, [])
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("EXPIRÉ", out[0].title)

    def test_read_inert_when_nobody_is_recognised(self):
        out = _fire(IdorDifferential,
                    _idor_action([{"label": "A", "headers": {"Cookie": OPAQUE}},
                                  {"label": "B", "headers": {"Cookie": OPAQUE}}], urls=[URL]),
                    lambda *a, **k: (403, "", "text/html"))
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("SANS EFFET", out[0].title)

    def test_read_hardened_target_still_yields_a_verdict(self):
        """CONTRÔLE NÉGATIF (la garde anti-faux-positif) : A entre, B est refusé comme l'anonyme —
        la cible DISCRIMINE, c'est un vrai négatif d'IDOR, pas une session morte."""
        def fake(url, headers=None, timeout=15, method="GET", body=None):
            if (headers or {}).get("Cookie") == "a":
                return 200, '{"owner": "A"}', "application/json"
            return 403, "", "text/html"

        out = _fire(IdorDifferential,
                    _idor_action([{"label": "A", "headers": {"Cookie": "a"}},
                                  {"label": "B", "headers": {"Cookie": "b"}}], urls=[URL]), fake)
        self.assertEqual(out[0].status, "tested")

    def test_write_expired_account_emits_no_write(self):
        """Chemin CRITICAL : « IDOR write non confirmé » certifierait une mutation cross-compte que la
        session morte n'a jamais pu tenter."""
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", body=None):
            calls.append(method)
            return 200, "x", "application/json"

        out = _fire(IdorDifferential,
                    _idor_action([self.LIVE_A, self.DEAD_B], urls=[URL], method="PUT",
                                 body="{}", destructive=True), fake)
        self.assertEqual(calls, [], "aucune écriture ne doit partir avec un matériel périmé")
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("EXPIRÉ", out[0].title)


# =================================================================================================
#  (5) PRIVESC — bas-privilège / admin
# =================================================================================================
class TestPrivEsc(unittest.TestCase):
    def test_expired_account_skips_without_request(self):
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", body=None):
            calls.append(url)
            return 200, "<h1>ADMIN</h1>", "text/html"

        out = _fire(PrivEsc, _privesc_action([{"label": "low", "headers": DEAD_HDRS},
                                              {"label": "admin", "headers": LIVE_HDRS}]), fake)
        self.assertEqual(calls, [])
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("EXPIRÉ", out[0].title)

    def test_inert_when_nobody_is_recognised(self):
        out = _fire(PrivEsc, _privesc_action([{"label": "low", "headers": {"Cookie": OPAQUE}},
                                              {"label": "admin", "headers": {"Cookie": OPAQUE}}]),
                    lambda *a, **k: (403, "forbidden", "text/html"))
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("SANS EFFET", out[0].title)


# =================================================================================================
#  (6) ATO / TAKEOVER — la classe la plus grave du catalogue
# =================================================================================================
class TestAuthTakeover(unittest.TestCase):
    def test_expired_material_skips_without_any_request(self):
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            calls.append(url)
            return 200, MARKER, {}

        out = _fire(AuthTakeover, _ato_action([{"label": "attacker", "headers": DEAD_HDRS}], TARGETS), fake)
        self.assertEqual(calls, [])
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("EXPIRÉ", out[0].title)

    def test_inert_material_refuses_the_verdict(self):
        out = _fire(AuthTakeover,
                    _ato_action([{"label": "attacker", "headers": {"Cookie": OPAQUE}}], TARGETS),
                    lambda *a, **k: (401, "", {}))
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("SANS EFFET", out[0].title)

    def test_live_session_still_promotes_a_real_takeover(self):
        """CONTRÔLE NÉGATIF : la promotion CRITICAL reste intacte."""
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if headers and headers.get("Authorization"):
                return 200, f'{{"user": "{MARKER}"}}', {}
            return 401, "", {}

        out = _fire(AuthTakeover, _ato_action([{"label": "attacker", "headers": LIVE_HDRS}], TARGETS), fake)
        self.assertEqual(out[0].status, "vulnerable")
        self.assertEqual(out[0].severity, "CRITICAL")

    def test_config_driven_path_also_guards_the_session(self):
        """Chemin historique (whoami_url/victim_marker) : la session vient de params, pas du bloc auth."""
        calls = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            calls.append(url)
            return 200, "victime", {}

        a = Action("auth.takeover", "app.test", cls="auth",
                   params={"whoami_url": URL, "victim_marker": "victime",
                           "attacker_session_headers": DEAD_HDRS,
                           "in_scope": ["app.test"], "out_scope": []})
        out = _fire(AuthTakeover, a, fake)
        self.assertEqual(calls, [])
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("EXPIRÉE", out[0].title)


# =================================================================================================
#  (7) LE RUN LE DIT — ledger + ligne d'avancement live, labels seuls, une seule fois
# =================================================================================================
class TestRunSaysIt(unittest.TestCase):
    @staticmethod
    def _scope(bearer):
        return Scope({"mode": "grey", "in_scope": ["app.test"], "out_scope": [], "allow_exploit": True,
                      "auth": {"accounts": [{"label": "attacker", "bearer": bearer},
                                            {"label": "victim", "cookies": OPAQUE}],
                               "idor_targets": TARGETS}})

    def _run_prepare(self, bearer):
        lines = []
        d = temp_dir(self, "forge-authmat-")
        led = Ledger(Path(d) / "ledger.jsonl")
        eng = Engine(self._scope(bearer), ledger=led, mode="auto", progress=lines.append)
        eng._prepare([Action("access_control.idor", "app.test", cls="access_control")], None, {}, {})
        eng._prepare([Action("access_control.idor", "app.test", cls="access_control")], None, {}, {})
        return (Path(d) / "ledger.jsonl").read_text(encoding="utf-8"), lines

    def test_expired_context_is_named_in_ledger_and_live_log(self):
        raw, lines = self._run_prepare(DEAD)
        self.assertIn("engine.auth_expired", raw)
        self.assertIn("attacker", raw)
        self.assertNotIn(DEAD, raw)                                  # SECRET : jamais le jeton
        self.assertEqual(raw.count("engine.auth_expired"), 1)        # émis UNE fois
        self.assertTrue(any("[AUTH]" in x and "EXPIRÉ" in x for x in lines), lines)

    def test_live_context_stays_silent(self):
        """CONTRÔLE NÉGATIF : aucun bruit quand le matériel est valide."""
        raw, lines = self._run_prepare(LIVE)
        self.assertIn("engine.auth_context", raw)                    # le contexte est bien armé…
        self.assertNotIn("engine.auth_expired", raw)                 # …et rien n'est signalé
        self.assertFalse([x for x in lines if "[AUTH]" in x])


if __name__ == "__main__":
    unittest.main()

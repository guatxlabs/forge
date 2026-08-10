# SPDX-License-Identifier: AGPL-3.0-or-later
"""RÔLE DE SONDE ANONYME + VÉTO DE PUBLICITÉ — les deux défauts de contrôle d'accès mis au jour par
le banc de détection (`docs/BENCH_DETECTION.md` §6, D1/D2/D3), prouvés DANS LES DEUX SENS.

POURQUOI CE FICHIER EXISTE, ET POURQUOI IL NE STUBE PAS `_fetch`
---------------------------------------------------------------
Toute la suite d'oracles monkeypatche le seam `_fetch` — c'est hermétique, rapide, et c'est
EXACTEMENT pourquoi D1 a survécu : le défaut vit dans `Oracle._http`, SOUS le seam. Un double de
`_fetch` ne voit jamais la fusion du matériel de session, donc aucun test stubé ne peut, par
construction, l'observer. Les 2268 tests de la suite restaient verts avec le défaut EN PLACE.

Ce fichier tire donc de VRAIES requêtes HTTP vers un serveur LOOPBACK monté par le test
(`127.0.0.1`, port éphémère, aucun trafic sortant), avec un `SessionStore` gouverné RÉELLEMENT lié
— la configuration que `scope.example.json` recommande, et qui désarmait l'oracle.

LES DEUX SENS, PARCE QU'UN SEUL SENS N'EST PAS UNE CORRECTION
------------------------------------------------------------
Le banc donne les deux moitiés, et la correction doit tenir les deux :

  SENS 1 — le VRAI IDOR reste CONFIRMÉ. `/api/private/order` (forme de la BOLA de VAmPI :
           ressource privée, 401 à l'anonyme, marqueur de la victime) -> HIGH `vulnerable`.
  SENS 2 — la ressource PUBLIQUE n'est JAMAIS promue. `/api/public/users` (forme de `/users/v1` de
           VAmPI : 200 anonyme PAR CONCEPTION, le marqueur y figure) -> INFO `tested`.

Et la borne qui interdit l'EXCÈS INVERSE :

  SENS 3 — `/api/shared` répond 2xx à TOUT LE MONDE mais ne sert la donnée de la victime
           qu'AUTHENTIFIÉ. Exiger le véto anonyme (`anon_denied`) pour promouvoir aurait tué ce vrai
           positif : il doit rester CONFIRMÉ. C'est la raison pour laquelle le discriminant de D3
           porte sur le MARQUEUR, pas sur le STATUT de l'anonyme.
  SENS 4 — la distinction est PAR RÔLE, pas un interrupteur global : sur la MÊME URL, avec le MÊME
           dict d'en-têtes VIDE, la sonde de l'attaquant part AUTHENTIFIÉE (session gouvernée) et la
           sonde de contrôle part ANONYME. C'est `TestRoleNotGlobalSwitch` qui le mesure, en comptant
           les requêtes reçues par le serveur.
"""
import http.server
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import session                                          # noqa: E402
from forge.engine import Engine                                    # noqa: E402
from forge.modules.access_control import IdorDifferential, PrivEsc  # noqa: E402
from forge.modules.auth import AuthTakeover                        # noqa: E402
from forge.roe import Action, Scope                                # noqa: E402

# --- constantes du harnais -------------------------------------------------------------------------
VICTIM_MARKER = "VICTIM_SECRET_MARKER_7Q3"        # donnée de la VICTIME (forme du marqueur VAmPI)
ATTACKER_BEARER = "attacker-token-never-logged"   # matériel de l'attaquant (via scope.session)
ADMIN_MARKER = "ADMIN_ONLY_PANEL_MARKER"


class _Handler(http.server.BaseHTTPRequestHandler):
    """Cible loopback aux QUATRE formes que le banc a rencontrées.

      /api/private/order  — PRIVÉE : 401 sans jeton, 200 + marqueur victime avec. (VAmPI
                            `/books/v1/victimbook` : le VRAI IDOR à conserver.)
      /api/public/users   — PUBLIQUE PAR CONCEPTION : 200 pour tous, marqueur inclus. (VAmPI
                            `/users/v1` : le faux HIGH à ne plus jamais promouvoir.)
      /api/shared         — 2xx pour TOUS, mais la donnée de la victime N'EST SERVIE
                            qu'authentifié. (La borne anti-excès-inverse.)
      /admin/panel        — 401 sans jeton, marqueur admin avec. (Sonde de contrôle de `privesc`.)

    Le serveur COMPTE ce qu'il reçoit (chemin, jeton présent ou non) : c'est cette trace, et non un
    verdict d'oracle, qui prouve qu'une sonde est réellement partie anonyme."""

    protocol_version = "HTTP/1.0"
    seen = []                                     # [(path, bool(jeton présent))] — partagé, remis à zéro par test

    def log_message(self, *_a):                   # silencieux
        pass

    def _send(self, code, body=""):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):                             # noqa: N802
        authed = bool(self.headers.get("Authorization"))
        type(self).seen.append((self.path, authed))
        if self.path.startswith("/api/public/users"):
            return self._send(200, f'{{"users": ["{VICTIM_MARKER}", "attacker1"]}}')
        if self.path.startswith("/api/shared"):
            if authed:
                return self._send(200, f'{{"shared": true, "owner": "{VICTIM_MARKER}"}}')
            return self._send(200, '{"shared": true, "owner": null}')
        if self.path.startswith("/admin/panel"):
            if not authed:
                return self._send(401)
            return self._send(200, f'{{"panel": "{ADMIN_MARKER}"}}')
        if not authed:
            return self._send(401)
        return self._send(200, f'{{"order": 1, "owner": "{VICTIM_MARKER}"}}')

    do_POST = do_GET


class _Harness(unittest.TestCase):
    """Serveur loopback + scope gouverné, montés/démontés par test. LOOPBACK STRICT : le serveur est
    lié à `127.0.0.1` sur un port éphémère et le périmètre est borné à CE couple hôte:port."""

    def setUp(self):
        _Handler.seen = []
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.srv.socket.settimeout(1.0)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.hostport = f"127.0.0.1:{self.port}"
        self.base = f"http://{self.hostport}"

    def _stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)

    # --- scope : le PIÈGE de D1 reproduit tel quel (un `session` gouverné EST configuré) -----------
    def scope(self, url, marker=VICTIM_MARKER, account_headers=None):
        """Scope AVEC `session` (ce que `scope.example.json` recommande) + bloc `auth` par-engagement.

        `account_headers=None` -> le compte attaquant ne porte AUCUN en-tête propre : c'est alors la
        SESSION GOUVERNÉE qui l'authentifie. C'est la configuration la plus dure pour le correctif —
        la sonde de l'attaquant et la sonde de contrôle passent le MÊME dict vide, seul leur RÔLE
        les distingue."""
        return Scope({
            "mode": "grey",
            "in_scope": [self.hostport],
            "out_scope": [],
            "allow_private": True,
            "allow_exploit": True,
            "session": {"bearer": ATTACKER_BEARER},
            "auth": {
                "accounts": [
                    {"label": "attacker", **({"headers": account_headers} if account_headers else {})},
                    {"label": "victim", "headers": {"Authorization": "Bearer victim-token"}},
                ],
                "idor_targets": [{"url": url, "owner": "victim", "marker": marker}],
            },
        })

    def action(self, scope, kind="access_control.idor", cls="access_control", **params):
        a = Action(kind, self.hostport, cls=cls)
        a.params["in_scope"] = scope.in_scope
        a.params["out_scope"] = scope.out_scope
        a.params.update(params)
        return a

    def fire_idor(self, scope, url):
        """Tire l'oracle IDOR AVEC le store gouverné lié — exactement comme le moteur le fait."""
        ctx = session.AuthContext.from_scope(scope)
        a = self.action(scope, accounts=ctx.accounts_as_params(),
                        idor_targets=list(ctx.idor_targets))
        store = session.SessionStore.from_scope(scope)
        with session.using(store):
            return [f.to_dict() for f in IdorDifferential().fire(a)]


# =================================================================================================
#  SENS 1 — le VRAI IDOR reste CONFIRMÉ malgré une session gouvernée (D1/D2)
# =================================================================================================
class TestGovernedSessionDoesNotDisarmTheOracle(_Harness):

    def test_private_resource_is_confirmed_with_governed_session(self):
        url = self.base + "/api/private/order"
        out = self.fire_idor(self.scope(url), url)
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f["status"], "vulnerable")            # D1 : rendait 'tested' (INFO)
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("CONFIRMÉ", f["title"])
        # D2 : l'evidence dit la VÉRITÉ sur la sonde de contrôle (elle disait `anon=200`).
        self.assertIn("anon=401", f["evidence"])
        self.assertIn("anon_refusé=True", f["evidence"])

    def test_control_probe_really_left_without_the_governed_material(self):
        """La PREUVE n'est pas le verdict, c'est la trace du serveur : une requête sur cette URL est
        arrivée SANS `Authorization` alors qu'un `scope.session` était lié."""
        url = self.base + "/api/private/order"
        self.fire_idor(self.scope(url), url)
        hits = [authed for path, authed in _Handler.seen if path == "/api/private/order"]
        self.assertIn(False, hits)                             # la sonde de contrôle : ANONYME
        self.assertIn(True, hits)                              # la sonde de l'attaquant : AUTHENTIFIÉE


# =================================================================================================
#  SENS 2 — la ressource PUBLIQUE n'est JAMAIS promue (D3)
# =================================================================================================
class TestPublicResourceIsNeverPromoted(_Harness):

    def test_public_200_carrying_the_marker_is_not_an_idor(self):
        url = self.base + "/api/public/users"
        out = self.fire_idor(self.scope(url), url)
        f = out[0]
        self.assertEqual(f["status"], "tested")                # D3 : rendait 'vulnerable' HIGH
        self.assertNotIn("CONFIRMÉ", f["title"])
        self.assertIn("LISIBLE ANONYMEMENT", f["title"])
        self.assertIn("marqueur_lisible_anonymement=True", f["evidence"])

    def test_public_200_carrying_the_marker_is_not_an_ato(self):
        """MÊME véto sur `auth.takeover` : le signal (A) y a la MÊME forme et promeut un CRITICAL."""
        url = self.base + "/api/public/users"
        sc = self.scope(url)
        ctx = session.AuthContext.from_scope(sc)
        a = self.action(sc, kind="auth.takeover", cls="auth",
                        accounts=ctx.accounts_as_params(), idor_targets=list(ctx.idor_targets))
        store = session.SessionStore.from_scope(sc)
        with session.using(store):
            out = [f.to_dict() for f in AuthTakeover().fire(a)]
        self.assertEqual(out[0]["status"], "tested")
        self.assertIn("marqueur_lisible_anonymement=True", out[0]["evidence"])


# =================================================================================================
#  SENS 3 — PAS D'EXCÈS INVERSE : 2xx pour tous, mais la donnée reste privée -> CONFIRMÉ
# =================================================================================================
class TestNoInverseExcess(_Harness):

    def test_true_idor_on_a_resource_that_answers_2xx_to_everyone(self):
        """`anon=200` ET pourtant un vrai IDOR : le marqueur de la victime n'est servi qu'authentifié.
        Un correctif de D3 qui exigerait `anon_denied` pour promouvoir DÉTRUIRAIT ce cas."""
        url = self.base + "/api/shared"
        out = self.fire_idor(self.scope(url), url)
        f = out[0]
        self.assertEqual(f["status"], "vulnerable")
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("anon=200", f["evidence"])               # l'anonyme n'est PAS refusé...
        self.assertIn("marqueur_lisible_anonymement=False", f["evidence"])   # ...mais le marqueur, si


# =================================================================================================
#  SENS 4 — RÔLE, pas interrupteur global : même URL, même dict vide, deux rôles
# =================================================================================================
class TestRoleNotGlobalSwitch(_Harness):

    def test_attacker_probe_keeps_the_session_while_control_probe_does_not(self):
        """Le compte attaquant ne porte AUCUN en-tête propre : les deux sondes passent `{}`. C'est
        donc UNIQUEMENT le rôle déclaré qui les sépare — et le serveur voit bien une requête
        authentifiée (par la session gouvernée) et une requête anonyme."""
        url = self.base + "/api/private/order"
        out = self.fire_idor(self.scope(url), url)
        hits = [authed for path, authed in _Handler.seen if path == "/api/private/order"]
        self.assertEqual(sorted(hits), [False, True])
        self.assertEqual(out[0]["status"], "vulnerable")       # la session gouvernée ARME toujours l'oracle

    def test_privesc_control_probe_is_anonymous_too(self):
        """`access_control.privesc` porte le MÊME défaut de classe : `anon_denied` est un CONJOINT de
        sa promotion. Sonde de contrôle anonyme -> 401 -> la privesc peut être prouvée."""
        url = self.base + "/admin/panel"
        sc = self.scope(url, marker=ADMIN_MARKER)
        a = self.action(sc, kind="access_control.privesc",
                        accounts=[{"label": "low"}, {"label": "admin"}],
                        admin_urls=[url], admin_marker=ADMIN_MARKER)
        store = session.SessionStore.from_scope(sc)
        with session.using(store):
            out = [f.to_dict() for f in PrivEsc().fire(a)]
        self.assertEqual(out[0]["status"], "vulnerable")
        self.assertIn("anon_refusé=True", out[0]["evidence"])

    def test_anonymous_scope_is_reentrant_and_exception_safe(self):
        """La portée est un COMPTEUR (réentrante) et se referme même sur exception : une sonde de
        contrôle qui lève ne doit pas rendre anonyme le reste du `fire()`."""
        self.assertFalse(session.probe_is_anonymous())
        with session.anonymous_probe():
            self.assertTrue(session.probe_is_anonymous())
            with session.anonymous_probe():
                self.assertTrue(session.probe_is_anonymous())
            self.assertTrue(session.probe_is_anonymous())       # l'imbrication ne referme pas trop tôt
        self.assertFalse(session.probe_is_anonymous())
        try:
            with session.anonymous_probe():
                raise RuntimeError("sonde hostile")
        except RuntimeError:
            pass
        self.assertFalse(session.probe_is_anonymous())


# =================================================================================================
#  D10 — `forge run --actions` arme enfin le contexte d'auth par-engagement
# =================================================================================================
class TestRunInjectsAuthContext(_Harness):

    def test_engine_run_arms_the_idor_oracle(self):
        """Avec un `scope.auth` COMPLET, une action IDOR NUE passée à `Engine.run()` rendait « IDOR
        non testé — config manquante » : l'injection ne vivait que sur le chemin `campaign()`."""
        url = self.base + "/api/private/order"
        sc = self.scope(url)
        eng = Engine(sc, mode="auto")
        eng.arm("test D10")
        a = Action("access_control.idor", self.hostport, cls="access_control")
        eng.run([a])
        titles = [f.to_dict()["title"] for f in eng.findings]
        self.assertTrue(titles, "aucun finding émis")
        self.assertFalse(any("config manquante" in t for t in titles), titles)
        self.assertTrue(any("CONFIRMÉ" in t for t in titles), titles)

    def test_injection_is_idempotent_between_prepare_and_run(self):
        """Une action déjà préparée (campagne) qui repasse par `run()` n'est ni réécrite ni
        re-journalisée : `setdefault` + garde « une seule fois » du ledger."""
        url = self.base + "/api/private/order"
        sc = self.scope(url)
        eng = Engine(sc, mode="auto")
        eng.arm("test idempotence")
        a = Action("access_control.idor", self.hostport, cls="access_control")
        eng._inject_auth_context([a])
        snapshot = dict(a.params)
        eng._inject_auth_context([a])
        self.assertEqual(a.params, snapshot)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""D4 — `header_injection.probe` promouvait un HIGH sur une REDIRECTION DE RÉPERTOIRE, prouvé DANS
LES DEUX SENS (`docs/BENCH_DETECTION.md` §6, D4).

CE QU'A MESURÉ LE BANC
----------------------
**5 HIGH FAUX** — 4 sur DVWA (Apache 2.4, un par répertoire découvert) + 1 sur VAmPI (Werkzeug 2.2).
Un seul phénomène derrière les cinq : une requête sur un répertoire SANS slash final reçoit une
redirection de canonicalisation dont le `Location` est reconstruit depuis l'en-tête `Host` :

    curl -H 'Host: evil.example' http://.../docs  ->  301  Location: http://evil.example/docs/
    curl -H 'Host: evil.example' http://.../ui    ->  308  Location: http://evil.example/ui/

DEUX STACKS INDÉPENDANTES : ce n'est pas un bug d'application, c'est la normalisation d'URI que fait
à peu près tout serveur web. Aucune des quatre applications du banc ne déclarait cette classe dans sa
vérité terrain.

POURQUOI LE CONTRÔLE EXISTANT NE POUVAIT PAS RATTRAPER
------------------------------------------------------
`control_reflects_host` compare avec le VRAI `Host` — celui où le marqueur ne peut PAR CONSTRUCTION
jamais apparaître. Le contrôle rendait donc toujours `False` et la conjonction promouvait toujours.
Et `Oracle.path_discrimination()` (le contrôle négatif générique livré pour la même FAMILLE de
défaut) ne couvre pas ce cas : `TestPathDiscriminationNeCouvrePas` le MESURE plutôt que de le
supposer — elle rend `verdict=True` sur la cible fautive, parce qu'elle répond à une autre question.

LES DEUX SENS, PARCE QU'UN SEUL SENS N'EST PAS UNE CORRECTION
-------------------------------------------------------------
  SENS 1 — le comportement PAR DÉFAUT devient muet. Redirection de répertoire Apache (301, corps
           auto-généré recopiant le `Location`) ET Werkzeug (308, corps vide) -> INFO `tested`.
  SENS 2 — la VRAIE injection d'en-tête reste HIGH. Trois formes qui PAIENT, toutes conservées :
           lien de réinitialisation absolu bâti depuis `Host` (corps), redirection applicative vers
           un AUTRE chemin, et CRLF response-splitting.
  SENS 3 — la borne contre l'EXCÈS INVERSE : une canonicalisation qui porte EN PLUS un reflet
           résiduel (en-tête `Link` applicatif) reste HIGH. La neutralisation retire l'ÉCHO, jamais
           la preuve — sinon il suffirait de cacher un vrai reflet derrière un 301 pour être muet.

Les cas loopback tirent de VRAIES requêtes HTTP vers `127.0.0.1` (port éphémère, aucun trafic
sortant) : le défaut vit dans l'interaction entre le statut, le `Location` et le corps réels.
"""
import http.server
import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.modules.httpflow import HeaderInjectionProbe, _same_path   # noqa: E402
from forge.roe import Action                                          # noqa: E402


# =================================================================================================
#  Harnais loopback — chaque handler est UNE forme rencontrée par le banc (ou sa contre-épreuve).
# =================================================================================================
def _injected_host(h):
    """L'hôte que l'oracle a injecté (X-Forwarded-Host prioritaire, sinon Host) — c'est ce que tout
    serveur web recopie dans un `Location` absolu."""
    return h.headers.get("X-Forwarded-Host") or h.headers.get("Host") or "localhost"


def _send(h, code, body=b"", extra=()):
    h.send_response(code)
    for k, v in extra:
        h.send_header(k, v)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    if body:
        h.wfile.write(body)


class ApacheDirRedirect(http.server.BaseHTTPRequestHandler):
    """DÉFAUT — Apache 2.4 : `/docs` -> 301 `Location: http://<Host>/docs/`, avec le corps
    auto-généré qui RECOPIE le `Location` (« The document has moved <a href=…>here</a> »). C'est ce
    corps qui a fait entrer 4 des 5 faux HIGH par la porte du CORPS et non du `Location`."""

    def do_GET(self):
        host = _injected_host(self)
        if not self.path.endswith("/"):
            loc = f"http://{host}{self.path}/"
            body = (b'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
                    b'<title>301 Moved Permanently</title>\n</head><body>\n<h1>Moved Permanently</h1>\n'
                    + f'<p>The document has moved <a href="{loc}">here</a>.</p>\n'.encode()
                    + b'</body></html>\n')
            return _send(self, 301, body, [("Location", loc)])
        return _send(self, 200, b"<html>index of docs</html>")

    def log_message(self, *a):
        pass


class WerkzeugDirRedirect(http.server.BaseHTTPRequestHandler):
    """DÉFAUT — Werkzeug 2.2 : `/ui` -> 308 `Location: http://<Host>/ui/`, corps vide. Seconde stack,
    même phénomène : c'est ce qui prouve que le comportement n'est pas applicatif."""

    def do_GET(self):
        host = _injected_host(self)
        if not self.path.endswith("/"):
            return _send(self, 308, b"", [("Location", f"http://{host}{self.path}/")])
        return _send(self, 200, b"<html>swagger ui</html>")

    def log_message(self, *a):
        pass


class ResetLinkPoison(http.server.BaseHTTPRequestHandler):
    """VRAI (celui qui PAIE) — la route applicative bâtit le lien de réinitialisation absolu depuis
    `Host` : le marqueur atterrit dans un lien envoyé à la victime par e-mail."""

    def do_GET(self):
        host = _injected_host(self)
        return _send(self, 200, (
            f'<html><body>Un e-mail a été envoyé. Lien : '
            f'<a href="https://{host}/account/reset/confirm?token=abc123">réinitialiser</a>'
            f'</body></html>').encode())

    def log_message(self, *a):
        pass


class AppRedirectOtherPath(http.server.BaseHTTPRequestHandler):
    """VRAI — DÉCISION applicative : `/account` redirige vers `/login` SUR L'HÔTE INJECTÉ. Le chemin
    de destination DIFFÈRE de celui de la requête : l'application a choisi, en s'appuyant sur un
    en-tête contrôlé par le client."""

    def do_GET(self):
        host = _injected_host(self)
        return _send(self, 302, b"", [("Location", f"https://{host}/login?next=/account")])

    def log_message(self, *a):
        pass


class DirRedirectPlusResidual(http.server.BaseHTTPRequestHandler):
    """VRAI, CACHÉ DERRIÈRE UNE CANONICALISATION — même 301 de répertoire, PLUS un en-tête `Link`
    applicatif bâti depuis `Host`. Contre-épreuve de l'excès inverse : si la neutralisation de
    l'écho mangeait le résidu, il suffirait d'un 301 pour rendre l'oracle muet sur un vrai reflet."""

    def do_GET(self):
        host = _injected_host(self)
        if not self.path.endswith("/"):
            return _send(self, 301, b"", [("Location", f"http://{host}{self.path}/"),
                                          ("Link", f'<https://{host}/api/v2>; rel="preconnect"')])
        return _send(self, 200, b"ok")

    def log_message(self, *a):
        pass


class CrlfSplit(http.server.BaseHTTPRequestHandler):
    """VRAI — CRLF response-splitting (CWE-113) : le paramètre `next` est écrit SANS filtrage dans un
    en-tête de réponse. Voie indépendante du host poisoning : elle doit rester intacte."""

    def do_GET(self):
        raw = self.path.split("?", 1)[1] if "?" in self.path else ""
        import urllib.parse as up
        val = up.parse_qs(raw).get("next", [""])[0]
        extra = [("X-Next", val.split("\r")[0])]
        for line in val.replace("\r\n", "\n").split("\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip():
                    extra.append((k.strip(), v.strip()))       # l'en-tête injecté SE MATÉRIALISE
        return _send(self, 200, b"ok", extra)

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class _LoopbackCase(unittest.TestCase):
    """Base : monte un serveur loopback, tire l'oracle dessus, rend le finding."""

    def fire(self, handler, path, params=None):
        srv, port = _serve(handler)
        try:
            p = dict(params or {})
            p.update({"in_scope": ["127.0.0.1"], "allow_private": True})
            return HeaderInjectionProbe().fire(Action(
                "header_injection.probe", f"http://127.0.0.1:{port}{path}", params=p))[0]
        finally:
            srv.shutdown()
            srv.server_close()


# =================================================================================================
class TestSens1DefautServeurDevientMuet(_LoopbackCase):
    """SENS 1 — le comportement PAR DÉFAUT ne promeut plus. Les 5 HIGH du banc viennent d'ici."""

    def test_apache_redirection_repertoire_nest_pas_une_vuln(self):
        f = self.fire(ApacheDirRedirect, "/docs")
        self.assertEqual(f.status, "tested", "une redirection de répertoire n'est pas une vulnérabilité")
        self.assertEqual(f.severity, "INFO")
        self.assertNotIn("CONFIRMÉE", f.title)

    def test_werkzeug_redirection_repertoire_nest_pas_une_vuln(self):
        """Seconde stack — c'est la reproduction sur DEUX stacks qui établit « comportement par défaut »."""
        f = self.fire(WerkzeugDirRedirect, "/ui")
        self.assertEqual(f.status, "tested")
        self.assertEqual(f.severity, "INFO")

    def test_labstention_est_NOMMEE_dans_levidence(self):
        """Une abstention MUETTE serait le défaut symétrique : l'opérateur doit lire CE QUI a été
        observé et POURQUOI ça n'a pas promu."""
        f = self.fire(ApacheDirRedirect, "/docs")
        self.assertIn("canonicalisation d'URL ÉCARTÉE", f.evidence)
        self.assertIn("X-Forwarded-Host", f.evidence)

    def test_un_HIGH_par_repertoire_ne_se_produit_plus(self):
        """Le banc récoltait UN HIGH PAR RÉPERTOIRE découvert : sur DVWA, 4 répertoires = 4 HIGH."""
        for d in ("/docs", "/config", "/external", "/dvwa"):
            f = self.fire(ApacheDirRedirect, d)
            self.assertNotEqual(f.status, "vulnerable", d)


# =================================================================================================
class TestSens2VraiPositifConserve(_LoopbackCase):
    """SENS 2 — une VRAIE injection d'en-tête reste détectée. Ce sont les findings qui PAIENT."""

    def test_lien_de_reset_absolu_depuis_Host_reste_HIGH(self):
        f = self.fire(ResetLinkPoison, "/account/reset")
        self.assertEqual(f.status, "vulnerable")
        self.assertEqual(f.severity, "HIGH")
        self.assertIn("host header poisoning", f.title)
        self.assertIn("reflet=corps", f.evidence)

    def test_redirection_applicative_vers_autre_chemin_reste_HIGH(self):
        f = self.fire(AppRedirectOtherPath, "/account")
        self.assertEqual(f.status, "vulnerable")
        self.assertEqual(f.severity, "HIGH")
        self.assertIn("host header poisoning", f.title)

    def test_crlf_response_splitting_reste_HIGH(self):
        """Voie CWE-113, indépendante du host poisoning — la correction ne doit pas l'effleurer."""
        f = self.fire(CrlfSplit, "/redir", params={"param": "next"})
        self.assertEqual(f.status, "vulnerable")
        self.assertIn("CRLF response-splitting", f.title)


# =================================================================================================
class TestSens3BorneContreLexcesInverse(_LoopbackCase):
    """SENS 3 — la neutralisation retire l'ÉCHO, jamais la PREUVE."""

    def test_canonicalisation_avec_reflet_residuel_reste_HIGH(self):
        f = self.fire(DirRedirectPlusResidual, "/docs")
        self.assertEqual(f.status, "vulnerable",
                         "un 301 de répertoire ne doit pas servir de paravent à un vrai reflet")
        self.assertIn("Link", f.evidence)

    def test_hote_construit_et_non_recopie_reste_promu(self):
        """`http://<marker>.evil/…` n'est pas une RECOPIE du Host, c'est une CONSTRUCTION : le
        discriminant échoue au test d'hôte exact et l'oracle promeut (fail-open vers la DÉTECTION)."""
        mk = HeaderInjectionProbe._marker("https://x/y", "host", "hostinj") + ".forge-hh.test"
        where, canonical = HeaderInjectionProbe._host_reflection(
            301, "https://x/y", [("Location", f"http://{mk}.evil.example/y/")], "", mk)
        self.assertFalse(canonical)
        self.assertEqual(where, "Location")


# =================================================================================================
class TestDiscriminantUnitaire(unittest.TestCase):
    """Le discriminant lui-même — le CHEMIN de destination, parce que c'est lui qui sépare une
    normalisation d'une DÉCISION applicative."""

    MK = "forgeabc123def.forge-hh.test"

    def test_same_path_tolere_le_slash_final_et_la_racine(self):
        for a, b in (("/docs", "/docs/"), ("/docs/", "/docs"), ("", "/"), ("/", ""), ("/a/b", "/a/b/")):
            self.assertTrue(_same_path(a, b), (a, b))
        for a, b in (("/docs", "/other"), ("/a/b", "/a"), ("/login", "/")):
            self.assertFalse(_same_path(a, b), (a, b))

    def _canon(self, status, req, loc):
        return HeaderInjectionProbe._is_canonical_redirect(status, req, loc, self.MK)

    def test_canonicalisation_reconnue(self):
        self.assertTrue(self._canon(301, "http://h/docs", f"http://{self.MK}/docs/"))
        self.assertTrue(self._canon(308, "http://h/ui", f"http://{self.MK}/ui/"))
        self.assertTrue(self._canon(302, "http://h/p", f"https://{self.MK}/p"))   # http->https canonique

    def test_decision_applicative_NON_reconnue_comme_canonicalisation(self):
        self.assertFalse(self._canon(302, "http://h/account", f"https://{self.MK}/login"))
        self.assertFalse(self._canon(302, "http://h/a/b", f"https://{self.MK}/"))
        self.assertFalse(self._canon(200, "http://h/docs", f"http://{self.MK}/docs/"))  # pas une 3xx
        self.assertFalse(self._canon(301, "http://h/docs", "http://autre.example/docs/"))  # pas le marqueur
        self.assertFalse(self._canon(None, "http://h/docs", f"http://{self.MK}/docs/"))

    def test_echo_du_location_dans_le_corps_est_neutralise(self):
        """Le corps auto-généré d'une redirection recopie son propre `Location` : sans neutralisation,
        la MÊME redirection par défaut repasserait par la porte du CORPS (c'est ce que faisait Apache)."""
        loc = f"http://{self.MK}/docs/"
        body = f'<html><p>The document has moved <a href="{loc}">here</a>.</p></html>'
        where, canonical = HeaderInjectionProbe._host_reflection(
            301, "http://h/docs", [("Location", loc)], body, self.MK)
        self.assertTrue(canonical)
        self.assertEqual(where, "")

    def test_reflet_residuel_dans_le_corps_survit_a_la_neutralisation(self):
        loc = f"http://{self.MK}/docs/"
        body = (f'<html><p>moved <a href="{loc}">here</a>.</p>'
                f'<link rel="canonical" href="https://{self.MK}/autre-page"></html>')
        where, canonical = HeaderInjectionProbe._host_reflection(
            301, "http://h/docs", [("Location", loc)], body, self.MK)
        self.assertFalse(canonical)
        self.assertEqual(where, "corps")


# =================================================================================================
class TestPathDiscriminationNeCouvrePas(_LoopbackCase):
    """Le contrôle négatif GÉNÉRIQUE existant (`Oracle.path_discrimination`) couvre-t-il D4 ? NON —
    et c'est MESURÉ ici, pas supposé : il fallait établir qu'on n'ajoute pas un second mécanisme
    concurrent à un mécanisme qui aurait déjà couvert le cas (deux contrôles rivaux dériveraient).

    `path_discrimination` répond à « la cible sert-elle un 2xx sur n'importe quel chemin deviné ? ».
    Une cible qui fait des redirections de répertoire répond 404/3xx sur un chemin fabriqué : elle
    DISCRIMINE parfaitement. Question différente, famille différente. Ce qui EST réutilisé, c'est le
    VOCABULAIRE de la retenue — pas un second contrôle."""

    def test_path_discrimination_dit_que_la_cible_discrimine(self):
        srv, port = _serve(ApacheDirRedirect)
        try:
            a = Action("header_injection.probe", f"http://127.0.0.1:{port}/docs",
                       params={"in_scope": ["127.0.0.1"], "allow_private": True})
            d = HeaderInjectionProbe().path_discrimination(a, a.target)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIs(d.verdict, True, "la cible fautive DISCRIMINE : le contrôle générique la laisse passer")
        self.assertFalse(d.catchall)


# =================================================================================================
class TestLoopbackStrict(unittest.TestCase):
    """SÛRETÉ — ce fichier ne parle qu'à `127.0.0.1` : les serveurs sont liés au loopback."""

    def test_serveurs_lies_au_loopback_uniquement(self):
        srv, _port = _serve(ApacheDirRedirect)
        try:
            self.assertEqual(srv.server_address[0], "127.0.0.1")
            self.assertEqual(srv.socket.family, socket.AF_INET)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()

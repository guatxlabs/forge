# SPDX-License-Identifier: AGPL-3.0-or-later
"""D14 — la garde D4 n'avait fermé QU'UNE PORTE SUR DEUX : le `Location` était couvert, le CORPS
non. Prouvé DANS LES DEUX SENS (`docs/BENCH_DETECTION.md` §6, D14).

CE QU'A MESURÉ LE REJEU DU BANC
--------------------------------
**4 HIGH FAUX de plus sur DVWA**, sur les MÊMES répertoires qu'en D4, à un caractère près — la
variante à SLASH FINAL, où Apache ne redirige plus : il sert l'index, et son pied de page recopie le
`Host` reçu. Rejoué à la main contre le conteneur `vulnerables/web-dvwa` :

    curl -H 'Host: evil.forge-hh.test' http://127.0.0.1:8081/docs/   -> 200, AUCUN `Location`
      <address>Apache/2.4.25 (Debian) Server at evil.forge-hh.test Port 80</address>
      occurrences de l'hôte injecté dans le corps : 1        `href` PORTEUR : 0
    (identique sur /config/, /external/, /external/phpids/0.6/)

`ServerSignature On` est le défaut Debian : toute page auto-générée recopie l'en-tête `Host`. La
garde de D4 ne regardait que le `Location` ; dès que le marqueur était dans le CORPS, `_reflected_in`
rendait `"corps"` et la seule garde restante était `control_reflects_host` — celle que D4 avait
elle-même démontrée structurellement incapable (elle compare avec le VRAI `Host`, où le marqueur ne
peut par construction jamais apparaître).

LE DISCRIMINANT RETENU — CE QUE LE CORPS *FAIT* DU `Host`
----------------------------------------------------------
Le marqueur occupe-t-il l'AUTORITÉ d'une URI (RFC 3986 §3.2 : l'autorité SUIT « // » et PRÉCÈDE
« / ? # ») ? Si oui, une URL est CONSTRUITE depuis un en-tête contrôlé par le client — lien de
réinitialisation, `<base href>`, ressource chargée, entrée de cache : c'est le vecteur qui PAIE. Si
non, le `Host` n'est que du TEXTE : signature serveur, titre, message. Le banc avait déjà chiffré la
distinction sans la nommer — « href porteur : 0 ».

LES DEUX SENS, PARCE QU'UN SEUL SENS N'EST PAS UNE CORRECTION
--------------------------------------------------------------
  SENS 1 — l'écho DÉCORATIF devient muet : la forme Apache EXACTE du banc (index de répertoire ET
           page 404 portant `<address>… Server at <hôte injecté> Port 80</address>`) -> INFO
           `tested`, avec l'abstention NOMMÉE dans l'évidence.
  SENS 2 — l'empoisonnement RÉEL reste HIGH : lien de reset absolu, `<base href>`, `<script src>`,
           `<form action>`, meta-refresh, JSON `reset_url`, lien d'e-mail en texte nu — et les voies
           HORS corps (`Location` applicatif, `Link`, CRLF) que ce lot n'a pas touchées.
  SENS 3 — borne contre l'EXCÈS INVERSE : un vrai lien CACHÉ DERRIÈRE la signature Apache reste
           HIGH. Sinon il suffirait d'ajouter un pied de page pour rendre l'oracle muet.
  MUTATION — discriminant neutralisé -> les 4 HIGH faux REVIENNENT (la garde est porteuse).

Les cas loopback tirent de VRAIES requêtes HTTP vers `127.0.0.1` (port éphémère, aucun trafic
sortant) : le défaut vit dans l'interaction entre le statut, les en-têtes et le corps réels.
"""
import http.server
import sys
import threading
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.modules import httpflow as hf                              # noqa: E402
from forge.modules.httpflow import HeaderInjectionProbe, _host_echo_split   # noqa: E402
from forge.roe import Action                                          # noqa: E402


# =================================================================================================
#  Harnais loopback — chaque handler est UNE forme rencontrée par le banc (ou sa contre-épreuve).
# =================================================================================================
def _injected_host(h):
    """L'hôte injecté (X-Forwarded-Host prioritaire, sinon Host) — ce qu'Apache recopie dans sa
    signature de serveur, et ce qu'une application recopie dans une URL absolue."""
    return h.headers.get("X-Forwarded-Host") or h.headers.get("Host") or "localhost"


def _send(h, code, body=b"", extra=()):
    h.send_response(code)
    for k, v in extra:
        h.send_header(k, v)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    if body:
        h.wfile.write(body)


#: le pied de page EXACT servi par le conteneur DVWA du banc (`ServerSignature On`, défaut Debian).
_APACHE_SIGNATURE = '<address>Apache/2.4.25 (Debian) Server at {host} Port 80</address>'


class ApacheDirIndex(http.server.BaseHTTPRequestHandler):
    """DÉFAUT — DVWA/Apache 2.4 sur `/docs/` : 200, AUCUN `Location`, index de répertoire dont le
    SEUL porteur de l'hôte injecté est la signature serveur. Les 4 HIGH faux du rejeu viennent d'ici."""

    def do_GET(self):
        host = _injected_host(self)
        body = ('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n<html>\n <head>\n'
                '  <title>Index of /docs</title>\n </head>\n <body>\n<h1>Index of /docs</h1>\n'
                '  <table>\n<tr><td><a href="/">Parent Directory</a></td></tr>\n'
                '<tr><td><a href="DVWA_v1.3.pdf">DVWA_v1.3.pdf</a></td></tr>\n</table>\n'
                + _APACHE_SIGNATURE.format(host=host) + '\n</body></html>\n')
        return _send(self, 200, body.encode())

    def log_message(self, *a):
        pass


class Apache404(http.server.BaseHTTPRequestHandler):
    """DÉFAUT — la MÊME signature sur une page d'erreur : `ServerSignature On` la met partout."""

    def do_GET(self):
        host = _injected_host(self)
        body = ('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
                '<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n'
                f'<p>The requested URL {self.path} was not found on this server.</p>\n<hr>\n'
                + _APACHE_SIGNATURE.format(host=host) + '\n</body></html>\n')
        return _send(self, 404, body.encode())

    def log_message(self, *a):
        pass


class ResetLinkBehindSignature(http.server.BaseHTTPRequestHandler):
    """VRAI, CACHÉ DERRIÈRE L'ÉCHO — la MÊME signature Apache, PLUS un lien de réinitialisation
    absolu bâti depuis `Host`. Contre-épreuve de l'excès inverse : si un pied de page suffisait à
    taire l'oracle, il suffirait d'en ajouter un pour cacher le vecteur qui paie."""

    def do_GET(self):
        host = _injected_host(self)
        body = ('<html><body><p>Un e-mail a été envoyé. Lien : '
                f'<a href="https://{host}/account/reset/confirm?token=abc123">réinitialiser</a></p>\n'
                + _APACHE_SIGNATURE.format(host=host) + '</body></html>')
        return _send(self, 200, body.encode())

    def log_message(self, *a):
        pass


class BaseHrefPoison(http.server.BaseHTTPRequestHandler):
    """VRAI — `<base href>` protocole-relatif : TOUTE URL relative de la page part chez l'attaquant."""

    def do_GET(self):
        host = _injected_host(self)
        return _send(self, 200, f'<html><head><base href="//{host}/"></head><body>x</body></html>'.encode())

    def log_message(self, *a):
        pass


class MetaRefreshPoison(http.server.BaseHTTPRequestHandler):
    """VRAI — meta-refresh bâti depuis `Host` : le navigateur s'y rend sans clic."""

    def do_GET(self):
        host = _injected_host(self)
        return _send(self, 200, (f'<html><head><meta http-equiv="refresh" '
                                 f'content="0;url=https://{host}/next"></head></html>').encode())

    def log_message(self, *a):
        pass


class JsonResetUrl(http.server.BaseHTTPRequestHandler):
    """VRAI — API JSON qui rend l'URL de reset construite depuis `Host` (aucune balise HTML)."""

    def do_GET(self):
        host = _injected_host(self)
        body = f'{{"ok":true,"reset_url":"https://{host}/reset?token=abc123"}}'
        return _send(self, 200, body.encode(), [("Content-Type", "application/json")])

    def log_message(self, *a):
        pass


class BareTextEmailLink(http.server.BaseHTTPRequestHandler):
    """VRAI — le lien part en TEXTE NU (corps d'e-mail rendu en aperçu), sans scheme ni balise : le
    marqueur y PRÉCÈDE un chemin+query, donc il est bien l'autorité d'une URL."""

    def do_GET(self):
        host = _injected_host(self)
        return _send(self, 200, f'Rendez-vous sur {host}/reset?token=abc123 pour continuer.'.encode())

    def log_message(self, *a):
        pass


class InertTitleEcho(http.server.BaseHTTPRequestHandler):
    """DÉFAUT (seconde forme) — un `Host` recopié dans un TITRE / un message d'erreur applicatif.
    Aucune URL construite : rien à empoisonner. Prouve que le discriminant n'est pas « c'est du
    Apache » mais « rien n'est construit »."""

    def do_GET(self):
        host = _injected_host(self)
        return _send(self, 200, (f'<html><head><title>Bienvenue sur {host}</title></head>'
                                 f'<body><p>Hôte demandé : {host} (inconnu)</p></body></html>').encode())

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class _LoopbackCase(unittest.TestCase):
    """Base : monte un serveur loopback, tire l'oracle dessus, rend le finding."""

    def fire(self, handler, path="/", params=None):
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
class TestSens1LechoDecoratifDevientMuet(_LoopbackCase):
    """SENS 1 — la forme EXACTE des 4 HIGH faux du rejeu ne promeut plus."""

    def test_index_de_repertoire_apache_nest_pas_une_vuln(self):
        f = self.fire(ApacheDirIndex, "/docs/")
        self.assertEqual(f.status, "tested",
                         "une signature de serveur n'est pas un empoisonnement de Host")
        self.assertEqual(f.severity, "INFO")
        self.assertNotIn("CONFIRMÉE", f.title)

    def test_les_quatre_repertoires_du_banc_ne_promeuvent_plus(self):
        """Le rejeu récoltait UN HIGH PAR RÉPERTOIRE à slash final : /config/, /docs/, /external/,
        /external/phpids/0.6/. Les quatre, un par un."""
        for d in ("/config/", "/docs/", "/external/", "/external/phpids/0.6/"):
            f = self.fire(ApacheDirIndex, d)
            self.assertNotEqual(f.status, "vulnerable", d)
            self.assertEqual(f.severity, "INFO", d)

    def test_la_page_404_porte_la_meme_signature_et_ne_promeut_pas(self):
        f = self.fire(Apache404, "/nexistepas")
        self.assertNotEqual(f.status, "vulnerable")

    def test_un_echo_applicatif_inerte_ne_promeut_pas_non_plus(self):
        """Le discriminant n'est pas « c'est Apache » : c'est « rien n'est CONSTRUIT »."""
        f = self.fire(InertTitleEcho, "/")
        self.assertEqual(f.status, "tested")

    def test_labstention_est_NOMMEE_dans_levidence(self):
        """Une abstention MUETTE serait le défaut symétrique : l'opérateur doit lire CE QUI a été
        observé ET pourquoi ça n'a pas promu."""
        f = self.fire(ApacheDirIndex, "/docs/")
        self.assertIn("écho DÉCORATIF ÉCARTÉ", f.evidence)
        self.assertIn("TEXTE INERTE", f.evidence)
        self.assertIn("<address>", f.evidence)          # l'extrait de contexte RÉEL est rendu
        self.assertIn("Host", f.evidence)               # l'en-tête responsable est nommé


# =================================================================================================
class TestSens2LempoisonnementReelResteHIGH(_LoopbackCase):
    """SENS 2 — ce sont les findings qui PAIENT ; aucun ne doit s'éteindre."""

    def test_lien_de_reset_absolu_reste_HIGH(self):
        f = self.fire(ResetLinkBehindSignature, "/account/reset")
        self.assertEqual(f.status, "vulnerable")
        self.assertEqual(f.severity, "HIGH")
        self.assertIn("host header poisoning", f.title)
        self.assertIn("reflet=corps", f.evidence)

    def test_base_href_reste_HIGH(self):
        f = self.fire(BaseHrefPoison, "/")
        self.assertEqual(f.status, "vulnerable")
        self.assertEqual(f.severity, "HIGH")

    def test_meta_refresh_reste_HIGH(self):
        f = self.fire(MetaRefreshPoison, "/")
        self.assertEqual(f.status, "vulnerable")

    def test_json_reset_url_reste_HIGH(self):
        """Aucune balise HTML : le discriminant porte sur la SYNTAXE d'URI, pas sur le HTML."""
        f = self.fire(JsonResetUrl, "/api/forgot")
        self.assertEqual(f.status, "vulnerable")

    def test_lien_en_texte_nu_reste_HIGH(self):
        """Sans scheme : le marqueur PRÉCÈDE un chemin+query -> il est bien l'autorité d'une URL."""
        f = self.fire(BareTextEmailLink, "/preview")
        self.assertEqual(f.status, "vulnerable")


# =================================================================================================
class TestSens3BorneContreLexcesInverse(_LoopbackCase):
    """SENS 3 — l'écho ne doit jamais servir de PARAVENT à un vrai reflet."""

    def test_un_vrai_lien_cache_derriere_la_signature_reste_HIGH(self):
        f = self.fire(ResetLinkBehindSignature, "/account/reset")
        self.assertEqual(f.status, "vulnerable",
                         "un pied de page ne doit pas suffire à taire un lien de reset empoisonné")
        self.assertNotIn("écho DÉCORATIF ÉCARTÉ", f.evidence,
                         "rien n'a été écarté : le corps PORTE bel et bien une URL construite")


# =================================================================================================
class TestDiscriminantUnitaire(unittest.TestCase):
    """Le discriminant lui-même — l'AUTORITÉ d'une URI (RFC 3986 §3.2), pas la présence du texte."""

    MK = "forgeabc123def.forge-hh.test"

    def carrying(self, body):
        return _host_echo_split(body, self.MK)[0]

    def inert(self, body):
        return _host_echo_split(body, self.MK)[1]

    def test_absent_du_corps_ne_rend_rien(self):
        self.assertEqual(_host_echo_split("<html>rien</html>", self.MK), ("", ""))
        self.assertEqual(_host_echo_split(None, self.MK), ("", ""))
        self.assertEqual(_host_echo_split("x", ""), ("", ""))

    def test_positions_PORTEUSES(self):
        for body in (
            f'<a href="https://{self.MK}/reset?t=1">x</a>',        # lien absolu
            f'<base href="//{self.MK}/">',                          # protocole-relatif
            f'<script src="http://{self.MK}/a.js"></script>',       # ressource chargée
            f'<form action="https://{self.MK}/login">',             # soumission
            f'<meta content="0;url=https://{self.MK}/n">',          # meta-refresh
            f'{{"u":"https://user:pw@{self.MK}/x"}}',               # userinfo
            f'https://{self.MK}:8443/reset?token=z',                # port explicite
            f'Rendez-vous sur {self.MK}/reset?token=z',             # texte nu + chemin
            f'voir {self.MK}?token=z',                              # texte nu + query
        ):
            self.assertTrue(self.carrying(body), body)

    def test_positions_INERTES(self):
        for body in (
            f'<address>Apache/2.4.25 (Debian) Server at {self.MK} Port 80</address>',   # LE cas du banc
            f'<title>Bienvenue sur {self.MK}</title>',
            f'<p>Hôte demandé : {self.MK} (inconnu)</p>',
            f'<!-- vhost {self.MK} -->',
            f'{{"host":"{self.MK}"}}',                              # écho JSON sans URL
        ):
            self.assertFalse(self.carrying(body), body)
            self.assertTrue(self.inert(body), body)

    def test_une_seule_occurrence_porteuse_suffit(self):
        """FAIL-OPEN VERS LA DÉTECTION : dix échos inertes ne masquent pas un lien construit."""
        body = (f'<address>Server at {self.MK} Port 80</address>' * 10
                + f'<a href="https://{self.MK}/reset?t=1">x</a>')
        carrying, inert = _host_echo_split(body, self.MK)
        self.assertTrue(carrying)
        self.assertTrue(inert, "l'écho inerte reste OBSERVÉ (il est juste non décisif)")

    def test_le_double_slash_doit_etre_COLLE_a_lautorite(self):
        """`//` quelque part avant ne suffit pas : l'autorité SUIT immédiatement le `//`."""
        self.assertFalse(self.carrying(f'<a href="https://autre.example/x">y</a> chez {self.MK} !'))


# =================================================================================================
class TestMutationLeDiscriminantEstPorteur(_LoopbackCase):
    """MUTATION — discriminant neutralisé (retour au « le marqueur est dans le corps => reflet ») :
    les 4 HIGH faux du rejeu REVIENNENT. Sans cela, on ne saurait pas que c'est bien LUI qui les
    éteint, et le test du SENS 1 pourrait passer pour une raison sans rapport."""

    @staticmethod
    def _avant(body, marker):
        """Le comportement d'AVANT le correctif : toute occurrence compte comme un reflet."""
        return ((marker in (body or "")) and "echo", "")

    def test_neutraliser_le_discriminant_ramene_les_quatre_faux_HIGH(self):
        revenus = []
        with mock.patch.object(hf, "_host_echo_split", self._avant):
            for d in ("/config/", "/docs/", "/external/", "/external/phpids/0.6/"):
                f = self.fire(ApacheDirIndex, d)
                if f.status == "vulnerable" and f.severity == "HIGH":
                    revenus.append(d)
        self.assertEqual(len(revenus), 4,
                         "MUTATION INATTEIGNABLE : ce n'est pas le discriminant qui les écarte")

    def test_le_vrai_positif_ne_depend_PAS_de_la_mutation(self):
        """Contre-borne : le lien de reset était déjà HIGH avant ET après — le correctif ne l'a pas
        « gagné » par accident, il l'a CONSERVÉ."""
        with mock.patch.object(hf, "_host_echo_split", self._avant):
            avant = self.fire(ResetLinkBehindSignature, "/account/reset")
        apres = self.fire(ResetLinkBehindSignature, "/account/reset")
        self.assertEqual(avant.status, "vulnerable")
        self.assertEqual(apres.status, "vulnerable")


if __name__ == "__main__":
    unittest.main()

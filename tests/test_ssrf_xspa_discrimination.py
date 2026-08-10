# SPDX-License-Identifier: AGPL-3.0-or-later
"""D5 — `ssrf.xspa` déclarait JOIGNABLES des ports qui n'écoutent nulle part, prouvé DANS LES DEUX
SENS (`docs/BENCH_DETECTION.md` §6, D5).

CE QU'A MESURÉ LE BANC
----------------------
**3 MEDIUM `vulnerable` FAUX** sur VAmPI, déclarant joignables les 10 ports
`[22,80,443,3306,5432,6379,8080,8443,9200,27017]` — **9 sur 10 FERMÉS** (connexion TCP directe) — sur
un endpoint qui n'est pas SSRF-able du tout : corps **identique de 1 563 octets** pour
`__debugger__=…:1/` et `…:3306/`.

LA CAUSE EXACTE — VÉRIFIÉE, ET CE N'EST PAS LE TIMING
-----------------------------------------------------
Le rapport du banc attribue le différentiel à des écarts de timing de ~20 ms. C'est inexact : le
timing est mesuré et imprimé, mais n'entre dans AUCUN verdict — seul `sig != closed_sig` promeut.
Le vrai coupable est la NEUTRALISATION DU REFLET, appliquée ASYMÉTRIQUEMENT. La baseline « fermée »
était le port **1**, et le corps était scrubé du numéro de port de LA REQUÊTE COURANTE :

    re.sub(r"(?<!\\d)1(?!\\d)",    "<PORT>", body)   # baseline : mange TOUS les « 1 » isolés
    re.sub(r"(?<!\\d)3306(?!\\d)", "<PORT>", body)   # port     : no-op (3306 absent du corps)

Sur n'importe quel corps HTML (`HTTP/1.1`, `version 1.0.1`, `console-1`), le corps de la BASELINE est
mutilé et celui des ports ne l'est pas : deux corps OCTET POUR OCTET IDENTIQUES rendent deux
signatures DIFFÉRENTES. Le mécanisme censé SUPPRIMER le faux signal le FABRIQUAIT — inconditionnellement,
d'où « 10 ports sur 10 joignables ». `TestCauseRacineSignatureAsymetrique` fige exactement ça.

LES DEUX SENS, PARCE QU'UN SEUL SENS N'EST PAS UNE CORRECTION
-------------------------------------------------------------
  SENS 1 — un canal qui ne porte PAS d'information ne produit plus de verdict. Réponse invariante
           (le cas VAmPI) ou deux baselines FERMÉES discordantes -> `skipped` (« je n'ai pas pu
           vérifier »), jamais `tested` (« vérifié, rien trouvé ») ni `vulnerable`.
  SENS 2 — un VRAI XSPA reste MEDIUM `vulnerable`, et ne liste QUE le port réellement ouvert. La
           vérité terrain n'est pas déclarée par le test : c'est un VRAI socket en écoute sur
           `127.0.0.1`, et le serveur cible tente une VRAIE connexion TCP.
  SENS 3 — la borne contre l'excès inverse : un canal qui VARIE mais dont aucun port ne se distingue
           reste `tested`. L'abstention ne doit pas avaler le vrai négatif.

Loopback strict : ports éphémères sur `127.0.0.1`, aucun trafic sortant.
"""
import http.server
import re
import socket
import sys
import threading
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.modules.ssrf import SsrfXspa, _XSPA_CLOSED_PORTS           # noqa: E402
from forge.roe import Action                                          # noqa: E402

# Les 10 ports que le banc a déclarés joignables (9 fermés sur 10).
BENCH_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]

# Corps de 1 563 octets calqué sur la console Werkzeug mesurée sur VAmPI : il contient les « 1 »
# isolés (`HTTP/1.1`, `version 1.0.1`, `console-1`) qui déclenchaient le scrub asymétrique.
_HEAD = (b"<html><head><title>Werkzeug Debugger</title></head><body><h1>Console locked</h1>"
         b"<p>HTTP/1.1 200 OK</p><p>version 1.0.1</p><div id='console-1'>1 of 1</div>")
CONSOLE_BODY = _HEAD + b"<!-- " + b"x" * (1563 - len(_HEAD) - 9) + b" -->"
assert len(CONSOLE_BODY) == 1563


def _q(path, name):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(path).query).get(name, [""])[0]


def _send(h, code, body):
    h.send_response(code)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


# =================================================================================================
#  Harnais loopback
# =================================================================================================
class InertConsole(http.server.BaseHTTPRequestHandler):
    """LE CAS DU BANC — la console Werkzeug de VAmPI : corps CONSTANT de 1 563 octets, quelle que
    soit l'URL injectée. Le paramètre n'a aucun effet observable : rien à mesurer."""

    def do_GET(self):
        _send(self, 200, CONSOLE_BODY)

    def log_message(self, *a):
        pass


class RealSsrfFetcher(http.server.BaseHTTPRequestHandler):
    """VRAI SSRF — le serveur tente une VRAIE connexion TCP vers l'URL fournie et rend un corps qui
    DÉPEND du résultat. La vérité terrain vient du socket, pas d'une déclaration du test."""

    def do_GET(self):
        sp = urllib.parse.urlsplit(_q(self.path, "url"))
        s = socket.socket()
        s.settimeout(1.5)
        try:
            s.connect((sp.hostname or "127.0.0.1", sp.port or 80))
            body = b"<html>fetch reussi : le service interne a repondu (connexion etablie)</html>"
        except OSError:
            body = b"<html>fetch echoue : connexion refusee par le service interne</html>"
        finally:
            s.close()
        _send(self, 200, body)

    def log_message(self, *a):
        pass


class NoisyChannel(http.server.BaseHTTPRequestHandler):
    """CANAL INSTABLE — corps constant PLUS un nonce par requête (CSRF/horodatage/équilibrage). Sans
    contrôle négatif, chaque port « diffère » de la baseline et TOUS sont déclarés joignables."""
    n = 0

    def do_GET(self):
        NoisyChannel.n += 1
        _send(self, 200, CONSOLE_BODY + f"<meta name='csrf' content='nonce-{NoisyChannel.n:08d}'>".encode())

    def log_message(self, *a):
        pass


class PureEcho(http.server.BaseHTTPRequestHandler):
    """L'app RECOPIE l'URL injectée mais ne joint AUCUN port. Le canal VARIE (donc mesurable), mais
    la variation n'est QUE l'écho — après neutralisation, aucun port ne se distingue -> `tested`."""

    def do_GET(self):
        _send(self, 200, f"<html>vous avez demande {_q(self.path, 'url')}</html>".encode())

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class _LoopbackCase(unittest.TestCase):
    def fire(self, handler, ports, internal_host="127.0.0.1"):
        srv, port = _serve(handler)
        try:
            return SsrfXspa().fire(Action("ssrf.xspa", f"http://127.0.0.1:{port}/fetch", params={
                "param": "url", "in_scope": ["127.0.0.1"], "allow_private": True,
                "internal_host": internal_host, "ports": list(ports), "port_timeout": 3}))[0]
        finally:
            srv.shutdown()
            srv.server_close()


# =================================================================================================
class TestCauseRacineSignatureAsymetrique(unittest.TestCase):
    """LA CAUSE RACINE, figée au niveau unitaire : deux corps IDENTIQUES doivent rendre des
    signatures IDENTIQUES, quels que soient les ports. C'est l'invariant que l'ancienne
    normalisation violait — et le seul test qui aurait attrapé D5 sans monter un serveur."""

    HOST = "127.0.0.1"

    def _sig(self, port, body, all_ports):
        urls = [f"http://{self.HOST}:{p}/" for p in all_ports]
        return SsrfXspa._sig(200, body, urls, all_ports, self.HOST)

    def test_corps_identiques_rendent_signatures_identiques(self):
        """Le cas exact du banc : port 1 vs port 3306 sur un corps identique octet pour octet."""
        body = CONSOLE_BODY.decode()
        allp = [1, 3306]
        self.assertEqual(self._sig(1, body, allp), self._sig(3306, body, allp),
                         "un corps identique ne doit JAMAIS produire deux signatures différentes")

    def test_aucun_des_10_ports_du_banc_ne_differe_dune_baseline_a_1(self):
        body = CONSOLE_BODY.decode()
        allp = [1] + BENCH_PORTS
        base = self._sig(1, body, allp)
        for p in BENCH_PORTS:
            self.assertEqual(self._sig(p, body, allp), base, f"port {p} déclaré différent à tort")

    def test_un_vrai_differentiel_de_contenu_survit_a_la_neutralisation(self):
        """Contre-épreuve : la normalisation symétrique ne doit pas TOUT égaliser."""
        allp = [1, 6379]
        ferme = self._sig(1, "connection refused", allp)
        ouvert = self._sig(6379, "-NOAUTH Authentication required redis", allp)
        self.assertNotEqual(ferme, ouvert)

    def test_le_scrub_traite_les_ports_du_plus_long_au_plus_court(self):
        """`127.0.0.1:8080` ne doit pas devenir `<HP>80` parce que `:80` a été traité d'abord —
        l'ordre était indifférent tant qu'un SEUL port était scrubé ; il ne l'est plus."""
        allp = [80, 8080]
        a = self._sig(8080, "service sur 127.0.0.1:8080 ici", allp)
        b = self._sig(80, "service sur 127.0.0.1:8080 ici", allp)
        self.assertEqual(a, b)
        self.assertNotIn("80", str(a))

    def test_echo_de_lurl_injectee_toujours_neutralise(self):
        allp = [1, 3306]
        a = self._sig(1, f"you asked to fetch http://{self.HOST}:1/", allp)
        b = self._sig(3306, f"you asked to fetch http://{self.HOST}:3306/", allp)
        self.assertEqual(a, b, "un echo pur ne doit pas passer pour une joignabilité")


# =================================================================================================
class TestSens1AbstentionQuandRienAMesurer(_LoopbackCase):
    """SENS 1 — les 3 MEDIUM faux du banc viennent d'ici."""

    def test_reponse_invariante_rend_skipped(self):
        f = self.fire(InertConsole, [45001, 45002, 45003])
        self.assertEqual(f.status, "skipped", "un corps identique ne prouve rien : il faut s'abstenir")
        self.assertEqual(f.severity, "INFO")
        self.assertIn("ne VARIE PAS", f.title)

    def test_les_10_ports_du_banc_ne_sont_plus_declares_joignables(self):
        """Reproduction littérale de la revendication fautive, ports du banc compris."""
        f = self.fire(InertConsole, BENCH_PORTS)
        self.assertNotEqual(f.status, "vulnerable")
        for p in BENCH_PORTS:
            self.assertNotIn(f"ports JOIGNABLES (différentiel)=[{p}", f.evidence)

    def test_canal_instable_rend_skipped(self):
        """Deux ports tous deux FERMÉS doivent être indiscernables. Ils ne le sont pas -> abstention."""
        f = self.fire(NoisyChannel, [45001, 45002, 45003])
        self.assertEqual(f.status, "skipped")
        self.assertIn("canal instable", f.title)

    def test_labstention_est_NOMMEE_et_dit_skipped_pas_tested(self):
        f = self.fire(InertConsole, [45001, 45002])
        self.assertIn("INDISTINGUABLES", f.evidence)
        self.assertIn("skipped", f.evidence)
        self.assertNotEqual(f.status, "tested")


# =================================================================================================
class TestSens2VraiXspaConserve(_LoopbackCase):
    """SENS 2 — un VRAI XSPA reste détecté. Vérité terrain = un VRAI socket en écoute."""

    def setUp(self):
        self.lst = socket.socket()
        self.lst.bind(("127.0.0.1", 0))
        self.lst.listen(8)
        self.open_port = self.lst.getsockname()[1]
        self.addCleanup(self.lst.close)
        self.closed = [45001, 45002]

    def test_vrai_xspa_reste_vulnerable_medium(self):
        f = self.fire(RealSsrfFetcher, self.closed + [self.open_port])
        self.assertEqual(f.status, "vulnerable")
        self.assertEqual(f.severity, "MEDIUM")
        self.assertEqual(f.cwe, "CWE-918")
        self.assertIn("XSPA CONFIRMÉ", f.title)

    def test_seul_le_port_REELLEMENT_ouvert_est_liste(self):
        """Le cœur du défaut : le banc listait 10 ports dont 9 fermés. On exige l'exactitude."""
        f = self.fire(RealSsrfFetcher, self.closed + [self.open_port])
        self.assertIn(f"ports JOIGNABLES (différentiel)=[{self.open_port}]", f.evidence)
        for p in self.closed:
            self.assertIn(f"{p}:same", f.evidence, f"le port fermé {p} ne doit pas être 'diff'")

    def test_le_controle_negatif_est_rapporte_comme_PASSE(self):
        f = self.fire(RealSsrfFetcher, self.closed + [self.open_port])
        self.assertIn("contrôle négatif PASSÉ", f.evidence)


# =================================================================================================
class TestSens3BorneContreLexcesInverse(_LoopbackCase):
    """SENS 3 — l'abstention ne doit pas avaler le vrai négatif."""

    def test_canal_qui_varie_sans_port_distinct_reste_tested(self):
        f = self.fire(PureEcho, [45001, 45002, 45003])
        self.assertEqual(f.status, "tested", "canal informatif + aucun port distinct = vrai négatif")
        self.assertIn("non confirmé", f.title)


# =================================================================================================
class TestBaselinesFermees(unittest.TestCase):
    """Les baselines elles-mêmes : deux ports DISTINCTS et HAUTS."""

    def test_deux_baselines_distinctes(self):
        self.assertEqual(len(set(_XSPA_CLOSED_PORTS)), 2)

    def test_ports_hauts_pour_ne_pas_mutiler_les_corps(self):
        """Un port à 5 chiffres n'apparaît pas par hasard dans un corps ; « 1 » y est partout.

        HONNÊTETÉ SUR LA PORTÉE : ce choix n'est PAS ce qui éteint le faux positif — c'est la
        normalisation SYMÉTRIQUE qui le fait, et elle tient même avec une baseline à 1. Le port haut
        est une DÉFENSE EN PROFONDEUR : il empêche le scrub, désormais appliqué à TOUS les corps,
        d'aller mutiler un différentiel RÉEL au passage. On mesure ce mécanisme (combien d'octets le
        scrub détruit) plutôt que d'affirmer un effet qu'on n'a pas démontré."""
        body = CONSOLE_BODY.decode()
        for p in _XSPA_CLOSED_PORTS:
            self.assertGreaterEqual(p, 10000, p)
            self.assertNotIn(str(p), body)
        # mécanisme : une baseline à « 1 » ampute un corps ordinaire ; une baseline haute ne le touche pas.
        mutile = re.sub(r"(?<!\d)1(?!\d)", "<PORT>", body)
        intact = re.sub(r"(?<!\d)" + str(_XSPA_CLOSED_PORTS[0]) + r"(?!\d)", "<PORT>", body)
        self.assertNotEqual(mutile, body, "témoin : « 1 » est bien présent dans un corps ordinaire")
        self.assertEqual(intact, body, "une baseline HAUTE ne modifie aucun octet du corps")


# =================================================================================================
class TestLoopbackStrict(unittest.TestCase):
    """SÛRETÉ — ce fichier ne parle qu'à `127.0.0.1`."""

    def test_serveurs_lies_au_loopback_uniquement(self):
        srv, _p = _serve(InertConsole)
        try:
            self.assertEqual(srv.server_address[0], "127.0.0.1")
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()

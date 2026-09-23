"""Tests hermetiques de la synchronisation A DERNIER OCTET de `race.condition` — aucun reseau.

CE QUI EST EN JEU. `race.condition` synchronisait par threads : gigue de l'ordre de la
MILLISECONDE, quand une fenetre check-then-act moderne se compte en microsecondes. Un negatif
obtenu ainsi ne dit pas « pas de race », il dit « pas de race atteignable a la milliseconde ».
La difference n'est pas academique — c'est le faux negatif silencieux qui clot une classe que
personne ne rouvrira, et c'est le defaut mesure le 2026-09-09 (12 couples sur 13 clos sous les
cinq tentatives).

Les tests ci-dessous epinglent les deux moities de la correction : la MECANIQUE (la requete est
bien amputee de son dernier octet, puis completee) et le DIRE (le finding annonce la precision
employee, et refuse de presenter un negatif imprecis comme un verdict).
"""
from __future__ import annotations

import contextlib
import unittest

from forge.roe import Action
from forge.modules import race as mod
from forge.modules.race import RaceCondition

TGT = "https://app.test/redeem"
BASE = {"in_scope": ["app.test"], "success_marker": "OK", "limit": 1, "burst": 3}


@contextlib.contextmanager
def _seams(**remplacants):
    """Restauration DEPUIS `__dict__` — forme imposee par `test_seam_restoration.py` : lire
    `cls.attr` rend la fonction, pas le descripteur, et la reposer en ferait une methode
    d'instance (tous les arguments du seam decales)."""
    sauve = {n: (n in RaceCondition.__dict__, RaceCondition.__dict__.get(n)) for n in remplacants}
    for nom, fn in remplacants.items():
        setattr(RaceCondition, nom, staticmethod(fn))
    try:
        yield
    finally:
        for nom, (avait, orig) in sauve.items():
            if avait and orig is not None:
                setattr(RaceCondition, nom, orig)
            else:
                try:
                    delattr(RaceCondition, nom)
                except AttributeError:
                    pass


class TestSerialisation(unittest.TestCase):

    def test_requete_brute_bien_formee(self):
        raw = RaceCondition._raw_request(TGT, "POST", "a=1", {"X-T": "v"})
        self.assertTrue(raw.startswith(b"POST /redeem HTTP/1.1\r\n"))
        self.assertIn(b"Host: app.test\r\n", raw)
        self.assertIn(b"Connection: close\r\n", raw)
        self.assertIn(b"Content-Length: 3\r\n", raw)
        self.assertTrue(raw.endswith(b"a=1"))

    def test_en_tetes_de_transport_non_dupliques(self):
        # Host/Connection/Content-Length sont poses par le serialiseur : les laisser passer depuis
        # `headers` produirait des en-tetes en double, que certains serveurs rejettent.
        raw = RaceCondition._raw_request(TGT, "POST", "a=1",
                                         {"Host": "x", "Connection": "keep-alive",
                                          "Content-Length": "999"})
        self.assertEqual(raw.count(b"Host:"), 1)
        self.assertEqual(raw.count(b"Connection:"), 1)
        self.assertEqual(raw.count(b"Content-Length:"), 1)
        self.assertNotIn(b"999", raw)

    def test_query_preservee(self):
        raw = RaceCondition._raw_request("https://app.test/r?c=1", "GET", None, {})
        self.assertTrue(raw.startswith(b"GET /r?c=1 HTTP/1.1\r\n"))

    def test_parse_response(self):
        self.assertEqual(RaceCondition._parse_response(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\ncorps"),
                         (200, "corps"))
        self.assertEqual(RaceCondition._parse_response(b""), (None, ""))
        self.assertEqual(RaceCondition._parse_response(b"nawak"), (None, ""))

    def test_schema_non_http_refuse(self):
        # Renvoie [] -> l'appelant replie sur threads. Aucun socket ouvert.
        self.assertEqual(RaceCondition()._burst_last_byte("ftp://app.test/x", "GET", None, {}, 2, 1),
                         [])


class TestAiguillage(unittest.TestCase):

    def _fire(self, params, last_byte=None, fetch=None):
        seams = {}
        if last_byte is not None:
            seams["_burst_last_byte"] = last_byte
        if fetch is not None:
            seams["_fetch"] = fetch
        with _seams(**seams):
            p = dict(BASE)
            p.update(params)
            return RaceCondition().fire(Action("race.condition", TGT, params=p))

    def test_defaut_reste_threads(self):
        """Non-regression stricte : sans `sync`, le seam `_fetch` est le chemin employe."""
        appels = []

        def fetch(url, **kw):
            appels.append(url)
            return (200, "NON")
        out = self._fire({}, last_byte=lambda *a, **k: [(200, "OK")] * 5, fetch=fetch)
        self.assertTrue(appels, "le mode par defaut doit passer par `_fetch`")
        self.assertEqual(out[0].status, "tested")

    def test_last_byte_employe_quand_demande(self):
        appels = []

        def fetch(url, **kw):
            appels.append(url)
            return (200, "NON")
        out = self._fire({"sync": "last_byte"},
                         last_byte=lambda *a, **k: [(200, "OK")] * 3, fetch=fetch)
        self.assertEqual(appels, [], "`last_byte` abouti -> aucun repli sur `_fetch`")
        self.assertEqual(out[0].status, "vulnerable")
        self.assertIn("DERNIER OCTET", out[0].evidence)

    def test_repli_sur_threads_si_transport_echoue(self):
        appels = []

        def fetch(url, **kw):
            appels.append(url)
            return (200, "NON")
        out = self._fire({"sync": "last_byte"}, last_byte=lambda *a, **k: [], fetch=fetch)
        self.assertTrue(appels, "transport bas niveau KO -> repli sur `_fetch`")
        self.assertIn("repli", out[0].evidence.lower())


class TestDireLaPrecision(unittest.TestCase):
    """Le coeur du chantier : un negatif imprecis ne doit pas se presenter comme un verdict."""

    def _fire(self, params, fetch):
        with _seams(_fetch=fetch):
            p = dict(BASE)
            p.update(params)
            return RaceCondition().fire(Action("race.condition", TGT, params=p))

    def test_negatif_en_threads_avertit_qu_il_ne_clot_pas_la_classe(self):
        out = self._fire({}, lambda url, **kw: (200, "NON"))
        self.assertEqual(out[0].status, "tested")
        self.assertIn("NE CLÔT PAS LA CLASSE", out[0].evidence)
        self.assertIn("last_byte", out[0].evidence)

    def test_positif_en_threads_n_avertit_pas(self):
        # Une preuve reste une preuve : la mise en garde ne porte que sur les NEGATIFS, sans quoi
        # elle deviendrait du bruit qu'on cesse de lire.
        out = self._fire({"limit": 0}, lambda url, **kw: (200, "OK"))
        self.assertEqual(out[0].status, "vulnerable")
        self.assertNotIn("NE CLÔT PAS LA CLASSE", out[0].evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)

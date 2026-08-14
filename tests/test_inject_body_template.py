# SPDX-License-Identifier: AGPL-3.0-or-later
"""Injecter dans un ARGUMENT GRAPHQL — la forme que `inject_request` ne savait pas écrire.

MESURÉ, deux campagnes de banc : **DVGA rend 0 sur 6 classes opposables**, et la cause n'est ni le
jugement ni la découverte. Les six vivent derrière UN SEUL `POST /graphql`, et le point d'injection
est un argument DANS la chaîne `query` — `pastes(filter:"…")`, `systemDiagnostics(cmd:…)`,
`uploadPaste(filename:"…")`. La forme historique ne sait produire qu'une query-string ou un corps
`x-www-form-urlencoded` : elle ne peut PAS écrire cet endroit-là. Les cinq oracles d'injection
étaient donc structurellement aveugles à GraphQL sans qu'aucun d'eux soit en défaut.

`body_template` + `PAYLOAD_SLOT` décrivent cette forme. Un seul changement de plomberie, et les
oracles qui passent déjà par `inject_request` deviennent capables de viser un argument GraphQL.

LE PIÈGE, ET LA RAISON D'ÊTRE DE LA MOITIÉ DE CE FICHIER — la charge atterrit dans DEUX contextes
imbriqués : une chaîne **GraphQL**, elle-même dans une chaîne **JSON**. N'échapper que pour JSON rend
un corps JSON parfaitement valide dont le GraphQL est CASSÉ dès que la charge contient un guillemet.
Le serveur répond « syntax error » et l'oracle lit ce refus comme « pas vulnérable ». Or un guillemet
est exactement ce que contient une charge SQLi : le faux négatif viserait en priorité la classe
qu'on cherche.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.modules.oracle import Oracle                                        # noqa: E402

SLOT = Oracle.PAYLOAD_SLOT
GQL = json.dumps({"query": '{pastes(filter:"%s"){id}}' % SLOT})
TARGET = "http://app.test/graphql"

#: charges qui cassent naïvement l'un ou l'autre contexte
PAYLOADS = ["1' OR '1'='1", 'a"b', "x\\y", "l1\nl2", '"; system("id"); "', "; id", "../../etc/passwd"]


def _graphql_string_balanced(query):
    """La chaîne GraphQL est-elle bien fermée ? On compte les guillemets NON échappés."""
    return re.sub(r"\\.", "", query).count('"') % 2 == 0


class BothNestedContextsAreEscaped(unittest.TestCase):

    def test_le_corps_reste_un_JSON_valide(self):
        for p in PAYLOADS:
            with self.subTest(payload=p):
                _u, data = Oracle.inject_request(TARGET, "filter", p, method="POST", body_template=GQL)
                json.loads(data)                     # lève si invalide -> le test échoue

    def test_la_chaine_GRAPHQL_reste_bien_fermee(self):
        """LA COUCHE QU'ON OUBLIE. Un corps JSON valide ne garantit pas un GraphQL valide."""
        for p in PAYLOADS:
            with self.subTest(payload=p):
                _u, data = Oracle.inject_request(TARGET, "filter", p, method="POST", body_template=GQL)
                q = json.loads(data)["query"]
                self.assertTrue(_graphql_string_balanced(q),
                                f"chaîne GraphQL cassée par la charge {p!r} : {q}")

    def test_la_charge_ARRIVE_bien_a_destination(self):
        """Échapper ne doit pas dénaturer : la charge doit rester reconnaissable côté serveur."""
        _u, data = Oracle.inject_request(TARGET, "filter", "1' OR '1'='1", method="POST",
                                         body_template=GQL)
        self.assertIn("1' OR '1'='1", json.loads(data)["query"])

    def test_un_gabarit_NON_JSON_est_rendu_tel_quel(self):
        """XML, form-data, texte : on ne prétend pas savoir échapper ce qu'on ne sait pas lire."""
        tmpl = f"<x>{SLOT}</x>"
        _u, data = Oracle.inject_request(TARGET, "p", 'a"b', method="POST", body_template=tmpl)
        self.assertEqual(data, '<x>a"b</x>')

    def test_un_creneau_HORS_chaine_graphql_n_est_echappe_QUE_pour_JSON(self):
        """Un argument numérique/enum n'est PAS dans une chaîne GraphQL : y appliquer la couche
        interne serait une faute — les `\\"` produits n'y seraient pas des échappements mais des
        antislashs littéraux, et la requête deviendrait illisible.

        LA CHARGE EST CHOISIE POUR RENDRE LA FAUTE VISIBLE : elle contient un guillemet. Une charge
        sans caractère spécial (`1 OR 1=1`) laisserait la couche GraphQL sans effet observable, et
        ce test ne verrait rien — mutation restée verte, constat sur le test et non sur le code."""
        tmpl = json.dumps({"query": "{paste(id:%s){content}}" % SLOT})
        _u, data = Oracle.inject_request(TARGET, "id", '1 OR "x"="x"', method="POST",
                                         body_template=tmpl)
        self.assertEqual(json.loads(data)["query"], '{paste(id:1 OR "x"="x"){content}}',
                         "la couche GraphQL a été appliquée hors d'une chaîne GraphQL")


class TheHistoricalFormIsUntouched(unittest.TestCase):
    """Sans gabarit — c'est-à-dire pour TOUS les appels d'aujourd'hui — rien ne bouge."""

    def test_GET_inchange(self):
        self.assertEqual(Oracle.inject_request("http://t/a?id=1&Submit=Submit", "id", "1'"),
                         ("http://t/a?id=1%27&Submit=Submit", None))

    def test_POST_urlencode_inchange(self):
        self.assertEqual(Oracle.inject_request("http://t/a?id=1", "id", "1'", method="POST"),
                         ("http://t/a?id=1", "id=1%27"))

    def test_un_gabarit_SANS_creneau_est_ignore(self):
        """Pas de marqueur = pas de point d'injection : on ne devine pas où l'opérateur voulait viser."""
        self.assertEqual(
            Oracle.inject_request("http://t/a", "id", "x", method="POST",
                                  body_template='{"query":"{a}"}'),
            ("http://t/a", "id=x"))

    def test_l_URL_n_est_PAS_reecrite_avec_un_gabarit(self):
        """Le routage de la cible reste le sien : un gabarit décrit un CORPS, pas une URL."""
        url, _d = Oracle.inject_request(TARGET, "filter", "x", method="POST", body_template=GQL)
        self.assertEqual(url, TARGET)


class ItNeverRaises(unittest.TestCase):

    def test_charges_et_gabarits_hostiles(self):
        for tmpl in (GQL, f"<x>{SLOT}</x>", SLOT, "{", None, ""):
            for p in ("", "\x00", "é" * 100, 42):
                with self.subTest(template=str(tmpl)[:20], payload=str(p)[:10]):
                    Oracle.inject_request(TARGET, "p", p, method="POST", body_template=tmpl)


if __name__ == "__main__":
    unittest.main()

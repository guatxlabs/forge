# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deux comptes voyant la même collection VIDE : preuve d'IDOR, ou artefact ? (D22)

TROUVÉ EN REJOUANT LE BANC À LA MAIN. Le finding `juiceshop/B access_control.idor @
/api/BasketItems` est un VRAI positif — vérifié : tout compte authentifié reçoit 8 items répartis
sur 5 `BasketId` d'AUTRES comptes, anonyme -> 401. Mais sa PREUVE était plus faible que ce qu'elle
affirmait.

`_same_object` concluait « B lit l'objet de A » sur : statuts accordés + même content-type + même
hash de corps normalisé. Son unique garde de trivialité :

    na = _normalize_body(ba)
    if not na:            # pas de contenu à comparer -> pas de preuve
        return False

Il refusait un corps **VIDE**. Il ne refusait PAS un corps **TRIVIAL**. `{"status":"success",
"data":[]}` n'est pas vide : deux comptes qui voient chacun leur PROPRE collection vide produisent
deux corps identiques, et l'oracle rendait « IDOR CONFIRMÉ ». Même famille que tout le reste de
cette série : **le garde existait et gardait à côté.**

Défaut LATENT : il n'a jamais tiré faux sur le banc. Il est fermé AVANT de se déclencher sur une
cible réelle — c'est précisément ce que la vérification manuelle sert à trouver.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.modules.access_control import IdorDifferential, _carries_payload   # noqa: E402

JSON = "application/json"


def _same(a_body, b_body, ct=JSON, sa=200, sb=200):
    return IdorDifferential._same_object((sa, a_body, ct), (sb, b_body, ct))


class AnEmptyCollectionProvesNothing(unittest.TestCase):

    def test_deux_collections_vides_identiques_ne_prouvent_rien(self):
        """LE DÉFAUT. Chaque compte voit SON panier, vide. Rien n'a été lu de personne."""
        vide = '{"status":"success","data":[]}'
        self.assertFalse(_same(vide, vide), "collection vide partagée prise pour une lecture cross-compte")

    def test_toutes_les_enveloppes_usuelles(self):
        for key in ("data", "items", "results", "records", "rows", "content", "list", "entries"):
            with self.subTest(enveloppe=key):
                self.assertFalse(_same('{"%s":[]}' % key, '{"%s":[]}' % key))

    def test_le_document_vide_lui_meme(self):
        for corps in ("[]", "{}", '{"data":{}}', "   ", ""):
            with self.subTest(corps=corps):
                self.assertFalse(_same(corps, corps))


class ARealSharedObjectStillCounts(unittest.TestCase):
    """L'EXCÈS INVERSE — fermer ce mécanisme ne doit RIEN retirer aux vraies lectures."""

    def test_le_vrai_positif_du_banc_survit(self):
        """Le corps EXACT de `/api/BasketItems` (Juice Shop) : 8 items, 5 BasketId d'autres comptes."""
        corps = ('{"status":"success","data":['
                 '{"ProductId":1,"BasketId":1,"id":1,"quantity":2},'
                 '{"ProductId":2,"BasketId":1,"id":2,"quantity":3},'
                 '{"ProductId":3,"BasketId":2,"id":3,"quantity":1},'
                 '{"ProductId":4,"BasketId":3,"id":4,"quantity":2},'
                 '{"ProductId":5,"BasketId":4,"id":5,"quantity":1},'
                 '{"ProductId":6,"BasketId":5,"id":6,"quantity":1}]}')
        self.assertTrue(_same(corps, corps), "le vrai positif mesuré du banc a été perdu")

    def test_un_objet_unique_peuple(self):
        corps = '{"id":42,"owner":"victim","secret":"MARQUEUR"}'
        self.assertTrue(_same(corps, corps))

    def test_un_corps_non_JSON_reste_une_preuve(self):
        """On ne prétend pas lire ce qu'on ne sait pas parser : du HTML non vide compte."""
        self.assertTrue(_same("<html><body>dossier de la victime</body></html>",
                              "<html><body>dossier de la victime</body></html>",
                              ct="text/html"))

    def test_un_scalaire_JSON_compte(self):
        for corps in ('"secret-de-la-victime"', "42", "true"):
            with self.subTest(corps=corps):
                self.assertTrue(_same(corps, corps))

    def test_une_enveloppe_PEUPLEE_compte(self):
        self.assertTrue(_same('{"status":"success","data":[{"id":1}]}',
                              '{"status":"success","data":[{"id":1}]}'))


class TheOtherGuardsAreUntouched(unittest.TestCase):

    def test_des_corps_differents_ne_sont_pas_le_meme_objet(self):
        self.assertFalse(_same('{"data":[{"id":1}]}', '{"data":[{"id":2}]}'))

    def test_un_refus_n_est_pas_une_lecture(self):
        corps = '{"data":[{"id":1}]}'
        self.assertFalse(_same(corps, corps, sb=403))

    def test_des_types_divergents_ne_sont_pas_le_meme_objet(self):
        self.assertFalse(IdorDifferential._same_object((200, '{"data":[{"id":1}]}', JSON),
                                                       (200, '{"data":[{"id":1}]}', "text/html")))


class ThePredicateIsHonestAboutItsLimit(unittest.TestCase):
    """`_carries_payload` répond « y a-t-il un CONTENU », jamais « à QUI appartient-il »."""

    def test_il_ne_juge_pas_l_appartenance(self):
        # Une vue GLOBALE légitime, peuplée, reste « porteuse » : ce prédicat ne tranche pas cela,
        # et la docstring le dit. Seuls une discrimination tierce ou un marqueur d'opérateur le font.
        self.assertTrue(_carries_payload('{"data":[{"catalogue":"public"}]}'))

    def test_pur_et_ne_leve_jamais(self):
        for corps in (None, "", "{", "[[[", b"", 42):
            with self.subTest(corps=corps):
                try:
                    _carries_payload(corps if isinstance(corps, (str, type(None))) else str(corps))
                except Exception as e:                       # noqa: BLE001
                    self.fail(f"a levé sur {corps!r} : {e!r}")


if __name__ == "__main__":
    unittest.main()

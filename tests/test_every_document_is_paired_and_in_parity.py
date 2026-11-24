# SPDX-License-Identifier: AGPL-3.0-or-later
"""La garde des deux langues, jouée par la suite : ses témoins, puis l'arbre réel.

`scripts/check_every_document_is_paired_and_in_parity.py` est câblée en CI et dans le `Makefile`
(`make check-document-languages`). La jouer aussi ici fait rougir `make test` sur un poste, avant
la CI, dès qu'un document change dans une seule langue ou qu'un document neuf arrive sans sa paire.

Les témoins (`valider_instrument`) jouent la décision sur de petits dépôts fabriqués : une garde
dont l'instrument ne voit plus un écart rendrait un vert sans valeur. L'arbre réel est ensuite
jugé avec l'ensemble nommé des documents en une seule langue et le plancher de paires.
"""
from __future__ import annotations

import pathlib
import sys
import unittest

RACINE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "scripts"))

import check_every_document_is_paired_and_in_parity as garde  # noqa: E402
import parite_des_langues as pdl  # noqa: E402


class EveryDocumentIsPairedAndInParity(unittest.TestCase):

    def test_les_temoins_de_l_instrument_rendent_leur_code(self):
        self.assertEqual(garde.valider_instrument(), [])

    def test_l_arbre_reel_est_sans_ecart(self):
        code, lignes = garde.juger(str(RACINE), pdl.UNE_SEULE_LANGUE, garde.MIN_PAIRES)
        self.assertEqual(code, 0, "\n".join(lignes))

    def test_les_documents_en_une_seule_langue_sont_les_releves_dates_du_banc(self):
        for chemin, raison in pdl.UNE_SEULE_LANGUE.items():
            with self.subTest(document=chemin):
                self.assertTrue(chemin.startswith("bench/detection/RESULTS_"), chemin)
                self.assertIn("bench.detection.report", raison)
                self.assertTrue((RACINE / chemin).is_file(), f"{chemin} : entrée sans document")


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""Les deux règles publiques sont-elles INFRANCHISSABLES, ou seulement écrites ?

Une recréation de dépôt nettoie le passé ; elle ne garantit rien sur l'avenir. Sans vérification
machine, la dérive recommence au premier commit — et ce dépôt a deux démonstrations de ce que
devient une règle non gardée : `_RATE_FLAG_KINDS` et `_SQL_ERROR_SIGNS`, justes le jour de leur
écriture et fausses quelques mois plus tard.

DEUX BARRIÈRES, UNE SEULE IMPLÉMENTATION (`scripts/check_commit_register.py`) :
  · le hook `commit-msg` — poste local, avant que le commit existe ;
  · le job CI sur la plage poussée — dépôt publié.
Le hook ne ferme pas : il n'est pas transporté par `git clone` et n'est jamais exécuté par l'édition
via l'interface web de GitHub, la voie même par laquelle des commits à compte personnel sont entrés.

Ce fichier vérifie les deux sens : ce qui doit être REFUSÉ l'est, et ce qui doit RESTER passe.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import unittest

RACINE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "scripts"))

from check_commit_register import (  # noqa: E402
    BANNIES, faute_d_identite, fautes_de_message)


class WhatMustBeRefused(unittest.TestCase):

    def test_le_recit_d_enquete_a_la_premiere_personne(self):
        for phrase in ("j'avais écarté ce champ deux jours plus tôt",
                       "ma contre-vérification a montré l'inverse",
                       "j'ai mesuré 27 cibles atteintes",
                       "je consigne le résultat ici"):
            with self.subTest(phrase=phrase[:36]):
                self.assertTrue(fautes_de_message(phrase), f"non détecté : {phrase}")

    def test_l_adresse_directe_a_un_interlocuteur(self):
        for phrase in ("comme vous l'avez demandé, le champ est corrigé",
                       "comme demandé, le débit est borné",
                       "vous trouverez le détail dans la roadmap",
                       "merci de vérifier le résultat"):
            with self.subTest(phrase=phrase[:36]):
                self.assertTrue(fautes_de_message(phrase), f"non détecté : {phrase}")

    def test_la_chronologie_de_session_comme_fil_narratif(self):
        for phrase in ("cette session a produit trois correctifs",
                       "dans ma dernière réponse, le chiffre était faux"):
            with self.subTest(phrase=phrase[:36]):
                self.assertTrue(fautes_de_message(phrase), f"non détecté : {phrase}")

    def test_une_identite_personnelle_ou_nominative(self):
        for nom, email in (("pseudo-perso", "1234567+pseudo-perso@users.noreply.github.com"),
                           ("Prénom Nom", "prenom.nom@example.com"),
                           ("GuatX", "noreply@guatx.com"),
                           ("guatxlabs", "moi@gmail.com")):
            with self.subTest(identite=f"{nom} <{email}>"):
                self.assertIsNotNone(faute_d_identite(nom, email), f"accepté à tort : {nom}")

    def test_l_identite_publique_unique_PASSE(self):
        self.assertIsNone(faute_d_identite("guatxlabs", "noreply@guatx.com"))


class WhatMustKeepPassing(unittest.TestCase):
    """L'EXCÈS INVERSE — un garde trop zélé appauvrirait la documentation qu'il prétend protéger."""

    def test_la_voix_de_l_outil(self):
        for phrase in ("un `skipped` dit « je n'ai PAS pu vérifier »",
                       "le statut énonce : je n'ai pas vu l'application"):
            with self.subTest(phrase=phrase[:36]):
                self.assertEqual(fautes_de_message(phrase), [], f"banni à tort : {phrase}")

    def test_une_date_de_mesure_reste_de_la_TRACABILITE(self):
        phrase = "MESURÉ le 2026-08-16 sur l'application vivante : 27 cibles, 0 page vulnérable."
        self.assertEqual(fautes_de_message(phrase), [])

    def test_un_POURQUOI_long_reste_admis(self):
        """La longueur n'a jamais été le défaut ; l'adressage l'était."""
        phrase = ("La forme urlencodée était un angle mort pour toute API JSON : le corps partait "
                  "sous un `Content-Type: application/json` sans en avoir la structure, et le "
                  "serveur répondait 500, ce que l'oracle lisait comme « pas vulnérable ». " * 3)
        self.assertEqual(fautes_de_message(phrase), [])

    def test_les_trailers_d_attribution_sont_ignores(self):
        msg = ("fix: un correctif\n\nUn corps normal.\n\n"
               "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>\n"
               "Signed-off-by: guatxlabs <noreply@guatx.com>\n")
        self.assertEqual(fautes_de_message(msg), [])

    def test_une_CITATION_de_la_mauvaise_forme_est_ignoree(self):
        """Une règle doit pouvoir citer ce qu'elle interdit sans se refuser elle-même."""
        msg = "docs: poser la règle\n\n> « j'avais écarté ce champ » -> adressé à une conversation\n"
        self.assertEqual(fautes_de_message(msg), [])


class TheTwoBarriersExist(unittest.TestCase):

    def test_le_hook_est_VERSIONNE_et_executable(self):
        hook = RACINE / ".githooks" / "commit-msg"
        self.assertTrue(hook.exists(), "hook absent — rien n'arrête la faute avant le commit")
        self.assertTrue(hook.stat().st_mode & 0o111, "hook non exécutable")

    def test_la_CI_verifie_la_PLAGE_poussee(self):
        ci = (RACINE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("check_commit_register.py", ci,
                      "aucune barrière CI — le hook seul ne couvre ni un autre poste ni "
                      "l'édition via l'interface web de GitHub")
        self.assertIn("fetch-depth: 0", ci, "sans historique complet, la plage est illisible")

    def test_le_verificateur_s_execute_vraiment(self):
        r = subprocess.run([sys.executable, str(RACINE / "scripts" / "check_commit_register.py"),
                            "--rev", "HEAD"], capture_output=True, text=True, cwd=RACINE)
        self.assertIn(r.returncode, (0, 1), f"le vérificateur a planté : {r.stderr[:200]}")

    def test_le_motif_de_chaque_regle_porte_sa_RAISON(self):
        for motif, raison in BANNIES.items():
            with self.subTest(motif=motif[:30]):
                self.assertTrue(raison.strip(), f"{motif} refusé sans justification écrite")


if __name__ == "__main__":
    unittest.main()

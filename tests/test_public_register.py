# SPDX-License-Identifier: AGPL-3.0-or-later
"""Le dépôt s'adresse-t-il à un LECTEUR PUBLIC, ou à un interlocuteur ?

Tout ce que ce dépôt publie — commentaires de code, documentation, roadmap — s'adresse à quelqu'un
qui n'était pas dans la pièce, qui ne connaît ni la session ni son auteur, et qui doit pouvoir agir
sur ce qu'il lit. La règle est écrite dans `ROADMAP.md` (gouvernance) et dans `CONTRIBUTING.md`.

CE FICHIER EXISTE PARCE QU'UNE RÈGLE DE STYLE SANS GARDE DÉRIVE. Ce dépôt en a la démonstration :
`_RATE_FLAG_KINDS` et `_SQL_ERROR_SIGNS` étaient deux listes tenues à la main, correctes le jour de
leur écriture, fausses quelques mois plus tard — et personne ne s'en apercevait, parce que rien ne
les vérifiait. Une convention de rédaction subit le même sort.

CE QUI EST BANNI : le récit d'enquête à la première personne, l'adresse directe à un interlocuteur,
la chronologie de session comme fil narratif.

CE QUI RESTE LÉGITIME, et qui n'est pas la même chose :
  · la VOIX DE L'OUTIL — « un `skipped` dit *je n'ai PAS pu vérifier* » énonce le sens d'un statut ;
  · l'adresse au LECTEUR d'une documentation — « votre SOC », « sur votre machine » ;
  · une DATE qui rend une mesure traçable — « MESURÉ le 2026-08-16 » n'est pas un journal intime ;
  · les chaînes de PROMPT destinées à un modèle (`forge/llm.py`), qui tutoient par construction.
"""
from __future__ import annotations

import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

RACINE = pathlib.Path(__file__).resolve().parents[1]

#: Tournures qui trahissent une adresse à un interlocuteur plutôt qu'à un lecteur.
BANNIES = {
    r"\bj'avais\b": "récit d'enquête à la première personne",
    r"\bmoi-même\b": "récit d'enquête à la première personne",
    r"\bma contre-vérification\b": "récit d'enquête à la première personne",
    r"\bje consigne\b": "récit d'enquête à la première personne",
    r"\bcomme (?:vous|tu) (?:l'|me |m')": "adresse directe à un interlocuteur",
    r"\bcomme demandé\b": "adresse directe à un interlocuteur",
    r"\b(?:notre|cette) session\b(?! gouvernée)": "chronologie de session comme fil narratif",
}

#: Exceptions ADMISES, chacune avec sa raison. Toute autre occurrence fait échouer le test.
ADMISES = {
    ("ROADMAP.md", r"\bj'avais\b"): "l'exemple de la règle, qui cite volontairement la mauvaise forme",
    ("ROADMAP.md", r"\bmoi-même\b"): "l'exemple de la règle, qui cite volontairement la mauvaise forme",
    ("ROADMAP.md", r"\bcomme (?:vous|tu) (?:l'|me |m')"): "l'exemple de la règle (adresse directe citée)",
    ("CONTRIBUTING.md", r"\bcomme demandé\b"): "énoncé de la règle elle-même",
    ("forge/llm.py", r"\bcomme (?:vous|tu) (?:l'|me |m')"): "chaîne de PROMPT adressée au modèle",
}


def _fichiers():
    for motif in ("forge/**/*.py", "bench/**/*.py", "docs/*.md"):
        yield from RACINE.glob(motif)
    for nom in ("ROADMAP.md", "CONTRIBUTING.md", "README.md"):
        p = RACINE / nom
        if p.exists():
            yield p


class TheRepositoryAddressesAPublicReader(unittest.TestCase):

    def test_aucune_tournure_d_interlocuteur_hors_exceptions_declarees(self):
        fautes = []
        for f in _fichiers():
            rel = str(f.relative_to(RACINE))
            texte = f.read_text(encoding="utf-8", errors="replace")
            for motif, raison in BANNIES.items():
                if (rel, motif) in ADMISES:
                    continue
                for m in re.finditer(motif, texte, re.I):
                    ligne = texte[:m.start()].count("\n") + 1
                    fautes.append(f"{rel}:{ligne} — {raison} : « {m.group(0)} »")
        self.assertEqual(fautes, [], "\n".join(
            ["tournures adressées à un interlocuteur (cf. ROADMAP.md § Gouvernance) :"] + fautes))

    def test_chaque_exception_porte_sa_RAISON(self):
        for (fichier, motif), raison in ADMISES.items():
            with self.subTest(fichier=fichier):
                self.assertTrue(raison.strip(), f"{fichier} exclu sans justification écrite")

    def test_le_garde_a_de_QUOI_mordre(self):
        """Un garde qui ne lit rien ne garde rien : on vérifie qu'il balaie un corpus réel."""
        fichiers = list(_fichiers())
        self.assertGreater(len(fichiers), 60, f"corpus trop maigre : {len(fichiers)} fichiers")

    def test_le_garde_DETECTE_vraiment_la_faute(self):
        """Contrôle positif : sans lui, un garde vert ne prouverait rien."""
        exemple = "Le champ a été écarté parce que j'avais conclu trop vite."
        touche = [m for motif in BANNIES for m in re.finditer(motif, exemple, re.I)]
        self.assertTrue(touche, "le garde ne reconnaît pas sa propre faute de référence")

    def test_la_voix_de_l_OUTIL_n_est_PAS_bannie(self):
        """L'excès inverse : « un `skipped` dit je n'ai PAS pu vérifier » énonce le sens d'un statut."""
        legitimes = ["un `skipped` dit « je n'ai PAS pu vérifier »",
                     "MESURÉ le 2026-08-16 sur l'application vivante",
                     "connaître la disponibilité sur votre machine"]
        for phrase in legitimes:
            with self.subTest(phrase=phrase[:40]):
                touche = [m for motif in BANNIES for m in re.finditer(motif, phrase, re.I)]
                self.assertEqual(touche, [], f"tournure légitime bannie à tort : {phrase}")


if __name__ == "__main__":
    unittest.main()

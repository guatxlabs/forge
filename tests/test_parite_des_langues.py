#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# ORIGINE : repris le 2026-11-24 de l'outillage des deux langues du dépôt Plume (guatxlabs/plume,
# `.github/scripts/test_parite_des_langues.py`), même licence AGPL-3.0-or-later. Seuls changent ici :
# le chemin d'import (l'outil vit sous `scripts/`) et l'ensemble réel attendu par
# `test_ensemble_reel_nomme_ses_raisons` (les trois relevés datés du banc de détection).

"""Épreuves de `parite_des_langues.py` sur de petites paires fabriquées.

Une paire juste doit rendre vert, et chaque défaut qu'une traduction peut introduire sans que sa
relecture le voie doit rendre rouge, nommé par sa famille et par `fichier:ligne`. Les paires vivent
dans un répertoire temporaire ; l'arbre du dépôt n'est jamais lu.

    python3 -m pytest tests/test_parite_des_langues.py
"""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import parite_des_langues as pdl  # noqa: E402

SELECTEUR = "[English](guide.md) | [Français](guide.fr.md)"
SELECTEUR_BASCULE = "[Français](guide.fr.md) | [English](guide.md)"

ORIGINAL = """\
# Guide

[English](guide.md) | [Français](guide.fr.md)

Le budget est de 2,7 Gio, mesuré sur 4 812 337 lignes.

## Installer

```sh
# commentaire libre
cargo test --locked   # suite par défaut
```

Voir [la carte](carte.md#sous-systèmes) et [le schéma](schema.md).

| clé | valeur |
|---|---|
| `EXPECTED_TESTS` | ci.yml |

### Détail

Lire `daemon/Cargo.toml` d'abord.
"""

TRADUCTION = """\
# Guide

[English](guide.md) | [Français](guide.fr.md)

The budget is 2.7 GiB, measured on 4,812,337 lines.

## Install

```sh
# free comment, translated
cargo test --locked   # default suite
```

See [the map](carte.fr.md#subsystems) and [the schema](schema.md).

| key | value |
|---|---|
| `EXPECTED_TESTS` | ci.yml |

### Detail

Read `daemon/Cargo.toml` first.
"""


CARTE = "# Sous-systèmes\n"
CARTE_EN = "# Subsystems\n"


class Paire(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name
        # carte.md a sa traduction, schema.md n'en a pas : un lien bascule, l'autre non. Le titre de
        # carte.fr.md porte l'ancre `#subsystems` que la traduction vise.
        for nom, texte in (("carte.md", CARTE), ("carte.fr.md", CARTE_EN), ("schema.md", "# x\n")):
            self.ecrire(nom, texte)

    def tearDown(self):
        self._tmp.cleanup()

    def ecrire(self, nom, texte):
        chemin = os.path.join(self.racine, nom)
        os.makedirs(os.path.dirname(chemin), exist_ok=True)
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(texte)

    def ecarts(self, traduction, original=ORIGINAL, convention=None, dossier=""):
        convention = convention or pdl.Convention()
        o = os.path.join(dossier, "guide" + convention.original + ".md")
        t = os.path.join(dossier, "guide" + convention.traduction + ".md")
        self.ecrire(o, original)
        self.ecrire(t, traduction)
        return pdl.comparer_fichiers(self.racine, o, t, convention)

    def peupler_docs(self):
        """Sous docs/, les cibles relatives de la paire de base : carte bascule, schema non."""
        for nom, texte in (("docs/carte.md", CARTE), ("docs/carte.fr.md", CARTE_EN),
                           ("docs/schema.md", "# x\n")):
            self.ecrire(nom, texte)

    def familles(self, ecarts):
        return sorted({e.famille for e in ecarts})

    def test_paire_juste_verte(self):
        self.assertEqual(self.ecarts(TRADUCTION), [])

    def test_titre_manquant_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("### Detail\n", ""))
        self.assertEqual(self.familles(ecarts), ["titres"])
        self.assertEqual(str(ecarts[0]).split(" [")[0], "guide.md:20:")

    def test_niveau_de_titre_change_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("### Detail", "## Detail"))
        self.assertEqual(self.familles(ecarts), ["titres"])
        self.assertIn("guide.fr.md:20", ecarts[0].message)

    def test_commande_modifiee_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("cargo test --locked", "cargo test"))
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.md", 11))

    def test_commande_ajoutee_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("cargo test --locked   # default suite\n",
                                                "cargo test --locked\ncargo clippy\n"))
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.fr.md", 12))

    def test_bloc_de_code_retire_rouge(self):
        sans_bloc = TRADUCTION.replace("```sh\n# free comment, translated\n"
                                       "cargo test --locked   # default suite\n```\n", "")
        self.assertIn("blocs", self.familles(self.ecarts(sans_bloc)))

    def test_nombre_change_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("4,812,337", "4,812,373"))
        self.assertEqual(self.familles(ecarts), ["nombres"])
        lieux = {(e.fichier, e.ligne) for e in ecarts}
        self.assertEqual(lieux, {("guide.md", 5), ("guide.fr.md", 5)})

    def test_lien_non_bascule_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("carte.fr.md#subsystems", "carte.md#subsystems"))
        # L'ancre est jugée contre le fichier réellement visé, carte.md, qui n'a pas ce titre.
        self.assertEqual(self.familles(ecarts), ["ancres", "liens"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.fr.md", 14))
        self.assertIn("non basculé", ecarts[0].message)

    def test_lien_bascule_sans_traduction_existante_rouge(self):
        # Les deux sens sont nommés : la cible attendue manque, la cible portée est en trop.
        ecarts = self.ecarts(TRADUCTION.replace("schema.md", "schema.fr.md"))
        self.assertEqual(self.familles(ecarts), ["liens"])
        lus = sorted((e.fichier, e.ligne, e.message) for e in ecarts)
        self.assertEqual(lus, [
            ("guide.fr.md", 14, "lien vers « schema.fr.md » absent de l'original"),
            ("guide.md", 14, "lien vers « schema.md » absent de la traduction"),
        ])

    def test_lien_en_trop_dans_la_traduction_rouge(self):
        ecarts = self.ecarts(TRADUCTION + "\nSee [the annex](annexe.md).\n")
        self.assertEqual([(e.fichier, e.ligne, e.message) for e in ecarts],
                         [("guide.fr.md", 24, "lien vers « annexe.md » absent de l'original")])

    def test_bloc_en_trop_dans_la_traduction_rouge(self):
        ecarts = self.ecarts(TRADUCTION + "\n```sh\nmake extra\n```\n")
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.fr.md", 24))
        self.assertIn("2 blocs de code contre 1 dans guide.md", ecarts[0].message)

    def test_tableau_en_trop_dans_la_traduction_rouge(self):
        ecarts = self.ecarts(TRADUCTION + "\n| a | b |\n|---|---|\n")
        self.assertEqual(self.familles(ecarts), ["tableaux"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.fr.md", 24))
        self.assertIn("2 tableaux contre 1 dans guide.md", ecarts[0].message)

    def test_lien_relatif_resolu_depuis_le_dossier_du_document(self):
        # docs/plan.md a sa traduction ; à la racine, plan.fr.md n'existe pas. Résolu depuis la
        # racine, le lien ne basculerait pas, et la traduction juste serait accusée.
        self.peupler_docs()
        for nom in ("docs/plan.md", "docs/plan.fr.md"):
            self.ecrire(nom, "# x\n")
        original = ORIGINAL + "\nVoir [le plan](plan.md).\n"
        juste = TRADUCTION + "\nSee [the plan](plan.fr.md).\n"
        self.assertEqual(self.ecarts(juste, original, dossier="docs"), [])
        ecarts = self.ecarts(juste.replace("plan.fr.md", "plan.md"), original, dossier="docs")
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertIn("non basculé", ecarts[0].message)
        self.assertEqual(ecarts[0].fichier, os.path.join("docs", "guide.fr.md"))

    def test_lien_absolu_resolu_depuis_la_racine(self):
        # annexe.fr.md existe à la racine, pas sous docs/ : `/annexe.md` bascule depuis docs/.
        self.peupler_docs()
        for nom in ("annexe.md", "annexe.fr.md", "docs/annexe.md"):
            self.ecrire(nom, "# x\n")
        original = ORIGINAL + "\nVoir [l'annexe](/annexe.md).\n"
        juste = TRADUCTION + "\nSee [the annex](/annexe.fr.md).\n"
        self.assertEqual(self.ecarts(juste, original, dossier="docs"), [])
        ecarts = self.ecarts(juste.replace("/annexe.fr.md", "/annexe.md"), original, dossier="docs")
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertIn("non basculé", ecarts[0].message)

    def test_selecteur_de_langue_identique_des_deux_cotes(self):
        # Le sélecteur vise le document lui-même et sa traduction : il est le même des deux côtés,
        # et ses liens ne basculent pas (la paire de base le porte et rend vert).
        self.assertIn(SELECTEUR, ORIGINAL)
        self.assertEqual(self.ecarts(TRADUCTION), [])
        # Depuis un sous-dossier, la cible relative désigne la même paire.
        self.peupler_docs()
        self.assertEqual(self.ecarts(TRADUCTION, dossier="docs"), [])
        # Un lien vers un AUTRE document non basculé reste accusé, sélecteur présent.
        ecarts = self.ecarts(TRADUCTION.replace("carte.fr.md#", "carte.md#"))
        self.assertEqual(self.familles(ecarts), ["ancres", "liens"])
        self.assertIn("non basculé", next(e for e in ecarts if e.famille == "liens").message)

    def test_selecteur_de_langue_convention_basculee(self):
        convention = pdl.Convention(".fr", "")
        for nom in ("carte.fr.md", "annexe.fr.md"):
            self.ecrire(nom, "# x\n")
        self.ecrire("carte.md", CARTE_EN)
        original = ORIGINAL.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.md", "carte.fr.md").replace("schema.md", "annexe.fr.md")
        juste = TRADUCTION.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.fr.md", "carte.md").replace("schema.md", "annexe.fr.md")
        self.assertEqual(self.ecarts(juste, original, convention), [])
        # Un sélecteur d'une autre convention vise un fichier qui n'est pas de la paire.
        # Ses deux liens diffèrent de ceux de l'original : la famille des liens le dit aussi.
        autre = "[English](guide.md) | [Deutsch](guide.de.md)"
        ecarts = self.ecarts(juste.replace(SELECTEUR_BASCULE, autre), original, convention)
        selecteur = [e for e in ecarts if e.famille == "sélecteur"]
        self.assertEqual([(e.fichier, e.ligne) for e in selecteur], [("guide.md", 3)])
        self.assertIn("attendu « guide.fr.md » puis « guide.md »", selecteur[0].message)
        self.assertEqual(self.familles(ecarts), ["liens", "sélecteur"])

    def test_selecteur_convention_inverse_nomme_l_original_d_abord(self):
        # Convention inverse, original `X.fr.md` et traduction `X.md` : l'original vient en premier,
        # quelle que soit sa langue.
        convention = pdl.Convention(".fr", "")
        for nom in ("carte.fr.md", "annexe.fr.md"):
            self.ecrire(nom, "# x\n")
        self.ecrire("carte.md", CARTE_EN)
        original = ORIGINAL.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.md#sous-systèmes", "carte.fr.md#x").replace("schema.md", "annexe.fr.md")
        juste = TRADUCTION.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.fr.md", "carte.md").replace("schema.md", "annexe.fr.md")
        self.assertEqual(self.ecarts(juste, original, convention), [])
        ecarts = self.ecarts(juste.replace(SELECTEUR_BASCULE, SELECTEUR), original, convention)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.md", 3, "sélecteur")])
        self.assertIn("inversé", ecarts[0].message)

    def test_selecteur_absent_des_deux_cotes_rouge(self):
        sans = SELECTEUR + "\n\n"
        ecarts = self.ecarts(TRADUCTION.replace(sans, ""), ORIGINAL.replace(sans, ""))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.md", 3, "sélecteur"), ("guide.fr.md", 3, "sélecteur")])
        self.assertIn("absent sous le titre de niveau 1 (ligne 1)", ecarts[0].message)
        self.assertIn("« guide.md » puis « guide.fr.md »", ecarts[0].message)

    def test_selecteur_absent_d_un_cote_rouge(self):
        # Ses deux liens manquent d'un côté : la famille des liens le dit aussi.
        for traduction, original, fautif in (
                (TRADUCTION.replace(SELECTEUR + "\n\n", ""), ORIGINAL, "guide.fr.md"),
                (TRADUCTION, ORIGINAL.replace(SELECTEUR + "\n\n", ""), "guide.md")):
            ecarts = self.ecarts(traduction, original)
            self.assertEqual([(e.fichier, e.ligne) for e in ecarts if e.famille == "sélecteur"],
                             [(fautif, 3)])
            self.assertEqual(self.familles(ecarts), ["liens", "sélecteur"])

    def test_selecteur_inverse_dans_la_traduction_rouge(self):
        # Mêmes cibles, donc aucun écart de lien : seul l'ordre trahit l'inversion.
        inverse = "[Français](guide.fr.md) | [English](guide.md)"
        ecarts = self.ecarts(TRADUCTION.replace(SELECTEUR, inverse))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.fr.md", 3, "sélecteur")])
        self.assertIn("inversé", ecarts[0].message)

    def test_selecteur_qui_vise_un_autre_fichier_rouge(self):
        autre = "[English](carte.md) | [Français](carte.fr.md)"
        ecarts = self.ecarts(TRADUCTION.replace(SELECTEUR, autre), ORIGINAL.replace(SELECTEUR, autre))
        selecteur = [e for e in ecarts if e.famille == "sélecteur"]
        self.assertEqual([(e.fichier, e.ligne) for e in selecteur],
                         [("guide.md", 3), ("guide.fr.md", 3)])
        self.assertIn("vise carte.md, carte.fr.md", selecteur[0].message)
        # Un seul lien, vers l'original : la traduction manque au sélecteur.
        seul = "[English](guide.md)"
        ecarts = self.ecarts(TRADUCTION.replace(SELECTEUR, seul), ORIGINAL.replace(SELECTEUR, seul))
        self.assertEqual(self.familles(ecarts), ["sélecteur"])
        self.assertEqual(len(ecarts), 2)

    def test_selecteur_libelle_change_rouge(self):
        # Les cibles sont justes, un libellé ne l'est pas : la forme exacte est jugée.
        ecarts = self.ecarts(TRADUCTION.replace("[Français]", "[French]", 1))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.fr.md", 3, "sélecteur")])
        self.assertIn("attendu exactement « [English](guide.md) | [Français](guide.fr.md) »", ecarts[0].message)

    def test_selecteur_aux_libelles_inverses_rouge(self):
        # Mêmes cibles dans le bon ordre, libellés intervertis des deux côtés : la ligne est la même des
        # deux côtés, et elle est fausse des deux.
        inverse = "[Français](guide.md) | [English](guide.fr.md)"
        ecarts = self.ecarts(TRADUCTION.replace(SELECTEUR, inverse), ORIGINAL.replace(SELECTEUR, inverse))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.md", 3, "sélecteur"), ("guide.fr.md", 3, "sélecteur")])
        self.assertIn("forme du sélecteur", ecarts[0].message)

    def test_selecteur_different_d_un_cote_a_l_autre_rouge(self):
        # Une convention dont les langues ne sont pas nommées (`.de`) : pas de forme exacte, mais la même
        # ligne des deux côtés reste exigée.
        convention = pdl.Convention("", ".de")
        self.ecrire("carte.de.md", CARTE_EN)
        selecteur = "[English](guide.md) | [Deutsch](guide.de.md)"
        original = ORIGINAL.replace(SELECTEUR, selecteur)
        juste = TRADUCTION.replace(SELECTEUR, selecteur).replace("carte.fr.md", "carte.de.md")
        self.assertEqual(self.ecarts(juste, original, convention), [])
        ecarts = self.ecarts(juste.replace("[Deutsch]", "[German]", 1), original, convention)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.de.md", 3, "sélecteur")])
        self.assertIn("différent de celui de l'original (guide.md:3)", ecarts[0].message)

    def test_selecteur_pas_juste_sous_le_titre_rouge(self):
        # Une phrase s'intercale : la ligne sous le titre n'est pas un sélecteur.
        intercale = "Lire en : " + SELECTEUR
        ecarts = self.ecarts(TRADUCTION.replace(SELECTEUR, intercale),
                             ORIGINAL.replace(SELECTEUR, intercale))
        self.assertEqual(self.familles(ecarts), ["sélecteur"])
        self.assertEqual(len(ecarts), 2)
        ecarts = self.ecarts(TRADUCTION.replace("# Guide\n\n", "# Guide\n\nIntro.\n\n", 1),
                             ORIGINAL.replace("# Guide\n\n", "# Guide\n\nIntro.\n\n", 1))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.md", 3, "sélecteur"), ("guide.fr.md", 3, "sélecteur")])

    def test_second_titre_1_ne_deplace_pas_le_selecteur(self):
        # Le sélecteur se cherche sous le PREMIER titre de niveau 1 : un second titre de niveau 1,
        # suivi d'une ligne qui n'est pas un sélecteur, ne fait pas d'écart.
        original = ORIGINAL + "\n# Annexe\n\nTexte de l'annexe.\n"
        juste = TRADUCTION + "\n# Appendix\n\nAppendix text.\n"
        self.assertEqual(self.ecarts(juste, original), [])

    def test_selecteur_sous_le_second_titre_1_seulement_rouge(self):
        # Placé sous le second titre de niveau 1 et absent sous le premier, le sélecteur manque.
        sans = SELECTEUR + "\n\n"
        original = ORIGINAL.replace(sans, "") + "\n# Annexe\n\n" + SELECTEUR + "\n"
        juste = TRADUCTION.replace(sans, "") + "\n# Appendix\n\n" + SELECTEUR + "\n"
        ecarts = self.ecarts(juste, original)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.md", 3, "sélecteur"), ("guide.fr.md", 3, "sélecteur")])
        self.assertIn("absent sous le titre de niveau 1 (ligne 1)", ecarts[0].message)

    def test_segment_de_code_replie_lu_comme_un_seul(self):
        # CommonMark : dans un paragraphe, la fin de ligne d'un segment de code vaut une espace.
        original = ORIGINAL + "\nLancer `cargo test\n--locked` puis lire.\n"
        juste = TRADUCTION + "\nRun `cargo test --locked` then read.\n"
        self.assertEqual(self.ecarts(juste, original), [])
        # Replié ailleurs dans la traduction : toujours le même segment.
        self.assertEqual(self.ecarts(TRADUCTION + "\nRun `cargo\ntest --locked` then read.\n",
                                     original), [])
        ecarts = self.ecarts(juste.replace("cargo test --locked` then", "cargo test` then"), original)
        self.assertEqual(self.familles(ecarts), ["identifiants"])
        self.assertIn(("guide.md", 24, "identifiant « cargo test --locked » absent de la traduction"),
                      [(e.fichier, e.ligne, e.message) for e in ecarts])

    def test_segment_de_code_replie_dans_une_citation(self):
        # La forme de docs/CIM.md : le mot qui suit le segment replié n'est pas un identifiant.
        original = ORIGINAL + "\n> Ingérés : `search a |\n> stats b` rendait `x 2`.\n"
        juste = TRADUCTION + "\n> Ingested: `search a |\n> stats b` returned `x 2`.\n"
        self.assertEqual(self.ecarts(juste, original), [])
        self.assertEqual(self.ecarts(TRADUCTION + "\n> Ingested: `search a | stats b` returned "
                                     "`x 2`.\n", original), [])

    def test_accent_grave_seul_ne_traverse_pas_le_paragraphe(self):
        # Un accent grave que rien ne ferme dans son paragraphe est du texte : la ligne vide, le
        # titre et la puce de liste arrêtent la recherche de sa fermeture.
        for coupure in ("\n", "## Suite\n", "- puce\n"):
            original = ORIGINAL + f"\nUn accent ` seul.\n{coupure}Puis `x` et ` y.\n"
            juste = TRADUCTION + f"\nA lone ` accent.\n{coupure}Then `x` and ` y.\n"
            self.assertEqual(self.ecarts(juste, original), [], coupure)
            ecarts = self.ecarts(juste.replace("`x`", "`z`"), original)
            self.assertEqual(self.familles(ecarts), ["identifiants"], coupure)

    def test_accent_grave_seul_n_emporte_pas_la_suite_du_paragraphe(self):
        # Sans fermeture, la ligne reste seule même quand le paragraphe continue : ce que portent
        # les lignes suivantes leur reste rapporté. (Un accent grave sur la suite fermerait le
        # segment, comme en CommonMark : `seul et` serait alors un segment.)
        original = ORIGINAL + "\nUn accent ` seul\net puis 42 ici.\n"
        juste = TRADUCTION + "\nA lone ` accent\nand then 42 here.\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("42", "43"), original)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.md", 25, "nombres"), ("guide.fr.md", 25, "nombres")])

    def test_ligne_de_tableau_coupe_le_paragraphe(self):
        # Un accent grave resté ouvert n'avale pas la ligne de tableau qui suit : elle reste une
        # ligne du tableau, et le segment qu'elle porte reste le sien.
        doc = pdl.analyser("Un accent ` seul\n| `x` | y |\n| --- | --- |\n", "a.md")
        self.assertEqual(doc.tableaux, [(2, 2)])
        self.assertEqual(doc.identifiants, {"x": 2})
        original = ORIGINAL + "\nUn accent ` seul\n| `x` | y |\n| --- | --- |\n"
        juste = TRADUCTION + "\nA lone ` accent\n| `x` | y |\n| --- | --- |\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("`x`", "`z`"), original)
        self.assertEqual(self.familles(ecarts), ["identifiants"])

    def test_puce_numerotee_coupe_le_paragraphe(self):
        # Une puce numérotée (`1.` ou `1)`) ouvre une liste : un accent grave resté ouvert sur la
        # ligne d'avant ne l'emporte pas.
        for puce in ("1. ", "1) "):
            doc = pdl.analyser(f"Un accent ` seul\n{puce}puis `z` fin\n", "a.md")
            self.assertEqual(doc.identifiants, {"z": 2}, puce)
            original = ORIGINAL + f"\nUn accent ` seul\n{puce}puis `z` fin\n"
            juste = TRADUCTION + f"\nA lone ` accent\n{puce}then `z` end\n"
            self.assertEqual(self.ecarts(juste, original), [], puce)

    def test_cloture_ou_puce_indentee_coupe_le_paragraphe(self):
        # Une clôture est une clôture à toute indentation pour l'outil (bloc dans une puce) ; une
        # puce indentée ouvre une sous-liste. Ni l'une ni l'autre n'est avalée par un accent ouvert.
        doc = pdl.analyser("- Lancer ` ceci\n    ```sh\n    make a `x`\n    ```\n"
                           "- a ` b\n    - sous `c` d\n", "a.md")
        self.assertEqual(doc.blocs, [(2, [(3, "make a `x`")])])
        self.assertEqual(doc.identifiants, {"c": 6})
        original = ORIGINAL + "\n- Lancer ` ceci\n    ```sh\n    make a `x`\n    ```\n"
        juste = TRADUCTION + "\n- Run ` this\n    ```sh\n    make a `x`\n    ```\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("make a", "make b"), original)
        self.assertEqual(self.familles(ecarts), ["blocs"])

    def test_ancre_html_sur_une_ligne_rejointe(self):
        original = ORIGINAL + "\nLancer `cargo\ntest` ici <a id=\"pin\"></a>.\n\nVoir [p](#pin).\n"
        juste = TRADUCTION + "\nRun `cargo\ntest` here <a id=\"pin\"></a>.\n\nSee [p](#pin).\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("[p](#pin)", "[p](#pine)"), original)
        self.assertEqual(self.familles(ecarts), ["ancres"])

    def test_ancre_vers_un_titre_traduit_verte(self):
        # La paire de base vise `carte.fr.md#subsystems`, titre réel de carte.fr.md.
        self.assertIn("carte.fr.md#subsystems", TRADUCTION)
        self.assertEqual(self.ecarts(TRADUCTION), [])

    def test_ancre_changee_d_une_lettre_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("#subsystems", "#subsystem"))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.fr.md", 14, "ancres")])
        self.assertIn("ancre « #subsystem » : aucun titre de carte.fr.md", ecarts[0].message)

    def test_ancre_restee_sur_le_titre_francais_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("#subsystems", "#sous-systèmes"))
        self.assertEqual(self.familles(ecarts), ["ancres"])
        self.assertIn("titre de l'original carte.md : viser le titre traduit", ecarts[0].message)
        # Encodée en pourcent, l'ancre désigne le même titre.
        ecarts = self.ecarts(TRADUCTION.replace("#subsystems", "#sous-syst%C3%A8mes"))
        self.assertIn("titre de l'original carte.md", ecarts[0].message)

    def test_ancre_dans_le_document_lui_meme(self):
        juste = TRADUCTION + "\nBack to [the detail](#detail).\n"
        original = ORIGINAL + "\nRetour au [détail](#détail).\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("(#detail)", "(#détail)"), original)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.fr.md", 24, "ancres")])
        self.assertIn("l'original guide.md", ecarts[0].message)

    def test_slug_github(self):
        # Minuscules, ponctuation retirée, espaces en tirets, accents conservés, contenu des
        # segments de code gardé, emoji retiré, `_` gardé, séquence de clôture ôtée.
        cas = {
            "Étape 2 : l'installation (rapide)": "étape-2--linstallation-rapide",
            "⚠️ `PLUME_*` — variables": "-plume_--variables",
            "3. L'authentification, et ce que « lié à l'hôte » veut dire":
                "3-lauthentification-et-ce-que--lié-à-lhôte--veut-dire",
            "Voir [la carte](carte.md) **vite** ##": "voir-la-carte-vite",
            "1.1 `a.b` <br> fin": "11-ab--fin",
        }
        for titre, attendu in cas.items():
            self.assertEqual(pdl.slug(titre), attendu, titre)

    def test_ancre_de_titre_en_double(self):
        self.ecrire("carte.fr.md", "# Subsystems\n\n## Usage\n\n## Usage\n")
        self.ecrire("carte.md", "# Sous-systèmes\n\n## Usage\n\n## Usage\n")
        original = ORIGINAL + "\nVoir [le second](carte.md#usage-1).\n"
        juste = TRADUCTION + "\nSee [the second](carte.fr.md#usage-1).\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("#usage-1", "#usage-2"), original)
        self.assertEqual(self.familles(ecarts), ["ancres"])

    def test_ancre_html_et_titre_souligne_existent(self):
        self.ecrire("carte.fr.md", CARTE_EN + "\n<a id=\"pin\"></a>\n\nUnderlined\n----------\n")
        for ancre in ("pin", "underlined"):
            original = ORIGINAL + f"\nVoir [ici](carte.md#{ancre}).\n"
            juste = TRADUCTION + f"\nSee [here](carte.fr.md#{ancre}).\n"
            self.assertEqual(self.ecarts(juste, original), [], ancre)

    def test_ancres_non_jugees(self):
        # La comparaison de paire ne juge pas les ancres de l'original (`comparer_documents` le fait) ; ni une cible qui n'est pas un document Markdown de l'arbre ;
        # ni une ancre en majuscules (la casse n'est pas tranchée). `script.sh` existe : c'est son
        # extension qui le tait, pas la règle du fichier absent.
        self.ecrire("script.sh", "#!/bin/sh\necho un\necho deux\n")
        original = ORIGINAL.replace("#sous-systèmes", "#nulle-part") + (
            "\nVoir [s](script.sh#L3), [a](absent.md#x) et [e](https://example.org/a.md#z).\n")
        juste = TRADUCTION.replace("#subsystems", "#Subsystems") + (
            "\nSee [s](script.sh#L3), [a](absent.md#x) and [e](https://example.org/a.md#z).\n")
        self.assertEqual(self.ecarts(juste, original), [])

    def test_ancre_vers_un_fichier_qui_n_est_pas_du_markdown_non_jugee(self):
        # `script.sh` existe dans l'arbre et n'a aucun titre `L3` : seule son extension tait l'ancre.
        self.ecrire("script.sh", "#!/bin/sh\necho un\necho deux\n")
        original = ORIGINAL + "\nVoir [s](script.sh#L3).\n"
        juste = TRADUCTION + "\nSee [s](script.sh#L3).\n"
        self.assertEqual(self.ecarts(juste, original), [])
        # Le même contenu sous un nom Markdown est jugé : c'est bien l'extension qui la tait.
        self.ecrire("script.md", "#!/bin/sh\necho un\necho deux\n")
        ecarts = self.ecarts(juste.replace("script.sh", "script.md"),
                             original.replace("script.sh", "script.md"))
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.fr.md", 24, "ancres")])

    def test_ancre_vers_un_fichier_hors_de_l_arbre_non_jugee(self):
        # La racine est un sous-dossier ; `../dehors.md` existe à côté, hors de l'arbre, et n'a pas
        # le titre visé : il n'est ni lu ni jugé.
        self.racine = os.path.join(self._tmp.name, "depot")
        for nom, texte in (("carte.md", CARTE), ("carte.fr.md", CARTE_EN), ("schema.md", "# x\n")):
            self.ecrire(nom, texte)
        with open(os.path.join(self._tmp.name, "dehors.md"), "w", encoding="utf-8") as f:
            f.write("# Dehors\n")
        original = ORIGINAL + "\nVoir [d](../dehors.md#rien).\n"
        juste = TRADUCTION + "\nSee [d](../dehors.md#rien).\n"
        self.assertEqual(self.ecarts(juste, original), [])
        # Dans l'arbre, la même ancre est accusée : c'est bien la sortie de l'arbre qui la tait.
        self.ecrire("dedans.md", "# Dedans\n")
        ecarts = self.ecarts(juste.replace("../dehors.md", "dedans.md"),
                             original.replace("../dehors.md", "dedans.md"))
        self.assertEqual(self.familles(ecarts), ["ancres"])

    def test_ancre_dans_une_definition_de_lien(self):
        original = ORIGINAL + "\nVoir [la carte][r].\n\n[r]: carte.md#sous-systèmes\n"
        juste = TRADUCTION + "\nSee [the map][r].\n\n[r]: carte.fr.md#subsystems\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("[r]: carte.fr.md#subsystems", "[r]: carte.fr.md#maps"),
                             original)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.fr.md", 26, "ancres")])

    def test_note_de_bas_de_page_n_est_pas_une_definition_de_lien(self):
        original = ORIGINAL + "\nVoir la note[^1].\n\n[^1]: Voir le manuel, page 12.\n"
        juste = TRADUCTION + "\nSee the note[^1].\n\n[^1]: See the manual, page 12.\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("page 12", "page 13"), original)
        self.assertEqual(self.familles(ecarts), ["nombres"])

    def test_bom_ne_masque_pas_le_premier_titre(self):
        self.assertEqual(self.ecarts(TRADUCTION, "\ufeff" + ORIGINAL), [])
        ecarts = self.ecarts(TRADUCTION.replace("# Guide\n", "Guide\n", 1), "\ufeff" + ORIGINAL)
        # Sans titre de niveau 1, le sélecteur n'a plus de place : les deux écarts sont nommés.
        self.assertEqual(self.familles(ecarts), ["sélecteur", "titres"])

    def test_ligne_de_tableau_retiree_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("| `EXPECTED_TESTS` | ci.yml |\n", ""))
        self.assertIn("tableaux", self.familles(ecarts))
        self.assertIn("identifiants", self.familles(ecarts))

    def test_identifiant_change_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("`daemon/Cargo.toml`", "`daemon/Cargo.lock`"))
        self.assertEqual(self.familles(ecarts), ["identifiants"])

    def test_commentaire_html_et_url_ne_comptent_pas(self):
        # Les nombres 42, 83 et 91 n'existent nulle part ailleurs : seule leur exclusion les tait.
        # L'URL diffère d'un côté à l'autre (page localisée) sans que ce soit un écart de nombre ;
        # une URL nue n'est pas comparée comme cible de lien, donc aucun écart de lien non plus.
        original = ORIGINAL + "\n<!-- note 42 -->\nSource : https://example.org/fr/v83\n"
        traduction = TRADUCTION + "\nSource: https://example.org/en/v91\n"
        self.assertEqual(self.ecarts(traduction, original), [])

    def test_titre_en_trop_rouge(self):
        ecarts = self.ecarts(TRADUCTION + "\n## Extra\n")
        self.assertEqual(self.familles(ecarts), ["titres"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.fr.md", 24))

    def test_commande_retiree_d_un_bloc_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("cargo test --locked   # default suite\n", ""))
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.md", 11))
        self.assertIn("absente", ecarts[0].message)

    def test_tableau_retire_entier_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("| key | value |\n|---|---|\n"
                                                "| `EXPECTED_TESTS` | ci.yml |\n", ""))
        self.assertIn("tableaux", self.familles(ecarts))
        tableaux = [e for e in ecarts if e.famille == "tableaux"]
        self.assertEqual((tableaux[0].fichier, tableaux[0].ligne), ("guide.md", 16))

    def test_lien_retire_de_la_traduction_rouge(self):
        ecarts = self.ecarts(TRADUCTION.replace("[the schema](schema.md)", "the schema"))
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertEqual((ecarts[0].fichier, ecarts[0].ligne), ("guide.md", 14))
        self.assertIn("absent de la traduction", ecarts[0].message)

    def test_definition_de_lien_comparee(self):
        original = ORIGINAL + "\nVoir [la carte][r].\n\n[r]: carte.md\n"
        juste = TRADUCTION + "\nSee [the map][r].\n\n[r]: carte.fr.md\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("[r]: carte.fr.md", "[r]: carte.md"), original)
        self.assertEqual(self.familles(ecarts), ["liens"])
        self.assertIn("non basculé", ecarts[0].message)

    def test_lien_dans_un_segment_de_code_n_est_pas_un_lien(self):
        # Un exemple de syntaxe cité entre accents graves ne se bascule pas : il reste identique.
        original = ORIGINAL + "\nÉcrire `[x](carte.md)` tel quel.\n"
        traduction = TRADUCTION + "\nWrite `[x](carte.md)` as is.\n"
        self.assertEqual(self.ecarts(traduction, original), [])

    def test_citation_lue_comme_le_texte(self):
        original = ORIGINAL + "\n> ## Note\n>\n> ```sh\n> make check\n> ```\n"
        juste = TRADUCTION + "\n> ## Note\n>\n> ```sh\n> make check\n> ```\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("> make check", "> make"), original)
        self.assertEqual(self.familles(ecarts), ["blocs"])
        ecarts = self.ecarts(juste.replace("> ## Note", "> ### Note"), original)
        self.assertEqual(self.familles(ecarts), ["titres"])

    def test_cloture_plus_courte_ne_ferme_pas_le_bloc(self):
        # Un bloc ouvert par quatre accents graves cite un bloc de trois sans se fermer.
        bloc = "\n````md\n```sh\nmake a\n```\nmake b\n````\n"
        original = ORIGINAL + bloc
        self.assertEqual(self.ecarts(TRADUCTION + bloc, original), [])
        ecarts = self.ecarts(TRADUCTION + bloc.replace("make b", "make c"), original)
        self.assertEqual(self.familles(ecarts), ["blocs"])
        self.assertIn("make b", ecarts[0].message)

    def test_diese_de_code_n_est_pas_un_commentaire(self):
        bloc = "\n```rust\n#[derive(Debug)]\nstruct S;\n```\n"
        original = ORIGINAL + bloc
        self.assertEqual(self.ecarts(TRADUCTION + bloc, original), [])
        ecarts = self.ecarts(TRADUCTION + bloc.replace("Debug", "Clone"), original)
        self.assertEqual(self.familles(ecarts), ["blocs"])

    def test_lien_au_texte_replie_lu_comme_un_seul(self):
        # CommonMark : le texte d'un lien peut passer à la ligne ; replié ailleurs de chaque côté, c'est
        # le même lien, et sa cible se compare comme les autres.
        original = ORIGINAL + "\nVoir [la carte des\nsous-systèmes](carte.md#sous-systèmes) ici.\n"
        juste = TRADUCTION + "\nSee [the map of the subsystems](carte.fr.md#subsystems)\nhere.\n"
        self.assertEqual(self.ecarts(juste, original), [])
        replie = TRADUCTION + "\nSee [the map of\nthe subsystems](carte.fr.md#subsystems) here.\n"
        self.assertEqual(self.ecarts(replie, original), [])
        ecarts = self.ecarts(replie.replace("subsystems](carte.fr.md#", "subsystems](carte.md#"), original)
        self.assertIn("non basculé", next(e for e in ecarts if e.famille == "liens").message)
        self.assertEqual(next(e for e in ecarts if e.famille == "liens").ligne, 24)

    def test_crochet_qui_n_ouvre_aucun_lien_n_emporte_pas_la_suite(self):
        # Sans lien qui traverse la coupure, la ligne reste seule : ce que porte la suivante lui reste
        # rapporté.
        original = ORIGINAL + "\nUn crochet [seul\net puis 42 ici.\n"
        juste = TRADUCTION + "\nA lone [bracket\nand then 42 here.\n"
        self.assertEqual(self.ecarts(juste, original), [])
        ecarts = self.ecarts(juste.replace("42", "43"), original)
        self.assertEqual([(e.fichier, e.ligne, e.famille) for e in ecarts],
                         [("guide.md", 25, "nombres"), ("guide.fr.md", 25, "nombres")])

    def test_point_barre_ne_change_pas_la_cible(self):
        juste = TRADUCTION.replace("(carte.fr.md#", "(./carte.fr.md#").replace("(schema.md)",
                                                                              "(./schema.md)")
        self.assertEqual(self.ecarts(juste), [])

    def test_convention_basculee(self):
        convention = pdl.Convention(".fr", "")
        # carte.fr.md a sa traduction carte.md ; annexe.fr.md n'en a pas.
        for nom in ("carte.fr.md", "annexe.fr.md"):
            self.ecrire(nom, "# x\n")
        self.ecrire("carte.md", CARTE_EN)
        original = ORIGINAL.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.md", "carte.fr.md").replace("schema.md", "annexe.fr.md")
        juste = TRADUCTION.replace(SELECTEUR, SELECTEUR_BASCULE).replace(
            "carte.fr.md", "carte.md").replace("schema.md", "annexe.fr.md")
        self.assertEqual(self.ecarts(juste, original, convention), [])
        ecarts = self.ecarts(juste.replace("(carte.md", "(carte.fr.md"), original, convention)
        self.assertIn("non basculé", ecarts[0].message)


PROSE_FR = ("Le capteur lit la file et le journal, puis il les envoie au central pour que la règle "
            "les juge dans la fenêtre qui est la sienne ; ce n'est pas une copie, et elle ne garde "
            "rien sur le disque quand le central est joignable par le réseau.\n")
PROSE_EN = ("The sensor reads the queue and the log, then it sends them to the central so that the rule "
            "can judge them in the window that is its own; this is not a copy, and it keeps nothing on "
            "the disk when the central is reachable by the network.\n")


class Langue(unittest.TestCase):
    """La langue de la prose de chaque fichier de la paire, lue par ses mots-outils."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def paire(self, original, traduction):
        for nom, texte in (("guide.md", original), ("guide.fr.md", traduction)):
            with open(os.path.join(self.racine, nom), "w", encoding="utf-8") as f:
                f.write(texte)
        return pdl.comparer_fichiers(self.racine, "guide.md", "guide.fr.md", pdl.Convention())

    def test_paire_dans_ses_langues_verte(self):
        tete = "# Guide\n\n" + SELECTEUR + "\n\n"
        self.assertEqual(self.paire(tete + PROSE_EN, tete + PROSE_FR), [])

    def test_paire_intervertie_rouge_des_deux_cotes(self):
        # Texte français dans `X.md`, anglais dans `X.fr.md`, sans lien croisé qui le trahirait.
        tete = "# Guide\n\n" + SELECTEUR + "\n\n"
        ecarts = self.paire(tete + PROSE_FR, tete + PROSE_EN)
        self.assertEqual([(e.fichier, e.famille) for e in ecarts],
                         [("guide.md", "langue"), ("guide.fr.md", "langue")])
        self.assertIn("la prose n'est pas en anglais", ecarts[0].message)
        self.assertIn("la prose n'est pas en français", ecarts[1].message)

    def test_document_presque_tout_en_code_non_juge(self):
        # Sous le plancher de mots-outils, aucune langue ne se dégage : pas de faux rouge.
        tete = "# Guide\n\n" + SELECTEUR + "\n\n"
        code = "```sh\nthe and is are of to in for with that this not by it be an as which from\n```\n"
        doc = tete + "Le budget est de 2 Gio.\n\n" + code
        self.assertEqual(self.paire(doc, doc), [])
        self.assertLess(pdl.analyser(doc, "x.md").mots_en, pdl.MIN_MOTS_OUTILS)

    def test_code_cite_et_cibles_ne_comptent_pas(self):
        texte = "`the and is are of to` [lien](the-and-is.md) <https://example.org/the/and/is>\n" * 10
        doc = pdl.analyser(texte, "x.md")
        self.assertEqual((doc.mots_fr, doc.mots_en), (0, 0))

    def test_langues_de_la_convention(self):
        self.assertEqual(pdl.Convention().langues(), ("en", "fr"))
        self.assertEqual(pdl.Convention(".fr", "").langues(), ("fr", "en"))
        self.assertEqual(pdl.Convention("", ".de").langues(), (None, None))


class DocumentSeul(unittest.TestCase):
    """`comparer_documents` : direction des liens et ancres, jugées document par document."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name
        self.fichiers = {
            "guide.md": "# Guide\n\n" + SELECTEUR + "\n\nSee [the map](carte.md#map).\n",
            "guide.fr.md": "# Guide\n\n" + SELECTEUR + "\n\nVoir [la carte](carte.fr.md#carte).\n",
            "carte.md": "# Map\n\n[English](carte.md) | [Français](carte.fr.md)\n",
            "carte.fr.md": "# Carte\n\n[English](carte.md) | [Français](carte.fr.md)\n",
            "journal.md": "# Journal\n\n" + PROSE_FR + "\nVoir [la carte](carte.fr.md#carte).\n",
        }

    def tearDown(self):
        self._tmp.cleanup()

    def juger(self, **remplacements):
        fichiers = dict(self.fichiers, **{k.replace("__", "."): v for k, v in remplacements.items()})
        for nom, texte in fichiers.items():
            with open(os.path.join(self.racine, nom), "w", encoding="utf-8") as f:
                f.write(texte)
        ecarts, illisibles = pdl.comparer_documents(self.racine, sorted(fichiers), pdl.Convention())
        self.assertEqual(illisibles, [])
        return [(e.fichier, e.ligne, e.famille) for e in ecarts], ecarts

    def test_arbre_juste_vert(self):
        self.assertEqual(self.juger()[0], [])

    def test_original_anglais_qui_vise_la_version_francaise_rouge(self):
        lieux, ecarts = self.juger(guide__md=self.fichiers["guide.md"].replace("(carte.md#map)", "(carte.fr.md#carte)"))
        self.assertEqual(lieux, [("guide.md", 5, "direction")])
        self.assertIn("viser « carte.md »", ecarts[0].message)

    def test_document_francais_sans_paire_qui_vise_la_version_anglaise_rouge(self):
        lieux, ecarts = self.juger(journal__md=self.fichiers["journal.md"].replace("(carte.fr.md#carte)", "(carte.md#map)"))
        self.assertEqual(lieux, [("journal.md", 5, "direction")])
        self.assertIn("document français qui vise la version anglaise", ecarts[0].message)

    def test_ancre_absente_dans_un_original_rouge(self):
        lieux, ecarts = self.juger(guide__md=self.fichiers["guide.md"].replace("#map", "#mapp"))
        self.assertEqual(lieux, [("guide.md", 5, "ancres")])
        self.assertIn("ancre « #mapp »", ecarts[0].message)

    def test_ancre_absente_dans_le_document_lui_meme_rouge(self):
        lieux, _ = self.juger(guide__md=self.fichiers["guide.md"] + "\nBack to [the top](#guid).\n")
        self.assertEqual(lieux, [("guide.md", 7, "ancres")])

    def test_le_selecteur_est_la_seule_exception_de_direction(self):
        # La ligne du sélecteur vise la version française : admise. La même cible dans le corps : écart.
        self.assertEqual(self.juger()[0], [])
        lieux, _ = self.juger(guide__md=self.fichiers["guide.md"] + "\nSee [the French page](guide.fr.md).\n")
        self.assertEqual(lieux, [("guide.md", 7, "direction")])

    def test_traduction_de_paire_laissee_a_la_comparaison_de_paire(self):
        # Une traduction qui vise la version anglaise est l'affaire de la paire (« lien non basculé ») :
        # la passe par document ne la compte pas une seconde fois.
        lieux, _ = self.juger(guide__fr__md=self.fichiers["guide.fr.md"].replace("(carte.fr.md#carte)", "(carte.md#map)"))
        self.assertEqual(lieux, [])

    def test_document_sans_paire_a_la_langue_indecise_non_juge_sur_la_direction(self):
        lieux, _ = self.juger(journal__md="# Journal\n\nVoir [la carte](carte.md#map).\n")
        self.assertEqual(lieux, [])


class LiensReplies(unittest.TestCase):
    def test_texte_de_lien_sur_trois_lignes_et_plus(self):
        for n in (2, 3, 5):
            texte = "Voir [le\n" + "grand\n" * (n - 1) + "guide](Y.md) puis la suite.\n"
            self.assertEqual(pdl.analyser(texte, "x.md").liens, [(1, "Y.md")], n)

    def test_texte_de_lien_replie_dans_une_citation(self):
        texte = "> Voir [le\n> grand\n> guide](Y.md) ici.\n"
        self.assertEqual(pdl.analyser(texte, "x.md").liens, [(1, "Y.md")])

    def test_la_fin_du_paragraphe_arrete_la_jointure(self):
        texte = "Voir [le\ngrand\n\nguide](Y.md) ici.\n"
        self.assertEqual(pdl.analyser(texte, "x.md").liens, [])


class Convention(unittest.TestCase):
    def test_suffixes(self):
        c = pdl.Convention()
        self.assertTrue(c.est_original("docs/X.md"))
        self.assertFalse(c.est_original("docs/X.fr.md"))
        self.assertTrue(c.est_traduction("docs/X.fr.md"))
        self.assertEqual(c.traduction_de("docs/X.md"), "docs/X.fr.md")
        self.assertEqual(c.original_de("docs/X.fr.md"), "docs/X.md")
        b = pdl.Convention(".fr", "")
        self.assertTrue(b.est_original("X.fr.md"))
        self.assertFalse(b.est_original("X.md"))
        self.assertTrue(b.est_traduction("X.md"))
        self.assertFalse(b.est_traduction("X.fr.md"))
        self.assertEqual(b.traduction_de("X.fr.md"), "X.md")

    def test_langues_manquantes(self):
        self.assertEqual(pdl.langues_manquantes(["a.md", "a.fr.md", "docs/b.fr.md", "c.md"]),
                         [("docs/b.fr.md", "docs/b.md"), ("c.md", "c.fr.md")])
        self.assertEqual(pdl.langues_manquantes(["a.md", "a.fr.md", "x.sh"]), [])

    def test_suffixes_identiques_refuses(self):
        with self.assertRaises(ValueError):
            pdl.Convention(".fr", ".fr")

    def test_suffixe_mal_forme_refuse(self):
        for mauvais in ("en", ".", ".e n", "../x", ".fr.md"):
            with self.assertRaises(ValueError, msg=mauvais):
                pdl.Convention("", mauvais)
        self.assertEqual(muet(pdl.main, ["--suffixe-traduction", "en"])[0], 2)


def muet(fonction, *args):
    """Appelle `fonction` sorties standard et d'erreur détournées ; rend (résultat, sortie)."""
    import io
    sortie, erreur = io.StringIO(), io.StringIO()
    anciens = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = sortie, erreur
    try:
        return fonction(*args), sortie.getvalue() + erreur.getvalue()
    finally:
        sys.stdout, sys.stderr = anciens


class CodeDeSortie(unittest.TestCase):
    """main() : 0 sans écart, 1 dès qu'un écart est nommé, 2 sans écart quand quelque chose n'a pas été lu."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name
        for nom, texte in (("carte.md", CARTE), ("carte.fr.md", CARTE_EN), ("schema.md", "# x\n"),
                           ("guide.md", ORIGINAL), ("guide.fr.md", TRADUCTION)):
            with open(os.path.join(self.racine, nom), "w", encoding="utf-8") as f:
                f.write(texte)

    def tearDown(self):
        self._tmp.cleanup()

    def main(self, *args):
        return muet(pdl.main, ["--racine", self.racine, *args])

    def test_paire_juste_rend_0(self):
        rc, _ = self.main("--paire", "guide.md", "guide.fr.md")
        self.assertEqual(rc, 0)

    def test_paire_avec_ecart_rend_1_et_le_nomme(self):
        with open(os.path.join(self.racine, "guide.fr.md"), "w", encoding="utf-8") as f:
            f.write(TRADUCTION.replace("### Detail\n", ""))
        rc, sortie = self.main("--paire", "guide.md", "guide.fr.md")
        self.assertEqual(rc, 1)
        self.assertIn("guide.md:20: [titres]", sortie)

    def test_fichier_absent_rend_2(self):
        rc, sortie = self.main("--paire", "guide.md", "absent.fr.md")
        self.assertEqual(rc, 2)
        self.assertIn("rien comparé", sortie)

    def suivre(self, *fichiers):
        subprocess.run(["git", "init", "-q", self.racine], check=True)
        subprocess.run(["git", "-C", self.racine, "add", "--", *fichiers], check=True)

    def ecrire(self, nom, contenu):
        mode = "wb" if isinstance(contenu, bytes) else "w"
        with open(os.path.join(self.racine, nom), mode,
                  **({} if isinstance(contenu, bytes) else {"encoding": "utf-8"})) as f:
            f.write(contenu)

    def test_illisible_puis_ecart_rend_1_et_nomme_les_deux(self):
        # `autre` se lit avant `guide` : la paire illisible n'arrête pas la comparaison, et l'écart
        # trouvé ensuite est imprimé ; une violation ne se lit pas comme « rien mesuré ».
        self.ecrire("autre.md", "# Autre\n")
        self.ecrire("autre.fr.md", "# Autre évalué\n".encode("latin-1"))
        self.ecrire("guide.fr.md", TRADUCTION.replace("### Detail\n", ""))
        self.suivre("autre.md", "autre.fr.md", "guide.md", "guide.fr.md")
        rc, sortie = self.main()
        self.assertEqual(rc, 1)
        self.assertIn("guide.md:20: [titres]", sortie)
        self.assertIn("autre.fr.md", sortie)
        self.assertIn("illisible", sortie)

    def test_illisible_sans_ecart_rend_2_et_le_nomme(self):
        self.ecrire("autre.md", "# Autre\n")
        self.ecrire("autre.fr.md", "# Autre évalué\n".encode("latin-1"))
        self.suivre("autre.md", "autre.fr.md", "guide.md", "guide.fr.md")
        rc, sortie = self.main()
        self.assertEqual(rc, 2)
        self.assertIn("autre.fr.md", sortie)
        self.assertIn("illisible", sortie)
        self.assertIn("1 paire(s) comparée(s), 0 écart(s)", sortie)

    def test_fichier_hors_utf8_rend_2(self):
        with open(os.path.join(self.racine, "guide.fr.md"), "wb") as f:
            f.write("# Guide évalué\n".encode("latin-1"))
        rc, sortie = self.main("--paire", "guide.md", "guide.fr.md")
        self.assertEqual(rc, 2)
        self.assertIn("rien comparé", sortie)

    def test_selecteur_absent_rend_1_et_le_nomme(self):
        self.ecrire("guide.fr.md", TRADUCTION.replace(SELECTEUR + "\n\n", ""))
        rc, sortie = self.main("--paire", "guide.md", "guide.fr.md")
        self.assertEqual(rc, 1)
        self.assertIn("guide.fr.md:3: [sélecteur] sélecteur de langue absent", sortie)

    def test_ancre_fausse_rend_1_et_la_nomme(self):
        self.ecrire("guide.fr.md", TRADUCTION.replace("#subsystems", "#subsystem"))
        rc, sortie = self.main("--paire", "guide.md", "guide.fr.md")
        self.assertEqual(rc, 1)
        self.assertIn("guide.fr.md:14: [ancres] ancre « #subsystem »", sortie)

    def test_fichier_vise_par_une_ancre_illisible_rend_2(self):
        # Une ancre qu'on n'a pas pu chercher n'est ni juste ni fausse : rien ne prouve la parité.
        self.ecrire("latin.md", "# Évalué\n".encode("latin-1"))
        self.ecrire("guide.md", ORIGINAL + "\nVoir [l](latin.md#x).\n")
        self.ecrire("guide.fr.md", TRADUCTION + "\nSee [l](latin.md#x).\n")
        rc, sortie = self.main("--paire", "guide.md", "guide.fr.md")
        self.assertEqual(rc, 2)
        self.assertIn("latin.md", sortie)
        self.assertIn("illisible", sortie)

    def test_fichier_vise_illisible_ne_tait_pas_les_ecarts_de_la_paire(self):
        # Les écarts déjà trouvés dans la paire restent imprimés et rendent 1 ; la paire est nommée
        # comme lue en partie, pas comme « aucun écart ».
        self.ecrire("latin.md", "# Évalué\n".encode("latin-1"))
        self.ecrire("guide.md", ORIGINAL + "\nVoir [l](latin.md#x).\n")
        self.ecrire("guide.fr.md", TRADUCTION.replace("### Detail\n", "") + "\nSee [l](latin.md#x).\n")
        rc, sortie = self.main("--paire", "guide.md", "guide.fr.md")
        self.assertEqual(rc, 1)
        self.assertIn("guide.md:20: [titres]", sortie)
        self.assertIn("latin.md", sortie)
        self.assertIn("lue en partie", sortie)
        self.assertNotIn("aucun écart", sortie)

    def test_depot_illisible_rend_2_meme_en_inventaire(self):
        # `racine` n'est pas un dépôt git : ls-files échoue, ce n'est pas une liste vide.
        self.assertIsNone(pdl.documents_suivis(self.racine))
        for args in ((), ("--inventaire",), ("--inventaire", "--strict")):
            rc, _ = self.main(*args)
            self.assertEqual(rc, 2, args)

    def test_inventaire_sur_zero_document_rend_2(self):
        subprocess.run(["git", "init", "-q", self.racine], check=True)
        for args in (("--inventaire",), ("--inventaire", "--strict")):
            rc, sortie = self.main(*args)
            self.assertEqual(rc, 2, args)
            self.assertIn("aucun document suivi", sortie)


class Inventaire(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.racine = self._tmp.name
        selecteur = "# x\n\n[English](A.md) | [Français](A.fr.md)\n"
        for nom in ("A.md", "A.fr.md", "B.md", "docs/C.md", "D.fr.md", "S.md"):
            chemin = os.path.join(self.racine, nom)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as f:
                f.write(selecteur if nom.startswith("A.") else "# x\n")
        subprocess.run(["git", "init", "-q", self.racine], check=True)
        self.suivre("A.md", "A.fr.md", "B.md", "docs/C.md", "D.fr.md", "S.md")
        # `S.md` est déclaré en une seule langue, avec sa raison : ce n'est pas un écart.
        self.seules = mock.patch.dict(pdl.UNE_SEULE_LANGUE, {"S.md": "tenu en une langue"}, clear=True)
        self.seules.start()

    def tearDown(self):
        self.seules.stop()
        self._tmp.cleanup()

    def suivre(self, *fichiers):
        subprocess.run(["git", "-C", self.racine, "add", "--", *fichiers], check=True)

    def test_liste_sans_rougir_puis_rougit_en_strict(self):
        documents = pdl.documents_suivis(self.racine)
        sans, orphelines, perimees = pdl.inventaire(documents, pdl.Convention())
        self.assertEqual(sans, ["B.md", "docs/C.md"])
        self.assertEqual(orphelines, ["D.fr.md"])
        self.assertEqual(perimees, [])
        attendu = ("B.md: sans traduction (attendue : B.fr.md), et absent de UNE_SEULE_LANGUE\n"
                   "docs/C.md: sans traduction (attendue : docs/C.fr.md), et absent de UNE_SEULE_LANGUE\n"
                   "D.fr.md: traduction sans original (attendu : D.md)\n"
                   "1 paire(s), 1 document(s) en une seule langue déclarés, 3 écart(s) (2 document(s) "
                   "sans traduction, 1 traduction(s) sans original, 0 entrée(s) périmée(s)), "
                   "sur 6 documents suivis\n")
        rc, sortie = muet(pdl.main, ["--racine", self.racine, "--inventaire"])
        self.assertEqual((rc, sortie), (0, attendu))
        rc, sortie = muet(pdl.main, ["--racine", self.racine, "--inventaire", "--strict"])
        self.assertEqual((rc, sortie), (1, attendu))
        self.assertEqual(muet(pdl.main, ["--racine", self.racine])[0], 0)

    def retirer(self, *fichiers):
        for nom in fichiers:
            os.remove(os.path.join(self.racine, nom))
        subprocess.run(["git", "-C", self.racine, "rm", "-q", "--cached", "--", *fichiers], check=True)

    def test_inventaire_juste_rend_0_en_strict(self):
        self.retirer("B.md", "docs/C.md", "D.fr.md")
        rc, sortie = muet(pdl.main, ["--racine", self.racine, "--inventaire", "--strict"])
        self.assertEqual(rc, 0, sortie)
        self.assertIn("1 paire(s), 1 document(s) en une seule langue déclarés, 0 écart(s)", sortie)

    def test_entree_qui_a_retrouve_sa_paire_est_un_ecart(self):
        self.retirer("B.md", "docs/C.md", "D.fr.md")
        with open(os.path.join(self.racine, "S.fr.md"), "w", encoding="utf-8") as f:
            f.write("# x\n")
        self.suivre("S.fr.md")
        documents = pdl.documents_suivis(self.racine)
        self.assertEqual(pdl.inventaire(documents, pdl.Convention())[2],
                         [("S.md", "a retrouvé sa traduction S.fr.md")])
        rc, sortie = muet(pdl.main, ["--racine", self.racine, "--inventaire", "--strict"])
        self.assertEqual(rc, 1)
        self.assertIn("S.md: entrée périmée de UNE_SEULE_LANGUE (tenu en une langue) : a retrouvé sa "
                      "traduction S.fr.md", sortie)

    def test_entree_qui_ne_designe_plus_un_document_suivi_est_un_ecart(self):
        self.retirer("B.md", "docs/C.md", "D.fr.md", "S.md")
        documents = pdl.documents_suivis(self.racine)
        self.assertEqual(pdl.inventaire(documents, pdl.Convention())[2],
                         [("S.md", "n'est plus un document suivi")])
        self.assertEqual(muet(pdl.main, ["--racine", self.racine, "--inventaire", "--strict"])[0], 1)

    def test_document_hors_de_l_ensemble_sans_paire_est_un_ecart(self):
        # Le même `S.md`, retiré de l'ensemble : il redevient un document sans traduction.
        self.retirer("B.md", "docs/C.md", "D.fr.md")
        del pdl.UNE_SEULE_LANGUE["S.md"]
        documents = pdl.documents_suivis(self.racine)
        self.assertEqual(pdl.inventaire(documents, pdl.Convention())[0], ["S.md"])
        self.assertEqual(muet(pdl.main, ["--racine", self.racine, "--inventaire", "--strict"])[0], 1)

    def test_entree_sans_raison_est_un_ecart(self):
        self.retirer("B.md", "docs/C.md", "D.fr.md")
        documents = pdl.documents_suivis(self.racine)
        for raison in ("", "   ", None):
            pdl.UNE_SEULE_LANGUE["S.md"] = raison
            self.assertEqual([d for d, _ in pdl.inventaire(documents, pdl.Convention())[2]], ["S.md"], raison)
            rc, sortie = muet(pdl.main, ["--racine", self.racine, "--inventaire", "--strict"])
            self.assertEqual(rc, 1, raison)
            self.assertIn("n'a aucune raison écrite", sortie)

    def test_entree_qui_n_est_pas_un_original_est_un_ecart(self):
        # Une traduction inscrite comme document en une seule langue : la convention ne la lit pas
        # comme un original, l'entrée ne désigne rien qui puisse rester seul.
        self.retirer("B.md", "docs/C.md")
        pdl.UNE_SEULE_LANGUE["D.fr.md"] = "une traduction prise pour un original"
        documents = pdl.documents_suivis(self.racine)
        self.assertIn(("D.fr.md", "n'est pas un original sous la convention"),
                      pdl.inventaire(documents, pdl.Convention())[2])

    def test_ensemble_reel_nomme_ses_raisons(self):
        # Le document en une seule langue du dépôt, avec une raison écrite.
        self.seules.stop()
        try:
            self.assertEqual(sorted(pdl.UNE_SEULE_LANGUE), [
                "bench/detection/RESULTS_2026-08-10.md",
                "bench/detection/RESULTS_2026-08-11-r5.md",
                "bench/detection/RESULTS_2026-08-11.md",
            ])
            self.assertTrue(all(r.strip() for r in pdl.UNE_SEULE_LANGUE.values()))
        finally:
            self.seules.start()

    def test_aucune_paire_ne_rend_pas_vert(self):
        self.retirer("A.fr.md")
        with open(os.devnull, "w") as nul:
            erreur, sys.stderr = sys.stderr, nul
            try:
                self.assertEqual(pdl.main(["--racine", self.racine]), 2)
            finally:
                sys.stderr = erreur


if __name__ == "__main__":
    unittest.main()

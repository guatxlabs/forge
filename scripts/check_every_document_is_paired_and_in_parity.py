#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# ORIGINE : repris le 2026-11-24 de l'outillage des deux langues du dépôt Plume (guatxlabs/plume,
# `.github/scripts/check_every_document_is_paired_and_in_parity.py`), même licence AGPL-3.0-or-later. Seuls changent ici :
# la racine (`scripts/` est à un niveau sous la racine) et le plancher de paires, relevé sur forge.

"""Chaque document suivi existe dans ses deux langues, et sa traduction garde les faits de l'original.

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Les documents de ce dépôt existent en anglais d'abord (`X.md`) et en français (`X.fr.md`). Rien ne
liait les deux fichiers : une section ajoutée d'un côté, une commande corrigée dans une seule langue,
un lien qui vise encore la version anglaise depuis la française, ou un document neuf écrit dans une
seule langue laissent chacun deux textes lisibles, dont l'un est faux ou absent, sans qu'aucun vert ne
bouge. `parite_des_langues.py` sait le mesurer ; tant qu'il se jouait à la main, il ne refusait rien.

CE QUI EST JUGÉ
---------------
- L'INVENTAIRE, en strict : tout document suivi a sa paire, sauf ceux de l'ensemble nommé
  `UNE_SEULE_LANGUE` de `parite_des_langues.py`, chacun avec sa raison ; une traduction sans original
  est un écart ; une entrée de l'ensemble qui a retrouvé sa paire, ou qui ne désigne plus un document
  suivi, en est un aussi.
- LA PARITÉ de chaque paire : titres, blocs de code et commandes, tableaux, cibles de liens (un lien
  vers `Y.md` vise `Y.fr.md` côté français quand ce fichier existe), sélecteur de langue à sa forme
  exacte, langue de la prose de chaque fichier, ancres de la traduction, nombres, identifiants entre
  accents graves — tout ce que l'outil compare.
- CE QUE CHAQUE DOCUMENT JUGE SEUL : la direction de ses liens (un document anglais vise la version
  anglaise, un document français la française ; le sélecteur seul fait exception) et les ancres qu'il
  vise, originaux et documents sans paire compris.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Avant de lire l'arbre, la garde joue sa propre décision sur de petits dépôts fabriqués : une paire
juste avec un document déclaré en une seule langue (vert), puis un document sans paire, une paire au
lien divergent, une entrée périmée de l'ensemble et une entrée qui ne désigne plus rien (rouge chacun),
et un dépôt sans document (refus). Une décision qui ne rend pas le code attendu fait refuser la garde :
un vert rendu par un instrument qui ne voit plus un écart ne vaudrait rien. Elle exige enfin un
PLANCHER de paires dans l'arbre réel : une découverte cassée ne passe pas pour un corpus juste.

CODES DE SORTIE
---------------
`0` inventaire et parité sans écart ; `1` un écart nommé, même si une autre paire n'a pas pu être lue ;
`2` rien de probant : instrument faux, dépôt illisible, paires sous le plancher, ou paire illisible
sans aucun écart ailleurs.

CE QU'ELLE NE TIENT PAS
-----------------------
Elle ne juge pas la traduction elle-même — le sens, le style, une phrase restée dans l'autre langue :
seulement les faits que la langue ne change pas, avec les limites que `parite_des_langues.py` écrit
dans son en-tête. Elle ne dit pas non plus que les deux langues ont changé DANS LE MÊME COMMIT : elle
juge l'arbre, et un arbre où une seule langue a bougé ne rougit que si un fait comparé diverge.
"""
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ICI)
import parite_des_langues as pdl  # noqa: E402

RACINE = os.path.realpath(os.path.join(ICI, ".."))
ETIQUETTE = "[parite-des-langues]"

# Plancher de paires lues dans l'arbre réel. Relevé à l'écriture de la garde : 54 paires.
MIN_PAIRES = 50


def juger(racine, une_seule_langue, min_paires=1):
    """(code, lignes à imprimer) pour le dépôt `racine`. Toute la décision est ici : les témoins la jouent
    telle quelle sur leurs dépôts fabriqués."""
    convention = pdl.Convention()
    documents = pdl.documents_suivis(racine)
    if documents is None:
        return 2, [f"{ETIQUETTE} REFUSE DE CONCLURE — `git ls-files` a échoué sous {racine} : rien n'est lu."]
    if not documents:
        return 2, [f"{ETIQUETTE} REFUSE DE CONCLURE — aucun document suivi : rien n'est inventorié."]
    lignes, ecarts = [], 0
    sans_traduction, orphelines, perimees = pdl.inventaire(documents, convention, une_seule_langue)
    for d in sans_traduction:
        lignes.append(f"::error file={d}::{d} : document suivi sans sa traduction "
                      f"{convention.traduction_de(d)}, et absent de UNE_SEULE_LANGUE")
    for d in orphelines:
        lignes.append(f"::error file={d}::{d} : traduction sans son original {convention.original_de(d)}")
    for d, pourquoi in perimees:
        lignes.append(f"::error file={d}::{d} : entrée périmée de UNE_SEULE_LANGUE "
                      f"({une_seule_langue[d]}) : {pourquoi}")
    ecarts += len(sans_traduction) + len(orphelines) + len(perimees)

    paires = pdl.paires(documents, convention)
    illisibles = []
    for original, traduction in paires:
        try:
            trouves = pdl.comparer_fichiers(racine, original, traduction, convention)
        except pdl.Illisible as e:
            illisibles.append(f"{original} / {traduction} : {e}")
            trouves = e.ecarts or []
        for e in trouves:
            lignes.append(f"::error file={e.fichier},line={e.ligne}::{e}")
        ecarts += len(trouves)
    seuls, seuls_illisibles = pdl.comparer_documents(racine, documents, convention)
    for e in seuls:
        lignes.append(f"::error file={e.fichier},line={e.ligne}::{e}")
    ecarts += len(seuls)
    illisibles += seuls_illisibles
    for i in illisibles:
        lignes.append(f"{ETIQUETTE} lue en partie ou illisible : {i}")

    bilan = (f"{len(paires)} paire(s), {len(set(une_seule_langue) & set(documents))} document(s) en une "
             f"seule langue déclaré(s), sur {len(documents)} documents suivis")
    if ecarts:
        return 1, lignes + [f"{ETIQUETTE} ÉCHEC — {ecarts} écart(s) ; {bilan}. Une modification d'un document "
                            f"touche ses deux langues ; un document en une seule langue s'inscrit dans "
                            f"UNE_SEULE_LANGUE avec sa raison."]
    if illisibles:
        return 2, lignes + [f"{ETIQUETTE} REFUSE DE CONCLURE — aucun écart, mais une paire au moins n'a pas "
                            f"été lue en entier ; {bilan}."]
    if len(paires) < min_paires:
        return 2, lignes + [f"{ETIQUETTE} REFUSE DE CONCLURE — {len(paires)} paire(s) lue(s), plancher "
                            f"{min_paires} : la découverte est cassée, ou des paires ont disparu (baisser "
                            f"MIN_PAIRES depuis son propre compte, jamais pour faire passer)."]
    return 0, lignes + [f"{ETIQUETTE} OK — {bilan} : inventaire et parité sans écart."]


SELECTEUR = "[English]({n}.md) | [Français]({n}.fr.md)"
# Une prose assez longue pour que sa langue se lise (plus de `MIN_MOTS_OUTILS` mots-outils).
PROSE = {
    "fr": ("\nLe capteur lit la file et le journal, puis il les envoie au central pour que la règle les juge "
           "dans la fenêtre qui est la sienne ; ce n'est pas une copie, et elle ne garde rien sur le disque "
           "quand le central est joignable par le réseau.\n"),
    "en": ("\nThe sensor reads the queue and the log, then it sends them to the central so that the rule can "
           "judge them in the window that is its own; this is not a copy, and it keeps nothing on the disk "
           "when the central is reachable by the network.\n"),
}


def fabriquer(racine, fichiers):
    """Un dépôt git où chaque fichier de `fichiers` (chemin -> texte) est écrit et suivi."""
    for chemin, texte in fichiers.items():
        complet = os.path.join(racine, chemin)
        os.makedirs(os.path.dirname(complet), exist_ok=True)
        with open(complet, "w", encoding="utf-8") as f:
            f.write(texte)
    subprocess.run(["git", "init", "-q", racine], check=True)
    if fichiers:
        subprocess.run(["git", "-C", racine, "add", "--", *fichiers], check=True)


def corpus_juste():
    guide = "# Guide\n\n" + SELECTEUR.format(n="guide") + "\n\nSee [the map](carte.md) and [the log](JOURNAL.md).\n"
    guide_fr = "# Guide\n\n" + SELECTEUR.format(n="guide") + "\n\nVoir [la carte](carte.fr.md) et [le journal](JOURNAL.md).\n"
    carte = "# Map\n\n" + SELECTEUR.format(n="carte") + "\n" + PROSE["en"]
    carte_fr = "# Carte\n\n" + SELECTEUR.format(n="carte") + "\n" + PROSE["fr"]
    # Le document en une seule langue porte déjà le sélecteur de sa paire future : quand le témoin lui
    # rend sa traduction, la paire est juste, et la seule faute qui reste est l'entrée périmée.
    journal = "# Journal\n\n" + SELECTEUR.format(n="JOURNAL") + "\n"
    return {"guide.md": guide, "guide.fr.md": guide_fr, "carte.md": carte, "carte.fr.md": carte_fr,
            "JOURNAL.md": journal}


def valider_instrument():
    """TÉMOINS : la décision de `juger`, jouée sur des dépôts fabriqués ; rend la liste des échecs.

    Chaque témoin exige son code ET la faute qui le fonde (un fragment de la ligne qui la nomme) : un
    rouge rendu pour une autre raison que celle mise en scène laisserait la règle visée sans témoin."""
    seules = {"JOURNAL.md": "tenu en une seule langue"}
    juste = corpus_juste()
    cas = [
        ("paire juste et document déclaré en une seule langue", juste, seules, 0, "OK", 0),
        ("document sans paire", dict(juste, **{"docs/neuf.md": "# Neuf\n"}), seules, 1,
         "docs/neuf.md : document suivi sans sa traduction", 1),
        ("traduction sans original", dict(juste, **{"docs/seule.fr.md": "# Seule\n"}), seules, 1,
         "docs/seule.fr.md : traduction sans son original", 1),
        ("paire au lien divergent", dict(juste, **{"guide.fr.md": juste["guide.fr.md"].replace(
            "(carte.fr.md)", "(carte.md)")}), seules, 1, "[liens] lien non basculé", 1),
        # Le sélecteur porte deux liens : leur absence est nommée aussi par la famille des liens.
        ("paire au sélecteur absent", dict(juste, **{"carte.fr.md": "# Carte\n"}), seules, 1,
         "[sélecteur] sélecteur de langue absent", 3),
        # La paire retrouvée est juste, et la traduction du guide vise la version française du journal :
        # l'entrée périmée est la seule faute.
        ("entrée périmée : le document a retrouvé sa paire",
         dict(juste, **{"JOURNAL.fr.md": juste["JOURNAL.md"],
                        "guide.fr.md": juste["guide.fr.md"].replace("(JOURNAL.md)", "(JOURNAL.fr.md)")}), seules, 1,
         "JOURNAL.md : entrée périmée de UNE_SEULE_LANGUE (tenu en une seule langue) : a retrouvé sa traduction", 1),
        ("entrée périmée : le document n'est plus suivi",
         {k: v for k, v in juste.items() if k != "JOURNAL.md"}, seules, 1,
         "JOURNAL.md : entrée périmée de UNE_SEULE_LANGUE (tenu en une seule langue) : n'est plus un document suivi", 1),
        ("document en une seule langue hors de l'ensemble", juste, {}, 1,
         "JOURNAL.md : document suivi sans sa traduction", 1),
        ("entrée sans raison écrite", juste, {"JOURNAL.md": ""}, 1,
         "JOURNAL.md : entrée périmée de UNE_SEULE_LANGUE () : n'a aucune raison écrite", 1),
        ("original anglais qui vise la version française", dict(juste, **{"guide.md": juste["guide.md"].replace(
            "(carte.md)", "(carte.fr.md)")}), seules, 1, "[direction] document anglais qui vise la version française", 1),
        ("ancre absente dans un original", dict(juste, **{"guide.md": juste["guide.md"].replace(
            "(carte.md)", "(carte.md#mapp)"), "guide.fr.md": juste["guide.fr.md"].replace(
            "(carte.fr.md)", "(carte.fr.md#carte)")}), seules, 1, "[ancres] ancre « #mapp »", 1),
        ("sélecteur aux libellés inversés", dict(juste, **{n: juste[n].replace(
            SELECTEUR.format(n="carte"), "[Français](carte.md) | [English](carte.fr.md)")
            for n in ("carte.md", "carte.fr.md")}), seules, 1, "[sélecteur] forme du sélecteur", 2),
        ("paire intervertie sans lien croisé", dict(juste, **{"carte.md": juste["carte.fr.md"] + PROSE["fr"],
                                                             "carte.fr.md": juste["carte.md"] + PROSE["en"]}),
         seules, 1, "[langue] la prose n'est pas en anglais", 2),
        ("dépôt sans document", {}, seules, 2, "aucun document suivi", 0),
    ]
    echecs = []
    for nom, fichiers, une_seule_langue, attendu, faute, fautes in cas:
        with tempfile.TemporaryDirectory() as racine:
            # Le lien vers JOURNAL.md vise un fichier absent dans le cas « n'est plus suivi » : sans
            # incidence, une cible absente reste telle quelle des deux côtés.
            fabriquer(racine, fichiers)
            code, lignes = juger(racine, une_seule_langue)
        if code != attendu or not any(faute in ligne for ligne in lignes):
            echecs.append(f"témoin « {nom} » : code {code}, attendu {attendu} avec « {faute} »"
                          + (f" — {lignes[-1]}" if lignes else ""))
        elif sum(1 for ligne in lignes if ligne.startswith("::error")) != fautes:
            echecs.append(f"témoin « {nom} » : {sum(1 for l in lignes if l.startswith('::error'))} faute(s) "
                          f"nommée(s), {fautes} attendue(s) — le témoin rougit aussi pour autre chose")
    with tempfile.TemporaryDirectory() as dehors:
        code, _ = juger(dehors, seules)
    if code != 2:
        echecs.append(f"témoin « dépôt illisible » : code {code}, attendu 2")
    return echecs


def main():
    echecs = valider_instrument()
    if echecs:
        print(f"{ETIQUETTE} REFUSE DE CONCLURE — l'INSTRUMENT est faux, aucun verdict sur l'arbre :")
        for e in echecs:
            print(f"    - {e}")
        return 2
    code, lignes = juger(RACINE, pdl.UNE_SEULE_LANGUE, MIN_PAIRES)
    for ligne in lignes:
        print(ligne)
    return code


if __name__ == "__main__":
    sys.exit(main())

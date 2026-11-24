#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# ORIGINE : repris le 2026-11-24 de l'outillage des deux langues du dépôt Plume (guatxlabs/plume,
# `.github/scripts/parite_des_langues.py`), même licence AGPL-3.0-or-later. Seuls changent ici :
# l'ensemble `UNE_SEULE_LANGUE` (les documents de forge tenus en une seule langue) et la
# racine par défaut (`scripts/` est à un niveau sous la racine, et non deux).

"""Parité entre un document et sa traduction : ce que la langue ne doit pas changer.

LE DÉFAUT VISÉ
--------------
Une traduction se relit pour son style ; ce qu'elle perd en route ne se voit pas à la relecture. Un
titre sauté, une commande recopiée avec une option en moins, un chiffre retouché, un lien qui vise
encore le document anglais alors que sa version française existe : chacun laisse un texte lisible,
fluide, et faux. Ce sont des faits que la langue ne change pas, donc des faits qu'une machine peut
comparer sans juger la traduction elle-même.

CE QUI EST COMPARÉ, PAIRE PAR PAIRE
-----------------------------------
- les TITRES : leur nombre et la suite de leurs niveaux ;
- les BLOCS DE CODE : leur nombre, et dans chacun les lignes de commande hors commentaires (une ligne
  qui commence par `#` ou `//` est un commentaire, comme la fin de ligne qui suit ` # ` ou ` // ` :
  c'est la part qu'une traduction a le droit de réécrire) ;
- les TABLEAUX : leur nombre et le nombre de lignes de chacun ;
- les CIBLES DE LIENS : un lien vers `Y.md` doit viser `Y.fr.md` côté traduction quand ce fichier
  existe, et rester tel quel sinon ; l'ancre (`#…`) est retirée avant comparaison, car elle dérive
  d'un titre, et un titre traduit change d'ancre. La cible se résout depuis le dossier du document,
  ou depuis la racine quand elle commence par `/`. Un lien vers le document lui-même ou vers sa
  traduction ne bascule pas : c'est celui du sélecteur de langue. Comme en CommonMark, le texte d'un
  lien peut passer à la ligne dans un paragraphe : le lien est lu entier, rapporté à la ligne où il
  s'ouvre ;
- le SÉLECTEUR DE LANGUE : la première ligne non vide sous le premier titre de niveau 1, la même des
  deux côtés, faite d'un lien vers l'original puis d'un lien vers la traduction et de séparateurs
  seulement, à la FORME EXACTE `[English](X.md) | [Français](X.fr.md)`, libellés compris, quand la
  convention nomme les deux langues. Absent d'un côté ou des deux, inversé, visant un autre fichier,
  d'une autre forme, ou différent d'un côté à l'autre : écart nommé ;
- la LANGUE DE LA PROSE de chaque fichier : ses mots-outils français et anglais (`MOTS_FRANCAIS`,
  `MOTS_ANGLAIS`), lus dans le texte courant hors blocs, segments de code, cibles et URL. La part des
  mots-outils de l'autre langue doit rester sous `PART_ETRANGERE_MAX` ; un fichier qui en porte moins
  de `MIN_MOTS_OUTILS` (un document presque tout en code) n'est pas jugé sur sa langue. Une paire
  intervertie, texte français dans `X.md`, rougit ainsi des deux côtés sans attendre un lien croisé ;
- les ANCRES DE LA TRADUCTION : un lien interne de la traduction dont l'ancre vise un document
  Markdown de l'arbre (elle-même comprise, pour `#…` seul) doit désigner un titre de ce fichier,
  par son slug GitHub — texte affiché en minuscules, ponctuation retirée, espaces en tirets, accents
  conservés, `-1`, `-2`… pour un titre en double — ou un `id`/`name` HTML. Une ancre restée sur le
  titre de l'original est nommée comme telle. Les ancres de l'original ne sont pas jugées : elles
  ne relèvent pas de la parité ;
- l'ENSEMBLE DES NOMBRES du texte courant, lus comme des suites de chiffres : `2,7` et `2.7`, ou
  `4 812 337` et `4,812,337`, donnent les mêmes suites, si bien que la typographie de chaque langue
  n'accuse rien ;
- l'ENSEMBLE DES IDENTIFIANTS ENTRE ACCENTS GRAVES. Comme en CommonMark, un segment peut passer à
  la ligne dans un paragraphe, la fin de ligne y valant une espace : il est lu comme UN segment, où
  qu'il soit replié de chaque côté.

Chaque écart est nommé par `fichier:ligne`, côté original quand il manque quelque chose à la
traduction, côté traduction quand elle porte quelque chose en trop.

CE QUE CHAQUE DOCUMENT JUGE SEUL
--------------------------------
Sur tout l'arbre suivi (pas sous `--paire`), chaque original de paire et chaque document sans paire :
- la DIRECTION de ses liens : un lien vers un document qui existe dans les deux langues vise la
  version de SA langue — celle de l'original vient de la convention, celle d'un document sans paire
  de sa prose (pas jugée quand elle est indécise). La ligne du sélecteur est la seule exception ;
- les ANCRES qu'il vise, dans un document Markdown de l'arbre (lui-même compris), comme pour la
  traduction ci-dessus.
La traduction d'une paire n'est pas relue ici : sa comparaison à l'original la tient déjà.

LA CONVENTION DE SUFFIXE EST UN PARAMÈTRE
-----------------------------------------
L'anglais d'abord : l'original est `X.md` (anglais) et la traduction `X.fr.md`. L'outil ne code pas
la convention en dur : `--suffixe-original ""` et `--suffixe-traduction .fr` sont les défauts, et
deux autres suffixes de la forme `.xx` se passent de la même façon.

LES DOCUMENTS EN UNE SEULE LANGUE SONT UN ENSEMBLE NOMMÉ
--------------------------------------------------------
`UNE_SEULE_LANGUE` nomme chaque document suivi qui n'a pas de traduction, avec sa raison écrite à
côté. Un document suivi sans sa paire et hors de cet ensemble est un écart ; une entrée de
l'ensemble sans raison écrite, qui a retrouvé sa paire, ou qui ne désigne plus un document suivi, en
est un aussi : une exception qu'on ne retire pas devient une trappe où l'on range ce qu'on n'a pas
traduit.

DEUX MODES
----------
- comparaison (défaut) : toutes les paires suivies par git, ou une seule avec `--paire ORIGINAL
  TRADUCTION`. Toutes les paires lisibles sont comparées et tous les écarts imprimés ; une paire
  illisible (fichier absent ou qui n'est pas de l'UTF-8) est nommée et n'arrête pas les autres.
  Code 1 dès qu'un écart est nommé, même si une autre paire n'a pas pu être lue : une violation
  trouvée ne se lit pas comme « rien mesuré ». Code 2 quand il n'y a aucun écart et que quelque
  chose n'a pas été lu (aucune paire, dépôt illisible, paire illisible) : un vert sur ce qui n'a pas
  été lu ne prouverait rien. Code 0 sinon. Un fichier visé par une ancre de la traduction et qui
  n'est pas de l'UTF-8 laisse la paire lue en partie : une ancre qu'on n'a pas pu chercher n'est ni
  juste ni fausse, elle n'est pas jugée, la paire est nommée, et ses autres écarts sont imprimés (code
  1 s'il y en a, 2 sinon).
- `--inventaire` : compte les paires, et liste les écarts de l'inventaire — document suivi sans
  traduction hors de `UNE_SEULE_LANGUE`, traduction sans original, entrée périmée de l'ensemble. Il
  rend 0 tant que `--strict` n'est pas passé ; avec `--strict`, un écart quelconque rend 1. Sur zéro
  document suivi, ou sur un dépôt illisible, il rend 2 dans les deux cas.

L'outil n'est pas lui-même une garde : `check_every_document_is_paired_and_in_parity.py` l'appelle
(inventaire strict, puis comparaison de toutes les paires), et c'est elle qui est câblée.

CE QU'IL NE VOIT PAS
--------------------
Les titres soulignés (`===` / `---` sous une ligne) ne sont pas comptés parmi les titres, seulement
les titres `#` ; leur ancre est tout de même admise. Ce que porte un segment de code replié (et le
reste des lignes qu'il emporte) est rapporté à la ligne où il s'ouvre ; un accent grave que rien ne
ferme avant la fin du paragraphe (ligne vide, titre, clôture, ligne de tableau, puce de liste ; la
clôture et la puce à toute indentation, comme dans une liste imbriquée) est du texte. Le slug suit
le texte affiché d'un titre au plus près sans le rendre vraiment : segments
de code, liens, emphase et balises HTML sont ôtés, pas les entités HTML (`&amp;`). Une ancre dont
seule la casse diffère d'un slug n'est pas accusée : ce que la page fait d'une majuscule n'a pas été
mesuré. Une ancre vers un fichier absent, ou hors de l'arbre, n'est pas jugée. Un
bloc de code indenté de quatre espaces n'est pas un bloc pour lui, seulement les blocs clôturés
(trois accents graves ou trois tildes). Les commentaires HTML ne sont pas rendus, donc pas comparés.
Les autoliens (`<https://…>`), les URL nues et les liens HTML (`<a href>`) ne sont pas comparés comme
cibles, et les nombres d'une URL nue ne sont pas lus : une traduction a le droit de pointer la page
d'une autre langue. Un nombre écrit en toutes lettres échappe à la comparaison des nombres.
L'ensemble est un ENSEMBLE : un nombre cité deux fois d'un côté et une fois de l'autre ne fait pas d'écart.
Un tableau n'est vu que si ses lignes commencent par une barre verticale : `a | b` suivi de `---|---`
n'est pas un tableau pour lui. Dans un bloc, ` # ` ou ` // ` coupe la ligne même entre guillemets :
`grep ' # a'` et `grep ' # b'` donnent la même commande. Une ligne de bloc qui commence par `#` est un
commentaire, sauf `#[`, `#!` et les directives du préprocesseur C (`#include`, `#define`…), qui sont
du code.
"""
import argparse
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import unquote

CLOTURE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
CITATION = re.compile(r"^\s{0,3}(?:>\s?)+")
TITRE = re.compile(r"^\s{0,3}(#{1,6})(?:\s+(.*))?$")
LIGNE_DE_TABLEAU = re.compile(r"^\s*\|")
SEGMENT_DE_CODE = re.compile(r"(`+)(.+?)\1")
SUITE_D_ACCENTS = re.compile(r"`+")
# Ligne qui ne prolonge pas un paragraphe : vide, titre, ligne de tableau, puce de liste (à toute
# indentation : une sous-liste en est une). Une clôture le coupe aussi : voir `ouvre_un_bloc`.
COUPE_LE_PARAGRAPHE = re.compile(r"^\s*$|^\s{0,3}#{1,6}(?:\s|$)|^\s*(?:\||[-*+]\s|\d{1,9}[.)]\s)")
LIEN_EN_LIGNE = re.compile(
    r"!?\[((?:[^\[\]\\]|\\.|\[[^\]]*\])*)\]\(\s*<?([^)\s>]*)>?(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)"
)
# `[^1]: …` est une note de bas de page, pas une définition de lien : son texte est du texte courant.
DEFINITION_DE_LIEN = re.compile(r"^\s{0,3}\[(?!\^)[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
URL_NUE = re.compile(r"<?\b[a-zA-Z][a-zA-Z0-9+.-]*://\S+")
NOMBRE = re.compile(r"\d+")
SCHEMA = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
SOULIGNEMENT = re.compile(r"^\s{0,3}(?:=+|-+)\s*$")
ANCRE_HTML = re.compile(r"<[a-zA-Z][^>]*\s(?:id|name)\s*=\s*[\"']([^\"']+)[\"']")
COMMENTAIRE_FINAL = re.compile(r"\s+(?:#|//)(?:\s.*)?$")
# Lignes qui commencent par `#` sans être des commentaires : attribut Rust, shebang, préprocesseur C.
DIESE_DE_CODE = re.compile(
    r"^#(?:\[|!|(?:include|define|undef|if|ifdef|ifndef|elif|else|endif|pragma|error)\b)")

# Documents suivis tenus en UNE seule langue, chacun avec sa raison. Tout autre document suivi a sa
# paire ; une entrée qui retrouve la sienne, ou qui ne désigne plus un document suivi, est un écart.
# LA LANGUE DE LA PROSE. Des mots-outils sans ambiguïté entre les deux langues (ni « a », ni « en », ni
# « on », ni « de », que l'autre langue emploie aussi ou que les identifiants découpés produisent), lus
# dans le texte courant seulement : hors blocs, segments de code, cibles de liens, URL et commentaires.
MOTS_FRANCAIS = frozenset("le la les des du une est et pour dans qui que pas sur avec ce cette ces sont "
                          "par au aux ne se sa ses son il elle ils mais plus où comme ou être peut sans "
                          "leur tout très aussi donc quand même entre".split())
MOTS_ANGLAIS = frozenset("the and is are of to in for with that this not by it be an as which from can "
                         "when if what its has have was were only does but than then their they there "
                         "these those will would into each any no so at".split())
# Sous ce nombre de mots-outils, la prose est trop courte pour qu'une langue s'en dégage : un document
# presque tout en code n'est pas jugé sur sa langue (il l'est sur tout le reste).
MIN_MOTS_OUTILS = 20
# Part de mots-outils de l'AUTRE langue à partir de laquelle un fichier n'est plus dans la sienne. Mesuré
# à l'écriture : la part étrangère la plus haute d'un fichier juste est sous 0,1 ; un fichier interverti
# la porte au-dessus de 0,9. La marge laisse les citations et les messages servis cités tels quels.
PART_ETRANGERE_MAX = 0.4
WORD = re.compile(r"[a-zà-öø-ÿ]+")
LIBELLES = {"en": "English", "fr": "Français"}
LANGUE_DU_SUFFIXE = {".en": "en", ".fr": "fr"}

UNE_SEULE_LANGUE = {
    "bench/detection/RESULTS_2026-08-10.md":
        "relevé daté du banc de détection, sortie brute de `python3 -m bench.detection.report` "
        "(exécution du 2026-08-10) : une mesure conservée telle quelle ne se réécrit pas, même traduite",
    "bench/detection/RESULTS_2026-08-11.md":
        "relevé daté du banc rejoué en entier après remédiation, sortie brute de "
        "`python3 -m bench.detection.report` (2026-08-11) : référence AVANT/APRÈS conservée telle quelle",
    "bench/detection/RESULTS_2026-08-11-r5.md":
        "relevé daté de la troisième campagne (« r5 », 2026-08-11), sortie brute de "
        "`python3 -m bench.detection.report` : un rapport de banc qui réécrit son texte ne vaut plus "
        "comme référence",
}


@dataclass
class Document:
    chemin: str
    titres: list = field(default_factory=list)       # (ligne, niveau)
    blocs: list = field(default_factory=list)        # (ligne d'ouverture, [(ligne, commande)])
    tableaux: list = field(default_factory=list)     # (première ligne, nombre de lignes)
    liens: list = field(default_factory=list)        # (ligne, cible brute)
    nombres: dict = field(default_factory=dict)      # nombre -> première ligne
    identifiants: dict = field(default_factory=dict)  # contenu entre accents graves -> première ligne
    titre_1: int = 0                                  # ligne du premier titre de niveau 1, 0 sans
    selecteur: tuple = None                           # (ligne, texte, [cibles]) sous ce titre
    ancres: set = field(default_factory=set)          # slugs des titres et `id`/`name` HTML
    mots_fr: int = 0                                  # mots-outils français du texte courant
    mots_en: int = 0                                  # mots-outils anglais du texte courant


@dataclass(frozen=True)
class Ecart:
    fichier: str
    ligne: int
    famille: str
    message: str

    def __str__(self):
        return f"{self.fichier}:{self.ligne}: [{self.famille}] {self.message}"


def commande(ligne):
    """La part d'une ligne de bloc qu'une traduction ne doit pas toucher ; None pour un commentaire."""
    s = ligne.strip()
    if not s or s.startswith("//") or (s.startswith("#") and not DIESE_DE_CODE.match(s)):
        return None
    s = COMMENTAIRE_FINAL.sub("", s)
    return " ".join(s.split()) or None


def retirer_commentaires_html(ligne, dans_commentaire):
    visible = []
    i = 0
    while i < len(ligne):
        if dans_commentaire:
            fin = ligne.find("-->", i)
            if fin < 0:
                return "".join(visible), True
            i = fin + 3
            dans_commentaire = False
        else:
            debut = ligne.find("<!--", i)
            if debut < 0:
                visible.append(ligne[i:])
                break
            visible.append(ligne[i:debut])
            i = debut + 4
            dans_commentaire = True
    return "".join(visible), dans_commentaire


def texte_rendu(titre):
    """Le texte qu'un titre affiche : séquence de clôture `#`, balisage en ligne et balises HTML ôtés,
    contenu des segments de code gardé tel quel."""
    titre = re.sub(r"(?:^|\s+)#+\s*$", "", titre.strip())
    morceaux = []
    for i, part in enumerate(re.split(r"(`+)(.+?)\1", titre)):
        if i % 3 == 1:
            continue
        if i % 3 == 2:
            morceaux.append(part)
            continue
        part = re.sub(r"!?\[((?:[^\[\]\\]|\\.)*)\](?:\([^)]*\)|\[[^\]]*\])", r"\1", part)
        part = re.sub(r"<[^>]*>", "", part)
        part = re.sub(r"\*+|~~|(?<!\w)_+|_+(?!\w)", "", part)
        morceaux.append(re.sub(r"\\(.)", r"\1", part))
    return "".join(morceaux)


def slug(titre):
    """L'ancre que GitHub donne à un titre : texte affiché en minuscules, tout ce qui n'est ni lettre,
    ni chiffre, ni `_`, ni `-`, ni espace retiré, chaque espace changée en tiret. Les accents restent.
    Le suffixe `-1`, `-2`… des titres en double est ajouté par l'appelant."""
    return re.sub(r"[^\w\- ]", "", texte_rendu(titre).lower()).replace(" ", "-")


def ouvre_un_bloc(ligne):
    """La clôture qui ouvre un bloc de code, ou None : trois accents graves ou tildes au moins, à toute
    indentation (un bloc peut vivre dans une puce), sans accent grave dans l'info d'une clôture à
    accents graves (CommonMark : ce serait un segment de code)."""
    m = CLOTURE.match(ligne)
    if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
        return m
    return None


def segment_ouvert(texte, debut=0):
    """Position de la première suite d'accents graves, à partir de `debut`, que rien ne ferme dans
    `texte` (même suite plus loin) ; None quand chaque segment ouvert se ferme."""
    i = debut
    while True:
        m = SUITE_D_ACCENTS.search(texte, i)
        if not m:
            return None
        fin = texte.find(m.group(), m.end())
        if fin < 0:
            return m.start()
        i = fin + len(m.group())


def rejoindre_les_segments(visible, suivantes, dans_commentaire):
    """La ligne `visible` prolongée des lignes de `suivantes` qu'un segment de code y ouvert sans s'y
    fermer emporte : (texte rejoint, lignes absorbées, état de commentaire HTML après elles).

    CommonMark : un segment de code peut passer à la ligne dans un paragraphe, et la fin de ligne y
    vaut une espace. Un segment qu'aucune ligne du paragraphe ne ferme n'en est pas un : ses accents
    graves sont du texte, et la ligne reste seule."""
    debut, absorbees = 0, 0
    while True:
        p = segment_ouvert(visible, debut)
        if p is None or dans_commentaire:
            return visible, absorbees, dans_commentaire
        essai, etat, k, ferme = visible, dans_commentaire, absorbees, False
        while k < len(suivantes) and not etat:
            ligne = CITATION.sub("", suivantes[k], count=1)
            if COUPE_LE_PARAGRAPHE.match(ligne) or ouvre_un_bloc(ligne):
                break
            vue, etat = retirer_commentaires_html(ligne, etat)
            essai = essai.rstrip() + " " + vue.strip()
            k += 1
            if segment_ouvert(essai, debut) != p:
                ferme = True
                break
        if ferme:
            visible, absorbees, dans_commentaire = essai, k, etat
        else:
            debut = p + len(SUITE_D_ACCENTS.match(visible, p).group())


def rejoindre_les_liens(visible, suivantes, dans_commentaire):
    """La ligne `visible` prolongée des lignes de `suivantes` que le texte d'un lien emporte : (texte
    rejoint, lignes absorbées, état de commentaire HTML après elles).

    CommonMark : le texte d'un lien peut passer à la ligne dans un paragraphe, autant de fois qu'il le
    faut. Les lignes du paragraphe sont absorbées jusqu'à la PLUS COURTE jointure qui fait naître un lien
    commençant avant la coupure courante et finissant après ; aucune jointure de ce genre jusqu'à la fin
    du paragraphe, et la ligne reste seule, comme un crochet de texte qui n'ouvre rien."""
    absorbees = 0
    while not dans_commentaire:
        coupure = len(visible.rstrip())
        essai, etat, k, trouve = visible.rstrip(), dans_commentaire, absorbees, False
        while k < len(suivantes) and not etat:
            ligne = CITATION.sub("", suivantes[k], count=1)
            if COUPE_LE_PARAGRAPHE.match(ligne) or ouvre_un_bloc(ligne):
                break
            vue, etat = retirer_commentaires_html(ligne, etat)
            essai = essai + " " + vue.strip()
            k += 1
            sans_code = SEGMENT_DE_CODE.sub(lambda s: " " * len(s.group(0)), essai)
            if any(m.start() < coupure < m.end() for m in LIEN_EN_LIGNE.finditer(sans_code)):
                trouve = True
                break
        if not trouve:
            break
        visible, dans_commentaire, absorbees = essai, etat, k
    return visible, absorbees, dans_commentaire


def analyser(texte, chemin):
    doc = Document(chemin)
    # Une marque d'ordre d'octets en tête collerait au premier `#` et masquerait le premier titre.
    texte = texte.removeprefix("\ufeff")
    cloture = None  # (caractère, longueur, ligne d'ouverture, commandes)
    dans_commentaire = False
    tableau = None  # [première ligne, nombre]

    def fermer_tableau():
        nonlocal tableau
        if tableau:
            doc.tableaux.append(tuple(tableau))
        tableau = None

    lignes = texte.splitlines()
    slugs = Counter()
    paragraphe = None  # ligne de texte précédente, que `===` ou `---` dessous ferait titre souligné
    attend_selecteur = False  # vrai entre le premier titre de niveau 1 et la ligne non vide suivante
    n = 0
    while n < len(lignes):
        brute = lignes[n]
        n += 1
        ligne = CITATION.sub("", brute, count=1)
        if cloture:
            m = CLOTURE.match(ligne)
            if (m and m.group(1)[0] == cloture[0] and len(m.group(1)) >= cloture[1]
                    and not m.group(2).strip()):
                doc.blocs.append((cloture[2], cloture[3]))
                cloture = None
            else:
                c = commande(ligne)
                if c:
                    cloture[3].append((n, c))
            continue
        m = ouvre_un_bloc(ligne)
        if m and not dans_commentaire:
            fermer_tableau()
            cloture = (m.group(1)[0], len(m.group(1)), n, [])
            attend_selecteur, paragraphe = False, None
            continue

        visible, dans_commentaire = retirer_commentaires_html(ligne, dans_commentaire)
        if LIGNE_DE_TABLEAU.match(visible):
            if tableau is None:
                tableau = [n, 0]
            tableau[1] += 1
        else:
            fermer_tableau()

        def ancrer(titre):
            base = slug(titre)
            doc.ancres.add(f"{base}-{slugs[base]}" if slugs[base] else base)
            slugs[base] += 1

        ici = n  # ce qu'une ligne rejointe porte est rapporté à sa première ligne
        t = TITRE.match(visible)
        premier_titre_1 = False
        if t:
            doc.titres.append((n, len(t.group(1))))
            ancrer(t.group(2) or "")
            premier_titre_1 = len(t.group(1)) == 1 and not doc.titre_1
        elif paragraphe and SOULIGNEMENT.match(visible):
            # Un titre souligné n'est pas compté parmi les titres, mais son ancre existe : la taire
            # accuserait à tort un lien qui la vise.
            ancrer(paragraphe)
        elif LIGNE_DE_TABLEAU.match(visible) is None and DEFINITION_DE_LIEN.match(visible) is None:
            visible, absorbees, dans_commentaire = rejoindre_les_segments(
                visible, lignes[n:], dans_commentaire)
            n += absorbees
            visible, absorbees, dans_commentaire = rejoindre_les_liens(
                visible, lignes[n:], dans_commentaire)
            n += absorbees
        # Lues après la jointure : un `id` posé sur une ligne absorbée existe tout autant.
        for a in ANCRE_HTML.finditer(visible):
            doc.ancres.add(a.group(1))
        paragraphe = (visible if visible.strip() and not t and not LIGNE_DE_TABLEAU.match(visible)
                      and not SOULIGNEMENT.match(visible) else None)

        if attend_selecteur and visible.strip():
            attend_selecteur = False
            hors_code = SEGMENT_DE_CODE.sub(" ", visible)
            # Une ligne faite de liens et de séparateurs seulement ; toute autre ligne n'en est pas un.
            seule = not LIEN_EN_LIGNE.sub("", hors_code).strip(" \t|·/")
            doc.selecteur = (ici, visible.strip(),
                             [x.group(2) for x in LIEN_EN_LIGNE.finditer(hors_code)] if seule else [])
        if premier_titre_1:
            doc.titre_1, attend_selecteur = ici, True

        d = DEFINITION_DE_LIEN.match(visible)
        if d:
            doc.liens.append((ici, d.group(1)))
            continue

        for s in SEGMENT_DE_CODE.finditer(visible):
            doc.identifiants.setdefault(s.group(2).strip(), ici)
        sans_code = SEGMENT_DE_CODE.sub(" ", visible)
        for lien in LIEN_EN_LIGNE.finditer(sans_code):
            doc.liens.append((ici, lien.group(2)))
        texte_courant = LIEN_EN_LIGNE.sub(lambda x: f" {x.group(1)} ", sans_code)
        texte_courant = URL_NUE.sub(" ", texte_courant)
        for nombre in NOMBRE.findall(texte_courant):
            doc.nombres.setdefault(str(int(nombre)), ici)
        for mot in WORD.findall(re.sub(r"<[^>]*>", " ", texte_courant).lower()):
            doc.mots_fr += mot in MOTS_FRANCAIS
            doc.mots_en += mot in MOTS_ANGLAIS

    fermer_tableau()
    if cloture:
        doc.blocs.append((cloture[2], cloture[3]))
    return doc


def langue_de_la_prose(doc):
    """« fr », « en », ou None quand la prose porte moins de MIN_MOTS_OUTILS mots-outils, ou que les deux
    langues s'y mêlent sans que l'une passe sous PART_ETRANGERE_MAX."""
    total = doc.mots_fr + doc.mots_en
    if total < MIN_MOTS_OUTILS:
        return None
    if doc.mots_en / total < PART_ETRANGERE_MAX:
        return "fr"
    if doc.mots_fr / total < PART_ETRANGERE_MAX:
        return "en"
    return None


def juger_la_langue(doc, attendue):
    """Les écarts de langue d'un fichier dont la langue `attendue` est connue."""
    if attendue not in LIBELLES:
        return []
    total = doc.mots_fr + doc.mots_en
    if total < MIN_MOTS_OUTILS:
        return []
    etrangers = doc.mots_en if attendue == "fr" else doc.mots_fr
    if etrangers / total < PART_ETRANGERE_MAX:
        return []
    autre = "anglais" if attendue == "fr" else "français"
    nom = "français" if attendue == "fr" else "anglais"
    return [Ecart(doc.chemin, 1, "langue",
                  f"la prose n'est pas en {nom} : {etrangers} mots-outils en {autre} sur {total} (part "
                  f"{etrangers / total:.2f}, plafond {PART_ETRANGERE_MAX}) — le fichier porte la version "
                  f"{nom}e, son texte est-il celui de l'autre langue ?")]


class Convention:
    """`X<original>.md` ↔ `X<traduction>.md` ; l'un des deux suffixes peut être vide, pas les deux."""

    def __init__(self, original="", traduction=".fr"):
        for s in (original, traduction):
            if s and not re.fullmatch(r"\.[A-Za-z][A-Za-z_-]*", s):
                raise ValueError(f"suffixe « {s} » : attendu vide ou de la forme .xx")
        if original == traduction:
            raise ValueError("les deux suffixes sont identiques : aucune paire ne peut se former")
        self.original = original
        self.traduction = traduction

    def _tige(self, chemin, suffixe):
        fin = suffixe + ".md"
        return chemin[: -len(fin)] if chemin.endswith(fin) else None

    def est_original(self, chemin):
        if self._tige(chemin, self.original) is None:
            return False
        # Avec un suffixe d'original vide, `X.fr.md` finit aussi par `.md` : c'est une traduction.
        return bool(self.original) or self._tige(chemin, self.traduction) is None

    def est_traduction(self, chemin):
        if self._tige(chemin, self.traduction) is None:
            return False
        return bool(self.traduction) or self._tige(chemin, self.original) is None

    def traduction_de(self, chemin):
        return self._tige(chemin, self.original) + self.traduction + ".md"

    def original_de(self, chemin):
        return self._tige(chemin, self.traduction) + self.original + ".md"

    def langues(self):
        """(langue de l'original, langue de la traduction) : un suffixe `.fr` ou `.en` nomme la sienne, le
        suffixe vide prend l'autre ; (None, None) quand la convention ne les nomme pas."""
        o, t = LANGUE_DU_SUFFIXE.get(self.original), LANGUE_DU_SUFFIXE.get(self.traduction)
        autre = {"en": "fr", "fr": "en"}
        if o is None and not self.original and t:
            o = autre[t]
        if t is None and not self.traduction and o:
            t = autre[o]
        return (o, t) if o and t else (None, None)


def cible_sans_ancre(cible):
    """La cible sans ancre ; `./y.md` et `y.md` désignent le même fichier, donc la même cible."""
    chemin = cible.split("#", 1)[0]
    while chemin.startswith("./"):
        chemin = chemin[2:]
    return chemin


def est_externe(chemin):
    return bool(SCHEMA.match(chemin)) or chemin.startswith("//")


def resoudre(chemin, dossier):
    """Le fichier qu'une cible désigne, relatif à la racine : `/Y.md` part de la racine, `Y.md` du
    dossier du document."""
    base = "" if chemin.startswith("/") else dossier
    return os.path.normpath(os.path.join(base, chemin.lstrip("/")))


def basculer(cible, dossier, convention, existe, paire=()):
    """La cible qu'un lien de l'original doit porter dans la traduction.

    Un lien vers l'un des deux documents de la `paire` est le sélecteur de langue : il est le même
    des deux côtés, donc ne bascule pas."""
    chemin = cible_sans_ancre(cible)
    if not chemin or est_externe(chemin):
        return chemin
    if resoudre(chemin, dossier) in paire:
        return chemin
    if not convention.est_original(chemin):
        return chemin
    traduit = convention.traduction_de(chemin)
    if existe(resoudre(traduit, dossier)):
        return traduit
    return chemin


def comparer_titres(o, t):
    for (lo, no), (lt, nt) in zip(o.titres, t.titres):
        if no != nt:
            return [Ecart(o.chemin, lo, "titres",
                          f"titre de niveau {no}, la traduction porte un niveau {nt} ({t.chemin}:{lt})")]
    if len(o.titres) > len(t.titres):
        lo, no = o.titres[len(t.titres)]
        return [Ecart(o.chemin, lo, "titres",
                      f"titre de niveau {no} sans pendant ({len(o.titres)} titres contre {len(t.titres)})")]
    if len(t.titres) > len(o.titres):
        lt, nt = t.titres[len(o.titres)]
        return [Ecart(t.chemin, lt, "titres",
                      f"titre de niveau {nt} en trop ({len(t.titres)} titres contre {len(o.titres)})")]
    return []


def comparer_blocs(o, t):
    ecarts = []
    if len(o.blocs) != len(t.blocs):
        court, long_ = (o, t) if len(o.blocs) < len(t.blocs) else (t, o)
        ligne = long_.blocs[len(court.blocs)][0]
        ecarts.append(Ecart(long_.chemin, ligne, "blocs",
                            f"{len(long_.blocs)} blocs de code contre {len(court.blocs)} dans {court.chemin}"))
    for (lo, co), (lt, ct) in zip(o.blocs, t.blocs):
        for (ko, xo), (kt, xt) in zip(co, ct):
            if xo != xt:
                ecarts.append(Ecart(o.chemin, ko, "blocs",
                                    f"commande « {xo} », la traduction porte « {xt} » ({t.chemin}:{kt})"))
                break
        else:
            if len(co) > len(ct):
                ko, xo = co[len(ct)]
                ecarts.append(Ecart(o.chemin, ko, "blocs",
                                    f"commande « {xo} » absente du bloc ouvert en {t.chemin}:{lt}"))
            elif len(ct) > len(co):
                kt, xt = ct[len(co)]
                ecarts.append(Ecart(t.chemin, kt, "blocs",
                                    f"commande « {xt} » en trop, absente du bloc ouvert en {o.chemin}:{lo}"))
    return ecarts


def comparer_tableaux(o, t):
    ecarts = []
    if len(o.tableaux) != len(t.tableaux):
        court, long_ = (o, t) if len(o.tableaux) < len(t.tableaux) else (t, o)
        ligne = long_.tableaux[len(court.tableaux)][0]
        ecarts.append(Ecart(long_.chemin, ligne, "tableaux",
                            f"{len(long_.tableaux)} tableaux contre {len(court.tableaux)} dans {court.chemin}"))
    for (lo, no), (lt, nt) in zip(o.tableaux, t.tableaux):
        if no != nt:
            ecarts.append(Ecart(o.chemin, lo, "tableaux",
                                f"tableau de {no} lignes, la traduction en porte {nt} ({t.chemin}:{lt})"))
    return ecarts


def comparer_liens(o, t, convention, existe):
    dossier = os.path.dirname(o.chemin)
    paire = {os.path.normpath(o.chemin), os.path.normpath(t.chemin)}
    attendus, origine, forme_brute = Counter(), {}, {}
    for ligne, cible in o.liens:
        b = basculer(cible, dossier, convention, existe, paire)
        if not b:
            continue
        attendus[b] += 1
        origine.setdefault(b, ligne)
        forme_brute.setdefault(cible_sans_ancre(cible), b)
    portes, position = Counter(), {}
    for ligne, cible in t.liens:
        c = cible_sans_ancre(cible)
        if not c:
            continue
        portes[c] += 1
        position.setdefault(c, ligne)

    manquants = attendus - portes
    en_trop = portes - attendus
    ecarts = []
    for c in sorted(en_trop):
        visee = forme_brute.get(c)
        if visee and visee != c and visee in manquants:
            ecarts.append(Ecart(t.chemin, position[c], "liens",
                                f"lien non basculé : « {c} » doit viser « {visee} », qui existe"))
            del manquants[visee]
        else:
            ecarts.append(Ecart(t.chemin, position[c], "liens", f"lien vers « {c} » absent de l'original"))
    for c in sorted(manquants):
        ecarts.append(Ecart(o.chemin, origine[c], "liens", f"lien vers « {c} » absent de la traduction"))
    return ecarts


def comparer_ensembles(o_valeurs, t_valeurs, o, t, famille, nom):
    ecarts = []
    for v in sorted(set(o_valeurs) - set(t_valeurs)):
        ecarts.append(Ecart(o.chemin, o_valeurs[v], famille, f"{nom} « {v} » absent de la traduction"))
    for v in sorted(set(t_valeurs) - set(o_valeurs)):
        ecarts.append(Ecart(t.chemin, t_valeurs[v], famille, f"{nom} « {v} » absent de l'original"))
    return ecarts


def comparer_nombres(o, t):
    return comparer_ensembles(o.nombres, t.nombres, o, t, "nombres", "nombre")


def comparer_identifiants(o, t):
    return comparer_ensembles(o.identifiants, t.identifiants, o, t, "identifiants", "identifiant")


def comparer_selecteur(o, t, convention=None):
    """Sous le premier titre de niveau 1 de chaque côté, la même ligne de sélecteur : un lien vers
    l'original, puis un lien vers la traduction, et rien d'autre que des séparateurs. Quand la
    convention nomme les deux langues, la ligne a une FORME EXACTE, la même des deux côtés :
    `[English](X.md) | [Français](X.fr.md)` — libellés compris."""
    dossier = os.path.dirname(o.chemin)
    attendu = [os.path.normpath(o.chemin), os.path.normpath(t.chemin)]
    relatifs = [os.path.relpath(c, dossier or '.') for c in attendu]
    noms = " puis ".join(f"« {r} »" for r in relatifs)
    lo, lt = convention.langues() if convention else (None, None)
    forme = f"[{LIBELLES[lo]}]({relatifs[0]}) | [{LIBELLES[lt]}]({relatifs[1]})" if lo else None
    ecarts, justes = [], []
    for doc in (o, t):
        if not doc.titre_1:
            ecarts.append(Ecart(doc.chemin, 1, "sélecteur",
                                "aucun titre de niveau 1 : le sélecteur de langue n'a pas de place"))
            continue
        ligne, texte, cibles = doc.selecteur or (doc.titre_1, "", [])
        vises = [resoudre(cible_sans_ancre(c), dossier) for c in cibles]
        if not cibles:
            ecarts.append(Ecart(doc.chemin, ligne, "sélecteur",
                                f"sélecteur de langue absent sous le titre de niveau 1 (ligne "
                                f"{doc.titre_1}) : attendu un lien vers {noms}"))
        elif vises == attendu[::-1]:
            ecarts.append(Ecart(doc.chemin, ligne, "sélecteur",
                                f"sélecteur inversé : il nomme la traduction avant l'original, attendu {noms}"))
        elif vises != attendu:
            ecarts.append(Ecart(doc.chemin, ligne, "sélecteur",
                                f"sélecteur qui vise {', '.join(cibles)} : attendu {noms}"))
        elif forme and texte != forme:
            ecarts.append(Ecart(doc.chemin, ligne, "sélecteur",
                                f"forme du sélecteur « {texte} » : attendu exactement « {forme} »"))
        else:
            justes.append((ligne, texte))
    if not forme and len(justes) == 2 and justes[0][1] != justes[1][1]:
        ecarts.append(Ecart(t.chemin, justes[1][0], "sélecteur",
                            f"sélecteur différent de celui de l'original ({o.chemin}:{justes[0][0]}), "
                            f"attendu la même ligne des deux côtés"))
    return ecarts


def comparer_ancres(o, t, convention, ancres_de):
    """Dans la traduction, chaque ancre d'un lien interne vers un document Markdown de l'arbre désigne
    un titre (ou un `id` HTML) du fichier visé. Les ancres de l'original ne sont pas jugées."""
    dossier = os.path.dirname(t.chemin)
    ecarts = []
    for ligne, cible in t.liens:
        if "#" not in cible:
            continue
        chemin, ancre = cible.split("#", 1)
        chemin, ancre = cible_sans_ancre(chemin), unquote(ancre)
        if not ancre or est_externe(chemin):
            continue
        vise = resoudre(chemin, dossier) if chemin else os.path.normpath(t.chemin)
        if not vise.endswith(".md") or vise.startswith(".."):
            continue
        ancres = ancres_de(vise)
        # La casse d'une ancre n'est pas tranchée (le slug est en minuscules ; ce que le navigateur
        # de la page fait d'une majuscule n'a pas été mesuré) : dans le doute, pas d'accusation.
        if ancres is None or ancre in ancres or ancre.lower() in ancres:
            continue
        message = f"ancre « #{ancre} » : aucun titre de {vise} n'a ce slug"
        if convention.est_traduction(vise):
            source = convention.original_de(vise)
            if ancre in (ancres_de(source) or ()):
                message += f" ; c'est celui d'un titre de l'original {source} : viser le titre traduit"
        ecarts.append(Ecart(t.chemin, ligne, "ancres", message))
    return ecarts


def comparer(original, traduction, convention, existe, ancres_de=None):
    """Tous les écarts entre deux documents déjà analysés, famille par famille.

    `ancres_de(chemin)` rend les ancres d'un document de l'arbre, ou None s'il n'existe pas ; sans
    elle, les ancres ne sont pas jugées."""
    ecarts = []
    ecarts += comparer_titres(original, traduction)
    ecarts += comparer_blocs(original, traduction)
    ecarts += comparer_tableaux(original, traduction)
    ecarts += comparer_liens(original, traduction, convention, existe)
    ecarts += comparer_nombres(original, traduction)
    ecarts += comparer_identifiants(original, traduction)
    ecarts += comparer_selecteur(original, traduction, convention)
    lo, lt = convention.langues()
    ecarts += juger_la_langue(original, lo) + juger_la_langue(traduction, lt)
    if ancres_de:
        ecarts += comparer_ancres(original, traduction, convention, ancres_de)
    return ecarts


def comparer_fichiers(racine, original, traduction, convention):
    def lire(rel):
        try:
            with open(os.path.join(racine, rel), encoding="utf-8") as f:
                texte = f.read()
        except (OSError, UnicodeDecodeError) as e:
            raise Illisible(f"{rel} : {e}") from e
        return analyser(texte, rel)

    def existe(rel):
        return os.path.isfile(os.path.join(racine, rel))

    lus, non_lus = {}, []

    def ancres_de(rel):
        # Un fichier visé illisible n'est pas une ancre fausse : ses ancres ne sont pas jugées, et la
        # paire est lue en partie. Le reste de la comparaison continue.
        if rel not in lus:
            try:
                lus[rel] = lire(rel).ancres if existe(rel) else None
            except Illisible as e:
                lus[rel] = None
                non_lus.append(str(e))
        return lus[rel]

    o, t = lire(original), lire(traduction)
    lus[os.path.normpath(original)], lus[os.path.normpath(traduction)] = o.ancres, t.ancres
    ecarts = comparer(o, t, convention, existe, ancres_de)
    if non_lus:
        raise Illisible("ancre(s) non jugée(s), fichier visé illisible : " + " ; ".join(non_lus),
                        ecarts)
    return ecarts


def comparer_documents(racine, documents, convention):
    """Ce qu'un document juge SEUL : la DIRECTION de ses liens et les ANCRES qu'ils visent. Rend (écarts,
    illisibles).

    Elle juge chaque original de paire et chaque document sans paire ; la traduction d'une paire est déjà
    tenue par sa comparaison à l'original (cibles basculées, ancres de la traduction). Un lien vers un
    document qui existe dans les deux langues vise la version de la langue du document qui le porte : la
    langue de l'original vient de la convention, celle d'un document sans paire de sa prose (non jugée
    quand elle est indécise). La ligne du sélecteur de langue est la seule exception. Une ancre vers un
    document Markdown de l'arbre désigne un titre ou un `id` de ce fichier."""
    present = set(documents)
    lo, lt = convention.langues()

    def existe(rel):
        return os.path.isfile(os.path.join(racine, rel))

    cache, illisibles = {}, []

    def lire(rel):
        if rel not in cache:
            try:
                with open(os.path.join(racine, rel), encoding="utf-8") as f:
                    cache[rel] = analyser(f.read(), rel)
            except (OSError, UnicodeDecodeError) as e:
                cache[rel] = None
                illisibles.append(f"{rel} : {e}")
        return cache[rel]

    def versions(vise):
        """(version originale, version traduite) d'un document qui existe dans les deux langues."""
        if convention.est_traduction(vise):
            o, t = convention.original_de(vise), vise
        elif convention.est_original(vise):
            o, t = vise, convention.traduction_de(vise)
        else:
            return None
        return (o, t) if existe(o) and existe(t) else None

    ecarts = []
    for d in documents:
        if convention.est_traduction(d) and convention.original_de(d) in present:
            continue
        doc = lire(d)
        if doc is None:
            continue
        a_sa_paire = convention.est_original(d) and convention.traduction_de(d) in present
        langue = lo if a_sa_paire else langue_de_la_prose(doc)
        ligne_du_selecteur = doc.selecteur[0] if doc.selecteur else None
        dossier = os.path.dirname(d)
        for ligne, cible in doc.liens:
            chemin, _, ancre = cible.partition("#")
            chemin = cible_sans_ancre(chemin)
            if est_externe(chemin):
                continue
            vise = resoudre(chemin, dossier) if chemin else os.path.normpath(d)
            if not vise.endswith(".md") or vise.startswith(".."):
                continue
            paire_visee = versions(vise) if chemin else None
            if paire_visee and langue and ligne != ligne_du_selecteur and lo:
                langue_visee = lo if vise == paire_visee[0] else lt
                if langue_visee != langue:
                    juste = paire_visee[1] if langue == lt else paire_visee[0]
                    nom = {"fr": "français", "en": "anglais"}
                    ecarts.append(Ecart(d, ligne, "direction",
                                        f"document {nom[langue]} qui vise la version {nom[langue_visee]}e "
                                        f"« {chemin} » : viser « {os.path.relpath(juste, dossier or '.')} »"))
            ancre = unquote(ancre)
            if ancre and existe(vise):
                cible_lue = lire(vise)
                if cible_lue is not None and ancre not in cible_lue.ancres and ancre.lower() not in cible_lue.ancres:
                    ecarts.append(Ecart(d, ligne, "ancres", f"ancre « #{ancre} » : aucun titre de {vise} n'a ce slug"))
    return ecarts, illisibles


class Illisible(Exception):
    """Un fichier n'a pas pu être lu. `ecarts` vaut None quand c'est un fichier de la paire (rien n'a
    été comparé), et la liste des écarts trouvés quand c'est un fichier visé par une ancre (la paire
    a été lue en partie)."""

    def __init__(self, message, ecarts=None):
        super().__init__(message)
        self.ecarts = ecarts


def documents_suivis(racine):
    try:
        sortie = subprocess.run(["git", "-C", racine, "ls-files", "-z", "--", "*.md"],
                                capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return sorted(p for p in sortie.decode("utf-8").split("\0") if p)


def inventaire(documents, convention, une_seule_langue=None):
    """(originaux sans traduction, traductions sans original, entrées périmées de l'ensemble en une
    seule langue), en chemins relatifs.

    Un original sans traduction nommé dans `une_seule_langue` n'est pas un écart. Une entrée de cet
    ensemble en est un quand elle ne porte pas de raison écrite (vide, absente), quand le document a sa
    traduction, ou quand il n'est plus suivi : la raison écrite à côté ne vaut plus rien."""
    seules = UNE_SEULE_LANGUE if une_seule_langue is None else une_seule_langue
    present = set(documents)
    sans_traduction = [d for d in documents
                       if convention.est_original(d) and convention.traduction_de(d) not in present
                       and d not in seules]
    orphelines = [d for d in documents
                  if convention.est_traduction(d) and convention.original_de(d) not in present]
    perimees = []
    for d in sorted(seules):
        raison = seules[d]
        if not isinstance(raison, str) or not raison.strip():
            perimees.append((d, "n'a aucune raison écrite : une exception sans raison ne se retire plus"))
        elif d not in present:
            perimees.append((d, "n'est plus un document suivi"))
        elif not convention.est_original(d):
            perimees.append((d, "n'est pas un original sous la convention"))
        elif convention.traduction_de(d) in present:
            perimees.append((d, f"a retrouvé sa traduction {convention.traduction_de(d)}"))
    return sans_traduction, orphelines, perimees


def langues_manquantes(chemins, convention=None):
    """Les documents de `chemins` dont l'autre langue n'y figure pas, en (chemin, chemin manquant). Une
    garde qui juge un document dans ses deux langues déclare les deux fichiers ; celle qui n'en garde
    qu'un rendrait vert sur une faute de l'autre."""
    convention = convention or Convention()
    presents = set(chemins)
    manquants = []
    for c in chemins:
        if convention.est_traduction(c):
            autre = convention.original_de(c)
        elif convention.est_original(c):
            autre = convention.traduction_de(c)
        else:
            continue
        if autre not in presents:
            manquants.append((c, autre))
    return manquants


def paires(documents, convention):
    present = set(documents)
    return [(d, convention.traduction_de(d)) for d in documents
            if convention.est_original(d) and convention.traduction_de(d) in present]


def racine_par_defaut():
    ici = os.path.dirname(os.path.abspath(__file__))
    return os.path.realpath(os.path.join(ici, ".."))


def main(argv=None):
    p = argparse.ArgumentParser(description="Parité entre un document et sa traduction.")
    p.add_argument("--racine", default=racine_par_defaut())
    p.add_argument("--suffixe-original", default="")
    p.add_argument("--suffixe-traduction", default=".fr")
    p.add_argument("--paire", nargs=2, metavar=("ORIGINAL", "TRADUCTION"))
    p.add_argument("--inventaire", action="store_true")
    p.add_argument("--strict", action="store_true")
    a = p.parse_args(argv)

    try:
        convention = Convention(a.suffixe_original, a.suffixe_traduction)
    except ValueError as e:
        print(f"convention invalide : {e}", file=sys.stderr)
        return 2

    documents = None
    if a.paire:
        a_comparer = [tuple(a.paire)]
    else:
        documents = documents_suivis(a.racine)
        if documents is None:
            print(f"aucun document lisible sous {a.racine} (git ls-files a échoué) : rien comparé",
                  file=sys.stderr)
            return 2
        if a.inventaire:
            sans_traduction, orphelines, perimees = inventaire(documents, convention)
            for d in sans_traduction:
                print(f"{d}: sans traduction (attendue : {convention.traduction_de(d)}), et absent de "
                      f"UNE_SEULE_LANGUE")
            for d in orphelines:
                print(f"{d}: traduction sans original (attendu : {convention.original_de(d)})")
            for d, pourquoi in perimees:
                print(f"{d}: entrée périmée de UNE_SEULE_LANGUE ({UNE_SEULE_LANGUE[d]}) : {pourquoi}")
            ecarts = len(sans_traduction) + len(orphelines) + len(perimees)
            seules = sorted(set(UNE_SEULE_LANGUE) & set(documents))
            print(f"{len(paires(documents, convention))} paire(s), {len(seules)} document(s) en une seule "
                  f"langue déclarés, {ecarts} écart(s) ({len(sans_traduction)} document(s) sans "
                  f"traduction, {len(orphelines)} traduction(s) sans original, {len(perimees)} entrée(s) "
                  f"périmée(s)), sur {len(documents)} documents suivis")
            if not documents:
                print("aucun document suivi : rien inventorié", file=sys.stderr)
                return 2
            return 1 if a.strict and ecarts else 0
        a_comparer = paires(documents, convention)
        if not a_comparer:
            print("aucune paire de documents suivis : rien comparé (voir --inventaire)", file=sys.stderr)
            return 2

    # Une paire illisible n'arrête pas les autres : un écart trouvé ailleurs reste une violation, et
    # il serait faux de le taire derrière un « rien comparé ».
    total, illisibles, partielles = [], [], []
    for original, traduction in a_comparer:
        try:
            total += comparer_fichiers(a.racine, original, traduction, convention)
        except Illisible as e:
            if e.ecarts is None:
                illisibles.append((original, traduction, e))
            else:
                total += e.ecarts
                partielles.append((original, traduction, e))
    # Ce que chaque document juge seul (direction des liens, ancres de l'original et des documents sans
    # paire), sur tout l'arbre suivi ; `--paire` ne lit que sa paire.
    seuls_illisibles = []
    if documents is not None:
        en_plus, seuls_illisibles = comparer_documents(a.racine, documents, convention)
        total += en_plus
    for e in total:
        print(e)
    for original, traduction, e in illisibles:
        print(f"{original} / {traduction} illisible, rien comparé pour cette paire : {e}", file=sys.stderr)
    for original, traduction, e in partielles:
        print(f"{original} / {traduction} lue en partie : {e}", file=sys.stderr)
    for e in seuls_illisibles:
        print(f"document illisible, direction et ancres non jugées : {e}", file=sys.stderr)
    print(f"{len(a_comparer) - len(illisibles) - len(partielles)} paire(s) comparée(s), "
          f"{len(total)} écart(s)"
          + (f", {len(partielles)} paire(s) lue(s) en partie" if partielles else "")
          + (f", {len(illisibles)} paire(s) illisible(s)" if illisibles else ""))
    if total:
        return 1
    if illisibles or partielles or seuls_illisibles:
        print("aucun écart, mais une paire au moins n'a pas été lue en entier : rien ne prouve la parité",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

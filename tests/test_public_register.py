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

LES DEUX LANGUES. Les documents existent en anglais (`X.md`) et en français (`X.fr.md`). Les motifs
français (`BANNIES`) lisent tout le corpus, versions françaises des documents racine comprises : tout
ce qu'ils jugeaient quand ces documents n'existaient qu'en français, ils le jugent encore. Les motifs
anglais (`BANNIES_EN`) sont ceux qui se déduisent mot pour mot des motifs français ; « je consigne »
et « ma contre-vérification » n'ont pas d'équivalent anglais unique (record/log, counter-/cross-check)
et ne sont pas jugés dans l'anglais.

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

#: Les mêmes tournures dans l'anglais des documents, quand la traduction est sans ambiguïté.
BANNIES_EN = {
    r"\bI had\b": "récit d'enquête à la première personne",
    r"\bmyself\b": "récit d'enquête à la première personne",
    r"\bas you (?:asked|requested|told me)\b": "adresse directe à un interlocuteur",
    r"\bas requested\b": "adresse directe à un interlocuteur",
    r"\b(?:our|this) session\b": "chronologie de session comme fil narratif",
}

#: Exceptions ADMISES, chacune avec sa raison. Toute autre occurrence fait échouer le test.
#:
#: VIDE À DESSEIN. Elle contenait cinq entrées par FICHIER — dont trois exemptaient les 1 200
#: lignes de `ROADMAP.md` pour un motif donné, ce qui aurait laissé passer une vraie rechute
#: ailleurs dans le fichier ; et DEUX ÉTAIENT MORTES, leur motif n'existant plus dans le fichier
#: visé. C'est précisément la liste tenue à la main que le docstring ci-dessus dénonce, juste le
#: jour de son écriture et fausse ensuite. Les citations sont désormais reconnues par leur FORME
#: (cf. `_est_citee`), ce qui ne demande aucun entretien. `test_aucune_exception_MORTE` refuse
#: qu'une entrée y survive à son besoin.
ADMISES = {}

#: Une occurrence CITÉE énonce la mauvaise forme au lieu de la commettre — et une règle doit
#: pouvoir citer ce qu'elle interdit sans se refuser elle-même. Trois formes valent citation :
#: les guillemets « … » (éventuellement sur plusieurs lignes), le code entre backticks, et les
#: lignes de citation Markdown « > ».
#: Le guillemet fermant peut être sur la ligne suivante — une citation se replie comme le reste du
#: texte — mais JAMAIS au-delà d'un saut de paragraphe : un « orphelin exempterait sinon tout le
#: texte jusqu'au » suivant, et l'exemption avalerait le fichier au lieu de couvrir une citation.
_GUILLEMETS = re.compile(r"«(?:[^»\n]|\n(?!\s*\n))*»")
_CODE = re.compile(r"`[^`\n]+`")
#: Les guillemets de l'anglais, droits ou courbes, sous la même borne de paragraphe. Ils ne valent
#: citation QUE pour les motifs anglais : un motif français entre guillemets droits reste une faute,
#: comme avant que l'anglais n'existe.
_GUILLEMETS_EN = re.compile(r'"(?:[^"\n]|\n(?!\s*\n))*"|“(?:[^”\n]|\n(?!\s*\n))*”')


def _spans_cites(texte, anglais=False):
    """Intervalles d'index du texte qui relèvent d'une citation. Pur, ne lève jamais."""
    spans = [m.span() for m in _GUILLEMETS.finditer(texte)]
    if anglais:
        spans += [m.span() for m in _GUILLEMETS_EN.finditer(texte)]
    spans += [m.span() for m in _CODE.finditer(texte)]
    debut = 0
    for ligne in texte.splitlines(keepends=True):
        if ligne.lstrip().startswith(">"):
            spans.append((debut, debut + len(ligne)))
        debut += len(ligne)
    return spans


def _est_citee(spans, position):
    return any(a <= position < b for a, b in spans)


def _fautes(rel, texte):
    """Les tournures fautives de `texte` (fichier `rel`), en (ligne, raison, extrait). Pur : c'est la
    décision que le test du corpus applique, et celle que ses témoins jouent.

    Les guillemets anglais ne valent citation que pour un motif ANGLAIS et dans un document `.md` :
    dans un `.py`, un guillemet droit délimite toute chaîne de code, et le compter comme citation
    rendrait les motifs anglais aveugles aux docstrings, aux commentaires et aux chaînes."""
    fautes = []
    spans = _spans_cites(texte)
    spans_en = _spans_cites(texte, anglais=True) if rel.endswith(".md") else spans
    for motif, raison in list(BANNIES.items()) + list(BANNIES_EN.items()):
        if (rel, motif) in ADMISES:
            continue
        cites = spans_en if motif in BANNIES_EN else spans
        for m in re.finditer(motif, texte, re.I):
            if _est_citee(cites, m.start()):
                continue
            fautes.append((texte[:m.start()].count("\n") + 1, raison, m.group(0)))
    return fautes


def _fichiers():
    for motif in ("forge/**/*.py", "bench/**/*.py", "docs/*.md"):
        yield from RACINE.glob(motif)
    for nom in ("ROADMAP.md", "CONTRIBUTING.md", "README.md",
                "ROADMAP.fr.md", "CONTRIBUTING.fr.md", "README.fr.md"):
        p = RACINE / nom
        if p.exists():
            yield p


class TheRepositoryAddressesAPublicReader(unittest.TestCase):

    def test_aucune_tournure_d_interlocuteur_hors_exceptions_declarees(self):
        fautes = []
        for f in _fichiers():
            rel = str(f.relative_to(RACINE))
            texte = f.read_text(encoding="utf-8", errors="replace")
            for ligne, raison, extrait in _fautes(rel, texte):
                fautes.append(f"{rel}:{ligne} — {raison} : « {extrait} »")
        self.assertEqual(fautes, [], "\n".join(
            ["tournures adressées à un interlocuteur (cf. ROADMAP.md § « Repository governance ») :"] + fautes))

    def test_chaque_exception_porte_sa_RAISON(self):
        for (fichier, motif), raison in ADMISES.items():
            with self.subTest(fichier=fichier):
                self.assertTrue(raison.strip(), f"{fichier} exclu sans justification écrite")

    def test_aucune_exception_MORTE(self):
        """Une exemption dont le motif a disparu du fichier visé n'exempte plus rien — elle ne fait
        qu'élargir la brèche pour le jour où la tournure reviendra.

        `ADMISES` en contenait deux, invisibles parce que rien ne les regardait : `CONTRIBUTING.md`
        n'avait plus « comme demandé », `forge/llm.py` plus d'adresse directe. C'est la troisième
        occurrence dans ce dépôt d'une liste tenue à la main qui survit à son objet — après
        `_RATE_FLAG_KINDS` et `_SQL_ERROR_SIGNS`, que le docstring de ce fichier cite déjà."""
        for (fichier, motif), _ in ADMISES.items():
            with self.subTest(fichier=fichier, motif=motif[:30]):
                p = RACINE / fichier
                self.assertTrue(p.exists(), f"{fichier} exempté mais absent du dépôt")
                texte = p.read_text(encoding="utf-8", errors="replace")
                self.assertTrue(re.search(motif, texte, re.I),
                                f"{fichier} : exemption MORTE, « {motif} » n'y figure plus")

    def test_une_CITATION_ne_compte_PAS_comme_une_faute(self):
        """Les trois formes de citation, et le contre-exemple qui prouve que le garde mord encore."""
        for cite in ("la règle bannit « j'avais écarté ce champ » comme récit",
                     "le motif `moi-même` est refusé par le garde",
                     "> « J'avais moi-même écarté ce champ » -> adressé à une conversation"):
            with self.subTest(cite=cite[:34]):
                spans = _spans_cites(cite)
                touches = [m for motif in BANNIES for m in re.finditer(motif, cite, re.I)]
                self.assertTrue(touches, "corpus mal choisi : aucune tournure à citer")
                self.assertTrue(all(_est_citee(spans, m.start()) for m in touches),
                                f"citation prise pour une faute : {cite}")
        nu = "Le champ a été écarté parce que j'avais conclu trop vite."
        spans = _spans_cites(nu)
        touches = [m for motif in BANNIES for m in re.finditer(motif, nu, re.I)]
        self.assertTrue(touches and not any(_est_citee(spans, m.start()) for m in touches),
                        "une faute en prose nue passe pour une citation — le garde ne mord plus")

    def test_un_guillemet_ORPHELIN_n_exempte_pas_la_suite_du_fichier(self):
        """Sans borne, un « jamais refermé exempterait tout le texte jusqu'au » suivant.

        C'est le mode de défaillance d'une exemption reconnue par la forme : elle ne coûte rien à
        écrire, donc elle doit coûter cher à élargir par accident."""
        texte = ("Un « guillemet ouvert et jamais refermé sur ce paragraphe.\n"
                 "\n"
                 "Le champ a été écarté parce que j'avais conclu trop vite.\n"
                 "\n"
                 "Et un » qui traîne bien plus loin.\n")
        spans = _spans_cites(texte)
        faute = re.search(r"\bj'avais\b", texte)
        self.assertFalse(_est_citee(spans, faute.start()),
                         "un guillemet orphelin a exempté un paragraphe entier")

    def test_le_garde_a_de_QUOI_mordre(self):
        """Un garde qui ne lit rien ne garde rien : on vérifie qu'il balaie un corpus réel."""
        fichiers = list(_fichiers())
        self.assertGreater(len(fichiers), 60, f"corpus trop maigre : {len(fichiers)} fichiers")

    def test_le_garde_lit_les_DEUX_langues(self):
        """Les documents racine existent en anglais et en français : le garde lit les deux, sinon le
        français qu'il jugeait avant la traduction sortirait de son regard sans que rien ne rougisse."""
        lus = {str(f.relative_to(RACINE)) for f in _fichiers()}
        for nom in ("ROADMAP", "CONTRIBUTING", "README"):
            for suffixe in (".md", ".fr.md"):
                with self.subTest(document=nom + suffixe):
                    self.assertIn(nom + suffixe, lus)
        self.assertTrue(any(f.endswith(".fr.md") for f in lus if f.startswith("docs/")),
                        "aucune version française de docs/ n'est lue")

    def test_les_motifs_ANGLAIS_mordent_et_respectent_les_citations(self):
        nu = "The field was ruled out because I had concluded too fast, as requested."
        touches = [m for motif in BANNIES_EN for m in re.finditer(motif, nu, re.I)]
        self.assertEqual(len(touches), 2, "un motif anglais ne reconnaît pas sa faute de référence")
        cite = 'the rule refuses "I had ruled this out" and "as you asked"'
        spans = _spans_cites(cite, anglais=True)
        touches = [m for motif in BANNIES_EN for m in re.finditer(motif, cite, re.I)]
        self.assertTrue(touches and all(_est_citee(spans, m.start()) for m in touches),
                        "une citation anglaise prise pour une faute")
        # Sur la décision que le test du corpus applique (`_fautes`) : la citation anglaise passe dans
        # un document, et un motif FRANÇAIS entre guillemets droits y reste une faute.
        self.assertEqual(_fautes("docs/X.md", cite), [], "citation anglaise refusée dans un document")
        fr = 'le champ "j\'avais conclu" reste une faute'
        self.assertEqual([e for _, _, e in _fautes("docs/X.fr.md", fr)], ["j'avais"],
                         "les guillemets droits exemptent un motif français")

    def test_dans_un_PY_un_guillemet_droit_n_est_pas_une_citation(self):
        """Dans du code, un guillemet droit délimite toute chaîne : docstring, commentaire ou chaîne
        qui porte un motif anglais restent des fautes."""
        for code in ('"""Retry added because I had seen it flake."""\n',
                     'log("this session closed")\n',
                     '# kept "as requested" by the reviewer\n'):
            with self.subTest(code=code[:30]):
                self.assertTrue(_fautes("forge/x.py", code), f"motif anglais non vu dans du code : {code}")
        # Les formes de citation communes aux deux langues valent toujours dans du code.
        self.assertEqual(_fautes("forge/x.py", "# le motif `I had` est refusé\n"), [])

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

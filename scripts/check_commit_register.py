#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vérifie qu'un commit respecte les deux règles publiques du dépôt : IDENTITÉ et ADRESSAGE.

SOURCE UNIQUE des deux barrières — le hook `commit-msg` (poste local, avant que le commit existe)
et le job CI (dépôt publié, sur la plage poussée) appellent ce même code. Deux implémentations d'une
même règle divergent toujours ; ce dépôt en a la démonstration avec `_RATE_FLAG_KINDS` et
`_SQL_ERROR_SIGNS`, justes le jour de leur écriture et fausses quelques mois plus tard.

POURQUOI DEUX BARRIÈRES. Un hook n'est pas transporté par `git clone`, et l'édition via l'interface
web de GitHub ne l'exécute jamais — c'est exactement par là que sont entrés les commits portant un
compte personnel. Le hook évite d'avoir à corriger après coup ; la CI est celle qui ferme.

CE QUI EST REFUSÉ
  · une identité d'auteur hors `guatxlabs <…@guatx.com>` : aucune adresse personnelle ni nominative ;
  · un message adressé à un interlocuteur : récit d'enquête à la première personne, adresse directe,
    chronologie de session comme fil narratif.

CE QUI RESTE ADMIS, et qu'un garde trop zélé détruirait
  · la VOIX DE L'OUTIL — « un `skipped` dit *je n'ai PAS pu vérifier* » énonce le sens d'un statut ;
  · une DATE de mesure — « MESURÉ le 2026-08-16 » est de la traçabilité, pas un journal ;
  · un « pourquoi » LONG. La longueur n'a jamais été le défaut ; l'adressage l'était.
  · les trailers d'attribution (`Co-Authored-By:`, `Signed-off-by:`, `Claude-Session:`).

COMMENT ÉCRIRE LA VOIX DE L'OUTIL : LA CITER. Ce garde lit des formes, pas des intentions — il ne
sait pas qui parle. Une tournure à la première personne qui énonce le sens d'un statut doit donc
porter une marque de citation : guillemets « … », code entre backticks, ou ligne « > ». C'est ce
que fait l'exemple `skipped` ci-dessus, et son pendant `tested` passe de la même façon.

CE FICHIER A DIT LE CONTRAIRE, et la mesure l'a corrigé. Il énumérait les verbes bannis après
« j'ai » et n'admettait que « > », au motif écrit que les guillemets exempteraient trop. Résultat
mesuré : 20 commits sont passés avec `j'ai inséré`, `j'ai composé`, `mon diagnostic`, `hier`, et
36 de plus au tour suivant. Reconnaître la citation à sa FORME attrape ces cinquante-six-là et
laisse passer la voix de l'outil sans avoir à l'énumérer.

USAGE
    check_commit_register.py --message-file <fichier>        # hook commit-msg
    check_commit_register.py --range <base>..<head>          # CI, plage poussée
    check_commit_register.py --rev HEAD                      # un commit précis
Sortie 0 si tout passe, 1 sinon (chaque faute est nommée avec sa raison).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys

#: Identité publique UNIQUE du dépôt.
NOM_ATTENDU = "guatxlabs"
DOMAINE_ATTENDU = "@guatx.com"

#: Tournures qui trahissent une adresse à un interlocuteur plutôt qu'à un lecteur public.
#: LES ÉLISIONS DE « JE » ET LES POSSESSIFS SONT PRIS EN BLOC, pas mot par mot. La version
#: précédente énumérait `j'ai (trouvé|corrigé|mesuré|…)` puis `ma (mesure|conclusion|…)` — et a
#: laissé passer `j'ai inséré`, `j'ai composé`, `mon propre garde`, `de mon côté`, `hier` dans
#: 56 commits, trouvés seulement par un audit INDÉPENDANT du garde. C'est la quatrième liste tenue
#: à la main de ce dépôt à survivre à son objet, après `_RATE_FLAG_KINDS`, `_SQL_ERROR_SIGNS` et
#: les exemptions du garde de documents. Une énumération ne peut pas être complète : on prend la
#: FORME, et la citation (guillemets, backticks, « > ») porte les emplois légitimes.
BANNIES = {
    r"\bj'\w+": "récit d'enquête à la première personne",
    r"\bje\s+\w+": "récit d'enquête à la première personne",
    r"\bmoi-même\b": "récit d'enquête à la première personne",
    r"\b(?:mon|ma|mes)\s+\w+": "possessif de session — une mesure appartient au dépôt, "
                               "pas à qui l'a faite",
    r"\bnous\s+(?:avons|allons|devons|avions)\b": "« nous » de conversation",
    r"\bcomme (?:vous|tu) (?:l'|me |m')": "adresse directe à un interlocuteur",
    r"\bcomme (?:demandé|convenu|discuté|promis)\b": "adresse directe à un interlocuteur",
    r"\b(?:vous|tu|votre) (?:avez|as|aviez|aurez|trouverez|verrez|noterez)\b":
        "adresse directe à un interlocuteur",
    r"\bmerci (?:de|pour)\b": "adresse directe à un interlocuteur",
    r"\b(?:notre|cette) session\b(?! gouvernée)": "chronologie de session comme fil narratif",
    # `hier` en message de commit est TOUJOURS de la chronologie : un lecteur public n'a aucun
    # repère pour l'interpréter. `aujourd'hui` N'EST PAS banni — il dit « à l'état actuel du
    # code », dans 8 emplois sur 9 relevés dans cet historique. L'asymétrie est mesurée.
    r"\b(?:d')?hier\b": "chronologie de session — un lecteur public n'a pas ce repère",
    r"\bdans (?:ma|notre) (?:dernière |précédente )?(?:réponse|conversation)\b":
        "renvoi à une conversation",
}

#: Lignes ignorées : trailers d'attribution et citations (une règle qui cite la mauvaise forme).
_IGNORE_LIGNE = re.compile(
    r"^\s*(?:>|Co-Authored-By:|Signed-off-by:|Claude-Session:|Reviewed-by:|Cc:)", re.I)

#: Une occurrence CITÉE énonce la forme au lieu de la commettre. Bornée au paragraphe : un
#: guillemet orphelin exempterait sinon tout le texte jusqu'au suivant.
_GUILLEMETS = re.compile(r"«(?:[^»\n]|\n(?!\s*\n))*»")
_CODE = re.compile(r"`[^`\n]+`")


def _spans_cites(texte):
    """Intervalles d'index relevant d'une citation. Pur, ne lève jamais."""
    return ([m.span() for m in _GUILLEMETS.finditer(texte)] +
            [m.span() for m in _CODE.finditer(texte)])


def fautes_de_message(texte):
    """[(ligne, motif, raison)] — les tournures interdites d'un message. Pur, ne lève jamais.

    Les spans cités sont calculés sur le texte ENTIER, pas ligne à ligne : une citation se replie
    d'une ligne sur l'autre, et découper d'abord ferait manquer sa seconde moitié."""
    texte = str(texte or "")
    spans = _spans_cites(texte)
    out, debut = [], 0
    for i, ligne in enumerate(texte.splitlines(keepends=True), start=1):
        if not _IGNORE_LIGNE.match(ligne):
            for motif, raison in BANNIES.items():
                for m in re.finditer(motif, ligne, re.I):
                    pos = debut + m.start()
                    if not any(a <= pos < b for a, b in spans):
                        out.append((i, m.group(0), raison))
        debut += len(ligne)
    return out


def faute_d_identite(nom, email):
    """Raison du refus d'une identité, ou None. Pur, ne lève jamais.

    Le libellé ne nomme PAS le slot : cette fonction ne sait pas si elle juge un auteur ou un
    committer, et le lui faire dire produisait « IDENTITÉ (committer) : auteur « … » »."""
    nom, email = str(nom or "").strip(), str(email or "").strip().lower()
    if nom != NOM_ATTENDU:
        return (f"nom « {nom} » — attendu « {NOM_ATTENDU} ». Un dépôt publié sous un collectif "
                f"ne doit pas exposer le compte personnel de qui l'écrit.")
    if not email.endswith(DOMAINE_ATTENDU):
        return (f"adresse « {email} » — attendue sous « {DOMAINE_ATTENDU} ». Aucune adresse "
                f"personnelle ni nominative.")
    return None


def _git(*args):
    """(code, stdout, stderr) de git. Le code de retour n'est PAS jetable.

    Une barrière doit échouer FERMÉE. En rendant seulement `stdout`, un `git log` qui échoue
    donnait une sortie vide, donc « aucune faute », donc un succès — la CI validait alors une
    plage qu'elle n'avait jamais lue. Les appelants qui prononcent un refus lisent le code."""
    p = subprocess.run(["git", *args], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def verifier_revisions(plage, une_seule=False):
    """Vérifie chaque commit d'une plage (`base..head`), ou UN commit si `une_seule`.

    `une_seule` existe parce que `git log HEAD` liste TOUT l'historique atteignable, pas le seul
    commit visé : sans `-1`, un contrôle « ce commit est-il conforme ? » rendait le verdict de
    l'historique entier. Rend la liste des lignes de refus, vide si tout passe."""
    sep = "\x1e"
    champs = ["%H", "%an", "%ae", "%cn", "%ce", "%B"]
    args = ["log", "--format=" + sep.join(champs) + "\x1d"]
    if une_seule:
        args.append("-1")
    args.append(plage)
    code, brut, err = _git(*args)
    if code != 0:
        motif = err.strip().splitlines()[0] if err.strip() else "sans message"
        return [f"PLAGE ILLISIBLE « {plage} » — git a refusé : {motif}. "
                f"Rien n'a été vérifié : ce refus est délibéré, une barrière échoue FERMÉE."]
    refus = []
    for bloc in brut.split("\x1d"):
        if not bloc.strip():
            continue
        parts = bloc.strip().split(sep)
        if len(parts) < len(champs):
            continue
        sha = parts[0][:8]
        corps = sep.join(parts[len(champs) - 1:])
        # Les DEUX slots, pas seulement l'auteur : un `cherry-pick`, un `rebase` ou l'édition via
        # l'interface web laissent l'auteur intact et écrivent une AUTRE identité en committer.
        # C'est par cette porte que des commits à compte personnel sont entrés dans ce dépôt.
        for role, nom, email in (("auteur", parts[1], parts[2]),
                                 ("committer", parts[3], parts[4])):
            mauvaise = faute_d_identite(nom, email)
            if mauvaise:
                refus.append(f"{sha} — IDENTITÉ ({role}) : {mauvaise}")
        for ligne, extrait, raison in fautes_de_message(corps):
            refus.append(f"{sha}:{ligne} — REGISTRE ({raison}) : « {extrait} »")
    return refus


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--message-file", help="fichier de message (hook commit-msg)")
    g.add_argument("--range", dest="plage", help="plage de commits, ex origin/main..HEAD")
    g.add_argument("--rev", help="une révision précise")
    args = ap.parse_args(argv)

    if args.message_file:
        with open(args.message_file, encoding="utf-8", errors="replace") as f:
            texte = f.read()
        refus = [f"ligne {ln} — REGISTRE ({raison}) : « {ex} »"
                 for ln, ex, raison in fautes_de_message(texte)]
        # Une clé absente rend un code non nul et une sortie vide : `faute_d_identite` refuse
        # alors le nom vide, ce qui est le comportement voulu — non configuré = non conforme.
        mauvaise = faute_d_identite(_git("config", "user.name")[1].strip(),
                                    _git("config", "user.email")[1].strip())
        if mauvaise:
            refus.append(f"IDENTITÉ : {mauvaise}")
    else:
        refus = verifier_revisions(args.plage or args.rev, une_seule=bool(args.rev))

    if not refus:
        return 0
    print("Commit refusé — un dépôt public s'adresse à un LECTEUR, pas à un interlocuteur.",
          file=sys.stderr)
    print("Règle : ROADMAP.md § Gouvernance, et CONTRIBUTING.md (checklist).\n", file=sys.stderr)
    for r in refus:
        print(f"  {r}", file=sys.stderr)
    print("\nCe qui reste ADMIS : la voix de l'outil (« un `skipped` dit je n'ai PAS pu vérifier »), "
          "une date de mesure, et un « pourquoi » long. La longueur n'est pas le défaut.",
          file=sys.stderr)
    print("Si c'est bien la voix de l'outil ou une CITATION de la mauvaise forme, préfixez la ligne "
          "de « > » : ce garde lit des formes, pas des intentions, et ne sait pas qui parle.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

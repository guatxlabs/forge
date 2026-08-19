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
BANNIES = {
    r"\bj'ai (?:trouvé|corrigé|mesuré|vérifié|conclu|écarté|commencé|décidé)\b":
        "récit d'enquête à la première personne",
    r"\bj'avais\b": "récit d'enquête à la première personne",
    r"\bmoi-même\b": "récit d'enquête à la première personne",
    r"\bma (?:contre-vérification|mesure|conclusion)\b": "récit d'enquête à la première personne",
    r"\bje (?:consigne|préfère|pense|crois|vais|voulais)\b": "récit à la première personne",
    r"\bcomme (?:vous|tu) (?:l'|me |m')": "adresse directe à un interlocuteur",
    r"\bcomme demandé\b": "adresse directe à un interlocuteur",
    r"\b(?:vous|votre) (?:avez|aviez|aurez|trouverez)\b": "adresse directe à un interlocuteur",
    r"\bmerci (?:de|pour)\b": "adresse directe à un interlocuteur",
    r"\b(?:notre|cette) session\b(?! gouvernée)": "chronologie de session comme fil narratif",
    r"\bdans (?:ma|notre) (?:dernière |précédente )?(?:réponse|conversation)\b":
        "renvoi à une conversation",
}

#: Lignes ignorées : trailers d'attribution et citations (une règle qui cite la mauvaise forme).
_IGNORE_LIGNE = re.compile(
    r"^\s*(?:>|Co-Authored-By:|Signed-off-by:|Claude-Session:|Reviewed-by:|Cc:)", re.I)


def fautes_de_message(texte):
    """[(ligne, motif, raison)] — les tournures interdites d'un message. Pur, ne lève jamais."""
    out = []
    for i, ligne in enumerate(str(texte or "").splitlines(), start=1):
        if _IGNORE_LIGNE.match(ligne):
            continue
        for motif, raison in BANNIES.items():
            for m in re.finditer(motif, ligne, re.I):
                out.append((i, m.group(0), raison))
    return out


def faute_d_identite(nom, email):
    """Raison du refus d'une identité d'auteur, ou None. Pur, ne lève jamais."""
    nom, email = str(nom or "").strip(), str(email or "").strip().lower()
    if nom != NOM_ATTENDU:
        return (f"auteur « {nom} » — attendu « {NOM_ATTENDU} ». Un dépôt publié sous un collectif "
                f"ne doit pas exposer le compte personnel de son auteur.")
    if not email.endswith(DOMAINE_ATTENDU):
        return (f"adresse « {email} » — attendue sous « {DOMAINE_ATTENDU} ». Aucune adresse "
                f"personnelle ni nominative.")
    return None


def _git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True).stdout


def verifier_revisions(plage):
    """Vérifie chaque commit d'une plage (`base..head`) ou une révision unique. Rend la liste des
    lignes de refus, vide si tout passe."""
    sep = "\x1e"
    brut = _git("log", "--format=%H" + sep + "%an" + sep + "%ae" + sep + "%B" + "\x1d", plage)
    refus = []
    for bloc in brut.split("\x1d"):
        if not bloc.strip():
            continue
        parts = bloc.strip().split(sep)
        if len(parts) < 4:
            continue
        sha, nom, email, corps = parts[0][:8], parts[1], parts[2], sep.join(parts[3:])
        mauvaise = faute_d_identite(nom, email)
        if mauvaise:
            refus.append(f"{sha} — IDENTITÉ : {mauvaise}")
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
        mauvaise = faute_d_identite(_git("config", "user.name").strip(),
                                    _git("config", "user.email").strip())
        if mauvaise:
            refus.append(f"IDENTITÉ : {mauvaise}")
    else:
        refus = verifier_revisions(args.plage or args.rev)

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
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Interdit l'octet NUL non déclaré dans un fichier suivi par git.

POURQUOI (mesuré, pas supposé). `console/src/common.rs` contenait UN octet NUL, dans un
commentaire de doc qui illustrait un vecteur d'injection CSV. Conséquence constatée sur ce
dépôt : `file` classait le fichier en `data`, et `grep` SANS `-a` retournait 1 (aucune
correspondance) sur un motif POURTANT présent 9 fois. Autrement dit, tout balayage de secrets
par grep — le nôtre, celui d'un contributeur, celui d'un auditeur externe — sautait ce fichier
EN SILENCE. Un secret déposé là n'aurait été vu par personne.

LA GARDE EST DÉRIVÉE, PAS ÉNUMÉRÉE. On ne vérifie pas « common.rs est propre » : on part de la
partition FERMÉE de tous les fichiers suivis, et on exige que chacun soit dans l'un des deux
états suivants — donc un fichier AJOUTÉ demain est couvert par construction :

  (A) il ne contient aucun octet NUL, ou
  (B) il est DÉCLARÉ binaire dans `.gitattributes`.

Un binaire légitime (police, image) tombe en (B) : le déclarer est un geste explicite, versionné
et relu, au lieu d'un saut silencieux. Ajouter un binaire sans le déclarer fait rougir (A).

ANTI-CONTOURNEMENT (leg B'). Sans plus, la garde se désarme en une ligne : `*.rs binary` dans
`.gitattributes` ferait passer n'importe quel NUL. On exige donc aussi la réciproque : tout
fichier déclaré binaire DOIT réellement contenir un NUL. Une déclaration en joker sur du code
source rougit alors sur tous les fichiers de code qui, eux, n'en contiennent pas.

RÉSIDU ASSUMÉ, écrit et non masqué : une déclaration NOMMÉE et ciblée (`chemin/exact.rs binary`)
passe les deux jambes. C'est voulu — elle est alors visible dans un fichier relu, ce qui en fait
un acte conscient et auditable, et non plus un angle mort. La garde supprime le silence, pas la
possibilité d'une décision explicite.

Usage :  python3 scripts/check_no_stray_nul.py [--repo CHEMIN]
Sortie :  0 = sain ; 1 = violation (message nommant chaque fichier et la jambe violée).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def tracked_files(repo: Path) -> list[str]:
    """Les chemins suivis par git, découpés sur NUL (`-z`) pour survivre aux noms exotiques."""
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"],
        capture_output=True,
        check=True,
    ).stdout
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def declared_binary(repo: Path, paths: list[str]) -> set[str]:
    """Les chemins que `.gitattributes` déclare binaires.

    On interroge git lui-même (`check-attr`) plutôt que de parser `.gitattributes` : les règles
    de précédence, les jokers et la macro `binary` (qui pose `-text -diff -merge`) sont ainsi
    évalués par l'implémentation de référence et non par une réécriture approximative.
    Un fichier compte comme déclaré binaire si `text` est `unset` (c'est ce que posent `binary`
    et `-text`).
    """
    if not paths:
        return set()
    stdin = "\0".join(paths).encode("utf-8", "surrogateescape")
    out = subprocess.run(
        ["git", "-C", str(repo), "check-attr", "--stdin", "-z", "text"],
        input=stdin,
        capture_output=True,
        check=True,
    ).stdout
    # `-z` produit un flux plat de triplets : chemin, NOM_ATTRIBUT, VALEUR.
    parts = out.split(b"\0")
    declared: set[str] = set()
    for i in range(0, len(parts) - 2, 3):
        path = parts[i].decode("utf-8", "surrogateescape")
        value = parts[i + 2]
        if value == b"unset":
            declared.add(path)
    return declared


def has_nul(repo: Path, rel: str) -> bool | None:
    """True/False, ou None si le fichier est illisible (lien mort, submodule)."""
    try:
        with open(repo / rel, "rb") as fh:
            while chunk := fh.read(1 << 20):
                if b"\x00" in chunk:
                    return True
        return False
    except (IsADirectoryError, FileNotFoundError, PermissionError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".", help="racine du dépôt (défaut : répertoire courant)")
    args = ap.parse_args()
    repo = Path(args.repo).resolve()

    paths = tracked_files(repo)
    declared = declared_binary(repo, paths)

    undeclared_nul: list[str] = []   # jambe A
    declared_but_text: list[str] = []  # jambe B'
    unreadable: list[str] = []

    for rel in paths:
        nul = has_nul(repo, rel)
        if nul is None:
            unreadable.append(rel)
            continue
        if nul and rel not in declared:
            undeclared_nul.append(rel)
        elif not nul and rel in declared:
            declared_but_text.append(rel)

    print(f"[nul-guard] {len(paths)} fichiers suivis, {len(declared)} déclarés binaires")

    if unreadable:
        # Non fatal, mais JAMAIS silencieux : un fichier non lu n'est pas un fichier propre.
        print(f"[nul-guard] {len(unreadable)} fichier(s) illisible(s), donc NON vérifié(s) :")
        for rel in unreadable:
            print(f"    ? {rel}")

    if undeclared_nul:
        print(
            "\n[nul-guard] ÉCHEC (A) — octet NUL dans un fichier NON déclaré binaire.\n"
            "  `grep` sans `-a` saute ce fichier EN SILENCE : tout balayage de secrets\n"
            "  l'ignore, et un secret déposé là ne serait vu par personne.\n"
            "  Corriger le contenu (échapper le NUL, p. ex. `\\x00` dans un commentaire),\n"
            "  ou déclarer le fichier binaire dans `.gitattributes` si c'en est un :"
        )
        for rel in undeclared_nul:
            print(f"    - {rel}")

    if declared_but_text:
        print(
            "\n[nul-guard] ÉCHEC (B') — fichier déclaré binaire mais qui est du texte.\n"
            "  Une déclaration en joker (p. ex. `*.rs binary`) désarmerait la jambe (A)\n"
            "  sur tout un type de fichier. Resserrer `.gitattributes` sur les vrais binaires :"
        )
        for rel in declared_but_text:
            print(f"    - {rel}")

    if undeclared_nul or declared_but_text:
        return 1

    print("[nul-guard] OK — aucun octet NUL non déclaré, aucune déclaration trop large")
    return 0


if __name__ == "__main__":
    sys.exit(main())

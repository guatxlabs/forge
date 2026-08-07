#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mesure l'invariant « zéro bibliothèque système de crypto/TLS » sur les périmètres où il est ÉNONCÉ.

POURQUOI CETTE GARDE EXISTE (défaut réel, mesuré, pas supposé). Le dépôt affirmait partout une
« openssl-freedom » NON PÉRIMÉTRÉE — le binaire console n'embarque ni `openssl`, ni `native-tls`,
ni `aws-lc`, ni `schannel`, ni `security-framework`. Mesure du 2026-08-07 avec la commande de
contrôle publiée dans `docs/DEPLOYMENT.md` :

    (défaut)                    ->  0   l'affirmation tient
    --features store-postgres   ->  0   l'affirmation tient
    --features object-store     -> 12   l'affirmation est FAUSSE
    --all-features              -> 20   l'affirmation est FAUSSE

La chaîne est TRANSITIVE et n'est pas réparable dans ce dépôt sans fork ni patch :

    object-store -> rust-s3 (`sync-rustls-tls`) -> attohttpc (`tls-rustls`) -> `__rustls`
                 -> rustls/DEFAULT -> aws-lc-rs -> aws-lc-sys

`attohttpc` déclare pourtant `rustls` en `default-features = false` — mais sa feature interne
`__rustls`, seule porte d'entrée de `tls-rustls`, réactive explicitement `rustls/default`, dont le
provider par défaut est `aws-lc-rs`. `attohttpc` expose bien une variante `-ring`
(`tls-rustls-webpki-roots-ring`), mais `rust-s3/sync-rustls-tls` câble en dur `attohttpc/tls-rustls` :
on ne peut pas l'atteindre, et l'ajouter en plus ne retirerait rien (les features cargo sont
ADDITIVES). Pire, l'unification de features propage ensuite `aws-lc-rs` à TOUTES les instances de
`rustls` du graphe — y compris la nôtre, épinglée `default-features = false, features = ["ring"]`
(le code appelle toujours `rustls::crypto::ring::default_provider()` EXPLICITEMENT, mais
`aws-lc-sys` est bel et bien compilé et lié).

La décision prise a été de CORRIGER L'AFFIRMATION, pas de pourchasser la dépendance : un invariant
énoncé trop largement est un défaut de véracité plus grave que la dépendance elle-même. Mais une
affirmation corrigée dans la doc se re-périme en silence à la première dépendance ajoutée. D'où
cette garde : elle MESURE, elle n'affirme pas.

CE QUE LA GARDE EXIGE, ET CE QU'ELLE N'EXIGE PAS. Elle exige 0 sur les périmètres CONTRACTUELS
(défaut, `store-postgres`) et échoue en nommant le périmètre cassé ET la dépendance fautive. Elle
n'exige RIEN de `--all-features` : c'est le périmètre EXCLU, connu et documenté — mais elle en
AFFICHE le compte à chaque exécution, pour que l'exclusion reste visible plutôt qu'oubliée.

ELLE PROUVE QU'ELLE MORD (`--self-test-red`). Un garde-fou incapable d'échouer est un décor. Le
périmètre exclu est ici un TÉMOIN POSITIF gratuit : il est connu sale. `--self-test-red` mesure ce
périmètre-là EN L'EXIGEANT propre, donc la garde DOIT rougir ; l'auto-test rend 0 quand elle a bien
mordu et 1 quand elle ne mord plus. Câblé en CI, il transforme en rouge le jour où la détection se
casse (regex morte, format de `cargo tree` changé) — au lieu d'un vert silencieux partout. Un
détecteur qui ne détecte plus rien serait, sinon, indiscernable d'un dépôt sain.

FAIL-CLOSED. Un `cargo tree` en échec, une sortie implausible (arbre tronqué), ou un auto-test du
comparateur qui ne reconnaît plus une ligne fautive de référence rendent 2 — jamais 0. Un contrôle
qui n'a rien pu contrôler n'est pas vert : c'est une sonde cassée.

Usage :
    python3 scripts/check_openssl_freedom.py                    # les périmètres contractuels
    python3 scripts/check_openssl_freedom.py --self-test-red    # prouve que la garde MORD
    python3 scripts/check_openssl_freedom.py --perimeter object-store --expect-clean
    python3 scripts/check_openssl_freedom.py --perimeter store-postgres

Codes de sortie :
    0 = invariant tenu (ou, sous `--self-test-red`, garde ayant correctement mordu)
    1 = invariant VIOLÉ (ou, sous `--self-test-red`, garde devenue muette)
    2 = sonde inutilisable (cargo indisponible/en échec, sortie implausible, comparateur muet)
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------------------------
# LA DÉFINITION de l'invariant. Ces cinq motifs SONT le contrat — ce sont exactement ceux de la
# commande de contrôle publiée dans `docs/DEPLOYMENT.md`. Les modifier, c'est modifier l'invariant :
# le faire volontairement, jamais pour faire taire un rouge.
#   openssl / native-tls          -> bibliothèque système à installer, versionner, patcher
#   aws-lc                        -> BoringSSL vendu par le crate, mais toolchain C/cmake au build
#   schannel / security-framework -> magasin d'AC de l'OS (Windows / macOS)
# ---------------------------------------------------------------------------------------------
INTERDITS = ("openssl", "native-tls", "aws-lc", "schannel", "security-framework")
MOTIF = re.compile("|".join(re.escape(m) for m in INTERDITS), re.IGNORECASE)

# Le comparateur doit se prouver VIVANT avant de rendre un verdict. Ces lignes sont des extraits
# RÉELS de `cargo tree` (mesure du 2026-08-07) ; si le motif cesse d'y répondre, la sonde est
# cassée et rendre « 0 occurrence » serait un mensonge. Le contre-exemple garantit qu'on ne rend
# pas non plus « tout est fautif » (un motif dégénéré en `.*` passerait la jambe positive).
TEMOINS_FAUTIFS = (
    "│   │   │   ├── aws-lc-rs v1.17.3",
    "│   │   │   │   ├── aws-lc-sys v0.43.0",
    "├── openssl-sys v0.9.109",
    "├── native-tls v0.2.14",
    "├── schannel v0.1.27",
    "├── security-framework v3.5.1",
)
TEMOINS_SAINS = (
    "├── ring v0.17.14",
    "├── rustls v0.23.42",
    "├── webpki-roots v1.0.4",
    "└── rusqlite v0.37.0",
)

# Un arbre de dépendances plausible pour ce crate fait des milliers de lignes (mesuré : > 10 000
# même sur le build par défaut, `--no-dedupe` développant chaque occurrence). Une sortie courte
# signifie que cargo a rendu autre chose qu'un arbre — on refuse de conclure dessus.
LIGNES_MINIMUM = 200

# ---------------------------------------------------------------------------------------------
# LES PÉRIMÈTRES. `exige_propre=True` = l'invariant est ÉNONCÉ ici, il DOIT tenir.
# `exige_propre=False` = périmètre EXCLU : mesuré et AFFICHÉ à chaque run, jamais exigé.
# Le périmètre exclu sert aussi de TÉMOIN POSITIF à `--self-test-red` (cf. docstring).
# ---------------------------------------------------------------------------------------------
PERIMETRES: dict[str, dict] = {
    "default": {
        "libelle": "(build par défaut)",
        "flags": [],
        "exige_propre": True,
        "note": "le binaire community livré",
    },
    "store-postgres": {
        "libelle": "--features store-postgres",
        "flags": ["--features", "store-postgres"],
        "exige_propre": True,
        "note": "backend PG : rustls/ring + webpki-roots, pile partagée avec le défaut",
    },
    "object-store": {
        "libelle": "--features object-store",
        "flags": ["--features", "object-store"],
        "exige_propre": False,
        "note": "EXCLU — rust-s3 -> attohttpc -> rustls/default -> aws-lc (transitif)",
    },
    "all-features": {
        "libelle": "--all-features",
        "flags": ["--all-features"],
        "exige_propre": False,
        "note": "EXCLU — contient object-store ; l'unification propage aws-lc à tout le graphe",
    },
}

# Contrat par défaut : ce qu'on EXIGE, et ce qu'on se contente d'AFFICHER.
CONTRAT = ["default", "store-postgres"]
EXCLUS_AFFICHES = ["object-store", "all-features"]

# Le périmètre connu sale qui sert de témoin à `--self-test-red`. Le plus large : si l'invariant y
# redevenait vrai, c'est que la chaîne a été réparée en amont — bonne nouvelle qui EXIGE de retirer
# l'exclusion de la doc, donc l'auto-test rougit pour le dire.
PERIMETRE_TEMOIN = "all-features"


def _console_dir(depot: Path) -> Path:
    """Le crate console — le seul crate Rust du dépôt, donc la seule fermeture à mesurer."""
    return depot / "console"


def cargo_tree(depot: Path, flags: list[str], inverse: str | None = None) -> tuple[int, str, str]:
    """Lance `cargo tree` sur le crate console. `inverse` bascule en mode `-i <crate>`.

    `--locked` est délibéré : la garde MESURE l'arbre verrouillé, elle ne doit jamais réécrire
    `Cargo.lock` au passage (une garde qui modifie ce qu'elle mesure n'en est pas une).
    `-e normal,build` = ce qui entre réellement dans le binaire et dans sa compilation ; les
    dev-dependencies sont hors périmètre (elles ne sont pas livrées). `--no-dedupe` développe
    chaque occurrence : le compte est celui de la commande de contrôle publiée.
    """
    cmd = ["cargo", "tree", "-e", "normal,build", "--locked"]
    if inverse:
        cmd += ["-i", inverse]
    else:
        cmd += ["--no-dedupe"]
    cmd += flags
    proc = subprocess.run(
        cmd,
        cwd=str(_console_dir(depot)),
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def auto_test_comparateur() -> str | None:
    """Prouve que le motif reconnaît une ligne fautive de référence ET épargne une ligne saine.

    Rend `None` si le comparateur est vivant, sinon le message d'échec. Sans cette jambe, une
    regex cassée rendrait « 0 occurrence » sur TOUS les périmètres et la garde passerait au vert
    en annonçant exactement le contraire de la réalité.
    """
    muets = [ligne for ligne in TEMOINS_FAUTIFS if not MOTIF.search(ligne)]
    if muets:
        return (
            "le motif ne reconnaît plus des lignes POURTANT fautives :\n    "
            + "\n    ".join(muets)
        )
    bavards = [ligne for ligne in TEMOINS_SAINS if MOTIF.search(ligne)]
    if bavards:
        return (
            "le motif marque comme fautives des lignes SAINES (motif trop large) :\n    "
            + "\n    ".join(bavards)
        )
    return None


def mesurer(depot: Path, cle: str) -> tuple[int, list[str]]:
    """Compte les occurrences interdites sur un périmètre. Lève `RuntimeError` si la sonde casse."""
    spec = PERIMETRES[cle]
    code, sortie, err = cargo_tree(depot, spec["flags"])
    if code != 0:
        raise RuntimeError(
            f"`cargo tree` a échoué sur le périmètre « {spec['libelle']} » (code {code}) :\n"
            + (err.strip() or "(aucune sortie d'erreur)")
        )
    lignes = sortie.splitlines()
    if len(lignes) < LIGNES_MINIMUM:
        raise RuntimeError(
            f"sortie implausible sur « {spec['libelle']} » : {len(lignes)} ligne(s) "
            f"(< {LIGNES_MINIMUM}). L'arbre n'a pas été produit — refus de conclure."
        )
    fautives = [ligne for ligne in lignes if MOTIF.search(ligne)]
    return len(fautives), fautives


def crates_fautifs(lignes: list[str]) -> list[str]:
    """Extrait `nom vX.Y.Z` des lignes fautives, dédupliqué et trié — le QUOI, lisible."""
    trouves = set()
    for ligne in lignes:
        m = re.search(r"([A-Za-z0-9_.-]+)\s+(v[0-9][^\s()]*)", ligne)
        if m:
            trouves.add(f"{m.group(1)} {m.group(2)}")
        else:  # ligne fautive mais illisible : la montrer telle quelle plutôt que la perdre
            trouves.add(ligne.strip())
    return sorted(trouves)


def expliquer(depot: Path, cle: str, lignes: list[str]) -> None:
    """Imprime QUI introduit chaque crate fautif — le POURQUOI, sans quoi le rouge est inactionnable."""
    spec = PERIMETRES[cle]
    for entree in crates_fautifs(lignes):
        nom = entree.split(" ", 1)[0]
        code, sortie, _ = cargo_tree(depot, spec["flags"], inverse=nom)
        if code != 0 or not sortie.strip():
            print(f"    {entree} — chaîne d'introduction indisponible (`cargo tree -i {nom}`)")
            continue
        print(f"    ── qui tire {entree} :")
        for ligne in sortie.splitlines():
            print(f"       {ligne}")


def _erreur(msg: str) -> None:
    """Écrit sur stderr APRÈS avoir vidé stdout — sinon le rouge se mélange au tableau quand la
    sortie est redirigée (stdout bufferisé par bloc, stderr non), et le rapport devient illisible."""
    sys.stdout.flush()
    print(msg, file=sys.stderr)
    sys.stderr.flush()


def afficher_tableau(resultats: list[tuple[str, int, bool]]) -> None:
    largeur = max(len(PERIMETRES[c]["libelle"]) for c, _, _ in resultats)
    print(f"\n  {'périmètre'.ljust(largeur)}   hits   verdict")
    print("  " + "-" * (largeur + 32))
    for cle, hits, exige in resultats:
        spec = PERIMETRES[cle]
        if not exige:
            verdict = "EXCLU (documenté, non exigé)"
        else:
            verdict = "OK (exigé : 0)" if hits == 0 else "ÉCHEC (exigé : 0)"
        print(f"  {spec['libelle'].ljust(largeur)}   {str(hits).rjust(4)}   {verdict}")
    print()


def main() -> int:
    parseur = argparse.ArgumentParser(
        description=(
            "Mesure l'invariant « zéro bibliothèque système de crypto/TLS » (ni openssl, ni "
            "native-tls, ni aws-lc, ni schannel, ni security-framework) dans la fermeture de "
            "dépendances du crate console, PAR PÉRIMÈTRE de features."
        ),
        epilog=(
            "Exemples :\n"
            "  python3 scripts/check_openssl_freedom.py\n"
            "  python3 scripts/check_openssl_freedom.py --self-test-red\n"
            "  python3 scripts/check_openssl_freedom.py --perimeter object-store --expect-clean\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parseur.add_argument(
        "--repo",
        default=str(Path(__file__).resolve().parent.parent),
        help="racine du dépôt (défaut : le parent de scripts/)",
    )
    parseur.add_argument(
        "--perimeter",
        choices=sorted(PERIMETRES),
        help="ne mesurer QU'UN périmètre (par défaut : le contrat + les exclus, affichés)",
    )
    parseur.add_argument(
        "--expect-clean",
        action="store_true",
        help="avec --perimeter : EXIGER 0 même sur un périmètre normalement exclu",
    )
    parseur.add_argument(
        "--self-test-red",
        action="store_true",
        help=(
            f"auto-test : exige 0 sur le périmètre CONNU SALE ({PERIMETRES[PERIMETRE_TEMOIN]['libelle']}) "
            "et rend 0 SI ET SEULEMENT SI la garde a rougi — prouve qu'elle mord encore"
        ),
    )
    args = parseur.parse_args()

    depot = Path(args.repo).resolve()
    if not _console_dir(depot).joinpath("Cargo.toml").is_file():
        _erreur(f"[tls-closure] ÉCHEC (sonde) — pas de crate console sous {depot}")
        return 2
    if shutil.which("cargo") is None:
        _erreur("[tls-closure] ÉCHEC (sonde) — `cargo` introuvable sur le PATH")
        return 2

    # Jambe 1 : le comparateur doit se prouver vivant AVANT toute mesure.
    panne = auto_test_comparateur()
    if panne is not None:
        _erreur(f"[tls-closure] ÉCHEC (sonde) — auto-test du comparateur : {panne}")
        return 2

    # ---------------------------------------------------------------------------------------
    # Mode auto-test : on mesure le périmètre CONNU SALE en l'exigeant propre. La garde DOIT
    # rougir. Si elle ne rougit plus, elle est devenue un décor — ou la chaîne a été réparée en
    # amont, ce qui EXIGE de retirer l'exclusion de la documentation. Les deux cas veulent un
    # humain, donc les deux rendent 1.
    # ---------------------------------------------------------------------------------------
    if args.self_test_red:
        cle = PERIMETRE_TEMOIN
        libelle = PERIMETRES[cle]["libelle"]
        print(
            f"[tls-closure] AUTO-TEST — mesure de « {libelle} » (périmètre CONNU SALE) en "
            "l'EXIGEANT propre.\n              La garde doit ROUGIR ; un vert ici signifierait "
            "qu'elle ne détecte plus rien."
        )
        try:
            hits, lignes = mesurer(depot, cle)
        except RuntimeError as exc:
            _erreur(f"[tls-closure] ÉCHEC (sonde) — {exc}")
            return 2
        if hits == 0:
            _erreur(
                f"\n[tls-closure] AUTO-TEST EN ÉCHEC — 0 occurrence sur « {libelle} », qui est "
                "pourtant\n  le périmètre connu sale. Deux causes possibles, toutes deux à "
                "traiter par un humain :\n"
                "    (a) la détection est cassée -> la garde est un DÉCOR, la réparer ;\n"
                "    (b) la chaîne a été réparée en amont (rust-s3/attohttpc passés à rustls/ring)\n"
                "        -> excellente nouvelle, mais RETIRER l'exclusion de la doc et de ce script,\n"
                "           sinon le dépôt continue de documenter une réserve qui n'existe plus."
            )
            return 1
        print(f"\n[tls-closure] la garde a MORDU : {hits} occurrence(s) interdite(s) détectée(s).")
        print("  Ce qu'un contributeur verrait en rouge :")
        for entree in crates_fautifs(lignes):
            print(f"    - {entree}")
        expliquer(depot, cle, lignes)
        print(
            "[tls-closure] AUTO-TEST OK — la garde détecte et sait NOMMER la dépendance fautive.\n"
            "              (ce périmètre reste EXCLU du contrat : le run normal ne le fait pas "
            "échouer)"
        )
        return 0

    # ---------------------------------------------------------------------------------------
    # Mode normal (ou --perimeter ciblé).
    # ---------------------------------------------------------------------------------------
    if args.perimeter:
        a_mesurer = [(args.perimeter, args.expect_clean or PERIMETRES[args.perimeter]["exige_propre"])]
    else:
        a_mesurer = [(c, True) for c in CONTRAT] + [(c, False) for c in EXCLUS_AFFICHES]

    print(
        "[tls-closure] Invariant mesuré : aucune bibliothèque système de crypto/TLS dans la "
        "fermeture\n              du crate console — ni "
        + ", ".join(f"`{m}`" for m in INTERDITS)
        + f".\n              Sonde : cargo tree -e normal,build --no-dedupe --locked (crate "
        f"{_console_dir(depot)})"
    )

    resultats: list[tuple[str, int, bool]] = []
    casses: list[tuple[str, list[str]]] = []
    for cle, exige in a_mesurer:
        try:
            hits, lignes = mesurer(depot, cle)
        except RuntimeError as exc:
            _erreur(f"\n[tls-closure] ÉCHEC (sonde) — {exc}")
            return 2
        resultats.append((cle, hits, exige))
        if exige and hits:
            casses.append((cle, lignes))

    afficher_tableau(resultats)

    for cle, spec_note in ((c, PERIMETRES[c]["note"]) for c, _, exige in resultats if not exige):
        print(f"  · « {PERIMETRES[cle]['libelle']} » : {spec_note}")
    if any(not exige for _, _, exige in resultats):
        print(
            "    Les périmètres EXCLUS sont mesurés et affichés À DESSEIN — l'exclusion doit rester\n"
            "    visible. Ils ne font PAS échouer ce contrôle. Leur justification :\n"
            "    docs/DEPLOYMENT.md § « Périmètre de l'openssl-freedom ».\n"
        )

    if not casses:
        print(
            "[tls-closure] OK — l'invariant tient sur TOUS les périmètres où il est énoncé "
            f"({', '.join(PERIMETRES[c]['libelle'] for c, _, e in resultats if e)})."
        )
        return 0

    for cle, lignes in casses:
        spec = PERIMETRES[cle]
        _erreur(
            f"[tls-closure] ÉCHEC — périmètre « {spec['libelle']} » : {len(lignes)} occurrence(s)\n"
            "  interdite(s) dans la fermeture, là où l'invariant est ÉNONCÉ (exigé : 0)."
        )
        print("\n  Dépendance(s) fautive(s) :")
        for entree in crates_fautifs(lignes):
            print(f"    - {entree}")
        print("\n  Chaîne(s) d'introduction :")
        expliquer(depot, cle, lignes)
        print(
            "\n  Que faire :\n"
            "    1. si c'est une dép AJOUTÉE ici : l'épingler `default-features = false` sur un\n"
            "       provider `ring` (c'est ce que fait déjà `rustls` dans console/Cargo.toml) ;\n"
            "    2. si la chaîne est TRANSITIVE et non réparable sans fork : ce périmètre doit\n"
            "       SORTIR du contrat — l'ajouter aux exclus de ce script ET corriger la phrase\n"
            "       correspondante de docs/DEPLOYMENT.md. Ne jamais élargir les exclusions sans\n"
            "       corriger la doc : c'est exactement le défaut que cette garde répare.\n"
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())

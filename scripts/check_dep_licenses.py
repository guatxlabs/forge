#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mesure la conformité de LICENCE de la fermeture de dépendances RÉELLE — y compris le sous-arbre
que `cargo-deny` ne voit pas.

POURQUOI CETTE GARDE EXISTE (défaut réel, mesuré, pas supposé). `deny.toml` porte depuis le
2026-08-03 une réserve : le sous-arbre de la feature `object-store` « n'apparaît PAS dans le graphe
de cargo-deny, même avec --all-features », cause « non élucidée ». La cause est désormais élucidée,
et la conséquence était pire que la réserve ne le laissait croire.

LA CAUSE, ÉTABLIE PAR MUTATION (2026-08-07, cargo-deny 0.18.2, le binaire épinglé de la CI).
`cargo-deny` (via `krates`) perd une dépendance OPTIONNELLE dont le nom de PAQUET diffère du nom de
sa cible `[lib]`. `rust-s3` est exactement ce cas : paquet `rust-s3`, `[lib] name = "s3"`. Dans la
sortie de `cargo metadata`, l'arête porte le nom de LIB (`"name": "s3"`) alors que la feature
déclare le nom de PAQUET (`object-store = ["dep:rust-s3"]`) : l'arête n'est jamais appariée, la
feature est tenue pour désactivée, et TOUT ce qui pend dessous disparaît. Quatre mesures, un seul
facteur changé à chaque fois :

    manifeste réel   (`rust-s3` optional, `dep:rust-s3`)   --all-features -> 239 crates, sous-arbre ABSENT
    syntaxe implicite (`object-store = ["rust-s3"]`)       --all-features -> 239 crates, sous-arbre ABSENT
    dép NON optionnelle                                    (sans drapeau) -> 250 crates, sous-arbre PRÉSENT
    dép renommée `s3 = { package = "rust-s3" }`            --all-features -> 287 crates, sous-arbre PRÉSENT

Ce n'est donc NI `--all-features` (le drapeau porte : 201 -> 239, les optionnelles de
`store-postgres`/`encryption` entrent bien), NI la syntaxe `dep:`, NI les `targets` de `deny.toml`,
NI une exclusion explicite. `cargo metadata --all-features` voit, lui, les 290 crates du
`Cargo.lock` : l'écart naît dans `cargo-deny`, mais il est DÉCLENCHÉ par une propriété nommable du
manifeste — et c'est pourquoi il est réparable (cf. « CE QUI RESTE À FAIRE » plus bas).

CE QUI SE CACHAIT DEDANS — la réserve disait « leurs licences ne sont pas contrôlées », elle ne
disait pas que le contrôle aurait ÉCHOUÉ. 51 crates échappent, et deux d'entre eux ne satisfont pas
la liste `allow` de `deny.toml` telle qu'elle était écrite :

    attohttpc  0.30.1   MPL-2.0     (le client HTTP de rust-s3)
    tiny-keccak 2.0.2   CC0-1.0     (via aws-lc-rs)

Vérifié en rendant le sous-arbre visible (dép renommée) puis en lançant le cargo-deny de la CI avec
la `deny.toml` du dépôt : `licenses FAILED`, code 4, ces deux crates nommés. Autrement dit, le vert
que la CI affichait n'était pas « conforme » : c'était « pas regardé ». Pire, `deny.toml` justifiait
le RETRAIT de `MPL-2.0` de sa liste par « cargo-deny la signale non rencontrée, y compris toutes
features activées » — une mesure prise À TRAVERS l'angle mort, sur une licence bel et bien présente.

CE QUE CETTE GARDE FAIT. Elle refait le contrôle de licence sur la source que `cargo-deny` n'atteint
pas : `cargo metadata --all-features --locked`, qui rend les 290 crates du `Cargo.lock`. Elle
évalue l'expression SPDX de chaque crate contre la liste `allow` de `deny.toml` — LUE dans
`deny.toml`, pas recopiée : une seule vérité de politique, deux moteurs pour l'appliquer. Elle
n'est donc pas un doublon de `cargo-deny` : elle est ce qui couvre son angle mort, et elle le
NOMME à chaque exécution au lieu de le laisser en note enfouie.

CE QU'ELLE N'EST PAS. Elle ne remplace pas `cargo-deny` : `bans` (versions multiples, jokers) et
`sources` (provenance des registres/git) restent à lui. Elle ne dit rien des AVIS de sécurité —
c'est `cargo audit`, qui lit `Cargo.lock` et voit donc, lui, le sous-arbre entier.

ELLE PROUVE QU'ELLE MORD (`--self-test-red`). Un garde-fou incapable d'échouer est un décor. Le
témoin positif est gratuit et il tombe pile dans l'angle mort : on rejoue le contrôle en RETIRANT
de la liste les licences qui ne sont atteignables QUE sous `object-store` (`MPL-2.0`, `CC0-1.0`).
La garde DOIT alors rougir, ET nommer des crates que `cargo-deny` ne voit pas — sans quoi elle
n'aurait pas prouvé qu'elle atteint le sous-arbre. L'auto-test rend 0 quand elle a mordu, 1 sinon.

FAIL-CLOSED. `cargo metadata` en échec, sortie implausible, `deny.toml` illisible ou liste `allow`
vide, ou auto-test de l'évaluateur SPDX muet : code 2, jamais 0. Un contrôle qui n'a rien pu
contrôler n'est pas vert, c'est une sonde cassée.

CE QUI RESTE À FAIRE, ET QUI N'EST PAS DANS CE FICHIER. L'angle mort est réparable À LA SOURCE, en
une ligne de `console/Cargo.toml` : déclarer la dépendance sous le nom de sa lib —
`s3 = { package = "rust-s3", ... }` avec `object-store = ["dep:s3"]`. Mesuré : `cargo-deny` passe
alors de 239 à 287 crates et voit `rust-s3`, `attohttpc` et `aws-lc-sys`. Ce changement touche le
manifeste et le `Cargo.lock`, hors périmètre de la présente intervention : il est consigné dans
`deny.toml` et `docs/DEPLOYMENT.md` §3quater.2. Tant qu'il n'est pas fait, CETTE garde est le seul
contrôle qui lise les licences du sous-arbre `object-store`.

Usage :
    python3 scripts/check_dep_licenses.py                       # le contrôle
    python3 scripts/check_dep_licenses.py --self-test-red       # prouve que la garde MORD
    python3 scripts/check_dep_licenses.py --list                # + le détail crate par crate
    python3 scripts/check_dep_licenses.py --cargo-deny /tmp/cargo-deny   # + le différentiel exact

Codes de sortie :
    0 = toutes les licences de la fermeture satisfont `allow` (ou, sous `--self-test-red`, la garde
        a correctement mordu)
    1 = au moins une licence NON autorisée (ou, sous `--self-test-red`, garde devenue muette)
    2 = sonde inutilisable (cargo/metadata en échec, deny.toml illisible, évaluateur muet)
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None  # traité en fail-closed dans main()

# ---------------------------------------------------------------------------------------------
# Le graphe mesuré doit être PLAUSIBLE. Le `Cargo.lock` de ce dépôt épingle 290 crates ; une sortie
# beaucoup plus courte signifie que `cargo metadata` a rendu autre chose qu'un graphe résolu — on
# refuse de conclure dessus plutôt que d'annoncer « 0 violation » sur du vide.
# ---------------------------------------------------------------------------------------------
CRATES_MINIMUM = 150

# ---------------------------------------------------------------------------------------------
# AUTO-TEST DE L'ÉVALUATEUR SPDX. Ces expressions sont RÉELLES — relevées dans le graphe mesuré le
# 2026-08-07 — et sont évaluées contre une liste de RÉFÉRENCE FIGÉE, jamais contre la liste vivante
# de `deny.toml` : un auto-test qui suivrait la politique ne testerait plus rien le jour où la
# politique s'élargit. Sans cette jambe, un évaluateur cassé rendrait « tout satisfait » et la garde
# passerait au vert en annonçant exactement le contraire de la réalité ; le versant négatif
# garantit qu'on n'a pas non plus un évaluateur dégénéré qui refuse tout.
# ---------------------------------------------------------------------------------------------
REFERENCE_ALLOW = frozenset(
    {"MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause", "Unicode-3.0",
     "AGPL-3.0", "ISC"}
)
TEMOINS_SATISFAITS = (
    "MIT OR Apache-2.0",
    "MIT/Apache-2.0",                                    # syntaxe cargo héritée : `/` vaut OR
    "(MIT OR Apache-2.0) AND Unicode-3.0",
    "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
    "AGPL-3.0-or-later",                                 # `-or-later` couvert par la forme nue
    "Apache-2.0 AND ISC",
    # aws-lc-sys : sept conjonctions, dont quatre disjonctions imbriquées — le cas le plus dur du
    # graphe, et celui qui compte le plus (c'est le crate au code C vendu).
    "ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND "
    "(Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)",
)
TEMOINS_REFUSES = (
    "MPL-2.0",                     # attohttpc — le crate que cargo-deny ne voit pas
    "CC0-1.0",                     # tiny-keccak — idem
    "GPL-2.0-only",
    "MIT-0",                       # NE doit PAS être satisfait par `MIT` : identifiant distinct
    "ISC AND MPL-2.0",             # un AND ne se satisfait pas d'un seul membre
    "LGPL-3.0-or-later",           # `-or-later` ne doit pas inventer une autorisation absente
    "BSD-2-Clause",
)

# Les licences qui, sur ce graphe, ne sont atteignables QUE par le sous-arbre invisible à
# cargo-deny. `--self-test-red` les retire de la liste pour fabriquer le rouge : c'est le témoin
# positif le plus honnête possible, puisqu'il exige que la garde nomme précisément ce que l'outil
# officiel manque. Si ces licences disparaissent du graphe (rust-s3 réparé en amont, feature
# retirée), l'auto-test rougit — et c'est voulu : la réserve documentée devrait alors être retirée.
LICENCES_TEMOIN_ANGLE_MORT = ("MPL-2.0", "CC0-1.0")


# =============================================================================================
# Évaluateur d'expressions SPDX.
# Grammaire (précédence croissante) :  OR  <  AND  <  WITH  <  atome | ( … )
# =============================================================================================
_JETON = re.compile(r"\(|\)|[^\s()]+")


def _decouper(expression: str) -> list[str]:
    """Découpe une expression SPDX. `/` est traité comme `OR` (syntaxe cargo héritée, encore
    portée par 14 crates de ce graphe, p.ex. `MIT/Apache-2.0`)."""
    normalisee = expression.replace("/", " OR ")
    return _JETON.findall(normalisee)


class _Analyseur:
    def __init__(self, jetons: list[str]) -> None:
        self.jetons = jetons
        self.i = 0

    def _lire(self) -> str | None:
        return self.jetons[self.i] if self.i < len(self.jetons) else None

    def ou(self, autorise) -> bool:
        valeur = self.et(autorise)
        while (j := self._lire()) and j.upper() == "OR":
            self.i += 1
            # Pas de court-circuit : l'analyse doit consommer la totalité de l'expression, sinon
            # une expression mal formée passerait inaperçue derrière un `True` précoce.
            valeur = self.et(autorise) or valeur
        return valeur

    def et(self, autorise) -> bool:
        valeur = self.avec(autorise)
        while (j := self._lire()) and j.upper() == "AND":
            self.i += 1
            valeur = self.avec(autorise) and valeur
        return valeur

    def avec(self, autorise) -> bool:
        valeur, texte = self.atome(autorise)
        if (j := self._lire()) and j.upper() == "WITH":
            self.i += 1
            exception = self._lire()
            if exception is None:
                raise ValueError("`WITH` sans exception")
            self.i += 1
            # Une exception SPDX ne se déduit pas de sa licence de base : elle doit être autorisée
            # NOMMÉMENT (c'est la forme retenue par `deny.toml`, « Apache-2.0 WITH LLVM-exception »).
            return autorise(f"{texte} WITH {exception}")
        return valeur

    def atome(self, autorise) -> tuple[bool, str]:
        j = self._lire()
        if j is None:
            raise ValueError("expression tronquée")
        if j == "(":
            self.i += 1
            valeur = self.ou(autorise)
            if self._lire() != ")":
                raise ValueError("parenthèse fermante manquante")
            self.i += 1
            return valeur, ""
        if j in (")", "AND", "OR", "WITH"):
            raise ValueError(f"identifiant attendu, trouvé « {j} »")
        self.i += 1
        return autorise(j), j


def satisfait(expression: str, autorisees: frozenset[str] | set[str]) -> bool:
    """Vrai si `expression` est satisfaite par au moins une combinaison de licences autorisées.

    Règle d'appariement d'un identifiant, calquée sur cargo-deny :
      · correspondance exacte ;
      · une licence GNU écrite `X-or-later` / `X-only` est couverte par la forme NUE `X` de la
        liste (c'est pour cela que `deny.toml` écrit `AGPL-3.0` et non `AGPL-3.0-or-later` — il
        la REFUSE sous la forme longue) ;
      · le suffixe `+` (`Apache-2.0+`) est traité comme `-or-later`.
    L'inverse n'est PAS vrai : autoriser `X-or-later` ne couvre pas `X` nu, et `MIT` ne couvre
    jamais `MIT-0` — ce sont des identifiants distincts.
    """

    def autorise(identifiant: str) -> bool:
        if identifiant in autorisees:
            return True
        for suffixe in ("-or-later", "-only", "+"):
            if identifiant.endswith(suffixe):
                if identifiant[: -len(suffixe)] in autorisees:
                    return True
        return False

    analyseur = _Analyseur(_decouper(expression))
    valeur = analyseur.ou(autorise)
    if analyseur.i != len(analyseur.jetons):
        raise ValueError(f"jetons non consommés à partir de « {analyseur.jetons[analyseur.i]} »")
    return valeur


def auto_test_evaluateur() -> str | None:
    """Prouve que l'évaluateur reconnaît des expressions RÉELLES satisfaites ET en refuse d'autres.

    Rend `None` s'il est vivant, sinon le message d'échec.
    """
    muets = []
    for expression in TEMOINS_SATISFAITS:
        try:
            if not satisfait(expression, REFERENCE_ALLOW):
                muets.append(f"REFUSÉE à tort : {expression}")
        except ValueError as exc:
            muets.append(f"NON ANALYSÉE : {expression} ({exc})")
    for expression in TEMOINS_REFUSES:
        try:
            if satisfait(expression, REFERENCE_ALLOW):
                muets.append(f"ACCEPTÉE à tort : {expression}")
        except ValueError as exc:
            muets.append(f"NON ANALYSÉE : {expression} ({exc})")
    if muets:
        return "l'évaluateur SPDX ne répond plus comme mesuré :\n    " + "\n    ".join(muets)
    return None


# =============================================================================================
# Lecture de la POLITIQUE (deny.toml) et du GRAPHE (cargo metadata).
# =============================================================================================
def lire_allow(chemin: Path) -> list[str]:
    """Lit `[licenses] allow` dans `deny.toml`. La politique n'est PAS recopiée ici : une garde qui
    porterait sa propre liste divergerait silencieusement de celle que cargo-deny applique."""
    if tomllib is None:
        raise RuntimeError("module `tomllib` absent — Python 3.11+ requis pour lire deny.toml")
    if not chemin.is_file():
        raise RuntimeError(f"politique introuvable : {chemin}")
    with chemin.open("rb") as flux:
        config = tomllib.load(flux)
    allow = config.get("licenses", {}).get("allow")
    if not allow:
        raise RuntimeError(
            f"`[licenses] allow` absente ou vide dans {chemin} — refus de conclure : une liste "
            "vide ferait tout échouer OU, selon l'implémentation, tout passer."
        )
    return list(allow)


def cargo_metadata(depot: Path) -> dict:
    """Le graphe COMPLET, toutes features activées, sur le lock VERROUILLÉ.

    `--all-features` est ce qui fait entrer les dépendances `optional` ; `--locked` est délibéré :
    la garde MESURE le lock, elle ne doit jamais le réécrire au passage. C'est cette source-là que
    `cargo-deny` n'exploite pas entièrement — elle rend les 290 crates du `Cargo.lock`, sous-arbre
    `object-store` compris.
    """
    console = depot / "console"
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features", "--locked"],
        cwd=str(console),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        indice = ""
        if "was not used in the crate graph" in proc.stderr and "--locked" in proc.stderr:
            indice = (
                "\n\n  INDICE — c'est l'artefact LOCAL connu, pas un défaut du dépôt : le "
                "`console/.cargo/config.toml`\n  gitignoré du monorepo porte un `[patch]` vers le "
                "core local ; cargo veut alors écrire un bloc\n  `[[patch.unused]]` dans "
                "`Cargo.lock`, ce que `--locked` interdit — à raison, une garde ne doit pas\n"
                "  réécrire ce qu'elle mesure. Ce fichier est ABSENT en CI et d'un clone public, "
                "où le contrôle\n  tourne normalement. Pour le rejouer à la main : mesurer une "
                "copie propre du dépôt, p.ex.\n"
                "      git archive HEAD | tar -x -C \"$D\" && python3 "
                "\"$D/scripts/check_dep_licenses.py\" --repo \"$D\""
            )
        raise RuntimeError(
            f"`cargo metadata` a échoué (code {proc.returncode}) dans {console} :\n"
            + (proc.stderr.strip() or "(aucune sortie d'erreur)")
            + indice
        )
    try:
        metadata = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"`cargo metadata` n'a pas rendu du JSON : {exc}") from exc
    if len(metadata.get("packages", [])) < CRATES_MINIMUM:
        raise RuntimeError(
            f"graphe implausible : {len(metadata.get('packages', []))} crate(s) "
            f"(< {CRATES_MINIMUM}). Le graphe n'a pas été produit — refus de conclure."
        )
    return metadata


def angles_morts_structurels(metadata: dict) -> list[tuple[str, str, str, int]]:
    """Recense les arêtes que `cargo-deny` ne peut PAS apparier, et le poids de ce qu'elles cachent.

    LE MÉCANISME, tel que mesuré. Une feature déclare une dépendance optionnelle par son nom de
    PAQUET (`object-store = ["dep:rust-s3"]`). L'arête correspondante de `cargo metadata` porte,
    elle, le nom EXTERNE du crate — c'est-à-dire le nom de sa cible `[lib]` quand la dépendance
    n'est pas explicitement renommée. Quand les deux diffèrent, l'appariement par nom échoue, la
    feature est tenue pour désactivée, et TOUT ce qui pend sous l'arête disparaît du graphe.

    On lit donc les ARÊTES RÉSOLUES, pas la table `[lib]` : c'est exactement la donnée sur
    laquelle l'appariement se fait, et cela évite de signaler des déclarations qui n'entrent pas
    dans le graphe (mesuré : la règle naïve « nom de paquet != nom de lib » sortait `libredox ->
    redox_syscall`, alors que `libredox` n'est même pas dans la fermeture — un faux positif).
    Recenser plutôt qu'énumérer en dur, c'est couvrir PAR CONSTRUCTION la prochaine dépendance qui
    tombera dans le même piège.

    Rend `(paquet consommateur, paquet optionnel, nom porté par l'arête, nb de crates cachés)`.
    """
    par_id = {paquet["id"]: paquet for paquet in metadata["packages"]}
    noeuds = {noeud["id"]: noeud for noeud in metadata["resolve"]["nodes"]}
    racine = metadata["resolve"]["root"]

    def fermeture(arete_coupee: tuple[str, str] | None) -> set[str]:
        vus: set[str] = set()
        pile = [racine]
        while pile:
            identifiant = pile.pop()
            if identifiant in vus:
                continue
            vus.add(identifiant)
            for arete in noeuds[identifiant]["deps"]:
                if arete_coupee and (identifiant, arete["pkg"]) == arete_coupee:
                    continue
                pile.append(arete["pkg"])
        return vus

    complete = fermeture(None)
    trouves: list[tuple[str, str, str, int]] = []
    for identifiant in complete:
        paquet = par_id[identifiant]
        optionnelles = {
            dependance["name"]
            for dependance in paquet.get("dependencies", [])
            if dependance.get("optional") and dependance.get("rename") is None
        }
        for arete in noeuds[identifiant]["deps"]:
            cible = par_id[arete["pkg"]]["name"]
            if cible not in optionnelles:
                continue
            if arete["name"] == cible.replace("-", "_"):
                continue
            caches = len(complete - fermeture((identifiant, arete["pkg"])))
            trouves.append((paquet["name"], cible, arete["name"], caches))
    return sorted(set(trouves))


def crates_vus_par_cargo_deny(binaire: Path, depot: Path) -> set[str] | None:
    """Le jeu de crates que `cargo-deny` voit réellement, pour AFFICHER le différentiel exact.

    Optionnel : la garde ne dépend pas de cargo-deny pour rendre son verdict (il n'est pas installé
    sur un poste de dev). Quand il est là — c'est le cas en CI, le job `security` le télécharge —
    on montre le manque en chiffres et en NOMS, au lieu de le décrire dans une note.
    """
    proc = subprocess.run(
        [str(binaire), "--locked", "--all-features", "--manifest-path", "console/Cargo.toml",
         "list", "--config", str(depot / "deny.toml"), "--format", "tsv", "--layout", "crate"],
        cwd=str(depot),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    lignes = proc.stdout.splitlines()[1:]
    return {ligne.split("\t")[0].strip() for ligne in lignes if ligne.strip()}


def _erreur(message: str) -> None:
    """Écrit sur stderr APRÈS avoir vidé stdout — sinon le rouge se mélange au tableau quand la
    sortie est redirigée (stdout bufferisé par bloc, stderr non)."""
    sys.stdout.flush()
    print(message, file=sys.stderr)
    sys.stderr.flush()


def evaluer(metadata: dict, autorisees: set[str]) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Rend (violations, illisibles). Une violation = (nom, version, expression SPDX)."""
    violations: list[tuple[str, str, str]] = []
    illisibles: list[str] = []
    for paquet in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        expression = paquet.get("license")
        if not expression:
            # Pas de champ `license` : cargo-deny irait lire le `license-file`. Nous ne savons pas
            # le faire — donc nous ne prétendons pas savoir. Fail-closed : c'est une VIOLATION à
            # trancher à la main, pas un crate qu'on laisse passer en silence.
            illisibles.append(
                f"{paquet['name']}@{paquet['version']} — aucun champ `license` "
                f"(license-file: {paquet.get('license_file') or 'absent'})"
            )
            continue
        try:
            ok = satisfait(expression, autorisees)
        except ValueError as exc:
            illisibles.append(f"{paquet['name']}@{paquet['version']} — SPDX non analysable : {exc}")
            continue
        if not ok:
            violations.append((paquet["name"], paquet["version"], expression))
    return violations, illisibles


def main() -> int:
    parseur = argparse.ArgumentParser(
        description=(
            "Contrôle de licence sur la fermeture de dépendances RÉELLE du crate console "
            "(cargo metadata --all-features), contre la liste `allow` de deny.toml. Couvre le "
            "sous-arbre `object-store` que cargo-deny ne voit pas."
        ),
        epilog=(
            "Exemples :\n"
            "  python3 scripts/check_dep_licenses.py\n"
            "  python3 scripts/check_dep_licenses.py --self-test-red\n"
            "  python3 scripts/check_dep_licenses.py --cargo-deny /tmp/cargo-deny --list\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parseur.add_argument(
        "--repo",
        default=str(Path(__file__).resolve().parent.parent),
        help="racine du dépôt (défaut : le parent de scripts/)",
    )
    parseur.add_argument(
        "--deny-config",
        default=None,
        help="chemin de deny.toml (défaut : <repo>/deny.toml) — la SEULE source de la politique",
    )
    parseur.add_argument(
        "--cargo-deny",
        default=None,
        help="chemin du binaire cargo-deny : affiche le différentiel EXACT de ce qu'il ne voit pas",
    )
    parseur.add_argument("--list", action="store_true", help="détailler chaque crate et sa licence")
    parseur.add_argument(
        "--self-test-red",
        action="store_true",
        help=(
            "auto-test : rejoue le contrôle SANS les licences atteignables uniquement dans "
            f"l'angle mort ({', '.join(LICENCES_TEMOIN_ANGLE_MORT)}) et rend 0 SI ET SEULEMENT SI "
            "la garde a rougi EN NOMMANT un crate invisible à cargo-deny"
        ),
    )
    args = parseur.parse_args()

    depot = Path(args.repo).resolve()
    politique = Path(args.deny_config) if args.deny_config else depot / "deny.toml"

    if not (depot / "console" / "Cargo.toml").is_file():
        _erreur(f"[dep-licenses] ÉCHEC (sonde) — pas de crate console sous {depot}")
        return 2
    if shutil.which("cargo") is None:
        _erreur("[dep-licenses] ÉCHEC (sonde) — `cargo` introuvable sur le PATH")
        return 2

    # Jambe 1 : l'évaluateur doit se prouver vivant AVANT toute mesure.
    panne = auto_test_evaluateur()
    if panne is not None:
        _erreur(f"[dep-licenses] ÉCHEC (sonde) — {panne}")
        return 2

    try:
        allow = lire_allow(politique)
        metadata = cargo_metadata(depot)
    except RuntimeError as exc:
        _erreur(f"[dep-licenses] ÉCHEC (sonde) — {exc}")
        return 2

    autorisees = set(allow)
    total = len(metadata["packages"])

    # -----------------------------------------------------------------------------------------
    # Mode auto-test : on retire de la politique les licences qui ne vivent QUE dans l'angle mort.
    # La garde DOIT rougir, et rougir EN NOMMANT ces crates-là — c'est ce qui prouve qu'elle
    # atteint le sous-arbre, pas seulement qu'elle sait dire non.
    # -----------------------------------------------------------------------------------------
    if args.self_test_red:
        retirees = [lic for lic in LICENCES_TEMOIN_ANGLE_MORT if lic in autorisees]
        restreinte = autorisees - set(LICENCES_TEMOIN_ANGLE_MORT)
        print(
            "[dep-licenses] AUTO-TEST — on rejoue le contrôle en RETIRANT de la politique les "
            f"licences\n              atteignables uniquement sous `object-store` : "
            f"{', '.join(LICENCES_TEMOIN_ANGLE_MORT)}.\n"
            "              La garde doit ROUGIR et NOMMER des crates que cargo-deny ne voit pas."
        )
        if not retirees:
            _erreur(
                "\n[dep-licenses] AUTO-TEST EN ÉCHEC — aucune de ces licences n'est dans la liste "
                f"`allow` de {politique}.\n  Le témoin a disparu : soit la politique a changé, soit "
                "le sous-arbre `object-store` n'est plus\n  tiré. Dans les deux cas, réviser cette "
                "garde ET la réserve documentée dans deny.toml."
            )
            return 1
        violations, illisibles = evaluer(metadata, restreinte)
        if not violations:
            _erreur(
                "\n[dep-licenses] AUTO-TEST EN ÉCHEC — 0 violation alors que "
                f"{', '.join(retirees)} viennent\n  d'être retirées de la politique. Deux causes, "
                "toutes deux à traiter par un humain :\n"
                "    (a) l'évaluation est cassée -> la garde est un DÉCOR, la réparer ;\n"
                "    (b) le sous-arbre `object-store` n'entre plus dans le graphe (feature retirée,\n"
                "        rust-s3 remplacé) -> retirer la réserve de deny.toml et de "
                "docs/DEPLOYMENT.md §3quater.2."
            )
            return 1
        print(f"\n[dep-licenses] la garde a MORDU : {len(violations)} licence(s) refusée(s).")
        for nom, version, expression in violations:
            print(f"    - {nom}@{version} : {expression}")
        if illisibles:
            print("  (licences illisibles, comptées comme à trancher :)")
            for ligne in illisibles:
                print(f"    - {ligne}")
        print(
            "[dep-licenses] AUTO-TEST OK — ces crates sont PRÉCISÉMENT ceux du sous-arbre que\n"
            "              cargo-deny ne voit pas : la garde atteint bien l'angle mort qu'elle "
            "couvre."
        )
        return 0

    # -----------------------------------------------------------------------------------------
    # Mode normal.
    # -----------------------------------------------------------------------------------------
    print(
        "[dep-licenses] Politique LUE dans "
        f"{politique.relative_to(depot) if politique.is_relative_to(depot) else politique} "
        f"(`[licenses] allow`, {len(allow)} entrées) :\n              "
        + ", ".join(f"`{lic}`" for lic in allow)
        + "\n              Sonde : cargo metadata --all-features --locked (crate "
        f"{depot / 'console'}) -> {total} crates."
    )

    aveugles = angles_morts_structurels(metadata)
    if aveugles:
        print(
            "\n  ANGLE MORT DE CARGO-DENY, mesuré ici et AFFICHÉ à dessein — arête(s) vers une "
            "dépendance\n  OPTIONNELLE dont la feature nomme le PAQUET là où l'arête résolue porte "
            "le nom de la LIB.\n  cargo-deny n'apparie pas les deux, tient la feature pour "
            "désactivée, et perd tout le sous-arbre :"
        )
        for consommateur, paquet, arete, caches in aveugles:
            print(
                f"    · {consommateur} -> feature `dep:{paquet}` / arête « {arete} » "
                f"-> {caches} crate(s) qu'AUCUNE autre arête n'atteint"
            )
        print(
            "    (le manque RÉEL de cargo-deny est plus large — sa propre résolution de features "
            "lui fait\n     perdre en plus des crates atteignables autrement : le chiffrer exige "
            "`--cargo-deny`.)"
        )
        print(
            "    C'est CE contrôle-ci qui lit leurs licences. Réparation à la source (hors de ce\n"
            "    script, elle touche le manifeste) : déclarer la dépendance sous le nom de sa lib,\n"
            "    `s3 = { package = \"rust-s3\", … }` + `object-store = [\"dep:s3\"]` — "
            "docs/DEPLOYMENT.md §3quater.2."
        )

    if args.cargo_deny:
        binaire = Path(args.cargo_deny)
        vus = crates_vus_par_cargo_deny(binaire, depot) if binaire.is_file() else None
        if vus is None:
            print(
                f"\n  Différentiel cargo-deny : INDISPONIBLE ({binaire}) — le verdict ci-dessous "
                "ne\n  dépend pas de lui, mais le manque n'est pas chiffré cette fois."
            )
        else:
            tous = {f'{p["name"]}@{p["version"]}' for p in metadata["packages"]}
            manques = sorted(tous - vus)
            print(
                f"\n  Différentiel MESURÉ : cargo-deny examine {len(vus)} crates, ce contrôle "
                f"{len(tous)}.\n  {len(manques)} crate(s) échappent donc à l'audit de licence "
                "officiel :"
            )
            for entree in manques:
                print(f"    · {entree}")

    violations, illisibles = evaluer(metadata, autorisees)

    if args.list:
        print(f"\n  Détail ({total} crates) :")
        for paquet in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
            print(f"    {paquet['name']}@{paquet['version']:<12} {paquet.get('license') or '(?)'}")

    if not violations and not illisibles:
        print(
            f"\n[dep-licenses] OK — les {total} crates de la fermeture (toutes features activées, "
            "sous-arbre\n               `object-store` COMPRIS) satisfont la politique de "
            "deny.toml."
        )
        return 0

    _erreur(
        f"\n[dep-licenses] ÉCHEC — {len(violations)} licence(s) non autorisée(s) et "
        f"{len(illisibles)} illisible(s)\n  dans la fermeture de dépendances redistribuée."
    )
    if violations:
        print("\n  Licence(s) refusée(s) par `[licenses] allow` :")
        for nom, version, expression in violations:
            print(f"    - {nom}@{version} : {expression}")
    if illisibles:
        print("\n  Licence(s) que ce contrôle ne sait pas trancher (fail-closed) :")
        for ligne in illisibles:
            print(f"    - {ligne}")
    print(
        "\n  Que faire :\n"
        "    1. si la licence est compatible AGPL-3.0-or-later et qu'on ACCEPTE de la\n"
        "       redistribuer : l'ajouter à `[licenses] allow` de deny.toml AVEC sa justification\n"
        "       (qui la tire, pourquoi elle est compatible) — jamais une ligne nue ;\n"
        "    2. si elle ne l'est pas : retirer la dépendance, ou la feature qui la tire.\n"
        "    Ne JAMAIS élargir la liste pour faire taire un rouge sans écrire pourquoi : c'est\n"
        "    exactement le défaut que cette garde répare.\n"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

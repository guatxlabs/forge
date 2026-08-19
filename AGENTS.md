<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Règles du dépôt — à lire AVANT de commiter

Ce fichier existe pour être lu **sans aucun contexte préalable** : par un contributeur nouveau, ou
par un agent qui ouvre ce dépôt sans mémoire de ce qui a précédé. Les deux règles ci-dessous ne se
négocient pas, et elles sont **vérifiées par la machine** — un commit qui les enfreint est refusé.

## 1. Une seule identité publique : `guatxlabs <noreply@guatx.com>`

```sh
git config user.name  guatxlabs
git config user.email noreply@guatx.com
```

**Aucune adresse personnelle ni nominative**, jamais — ni en auteur, ni en committer. Un dépôt
publié sous un collectif ne doit pas exposer le compte personnel de qui l'écrit.

Cette règle a une histoire utile : l'historique a porté pendant des mois deux identités pour une
même personne, dont un compte GitHub personnel entré par l'**édition via l'interface web**. Un
`.mailmap` ne l'a pas corrigé — la page *Contributors* de GitHub apparie les commits aux comptes
par l'adresse stockée dans les octets du commit. Il a fallu réécrire l'historique.

## 2. Un message de commit s'adresse à un LECTEUR PUBLIC

Écrivez pour quelqu'un qui n'était pas dans la pièce, qui ne vous connaît pas, et qui doit pouvoir
agir sur ce qu'il lit. Dites **ce qui change et pourquoi**.

**Interdit** — le commit n'est pas un compte rendu de conversation :

* le récit d'enquête à la première personne (« j'avais écarté ce champ », « ma vérification ») ;
* l'adresse directe à un interlocuteur (« comme vous l'avez demandé », « merci de vérifier ») ;
* la chronologie de session comme fil narratif (« cette session a produit… »).

**Admis, et à ne pas confondre avec ce qui précède** :

* la **voix de l'outil** — « un `skipped` dit *je n'ai PAS pu vérifier* » énonce le sens d'un statut ;
* une **date de mesure** — « MESURÉ le 2026-08-16 » est de la traçabilité, pas un journal ;
* un **« pourquoi » long**. La longueur n'a jamais été le défaut ; l'adressage l'était.

La chronologie d'une investigation appartient à `ROADMAP.md`, qui existe pour ça.

## Comment ces règles sont tenues

| barrière | portée | activation |
|---|---|---|
| hook `commit-msg` | poste local, avant que le commit existe | `make hooks` (une fois par clone) |
| job CI `registre public` | tout ce qui arrive au dépôt | automatique |

Le hook **ne suffit pas** : il n'est pas transporté par `git clone` et n'est jamais exécuté par
l'édition web de GitHub — la voie même par laquelle le problème était entré. **C'est la CI qui
ferme.** Le hook évite seulement d'avoir à corriger après coup.

Vérifier un message avant de commiter, ou une plage déjà écrite :

```sh
python3 scripts/check_commit_register.py --message-file <fichier>
python3 scripts/check_commit_register.py --range origin/main..HEAD
```

## Le reste

Les invariants techniques (scope-guard fail-closed, gate ROE à 4 couches, plancher exploit, ledger
append-only, rédaction des secrets, planner coverage-safe, findings à preuve) sont dans
[`CONTRIBUTING.md`](CONTRIBUTING.md). Une PR qui en affaiblit un est refusée, quelle que soit son
utilité par ailleurs.

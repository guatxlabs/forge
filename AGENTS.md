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

La chronologie d'une investigation n'appartient pas au dépôt public : `ROADMAP.md` y est un
**sommaire** — ce qui est livré, ce qui reste ouvert, les limites assumées — et non un journal de
campagne. Le récit d'une enquête se tient hors du dépôt ; ce qui doit en survivre publiquement,
c'est la **décision** et son **pourquoi**, dans le message du commit qui la porte.

### La première personne : interdite nue, admise CITÉE

Le garde lit des **formes**, pas des intentions — il ne sait pas qui parle. Toute élision de « je »
et tout possessif (`mon`, `ma`, `mes`) sont donc refusés **en bloc**, quel que soit le verbe qui
suit. Ce n'est pas de la sévérité gratuite : la version qui énumérait les verbes
(`j'ai trouvé|corrigé|mesuré|…`) a laissé passer **56 occurrences** — `j'ai inséré`, `j'ai composé`,
`mon propre garde`, `de mon côté`, `ma main` — dans des commits qu'elle déclarait conformes.

La voix de l'outil s'écrit pourtant à la première personne, et doit passer. Elle passe en portant
une **marque de citation** — c'en est une :

| marque | exemple |
|---|---|
| guillemets | un `skipped` dit « je n'ai PAS pu vérifier » |
| code | le motif `mon propre garde` n'était pas couvert |
| ligne `>` | `> un `tested` dit « j'ai vérifié, rien trouvé »` |

C'est aussi ce qui permet à la règle de citer ce qu'elle interdit sans se refuser elle-même. Une
citation ne traverse pas un saut de paragraphe, et **un span de code ne doit pas être coupé par un
retour à la ligne** — sinon l'appariement des backticks se décale et le contenu cité redevient
visible au garde.

### `hier` est interdit, `aujourd'hui` ne l'est pas

Asymétrie mesurée, pas supposée. « hier » n'a aucun référent pour un lecteur qui arrive six mois
plus tard. « aujourd'hui » sert à dire *à l'état actuel du code* — « aucun réglage n'expose ce
levier aujourd'hui » — dans 8 emplois sur 9 relevés dans cet historique.

## Comment ces règles sont tenues

| barrière | portée | activation |
|---|---|---|
| hook `commit-msg` | poste local, avant que le commit existe | `make hooks` (une fois par clone) |
| job CI `registre public` | tout ce qui arrive au dépôt | automatique |

Le hook **ne suffit pas** : il n'est pas transporté par `git clone` et n'est jamais exécuté par
l'édition web de GitHub — la voie même par laquelle le problème était entré. **C'est la CI qui
ferme.** Le hook évite seulement d'avoir à corriger après coup.

Les deux slots d'identité sont vérifiés, **auteur et committer** : un `cherry-pick`, un `rebase` ou
l'édition web laissent l'auteur intact et écrivent une autre identité en committer — et c'est par
là que le compte personnel était entré. Une plage que git n'a pas su lire est un **refus**, pas un
silence : une barrière échoue fermée.

Vérifier un message avant de commiter, ou une plage déjà écrite :

```sh
python3 scripts/check_commit_register.py --message-file <fichier>
python3 scripts/check_commit_register.py --range origin/main..HEAD
```

### Ce qu'un garde ne peut pas faire, et ce qu'il faut faire à la place

**Un garde n'attrape que ce qu'il sait décrire.** Les 56 occurrences citées plus haut n'ont pas été
trouvées par lui — il les déclarait conformes — mais par un **audit indépendant**, écrit avec
d'autres motifs, exprès plus larges, et confronté ligne à ligne. Ce dépôt a quatre listes tenues à
la main qui ont survécu à leur objet : `_RATE_FLAG_KINDS`, `_SQL_ERROR_SIGNS`, les exemptions du
garde de documents, et cette énumération de verbes.

Avant d'affirmer qu'un dépôt est propre : écrire un contrôle **indépendant du garde**, comparer, et
trier les faux positifs à la main. Un garde vert ne prouve que l'absence de ce qu'il cherche.

### Si vous réécrivez l'historique

Trois pièges rencontrés, chacun ayant coûté une reprise :

* `git filter-repo` **remet l'arbre de travail à l'état commité**. Toute modification non commitée
  est perdue — commiter d'abord, réécrire ensuite.
* sans `--prune-empty=never`, un commit dont le seul changement devient un no-op après réécriture
  est **supprimé avec son message**. Vérifier le compte de commits avant/après.
* filter-repo **réécrit les SHA cités dans les messages** : un remplacement littéral qui contient
  un SHA ne matchera plus au tour suivant.

## Le reste

Les invariants techniques (scope-guard fail-closed, gate ROE à 4 couches, plancher exploit, ledger
append-only, rédaction des secrets, planner coverage-safe, findings à preuve) sont dans
[`CONTRIBUTING.md`](CONTRIBUTING.md). Une PR qui en affaiblit un est refusée, quelle que soit son
utilité par ailleurs.

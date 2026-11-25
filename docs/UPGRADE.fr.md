# Forge — Upgrade / Migration / Backup (runbook)

[English](UPGRADE.md) | [Français](UPGRADE.fr.md)

> 🧭 [Documentation Forge](README.fr.md) · Voir aussi : [Déploiement](DEPLOYMENT.fr.md) ·
> [Migration de données](MIGRATION.fr.md) · [Sauvegardes chiffrées](BACKUP.fr.md) ·
> [Custody des clés](KEY_CUSTODY.fr.md)

> **Usage AUTORISÉ uniquement.** Rien de ce runbook n'arme quoi que ce soit. L'upgrade est une
> opération de **maintenance de données** (schéma + sauvegarde), pas une action offensive.

Ce document décrit le cycle de vie **UPGRADE → VÉRIF → ROLLBACK** d'une console Forge déjà déployée, en
**une seule commande fail-closed**. Le principe directeur : **on ne migre JAMAIS sans un instantané
chiffré vérifié**, et **tout échec revient à l'état EXACT d'avant**.

---

## TL;DR

```sh
# À quelle version de schéma est cette base ? (lecture seule, ne démarre pas le serveur)
forge status

# Aperçu SANS rien muter (montre le snapshot + la migration prévue)
forge upgrade --dry-run

# Upgrade réel : snapshot chiffré -> migrate additif -> vérif -> rollback si échec
FORGE_UPGRADE_PASS='…' \
forge upgrade --passphrase-env FORGE_UPGRADE_PASS
```

Idempotent : re-lancer alors que la base est déjà à jour = **no-op succès** (vérifié, aucun changement).

---

## 1. `status` — « à quelle version est cette base »

`forge status [--db <path>] [--ledger <path>] [--json]` imprime un instantané **lecture seule**
(aucune mutation, ne démarre **pas** le serveur, exit rapide) :

| Champ | Sens |
|-------|------|
| `version` | version produit (fichier `VERSION`, source unique) |
| `schema_version` | version **LOGIQUE** du schéma persistée (`settings.schema_version`, tamponnée par `migrate()`) |
| `schema_version_expected` | version attendue par **ce binaire** (compilée) |
| `backend` | `sqlite` (build par défaut) ou `postgres` |
| `db` | chemin SQLite, ou URL Postgres **RÉDIGÉE** (jamais de credentials) |
| `ledger` / `ledger_ok` / `ledger_head` | tête de la chaîne d'audit, **hash-chain re-vérifiée** |
| `ha_configured` | HA armé via `FORGE_HA` (le *leader* live, lui, est sur `/health`) |

La même version est **surfacée sur `/health`** (champ `schema_version`, additif) d'une instance vivante.

> Une base **antérieure** au stamp affiche `schema_version: (non tamponnée)` → le prochain boot (ou
> `upgrade`) la tamponne. C'est rétro-compatible, jamais une valeur inventée.

### Historique des versions de schéma

| Version | Ce qu'elle ajoute | Effet sur une base existante |
|---|---|---|
| 1 | socle (`run_id`/`cwe`/`cvss` sur `finding`, colonnes C2 sur `run_job`, engagements, tenants…) | — |
| 2 | `run_job.findings_dropped` · `run_job.findings_write_errors` — comptabilité des findings **émis par le moteur et non stockés** (cf. `docs/HTTP_API.md`, section `/api/ingest`) | **Deux `ALTER TABLE … ADD COLUMN` additifs**, idempotents (error-ignored) et **réversibles** en pratique : aucune donnée existante n'est lue, écrite ni convertie ; un binaire ANTÉRIEUR rebranché sur la base migrée continue de fonctionner (il ignore simplement les deux colonnes). Les lignes déjà présentes prennent **`NULL`** — c'est-à-dire « **part refusée inconnue** », délibérément PAS `0` : un `DEFAULT 0` aurait affirmé rétroactivement qu'aucun finding n'avait été perdu, ce qui est précisément le mensonge que ce lot supprime. |
| 3 | clés par base `enterprise.<name>` copiées sous `advanced.<name>` (cf. §8) | **Additive** : lignes neuves, valeurs inchangées, anciennes lignes laissées, plus l'enregistrement `migration.renamed_settings`, dans la transaction du tampon ; refus (rien écrit) quand les deux noms sont en écart. Un binaire ANTÉRIEUR rebranché sur la base migrée lit les anciennes lignes — les valeurs d'avant la montée — et remet le tampon à 2 ; le démarrage suivant du binaire neuf compare les deux noms et refuse au moindre écart (§8). |

> **Postgres** : les deux colonnes sont dans `PG_SCHEMA` (cluster frais) ; une migration
> `migrate-store` depuis SQLite les reprend, car elle copie les colonnes **énumérées** sur la source
> (`PRAGMA table_info`) et exige leur présence sur la cible.

---

## 2. `upgrade` — flux sûr en une commande

```
forge upgrade --passphrase-env <ENVVAR>
    [--db <path>] [--ledger <path>] [--backup-dir <dir>]
    [--to <postgres-url>] [--force] [--dry-run]
```

Séquence **FAIL-CLOSED** (chaque étape peut seulement AVANCER si la précédente a réussi) :

1. **Snapshot pré-upgrade CHIFFRÉ.** Réutilise le moteur de backup audité (**argon2id** + **XChaCha20-Poly1305**,
   sel/nonce par archive), chaîne ledger vérifiée **avant** écriture, archive **fsync'd**, taggée
   `pre-upgrade-<schema_version>-<epoch>.forge` dans `--backup-dir` (défaut : dossier de la base). Le
   snapshot est **re-vérifié** (déchiffrement + sha256 du manifest + hash-chain) : **s'il est invérifiable,
   on N'A PAS de filet → ABORT avant toute mutation.** *On ne migre jamais sans un bon instantané.*
2. **Migrate additif** (`SCHEMA` idempotent + `migrate()` : `ADD COLUMN`/`CREATE TABLE IF NOT EXISTS`,
   error-ignored). Tamponne `schema_version`. Si `--to <postgres-url>` est fourni : **migration de store
   gouvernée** SQLite → Postgres (`migrate-store` : ordre FK, préservation des ids, vérif des comptes
   ligne à ligne, checkpoint ledger signé) — **feature `store-postgres`** requise dans l'image.
3. **Vérif** : self-check de schéma (colonnes additives présentes + `schema_version == cible`) +
   `ledger verify` (hash-chain) + (store) la vérif des comptes de `migrate-store`.
4. **Self-check santé** : la base répond (`SELECT 1`) + tête de ledger cohérente (les mêmes contrôles que
   `/health`).
5. **Sur TOUT échec en 2–4 : RESTORE** depuis le snapshot pré-upgrade → retour à l'état **EXACT** d'avant,
   **exit non-zéro**, message clair. **Jamais de base à moitié migrée.** Sur succès : `schema_version`
   tamponnée + entrée ledger **`console.upgrade {from, to, backup_id}`** (métadonnées seules).

**Idempotent** : si la base est déjà à la version cible, l'étape *migrate* est **sautée** (elle est de
toute façon additive-idempotente) mais la **vérif tourne quand même** → no-op succès.

**`--dry-run`** : imprime le plan (où serait écrit le snapshot, `would_migrate`, cible de store rédigée)
et **ne mute RIEN** (aucun snapshot, aucun `migrate`).

### Secrets
- **Passphrase** du snapshot : lue **UNIQUEMENT** depuis l'ENV nommée par `--passphrase-env` (jamais en
  argv → jamais dans `ps`/l'historique shell).
- **URL Postgres** (`--to`) : **rédigée** (sans `user:pass` ni query-string) dans le rapport ET le ledger.

---

## 3. Scénarios

### 3.1 SQLite solo (build par défaut)

```sh
# 1) constater l'état
forge status --db /data/db/forge.db --ledger /data/ledger/engagement.jsonl

# 2) aperçu
forge upgrade --db /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl --backup-dir /data/backups --dry-run

# 3) upgrade réel
FORGE_UPGRADE_PASS='…' forge upgrade \
    --db /data/db/forge.db --ledger /data/ledger/engagement.jsonl \
    --backup-dir /data/backups --passphrase-env FORGE_UPGRADE_PASS
```

En Docker : arrêter le conteneur console, lancer `upgrade` en **one-shot** sur les mêmes volumes, puis
redémarrer sur la nouvelle image.

```sh
docker stop forge
docker run --rm \
  -v forge-db:/data/db -v forge-ledger:/data/ledger -v forge-backups:/data/backups \
  -e FORGE_UPGRADE_PASS \
  forge:<nouvelle-version> \
  forge upgrade --db /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl --backup-dir /data/backups \
    --passphrase-env FORGE_UPGRADE_PASS
docker start forge   # boot sur la nouvelle image (migrate() re-tamponne, idempotent)
```

### 3.2 Postgres (backend avancé, flag-gated)

Le **schéma** Postgres (`PG_SCHEMA`, colonnes de `migrate()` déjà fusionnées) est appliqué **au boot** de
l'image `store-postgres` et **tamponné** (`schema_version`) sous le verrou DDL cluster. Deux cas :

- **Migrer les DONNÉES SQLite → Postgres** (bascule de backend) : image `store-postgres`, puis
  ```sh
  FORGE_UPGRADE_PASS='…' forge upgrade \
      --db /data/db/forge.db --ledger /data/ledger/engagement.jsonl \
      --backup-dir /data/backups --passphrase-env FORGE_UPGRADE_PASS \
      --to 'postgres://…@pg:5432/forge?sslmode=require'   # [--force] pour écraser une cible non vide
  ```
  Le snapshot pré-upgrade protège la **source SQLite** ; la migration de store est **gouvernée**
  (vérif des comptes, refus d'écraser sans `--force`, checkpoint signé `console.store.migrate`). Détails
  bas niveau : [`docs/MIGRATION.md`](MIGRATION.fr.md) §Postgres et [`docs/DEPLOYMENT.md`](DEPLOYMENT.fr.md) §3bis.
- **Bump de schéma d'une base Postgres déjà en service** : le schéma additif est appliqué **au boot**
  (idempotent). Le snapshot logique Postgres se fait par `pg_dump` (cf. `/api/backup` sous PG et
  [`docs/BACKUP.md`](BACKUP.fr.md)) — **avant** un `docker pull` majeur, prenez ce dump.

### 3.3 HA / multi-instance — upgrade rolling (drain-leader)

⚠️ **NE JAMAIS lancer la migration depuis N instances en parallèle.** Sous HA (Postgres partagé),
plusieurs réplicas écrivant le schéma / migrant les données **en même temps** provoquent des courses
(duplicate-key, `tuple concurrently updated`). Procédure sûre :

1. **Boot ordonné** : le boot applique `PG_SCHEMA` sous un `pg_advisory_xact_lock` cluster-global → un
   **seul** réplica pose le schéma additif à la fois, les autres voient tout déjà présent (idempotent).
   Un upgrade **purement schéma-additif** peut donc se faire par **rolling restart** des réplicas sur la
   nouvelle image, sans commande manuelle.
2. **Si une migration de DONNÉES est nécessaire** (`upgrade --to …` / `migrate-store`) : **draine le
   leader** — mets à jour **UNE** instance hors rotation (ou une instance de maintenance dédiée), lance
   `upgrade`/`migrate-store` **là uniquement**, vérifie (`status`, `ledger verify`), **puis** fais le
   rolling restart des autres réplicas sur la nouvelle image. Jamais deux migrations concurrentes.
3. Le *leader* live est visible sur `/health` (`leader: true/false`, `instance_id`) — utilise-le pour
   choisir/confirmer l'instance de maintenance.

---

## 4. Rollback

Le rollback est **automatique** : au moindre échec des étapes *migrate*/*vérif*/*santé*, `upgrade`
restaure db + ledger depuis le snapshot pré-upgrade (`restore --force` interne, re-vérifié sha256 +
hash-chain) et **sort non-zéro**. La base **n'est jamais laissée à moitié migrée**. La restauration
elle-même est **tracée** au ledger (`console.restore`) — le rollback est auditable.

Si le rollback automatique **échoue lui-même** (I/O, permissions), le message indique le chemin du
snapshot chiffré et la commande manuelle exacte :

```sh
forge restore --in <pre-upgrade-…​.forge> --passphrase-env <ENV> \
    --to <db> --ledger <ledger> --force
```

---

## 5. Backup / Restore (rappel — UX une commande)

`upgrade` **réutilise** ces primitives ; on peut aussi les appeler seules.

```sh
# Sauvegarde CHIFFRÉE (db + ledger + clé .ed25519 + manifest) — passphrase via ENV, jamais argv
FORGE_BACKUP_PASS='…' forge backup --out /data/backups/manual.forge \
    --db /data/db/forge.db --ledger /data/ledger/engagement.jsonl \
    --passphrase-env FORGE_BACKUP_PASS

# Restauration (déchiffre, vérifie sha256 + hash-chain, refuse d'écraser un install non vide sans --force)
FORGE_BACKUP_PASS='…' forge restore --in /data/backups/manual.forge \
    --to /data/db/forge.db --ledger /data/ledger/engagement.jsonl \
    --passphrase-env FORGE_BACKUP_PASS   # [--force] pour un swap en place
```

**Propriétés de sécurité** (identiques à `upgrade`) : archive **toujours chiffrée** (aucun chemin en
clair — elle embarque la clé de signature ET la base), **AEAD-authentifiée** (une mauvaise passphrase ou
une altération ⇒ échec propre, **rien écrit**), chaîne ledger vérifiée **avant** backup et **à la**
restauration, garde **anti-écrasement** (`--force` explicite), passphrase **transitoire** (jamais
stockée/loggée/ledgerisée). Programmation + rétention + offsite S3/MinIO : [`docs/BACKUP.md`](BACKUP.fr.md).

### Drill de restore offsite (recommandé)

```sh
# 1) récupérer une archive offsite (S3/MinIO ou copie local_dir), la valider SANS écrire :
FORGE_BACKUP_PASS='…' forge restore --in /tmp/offsite-copy.forge \
    --to /tmp/restore-drill.db --ledger /tmp/restore-drill.jsonl --passphrase-env FORGE_BACKUP_PASS
# 2) vérifier la base + la chaîne restaurées :
forge status --db /tmp/restore-drill.db --ledger /tmp/restore-drill.jsonl
forge ledger verify --ledger /tmp/restore-drill.jsonl
# 3) nettoyer : rm /tmp/restore-drill.*
```

Les snapshots `pre-upgrade-*` écrits par `upgrade` sont des archives de backup **standard** : ils sont
**balayés par la rétention existante** (cf. politique de backup) et restaurables par la commande ci-dessus.

---

## 6. Propriétés de sécurité (résumé)

| Garantie | Mécanisme |
|----------|-----------|
| Jamais de migration sans filet | Snapshot pré-upgrade **chiffré + chain-vérifié** obligatoire, sinon ABORT |
| Jamais de base à moitié migrée | Tout échec 2–4 → **RESTORE** à l'état exact d'avant, exit non-zéro |
| Rejeu sûr | Idempotent (migrate additif ; même-version → skip + vérif) |
| Build par défaut byte-identique | Nouvelles sous-commandes **additives** ; flux existants inchangés ; **openssl-free** (build par défaut — cf. `DEPLOYMENT.md` §3quater.1) |
| Crypto auditée | Réutilise argon2id + XChaCha20-Poly1305 du backup (aucun nouveau chemin crypto) |
| Secrets protégés | Passphrase via **ENV** (jamais argv) ; URL Postgres **rédigée** dans log/ledger |
| Auditable | `console.backup` / `console.upgrade` / `console.restore` chaînés au ledger tamper-evident |
| HA correct | **Drain-leader** documenté ; jamais N migrations concurrentes |

> Vérif de **signature** du ledger (Ed25519/HMAC) et anti-**troncature** (high-water-mark) restent du
> ressort du moteur `forge ledger verify --pubkey` (Python) + de l'ancrage hors-host ; `upgrade`
> re-vérifie le **hash-chaining** (même algo que `/api/ledger/verify`). Voir [`KEY_CUSTODY.md`](KEY_CUSTODY.fr.md).

---

## 7. Variables renommées : `FORGE_ENTERPRISE_*` → `FORGE_ADVANCED_*`

Forge n'a pas d'édition payante : les variables qui engagent les modules avancés portent le nom `FORGE_ADVANCED_*`.
Le renommage est fait **sans alias** — l'ancien nom n'active plus rien.

| Ancien nom (retiré) | Nouveau nom |
|---|---|
| `FORGE_ENTERPRISE_STORE` | `FORGE_ADVANCED_STORE` |
| `FORGE_ENTERPRISE_COMPLIANCE` | `FORGE_ADVANCED_COMPLIANCE` |
| `FORGE_ENTERPRISE_SSO` | `FORGE_ADVANCED_SSO` |
| `FORGE_ENTERPRISE_TENANCY` | `FORGE_ADVANCED_TENANCY` |
| `FORGE_ENTERPRISE_SCIM` | `FORGE_ADVANCED_SCIM` |

**Refus au démarrage.** Ignorer un ancien nom en silence éteindrait le cloisonnement des locataires, le SSO ou
la conformité chez qui met à jour sans lire cette note. Une variable `FORGE_ENTERPRISE_*` simplement **présente**
(quelle que soit sa valeur, même vide) fait donc refuser le démarrage de la console — le serveur et toutes les
sous-commandes sauf `--version` et `--help` — avec le code de sortie 2 et un message qui nomme chaque variable
trouvée et son nouveau nom :

```text
[forge] FATAL retired environment variable(s) still set: FORGE_ENTERPRISE_SSO -> rename it to FORGE_ADVANCED_SSO. The FORGE_ENTERPRISE_* names are no longer read (renamed FORGE_ADVANCED_*, no alias); refusing to start rather than run with an advanced module silently off. See docs/UPGRADE.md §7.
```

Le moteur Python applique la même règle quand il construit le signeur du ledger (`RetiredEnvNameError`). Pour
mettre à jour : renommer les variables dans le `.env`, le fichier compose, la ConfigMap ou le Deployment, puis
redémarrer. Les clés de configuration par base suivent au §8 — elles sont migrées pour vous, sans rien retirer.

## 8. Clés de réglage, champ `whoami` et code d'erreur renommés : `enterprise` → `advanced`

Le mot quitte aussi les clés de configuration par base et ce que la console sert. Aucun alias : une fois
migrés, les anciens noms ne sont plus lus nulle part.

| Où | Ancien nom (retiré) | Nouveau nom |
|---|---|---|
| table `settings` | `enterprise.tenancy` | `advanced.tenancy` |
| table `settings` | `enterprise.sso` | `advanced.sso` |
| table `settings` | `enterprise.scim` | `advanced.scim` |
| table `settings` | `enterprise.compliance` | `advanced.compliance` |
| table `settings` | `enterprise.superadmin` | `advanced.superadmin` |
| `GET /api/whoami` | champ `enterprise` (`{tenancy, sso, scim, rbac, compliance}`) | champ `advanced` (même contenu) |
| `GET /api/compliance/policy` | `ledger_signer.enterprise_flag` | `ledger_signer.advanced_flag` |
| HTTP 403 de `/api/tenants*` | `"error": "enterprise_disabled"` | `"error": "advanced_disabled"` |

**Ce que fait la migration — additive, et une seule fois.** Version de schéma **3**. Pendant une passe de
schéma — démarrage du serveur (SQLite et Postgres), `forge upgrade`, `forge migrate`, `POST /api/setup/migrate`,
`forge seed-demo`, et `forge migrate-store` après sa vérification des comptes — sur une base pas encore
tamponnée à 3 et jamais migrée, chaque clé `enterprise.<name>` est **copiée** sous `advanced.<name>` en gardant
sa valeur, et l'ancienne ligne est **laissée en place**. La même transaction écrit l'enregistrement
`migration.renamed_settings` — la liste des noms qui existaient sous l'ancien préfixe à ce moment-là, par exemple
`tenancy,superadmin` (vide s'il n'y en avait aucun ; jamais une valeur de réglage) — puis le tampon de version.
Le cloisonnement des locataires, le SSO, SCIM, la conformité et le super-administrateur sont identiques après le
premier démarrage du binaire neuf ; la console imprime une ligne par clé copiée (noms des clés, jamais les
valeurs). Le binaire neuf ne lit que les noms `advanced.*` et n'écrit jamais les noms `enterprise.*`. Valeurs
égales sous les deux noms : rien à copier. Valeurs différentes : refus, ci-dessous. La copie n'a jamais lieu une
seconde fois — l'enregistrement dit qu'elle est faite.

**Un binaire antérieur qui redémarre remet le tampon à 2.** Un retour arrière, ou un ancien pod relancé pendant le
redémarrage roulant du §3.3, démarre l'image précédente, qui tamponne sa propre version de schéma (2) sans rien
comparer. Le démarrage suivant du binaire neuf ne copie rien : il **compare** les deux noms et **refuse au moindre
écart**. Pour chaque nom de l'enregistrement, l'ancienne et la nouvelle clé doivent être présentes et égales ;
pour un nom hors de l'enregistrement dont l'ancienne clé est présente (écrite entre-temps), la nouvelle doit être
présente et égale. Ce démarrage refuse donc quand une clé LISTÉE dans l'enregistrement manque ou diffère sous
l'un des deux noms, ou quand une clé ancienne, listée ou non, existe sans clé neuve égale. Une clé posée
SEULEMENT sous `advanced.*`, qui n'a jamais existé sous l'ancien nom (absente de l'enregistrement et des lignes
`enterprise.*`), n'est pas comparée — et le binaire antérieur ne la voit pas.

**Ne modifier aucune de ces cinq clés pendant le déploiement**, tant que tous les réplicas ne tournent pas sur
l'image neuve (par exemple `kubectl rollout status` sur le Deployment) **et** que `/health` ne rend pas
`schema_version: 3`. Ce que `/health` expose est le tampon de la base — partagé par tous les réplicas sous
Postgres — que tout binaire antérieur remet à 2 en démarrant ; il ne dit pas quel binaire tourne sur un réplica
(`version` est la même chaîne dans les deux images de cette version).

**Un retour arrière montre les valeurs d'avant la montée.** L'image précédente ne lit que `enterprise.*` : un
super-administrateur révoqué depuis la montée sous `advanced.superadmin` l'est de nouveau pour elle, et un
cloisonnement des locataires posé seulement sous `advanced.tenancy` est éteint pour elle. Le démarrage suivant du
binaire neuf refuse ensuite tant qu'une clé listée dans l'enregistrement manque ou diffère sous l'un des deux
noms, ou qu'une clé ancienne existe sans clé neuve égale ; une clé posée seulement sous `advanced.*` et qui n'a
jamais existé sous l'ancien nom — le cloisonnement de cet exemple — n'est pas comparée : ce démarrage passe et le
binaire neuf l'applique de nouveau.

**Le refus.** Rien n'est écrit (la transaction est annulée, la version n'est pas tamponnée, une clé supprimée le
reste) et la console refuse de démarrer, code de sortie 2. Chaque écart nomme les deux clés et leur état —
`present`, `absent` ou `differs` — jamais une valeur, `superadmin` contenant des identités :

```text
[forge] FATAL settings keys out of step: enterprise.superadmin present, advanced.superadmin absent. The enterprise.* settings keys were renamed advanced.* (no alias); until the enterprise.* leftovers are removed, both names must hold the same value. Give BOTH names the same intended value; never delete an advanced.* key to get past this; if the enterprise.* rows were removed on purpose, run the complete removal of docs/UPGRADE.md §8. Refusing to start rather than pick one.
```

La dernière phrase dépend de l'endroit du refus : `forge migrate-store` finit par « migrate-store refused: its
transaction is rolled back, the target holds no copied row. » ; `forge migrate` et `POST /api/setup/migrate` par
« Import refused: the target database was copied but not migrated; correct the source, then import again. » ;
`forge upgrade` par « Upgrade refused: the database goes back to its pre-upgrade snapshot. » Pour résoudre,
donner aux deux noms la même valeur voulue — ne jamais supprimer une clé `advanced.*` pour passer le refus. Pour
révoquer un super-administrateur, donner aux deux noms la nouvelle liste (une liste vide ne désigne personne) ;
si l'une des deux lignes manque, l'insérer d'abord avec cette valeur. Par exemple sur SQLite :

```bash
sqlite3 forge.db "UPDATE settings SET value='<value>' WHERE key IN ('enterprise.superadmin','advanced.superadmin');"
```

**Retirer les restes est le point de non-retour.**

Une fois retirés, l'image précédente ne trouve plus aucune clé `enterprise.*` : pour elle, le cloisonnement des
locataires, le SSO, SCIM, la conformité et le super-administrateur sont **éteints**. Revenir en arrière après le
retrait OUVRE donc le cloisonnement des locataires. Ne les retirer que lorsque tous les réplicas tournent sur la
version neuve et qu'aucun retour vers une image antérieure ne reste possible. Aucune sous-commande ne le fait : la
console n'a pas de commande d'entretien des réglages, et cette version n'en ajoute pas. C'est UNE transaction de
deux instructions, la même sous SQLite (`sqlite3 forge.db`) et sous Postgres (`psql`) : supprimer les cinq
anciennes clés ET vider la liste de l'enregistrement. L'enregistrement reste, vidé ; après lui, plus rien n'est
comparé TANT QU'aucune ligne `enterprise.*` n'est réécrite. Une ligne ancienne recréée ensuite (par un binaire
antérieur ou à la main) est comparée : le démarrage refuse si la clé neuve ne porte pas la même valeur.

```sql
BEGIN;
DELETE FROM settings WHERE key IN ('enterprise.tenancy','enterprise.sso','enterprise.scim','enterprise.compliance','enterprise.superadmin');
UPDATE settings SET value='' WHERE key='migration.renamed_settings';
COMMIT;
```

**Ne jamais supprimer la ligne `migration.renamed_settings`.** Le retrait ci-dessus la vide, il ne la supprime
pas. Sans l'enregistrement, la migration suivante se rejoue comme une première migration et peut recopier sous
`advanced.*` des restes `enterprise.*` — un super-administrateur révoqué le redeviendrait. Sa liste est lue
fermée : un élément qui n'est pas l'un des cinq noms (casse différente, espaces, mot inconnu, élément vide) fait
refuser le démarrage avec l'écart `migration.renamed_settings lists unknown name "<element>"` (32 caractères
affichés au plus, tout caractère hors ASCII imprimable remplacé par `?`).

**Navigateur qui garde l'ancienne interface.** Un onglet dont le JavaScript précède la mise à jour lit le champ
`enterprise` absent de `whoami` comme « aucun module avancé » : les liens Identité et Conformité restent masqués
jusqu'au rechargement de la page. Rien ne s'ouvre — le serveur continue d'appliquer le drapeau et la garde
d'administration de chaque module. Les fichiers statiques sont servis sans version dans leur URL et sans
`Cache-Control` : recharger la page (Ctrl+F5 au besoin) après la mise à jour rend les liens.

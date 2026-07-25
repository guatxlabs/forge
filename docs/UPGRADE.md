# Forge — Upgrade / Migration / Backup (runbook)

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Déploiement](DEPLOYMENT.md) ·
> [Migration de données](MIGRATION.md) · [Sauvegardes chiffrées](BACKUP.md) ·
> [Custody des clés](KEY_CUSTODY.md)

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
| `backend` | `sqlite` (défaut/community) ou `postgres` |
| `db` | chemin SQLite, ou URL Postgres **RÉDIGÉE** (jamais de credentials) |
| `ledger` / `ledger_ok` / `ledger_head` | tête de la chaîne d'audit, **hash-chain re-vérifiée** |
| `ha_configured` | HA armé via `FORGE_HA` (le *leader* live, lui, est sur `/health`) |

La même version est **surfacée sur `/health`** (champ `schema_version`, additif) d'une instance vivante.

> Une base **antérieure** au stamp affiche `schema_version: (non tamponnée)` → le prochain boot (ou
> `upgrade`) la tamponne. C'est rétro-compatible, jamais une valeur inventée.

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

### 3.1 SQLite solo (community, défaut)

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

### 3.2 Postgres (backend enterprise)

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
  bas niveau : [`docs/MIGRATION.md`](MIGRATION.md) §Postgres et [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) §3bis.
- **Bump de schéma d'une base Postgres déjà en service** : le schéma additif est appliqué **au boot**
  (idempotent). Le snapshot logique Postgres se fait par `pg_dump` (cf. `/api/backup` sous PG et
  [`docs/BACKUP.md`](BACKUP.md)) — **avant** un `docker pull` majeur, prenez ce dump.

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
stockée/loggée/ledgerisée). Programmation + rétention + offsite S3/MinIO : [`docs/BACKUP.md`](BACKUP.md).

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
| Community byte-identique | Nouvelles sous-commandes **additives** ; flux existants inchangés ; **openssl-free** |
| Crypto auditée | Réutilise argon2id + XChaCha20-Poly1305 du backup (aucun nouveau chemin crypto) |
| Secrets protégés | Passphrase via **ENV** (jamais argv) ; URL Postgres **rédigée** dans log/ledger |
| Auditable | `console.backup` / `console.upgrade` / `console.restore` chaînés au ledger tamper-evident |
| HA correct | **Drain-leader** documenté ; jamais N migrations concurrentes |

> Vérif de **signature** du ledger (Ed25519/HMAC) et anti-**troncature** (high-water-mark) restent du
> ressort du moteur `forge ledger verify --pubkey` (Python) + de l'ancrage hors-host ; `upgrade`
> re-vérifie le **hash-chaining** (même algo que `/api/ledger/verify`). Voir [`KEY_CUSTODY.md`](KEY_CUSTODY.md).

# Forge — Upgrade / Migration / Backup (runbook)

[English](UPGRADE.md) | [Français](UPGRADE.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Deployment](DEPLOYMENT.md) ·
> [Data migration](MIGRATION.md) · [Encrypted backups](BACKUP.md) ·
> [Key custody](KEY_CUSTODY.md)

> **AUTHORIZED use only.** Nothing in this runbook arms anything. The upgrade is a
> **data maintenance** operation (schema + backup), not an offensive action.

This document describes the **UPGRADE → VERIFY → ROLLBACK** lifecycle of an already deployed Forge console, in
**a single fail-closed command**. The guiding principle: **we NEVER migrate without a verified encrypted
snapshot**, and **any failure returns to the EXACT prior state**.

---

## TL;DR

```sh
# Which schema version is this database at? (read-only, does not start the server)
forge status

# Preview WITHOUT mutating anything (shows the snapshot + the planned migration)
forge upgrade --dry-run

# Real upgrade: encrypted snapshot -> additive migrate -> verify -> rollback on failure
FORGE_UPGRADE_PASS='…' \
forge upgrade --passphrase-env FORGE_UPGRADE_PASS
```

Idempotent: re-running when the database is already up to date = **successful no-op** (verified, no change).

---

## 1. `status` — "which version is this database at"

`forge status [--db <path>] [--ledger <path>] [--json]` prints a **read-only** snapshot
(no mutation, does **not** start the server, fast exit):

| Field | Meaning |
|-------|------|
| `version` | product version (`VERSION` file, single source) |
| `schema_version` | persisted **LOGICAL** schema version (`settings.schema_version`, stamped by `migrate()`) |
| `schema_version_expected` | version expected by **this binary** (compiled in) |
| `backend` | `sqlite` (default build) or `postgres` |
| `db` | SQLite path, or **REDACTED** Postgres URL (never credentials) |
| `ledger` / `ledger_ok` / `ledger_head` | head of the audit chain, **hash-chain re-verified** |
| `ha_configured` | HA armed via `FORGE_HA` (the live *leader*, for its part, is on `/health`) |

The same version is **surfaced on `/health`** (field `schema_version`, additive) of a live instance.

> A database **older** than the stamp shows `schema_version: (non tamponnée)` (not stamped) → the next boot (or
> `upgrade`) stamps it. This is backward-compatible, never an invented value.

### Schema version history

| Version | What it adds | Effect on an existing database |
|---|---|---|
| 1 | base (`run_id`/`cwe`/`cvss` on `finding`, C2 columns on `run_job`, engagements, tenants…) | — |
| 2 | `run_job.findings_dropped` · `run_job.findings_write_errors` — accounting of findings **emitted by the engine and not stored** (see `docs/HTTP_API.md`, section `/api/ingest`) | **Two additive `ALTER TABLE … ADD COLUMN`**, idempotent (error-ignored) and **reversible** in practice: no existing data is read, written or converted; an OLDER binary plugged back onto the migrated database keeps working (it simply ignores the two columns). Rows already present take **`NULL`** — that is, "**refused share unknown**", deliberately NOT `0`: a `DEFAULT 0` would have retroactively asserted that no finding had been lost, which is precisely the lie this batch removes. |
| 3 | per-database keys `enterprise.<name>` copied to `advanced.<name>` (see §8) | **Additive**: new rows, values unchanged, old rows left in place, plus the record `migration.renamed_settings`, in the stamp's transaction; refused (nothing written) when the two names are out of step. An OLDER binary plugged back onto the migrated database reads the old rows — the values from before the upgrade — and resets the stamp to 2; the next start of the new binary compares both names and refuses at the slightest gap (§8). |

> **Postgres**: the two columns are in `PG_SCHEMA` (fresh cluster); a `migrate-store`
> migration from SQLite carries them over, because it copies the columns **enumerated** on the source
> (`PRAGMA table_info`) and requires their presence on the target.

---

## 2. `upgrade` — safe flow in one command

```
forge upgrade --passphrase-env <ENVVAR>
    [--db <path>] [--ledger <path>] [--backup-dir <dir>]
    [--to <postgres-url>] [--force] [--dry-run]
```

**FAIL-CLOSED** sequence (each step can only MOVE ON if the previous one succeeded):

1. **ENCRYPTED pre-upgrade snapshot.** Reuses the audited backup engine (**argon2id** + **XChaCha20-Poly1305**,
   per-archive salt/nonce), ledger chain verified **before** writing, archive **fsync'd**, tagged
   `pre-upgrade-<schema_version>-<epoch>.forge` in `--backup-dir` (default: the database folder). The
   snapshot is **re-verified** (decryption + manifest sha256 + hash-chain): **if it cannot be verified,
   we have NO safety net → ABORT before any mutation.** *We never migrate without a good snapshot.*
2. **Additive migrate** (idempotent `SCHEMA` + `migrate()`: `ADD COLUMN`/`CREATE TABLE IF NOT EXISTS`,
   error-ignored). Stamps `schema_version`. If `--to <postgres-url>` is provided: **governed store
   migration** SQLite → Postgres (`migrate-store`: FK order, id preservation, row-by-row count
   verification, signed ledger checkpoint) — **`store-postgres` feature** required in the image.
3. **Verify**: schema self-check (additive columns present + `schema_version == cible`) +
   `ledger verify` (hash-chain) + (store) the `migrate-store` count verification.
4. **Health self-check**: the database answers (`SELECT 1`) + consistent ledger head (the same checks as
   `/health`).
5. **On ANY failure in 2–4: RESTORE** from the pre-upgrade snapshot → back to the **EXACT** prior state,
   **non-zero exit**, clear message. **Never a half-migrated database.** On success: `schema_version`
   stamped + ledger entry **`console.upgrade {from, to, backup_id}`** (metadata only).

**Idempotent**: if the database is already at the target version, the *migrate* step is **skipped** (it is
additive-idempotent anyway) but **verification still runs** → successful no-op.

**`--dry-run`**: prints the plan (where the snapshot would be written, `would_migrate`, redacted store target)
and **mutates NOTHING** (no snapshot, no `migrate`).

### Secrets
- Snapshot **passphrase**: read **ONLY** from the ENV named by `--passphrase-env` (never in
  argv → never in `ps`/the shell history).
- **Postgres URL** (`--to`): **redacted** (no `user:pass` nor query-string) in the report AND the ledger.

---

## 3. Scenarios

### 3.1 Solo SQLite (default build)

```sh
# 1) check the state
forge status --db /data/db/forge.db --ledger /data/ledger/engagement.jsonl

# 2) preview
forge upgrade --db /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl --backup-dir /data/backups --dry-run

# 3) real upgrade
FORGE_UPGRADE_PASS='…' forge upgrade \
    --db /data/db/forge.db --ledger /data/ledger/engagement.jsonl \
    --backup-dir /data/backups --passphrase-env FORGE_UPGRADE_PASS
```

In Docker: stop the console container, run `upgrade` as a **one-shot** on the same volumes, then
restart on the new image.

```sh
docker stop forge
docker run --rm \
  -v forge-db:/data/db -v forge-ledger:/data/ledger -v forge-backups:/data/backups \
  -e FORGE_UPGRADE_PASS \
  forge:<nouvelle-version> \
  forge upgrade --db /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl --backup-dir /data/backups \
    --passphrase-env FORGE_UPGRADE_PASS
docker start forge   # boot on the new image (migrate() re-stamps, idempotent)
```

### 3.2 Postgres (advanced backend, flag-gated)

The Postgres **schema** (`PG_SCHEMA`, `migrate()` columns already merged in) is applied **at boot** of
the `store-postgres` image and **stamped** (`schema_version`) under the cluster DDL lock. Two cases:

- **Migrating SQLite DATA → Postgres** (backend switch): `store-postgres` image, then
  ```sh
  FORGE_UPGRADE_PASS='…' forge upgrade \
      --db /data/db/forge.db --ledger /data/ledger/engagement.jsonl \
      --backup-dir /data/backups --passphrase-env FORGE_UPGRADE_PASS \
      --to 'postgres://…@pg:5432/forge?sslmode=require'   # [--force] to overwrite a non-empty target
  ```
  The pre-upgrade snapshot protects the **SQLite source**; the store migration is **governed**
  (count verification, refusal to overwrite without `--force`, signed checkpoint `console.store.migrate`). Low-level
  details: [`docs/MIGRATION.md`](MIGRATION.md) §Postgres and [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) §3bis.
- **Schema bump of a Postgres database already in service**: the additive schema is applied **at boot**
  (idempotent). The Postgres logical snapshot is done by `pg_dump` (see `/api/backup` under PG and
  [`docs/BACKUP.md`](BACKUP.md)) — **before** a major `docker pull`, take that dump.

### 3.3 HA / multi-instance — rolling upgrade (drain-leader)

⚠️ **NEVER run the migration from N instances in parallel.** Under HA (shared Postgres),
several replicas writing the schema / migrating the data **at the same time** cause races
(duplicate-key, `tuple concurrently updated`). Safe procedure:

1. **Ordered boot**: the boot applies `PG_SCHEMA` under a cluster-global `pg_advisory_xact_lock` → a
   **single** replica lays down the additive schema at a time, the others see everything already present (idempotent).
   A **purely schema-additive** upgrade can therefore be done by **rolling restart** of the replicas onto the
   new image, with no manual command.
2. **If a DATA migration is needed** (`upgrade --to …` / `migrate-store`): **drain the
   leader** — update **ONE** instance out of rotation (or a dedicated maintenance instance), run
   `upgrade`/`migrate-store` **there only**, verify (`status`, `ledger verify`), **then** do the
   rolling restart of the other replicas onto the new image. Never two concurrent migrations.
3. The live *leader* is visible on `/health` (`leader: true/false`, `instance_id`) — use it to
   choose/confirm the maintenance instance.

---

## 4. Rollback

Rollback is **automatic**: at the slightest failure of the *migrate*/*verify*/*health* steps, `upgrade`
restores db + ledger from the pre-upgrade snapshot (internal `restore --force`, re-verified sha256 +
hash-chain) and **exits non-zero**. The database **is never left half-migrated**. The restore
itself is **recorded** in the ledger (`console.restore`) — the rollback is auditable.

If the automatic rollback **itself fails** (I/O, permissions), the message gives the path of the
encrypted snapshot and the exact manual command:

```sh
forge restore --in <pre-upgrade-…​.forge> --passphrase-env <ENV> \
    --to <db> --ledger <ledger> --force
```

---

## 5. Backup / Restore (reminder — one-command UX)

`upgrade` **reuses** these primitives; they can also be called on their own.

```sh
# ENCRYPTED backup (db + ledger + .ed25519 key + manifest) — passphrase via ENV, never argv
FORGE_BACKUP_PASS='…' forge backup --out /data/backups/manual.forge \
    --db /data/db/forge.db --ledger /data/ledger/engagement.jsonl \
    --passphrase-env FORGE_BACKUP_PASS

# Restore (decrypts, verifies sha256 + hash-chain, refuses to overwrite a non-empty install without --force)
FORGE_BACKUP_PASS='…' forge restore --in /data/backups/manual.forge \
    --to /data/db/forge.db --ledger /data/ledger/engagement.jsonl \
    --passphrase-env FORGE_BACKUP_PASS   # [--force] for an in-place swap
```

**Security properties** (identical to `upgrade`): archive **always encrypted** (no plaintext
path — it bundles the signing key AND the database), **AEAD-authenticated** (a wrong passphrase or
tampering ⇒ clean failure, **nothing written**), ledger chain verified **before** backup and **at**
restore, **anti-overwrite** guard (explicit `--force`), **transient** passphrase (never
stored/logged/written to the ledger). Scheduling + retention + S3/MinIO offsite: [`docs/BACKUP.md`](BACKUP.md).

### Offsite restore drill (recommended)

```sh
# 1) fetch an offsite archive (S3/MinIO or local_dir copy), validate it WITHOUT writing:
FORGE_BACKUP_PASS='…' forge restore --in /tmp/offsite-copy.forge \
    --to /tmp/restore-drill.db --ledger /tmp/restore-drill.jsonl --passphrase-env FORGE_BACKUP_PASS
# 2) check the restored database + chain:
forge status --db /tmp/restore-drill.db --ledger /tmp/restore-drill.jsonl
forge ledger verify --ledger /tmp/restore-drill.jsonl
# 3) clean up: rm /tmp/restore-drill.*
```

The `pre-upgrade-*` snapshots written by `upgrade` are **standard** backup archives: they are
**swept by the existing retention** (see the backup policy) and restorable with the command above.

---

## 6. Security properties (summary)

| Guarantee | Mechanism |
|----------|-----------|
| Never a migration without a safety net | **Encrypted + chain-verified** pre-upgrade snapshot mandatory, otherwise ABORT |
| Never a half-migrated database | Any failure in 2–4 → **RESTORE** to the exact prior state, non-zero exit |
| Safe replay | Idempotent (additive migrate; same version → skip + verify) |
| Default build byte-identical | **Additive** new subcommands; existing flows unchanged; **openssl-free** (default build — see `DEPLOYMENT.md` §3quater.1) |
| Audited crypto | Reuses the backup's argon2id + XChaCha20-Poly1305 (no new crypto path) |
| Protected secrets | Passphrase via **ENV** (never argv); Postgres URL **redacted** in log/ledger |
| Auditable | `console.backup` / `console.upgrade` / `console.restore` chained into the tamper-evident ledger |
| Correct HA | **Drain-leader** documented; never N concurrent migrations |

> Ledger **signature** verification (Ed25519/HMAC) and anti-**truncation** (high-water-mark) remain the
> responsibility of the `forge ledger verify --pubkey` engine (Python) + off-host anchoring; `upgrade`
> re-verifies the **hash-chaining** (same algorithm as `/api/ledger/verify`). See [`KEY_CUSTODY.md`](KEY_CUSTODY.md).

---

## 7. Renamed variables: `FORGE_ENTERPRISE_*` → `FORGE_ADVANCED_*`

Forge has no paid edition: the variables that engage the advanced modules carry the name `FORGE_ADVANCED_*`.
The rename has **no alias** — the old name engages nothing.

| Old name (retired) | New name |
|---|---|
| `FORGE_ENTERPRISE_STORE` | `FORGE_ADVANCED_STORE` |
| `FORGE_ENTERPRISE_COMPLIANCE` | `FORGE_ADVANCED_COMPLIANCE` |
| `FORGE_ENTERPRISE_SSO` | `FORGE_ADVANCED_SSO` |
| `FORGE_ENTERPRISE_TENANCY` | `FORGE_ADVANCED_TENANCY` |
| `FORGE_ENTERPRISE_SCIM` | `FORGE_ADVANCED_SCIM` |

**Refusal at start-up.** Ignoring an old name in silence would switch off tenant isolation, SSO or compliance
for whoever upgrades without reading this note. So a `FORGE_ENTERPRISE_*` variable that is merely **present**
(whatever its value, even empty) makes the console refuse to start — the server and every subcommand except
`--version` and `--help` — with exit code 2 and a message that names each variable found and its new name:

```text
[forge] FATAL retired environment variable(s) still set: FORGE_ENTERPRISE_SSO -> rename it to FORGE_ADVANCED_SSO. The FORGE_ENTERPRISE_* names are no longer read (renamed FORGE_ADVANCED_*, no alias); refusing to start rather than run with an advanced module silently off. See docs/UPGRADE.md §7.
```

The Python engine applies the same rule when it builds the ledger signer (`RetiredEnvNameError`). To
upgrade: rename the variables in your `.env`, compose file, ConfigMap or Deployment, then restart. The
per-database configuration keys follow in §8 — those are migrated for you, nothing removed.

## 8. Renamed settings keys, `whoami` field and error code: `enterprise` → `advanced`

The word goes from the per-database configuration keys and from what the console serves too. Nothing has an
alias: once migrated, the old names are read nowhere.

| Where | Old name (retired) | New name |
|---|---|---|
| `settings` table | `enterprise.tenancy` | `advanced.tenancy` |
| `settings` table | `enterprise.sso` | `advanced.sso` |
| `settings` table | `enterprise.scim` | `advanced.scim` |
| `settings` table | `enterprise.compliance` | `advanced.compliance` |
| `settings` table | `enterprise.superadmin` | `advanced.superadmin` |
| `GET /api/whoami` | field `enterprise` (`{tenancy, sso, scim, rbac, compliance}`) | field `advanced` (same content) |
| `GET /api/compliance/policy` | `ledger_signer.enterprise_flag` | `ledger_signer.advanced_flag` |
| HTTP 403 of `/api/tenants*` | `"error": "enterprise_disabled"` | `"error": "advanced_disabled"` |

**What the migration does — additive, and once.** Schema version **3**. During a schema pass — server start
(SQLite and Postgres), `forge upgrade`, `forge migrate`, `POST /api/setup/migrate`, `forge seed-demo`, and
`forge migrate-store` after its row-count check — on a database not yet stamped 3 and never migrated, each
`enterprise.<name>` key is **copied** to `advanced.<name>` with its value unchanged, and the old row is **left
in place**. The same transaction writes the record `migration.renamed_settings` — the list of names that existed
under the old prefix at that moment, for example `tenancy,superadmin` (empty when there were none; never a
setting value) — then the schema version stamp. Tenant isolation, SSO, SCIM, compliance and the
super-administrator are identical after the first start of the new binary; the console prints one line per
copied key (key names, never values). The new binary reads only the `advanced.*` names and never writes the
`enterprise.*` ones. Equal values under both names: nothing to copy. Different values: refusal, below. The copy
never happens a second time — the record says it was done.

**An older binary that starts again resets the stamp to 2.** A rollback, or an old pod restarted while the
rolling restart of §3.3 is in progress, starts the previous image, which stamps its own schema version (2)
without comparing anything. The next start of the new binary copies nothing: it **compares** both names and
**refuses at the slightest gap**. For each name in the record, the old and the new key must both be present and
equal; for a name outside the record whose old key is present (written meanwhile), the new key must be present
and equal. That start therefore refuses when a key LISTED in the record is missing or differs under either name,
or when an old key, listed or not, exists without an equal new key. A key set ONLY under `advanced.*`, which
never existed under the old name (absent from the record and from the `enterprise.*` rows), is not compared —
and the older binary does not see it.

**Change none of these five keys during the rollout**, until every replica runs the new image (for instance
`kubectl rollout status` on the Deployment) **and** `/health` reports `schema_version: 3`. What `/health` exposes
is the stamp of the database — shared by every replica on Postgres — that any older binary resets to 2 when it
starts; it does not tell which binary a replica runs (`version` is the same string in both images of this
release).

**A rollback shows the values from before the upgrade.** The previous image reads only `enterprise.*`: a
super-administrator revoked since the upgrade under `advanced.superadmin` is one again for it, and tenant
isolation turned on only under `advanced.tenancy` is off for it. The next start of the new binary then refuses
while a key listed in the record is missing or differs under either name, or an old key exists without an equal
new key; a key set only under `advanced.*` that never existed under the old name — the tenant isolation of this
example — is not compared, so that start goes through and the new binary applies it again.

**The refusal.** Nothing is written (the transaction is rolled back, the version is not stamped, a deleted key
stays deleted) and the console refuses to start, exit code 2. Each gap names both keys and their state —
`present`, `absent` or `differs` — never a value, since `superadmin` holds identities:

```text
[forge] FATAL settings keys out of step: enterprise.superadmin present, advanced.superadmin absent. The enterprise.* settings keys were renamed advanced.* (no alias); until the enterprise.* leftovers are removed, both names must hold the same value. Give BOTH names the same intended value; never delete an advanced.* key to get past this; if the enterprise.* rows were removed on purpose, run the complete removal of docs/UPGRADE.md §8. Refusing to start rather than pick one.
```

The last sentence depends on where the refusal happens: `forge migrate-store` ends with "migrate-store refused:
its transaction is rolled back, the target holds no copied row."; `forge migrate` and `POST /api/setup/migrate`
with "Import refused: the target database was copied but not migrated; correct the source, then import again.";
`forge upgrade` with "Upgrade refused: the database goes back to its pre-upgrade snapshot." To resolve, give both
names the same intended value — never delete an `advanced.*` key to get past the refusal. To revoke a
super-administrator, give both names the new list (an empty list designates nobody); if one of the two rows is
missing, insert it with that value first. For example on SQLite:

```bash
sqlite3 forge.db "UPDATE settings SET value='<value>' WHERE key IN ('enterprise.superadmin','advanced.superadmin');"
```

**Removing the leftovers is the point of no return.**

Once they are removed, the previous image finds no `enterprise.*` key any more: for it, tenant isolation, SSO,
SCIM, compliance and the super-administrator are **off**. Rolling back after the removal therefore OPENS tenant
isolation. Remove them only once every replica runs the new version and no rollback to an older image remains
possible. No subcommand does it: the console has no settings-maintenance command, and this release adds none.
It is ONE transaction of two statements, the same on SQLite (`sqlite3 forge.db`) and on Postgres (`psql`): delete
the five old keys AND empty the list of the record. The record stays, emptied; after it, nothing is compared AS
LONG AS no `enterprise.*` row is written again. An old row recreated afterwards (by an older binary or by hand)
is compared: the start refuses unless the new key holds the same value.

```sql
BEGIN;
DELETE FROM settings WHERE key IN ('enterprise.tenancy','enterprise.sso','enterprise.scim','enterprise.compliance','enterprise.superadmin');
UPDATE settings SET value='' WHERE key='migration.renamed_settings';
COMMIT;
```

**Never delete the `migration.renamed_settings` row.** The removal above empties it, it does not delete it.
Without the record, the next migration replays as a first migration and can copy leftover `enterprise.*` rows
back under `advanced.*` — a revoked super-administrator would be one again. Its list is read closed: an element
that is not one of the five names (other case, spaces, unknown word, empty element) makes the start refuse with
the gap `migration.renamed_settings lists unknown name "<element>"` (at most 32 characters shown, any character
outside printable ASCII as `?`).

**Browser holding the old interface.** A tab whose JavaScript predates the upgrade reads the absent
`enterprise` field of `whoami` as "no advanced module": the Identity and Compliance links stay hidden until the
page is reloaded. Nothing opens — the server keeps enforcing each module's flag and admin gate. The static files
are served without a version in their URL and without `Cache-Control`, so a reload (Ctrl+F5 if needed) after the
upgrade is the way to get the links back.

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

The Python engine applies the same rule when it builds the ledger signer (`RetiredEnvNameError`). The
per-database configuration keys (`enterprise.sso`, `enterprise.tenancy`, `enterprise.compliance`,
`enterprise.scim`) do not change. To upgrade: rename the variables in your `.env`, compose file, ConfigMap or
Deployment, then restart.

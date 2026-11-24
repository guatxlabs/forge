# Data migration — importing an existing Forge install

[English](MIGRATION.md) | [Français](MIGRATION.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Administration](ADMINISTRATION.md#6-data-migration) ·
> [Installation](INSTALLATION.md) · [Backup & restore](BACKUP.md)

This runbook migrates an **existing Forge Console** install (typically a
`systemd`/bare-metal, non-containerised deployment) to a **Docker install** (or any other target),
without losing or corrupting the audit.

Three coupled artefacts travel **together**:

| Artefact | File (default) | Role |
|----------|------------------|------|
| SQLite database | `forge.db` | findings / runs / ROE / accounts / settings |
| Engagement ledger | `engagement.jsonl` | **tamper-evident** SHA-256 chain of mutations |
| **Signing key** | `engagement.jsonl.ed25519` | Ed25519 secret (0600) that **signs** the ledger entries |

> ⚠️ **The `.ed25519` key MUST follow the ledger.** Entries written by the Python engine
> (`alg=ed25519`) can only be verified (non-repudiation) with their sibling signing key.
> Migrating the ledger **without** its key breaks verifiability: `forge ledger verify` will no longer be able to
> validate the signatures. The `migrate` subcommand copies the key automatically **as 0600**; never
> leave it behind and never loosen its permissions.

The tool **invents no default**: every path is explicit, the source is opened
**read-only** (the original install is never modified), and the migration is **itself
recorded** in the target ledger (entry `console.migrate`, continuous SHA-256 chain).

---

## Primary UX: the `forge migrate` subcommand

```
forge migrate --from <dir|db> --to <db> [--ledger <path>] [--verify]
                      [--encrypt --key-env <ENVVAR>]
```

| Flag | Meaning |
|------|------|
| `--from <dir\|db>` | Source. A **folder** ⇒ `{dir}/forge.db` + `{dir}/engagement.jsonl`. A **`.db` file** ⇒ that file + its sibling `engagement.jsonl`. |
| `--to <db>` | **Target** database (must not pre-exist — `VACUUM INTO` refuses to overwrite). |
| `--ledger <path>` | **Target** ledger (default: `engagement.jsonl` next to `--to`). The `.ed25519` key is copied next to it, as 0600. |
| `--verify` | Recomputes the SHA-256 chain of the **source ledger** and **ABORTS** (no write) on a break. |
| `--encrypt` | Writes a **SQLCipher-encrypted** database. Requires a binary compiled with `--features encryption` (otherwise a clear error). |
| `--key-env <ENVVAR>` | Name of the **environment variable** carrying the encryption key (never the key in argv → no leak via `ps`/history). |

Exit codes: `0` OK · `1` migration/verification failure · `2` usage error.

---

## Runbook A — systemd → Docker (plaintext → plaintext)

Context: the console was running under systemd with, say:

```
/var/lib/forge/forge.db
/var/lib/forge/engagement.jsonl
/var/lib/forge/engagement.jsonl.ed25519   # 0600
```

Docker target (see `docker-compose.yml`): mounted volumes
`forge-db:/data/db` and `forge-ledger:/data/ledger`, with

```
FORGE_CONSOLE_DB:     /data/db/forge.db
FORGE_CONSOLE_LEDGER: /data/ledger/engagement.jsonl
```

### 1. Stop the source console (consistency)

```bash
sudo systemctl stop forge
```

Stopping guarantees a **consistent** copy (no concurrent write). `migrate` opens the source
read-only anyway, but a clean stop avoids any in-flight WAL.

### 2. Verify + migrate in a one-shot container

Mount the source folder **read-only** and the target volumes, then run `migrate`. The same
`forge` image serves as a throwaway container (`--rm`):

```bash
docker run --rm \
  -v /var/lib/forge:/src:ro \
  -v forge-db:/data/db \
  -v forge-ledger:/data/ledger \
  forge:0.0.1 \
  forge migrate \
    --from   /src \
    --to     /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl \
    --verify
```

What the command does, in order:

1. opens `/src/forge.db` **read-only**;
2. `--verify`: recomputes the SHA-256 chain of `/src/engagement.jsonl`; **ABORTS** if it is broken
   (nothing is written on the target side);
3. copies the database by `VACUUM INTO` (consistent copy, compatible with a read-only source);
4. applies `SCHEMA` + `migrate()` on the target → an **older database is upgraded in place**
   (additive columns, new tables);
5. copies `engagement.jsonl` **and** `engagement.jsonl.ed25519` (**0600 enforced**) into
   `/data/ledger/`;
6. appends a `console.migrate` entry to the target ledger (continuous SHA-256 chain).

Output: a JSON report (`ok`, `source_db`, `target_db`, `target_ledger`, `encrypted:false`,
`ledger_copied`, `key_copied`, `verify:{ok,entries,…}`).

### 3. Start the target and re-verify

```bash
docker compose up -d forge
```

Then, once the console is up:

```bash
curl -s http://127.0.0.1:7100/api/ledger/verify | jq
# -> {"ok": true, "entries": N+1, "head": "...", "alg": "...", "sig_checked": false, ...}
```

`sig_checked:false` is normal on the console side (it does not hold the private key). For
**signature** verification (non-repudiation), use the engine, which reads
`engagement.jsonl.ed25519`:

```bash
forge ledger verify --ledger /data/ledger/engagement.jsonl
```

If the key did **not** travel, this signature verification fails — it is the symptom of an
incomplete migration. Start again, making sure that `.ed25519` is indeed present on the source side.

---

## Runbook B — plaintext → encrypted at rest (SQLCipher)

Encryption at rest is **opt-in** and **disabled by default**: the standard binary does not depend
on SQLCipher/openssl. To use it, compile a binary with the feature:

```bash
cd console
cargo build --release --features encryption   # requires a crypto backend (openssl) at compile time
```

> Without this binary, `migrate --encrypt` returns a **clear error** (« chiffrement au repos NON
> compilé », i.e. encryption at rest NOT compiled in), never a fake plaintext success. Likewise, `GET /api/setup/state` publishes
> `capabilities.sqlcipher:false` on a default build.

### 1. Migrate while encrypting the target

The encryption key is passed **through an environment variable** (never in argv). Name the
variable via `--key-env`:

```bash
export FORGE_DB_KEY='une-passphrase-forte-et-secrete'

forge migrate \
  --from   /var/lib/forge \
  --to     /data/db/forge.db \
  --ledger /data/ledger/engagement.jsonl \
  --verify \
  --encrypt --key-env FORGE_DB_KEY
```

Encryption-specific steps:

- the source database (plaintext, read-only) is **exported encrypted** via an `ATTACH … KEY` +
  `SELECT sqlcipher_export(...)`;
- the target is then opened with `PRAGMA key` **before any other statement**, then
  `SCHEMA`+`migrate()` (in-place upgrade);
- the **ledger and the `.ed25519` key stay in plaintext** and travel as in Runbook A (the ledger is
  already tamper-evident through its hash chain; its Ed25519 key is the secret to protect as 0600).

### 2. Start the encrypted console

The console **must** know the key at boot. It reads `FORGE_DB_KEY` and issues `PRAGMA key`
**immediately after opening the connection, before any query** (SQLCipher contract).
Under Docker, inject the key through the environment (e.g. a Docker secret mounted as a variable):

```yaml
# docker-compose.override.yml excerpt (image compiled with --features encryption)
services:
  forge:
    image: forge:0.0.1-encryption
    environment:
      FORGE_DB_KEY: ${FORGE_DB_KEY}   # from a secret, never committed
```

Without the correct `FORGE_DB_KEY`, the encrypted database is **unreadable** (fail-closed): the console will
not start on usable data. This is the expected behaviour.

---

## Post-migration checklist

- [ ] `GET /api/ledger/verify` → `ok:true` (hash chain intact on the console side).
- [ ] `forge ledger verify` → signatures OK (**the `.ed25519` key travelled** and is 0600).
- [ ] `ls -l <ledger>.ed25519` → `-rw-------` (0600).
- [ ] Findings / Runs / ROE tabs populated as on the source (schema upgraded, data present).
- [ ] `console.migrate` entry present at the end of the target ledger (provenance recorded).
- [ ] (encrypted) startup fails **without** `FORGE_DB_KEY`, succeeds **with** it — evidence of encryption at rest.
- [ ] Original source kept intact (read-only) until the target is fully validated.

## Alternative: `POST /api/setup/migrate` (pre-provision only)

A **public but pre-provision** endpoint exists to drive the same migration from the
first-deployment wizard, from a **pointed-to** source (server-side paths):

```bash
curl -s -X POST http://127.0.0.1:7100/api/setup/migrate \
  -H 'Content-Type: application/json' \
  -d '{"from":"/src","to":"/data/db/forge.db",
       "ledger":"/data/ledger/engagement.jsonl","verify":true}' | jq
```

It returns the ledger **verification result** and **closes (409)** as soon as the console is
provisioned (an enabled admin exists). It is a minimal shortcut: the **primary documented UX
remains the CLI subcommand** run in a one-shot container (above). Encryption
(`"encrypt":true`) there also requires a binary compiled with `--features encryption` (otherwise `400`).

---

## Migrating to the **Engagement** model (first-class object) — zero loss

The engagement is now a **first-class object**: each engagement carries **ITS OWN** scope (in/out),
**ITS OWN** mode and **ITS OWN** dedicated ledger, and each data row (`finding` / `runrecord` /
`roe_decision` / `run_job`) carries an `engagement_id`. This switch is **backward-compatible with ZERO LOSS**
for any earlier install (single-scope, single-ledger) — **nothing to do, everything keeps working**:

- **Automatic backfill.** The schema migration adds `engagement_id INTEGER NOT NULL DEFAULT 1`:
  **all** existing rows are retroactively attached to **engagement #1**. No data is
  moved, rewritten or lost.
- **Engagement #1 = your current install.** On the 1st boot, `ensure_default_engagement` creates engagement #1
  **from the CURRENT server scope** (`in_scope` + `mode`) and the **CURRENT ledger**
  (`FORGE_CONSOLE_LEDGER`). Your original scope and ledger therefore become, identically, those of
  engagement #1. The operation is **idempotent**: it never rewrites an engagement already present.
- **`campaign` remains a sub-label.** The existing free-text `campaign` field remains a **sub-label
  WITHIN** an engagement (it is **not** an engagement) — your historical campaigns remain
  readable as they are under engagement #1.
- **Ledger unchanged for #1.** Engagement #1 keeps writing to the original console ledger
  (`FORGE_CONSOLE_LEDGER`); the existing SHA-256 chain is **extended**, never broken. New
  engagements each receive a **dedicated** ledger derived server-side (`engagement-<id>.jsonl`, sibling
  of the console ledger) — never a client-supplied path (anti write-anywhere).

### Concurrent runs, isolated per engagement

The run slot is no longer a console-global FIFO: it is **one slot per engagement**. Consequences,
all **fail-closed**:

- **Inter-engagement concurrency.** Several engagements can have a live run **at the same time**;
  launching a run for B while a run of A is going returns **202**, never a cross 409.
- **Per-engagement FIFO.** A 2nd `POST /api/run` on the **same** engagement returns **409**
  (`{"error":"run_in_progress","engagement_id":<id>}`).
- **Strict isolation.** A run for A applies A's scope-guard and writes A's ledger **only**
  — it can neither read nor write the scope, the findings, the ledger or the slot of another engagement
  (each request carries its `engagement_id`; isolation by construction). A run of A cannot
  fire against a target that is only in B's scope (**400 out_of_scope** before any spawn).

**No migration action is required** to benefit from all this: a single-engagement install
is simply a deployment with **a single** engagement (#1), and the day you create a 2nd engagement
(`POST /api/engagements`), it starts isolated with its own scope and its own ledger.

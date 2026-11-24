# Encrypted backup & restore

[English](BACKUP.md) | [Français](BACKUP.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Administration](ADMINISTRATION.md#5-backup--restore) ·
> [Data migration](MIGRATION.md) · [Configuration](CONFIGURATION.md#16-scheduled-backups)

This runbook describes **backup** and **restore** of the Forge Console: the archive
format, the encryption, why **the signing key travels inside the encrypted
archive**, the restore guardrails, and scheduling + **offsite** shipping.

A backup bundles the engagement's **three coupled artefacts** — exactly the same ones
as the migration:

| Artefact | Archive entry | Role |
|----------|------------------|------|
| SQLite database | `db.sqlite` | findings / runs / ROE / accounts / settings (**consistent** snapshot via `VACUUM INTO`) |
| Engagement ledger | `engagement.jsonl` | **tamper-evident** SHA-256 chain of mutations |
| **Signing key** | `signing.ed25519` | Ed25519 secret (0600) that **signs** the ledger entries |
| Manifest | `manifest.json` | schema + per-file `sha256` (re-verified on restore) |

---

## 1. The archive is ALWAYS encrypted — there is no plaintext path

Because the archive bundles **the `.ed25519` private signing key AND the database**, it is
**always** sealed. There is **no unencrypted variant** and **a passphrase is
mandatory** (fail-closed: missing passphrase ⇒ refusal, nothing is written).

> ⚠️ **The `.ed25519` key MUST stay with the ledger.** Without it, the signed chain becomes
> unverifiable. The backup bundles it, the restore puts it back **as 0600**.

### Format (self-describing)

```
[ en-tête EN CLAIR ]                       [ ciphertext AEAD (tar chiffré) ]
 magic "FORGEBK1" (8o)                      XChaCha20-Poly1305( tar, key, nonce, AAD=en-tête )
 version (1o)                               │
 m_cost | t_cost | p_cost (argon2, 3×4o LE) │  tar = manifest.json
 salt_len(1o) | salt (16o)                  │        db.sqlite
 nonce_len(1o) | nonce (24o)                │        engagement.jsonl
                                            │        signing.ed25519
```

The header (magic | version | argon2 parameters | salt | nonce) is written **in plaintext** in front of the
ciphertext **AND bound as associated data (AAD)** of the AEAD.

### Encryption: argon2id + XChaCha20-Poly1305 (pure Rust, no C dependency)

```
passphrase ──argon2id(sel 16o aléatoire, params par défaut)──▶ clé 32o
tar(archive) ──XChaCha20-Poly1305(clé, nonce 24o aléatoire, AAD = en-tête)──▶ ciphertext‖tag
```

- **KDF**: argon2id (Algorithm id, v0x13). The salt (16 bytes) and the nonce (24 bytes) are drawn from the
  **OS CSPRNG** on every backup ⇒ two backups of the same state differ, and replaying a
  nonce is improbable. The argon2 parameters travel **in the header** (self-describing) so they
  can be re-derived on restore; they are **validated within safe bounds** before derivation
  (a corrupted header ⇒ clean error, never a panic/DoS).
- **AEAD**: XChaCha20-Poly1305. The Poly1305 tag authenticates **the body AND the header** (AAD):
  altering a single byte (body, salt, nonce or parameters) **makes decryption fail**.
- **The passphrase / derived key are NEVER stored, logged nor written to the ledger.** The derived
  key is wiped from the stack as soon as it is no longer needed.

**Wrong passphrase** or **tampered archive** ⇒ **clean** failure (invalid AEAD tag): the
restore writes **nothing**.

---

## 2. Integrity: the ledger is verified before and after

- **Before the backup**: the ledger's SHA-256 chain is verified. A **broken** chain **aborts**
  the backup (no archive written).
- **On restore**: (1) the AEAD authenticates the archive; (2) the `sha256` of **each** file
  in `manifest.json` is re-verified; (3) the chain of the extracted ledger is re-verified **before** any
  placement; (4) after placement, the chain is **re-verified** then the action is recorded.

---

## 3. Restore: anti-overwrite guard + "restart required"

Restore **refuses to overwrite** an existing **non-empty** install (database or ledger) without a
**`--force`** (CLI) or an **explicit confirmation** (API). By default, it **validates and reports**
without writing anything.

> ℹ️ **The live console already holds the database open.** An **in-place** swap replaces
> `db.sqlite`/ledger/key under an active SQLite connection: it **requires a restart** of the
> console (`docker restart` / `systemctl restart forge`) to load the restored state. Until
> that is done, the API answers `restart_required: true` with a maintenance note.

---

## 4. CLI (trusted, local path)

The passphrase is read **only from an ENV variable** (never in `argv` — no leak via
`ps`/`cmdline`), never from `--flag`.

```bash
# ENCRYPTED backup (argon2id + XChaCha20-Poly1305)
export FORGE_BK_PASS='une-passphrase-forte-et-unique'
forge backup --out /backups/forge-$(date +%s).forge --passphrase-env FORGE_BK_PASS \
    [--db forge.db] [--ledger engagement.jsonl]

# Restore: decrypts, verifies sha256 + ledger chain, refuses to overwrite without --force
forge restore --in /backups/forge-XXXX.forge --passphrase-env FORGE_BK_PASS \
    [--to forge.db] [--ledger engagement.jsonl] [--force]
```

Exit codes: `0` OK, `1` failure, `2` usage.

### Docker one-shot (manual backup)

Mount the data volumes + an output folder, pass the passphrase through the container's ENV, and
run the `backup` subcommand as a one-shot:

```bash
docker run --rm \
  -e FORGE_BK_PASS="$FORGE_BK_PASS" \
  -v forge_data:/data \
  -v "$PWD/backups:/backups" \
  forge \
  forge backup \
    --out /backups/forge-$(date +%Y%m%d-%H%M%S).forge \
    --passphrase-env FORGE_BK_PASS \
    --db /data/forge.db \
    --ledger /data/engagement.jsonl
```

The output archive (`/backups/*.forge`) is encrypted and bundles database + ledger + key.

---

## 5. API (admin-gated, written to the ledger)

All routes require an **admin session** (`check_admin`, otherwise `403`). Each action is
**written to the ledger** (metadata **only** — never the passphrase).

| Route | Role |
|-------|------|
| `POST /api/backup` | Body `{passphrase}` ⇒ creates the encrypted archive and **returns it as a download** (`Content-Disposition`). Ledger `console.backup`: actor + timestamp + archive **size + sha256**. |
| `POST /api/restore` | Body `{archive_b64, passphrase, apply?, confirm?}`. **By default**: validates + verifies + reports (no write). `apply:true` **requires** `confirm:true` ⇒ in-place swap (**restart required**). Ledger `console.restore.validate` / `console.restore`. |
| `GET /api/backup/policy` | Scheduled/offsite policy, **secrets redacted** (`***REDACTED***`); `passphrase_env` (an ENV NAME) kept. |
| `POST /api/backup/policy` | Saves the (validated) policy; any plaintext `passphrase` is **removed** before persistence. Ledger `console.backup.policy.set`. |

The **passphrase** travels in the request body, is used once (derivation) then
**discarded** — never persisted on the server side nor on the browser side (the fields are cleared after sending).

### UI (`#admin` → « Sauvegarde & restauration », Backup & restore)

- **Create a backup**: prompts for the passphrase (entered twice) ⇒ downloads the encrypted archive.
- **Restore**: file selection + passphrase + *apply* / *confirm* boxes (the swap requires
  both). By default: non-destructive validation with a report.
- **Policy editor**: interval, retention, `passphrase_env`, staging, offsite destination.

---

## 6. Scheduled backup + offsite

Configured via `settings.backup_policy` (no hard-coded value; **without a policy, no
scheduled backup**). A **periodic runner in the console** checks on each tick whether a backup
is **due**; it is **fail-open**: a backup/shipping failure is **logged + written to the ledger**
(`console.backup.error`) but **never crashes** the console.

```json
{
  "enabled": true,
  "interval_secs": 86400,
  "retention": 7,
  "passphrase_env": "FORGE_BACKUP_PASSPHRASE",
  "staging_dir": "/data/backups",
  "offsite": { "kind": "exec", "program": "/usr/bin/rclone",
               "args": ["copy", "{archive}", "remote:forge-backups/"], "timeout_secs": 300 }
}
```

- **`passphrase_env`**: the passphrase of the **scheduled** backup comes from this **ENV variable**
  of the console process — **never** stored in plaintext in `settings`. If the ENV is missing ⇒ the scheduled
  backup **fails closed** (logged/written to the ledger), without exposing anything.
- **`retention`**: keeps the *N* most recent local archives in `staging_dir`
  (`0` = unlimited).
- **`offsite.kind` ∈ {none, local_dir, exec}** (**closed** list):
  - `none`: nothing is shipped (default).
  - `local_dir`: copies the archive into `dir`.
  - `exec`: runs a **FIXED argv** (no shell, `program` = **absolute path**) with a **timeout**.
    The literal token `{archive}` in `program`/`args` is replaced by the archive path.
    Ideal for `rclone`/`scp`/`aws s3`. **No inline secret**: provide the credentials via
    the process ENV (e.g. `RCLONE_CONFIG_*`) or a mounted config file, never in the policy.

The runner tick is adjustable via `FORGE_BACKUP_TICK_SECS` (default 60 s).

### Alternative: cron / systemd-timer

If you prefer to drive the backup **outside** the console, disable the policy (`enabled:false`)
and schedule the CLI subcommand. systemd-timer example:

```ini
# /etc/systemd/system/forge-backup.service
[Service]
Type=oneshot
Environment=FORGE_BK_PASS=%I
ExecStart=/usr/local/bin/forge backup \
  --out /data/backups/forge-%%Y%%m%%d.forge --passphrase-env FORGE_BK_PASS \
  --db /data/forge.db --ledger /data/engagement.jsonl

# /etc/systemd/system/forge-backup.timer
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
```

(The passphrase must come from a protected source — `systemd` credential, `0600` file, or
secrets manager — never a committed literal.)

---

## 7. What is NEVER written to the ledger / the logs

- Neither the **passphrase** nor the **derived key** (no entry, no log).
- The content of **offsite secrets** (`GET /api/backup/policy` redacts any *secretish* field).

Ledger entries (`console.backup`, `console.restore`, `console.backup.scheduled`,
`console.backup.offsite`, `console.backup.policy.set`) carry only **metadata**: actor,
timestamp, archive size/sha256, offsite `kind`, status.

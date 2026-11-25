# Forge — Self-service deployment (runbook) & footprint

[English](DEPLOYMENT.md) | [Français](DEPLOYMENT.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Installation](INSTALLATION.md) ·
> [First deployment (wizard)](FIRST_DEPLOYMENT.md) · [Configuration](CONFIGURATION.md) ·
> [**Upgrade / migration / backup (runbook)**](UPGRADE.md)

> **AUTHORIZED use only.** Forge stays **INERT by default** (empty `in_scope` = everything refused).
> Nothing in this runbook arms anything: the operator arms each layer consciously (see the
> 4-layer ROE gate in the [README](../README.md)).

This document is the **end-to-end self-deploy runbook** for a fresh client: choose an image,
run it, provision the install **from the browser** (wizard — **nothing hard-coded**),
migrate any existing data, and set up **scheduled encrypted
backups**. The second half keeps the **measured footprint** and the deployment matrix.

**Table of contents**

1. [Build & run options](#1-build--run-options) — mini/full, Docker, docker-compose, native/systemd, `encryption` image (§1.5), **field** encryption of auth material (§1.6, default build)
2. [First boot — the web wizard](#2-first-boot--the-web-wizard) — admin, crypto, detection source, operator policy
3. [Data — migration & encrypted backups](#3-data--migration--encrypted-backups)
4. [Build context & `guatx-core` dependency](#4-build-context--guatx-core-dependency)
5. [`/health` liveness & `Host` header](#5-health-liveness--host-header)
6. [Measured footprint & deployment matrix](#6-measured-footprint--deployment-matrix) *(reference)*

---

## 1. Build & run options

> ℹ️ **Build context = the ROOT of this repository.** The console resolves `guatx-core` through a pinned
> public git-dep (`git = "https://github.com/guatxlabs/core", tag = "v0.2.6"`, see
> `console/Cargo.toml`) — the core is fetched from GitHub at build time, no sibling crate required. All
> the `docker build`/`docker compose` commands below are run **from the repository root** (a
> standalone clone is enough). Details in [§4](#4-build-context--guatx-core-dependency).

### 1.0 MANDATORY pre-step — the scope file (fail-loud)

The active scope/ROE is **mounted as a volume**, never baked into the image. Create the **file** before any `up`:

```sh
# from the repository root
cp scope.example.json scope.json          # empty in_scope = INERT; edit WITH written AUTHORIZATION
```

If `scope.json` is missing, Docker creates an empty **directory** in its place: the compose entrypoint
**fails loudly** (explicit message) rather than starting on an unreadable scope. Missing/empty
without a directory ⇒ fallback to the embedded `scope.example.json` (INERT). `scope.json` stays gitignored.

### 1.1 Image profiles: `mini` vs `full`

A single `--build-arg FORGE_TOOLS_PROFILE` switches the footprint. Modules **degrade cleanly**
(`available:false`) when a tool is missing — no error, the engine handles it.

| Profile | Contents | Size | `?format=pdf` | PD modules (httpx/nuclei/subfinder) |
|---|---|---|---|---|
| `mini` | console + `python3` + `nmap` | **~150-250 MB** | `pdf_unavailable` (browser printing) | `available:false` |
| `full` *(default)* | + ProjectDiscovery binaries (SHA256-verified) + weasyprint PDF engine | **~350-500 MB** | turnkey active | available |

### 1.2 Docker (image only)

```sh
# from the repository root
# full (default)
docker build -t forge:0.0.1 .
# mini
docker build --build-arg FORGE_TOOLS_PROFILE=mini -t forge:0.0.1-mini .

docker run -d --name forge \
  -p 127.0.0.1:7100:7100 \
  -v forge-db:/data/db -v forge-ledger:/data/ledger \
  -v "$PWD/scope.json:/data/scope/scope.json:ro" \
  --env-file .env \
  forge:0.0.1
```

> Bind **loopback only** (`127.0.0.1:7100`). Expose publicly only through a
> reverse-proxy + auth + `FORGE_CONSOLE_HOST` (anti-DNS-rebinding host-allowlist) — see [§5](#5-health-liveness--host-header).

### 1.3 docker-compose *(recommended)*

The compose file already sets the right context, the scope fail-loud, the volumes, the `/health` healthcheck
and the loopback bind. **Optional services behind profiles** ⇒ a bare `up` starts the **console alone**.

```sh
# from the repository root
docker compose up -d --build          # console ALONE (full profile by default)
FORGE_TOOLS_PROFILE=mini docker compose up -d --build   # console ALONE, mini image

# optional layers, on demand (none is required at boot):
docker compose --profile browser up -d        # + access/evasion (Camoufox :8080)
docker compose --profile msf --profile burp up -d   # + connectors (BYO images)

docker compose config      # validate the resolved configuration
```

Secrets & overrides (argon2id hashes, tokens, URLs of the driven services, keys) → `.env`
(gitignored, `required:false`). Commented template: [`.env.example`](../.env.example). The
`browser`/`msf`/`burp` connectors stay **inert** as long as their service is not reachable (probe at fire-time).

> **Secrets without a plaintext `.env`.** Each env secret accepts a `<VAR>_FILE` twin: the env carries a
> **path**, the secret lives in a **root-owned mounted file** (Docker secret / k8s Secret), not in
> a `.env` sitting next to the app. Details, table of covered secrets, and what is already write-only
> through the UI (detection, SSO `client_secret`): [`docs/SECRETS.md`](SECRETS.md).

### 1.4 Native / systemd (without Docker)

Hardened unit provided: [`deploy/forge.service`](../deploy/forge.service)
(`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`, seccomp `@system-service`…).
The systemd hardening **weakens no application guardrail**; it reinforces process isolation.

```sh
cd console && cargo build --release            # from the repository root; offline binary (cargo cache)
sudo install -m0755 target/release/forge /usr/local/bin/
sudo mkdir -p /opt/forge && sudo cp -r ../forge /opt/forge/forge && sudo cp -r web /opt/forge/console/web
sudo useradd --system --home /opt/forge --shell /usr/sbin/nologin forge
sudo mkdir -p /var/lib/forge/{db,ledger,scope}                      # fill scope/scope.json WITH AUTHORIZATION
sudo install -m0600 -o root -g forge /dev/null /etc/forge/forge.env   # put the argon2id hashes in it
sudo cp deploy/forge.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now forge
```

The Python package is **pure-stdlib** (`deps=[]`): it also fits in a venv **with no pip dependency at all**.

### 1.5 `encryption` image (encryption AT REST — SQLCipher, opt-in)

> ℹ️ The **authentication material** (bearers/cookies/headers of an engagement's test accounts)
> is encrypted **per field**, in the **default** build, without SQLCipher — see
> [§1.6](#16-field-encryption-of-authentication-material-default-build). SQLCipher below
> encrypts **everything else** on top, at the cost of a system crypto backend at compile time.

The **default** build stores the SQLite database **in plaintext** (`capabilities.sqlcipher:false`). For
encryption at rest, compile the console with the `encryption` feature then provide the key at boot:

```sh
# 1) encrypted image (Cargo feature -> SQLCipher crypto backend)
cd console && cargo build --release --features encryption   # from the repository root
#    (Docker: build an image tagged forge:0.0.1-encryption with this feature)

# 2) at boot, the console reads FORGE_DB_KEY and issues `PRAGMA key` BEFORE any query (SQLCipher contract)
#    docker-compose.override.yml excerpt:
#      services:
#        forge:
#          image: forge:0.0.1-encryption
#          environment:
#            FORGE_DB_KEY: ${FORGE_DB_KEY}     # [SECRET] from .env/docker secret, NEVER committed
```

Without the correct `FORGE_DB_KEY`, the encrypted database is **unreadable** (fail-closed). Converting an existing
plaintext install → encrypted = **Runbook B** of [`docs/MIGRATION.md`](MIGRATION.md). The wizard exposes
`capabilities.sqlcipher` (true only on this build) so that the UI reflects it honestly.

> **Apart from** crypto AT REST (opt-in), the **engagement ledger** is signed with **Ed25519** (asymmetric,
> verifiable by a third party with the public key alone) **by default** — no action required.

### 1.6 FIELD encryption of authentication material (default build)

An engagement's `scope_json` can carry an **authentication context** (`auth.accounts[]`):
the operator's **bearers, cookies and header values of test accounts** — that is,
**authenticated sessions on a client's estate**. It is the only data in the database that is a
*live credential*. It is **encrypted at rest in the default build**, without SQLCipher and **without
any additional dependency**: the **pure Rust** AEAD stack already embedded (XChaCha20-Poly1305 +
argon2id — the one that encrypts backups) is reused. The **default** build's `openssl-freedom`
stays intact ([§3quater.1](#perimetre-de-l-openssl-freedom) — 0 occurrences measured).

```sh
# The key follows the in-house <VAR>_FILE pattern (see "Secrets without a plaintext .env"):
FORGE_FIELD_KEY=<passphrase forte>          # ... OR, better:
FORGE_FIELD_KEY_FILE=/run/secrets/forge_field_key   # root-mounted Docker/k8s secret, the env only carries a PATH
```

**What is encrypted, and what is not** (deliberate scope):

| Data | At rest | Why |
|---|---|---|
| `auth.accounts[].bearer` / `.cookies` / values of `.headers` | **encrypted** | replayable credential |
| `auth.accounts[].label`, header/cookie **names** | plaintext | not secret; the editor re-displays them **without the key** |
| `auth.idor_targets[]` (`url`/`owner`/`marker`) | plaintext | config already served back in plaintext by the API |
| `users.pass_hash` (argon2id), `session.token_sha` (SHA-256) | plaintext | **one-way** fingerprints, not replayable material |

**Fail-closed — three rules, no silent degradation:**

1. **No auth context ⇒ no key required.** An install that does not arm a context is
   **never** affected: behaviour and payloads unchanged.
2. **Writing material without a key ⇒ `503 field_key_missing`.** A credential is **never** persisted
   in plaintext "for the time being". The message names the variable to set. *(Re-framing a scope without
   re-entering material remains possible without the key: nothing new needs encrypting.)*
3. **Launching a run whose material does not open ⇒ the run is REFUSED** (`auth_context_sealed`).
   Starting with an **empty** auth context would silently disarm the access-control oracles: the
   engine would appear to run while no longer testing anything cross-account. There is no fallback.

**Migration of an existing install: automatic, at boot.** Earlier rows carry the material
in plaintext; the console **seals them in place** at startup (idempotent, replayable). Without a key, nothing
is converted and the boot **shouts** about it — letting people believe in encryption would be worse than acknowledged plaintext:

```
[forge] ⚠️ MATÉRIEL D'AUTHENTIFICATION EN CLAIR AU REPOS — 2 engagement(s) … FORGE_FIELD_KEY n'est pas posée …
[forge] CHIFFREMENT DE CHAMP ARMÉ — 2 engagement(s) avec matériel d'authentification, chiffré AU REPOS …
```

(The first line says the authentication material is in plaintext at rest and `FORGE_FIELD_KEY` is not set;
the second that field encryption is armed and the material is encrypted at rest.)

The state is also **visible in the product**: `GET /api/engagements` returns `auth.at_rest` ∈
`sealed | plaintext | mixed | none` (no secret — just the state).

> ⚠️ **CUSTODY — `FORGE_FIELD_KEY` is a secret to keep, just like the backup
> passphrase.** A backup restored on a machine without this key yields an **intact** database whose
> auth material stays **sealed**: runs of those engagements will refuse to start until
> the key is provided. The two secrets are **independent** and **both required** (see
> [`docs/KEY_CUSTODY.md`](KEY_CUSTODY.md)). Losing the key entails no loss of any other data: it
> is enough to **re-enter** the authentication material in the engagement editor.

The two layers **compose**: `--features encryption` (SQLCipher) on top of sealed fields
remains valid — the field is then encrypted twice, which has no side effect.

---

## 2. First boot — the web wizard

**Nothing is hard-coded.** A fresh install has **no admin, no real scope, no detection
source**: everything is provisioned **from the browser** on first access.

1. Open **`http://127.0.0.1:7100`** (or the reverse-proxy URL). The SPA calls `GET /api/setup/state`:
   - `needs_setup:true` ⇒ the **wizard** is displayed;
   - `capabilities.sqlcipher` ⇒ the UI knows whether encryption at rest is available (`encryption` image).
2. **The wizard `POST /api/setup`** (a **PUBLIC but self-disabling** route: `409` as soon as an admin
   exists). Fields — only the admin is required, **everything else is persisted only if provided**:
   - **Create the admin** (`admin_login` + `admin_password`) → **argon2id** hash, role `admin`. The
     password/hash is **never** logged nor written to the ledger. The browser **lands logged in** (cookie
     `forge_session`, HttpOnly/SameSite=Strict).
   - **Crypto** — the ledger is already signed with **Ed25519** automatically; encryption **at rest**
     depends on the image (`encryption`, see [§1.5](#15-encryption-image-encryption-at-rest--sqlcipher-opt-in)),
     surfaced via `capabilities.sqlcipher`.
   - **Detection source = THEIR infra** (`detection_source`, optional) — a **configurable, code-free**
     plugin: FortiGate/pfSense/OPNsense/CrowdSec/Elastic/OpenSearch/file/exec… Model, presets
     and MITRE mapping: **[`docs/DETECTION.md`](DETECTION.md)**. Can also be set later in
     Administration → « Source de détection » (*Detection source*). The auth secret is **write-only** (never returned/logged).
   - **Operator policy** (`operator_policy`, optional) — governs the **operator/C2** role (RBAC);
     empty = C2 **closed** (fail-closed). `session_ttl` optional.
3. The auth gate **engages** as soon as an enabled admin exists (the DB state is authoritative). `/api/setup`
   closes for good.

> ⚠️ **Security — DO NOT expose the port BEFORE the first provisioning.** The zero-config wizard is
> **public by design** until an admin exists (`POST /api/setup` self-disables with `409`
> only once the admin is created). As long as the install is blank, **whoever reaches the host before you
> can claim the admin** — standard exposure of self-hosted wizards. The code handles the race
> (atomic admin creation, `/api/setup` fail-closed from the first admin), **but the port must stay
> on loopback / behind auth as long as the install is not provisioned.** The default bind is
> already **`127.0.0.1:7100`** (loopback) — **do NOT switch to `0.0.0.0` before claiming the admin.**
> Provision first (locally or through an authenticated tunnel/reverse-proxy), publish afterwards. In
> headless mode, provision through env variables (below) **before** the first exposed start.

**Headless provisioning** (no browser): set `FORGE_CONSOLE_PASS_HASH` /
`FORGE_CONSOLE_OPERATOR_HASH` (argon2id hashes via `forge hashpw` / `hashpw-operator`) and
`FORGE_CONSOLE_TOKEN` in `.env`/the EnvironmentFile — the `state` then switches to `provisioned:true` without the wizard.

**RBAC/administration after boot**: account management via `/api/users` (admin); **Basic** = viewer
(read), **Bearer token** = agent/admin (ingestion write), **operator** role for the governed C2.
All routes (except `/health`) sit behind **host-guard** (anti-rebinding) + **auth-guard**.

---

## 3. Data — migration & encrypted backups

### 3.1 Migrating an existing install

Move a **systemd/bare-metal** install to Docker (or any target) **without losing the audit**. Three
**coupled** artefacts travel together: the SQLite database, the `engagement.jsonl` ledger, **and its
`.ed25519` signing key** (otherwise the signed chain becomes unverifiable). Full runbook + guardrails:
**[`docs/MIGRATION.md`](MIGRATION.md)**.

```sh
# Primary UX: one-shot container at the 1st deployment (source opened READ-ONLY, never mutated)
docker run --rm \
  -v /ancien/forge:/import:ro -v forge-db:/data/db -v forge-ledger:/data/ledger \
  forge:0.0.1 \
  forge migrate --from /import --to /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl --verify
# encrypt along the way (`encryption` image): ... --encrypt --key-env FORGE_DB_KEY   (key via ENV, never argv)
```

The wizard also offers a **pre-provision import** (`POST /api/setup/migrate`), **opt-in** and reserved
for pre-deployment (disabled by default: `FORGE_ALLOW_API_MIGRATE` + `FORGE_CONSOLE_IMPORT_DIR`); the
CLI path above remains the documented UX.

**Updating an ALREADY deployed console** (schema bump after a `docker pull` of a more
recent image) → **a single fail-closed command** `forge upgrade`: **encrypted** pre-upgrade snapshot →
additive `migrate` → schema/ledger/health verification → **automatic rollback** at the slightest failure. See the dedicated
runbook **[`docs/UPGRADE.md`](UPGRADE.md)** (solo SQLite, Postgres, HA rolling-upgrade, restore drill).
The schema version is visible via `forge status` and the `schema_version` field of `/health`.

### 3.2 Encrypted backups + scheduling + offsite

The backup archive is **ALWAYS encrypted** (argon2id + **XChaCha20-Poly1305**, pure Rust) — there
is **no plaintext path**, because it bundles **the signing key AND the database**. Format,
restore, guardrails and offsite shipping: **[`docs/BACKUP.md`](BACKUP.md)**.

- **Policy** (enable / interval / retention / offsite `rclone`|`exec`): set in
  Administration → « Sauvegarde & restauration » (*Backup & restore*) or `POST /api/backup/policy` — **nothing hard-coded**. The name of the ENV
  carrying the passphrase is referenced by `policy.passphrase_env` (never the passphrase in plaintext in the DB).
- **In-console scheduler** (fail-open: a failure is logged + written to the ledger, never crashes the console),
  driven by 2 environment knobs:

| Variable | Role | Default |
|---|---|---|
| `FORGE_BACKUP_TICK_SECS` | scheduler wake-up period | `60` s |
| `FORGE_BACKUP_PASSPHRASE` | **[SECRET]** passphrase (ENV name referenced by `policy.passphrase_env`) | — |

Restore: `POST /api/restore` (or CLI), mandatory passphrase (fail-closed), `sha256` manifest
re-verified, `.ed25519` key put back as `0600`.

### 3.3 S3/MinIO object store for artefacts (`s3` offsite) — Cargo feature `object-store` (OPT-IN)

Artefact storage (offsite backup archive, exports/evidence) goes through a backend-agnostic **BlobStore
seam** (`console/src/blob.rs`). The **DEFAULT build** compiles only
`LocalFsBlobStore` (**file system**, no new dependency): the default path (no
S3 artefact configured) is **unchanged**. The **S3/MinIO** implementation (`S3BlobStore`) and its
`rust-s3` dependency live **behind the Cargo feature `object-store`** (OFF by default). The default build
(feature OFF) pulls **no** S3 dependency and stays byte-identical.

⚠️ **This feature is the ONLY perimeter where the repository's openssl-freedom does not hold** — and this was
wrongly claimed here before. `rust-s3` is indeed wired as `sync-rustls-tls` (so **neither** `native-tls` **nor**
`openssl`), but the `attohttpc → rustls/DEFAULT` chain pulls in **`aws-lc-rs`/`aws-lc-sys`**: **12**
forbidden occurrences measured, against **0** in the default build. The chain is **transitive** — not
fixable without forking `rust-s3`/`attohttpc`. Practical consequence: building with `object-store`
requires a **C + cmake** toolchain at build time (nothing more at runtime). Details, measurements and automatic
guard: [§3quater.1](#perimetre-de-l-openssl-freedom).

**Runtime selection**: `S3BlobStore` is chosen **only** if the feature is compiled **AND** the S3
ENV is configured; otherwise `LocalFsBlobStore` (root `FORGE_BLOB_DIR`, default `blobs/` sibling of the database).

| Variable | Role | Default |
|---|---|---|
| `FORGE_BLOB_DIR` | local store root (feature OFF **or** S3 not configured) | `blobs/` sibling of the database |
| `FORGE_BLOB_S3_ENDPOINT` | S3/MinIO endpoint (e.g. `http://minio:9000`) — **required** for S3 | — |
| `FORGE_BLOB_S3_BUCKET` | target bucket — **required** for S3 | — |
| `FORGE_BLOB_S3_ACCESS_KEY` | **[SECRET]** access key — **required** for S3 | — |
| `FORGE_BLOB_S3_SECRET_KEY` | **[SECRET]** secret key — **required** for S3 | — |
| `FORGE_BLOB_S3_REGION` | SigV4 region (MinIO ignores it but SigV4 requires it) | `us-east-1` |

**Path-style** addressing enforced (MinIO-compatible). Credentials live **only in the ENV** —
never in the database, never in the backup policy, never logged/written to the ledger (traces carry
only `backend`/`bucket`/`key`/`url`).

**`s3` offsite backup**: under the feature, the backup policy accepts `offsite.kind = "s3"` (optional
key prefix `key_prefix`). The scheduler PUTs the **encrypted** archive to the S3 bucket, referenced by
key/URL — trace `console.backup.offsite` (kind + status, no secret). Policy example:

```jsonc
POST /api/backup/policy
{ "enabled": true, "interval_secs": 86400, "retention": 7,
  "passphrase_env": "FORGE_BACKUP_PASSPHRASE",
  "offsite": { "kind": "s3", "key_prefix": "offsite/backups" } }
```

**Build & validation (MinIO round-trip)**:

```bash
cd console && cargo build --release --features object-store   # (Docker: --build-arg FORGE_CARGO_FEATURES=object-store)

# test MinIO + bucket
docker run -d --rm -e MINIO_ROOT_USER=forge -e MINIO_ROOT_PASSWORD=forgepw123 \
    -p 9000:9000 --name forge-minio minio/minio server /data
docker run --rm --network host --entrypoint sh minio/mc -c \
    'mc alias set l http://localhost:9000 forge forgepw123 && mc mb l/forge-artifacts'

export FORGE_BLOB_S3_ENDPOINT=http://localhost:9000 FORGE_BLOB_S3_BUCKET=forge-artifacts \
       FORGE_BLOB_S3_ACCESS_KEY=forge FORGE_BLOB_S3_SECRET_KEY=forgepw123
# PUT→GET→EXISTS→DELETE round-trip on the active store (S3 here, otherwise local)
forge blob-selftest --key evidence/proof.bin
# ships a REAL artefact (encrypted backup archive) through the wired offsite producer, then GET-verifies it
forge blob-selftest --file ./mon-archive.forge --key-prefix offsite/backups
```

Feature OFF (default), the `blob-selftest` subcommand does not exist and only the local store is available.

---

## 3bis. Postgres backend (Stage 4 — HA / multi-instance)

The DEFAULT backend is **SQLite** (local file, zero dependency) — **unchanged**. An OPT-IN
**Postgres** backend exists behind the Cargo feature `store-postgres`: several **stateless console**
instances can share **ONE** Postgres database. The PG backend is **openssl-free** — TLS `rustls` +
`ring` provider, never native-tls/openssl, **0** forbidden occurrences measured under
`--features store-postgres` ([§3quater.1](#perimetre-de-l-openssl-freedom)); the default build (feature
OFF) compiles **no** Postgres dependency and stays byte-identical.

### 3bis.1 Build & run with Postgres

Two runtime settings drive the selection (**FAIL-CLOSED** gate):

| Variable | Role |
|---|---|
| `FORGE_ADVANCED_STORE=postgres` | selects the Postgres backend (otherwise SQLite) |
| `FORGE_DB_URL` | DSN `postgres://user:pass@host:5432/db` — **required** if `…=postgres` (otherwise refuses to start) |

The feature must be **compiled** into the binary (`FORGE_ADVANCED_STORE=postgres` on a default-build
binary fails at boot with a clear message « rebuild with `--features store-postgres` »).

```sh
# Native: build the feature (openssl-free) then run
cd console && cargo build --release --features store-postgres
FORGE_ADVANCED_STORE=postgres \
FORGE_DB_URL='postgres://forge:forge@db.internal:5432/forge' \
  ./target/release/forge
```

**docker-compose** — an ADDITIVE override (`docker-compose.postgres.yml`) recompiles the image with the
feature (`--build-arg FORGE_CARGO_FEATURES=store-postgres`, which also installs `pg_dump`/`pg_restore`
in the image) and starts a `postgres:16` service (profile `postgres`). The default SQLite deployment
(`docker-compose.yml` alone) stays **unchanged**:

```sh
# from the repository root — postgres profile + override
docker compose -f docker-compose.yml -f docker-compose.postgres.yml \
               --profile postgres up -d --build
```

Default EVAL credentials (`forge/forge`) — **override** them in prod via `.env`
(`FORGE_PG_USER`/`FORGE_PG_PASSWORD`/`FORGE_PG_DB`, picked up both by the `postgres` service and by
`FORGE_DB_URL`). **Never** publish the Postgres port publicly (the service stays `expose:`-only on
the compose network).

### 3bis.2 Migrating SQLite data → Postgres (Stage 3, governed)

If you already have SQLite data to keep, migrate it **BEFORE** the 1st Postgres run with the governed
migrator (table-by-table copy in FK order, realignment of IDENTITY sequences, **row-by-row count
verification** with ROLLBACK on mismatch, **signed ledger checkpoint**):

```sh
# dry-run first (writes NOTHING) — inspects what WOULD be copied
forge migrate-store --to 'postgres://forge:forge@postgres:5432/forge' \
  --from /data/db/forge.db --ledger /data/ledger/engagement.jsonl --dry-run
# then the real migration (--force to overwrite a non-empty target)
forge migrate-store --to 'postgres://forge:forge@postgres:5432/forge' \
  --from /data/db/forge.db --ledger /data/ledger/engagement.jsonl
```

Exit codes: `0` OK · `1` governance refusal (non-empty target without `--force`) or count mismatch
(rollback) · `2` usage/connection/schema · **`3` migration committed but ledger checkpoint not written**
(governance: a migration without its tamper-evident checkpoint **never** reports success — to be
treated as a failure, re-issue the checkpoint). In Docker, run it through a one-shot container
`run --rm --entrypoint forge … migrate-store …` (see `docker-compose.postgres.yml`).

### 3bis.3 Postgres backup & restore (`pg_dump`)

Under an active Postgres backend, `forge backup` (CLI / `POST /api/backup` / scheduler) backs up
**Postgres** — no longer the SQLite file (which would be **empty**). The `db` artefact of the encrypted archive is a
**`pg_dump -Fc`** dump (custom format, compressed, **restorable via `pg_restore`**), under the entry
`db.pgdump` (the manifest carries `db_format: "pgdump"`). `pg_dump` is invoked with a **fixed argv (no-shell)**
and the DSN credentials are **redacted** in the logs/the ledger. **If `pg_dump` is missing** from the PATH,
the backup **fails with a clear message** (never a silent fallback to an empty SQLite) — hence
`postgresql-client` in the PG image.

The rest of the chain is **unchanged**: archive **always encrypted** (argon2id + XChaCha20-Poly1305),
ledger + `.ed25519` key included, ledger chain verified before/after.

**Postgres restore** (manual, outside the console) — extract `db.pgdump` from the decrypted archive then:

```sh
# 1) decrypt the archive (POST /api/restore apply=false, or the restore tool) and extract db.pgdump
# 2) restore into a target database with pg_restore (custom format)
createdb -h HOST -U forge forge_restored
pg_restore -h HOST -U forge -d forge_restored --no-owner db.pgdump
# check: pg_restore --list db.pgdump  (lists the TABLE DATA — non-trivial + restorable dump)
```

> The **in-place swap** of `POST /api/restore apply=true` stays SQLite-only (it replaces the local
> file). Under Postgres, restore is done via `pg_restore` above (the dump is a standard PG
> artefact). The SQLite `restore` CLI is **not** the PG path.

### 3bis.4 `/health` liveness under PG

`/health` (§5) **pings the ACTIVE store**: under PG it runs a `SELECT 1` **through the backend** (hence via
the HA **reconnect+retry** — see 3bis.5). **Additive `db`** field: `"ok"` if the ping succeeds, `"degraded"`
if the database is unreachable. The probe stays **fast and non-fatal**: `/health` **always answers 200**
(liveness of the HTTP router) even when `degraded`, so the `HEALTHCHECK` (which only tests the 200 code)
does not flap on a transient DB outage — but a supervisor can read `db` to raise an alert.

### 3bis.5 HA / multi-instance — what is turnkey and what is NOT

**Turnkey**: `N` **stateless** console instances against **ONE** shared Postgres database. Each instance
holds a **session-pinned client**; on an outage (Postgres restart/failover) a store operation
that fails with a **connection error** **RECONNECTS once then REPLAYS** the operation
(reconnect at the granularity of an operation — never in the middle of a transaction; an
`INSERT`+`last_insert_id` pair cannot straddle a reconnect). The PG seam shares the same **lock
granularity** as SQLite.

**NOT turnkey — real constraints to know (let us be honest):**

- **The tamper-evident ledger is a FILE (`engagement.jsonl`), not in Postgres.** Multi-instance
  therefore requires either **shared storage** for this file (RWX volume / NFS — beware of concurrent
  appends: the console serialises its own appends under a **per-instance** lock, which does
  **not** cover two instances writing the **same** file in parallel), or **one ledger per
  instance** (separate chains, to be aggregated on read). There is **no** turnkey transactional
  shared ledger. For true multi-writer, prefer **one ledger per instance** (each
  chain stays independently verifiable) over a shared file exposed to concurrent appends.
- **Per-instance / eventually consistent in-memory caches.** Several caches are **local** to
  each process and **recomputed at boot / after a mutation made BY THAT instance**:
  `detection_config` (detection source), `auth_required` (auth gate engaged), the **ledger head**
  (`prev`/`seq`). A mutation made through **instance A** (e.g. changing the detection source, creating an
  account) does **not** invalidate the cache of **instance B** until B reboots / repeats
  the action → **eventual consistency** window. The **data** (table `settings`/`users`…) is consistent
  in Postgres immediately; it is the **cache** that lags. Safe for reading (readable fail-open),
  but do not count on instant inter-instance propagation of admin settings.
- **Sticky sessions recommended**: per-instance caches + the per-instance ledger head make
  **sticky** routing (an admin session → always the same instance) more predictable than pure
  round-robin.

In short: **read/execution scale-out against a shared Postgres = OK**; the shared audit-ledger
and instant propagation of admin settings **are not** automatic — size accordingly
(one ledger per instance, or deliberate shared storage; admin settings propagated at reboot).

### 3bis.6 HA on Kubernetes — `k8s/` manifests

The HA manifests live in **`k8s/`** (at the repo root) and materialise the Wave A/B/C topology
above on Kubernetes: **console with N replicas** against **one shared Postgres**, MinIO/S3 for
artefacts, sticky Ingress for the SSE streams, and — the heart of #13 — **deny-by-default
east-west NetworkPolicies**. It is the k8s counterpart of the `docker-compose.ha.yml` + `Caddyfile` harness. This section
**REPLACES** the old « k3s / k8s single-replica » note (see [§6 « Architecture constraint »](#architecture-constraint)) for the HA case.

**Apply.**

```sh
# 1) Build the image WITH the Postgres backend (+ object-store if S3 artefacts) — the default
#    SQLite image FAILS CLOSED under FORGE_HA=1.
docker build -f Dockerfile \
  --build-arg FORGE_CARGO_FEATURES="store-postgres object-store" \
  -t <registry>/forge:0.0.1 .         # context = repository root (guatx-core git-dep, no sibling)
docker push <registry>/forge:0.0.1

# 2) Set the image in k8s/40-console.yaml (and the real host in k8s/50-ingress.yaml +
#    FORGE_CONSOLE_HOST in k8s/11-config.yaml).

# 3) PROD: DO NOT apply k8s/10-secrets.example.yaml (EVAL placeholders). Provision the 3
#    Secrets (forge-db, forge-auth, forge-objectstore) out-of-band (SealedSecrets/ExternalSecrets/
#    SOPS), remove the line from kustomization.yaml, then:
kubectl apply -k k8s/                          # namespace + config + PG + MinIO + console + ingress + netpol
# (lab: apply as is — the eval Secrets boot the test cluster.)
```

Validated by **`kubeconform -strict`** (20 resources, 0 invalid) and `kubectl kustomize k8s/`.

**Console env contract (= Wave A/B/C).** `k8s/40-console.yaml` reproduces exactly the contract of the
compose overrides:

| Variable | k8s source | Role |
|---|---|---|
| `FORGE_HA=1` | ConfigMap | engages HA — boot FAILS CLOSED if the active store ≠ Postgres |
| `FORGE_ADVANCED_STORE=postgres` | ConfigMap | selects the PG backend (requires `FORGE_DB_URL`) |
| `FORGE_DB_URL` | **Secret** `forge-db` | shared Postgres DSN |
| `FORGE_INSTANCE_ID` | **`fieldRef: metadata.name`** | instance identity = **pod name** (unique per replica → leader lease key). A static value would collide — hence the `fieldRef`, the k8s equivalent of compose's HOSTNAME fallback |
| `FORGE_CONSOLE_ADDR=0.0.0.0:7100` | ConfigMap | pod-internal bind (never public — Service + Ingress + NetworkPolicy in front) |
| `FORGE_CONSOLE_HOST` | ConfigMap | anti-DNS-rebinding Host allowlist — MUST include the Ingress public host + the Service names |
| `FORGE_CONSOLE_TOKEN` / `_PASS_HASH` / `_OPERATOR_HASH` | **Secret** `forge-auth` | ingestion bearer + argon2id hashes (stable across replicas) |
| `FORGE_BLOB_S3_*` | ConfigMap (endpoint/bucket) + **Secret** `forge-objectstore` (keys) | artefact object-store, active only if the image is built with `--features object-store` |
| `FORGE_CONSOLE_DB` | ConfigMap → `emptyDir` | **pod-local** SQLite fallback (unused under PG) — never on the shared volume |

**Leader election — no separate worker.** The replicas are identical. They **self-elect a single
run-leader** via the single-row lease `leader_lease` (`scope='run-worker'`, TTL 45 s) in the shared
Postgres: the leader executes the engagements (one-run-per-engagement, fenced in the DB), the others serve
UI/API and **take over the lease** when it expires. `leader`/`instance_id` are published on `GET /health`.
**No distinct worker Deployment is needed** — scaling `replicas` is enough.

**Probes.** `readinessProbe`/`livenessProbe` = `GET /health` on 7100, with **`Host: localhost`** as a
header (in the default allowlist) — otherwise kubelet would send `Host: <podIP>` → 421 → false unhealthy.
`/health` **always answers 200** when the HTTP router is alive (`db:"degraded"` on a transient DB
outage, without making the probe flap).

**Shared RWX ledger — the choice to make (RWX vs object-store vs per-instance ledger).** The
tamper-evident ledger is a **file** (`engagement.jsonl`), not a Postgres table. `k8s/40-console.yaml`
places it on a **`ReadWriteMany` PVC** mounted by all replicas — which **requires an RWX StorageClass**
(NFS / CephFS / EFS / Azure Files / Filestore). Classic block volumes (**RWO**: EBS, GCE-PD, most
default CSIs) **do not satisfy** RWX and the 2nd replica will not schedule. Three options,
in order of audit robustness:

1. **Per-instance ledger** (recommended for true multi-writer) — each replica writes **its own**
   chain (StatefulSet + one RWO PVC per pod); each chain stays independently verifiable, aggregated on
   read. No concurrent appends on the same file. *(The provided manifest uses a Deployment +
   shared RWX PVC to stay turnkey; migrate to a per-instance StatefulSet if strict audit
   demands it.)*
2. **Shared RWX PVC** (provided) — a single `engagement.jsonl` for all. The console **serialises its own
   appends per instance**; that lock **does not cover** two instances writing the same file in
   parallel → accept the "concurrent appends" caveat or route stickily.
3. **Object-store for artefacts** — **evidence/exports/backups** (not the ledger itself) go
   to MinIO/S3 through the `object-store` seam (`FORGE_BLOB_S3_*`), relieving the shared volume of bulky
   binaries. Orthogonal to the ledger choice: combinable with (1) or (2).

**Ledger signing key — OFF the shared volume.** ⚠️ The `forge-ledger` RWX PVC must
carry only the ledger's **JSONL projection** (`engagement.jsonl` + high-water-mark), **never the signing
key**. By default the **local** signer writes its Ed25519 **private key** to `<ledger>.ed25519` (0600)
**next to** the ledger — hence **on this shared volume**, where `0600` is **not** an isolation
boundary: any pod/sidecar mounting the same PVC, or a **snapshot** of the PVC, reads the raw private key (→
forged ledger entries). Acceptable in a single-tenant lab; **not** in HA/multi-tenant. Two supported
patterns, opt-in (both preserve `runAsNonRoot`/`readOnlyRootFilesystem` + the deny-by-default
NetworkPolicies; their Secrets are **not** in the default `kubectl apply -k k8s/`):

1. **(preferred) Off-host PKCS#11 signer** (`FORGE_LEDGER_SIGNER=pkcs11`) — the key lives on an HSM/token and
   touches **no** pod volume. Opt-in env block in `k8s/40-console.yaml`; module + PIN via the
   `forge-ledger-pkcs11` Secret.
2. **(fallback) Key in a read-only mounted Secret** — pre-generate the Ed25519 key out-of-band, provide it via the
   dedicated `forge-ledger-key` Secret **mounted read-only**, and point **`FORGE_LEDGER_KEY`** at it
   (opt-in block in `k8s/40-console.yaml`). The key is **read, not rewritten** → it **never** lands on
   the shared `forge-ledger` PVC.

Full details, k8s wiring and rotation: **[`docs/KEY_CUSTODY.md` §Key custody in HA](KEY_CUSTODY.md#key-custody-in-ha-kubernetes--keep-the-private-key-off-the-shared-ledger-volume)**.

**Postgres — managed recommended in prod.** `k8s/20-postgres.yaml` provides a **single-replica StatefulSet +
headless Service + RWO PVC** for **test/dev**. In **prod, prefer a managed/operated Postgres** (RDS,
Cloud SQL, CloudNativePG/Crunchy): a single-pod Postgres does not make the stack HA (backups, failover, PITR
come from the managed service). To point the console at it: do not apply `20-postgres.yaml`, put the managed
DSN in the `forge-db` Secret, and replace the `console→postgres` egress rule with an `ipBlock` towards
the managed endpoint (see the notes in `60-networkpolicies.yaml`). Same for MinIO → **external S3** in prod.

**Sticky sessions for SSE.** SSE streams (run logs, live presence) must stay **pinned to a
single backend** for the duration of the stream, and the per-instance caches + the per-instance ledger head
make sticky routing correct anyway. Two levels, combined:

- **nginx Ingress** (`k8s/50-ingress.yaml`): `affinity: cookie` (cookie `forge_lb`) — k8s equivalent of
  Caddy's `lb_policy cookie`; plus `proxy-buffering: off` + `proxy-read-timeout: 3600` so as not to
  buffer/cut the streams.
- **Service** (`k8s/40-console.yaml`): `sessionAffinity: ClientIP` (belt and braces). The alternative
  without an ingress-controller is a `Service type: LoadBalancer` + `ClientIP` + `externalTrafficPolicy:
  Local` (provided commented out).

**NetworkPolicy model — deny-by-default east-west (heart of #13).** `k8s/60-networkpolicies.yaml` first lays down
a **`default-deny-all`** (empty podSelector, `policyTypes: [Ingress, Egress]`, no rule → everything
refused in both directions for **all** pods in the namespace), then **only** the
least-privilege, additive paths:

| Allowed flow | Egress (source) | Ingress (destination) |
|---|---|---|
| Ingress-controller → **console:7100** | — (outside the namespace) | policy `forge` (from ns `ingress-nginx`) |
| **console → Postgres:5432** | policy `forge` | policy `forge-postgres` (from console pods) |
| **console → MinIO:9000** | policy `forge` | policy `forge-minio` (from console pods) |
| **\<all pods\> → kube-dns:53** (UDP+TCP) | policy `allow-dns-egress` | (kube-system) |

**Everything else is refused**: no internet egress, no lateral movement, **no
console↔console traffic** (the leader lease, presence and inter-instance cache invalidation go **through
Postgres**, not pod-to-pod; the shared ledger is a file volume, not a network path). A connection
only goes through if it is allowed **on both sides** (source egress **and** destination ingress) — both
are provided. Two caveats documented in the file: (a) **kubelet probes** come from the
node, not from a pod — most CNIs (Calico/Cilium) exempt them; otherwise uncomment the
`ipBlock` stub towards the **node CIDR** in the console policy; (b) for an **external backend** (managed PG / external
S3), replace the pod-selector rule with an `ipBlock` towards its CIDR:port.

---

## 3ter. SSO — native OIDC, SAML through an OIDC bridge (advanced module, flag-gated)

Forge's SSO is **OIDC (OpenID Connect)** — and **nothing else** natively. Like the
Postgres backend ([§3bis](#3bis-postgres-backend-stage-4--ha--multi-instance)) and multi-tenancy, it is
an **advanced, separable, runtime-gated module** (open, like everything else): the **default** build behaves
**exactly** as today — **LOCAL** accounts only (`users` + argon2id + cookie
`forge_session` + admin/operator/viewer RBAC). As long as the flag is not **engaged**, all the
`/api/sso/*` routes are **absent** (404) and local login is **unchanged** (byte-identical). SSO never weakens
the governance/audit surface: it only **ADDS** an Authorization-Code login path which,
on success, issues **THE SAME** `forge_session` cookie as `/api/login`.

### 3ter.1 What Forge speaks natively: OIDC (and only OIDC)

| Variable | Role |
|---|---|
| `FORGE_ADVANCED_SSO` (truthy) **or** per-DB config key `advanced.sso` | engages OIDC SSO (otherwise default build, local login only) |
| `FORGE_SSO_HTTP_TIMEOUT` | timeout of the discovery/JWKS/token fetches (default `10` s) |

The OIDC provider is configured **on the admin side** (admin-gated route `POST /api/sso/config`, `client_secret`
**write-only** / redacted, never returned/logged/written to the ledger) — **nothing hard-coded**, same substrate as the
detection source. Fields: **`issuer`**, **`client_id`** / **`client_secret`**, **`redirect_uri`** (the
`/api/sso/callback` of this console), **`allowed_redirect_uris`** (allowlist of post-login return
targets — the browser is **never** redirected elsewhere, same discipline as `redirect.open` /
`oauth.flow`, hence **no open-redirect**), and the identity mapping (`provisioning` = `match`/`auto`,
`user_claim` = `email`/`sub`, `default_role`).

**Authorization-Code + PKCE (S256)** flow, **fail-closed at every step**: `GET /api/sso/login` builds
the authorize URL (state + nonce + challenge persisted server-side) and 302s to the IdP; `GET
/api/sso/callback` validates the state (one-time), exchanges the code for the tokens, then **cryptographically
VALIDATES the ID token** — **RS256** signature **via the IdP's JWKS** (exact kid; `none`/HS\*
rejected → no algorithm downgrade), `iss`, `aud == client_id`, `exp`, and `nonce` binding.

> #### ✅ SSO transport — native `https://`, verified (the egress TLS proxy is NO LONGER required)
>
> **The console speaks TLS itself.** Discovery, JWKS **and** the token exchange go through the **single
> TLS seam** (`console/src/tls.rs`): an `issuer` in **`https://`** is reached **directly**, with
> **full certificate verification** — chain up to the Mozilla roots (`webpki-roots`) **and** host
> name — **the handshake completing BEFORE the first application byte**. Point `issuer` at your IdP's
> `https://` endpoint.
>
> **What this fixes.** On callback, the console POSTs to the IdP's **token endpoint** the
> **`client_secret`** (`Authorization: Basic`, client_secret_basic) **and** the authorization **`code`**.
> Previously this POST went out in **plain HTTP** and that hop had to be protected by an egress TLS proxy or
> a trusted internal segment. **That workaround is obsolete**: over `https://`, a MITM gets a
> failed connection, never the secret. The test suite contains the corresponding check (a chain
> not anchored in a trusted root makes the connection fail).
>
> **What has NOT changed (defence in depth, independent of the transport):**
> - the **`client_secret` is write-only** — never returned, **never logged, never written to the ledger** (redacted);
> - the console **SSRF deny-list** (`net::resolve_guarded_with`) blocks loopback / link-local
>   (169.254.169.254) / RFC1918 / ULA / unspecified on the **resolved** connection **IP** (anti-DNS-rebinding),
>   for discovery, JWKS **and** the token POST — except the `FORGE_ALLOW_INTERNAL_INTEGRATIONS` escape-hatch.
>   **TLS does not replace it**: encrypting a fetch to `169.254.169.254` does not make it a legitimate
>   target, and the refusal falls **before** any connection, hence before any handshake;
> - the discovery endpoints (`token`/`jwks`/`authorization`) are **pinned to the issuer's origin**
>   (anti-SSRF, a hostile discovery document cannot redirect elsewhere);
> - the **ID token is still validated RS256/JWKS** whatever the fetch transport (token integrity); TLS
>   now adds the **confidentiality** of the `client_secret`/`code` on the wire.
>
> **`http://` is still accepted, but governed.** A plaintext **on-prem** IdP remains reachable: it must be
> an **internal target** AND the `FORGE_ALLOW_INTERNAL_INTEGRATIONS=1` escape-hatch must be set
> explicitly. A **public** IdP over `http://` is therefore, in practice, refused by the deny-list. The
> egress TLS proxy / service-mesh mTLS / oauth2-proxy patterns **remain usable** if your
> topology already imposes them — they are simply no longer **necessary**.
>
> **No verification escape hatch.** There is no option, no environment variable, no build
> flag to accept an untrusted certificate (self-signed, unknown chain, wrong host name): a
> TLS that verifies nothing is plaintext in disguise, and that is precisely where escape hatches get in.
>
> **Private enterprise CA — `FORGE_EXTRA_CA_PEM` (shipped).** The trust roots are the **compiled Mozilla**
> roots (`webpki-roots`); the **system store is NOT read**, and it will not be:
> that is what keeps the posture free of OS dependencies (no `schannel`, no `security-framework`, no
> `openssl`). An IdP — or a collector — signed by the **organisation's private CA** was therefore not
> verifiable, and the only remaining ways out were bad ones, including **falling back to plaintext**.
>
> The operator can now **explicitly provide** their own anchors:
>
> ```bash
> FORGE_EXTRA_CA_PEM_FILE=/etc/forge/entreprise-ca.pem   # a PATH (Docker/k8s mount, ConfigMap)
> # or, inline:
> FORGE_EXTRA_CA_PEM="-----BEGIN CERTIFICATE-----\n…"    # the PEM VERBATIM (in-house <VAR> / <VAR>_FILE pattern)
> ```
>
> The PEM can carry **several** `CERTIFICATE` blocks (intermediate CA chain included). The anchors
> are **ADDED** to the Mozilla roots, never substituted.
>
> **What this knob is NOT.** It is **not** a verification escape hatch, and this is a distinction
> of substance, not of vocabulary: verification remains **FULL**. Chain validated up to an anchor, **host
> name verified**, **expiry honoured**. We widen the set of trusted issuers; we loosen
> **no** check. There is still no option, no variable, no build flag to
> accept a self-signed certificate, an unknown chain, a wrong host name or an expired certificate —
> and the **source** guard that forbids the crate from opening rustls's `dangerous` API stays in place.
> Four tests pin it down: the provided CA makes its own handshake **succeed**; **another** CA lets it
> **fail**; the **host name** is still verified, anchor in place; an **expired** certificate is
> still refused, anchor in place.
>
> **FAIL-CLOSED at boot.** A configured but **unreadable, empty or invalid** PEM makes **startup
> fail** (`[forge] FATAL …`, code 2). It **never** silently degrades to "no anchor": otherwise
> the operator would believe their CA installed and discover the opposite hours later, in the form
> of an "unknown issuer" that does not point to the cause. Nothing configured ⇒ **no** line at boot,
> behaviour unchanged.
>
> The other ways out remain valid if your topology already imposes them: publicly recognised CA, **internal**
> target over `http://` under `FORGE_ALLOW_INTERNAL_INTEGRATIONS=1` (**governed** plaintext), or a
> TLS-terminating egress **proxy**.
>
> **mTLS — `FORGE_CLIENT_CERT_PEM` / `FORGE_CLIENT_KEY_PEM` (shipped).** Symmetrical to the knob above, and
> the two must not be confused: the enterprise anchor serves to **verify the peer**, the client identity
> serves to **authenticate us to it**. The seam installed no client certificate, and an
> endpoint that **requires** one — enterprise OIDC IdP, collector behind a service-mesh — remained
> delegated to the Python collector. That is over: rustls natively presents the provided chain
> (`with_client_auth_cert`), **with no new dependency and no system library**.
>
> ```bash
> FORGE_CLIENT_CERT_PEM_FILE=/etc/forge/client.pem   # client chain: leaf FIRST, then intermediates
> FORGE_CLIENT_KEY_PEM_FILE=/etc/forge/client.key    # private key — 0600 file, root-only
> ```
>
> **The `_FILE` form is the right one for the key**, and this is not a style detail: a process's
> environment can be read in `/proc/<pid>/environ`, gets copied into configuration dumps, container
> inspections and incident reports. The verbatim form (`FORGE_CLIENT_KEY_PEM=…`)
> exists for 12-factor; it is not recommended.
>
> **The private key appears nowhere.** It is the most sensitive secret the binary handles — it
> does not expire on its own and it signs our identity to any mTLS peer. It is written neither
> at boot, nor in a log, nor in an error, nor in the ledger, nor in an API response: a refusal
> says **that** the key is invalid (and **which variable** is at fault), never **what it contains** —
> not even a fragment. The boot line announces the chain length and the variable names, nothing
> else. Two tests **sweep** the outputs (success and failure) looking for the slightest fragment of the
> key body.
>
> **What this knob is NOT.** Presenting an identity loosens **nothing** in the verification of the
> **server** certificate: chain, host name and expiry stay verified identically. And the
> certificate is sent **only if the peer ASKS for it** — setting it changes **nothing** for ordinary
> endpoints (a test pins this).
>
> **FAIL-CLOSED at boot.** The two variables go **together or not at all**. A **half** on its own, an
> **unreadable** PEM, or a **key that does not match the certificate** (comparison of the
> `SubjectPublicKeyInfo` — the mistake made when renewing one without the other) make **startup
> fail** (`[forge] FATAL …`, code 2) **naming the variable**. Never a silently absent mTLS,
> which would be discovered at the first handshake in the form of a "connection refused" that does not
> point to the cause. Nothing configured ⇒ **no** line at boot, behaviour unchanged.
>
> A **pair** of tests pins the mechanism against a test server that **requires** a client certificate
> (`WebPkiClientVerifier`): with the identity, the peer authenticates us and the session carries application
> bytes; **without** it, the connection carries nothing. Without the negative half, we would not know whether
> that server really requires anything at all.

**Groups → Forge roles mapping.** The OIDC `groups` claim of the ID token is resolved to a Forge
role/grants **through the "groups-from-claims" RBAC seam** (`rbac::groups_from_claims` → `rbac::resolve` →
`rbac::apply_to_user`): the IdP's groups drive the role (and the tenant grants) of the identity, from the
**first** login (including for an auto-provisioned account). **Fail-closed / least privilege**:
no matching group ⇒ the configured `default_role` (never super-admin, which cannot be represented in the
mapping). The IdP thus remains **the** source of truth for roles, with no double administration of accounts.

### 3ter.2 SAML-only IdPs: supported through an **external OIDC bridge** (by design)

Forge does **NOT** implement native in-process SAML — a **deliberate choice**, not a gap:

- **openssl-free posture.** The Rust SAML stack (**`samael`**) pulls in **openssl + libxmlsec1**, hence two
  **system libraries** to install, version and patch on every host — which is exactly what the
  openssl-free posture of the **default build** refuses (`rustls`/`ring`, never native-tls/openssl — same
  discipline as the PG backend in [§3bis](#3bis-postgres-backend-stage-4--ha--multi-instance)).
  **For honesty's sake:** "openssl-free" does **not** mean "100 % Rust". `ring` — the crypto
  provider of `rustls`, and therefore of the outbound TLS seam — embeds **assembly and C** compiled by `cc`.
  The difference is not "zero C", it is **"zero system libraries"**: that C is **vendored with
  the crate and compiled by cargo** (and `cc` + a C toolchain are required anyway by
  `rusqlite/bundled`), whereas openssl/libxmlsec1 are host `.so` files. The refusal of `samael` rests on that
  criterion, not on an absolute "pure-Rust".
  **And the posture is SCOPED**: it holds for the default build and `store-postgres`, **not** for
  `object-store` — see [§3quater.1](#perimetre-de-l-openssl-freedom). What accepting `samael` would add
  is nonetheless of a different nature: two **host** `.so` files, whereas the `object-store` overflow is
  C **vendored and compiled by cargo**.
- **Attack surface.** Verifying **XML-DSig** signatures + **exclusive C14N** oneself is
  precisely the **XML-Signature-Wrapping (XSW)** foot-gun class — an auth bypass shipped
  repeatedly **even by mature SAML stacks**. Forge keeps its **single** auth surface, minimal and
  free of system libraries, rather than adding that debt.

**Supported pattern: put an OIDC bridge IN FRONT OF Forge.** The bridge terminates SAML against the client's IdP and
presents **OIDC** to Forge. Forge **only ever** speaks the OIDC it already validates (RS256/JWKS,
groups→roles) → openssl-freedom of the default build preserved, **zero new dependency, zero new
attack surface**. Proven
bridges: **Dex** (SAML connector), **Keycloak identity brokering** (brokers the client's SAML IdP, exposes
OIDC to Forge), or **oauth2-proxy**.

```
   IdP SAML du client                Pont OIDC (hors Forge)              Forge console
 ┌──────────────────┐   SAML 2.0   ┌──────────────────────────┐  OIDC  ┌────────────────────┐
 │ ADFS / Azure AD  │ ───────────▶ │ Dex (connecteur SAML)    │ ─────▶ │ /api/sso/login     │
 │ Shibboleth / …   │ ◀─────────── │  — ou —                  │ ◀───── │ /api/sso/callback  │
 └──────────────────┘  assertion   │ Keycloak identity broker │ authz  │ RS256/JWKS + groups│
                                    │  — ou — oauth2-proxy     │  code  │      → rôles RBAC   │
                                    └──────────────────────────┘        └────────────────────┘
     libxmlsec1/XML-DSig CONFINÉ dans le pont ↑              Forge = OIDC pur, openssl-free ↑
```

The bridge carries **all** the XML/openssl complexity; Forge receives a standard OIDC ID token and applies its
unchanged `groups → rôles` mapping. This is the recommended path for any SAML-only IdP.

### 3ter.3 Escape hatch — OPTIONAL Cargo feature `saml` (not built by default)

If a **contract** requires **in-process** SAML (no bridge possible), a future Cargo feature **`saml`**
(`samael` backend) could be added — producing a distinct **openssl + libxmlsec1 build variant**,
the **default build remaining openssl-free** (same opt-in discipline as `store-postgres` /
`encryption` / `object-store`: the contract covers the **default build**, each feature answers for
its own — and `object-store` already overflows, see [§3quater.1](#perimetre-de-l-openssl-freedom)).
**Not implemented today**: documented as **available on request**, not shipped. The
default, and the recommendation, remain the **OIDC bridge** above.

---

## 3quater. Outbound TLS seam — the console speaks `https://`, and verifies it

**Decision: no plaintext.** The console had exactly **three** outbound TCP connections, all on raw sockets:
the OIDC token exchange, the notification webhook, and the detection source fetcher. They now
all go through **a single seam** — `console/src/tls.rs` — which speaks `http://` (**governed** plaintext) or
`https://` (**verified TLS**). A single implementation, hence **a single trust policy** to
verify.

| Outbound | File | Before | Now |
|---|---|---|---|
| OIDC token exchange (`client_secret` + `code`) | `sso/mod.rs` | plaintext, egress TLS proxy **prescribed** | native `https://`, verified certificate — proxy **no longer required** ([§3ter.1](#3ter1-what-forge-speaks-natively-oidc-and-only-oidc)) |
| Notification webhook | `notify_channels.rs` | on-prem collector **only** | Slack / Teams / PagerDuty reachable over `https://` |
| Detection source fetcher | `net.rs` | `https://` **refused** (or delegated to Python) | served **in Rust**, with no spawn on a read route |

**What is guaranteed — and what is not.**

- **Full verification, no escape hatch.** Chain up to the compiled Mozilla roots
  (`webpki-roots`) **and** host name. The **handshake completes before the first application byte**: facing
  an unproven peer, the caller gets **no stream**, hence writes **no secret**. There is no
  option, no ENV, no feature to accept an untrusted certificate — a **source guard** test
  forbids the crate from opening rustls's dangerous API.
- **The SSRF deny-list stays upstream** (`net::resolve_guarded_with`) and applies to the **resolved IP** that
  is about to be connected, over `http://` **as well as** `https://`. Encrypting a fetch to `169.254.169.254` does not
  make it a legitimate target.
- **Plaintext remains possible where it is governed**: **internal** target + `FORGE_ALLOW_INTERNAL_INTEGRATIONS=1`.
  A **secret** to a **public** target over `http://` stays **refused**; over `https://` it is allowed.
- **No SMTP** — refused independently of TLS (STARTTLS is a *negotiated* upgrade; see
  [`ADMINISTRATION.md` §5bis](ADMINISTRATION.md)).
- **mTLS: shipped.** The seam now installs a **client certificate** when the operator provides one
  (`FORGE_CLIENT_CERT_PEM` / `FORGE_CLIENT_KEY_PEM`, rustls-native `with_client_auth_cert` — no
  new dependency); see [§3ter.1](#3ter1-what-forge-speaks-natively-oidc-and-only-oidc).
  What remains delegated to the Python collector is a **source-specific** identity: the seam's
  is that of the **process**.
- **Enterprise CA: provided explicitly.** The roots are the **compiled** ones; the **system
  store is not read** (that is what avoids `schannel` / `security-framework` / `openssl`). A
  certificate issued by a private CA becomes verifiable by setting `FORGE_EXTRA_CA_PEM` — see
  [§3ter.1](#3ter1-what-forge-speaks-natively-oidc-and-only-oidc).

**Measured cost.** The addition weighs **6 net crates** — `ring`, `rustls`, `rustls-pki-types`,
`rustls-webpki`, `untrusted`, `webpki-roots` — and **≈ +20 s CPU** of cold compilation. **No new
machine prerequisite**: `ring` compiles asm/C via `cc`, already required by `rusqlite/bundled`. The
`store-postgres` feature **shares** exactly this stack (a single `rustls` version, no conflict).

⚠️ `rustls` is pinned `default-features = false, features = ["ring", …]`: its **default** feature is
the `aws-lc-rs` provider, which pulls in a C/cmake toolchain. What follows states exactly where this pin
**holds** and where it is **overflowed**.

<a id="perimetre-de-l-openssl-freedom"></a>

### 3quater.1 openssl-freedom perimeter — true by default, FALSE under `object-store`

**The invariant.** *The dependency closure of the console crate contains no crypto/TLS system
library: no `openssl`, no `native-tls`, no `aws-lc`, no `schannel`, no `security-framework`.*

**It is SCOPED, and the perimeter is part of the statement.** Measured on 2026-08-07:

| Build perimeter | Forbidden occurrences | The invariant |
|---|---|---|
| **default build** | **0** | **holds** |
| `--features store-postgres` | **0** | **holds** |
| `--features encryption` | **0** | holds *(SQLCipher requires a crypto backend at BUILD time, not an extra system lib in the closure)* |
| `--features object-store` | **12** | **FALSE** |
| `--all-features` | **20** | **FALSE** |

**Why it cannot be fixed here** — this is the useful information, not the confession. The chain is
**transitive** and no link in it belongs to us:

```
object-store → rust-s3 (`sync-rustls-tls`) → attohttpc (`tls-rustls`) → `__rustls`
             → rustls/DEFAULT → aws-lc-rs → aws-lc-sys
```

`attohttpc` does declare `rustls` with `default-features = false` — but its internal feature `__rustls`,
the **only entry point** of `tls-rustls`, explicitly re-enables `rustls/default`, whose default
provider is `aws-lc-rs`. `attohttpc` does expose a `-ring` variant (`tls-rustls-webpki-roots-ring`), but
`rust-s3/sync-rustls-tls` **hard-wires** `attohttpc/tls-rustls`: it is **unreachable** from our
manifest, and adding it on top would remove nothing — **cargo features are ADDITIVE**. One would have to
fork or patch `rust-s3`/`attohttpc`. The deliberate choice is therefore to **correct the claim**, not to
chase the dependency: an invariant stated too broadly is a more serious truthfulness defect than the
dependency itself.

**What `object-store` overflows exactly.** Not only its own subtree: cargo's **feature
unification** propagates `aws-lc-rs` to **all** instances of `rustls` in the graph — including
ours, pinned `["ring"]`. The code still calls `rustls::crypto::ring::default_provider()`
**explicitly** (see `console/src/tls.rs`), so the provider **used at runtime remains `ring`**; but
`aws-lc-sys` is indeed **compiled and linked** into that binary. That is what the count of 20 under
`--all-features` against 12 under `object-store` alone says.

**What this changes for an operator.** The shipped binary (default build) and the
**Postgres** variant require **no** crypto/TLS library from the host — that is the promise, and it holds.
A binary built **with `object-store`** additionally compiles `aws-lc-sys`: plan for the
**C + cmake** toolchain at build time. Nothing to install at **runtime** in either case (aws-lc is *vendored* by the crate,
not borrowed from the system), so it is a **build** cost, not a deployment cost.

**The guard, not the sentence.** This page goes stale on its own at the next added dependency. The
check is therefore **executed**, by hand as well as in CI (job `console` of `.github/workflows/ci.yml`):

```sh
# from the repository root — requires 0 on the contractual perimeters, DISPLAYS the excluded ones
python3 scripts/check_openssl_freedom.py

# proves the guard still BITES (requires 0 on the known-dirty perimeter: it must go red)
python3 scripts/check_openssl_freedom.py --self-test-red

# the raw measurement, perimeter by perimeter, if you want to redo it by hand
cd console
cargo tree -e normal,build --no-dedupe | grep -icE "openssl|native-tls|aws-lc|schannel|security-framework"
cargo tree -e normal,build --no-dedupe --features store-postgres | grep -icE "openssl|native-tls|aws-lc|schannel|security-framework"
cargo tree -e normal,build --no-dedupe --all-features | grep -icE "openssl|native-tls|aws-lc|schannel|security-framework"
# expected: 0, 0, 20
```

When red, the script **names** the broken perimeter **and** the introduction chain (`cargo tree -i`) —
it does not just say "failure". Widening its exclusions without correcting this section is re-opening
exactly the hole it has just plugged.

<a id="perimetre-de-l-audit-de-licences"></a>

### 3quater.2 LICENCE audit perimeter — `cargo-deny` does not descend into `object-store`

It is **the same subtree** as in §3quater.1, and it is no coincidence: `object-store` is the
only feature whose closure is not entirely read by the tooling. There it was about crypto;
here it is about the **right to redistribute** — the repository is published under `AGPL-3.0-or-later` and the binary
embeds its whole graph.

**The blind spot, in figures.** Measured on 2026-08-07 with `cargo-deny 0.18.2`, the CI's pinned binary:

| What is read | Crates examined |
|---|---|
| `cargo-deny --all-features` (job `security`) | **239** |
| `cargo metadata --all-features` / `Cargo.lock` | **290** |
| **gap** | **51 crates, never read by the official audit** |

**The cause, established by mutation — not inferred.** `cargo-deny` (via `krates`) loses an
**optional** dependency whose **package** name differs from the name of its `[lib]` target. `rust-s3` is exactly that
case: package `rust-s3`, `[lib] name = "s3"`. The feature declares the package
(`object-store = ["dep:rust-s3"]`) whereas the resolved edge in `cargo metadata` carries the lib name
(`"name": "s3"`): name matching fails, the feature is taken as **disabled**, and everything that
hangs beneath it disappears. A single factor changed at each measurement:

| Manifest | Invocation | Crates seen | Subtree |
|---|---|---|---|
| actual (`optional`, `dep:rust-s3`) | `--all-features` | 239 | **absent** |
| implicit syntax (`object-store = ["rust-s3"]`) | `--all-features` | 239 | **absent** |
| dependency made **non**-optional | *(no flag)* | 250 | **present** |
| dependency renamed `s3 = { package = "rust-s3" }` | `--all-features` | 287 | **present** |

So it is **neither** `--all-features` (the flag does take effect: 201 → 239), **nor** the `dep:` syntax, **nor** a
restricted `targets` in `deny.toml` (there is none), **nor** an explicit exclusion.

**What it was hiding — green did not mean "compliant", it meant "not looked at".** Two of the 51 crates do not
satisfy the `allow` list as it was written: `attohttpc 0.30.1` (**MPL-2.0**) and
`tiny-keccak 2.0.2` (**CC0-1.0**). Verified by making the subtree visible then re-running the CI's
cargo-deny with the repository's `deny.toml`: `licenses FAILED`, code 4, those two crates named. Worse,
`deny.toml` **justified removing `MPL-2.0`** from its list with « cargo-deny la signale non
rencontrée » (cargo-deny reports it as not encountered) — a decision taken **through** the blind spot.

**AGPL compatibility of the subtree: verified, and it holds.** 51 crates, no proprietary licence,
no irreconcilable copyleft:

- **MIT / Apache-2.0 / ISC / BSD-2 / BSD-3 / MIT-0 / Unicode-3.0** (48 crates) — permissive, inbound
  to AGPLv3 without reservation (Apache-2.0 is GPLv3/AGPLv3-compatible, not GPLv2 — irrelevant here).
- **MPL-2.0** — `attohttpc` alone. **Per-file** copyleft, GPL/AGPL-compatible **by construction**:
  §3.3 allows the "Larger Work" under a *Secondary License* (GPL/LGPL/AGPL) **unless** there is an
  "Incompatible With Secondary Licenses" notice (Exhibit B). **Verified: no `attohttpc` source file
  carries that notice.** Remaining obligation: the MPL files stay under MPL, source available —
  which the AGPL already imposes.
- **CC0-1.0** — `tiny-keccak` alone. Public domain waiver, no reciprocity.
- **`aws-lc-sys 0.43.0`** deserves a look of its own: ~69 MB of **vendored C** (BoringSSL, itself a fork
  of OpenSSL) under a seven-conjunct expression,
  `ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)`.
  The two expected pitfalls are **absent**, verified in the vendored tree and not on the strength of the SPDX field:
  · code derived from OpenSSL/SSLeay is **relicensed Apache-2.0** by AWS — **zero** occurrences of the
  advertising clause "All advertising materials…" (the one that makes the old OpenSSL licence
  GPL-incompatible) in the 69 MB; · `third_party/jitterentropy` is dual BSD-3-Clause **or** GPLv2,
  and the `LICENSE` **expressly elects BSD-3-Clause and NOT GPLv2** — it is the only mention of GPL in
  the whole crate (9 files, all headers of that library).

**Verdict: no incompatibility with `AGPL-3.0-or-later`.** `MPL-2.0` and `CC0-1.0` are now
allowed **by name** in `deny.toml`, with their justification.

**The compensation, because the exclusion remains.** `cargo-deny` stays blind as long as the manifest
is not fixed: its `bans` and `sources` checks do **not** cover these 51 crates. What is
covered, and by what:

| Axis | On the 239 | On the 51 of `object-store` |
|---|---|---|
| **Security advisories** | `cargo audit` (reads `Cargo.lock`) | ✅ **yes** — all 290 crates |
| **Licences** | `cargo deny check licenses` | ✅ **yes** — `scripts/check_dep_licenses.py` |
| **Bans / multiple versions** | `cargo deny check bans` | ❌ **no** — deliberate exclusion |
| **Provenance (registry/git)** | `cargo deny check sources` | ❌ **no** — deliberate exclusion |

```sh
# from the root — redoes the licence check on the 290 crates, with the `allow` list
# READ from deny.toml (a single policy truth, two engines to apply it)
python3 scripts/check_dep_licenses.py

# proves the guard still BITES: it must go red naming attohttpc and tiny-keccak
python3 scripts/check_dep_licenses.py --self-test-red

# the EXACT differential, if the cargo-deny binary is there (CI passes it in)
python3 scripts/check_dep_licenses.py --cargo-deny /tmp/cargo-deny
```

**The fix at the source, known and measured, deliberately not applied here.** One line of
`console/Cargo.toml` is enough — declare the dependency under its lib name:

```toml
s3 = { package = "rust-s3", version = "0.37", optional = true, default-features = false, features = ["sync-rustls-tls"] }
# and: object-store = ["dep:s3"]
```

Measured: `cargo-deny` goes from 239 to **287** crates and sees `rust-s3`, `attohttpc` and `aws-lc-sys`. It
touches the manifest and `Cargo.lock` — hence a rebuild and a review in their own right. The day it is
done: remove this paragraph **and** the exclusion from `deny.toml`; `check_dep_licenses.py --self-test-red`
will go red by itself as a reminder.

---

## 4. Build context & `guatx-core` dependency

The build context is the **ROOT of this repository**. The `console` crate resolves `guatx-core` through a
**PINNED public git-dep** — `guatx-core = { git = "https://github.com/guatxlabs/core", tag =
"v0.2.6", features = ["forge"] }` (see `console/Cargo.toml`): the core is **fetched from GitHub at
build time**, no sibling crate is required in the context. A **standalone** clone of this repository builds
directly (`docker build -t forge:0.0.1 .` from the root; the compose file sets `context: .`).

- **Reproducibility**: `console/Cargo.lock` is **committed** (removed from `console/.gitignore`) — a
  binary/product locks its deps for identical client/CI builds. The Dockerfile in fact builds with
  `cargo build --release --locked`, which **requires** a present and up-to-date `Cargo.lock`.
- **Dev override (monorepo)**: `console/.cargo/config.toml` (**GITIGNORED**, absent from public clones)
  carries a `[patch]` that redirects the git-dep to the local core (`path = "../../core"`) — it keeps the
  speed of the path in development without depending on the published core. The default build (without this file)
  resolves the pinned git-dep.
- **Context ignore**: `Dockerfile.dockerignore` (a **Dockerfile-specific** ignore-file —
  BuildKit prefers it over a root `.dockerignore` when it sits next to the Dockerfile designated by `-f`).
  Patterns relative to the **repository root**. Excludes the Cargo cache `console/target/` (several GB, cf. §6), the
  `*.db`/WAL, the `*.jsonl` ledger, `__pycache__`, `**/.git` and the secrets (`*.env`/`*.key`/…).

**`path` → git-dep migration: DONE.** The console used to consume `core` as a `path` dep (monorepo
sibling layout), which imposed a parent build context. The public repo `guatxlabs/core` (tag
`v0.2.6`) now exists and the dep is **git**: the context **is** the repository root, the
builder step that copied the sibling `core/` has **disappeared**, and a **standalone** checkout (no sibling) builds as is.

---

## 5. `/health` liveness & `Host` header

The `HEALTHCHECK` (Dockerfile **and** compose) performs a real **`GET /health` expecting HTTP 200** — not a
mere TCP port-open (which would pass even if the HTTP router were dead).

- `/health` is **PUBLIC** (outside `auth_guard`) but **under `host_guard`** (anti-DNS-rebinding): the probe
  **must** send an allowed `Host`. When targeting `http://127.0.0.1:7100/health`, urllib sets
  `Host: 127.0.0.1:7100` → `host_guard` strips the port → `127.0.0.1`, present in the **default**
  allowlist (`localhost` / `127.0.0.1` / `::1`). Verified by running the binary: Host `127.0.0.1` → 200
  (healthy); foreign Host → **421** (unhealthy).
- Behind a reverse-proxy with a restricted `FORGE_CONSOLE_HOST`, the probe keeps targeting `127.0.0.1`
  (always in the default allowlist, independently of `FORGE_CONSOLE_HOST`) — the healthcheck stays
  green without opening the host-guard.
- **`/health` body**: `{"status":"ok","version":"X.Y.Z","db":"ok|degraded"}`. The **`db`** field is
  **additive** (Stage 4): it **pings the ACTIVE store** (SQLite: trivial `SELECT 1`; Postgres: `SELECT 1`
  via the backend, hence through the HA reconnect+retry). `"degraded"` = database unreachable. The probe is
  **non-fatal**: `/health` **always answers 200** even when `degraded` (the `HEALTHCHECK` only tests the
  200 code → it does not flap on a transient DB outage), but an external supervisor can read `db`
  to alert on/evict an instance whose DB is down.

```sh
docker inspect --format '{{.State.Health.Status}}' forge      # -> healthy
curl -s http://127.0.0.1:7100/health   # -> {"db":"ok","status":"ok","version":"0.0.1"}
```

---

## 6. Measured footprint & deployment matrix

*(measured figures)*

### Composition

Forge itself:

Count MEASURED on this tree, `wc -l`, `__pycache__/` and `target/` excluded (the command is given
so that you can redo it):

| Language | Perimeter | LOC | Command |
|---|---|---|---|
| Python | engine, pure stdlib, `deps=[]` | **23,876** | `find forge -name '*.py' -not -path '*__pycache__*' \| xargs wc -l` |
| Rust | console (tests included) | **51,749** | `find console/src -name '*.rs' \| xargs wc -l` |
| Rust | guatx-core | **9,280** | `find src -name '*.rs' \| xargs wc -l` (in the `core` repository) |
| JS / HTML / CSS | UI | **10,471** | `find console/web -type f \( -name '*.js' -o -name '*.html' -o -name '*.css' \) \| xargs wc -l` |

> The figures previously published here (~5,256 / ~4,006 / ~1,032 / ~3,513) dated from a much
> earlier tree and underestimated the code by a factor of 2.5 to 12. They are replaced by the measurement above.

**ZERO** Java / C / C++ / Go / bash in the Forge code — *Forge's code*. The **dependency
closure**, on the other hand, contains C/asm compiled by cargo: the **SQLite** amalgamation (`rusqlite/bundled`) and
the asm of **`ring`** (crypto provider of the TLS seam). "openssl-free" therefore does not mean "zero C" but
**"zero system libraries to install"** — that C is vendored with the crates and built by cargo.
And the claim is **scoped**: it holds for the default build and `--features store-postgres`
(**0** occurrences measured), **not** for `--features object-store` (**12**, via `aws-lc-sys`, which adds
**cmake** to the build prerequisites). Measurements, chain and automatic guard:
[§3quater.1](#perimetre-de-l-openssl-freedom).

The **ORCHESTRATED** tools (never embedded, all **OPTIONAL**, self-neutralised if absent):

| Tool | Language |
|---|---|
| nmap | C |
| httpx / nuclei / subfinder | Go |
| MSF | Ruby |
| Burp | Java |
| browser / camoufox | Python + Firefox |

### Size

Measured on this tree (`find … -printf '%s\n' | awk`):

- **Python** (`forge/`, `__pycache__` excluded): **1,371 KB**
- **web** (`console/web/`, all files): **877 KB**
- **Rust console binary**: **not measured** — no `console/target/release/forge` is present on this
  tree, and we do not publish a binary size we have not weighed. Measure yours after
  `cargo build --release`: `ls -l console/target/release/forge`. *(The "4.2 MB" figure published
  previously has no reproducible measurement attached; it is withdrawn rather than carried over.)*
- The build cache `console/target/` weighs **2.8 GB** on this tree — it is **never shipped**
  (`.dockerignore`). *(The previous note spoke of "1.6 GB in `forge/`": the cache is not in
  `forge/`, and it has grown since.)*
- **Docker image**:
  - **minimal ~150-250 MB** (console + python + nmap)
  - **complete ~350-500 MB** (+ PD Go binaries)
- `browser-automation` = separate **4 GB** image (optional sidecar behind `profiles: ["browser"]`).

### Deployment matrix

#### Docker ✅

- `docker compose config` valid; a bare `up` starts the **console alone** (optional services under profiles).
- Multi-stage (rust builder discarded → debian-slim runtime).
- Non-root uid 10001, tini PID1, DB / ledger / scope volumes.
- Build context & `core/` dependency, context ignore, image profiles, SHA256 supply-chain,
  liveness: see [§1](#1-build--run-options), [§4](#4-build-context--guatx-core-dependency),
  [§5](#5-health-liveness--host-header).

**Supply-chain — SHA256 pins, single source.** Tool archives are never fetched unverified "by
tag": each archive is **pinned by digest, per architecture**, and validated by
`sha256sum -c` — any mismatch **makes the build fail**. Versions, digests, URL templates
and archive members live in a **single manifest**, [`forge/tools.json`](../forge/tools.json), read
by the `Dockerfile` **at build time** *and* by the **runtime** installer (`forge tools install|update|remove`).
There is therefore no longer a pin copied between `Dockerfile` and `docker-compose.yml`: **bumping a version =
editing this single file** (version + digests from the upstream `*_checksums.txt`). A tool without a pin for
the target architecture is **dropped from the plan** (never downloaded unverified); the base group `core`
(httpx/nuclei/subfinder) is additionally guarded by `--require-complete core`, which makes the build fail
rather than produce a truncated image. Anti-regression guard: `tests/test_tools_manifest.py`.

**Tools at runtime, no rebuild.** `forge tools list|install|update|remove` installs a manifest tool
into the **persistent tools volume** `/data/tools/bin` (forge-owned uid 10001, at the head of the
PATH in front of the baked `/usr/local/bin`), after verifying the SHA256 pin, and **logs** the act to the
engagement ledger. Empty by default → behaviour identical to the `FORGE_TOOLS_PROFILE` baseline.
Details: [`docs/TOOLS_LIFECYCLE.md`](TOOLS_LIFECYCLE.md).

#### k3s / k8s ✅

- **Two modes**: (a) **single-replica** SQLite (default build, below); (b) **multi-replica HA**
  against shared Postgres → **`k8s/` manifests + deny-by-default NetworkPolicies**, see
  [§3bis.6](#3bis6-ha-on-kubernetes--k8s-manifests).
- Mode (a): **single-replica** Deployment.
- ⚠️① the console **SPAWNS** `python3 -m forge.cli` (setsid) → python + forge package **IN THE SAME
  container** (not separable).
- ⚠️② in mode (a) SQLite + ledger = **ReadWriteOnce PVC** → no horizontal scaling. Mode (b) lifts this
  via shared Postgres + ledger on an **RWX** PVC (or per-instance ledger) — see §3bis.6.
- External tools (browser:8080, msfrpcd:55553, burp:1337) = optional Services / sidecars.

#### Native host ✅

- `pip install -e .` + `cargo build --release` + tools on the PATH.
- Hardened systemd unit provided (`deploy/forge.service`) — see [§1.4](#14-native--systemd-without-docker).

#### venv ✅

- `deps=[]` → the Python part fits in a venv **with no pip dependency at all**.

### Reports & PDF export

The engagement report is served by the console: `GET /api/report/:id?format=md` (**default**,
backward-compat) and `?format=html` (branded client deliverable, with `@media print` CSS + colours forced by
`print-color-adjust`).

- **Default PDF path (no dependency)**: open `?format=html` then **"Print" →
  "Save as PDF"** in the browser. The print stylesheet is provided, so
  badges/posture stay readable. This is the recommended path — **zero external binary**.
- **`?format=pdf` (OPTIONAL)**: server-side PDF rendering, enabled **only if** a PDF engine is
  present on the PATH (`weasyprint` recommended, pure-Python pip; `wkhtmltopdf` supported if it is already there).
  Absent → JSON `pdf_unavailable` pointing to browser printing. The `full` profile embeds
  `weasyprint` (isolated venv `/opt/pdfenv`, symlinked into `/usr/local/bin`) → turnkey `?format=pdf`;
  `mini` omits it.

> The PDF engine is an **optional orchestrated** tool (like nmap/nuclei/Burp): not embedded,
> self-neutralised if absent. The claim "ZERO Go/Ruby/… in the Forge code" is not affected
> (weasyprint is pure-Python; its C libs pango/cairo are in the same category as nmap).

### Architecture constraint

- **STATEFUL single-replica + RWO PVC** (no scale-out).
- Future HA / multi-tenant = off-host ledger + shared store (to be rethought).
- **Current ideal profile**: single operator / small MSSP.
- **Strength**: tiny governed core + heavy engines pluggable as optional sidecars
  ("mini" deliverable ~200 MB or "full" depending on the client).

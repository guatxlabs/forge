# Secrets — `*_FILE` indirection (Docker & k8s secrets)

[English](SECRETS.md) | [Français](SECRETS.fr.md)

> **Principle**: *"the key must not be left next to the door".* No secret lives in plaintext
> in a `.env` left next to the app. The environment carries a **PATH**; the secret lives in a
> **mounted, root-owned file**, outside the working directory. This is the standard
> 12-factor secret pattern (Docker secrets / Kubernetes Secret-as-file).

## TL;DR

Every environment variable that carries a secret accepts a **`<VAR>_FILE` twin**:

1. if `<VAR>` is set **and non-empty** → its value is used (direct path, **default
   unchanged** — byte-identical to before);
2. otherwise, if `<VAR>_FILE` is set → the file it points to is **read**, its **trailing newline/space is
   removed**, and its content is used;
3. otherwise → the secret is considered **absent** (the app's own fallback applies: ephemeral
   generation for the ingest token, *fail-closed* refusal for a backup passphrase, etc.).

**Fail-soft**: an unreadable `<VAR>_FILE` (wrong path, permissions) **never** makes the
process crash and **never** produces a silent empty secret that would weaken auth — it logs a
warning (naming the **variable**, never the value) and falls back to the app's fallback.

The value of a secret is **never** logged nor passed on `argv`.

## Covered secrets

| Variable | Role | Consumed by |
|----------|------|--------------|
| `FORGE_CONSOLE_TOKEN` | `/api/ingest` ingestion bearer | console (Rust) + `console_client` client (Python) |
| `FORGE_FIELD_KEY` | **Field** encryption of the engagement authentication material (bearers/cookies/headers of the test accounts) **and of the three integration secrets** (detection source, notification channel, SSO `client_secret`) — **default build** | console (Rust) |
| `FORGE_DB_KEY` | SQLCipher key at rest (`--features encryption` image) | console (Rust) |
| `FORGE_BACKUP_PASSPHRASE` | Passphrase of the encrypted backups (named by `policy.passphrase_env`) | console (Rust) — backup/restore/scheduler/upgrade |
| `FORGE_COMPLIANCE_ARCHIVE_KEY` | Governed purge archive passphrase | console (Rust) |
| `FORGE_LEDGER_SIGNER_CREDENTIAL` | Bearer token of the KMS/HSM/HTTP remote signer | engine (Python, `signing.py`) |
| `FORGE_LEDGER_SIGNER_ARGV` | Argv of the exec signer (may carry creds) | engine (Python, `signing.py`) |
| `FORGE_LEDGER_PKCS11_PIN` | User PIN of the PKCS#11 token | engine (Python, `signing_pkcs11.py`) |
| `PLUME_TOKEN` | Basic auth of the legacy detection preset | console (Rust) + engine (Python) |
| `FORGE_DETECTION_SOURCE` | Detection source config (JSON carrying the auth secret) | engine (Python, `collectors`) |
| `MSF_RPC_PASS`, `MSF_RPC_TOKEN` | msfrpcd creds (`msf.module` connector) | engine (Python) |
| `BURP_API_KEY` | Burp REST API key (`burp.scan` connector) | engine (Python) |

Each one accepts `<VAR>_FILE`. Example: the console reads `FORGE_CONSOLE_TOKEN`, otherwise
`FORGE_CONSOLE_TOKEN_FILE`.

### Already write-only through the UI — they **never** need a `.env`

> ⚠️ **"Write-only" describes the API SURFACE, not storage at rest** — both are now covered, but
> they really are **two** properties. These secrets are never served back by a read, never
> logged, never ledgered (API surface) **and** they are encrypted in the `settings` table by
> **field** encryption (`FORGE_FIELD_KEY`, default build) — see "What is encrypted at rest"
> below. `--features encryption` + `FORGE_DB_KEY` (whole database) remains composable on top.

- **Detection source secret** (`settings.detection_source`): entered in the first-deployment
  wizard or in *Administration → Detection source*, stored **write-only** in the database (never
  read back in plaintext, never logged). The `PLUME_*` / `FORGE_DETECTION_SOURCE` variables are only a
  **backward-compatible fallback** for driving outside the UI.
- **SSO `client_secret`**: set in the settings through the UI, **write-only**, never re-issued. No
  env variable, hence no `.env`, is needed for it.
- **Notification channel token** (`settings.notify_channel` → `auth.secret`): same write-only
  pattern (`GET` returns `secret_set: bool`), same caveat about storage at rest.

### What is encrypted at rest — MEASURED state

| Data | Location | At rest (default build) |
|---|---|---|
| Engagement auth material (bearer/cookies/headers) | `engagement.scope_json` → `auth.accounts[]` | **encrypted** (`FORGE_FIELD_KEY`) |
| Same, in internal transit to the engine | `run_job.spawn_spec` (HA *pending* path) | **encrypted** (inherited) — and purged at claim |
| Account passwords | `users.pass_hash` | **argon2id hash** — not applicable (one-way) |
| Session tokens | `session.token_sha` | **SHA-256** — not applicable (one-way) |
| Detection source secret | `settings.detection_source` → `auth.secret` | **encrypted** (`FORGE_FIELD_KEY`) |
| Notification channel token | `settings.notify_channel` → `auth.secret` | **encrypted** (`FORGE_FIELD_KEY`) |
| SSO `client_secret` | `settings.sso.config` → `client_secret` | **encrypted** (`FORGE_FIELD_KEY`) |

**The last three rows have just switched** — they were "in plaintext", recorded as a
**known and accepted** gap. The reason for the gap was technical and real: sealing them **requires**
making their points of use fallible (`ds_secret`, `ch_secret`, `sso::load_config`), and the last one
returned an `Option` — a failed decryption would have become "**SSO not configured**" there, that is,
the **silent degradation** that the fail-closed behaviour of field encryption exists to forbid.

The imposed order was therefore respected: **fallibility first, sealing second.**

- `sso::load_config` now returns `Result<Option<SsoConfig>, String>` — **three** distinct outcomes:
  `Ok(None)` = not configured (403 `sso_unconfigured`), `Ok(Some)` = usable, `Err` = **configured but
  unreadable** (503 `sso_secret_unreadable`). A secret that does not open can no longer pass itself off as
  a console that was never configured.
- The source secret and the channel token are opened at their **single point of use**
  (`collect_detections_with`, `deliver_blocking`): without a key, the integration **refuses** to go out with a
  named reason, rather than presenting itself **without authentication** — a 401 that the admin
  would diagnose as a SIEM outage.
- An existing database is **converted at boot**, in place and idempotently
  (`migrate_seal_settings_secrets`). Without a key, nothing is converted but the remaining plaintext is **counted and
  announced** — never kept quiet.

The scope stays **measured**: only the **value** of the secret is sealed. `kind`, `endpoint`,
`auth.type`, `issuer`, `client_id` stay readable at rest — the admin must be able to re-edit their config
without the key, and these are not credentials. `--features encryption` + `FORGE_DB_KEY` (**full**
encryption) remains **composable** on top.

## Docker Compose

`docker-compose.yml` provides a `secrets:` block (commented out, opt-in) and the wiring example
`FORGE_BACKUP_PASSPHRASE_FILE: /run/secrets/backup_passphrase`. Steps:

1. Write each secret to a host file **never tracked by git**: either an absolute path outside
   the repository (recommended, e.g. `/etc/forge/secrets/backup_passphrase`), or `./secrets/<nom>` **provided**
   that `secrets/` is ignored by git (check: `git check-ignore -v secrets/<nom>`).
2. Uncomment the (top-level) `secrets:` block and declare the files (`file: ./secrets/...`) —
   or, in Swarm mode, `external: true` + `docker secret create`.
3. In the `forge` service, add the `secrets:` clause listing the secrets to mount (Docker
   exposes them under `/run/secrets/<nom>`, mode `0400` root).
4. Uncomment the corresponding `environment:` line `<VAR>_FILE: /run/secrets/<nom>`.

```yaml
# docker-compose.yml (excerpt)
services:
  forge:
    environment:
      FORGE_BACKUP_PASSPHRASE_FILE: /run/secrets/backup_passphrase
    secrets:
      - backup_passphrase
secrets:
  backup_passphrase:
    file: /etc/forge/secrets/backup_passphrase   # host file outside the repository (never tracked by git)
```

The direct value (`FORGE_BACKUP_PASSPHRASE: ...` through `.env`) remains supported (backward compatibility).

## Kubernetes

The **Secret-mounted-as-file** pattern already exists for the ledger signing key
(`forge-ledger-key`, OPTION B in `k8s/40-console.yaml`). It is **mirrored** for the token, the
passphrase and the connector creds through the `forge-secret-files` Secret (in
`k8s/10-secrets.example.yaml`, opt-in):

1. Provision the `forge-secret-files` Secret **out of band** (SealedSecrets / ExternalSecrets / SOPS
   / `kubectl create secret`). The example file `k8s/10-secrets.example.yaml` contains only
   **placeholders**: it documents the expected shape, it is not meant to be applied as is.
2. In the console's `Deployment`: uncomment the `secret-files` **volume** (projects the Secret
   as files, `defaultMode: 0440`), the **volumeMount** (`/etc/forge/secrets`, `readOnly: true`), and
   the `FORGE_*_FILE` env entries pointing to the mounted paths.

```yaml
# k8s/40-console.yaml (excerpt — env)
- name: FORGE_CONSOLE_TOKEN_FILE
  value: /etc/forge/secrets/console_token
# ... volume ...
- name: secret-files
  secret:
    secretName: forge-secret-files
    defaultMode: 0440   # owner+group read; fsGroup gives the GROUP to the process, not ownership
    items:
      - { key: console_token, path: console_token }
```

Prefer a Secret **mounted as a file** over an env `secretKeyRef`: with `secretKeyRef`, the plaintext
value lands in the **pod's environment** (visible in `kubectl describe pod`, crash
dumps, the environ of child processes); mounted as a file, it stays in a root-owned tmpfs read on
demand.

> ⚠️ **Secrets stay out of the default `kubectl apply -k k8s/`.** `10-secrets.example.yaml` is
> **deliberately absent** from the `resources:` list of `kustomization.yaml` — its placeholder
> values never go out by default. `kubectl kustomize k8s/` renders an **identical** manifest
> with or without this change (the additions are comments + a Secret in the excluded file).

## Implementation (reference)

- **Rust**: `console/src/secret_env.rs` — `secret_from_env(name) -> Option<String>` (direct env →
  `<VAR>_FILE` read + `trim_end` → `None` fail-soft). Call sites: `main.rs` (token), `dbmigrate.rs`
  (`FORGE_DB_KEY`), `backup.rs::read_passphrase_env` (shared by backup/restore/scheduler/`upgrade`),
  `compliance.rs` (archive key), `detection.rs` (legacy `PLUME_TOKEN`).
- **Python**: `forge/portability.py` — `env_secret(name, env=None)` (same precedence + `rstrip`).
  Call sites: `console_client.py` (token), `modules/msf.py`, `modules/burp.py`, `cli/purple.py`,
  `collectors/base.py::load_source` (`env:NAME`), `signing.py` (credential/argv),
  `signing_pkcs11.py` (PIN).

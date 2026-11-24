# First deployment — the web wizard

[English](FIRST_DEPLOYMENT.md) | [Français](FIRST_DEPLOYMENT.fr.md)

> [Contents](README.md) · Prerequisite: [Installation](INSTALLATION.md) · Next:
> [Administration](ADMINISTRATION.md) · See also: [Configuration](CONFIGURATION.md)

**Nothing is hard-coded.** A fresh install has **no admin, no real scope, no detection
source**: everything is provisioned **from the browser** on first access, through a
**self-disabling** wizard.

## The flow

1. Open **`http://127.0.0.1:7100`** (or the reverse-proxy URL). The SPA calls
   `GET /api/setup/state`:
   - `needs_setup:true` ⇒ the **wizard** is displayed;
   - `capabilities.sqlcipher` ⇒ the UI knows whether encryption at rest is available (the
     `encryption` image).
2. **The wizard `POST /api/setup`** (a **PUBLIC but self-disabling** route: **409** as soon as an
   enabled admin exists). Only the admin is required; **everything else is persisted only if provided**.
3. The auth gate **engages** as soon as an enabled admin exists (the DB state is authoritative). `/api/setup`
   closes for good. The browser **lands logged in** (cookie `forge_session`,
   HttpOnly/SameSite=Strict).

## The four parts of the wizard

### 1. Create the admin *(required)*
`admin_login` + `admin_password` → **argon2id** hash, role `admin`. The password/hash is
**never** logged nor written to the ledger. It is a **named individual account**: administration then
requires an admin session (no fallback to a shared secret).

### 2. Crypto *(automatic + capability)*
- The **ledger** is already signed with **Ed25519** automatically — no action needed.
- **Encryption at rest** depends on the **image** (`encryption`, see
  [Installation §6](INSTALLATION.md#6-encryption-image-encryption-at-rest--sqlcipher-opt-in)),
  surfaced via `capabilities.sqlcipher`. The UI honestly reflects whether it is available.

### 3. Detection source = **YOUR infra** *(optional)*
`detection_source` — a **configurable, code-free** plugin: FortiGate / pfSense / OPNsense / CrowdSec /
Elastic / OpenSearch / file / exec / Plume… Model, presets and MITRE mapping:
**[`DETECTION.md`](DETECTION.md)**. Can also be set later in Administration → « Source de
détection » (*Detection source*). The **auth secret is write-only** (never returned/logged). Leaving it empty = inert purple loop
(readable fail-open) — see [Using Forge standalone](STANDALONE.md).

### 4. Operator policy *(optional)*
`operator_policy` — governs the **operator/C2** role (RBAC). Empty = C2 **closed** (fail-closed).
Key field: `source_cidrs` (allowlist of client IPs permitted to launch a run). `session_ttl`
optional (config substrate; the effective TTL is driven by `FORGE_CONSOLE_SESSION_TTL`).

## What the wizard persists

| Field | Where | Condition |
|---|---|---|
| Admin (login + argon2id hash, admin role) | table `users` | **always** |
| `operator_policy` | `settings.operator_policy` | if provided (JSON object) |
| `detection_source` | `settings.detection_source` (write-only secret) | if provided (JSON object) |
| `session_ttl` | `settings.session_ttl` | if a positive integer is provided |

Ledger: `console.setup.provision` (attribution = the admin login; **never** the password/hash).
The detection source is **hot-reloaded** if provided.

## Headless provisioning (no browser)

For an automated deployment, set in `.env` / the EnvironmentFile:

- `FORGE_CONSOLE_PASS_HASH` (viewer argon2id hash via `forge hashpw`),
- `FORGE_CONSOLE_OPERATOR_HASH` (operator argon2id hash via `forge hashpw-operator`),
- `FORGE_CONSOLE_TOKEN` (ingestion bearer).

The state then switches to `provisioned:true` without the wizard. For an **individual admin account** headless:
`forge useradd <login> admin` (password on STDIN). See [Configuration §1.2](CONFIGURATION.md#12-console--authentication--rbac-secrets).

## After the wizard — RBAC

- **Accounts**: `/api/users` (admin) or Administration → « Comptes » (*Accounts*). Roles `viewer` / `operator` /
  `admin` — see [Administration](ADMINISTRATION.md).
- **All routes** (except `/health`, `/api/login`, `/api/setup*`) sit behind **host-guard**
  (anti-rebinding) + **auth-guard**. Details: [Security model](SECURITY_MODEL.md).

## Securing exposure

The console binds `127.0.0.1:7100` by default. To expose it:
1. `FORGE_CONSOLE_ADDR=0.0.0.0:7100` (in an isolated network) + loopback mapping + reverse-proxy;
2. add the public host name to the host-guard via `FORGE_CONSOLE_HOST`;
3. **and** set `FORGE_CONSOLE_PASS_HASH` (or an enabled account) — never expose the open-localhost dev
   mode outside the machine.

If you are behind an upstream proxy, configure `settings.trusted_proxy` (the proxy's CIDR) so that
`X-Forwarded-For` is honoured (otherwise the source-CIDR policy would see the proxy's IP). See
[Configuration §2](CONFIGURATION.md#2-settings-table-configured-in-the-ui-ledgered).

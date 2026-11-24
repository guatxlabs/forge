# Forge — In-UI console (governed subcommand runner)

[English](CONSOLE.md) | [Français](CONSOLE.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Administration](ADMINISTRATION.md) ·
> [Backup & restore](BACKUP.md) · [Upgrade / migration](UPGRADE.md) ·
> [Security model](SECURITY_MODEL.md)

> **AUTHORISED use only.** The in-UI Console arms nothing: it exposes a small set
> of operating operations **already** available in the CLI, behind strict governance.

The **Forge Console** (roadmap **P5**) lets you launch a small number of `forge` subcommands
**from the web UI** (panel Administration → **« Console Forge »** (*Forge console*)), without opening a Linux shell. It
**removes the need** for shell access to the container for routine ops:

```bash
# BEFORE — shell access to the container required
docker compose exec forge forge status
docker compose exec forge forge ledger verify
docker compose exec forge forge backup --out /data/snap.forge --passphrase-env FORGE_BACKUP_PASSPHRASE
docker compose exec forge forge upgrade --passphrase-env FORGE_BACKUP_PASSPHRASE

# AFTER — one click in Administration → Console Forge (admin only), output streamed live
```

## It is NOT a shell

This is the most important point. The Console **does not execute free-form commands**. There is:

- **no "type your command" field** — the UI only shows a **fixed list** of commands, each
  with only its **typed options** (checkboxes / fields);
- **no arbitrary flag** — each command has an **argument schema** (closed set of flags + types);
  any flag/argument outside the schema is **rejected (400)**;
- **no going through a shell** — the server builds a **FIXED `argv`**
  `[sous-commande, --flag, valeur-typée, …]` from the **validated** triplet
  (allowlisted command, allowlisted flag, typed value) and launches the **`forge` binary** directly
  (`spawn`, never `sh -c`, never a shell string, never user text promoted to a flag);
- **no shell metacharacter** — any value containing a metacharacter (`` ; & | $ ` < > ( ) … ``,
  space, control byte) is **refused fail-closed** (defence in depth — the `argv` is fixed
  anyway).

Endpoint: `POST /api/console/exec` — body `{command, args?:{…}, confirm?:bool}`. The back end lives in
`console/src/exec.rs`; the UI in `console/web/js/views/admin/console.js`.

## The allowlist (conservatively curated)

| UI command | Actual `forge …` | Effect | Arguments (schema) |
|-------------|----------------|-------|--------------------|
| `status` | `forge status` | **read-only** | none |
| `ledger verify` | `forge ledger verify` | **read-only** | none |
| `read findings` | `forge findings` | **read-only** | `--campaign <ident>?`, `--json`? |
| `read roe` | `forge roe` | **read-only** | `--campaign <ident>?`, `--json`? |
| `read coverage` | `forge coverage` | **read-only** | `--campaign <ident>?`, `--json`? |
| `backup` | `forge backup` | creates an encrypted file | `--out <nom-géré>` (managed folder, anti-traversal) + `--passphrase-env <VAR>` |
| `upgrade` | `forge upgrade` | **state-changing** (fail-closed + rollback) | `--passphrase-env <VAR>`, `--dry-run`? — **requires `confirm:true`** outside dry-run |

### Deliberately excluded (never exposed)

- **`restore`** — **destructive** overwrite of the database + ledger + key (irreversible). Stays in the CLI.
- **`migrate-store` / `migrate`** — store switch / import — **destructive**, reserved to the operator
  CLI. (If ever exposed: **dry-run only**.)
- **`seed-demo`** — **development** fixture.
- **`useradd` / `hashpw`** — the UI **already manages accounts** (Administration → « Comptes » (*Accounts*) panel).
- **`blob-selftest`** — dev round-trip.

Rationale: only **read-only** operations are exposed + two low-risk operating operations
(`backup` creates a file; `upgrade` is **fail-closed** with a pre-upgrade snapshot + rollback),
excluding anything that **overwrites** or **mutates** irreversibly.

## Governance & safety

- **Admin only** — `check_admin` (session with the `admin` role, **fail-closed**; no fallback through
  a shared secret). A non-admin receives **403** and the panel **does not appear** in the nav (the server
  remains the authority). A forged request to `/api/console/exec` by a non-admin is **refused**.
- **Allowlist + args schema** — command outside the allowlist → **400**; flag/argument outside the schema → **400**;
  shell metacharacter / traversal in a value → **400**. Everything is **fail-closed**.
- **Confirmation of state-changing commands** — `upgrade` (outside `--dry-run`) requires `confirm:true`
  in the body; the UI enforces a confirmation **checkbox**. Without confirmation → **refusal**.
- **Secrets resolved server-side** — for `--passphrase-env` you only supply an ENV **variable NAME**,
  **never the value**. The server resolves it through `secret_from_env` (which also handles the Docker/k8s
  `*_FILE` indirection) only to **confirm** that it exists; the **value** is discarded immediately and
  **never** enters the `argv`, the ledger, the output or the logs. The child `forge` binary
  re-resolves it itself.
- **Ledger** — each execution writes a **`console.exec`** entry to the tamper-evident ledger:
  `{command, by (admin acteur), args (rédigés — noms de variables/fichiers seulement), argv, confirm}`.
  No secret **value** ever appears in it.
- **Ceilings (anti-DoS)** — the output is capped (256 KiB; beyond that it is cleanly truncated) and the duration
  is capped (default **300 s**, `FORGE_CONSOLE_EXEC_TIMEOUT_SECS`); when exceeded the **process
  group** is killed (`killpg`).
- **Streaming** — the stdout/stderr output is **streamed live** (SSE, `log`/`status` events) into
  a **read-only** pane; the UI renders each line **escaped** (`textContent`, never `innerHTML`
  of server text → no XSS). The UI also displays **the command that is about to run** (transparency).

## Environment variables

| Variable | Role | Default |
|----------|------|--------|
| `FORGE_CONSOLE_BACKUP_DIR` | **Managed** folder where `backup --out <nom>` writes (the supplied name is a plain *basename* joined to this folder — anti-traversal). | `console-backups` |
| `FORGE_CONSOLE_EXEC_TIMEOUT_SECS` | Duration ceiling of an execution (1..3600). | `300` |
| `FORGE_CONSOLE_EXEC_BIN` | `forge` binary to launch (fixed; never derived from user input). Test override / non-standard install. | current console binary |

## Default build

The Console is **additive** and **admin-gated**: the **default** build starts
unchanged, the panel is shown only to an admin, and no surface is opened to a non-admin.

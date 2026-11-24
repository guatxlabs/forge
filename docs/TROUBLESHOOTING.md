# Troubleshooting & FAQ

[English](TROUBLESHOOTING.md) | [Français](TROUBLESHOOTING.fr.md)

> [Contents](README.md) · See also: [Configuration](CONFIGURATION.md) · [HTTP API](HTTP_API.md) ·
> [Security model](SECURITY_MODEL.md) · [Installation](INSTALLATION.md)

Most Forge "problems" are **intended fail-closed behaviours**: the product
refuses rather than act on an ambiguous configuration. This page helps tell a real blocker apart
from a guard doing its job.

## First reflex: the read-only diagnostics

```sh
python3 -m forge.cli doctor            # which modules are operational + detection source
python3 -m forge.cli doctor --purple   # purple loop preflight (console /health + source)
curl -s http://127.0.0.1:7100/health   # liveness -> {"status":"ok","version":"0.0.1"}
forge ledger verify --ledger <L>       # integrity of the engagement chain
```

None of them fires anything or touches the scope/ledger.

---

## Common symptoms

### HTTP 421 "host non autorisé (anti-rebinding)" (host not allowed)
The request's `Host` is not in the **host-guard** allowlist. Add the public host name to
`FORGE_CONSOLE_HOST` (CSV). `localhost`/`127.0.0.1`/`::1` are always accepted — which is why the
healthcheck (which targets `127.0.0.1`) stays green even behind a restricted host-guard. See
[Configuration §1.1](CONFIGURATION.md#11-console--bind-state-paths-session).

### HTTP 401 "auth requise" (auth required; the SPA shows the login portal)
The auth gate is **engaged** (an env hash is set **or** an enabled account exists) and no valid
proof is presented. Log in through `POST /api/login`, or present Basic (viewer) / Bearer
(ingestion token). On a fresh install, this is the expected behaviour after the wizard. See
[Security model §2](SECURITY_MODEL.md#2-authorisation-authz--rbac--gates).

### HTTP 403 "operator_required" on `/api/run`
The **operator** role is not provisioned (C2 closed, fail-closed) **or** the proof/the source-CIDR
check fails. Provision: `forge useradd <login> operator` (or `FORGE_CONSOLE_OPERATOR_HASH` +
`X-Forge-Operator` header). If `operator_policy.source_cidrs` is configured, check that the client IP
(or the last XFF hop, if `trusted_proxy` is correct) falls within a CIDR.

### HTTP 403 "admin_required"
Administration requires an **admin session** (no fallback through a shared secret). Log in with an
admin account. To create the first one: the [wizard](FIRST_DEPLOYMENT.md) or `forge useradd <login> admin`.

### HTTP 400 "out_of_scope" when launching a run
The target is not in the **server scope** (`FORGE_CONSOLE_SCOPE`). C2-light refuses, **before** the
spawn, any target outside `in_scope`. Check: `forge scope-check <cible> --scope <scope.json>`.

### HTTP 400 on `/api/run` with an exploit/destructive module
**Exploit floor**: `exploit`/`destructive` modules are refused except for a **governed high-impact
opt-in** — set `arm:true` + `reason` (non-empty) **and** be an operator. Otherwise, remove these modules
from the run. See [Architecture §3.3](ARCHITECTURE.md#33-the-governed-c2-light-run-flow).

### HTTP 409 "run_in_progress"
**FIFO PER ENGAGEMENT**: at most one live run *per engagement* (the 409 body carries
the busy `engagement_id`). Wait for THAT run to finish or `POST /api/runs/:id/cancel`. Another
engagement can, for its part, launch a run **in parallel** without a 409 — concurrency is inter-engagement.

### `forge scope-check` says HORS SCOPE / nothing fires (everything DRY_RUN or VETO)
Forge is **INERT by default**: empty `in_scope` ⇒ everything is refused (fail-closed). Fill in
`in_scope` in `scope.json` **with written authorisation**. To fire, you also need to **arm**
(`--arm`) and **approve** (`--approve` or `--mode auto`), and — for an exploit — `allow_exploit:true`
in the scope. See [Concepts §1](CONCEPTS.md#1-roe--scope-guard).

### A module shows as `INDISPONIBLE ⛔` in `forge doctor`
Its underlying tool is missing (auto-neutralisation) — this **is not an error**, the module is
simply SKIPPED at firing. `forge doctor` prints the expected tool + the install hint. In the `mini` image,
httpx/nuclei/subfinder/weasyprint are deliberately absent (switch to `full` to ship them). An
unreachable recon module emits a `status=skipped` finding (offline-safe), not a crash.

### An enabled connector does not fire
Check that it has not been **disabled** in governance (`GET /api/modules` → `enabled`). A
disabled connector is SKIPPED **even if its binary is present**. See
[Administration §3](ADMINISTRATION.md#3-connector-governance-installuninstall).

### Purple coverage answers `source_reachable:false`
The detection source is **absent / unreachable / misconfigured** — Forge declares the measurement
**impossible** (readable fail-open) and **never makes up** `detected`/`parent_approx`/`missed`/`MTTD`. This is valid in
standalone mode. To enable it: *Administration → Detection source* (or `PLUME_URL`/`PLUME_TOKEN`),
then `forge doctor --purple` for the preflight. Source **reachable but empty** (fresh SOC) =
`reachable:true, detections:[]` — also valid. See [`DETECTION.md`](DETECTION.md).

### The MTTD looks abnormally high (several hundred seconds)
Forge's MTTD is a **time-to-ALERT**, not a time-to-event: it includes the ingest latency + the SIEM's
**rule evaluation cadence** (`interval_s`). An MTTD dominated by the rule interval
does **not** indicate a slow SOC. Full explanation: [`MTTD.md`](MTTD.md).

### The container is `unhealthy`
The healthcheck performs a real `GET /health` expecting 200. Check the logs
(`docker logs forge`) — often a **scope mounted as a directory** (see below) or a
bind that failed. `docker inspect --format '{{.State.Health.Status}}' forge`.

### "FATAL: /data/scope/scope.json est un REPERTOIRE, pas un fichier" (is a DIRECTORY, not a file)
The **scope pre-step was forgotten**: Docker creates an empty directory when `./scope.json` is absent
on the host. Run `cp scope.example.json scope.json` in `forge/` **before** `docker compose up`.
The entrypoint fails **loudly** on purpose (rather than starting on an unreadable scope), and falls back
to `scope.example.json` (INERT) if the file is missing/empty without being a directory. See
[Installation](INSTALLATION.md#mandatory-pre-step--the-scope-file-fail-loud).

### The encrypted database does not open / the console does not start (`encryption` build)
`FORGE_DB_KEY` is absent or incorrect ⇒ database **unreadable** (fail-closed, expected behaviour).
Supply the right key through the ENV (never in argv). On a **default** (unencrypted) build,
`FORGE_DB_KEY` is simply ignored and `capabilities.sqlcipher:false`. See
[`MIGRATION.md`](MIGRATION.md) Runbook B.

### `forge ledger verify` fails after a migration
The `.ed25519` key **did not travel** with the ledger. Ed25519 signatures are verifiable only
by their sibling signing key. Redo the migration making sure that
`engagement.jsonl.ed25519` is present on the source side; `forge migrate` copies it
automatically at `0600`. `GET /api/ledger/verify` (chain, `sig_checked:false`) can be OK on the
console side while the **signature** fails on the engine side — that is the symptom. See
[`MIGRATION.md`](MIGRATION.md).

### `ledger verify` reports "algo interdit pour kind (downgrade refusé)" (algorithm forbidden for kind, downgrade refused)
Anti-downgrade guard: a non-console entry carries `sha256-console`, or a console entry carries a
signed algorithm. This signals **tampering** (rewrite/relabel). The ledger is broken — investigate
(the `broken` entry is reported). See [Security model §4](SECURITY_MODEL.md#4-ledger-integrity).

### The Docker build fails "pin SHA256 absent / non-correspondance" (SHA256 pin missing / mismatch)
Hardened supply chain: the ProjectDiscovery archives are **pinned by digest**; any
mismatch makes the build fail. When bumping a version, refresh **version AND digest**
(from the official `*_checksums.txt`). Alternative: `mini` build then bind-mount the binaries.

### The Docker build fails to fetch `guatx-core`
The **build context is the root of this repository**; the console resolves `guatx-core` through a pinned
public git dependency (`tag = "v0.2.2"`, cf. `console/Cargo.toml`), **fetched from GitHub at build time** —
the builder therefore needs **network access to github.com** (or a Cargo registry mirror/cache). In
monorepo dev, `console/.cargo/config.toml` (gitignored) redirects the dependency to the local core. Run
`docker build -t forge:0.0.1 .` **from the repository root**, or use the compose file (`context: .`).
See [`DEPLOYMENT.md`](DEPLOYMENT.md) §4.

### `?format=pdf` returns `pdf_unavailable`
No PDF engine on the PATH (`mini` image, or install without weasyprint). Use
`?format=html` + the browser's "Print → Save as PDF" (print stylesheet
provided), or install `weasyprint` (pip, pure Python) / switch to the `full` image. See
[`DEPLOYMENT.md`](DEPLOYMENT.md) § Reports & PDF export.

---

## FAQ

**Does Forge replace Metasploit / Burp / nuclei?**
No — it **drives** and **governs** them, and **measures** their defensive impact. It is a
governance + evidence + measurement layer, not an arsenal. See [Overview](OVERVIEW.md) and
[`POSITIONING.md`](POSITIONING.md).

**Do I need Plume / a SOC to use Forge?**
No. Forge is complete in **standalone** mode; the purple loop is optional and plugs in later
without migration. See [Using Forge standalone](STANDALONE.md).

**Is it a C2 / a beacon?**
No — no implant, no persistent access, no post-exploitation. The "C2-light" run-flow is
a **governed and audited campaign launcher**, not a persistent command channel. See
[Architecture §3.3](ARCHITECTURE.md#33-the-governed-c2-light-run-flow).

**Can Forge fire on its own by accident?**
Not by construction: INERT by default, empty `in_scope` = nothing, explicit arming + approval,
opt-in exploit floor, `VETO` never fired. See [Concepts §1](CONCEPTS.md#1-roe--scope-guard).

**Does the ledger prove anything to a third party?**
Yes: `forge ledger verify --pubkey <clé publique>` lets an auditor verify integrity **and**
scope membership with the **public key alone**, without being able to forge. The private key stays
local today (documented custody). See [Concepts §2](CONCEPTS.md#2-the-engagement-ledger).

**Can I expose the console on the Internet?**
Only behind a reverse proxy + auth + `FORGE_CONSOLE_HOST` + enabled hashes/accounts (+
`trusted_proxy` if behind a proxy). Never expose the open-localhost dev mode. See
[Security model §7](SECURITY_MODEL.md#7-surface-hardening).

**Does Forge scale horizontally?**
Not yet: **stateful single-replica** (SQLite + ledger on an RWO PVC). Ideal profile:
single operator / small MSSP. See [`DEPLOYMENT.md`](DEPLOYMENT.md) § Architecture constraint.

**How many modules and which techniques?**
88 modules in the registry (MEASURED on 2026-11-24: `python3 -m forge.cli modules --json`) (recon, proof oracles, evasion, connectors), each tagged with MITRE ATT&CK.
Partial table: [MODULES.md](MODULES.md) (an EXTRACT written by hand: 43 of the 88; the complete list is the output of `python3 -m forge.cli modules --json`).

**How do I back up / migrate without losing the audit?**
The three coupled artefacts (DB + ledger + `.ed25519` key) travel together. Backup always
encrypted: [`BACKUP.md`](BACKUP.md). Migration: [`MIGRATION.md`](MIGRATION.md).

**Where are the configuration values?**
Full table of the environment variables and of the `settings` keys: [Configuration](CONFIGURATION.md).

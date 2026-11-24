# Configuration reference

[English](CONFIGURATION.md) | [Français](CONFIGURATION.fr.md)

> [Contents](README.md) · See also: [Installation](INSTALLATION.md) ·
> [First deployment](FIRST_DEPLOYMENT.md) · [Administration](ADMINISTRATION.md) ·
> [Security model](SECURITY_MODEL.md)

Forge is configured at **two complementary levels**:

1. **Environment variables** — set **at deployment** (image / `.env` / systemd EnvironmentFile).
   They drive the bind, the state paths, the bootstrap secrets, the driven services. Commented
   template: [`../.env.example`](../.env.example).
2. **`settings` table** (SQLite) — configured **in the UI** (first-boot wizard or
   *Administration*), admin-only, **ledgered**. It holds the detection source, the operator policy,
   the backup policy, etc. **Nothing in it is hard-coded.**

> Safety: the defaults leave Forge **INERT** and on **loopback**. Nothing is armed. Secrets
> ([SECRET]) must NEVER be committed; keep `.env` at `0600`.

---

## 1. Environment variables

### 1.1 Console — bind, state paths, session

| Variable | Meaning | Default | Example |
|---|---|---|---|
| `FORGE_CONSOLE_ADDR` | API/UI bind address. **Never** `0.0.0.0` without reverse proxy + auth + host allowlist. | `127.0.0.1:7100` (binary) · `0.0.0.0:7100` (image, isolated network) | `127.0.0.1:7100` |
| `FORGE_CONSOLE_DB` | Path of the SQLite store. | `forge.db` | `/data/db/forge.db` |
| `FORGE_CONSOLE_LEDGER` | Path of the engagement ledger (JSONL). | `engagement.jsonl` | `/data/ledger/engagement.jsonl` |
| `FORGE_CONSOLE_SCOPE` | Path of the **active** scope/ROE (empty in_scope = INERT). Fail-closed pre-filter of the targets launchable from the web. | `<pkg_dir>/scope.json` | `/data/scope/scope.json` |
| `FORGE_CONSOLE_WEB` | Root of the UI assets served as fallback. | auto-resolved (`console/web`) | `/opt/forge/console/web` |
| `FORGE_CONSOLE_USER` | Identifier of the **viewer** role (Basic auth). | `forge` | `forge` |
| `FORGE_CONSOLE_SESSION_TTL` | Lifetime of a session (s). **This is the effective value** of the session TTL. | `3600` | `1800` |
| `FORGE_CONSOLE_HOST` | Anti-DNS-rebinding `Host` allowlist (CSV) when exposed through a proxy. `localhost`/`127.0.0.1`/`::1` are always accepted. | *(empty)* | `console.exemple.test` |
| `FORGE_CONSOLE_LEDGER_PUBKEY` | Ed25519 public key (hex 64) for console-side verification. **Public, not secret.** | *(empty)* | `a1b2…` |

### 1.2 Console — authentication / RBAC secrets

Empty ⇒ **open-localhost dev mode** for the viewer, ingestion token **generated at boot**, operator
role **not provisioned** (C2 closed). Fill them in for a hardened deployment (or provision everything
through the [wizard](FIRST_DEPLOYMENT.md)).

| Variable | Meaning | Default | How to obtain it |
|---|---|---|---|
| `FORGE_CONSOLE_TOKEN` | **[SECRET]** **Ingestion** bearer (engine→console channel). Otherwise generated at boot (ephemeral). | *(auto)* | `openssl rand -hex 16` |
| `FORGE_CONSOLE_PASS_HASH` | **[SECRET]** argon2id hash of the **viewer** role (Basic). Its presence engages the auth gate. | *(empty)* | `forge hashpw '<pw>'` |
| `FORGE_CONSOLE_OPERATOR_HASH` | **[SECRET]** argon2id hash of the C2 **operator** role (`X-Forge-Operator` header). Empty = **C2 closed** (fail-closed). | *(empty)* | `forge hashpw-operator '<pw>'` |

> **Individual attribution**: administration (`check_admin`) does **NOT accept** an env-hash
> fallback — it requires a named **admin session** (created through the wizard or `forge useradd
> <login> admin`). The env hashes are a **headless bootstrap** mechanism (viewer/operator).

### 1.3 Python engine — spawn & timeouts

| Variable | Meaning | Default | Example |
|---|---|---|---|
| `FORGE_PKG_DIR` | Root of the `forge` python package spawned by the console (cwd of the spawn). | `..` | `/opt/forge` |
| `FORGE_PYTHON` | Interpreter for `python3 -m forge.cli`. | `python3` | `python3` |
| `FORGE_DURATIONS` | Kill switch of the **observed-durations store** (`<ledger>.durations`, sidecar of the engagement ledger — hence **per engagement**, deleted with it). It aggregates the duration of shots **PER MODULE KIND ONLY** (never per target/host/URL: that would be a reconnaissance log outliving the engagement), at a **bounded** size (≤ 256 kinds, fixed aggregate per kind, ~a few KiB). It serves **only** the SUBMISSION order of the intra-wave preheat (`engine._preheat_key`) — **no** firing, scope or ROE decision depends on it. `0`/`off`/`false`/`no` ⇒ no file, no measurement, preheat on `action.cost` (behaviour before this version). Without `--ledger`, there is no file anyway. | *(active)* | `0` |
| `FORGE_RUN_TIMEOUT` | Max budget (s) of a C2-light run (watchdog). | `1800` (binary) · `900` (image) | `900` |
| `FORGE_KIND_BUDGET_SHARE` | **Share of the time budget that ONE SINGLE module kind may consume** in a run, as a fraction. Serves the second clause of the budget gate (`engine._budget_gate` → `interrupt.KindShare`): a shot is not STARTED if its **expected** consumption (observed mean of the kind on this run, failing that the `.durations` sidecar, failing that the declared bound — never beyond that bound), added to what the kind has **already** consumed, would exceed this share. Motivated by measurement: on a real campaign, `web.testssl` took **1 484 s (41 %)** of a 3 600 s budget — three individually reasonable shots, two of them killed at their 600 s wall — while wave 1 did not finish. **This is not a truncation**: the refused action comes out as a **named SKIP**, listed in the report, **with no verdict at all** (neither `tested`, nor `not_vulnerable`, nor finding). Three guards: the **1st shot of a kind is never refused** (a slow scanner always runs at least once); the **qualifying classes** (IDOR/auth/RCE/SSRF/biz — `planner.is_floored`) are **exempt**; and **with no time budget set, the clause is completely inert**. `0` disables it. Unreadable value → default. | `0.3333` (1/3) | `0.25` |
| `FORGE_PLAN_TIMEOUT` | Max budget (s) of a **dry-plan** (`POST /api/plan`, inert). When exceeded: the engine **group** is killed and the caller receives `504 plan_timeout` (never a partial preview). Invalid value or `0` → default. | `300` | `60` |
| `FORGE_PLAN_MAX_CONCURRENT` | Number of simultaneous **in-flight dry-plans** (each one spawns an engine process). Beyond that: `429 plan_busy` — an explicit error, **not** a silent queue. **Re-read on every dry-plan** (like `FORGE_PLAN_TIMEOUT`): a change takes effect without a restart. Invalid value or `0` → default. | `2` | `4` |
| `FORGE_ENGINE_TIMEOUT` | Budget (s) of the **engine work** of the other spawns: catalog `GET /api/techniques`, `GET /api/workflows`, detection collector, **DOCX/PDF** rendering of the deliverable, and registry probe (`POST /api/modules/refresh`, boot). When exceeded: the **group** is killed and the route returns its NAMED cause (`techniques_unavailable`/`builtins_unavailable` in fail-soft, `504 docx_engine_timeout` for the deliverable). Re-read on every call. Invalid value or `0` → default. **The wall-clock time of a cut request equals this budget PLUS the time for the spawn to actually die** (SIGTERM, then SIGKILL after 5 s if a member ignores it): measured at **5.02–5.06 s** (9 measurements) for a 5 s budget on an engine that exits on SIGTERM. | `120` | `30` |
| `FORGE_ENGINE_MAX_CONCURRENT` | Number of live **READ** engine spawns (a counter distinct from the dry-plan one and the operator one: a burst of reads does not starve the operator, and vice versa — the machine total is the **sum** of the three). A slot is held for the **life of the process AND of its descendants**, not for that of the HTTP request: abandoning the request does not release it. A descendant that LEAVES the group (`setsid`/double-fork) is found again through the spawn's environment marker and through the parent chain (subreaper) — measured: 40 abandoned requests left **40** live descendants with a ceiling of 4; they now leave **0** and the bound refuses (burst of 20: 16 × `429`). Limits written in `docs/HTTP_API.md`, and they are CHEAPER FOR THE ESCAPEE THAN THEIR NAME SUGGESTS: removing ONE environment variable is enough (`env -u FORGE_ENGINE_SPAWN` → **7 survivors**, exactly like `env -i`) when the leader has already exited; and work delegated to a NON-descendant (`systemd-run --user`) simply leaves the domain (**5 survivors** for 4 abandoned requests, slot released immediately). Outside Linux, no `/proc`: fallback to the group kill. COST ON THE NOMINAL PATH, measured, AND IT DEPENDS ON THE SHAPE OF THE DESCENDANT (only one shape had been measured and its figure wrongly generalised): no descendant **0.030–0.040 s**; descendant that REDIRECTS its fds and dies on SIGTERM **0.133–0.146 s**; that REDIRECTS its fds and IGNORES SIGTERM **5.17–5.24 s** (slot held until the SIGKILL of the grace window, and it is indeed killed); that INHERITS the stdout pipe — the default of a `fork`/`Popen` without redirection — **0.380–0.396 s**, versus the WHOLE ENGINE BUDGET before the fix (**5.13 s** at `FORGE_ENGINE_TIMEOUT=5`, **9.13 s** at 9, **120.061 s** at the shipped default, and the valid output was DISCARDED). The lever for that case was not `CANCEL_GRACE_SECS` but `FORGE_ENGINE_TIMEOUT`; it is fixed at the cause (the response no longer waits for an inherited pipe to close, cf. `docs/HTTP_API.md`). Beyond that: **explicit** refusal (the message names the variable), **not** a silent queue. Re-read on every call. Invalid value or `0` → default. | `4` | `8` |
| `FORGE_ENGINE_OPERATOR_MAX_CONCURRENT` | Number of live **OPERATOR** engine spawns: `POST /api/import`, `POST /api/modules/refresh`, `POST`/`DELETE /api/tools`, registry probe at boot. A gate separate from reads for two measured reasons: a burst of viewer reads must not make an operator import fail, and 40 concurrent refreshes must not make a viewer read 50× slower (measured **0.21 s → 11.4 s** before the bound, **0.34 s → 3.7 s** after). Beyond that: explicit refusal (`429 import_busy`, `429` + `probe_error` for the refresh). Re-read on every call. | `2` | `4` |
| `FORGE_IMPORT_TIMEOUT` | Budget (s) of the parse of a **scan import** (`POST /api/import`) — distinct from `FORGE_ENGINE_TIMEOUT` because a scanner export (up to 64 MiB, the route's input ceiling) is legitimately longer than a catalog. When exceeded: spawn killed, `504 import_timeout`, **no** partial finding inserted. Re-read on every call. Invalid value or `0` → default. **Why 600 s by default**: the budget is sized on the route's INPUT CEILING (64 MiB), not on a typical import. Measured on this machine (real `python3` engine, in-scope targets): 1.3 MiB / 9 000 entries → **4.7 s**; 11.1 MiB / 72 000 entries → **49.2 s** (super-linear growth). At 64 MiB, the order of magnitude therefore exceeds 285 s: a shorter default would cut a legitimate import at the worst moment. What a slow import costs: **one** of the 2 slots of the OPERATOR gate (never the read gate), on an operator-authenticated route, with no process leak (measured: 0 survivors after the client disconnects). An operator who wants a short wall-clock lowers it — that is the point of the variable. | `600` | `120` |
| `FORGE_CONSOLE_URL` | `POST /api/ingest` ingestion target for the **Python client** (`campaign`, `demo_ingest`, `doctor`). Must match `FORGE_CONSOLE_ADDR`. | `http://127.0.0.1:7100` | `http://127.0.0.1:7100` |
| `FORGE_LEDGER_KEY` | **[SECRET]** Ledger signing key material on the engine side. Empty = auto-generated local key (`<base>.ed25519`, `0600`). | *(empty)* | *(key material)* |
| `FORGE_TOOLS_DIR` | Root of the **runtime tools volume** (`forge tools install\|update\|remove`): binaries go into `<dir>/bin`, receipts into `<dir>/state`. `<dir>/bin` must be on the `PATH` to be resolved (the image puts it there, ahead of the baked `/usr/local/bin`). **Nothing is created until an operator action has taken place** → empty = behaviour identical to the baseline. Cf. `docs/TOOLS_LIFECYCLE.md`. | `<data_dir>/tools` | `/data/tools` |
| `FORGE_TOOLS_MANIFEST` | Path of the tools **manifest** (versions + SHA256 pins per architecture + URL templates). Empty = `tools.json` shipped in the package. An operator manifest remains subject to the **same** fail-closed validations (`https://` URL mandatory, 64-hex digest, `bin` without path separator): it moves the allowlist, it does not remove it. | *(shipped)* | `/etc/forge/tools.json` |
| `PYTHONPATH` / `PYTHONUNBUFFERED` | Resolution of the `forge` package / unbuffered logs (set by the image/systemd). | image | `/opt/forge` / `1` |

> **Byte ceiling (not configurable).** The output of an engine spawn is collected in RAM: it is
> capped at **8 MiB** (text outputs: dry-plan, catalogs) and **64 MiB** (binary outputs: DOCX/PDF).
> Beyond that, the group is killed and the caller receives an explicit error (`502 plan_output_too_large` for the
> dry-plan, `501` degradation for the deliverable) — **no partial output is returned as complete**.
> This is not an operating setting but an anti-OOM dam: these values are constants of the binary.

### 1.4 Encryption at rest

| Variable | Meaning | Default | Example |
|---|---|---|---|
| `FORGE_FIELD_KEY` | **[SECRET]** **Field encryption** passphrase. Covers (a) the engagement **authentication material** (bearers/cookies/headers of the test accounts) and (b) the **three integration secrets**: detection source token, notification channel token, SSO `client_secret`. **DEFAULT build** — pure-Rust AEAD, no added dependency. Required **only** if one of these secrets is set: without it, every write is refused (**503** `field_key_missing`), a run whose material is sealed **refuses to start**, and an integration whose secret is sealed **refuses to go out** (never an empty context or authentication in silence). Accepts `FORGE_FIELD_KEY_FILE`. | *(empty)* | *(strong passphrase)* |
| `FORGE_DB_KEY` | **[SECRET]** SQLCipher key (**full** encryption). The console issues `PRAGMA key` **before any query**. Without it (on an encrypted build), the database is **unreadable** (fail-closed). **Ignored** on the default build (database in plaintext). | *(empty)* | *(strong passphrase)* |

The two layers are **independent and composable**: `FORGE_FIELD_KEY` protects the credentials
**in the default build** (openssl-freedom intact); `FORGE_DB_KEY` encrypts **everything else**, at
the cost of a system crypto backend at compile time (`encryption` image).

See [`DEPLOYMENT.md` §1.6](DEPLOYMENT.md#16-field-encryption-of-authentication-material-default-build)
(field), [`MIGRATION.md`](MIGRATION.md) Runbook B and [Installation §6](INSTALLATION.md#6-encryption-image-encryption-at-rest--sqlcipher-opt-in) (SQLCipher).

### 1.4bis Outbound egress — TLS trust and client identity

The **three** TCP outputs of the console (OIDC token exchange, notification webhook, detection source
fetcher) go through a **single TLS seam** (`console/src/tls.rs`) whose verification is
**full and without escape hatch**: chain, host name, validity. The **system** CA store **is not
read** (no-OS-dependency posture: no `schannel`/`security-framework`/`openssl`), so a **private
enterprise CA** must be **supplied explicitly**.

Two directions not to be confused: `FORGE_EXTRA_CA_PEM` is used to **verify the peer**; `FORGE_CLIENT_*`
is used to **authenticate us to it** (mTLS). Setting the second relaxes nothing of the first.

| Variable | Meaning | Default | Example |
|---|---|---|---|
| `FORGE_EXTRA_CA_PEM` | **ADDITIONAL** trust anchors in **verbatim PEM** format (one or more `CERTIFICATE` blocks), **added** to the Mozilla roots — never substituted. For an OIDC IdP or a collector signed by the organisation's private CA. **Verification stays FULL**: this is **not** a switch, there is still no way to accept an unknown chain, a wrong host name or an expired certificate. **FAIL-CLOSED**: an unreadable/empty/invalid PEM **kills the boot** (`FATAL`, code 2) rather than silently degrading to "no anchor". Accepts `FORGE_EXTRA_CA_PEM_FILE` (a **path**). | *(empty = Mozilla roots only)* | `-----BEGIN CERTIFICATE-----…` |
| `FORGE_CLIENT_CERT_PEM` | **CLIENT certificate chain** (PEM, **leaf first**, intermediates next) that the console **presents to the peer that requires it** (mTLS). It is sent **only if the peer asks for it**: setting it changes **nothing** for ordinary endpoints. Public — the peer receives it on the wire. Accepts `FORGE_CLIENT_CERT_PEM_FILE` (a **path**). | *(empty = no certificate presented)* | `-----BEGIN CERTIFICATE-----…` |
| `FORGE_CLIENT_KEY_PEM` | **[SECRET — the most sensitive of the binary]** Private key of the chain above (PKCS#8, PKCS#1 or SEC1). It appears **nowhere**: not at boot, not in a log, not in an error, not in the ledger, not in an API response. A refusal says **that** the key is invalid, never **what it contains**. **Strongly prefer `FORGE_CLIENT_KEY_PEM_FILE`** (a **path** to a `0600` file): a process's environment can be read in `/proc/<pid>/environ` and is copied into any configuration dump. | *(empty = no certificate presented)* | `/etc/forge/client.key` via `…_FILE` |
| `FORGE_ALLOW_INTERNAL_INTEGRATIONS` | Allows **integration** fetches to reach an **internal/private** target (on-prem SIEM/IdP). Absent/false ⇒ SSRF deny-list (loopback, RFC1918, link-local, cloud metadata, ULA). **Does not cover** sending a secret in plaintext to a **public** target: that refusal has **no** escape hatch. | *(empty = refused)* | `1` |

**The two `FORGE_CLIENT_*` go together, or neither.** A certificate without a key cannot sign anything,
a key without a certificate proves no identity: in both cases rustls would simply send nothing,
and the mTLS peer would refuse the connection with a message that does not point to the
missing variable. The boot therefore **dies** (`FATAL`, code 2) on a half-set identity, on an
unreadable PEM, and on a **key that does not match the certificate** (comparison of the
`SubjectPublicKeyInfo`) — the mistake one makes when renewing one without the other.

### 1.5 Migration through the API (opt-in, pre-provisioning)

| Variable | Meaning | Default | Example |
|---|---|---|---|
| `FORGE_ALLOW_API_MIGRATE` | Opens `POST /api/setup/migrate` (otherwise **403** — the `forge migrate` CLI remains the primary UX). | *(off)* | `1` |
| `FORGE_CONSOLE_IMPORT_DIR` | Allowlisted root of the import paths of the API migration (anti path traversal). | *(data root)* | `/import` |

### 1.6 Scheduled backups

| Variable | Meaning | Default | Example |
|---|---|---|---|
| `FORGE_BACKUP_TICK_SECS` | Wake-up period of the backup scheduler. | `60` | `60` |
| `FORGE_BACKUP_PASSPHRASE` | **[SECRET]** Passphrase of the **scheduled** backup. **The NAME of this variable** is referenced by `backup_policy.passphrase_env` (never the passphrase in the DB). | *(empty)* | *(passphrase)* |

Details: [`BACKUP.md`](BACKUP.md).

### 1.7 Purple loop — detection source (legacy / collector)

The source is configured **preferably in the UI** (`settings.detection_source`, §2). The variables
below are **fallbacks**:

| Variable | Meaning | Default | Example |
|---|---|---|---|
| `PLUME_URL` | **[PURPLE]** Backward-compatible `kind=plume` preset (used only if `settings.detection_source` is absent). Internal `http://` only. | *(empty = purple OFF)* | `http://plume-internal:8000` |
| `PLUME_TOKEN` | **[SECRET][PURPLE]** Basic auth = `base64("user:pass")`. | *(empty)* | `dXNlcjpwYXNz` |
| `FORGE_DETECTION_SOURCE` | **[SECRET]** Full JSON specification of a source ("rich" kinds: crowdsec/elastic/syslog/mTLS/exec). The console passes it **through ENV** to the Python collector (never in argv). | *(empty)* | `{"kind":"crowdsec",…}` |

Full model and presets: [`DETECTION.md`](DETECTION.md). Plume prerequisites:
[`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).

### 1.8 Access/evasion layer (browser-automation, optional)

| Variable | Meaning | Default | Example |
|---|---|---|---|
| `FORGE_BROWSER_URL` | Camoufox + Xvfb service for the `evasion.*` modules. Unreachable = inert connector. | `http://localhost:8080` (image: `http://browser-automation:8080`) | `http://browser-automation:8080` |

### 1.9 Operator connectors (optional)

Empty/unreachable ⇒ connector inert at fire-time (no embedded offensive capability).

| Variable | Meaning | Default |
|---|---|---|
| `MSF_RPC_HOST` | msfrpcd host. | `127.0.0.1` |
| `MSF_RPC_PORT` | msfrpcd RPC port. | `55553` |
| `MSF_RPC_USER` | RPC user. | `msf` |
| `MSF_RPC_SSL` | TLS to msfrpcd. | `true` |
| `MSF_RPC_PASS` | **[SECRET]** RPC password (`msfrpcd -P`). | *(empty)* |
| `MSF_RPC_TOKEN` | **[SECRET]** Permanent RPC token (alternative to user/pass). | *(empty)* |
| `BURP_API_URL` | Burp REST API base. | `http://127.0.0.1:1337` |
| `BURP_API_KEY` | **[SECRET]** Burp API key (often embedded in the URL). | *(empty)* |

### 1.10 Build-time (image)

| Variable | Meaning | Default | Example |
|---|---|---|---|
| `FORGE_TOOLS_PROFILE` | `--build-arg`: `full` (SHA256-verified httpx/nuclei/subfinder + weasyprint PDF engine) or `mini` (omits them). | `full` | `mini` |

See [Installation §1](INSTALLATION.md#1-image-profiles-mini-vs-full).

---

## 2. `settings` table (configured in the UI, ledgered)

Keys of the SQLite `settings` table, mutated through the API (admin) or the wizard. **No hard-coded
value**: an absent key = default behaviour, never an invented value.

| Key | Meaning | Default | Written by |
|---|---|---|---|
| `detection_source` | `DetectionSource` object (source of the purple loop). Auth secret **write-only** (never returned). | *(absent = purple OFF, readable fail-open)* | wizard · `POST /api/detection/source` · `POST /api/setup` |
| `operator_policy` | Policy of the operator role (C2). Key field: `source_cidrs` (client IP allowlist). Absent/empty = **no** source restriction. | *(absent)* | wizard · `POST /api/setup` |
| `backup_policy` | Scheduled/offsite backup policy (`enabled`, `interval_secs`, `retention`, `passphrase_env`, `staging_dir`, `offsite`). Secrets redacted on GET. | *(absent = no scheduled backup)* | `POST /api/backup/policy` |
| `backup_last_run` | Internal timestamp of the last due backup tick (scheduler state). | *(absent)* | scheduler (internal) |
| `session_ttl` | Session TTL **persisted** by the wizard/setup (config substrate). The **effective** duration is driven by `FORGE_CONSOLE_SESSION_TTL` (§1.1). | *(absent)* | `POST /api/setup` |
| `trusted_proxy` | CIDR(s) of the trusted upstream proxy(ies). An `X-Forwarded-For` is honoured **only** if the TCP peer falls within one of them; otherwise **fail-closed** fallback to the TCP peer. A non-CIDR value ⇒ XFF ignored. | *(absent = XFF not honoured)* | admin (settings) |

### Module governance (`module` table)

Distinct from `settings`: the `module` table holds the **catalog** (populated at boot from `forge
modules`) **and** the per-connector governance, mutated by `POST /api/modules/:kind` (admin,
ledgered):

| Field | Meaning | Effect |
|---|---|---|
| `enabled` (bool) | Connector enabled/disabled. | `enabled=false` ⇒ SKIP at firing (like a missing tool), **even if the binary is present**. |
| `web_allowed` (bool) | The connector may be launched from the web (C2-light). | Controls the `web_allowed` floor of the modules selectable through `/api/run`. |
| `available_override` (bool\|null) | Forces/clears the displayed availability state (3 states: unchanged / cleared / forced). | Reflects availability in the UI. |

See [Administration → Connector governance](ADMINISTRATION.md#3-connector-governance-installuninstall).

---

## 2bis. Rate (`rate`) — what it throttles, and what it does not

Set in **`scope.json`**, not in the environment. The point to know, because it surprises:

| | throttled by `rate`? |
|---|---|
| Forge's **43 NATIVE modules** derived from `Oracle`, cf. §2ter (its own urllib probes: injection oracles, access control, passive recon, headers…) | **yes, always** |
| The tools whose rate is counted in **HTTP REQUESTS/s** (`nuclei`, `httpx`, `feroxbuster`, `katana`, `dnsx`, `subfinder`) | **yes, by default** |
| The other external tools — **packets/s** (`naabu`, `nmap`) or **delay per request** (`sqlmap`, `wfuzz`, `dalfox`, `gobuster`, `wpscan`) | **no, unless explicitly requested** |

The cost of throttling is real, and it is what had justified the generalised opt-in. Measured at `rate: 5`:

    naabu       1,1 min  ->  3,6 h     # 65 535 ports at 5 packets/s
    feroxbuster       …  ->  ~100 min  # before: a few minutes
    nuclei      1,0 min  ->   30 min
    httpx       0,1 min  ->  3,3 min

**But the cost of NOT throttling had never been quantified, and it is worse.** Measured on 2026-08-11
(clean machine, baselines verified, Juice Shop on loopback, 900 s autonomous campaign):

| `rate` | target memory | outcome | work actually done |
|---|---|---|---|
| **20** | 167 -> **5 023 MiB** | **DEAD** (`Exited 139`) at t+145 s | 8 actions, **1 660 errors** |
| **5** | 162 -> **484 MiB** | **alive**, HTTP 200 | **1 360 actions**, 2 730 findings |

**170 times more actions fired when throttling.** A dead target turns the whole rest of the plan into
errors: here, throttling does not cost coverage — throttling IS coverage. The killer was isolated
ALONE, without a campaign (`feroxbuster --rate-limit 20` -> 5 051 MiB and dead; `--rate-limit 5` -> 384 MiB
and alive), and a ONE-variable disambiguation shows that it is the **rate** and not the
concurrency: 4 threads at 20 req/s kill, 50 threads at 5 req/s do nothing.

Hence the current default: **a tool that counts in HTTP requests follows `rate` without being asked.**
The quantified bill above is that of the PORT scanner; it is not paid by default. And
the unit is not guessed — each tool declares it in its params schema ("req/s" vs
"packets/s"), and forge reads it there rather than from a hand-maintained list.

> ⚠️ **Without `rate` declared in the scope, nothing is throttled** — crawlers included. Forge does not
> make up a rate that the engagement has not set. On a real target, declaring `rate` is therefore not
> an optimisation: it is what separates an engagement from a service degradation.

**To ALSO throttle the tools that remain opt-in: `"rate_explicit": true`** in the scope —
that is, the PORT scanner (`naabu -rate`, `nmap --max-rate`) and the tools whose flag is
a **delay per request** (sqlmap/wfuzz/dalfox/gobuster/wpscan). It additionally arms the **RUN
rate ceiling** (`RunCap`, cf. §2ter). Without it, the argv of those tools remains **byte-identical** to
their default; the **req/s** tools, for their part, follow `rate` without being asked (see above).

> **Four tools silently escaped it** (fixed): `recon.katana`, `recon.dnsx`,
> `recon.subfinder` and `web.wpscan` declared a `{param:rate}` group in their argv template
> **without ever receiving a rate** — the list of affected kinds was hand-maintained and had
> drifted from the catalog. A template group whose param is missing is simply **dropped**, so
> nothing flagged it: the UI did display a "rate-limit (-rl req/s)" field for katana, and
> katana — an **HTTP crawler** — ran at full speed under `rate_explicit`. The list is
> now **derived from the registry**; a tool added to the catalog with a rate group is
> covered automatically (guard: `tests/test_run_rate_cap.py::TestEveryToolThatDeclaresARateGetsOne`).

Arm it when the engagement requires it: a programme that forbids sustained traffic, a fragile target, or
an "*avoid service degradation*" clause.

> This lever **has always existed and worked**; it was documented **nowhere** (0
> occurrences in the docs and the scope example as of 2026-08-11), which made it look dead during
> an audit. A lever that cannot be found is as good as an absent lever — hence this section.

---

## 2ter. `run_rate` — the **RUN** rate ceiling (the second stage)

`rate` bounds the rate of an **ACTION**. It bounded nothing at the level of a **RUN**, and that was not
a detail: the bucket is rebuilt on **every `fire()`** and lives in **thread-local** storage, so the first
shot of each action finds its slot free, and the effective ceiling is **multiplied by the
parallelism**. Measured (`tests/test_run_rate_cap.py`, injected clock, `rate: 5` declared):

| | observed RUN rate |
|---|---|
| serial, 30 actions × 1 request | **UNBOUNDED** (0 s of waiting over the whole run) |
| serial, 12 actions × 3 requests | 7.29 req/s |
| serial, 24 actions × 2 requests | 9.79 req/s |
| **parallel pool=4**, 24 × 2 | **33.5 req/s** (median of 5) |
| **parallel pool=8**, 24 × 2 | **59.0 req/s** |

`rate: 5` therefore delivered up to **11.8× the announced rate**. The cost is established: a target (Juice
Shop) left **34 min without being targeted** stays stable (102 → 21 MiB); campaign launched at 13:12:42 →
**3.78 GiB at 13:13:24** → `Exited(139)` at 13:14:47. Bringing a target to its knees violates
"*avoid service degradation*", a clause of nearly all programmes — grounds for exclusion.

**The run ceiling is a SECOND stage, not a replacement.** The two are **chained**: a
request waits for the RUN slot, **then** for that of its ACTION. The resulting rate is that of the
tighter of the two; neither cancels the other (a tight `rate` keeps its bursts smoothed even under a
wide `run_rate`, and vice versa).

| `scope.json` key | Effect |
|---|---|
| `"run_rate": N` | Ceiling of **N req/s for the whole run**, shared by all actions **and all workers**. **TAKES PRECEDENCE** over the next row — including `0`, which **disarms**. |
| `"rate_explicit": true` | Failing `run_rate`, arms the ceiling at the value of `rate`. This is the only automatic arming, and it is consistent: this lever already says "throttle everything, tools included, this engagement requires it". |
| *(nothing)* | **NO run ceiling** — the default, byte-identical to before. |

**Why the default is "no ceiling"**: arming a ceiling automatically would collapse the coverage
of every existing run that asked for nothing (cf. §2bis — `rate: 5` imposed on the tools takes naabu
from 1.1 min to 3.6 h). A brake is an **operator decision**; no decision, no brake — the
same rule as `--run-timeout`.

> **NAMED BREAKING CHANGE — the CONSOLE path.** `console/src/runs_proc.rs` sets
> `"rate_explicit": spec.rate.is_some()`: filling in the *Rate-limit* field of the **Launch** view
> therefore now **also** arms the run ceiling. It is a change of behaviour, and it is
> intended — it is what the UI already promised ("sets the rate (req/s)", cf. `docs/QUICKSTART.md`)
> and did not deliver: until now a `rate: 5` set in Launch delivered up to **59 req/s**.
> The run is slower because it finally respects the requested rate. For the old behaviour without
> giving up the tool flags: `"run_rate": 0` in the scope.

**A throttled run SAYS SO.** Before the first shot: a `[DÉBIT RUN]` progress line naming the
value **and the setting it came from**, plus an `engine.run_rate` ledger entry. At the end: the
**observed** rate and the imposed seconds of waiting, also exposed in `Engine.coverage()['run_rate']`.
An invisible brake is worse than an absent brake: the operator would conclude that forge is slow.

**Honest scope**: the ceiling bounds what goes through the oracles' HTTP chokepoint
(`Oracle._http`) — the **43 native modules** derived from `Oracle` (MEASURED on 2026-11-24, out of 69
native kinds: `python3 -c "import forge.modules; from forge.modules.registry import REGISTRY; from forge.modules.oracle import Oracle; print(sum(issubclass(c, Oracle) for c in REGISTRY.values()))"`). A **subprocess** (nuclei, feroxbuster, naabu…) does not
go through it; its rate is throttled by **its own flag**, that is, by `rate_explicit` (§2bis).
To *really throttle everything*: `"rate_explicit": true` — which arms both at once.

---

## 2quater. Third-party egress of a module — `allow_tool_egress`

Forge already gates the LLM assist (`scope.llm.allow_external`) and the embeddings memory backend behind an
**explicit** egress. It did not gate its **tools**, and measurement made the inconsistency untenable:
`recon.httpx`, considered *loopback-safe*, downloaded **92.6 MiB from huggingface.co on each of
its 4 shots** (~370 MiB) through its `-tech-detect` flag — **the only proven egress over 4 906 findings**,
in a bench announced as "strict loopback". It had not escaped any prohibition: it had escaped
**scrutiny**, because the exclusion was based on the **declared intent**, never on the **observed**
egress.

The principle: **a module that goes out to a third party DECLARES it, and the operator can REFUSE it.**

| Value of `allow_tool_egress` | Effect |
|---|---|
| *(absent)* / `false` | **Refusal** of any declared egress (default, fail-closed) |
| `true` | Allows the **declared** hosts (never the others: the declaration remains the contract) |
| `["*.huggingface.co", …]` | **Allowlist** by pattern (`fnmatch`); empty list ⇒ refusal |

On the module side (duck-typed, no existing module has to change): `egress = ("hôte", …)` and, if the
module **cannot** do without it, `egress_required = True`.

* module that can **degrade** (the case of `recon.httpx`) → it still fires, and receives
  `action.params['_egress_allowed'] = False`: it is up to it to remove the feature that goes out.
  Coverage-safe: we **bound**, we do not delete;
* module that **cannot** do without it → **named VETO** by the ROE (layer 3bis), which cites the host
  and the key that lifts the refusal. No verdict is issued for the action.

The finding is stated **once per module** (`[EGRESS TIERS]` progress line + `engine.tool_egress`
ledger entry + `coverage()['tool_egress']`) — **including when the egress is allowed**: an
egress allowed without being seen will happen again identically.

---

## 2quinquies. AUTHENTICATED discovery — what forge does NOT do, and why

**To say right away: deep discovery under authentication is NOT automatic.** Forge's native
oracles carry the governed session (`scope.session`) on every request; the **external
crawlers** do not. They therefore explore the target **unauthenticated**.

### The cost, measured

Bench of 2026-08-16, DVWA (an application whose ENTIRE vulnerable content is behind a login):

| | measured |
|---|---|
| distinct targets reached in an autonomous campaign | 27 |
| `/vulnerabilities/*` targets (the vulnerable pages) | **0** |
| reportable classes found, autonomous track | **0 / 9** |
| … the same classes, seeded by hand with the session | **5 / 9** |

Forge's judgement is not at fault: the oracles find 5 classes out of 9 as soon as they are given
the targets. What is missing is upstream — **the crawler only sees a login page**.

### Why it is not simply "wired"

Giving the session to an external tool requires a channel. There are only two, and **neither is safe
via docker**:

| channel | what the tools support | what it costs |
|---|---|---|
| **argv** (`-b/--cookies`, `-H`) | feroxbuster ✅, katana ✅ | the secret becomes **world-readable** via `ps`, and ends up in the ledger and the PoCs |
| **file** (`-H <file>`, `-config`) | katana ✅, feroxbuster via `ferox-config.toml` | requires a **mount** into the container — refused by design |

And the refusal of the mount is not a missing convenience: it is argued in
`forge/runner.py` §1, and its argument **covers exactly this case**. Every docker invocation already carries
`--network host`; a mount, even `:ro`, bounds **writes**, not **reads** — and
"a read in a container that has the host's network is one `curl` away from exfiltration".

**The file channel would therefore be LESS safe than argv, not more**: argv exposes the secret to whoever reads
`ps` on the machine; the mounted file exposes it to the third-party image itself, which has the network. It is
counter-intuitive, and it is the reason why forge does neither by default.

### What the operator can do, today

1. **Seed the authenticated targets** (`forge run --actions`) — the path measured at 5/9 on DVWA.
   The operator knows their URLs; they do not need a crawler to guess them.
2. **Run the crawler as a LOCAL BINARY** rather than in a container. Outside docker, the file
   channel becomes viable again: a headers file at `0600` is readable only by its owner
   and does not appear in `ps`. It is **strictly safer than argv** — but only outside a
   container.
3. **Accept the argv exposure knowingly**, by passing the cookie yourself through
   the tool's `params.extra_args`. Forge does not do it for you: *a tool that redacts its
   secrets everywhere else must not publish one in a command line without you having
   decided so.*

---

## 3. What is configurable where?

| Setting | At deployment (env) | In the UI (settings) |
|---|:---:|:---:|
| Bind, state paths, session TTL | ✅ | — |
| Bootstrap secrets (token, viewer/operator hash) | ✅ | (accounts created through UI/CLI afterwards) |
| Admin & individual accounts | (bootstrap) | ✅ (wizard + Administration → « Comptes » (*Accounts*)) |
| Detection source (purple) | ✅ (legacy `PLUME_*`/`FORGE_DETECTION_SOURCE`) | ✅ **recommended** (`detection_source`) |
| Operator policy (source CIDR) | — | ✅ (`operator_policy`) |
| Backup policy (schedule/offsite) | (2 knobs: tick, passphrase env) | ✅ (`backup_policy`) |
| Connector governance | — | ✅ (`module`) |
| Encryption at rest | ✅ (`encryption` image + `FORGE_DB_KEY`) | (reflected: `capabilities.sqlcipher`) |
| Trusted proxy (XFF) | — | ✅ (`trusted_proxy`) |

**Headless provisioning** (without a browser) is possible: set `FORGE_CONSOLE_PASS_HASH` /
`FORGE_CONSOLE_OPERATOR_HASH` / `FORGE_CONSOLE_TOKEN` — the setup state then switches to `provisioned:true`
without the wizard. See [First deployment](FIRST_DEPLOYMENT.md).

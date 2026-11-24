# Administration

[English](ADMINISTRATION.md) | [Français](ADMINISTRATION.fr.md)

> [Contents](README.md) · Prerequisites: [First deployment](FIRST_DEPLOYMENT.md) · References:
> [Configuration](CONFIGURATION.md) · [HTTP API](HTTP_API.md) · [Security model](SECURITY_MODEL.md)

All administration is done in the **Administration** tab of the SPA or through the API — **admin session
required** (no fallback through a shared secret: administration mutations are **attributable to a
named individual account** and **ledgered**).

- [1. Accounts & roles](#1-accounts--roles)
- [2. Detection source](#2-detection-source)
- [3. Connector governance (install/uninstall)](#3-connector-governance-installuninstall)
- [4. Operator policy & source-CIDR](#4-operator-policy--source-cidr)
- [5. Backup & restore](#5-backup--restore)
- [6. Data migration](#6-data-migration)

---

## 1. Accounts & roles

Three roles (application constraint; the `users` table stores a TEXT):

| Role | Can | Cannot |
|---|---|---|
| **viewer** | Read: findings, ATT&CK coverage, purple, runs, ledger, GXQL, dashboards. | Launch a run, administer. |
| **operator** | Everything a viewer can **+** launch/cancel a C2-light run (`/api/run*`), refresh the modules. | Administer (accounts/settings/governance). |
| **admin** | Everything **+** administration: accounts, settings, detection source, connector governance, backup/restore, setup. | — (superset). |

### Managing accounts

- **UI**: Administration → « Comptes » (*Accounts*) — create, change the role/password, disable.
- **API** (admin): `GET /api/users` (never `pass_hash`), `POST /api/users` (`{login, role,
  password}`), `POST /api/users/:login` (update), `DELETE /api/users/:login`.
- **CLI**: `forge useradd <login> <role>` (password on STDIN). Idempotent per login.

Guards:
- The **last enabled admin** is protected (impossible to lock yourself out).
- A changed/disabled role takes effect **immediately**, even on a session already issued (the account
  is re-read on every lookup).
- Every mutation is **ledgered** (attribution = the acting admin); `GET` never returns the hash.

### How to log in

- **Individual session**: `POST /api/login {login, password}` → `forge_session` cookie
  (HttpOnly, SameSite=Strict) + token. TTL = `FORGE_CONSOLE_SESSION_TTL` (default 3600 s).
- **Headless bootstrap** (backward compatibility): viewer Basic (`FORGE_CONSOLE_PASS_HASH`); operator through
  the `X-Forge-Operator` header (`FORGE_CONSOLE_OPERATOR_HASH`). **Administration does NOT accept** this
  fallback — it requires a named admin session.

---

## 2. Detection source

The purple loop joins the **fired** techniques (red) to the **detected** techniques (blue). The detection
**source** is a **configurable plugin** — Plume is only a preset. Full
configuration, presets per infrastructure (FortiGate/pfSense/OPNsense/CrowdSec/Elastic/OpenSearch/file/exec)
and MITRE mapping: **[`DETECTION.md`](DETECTION.md)**.

In short (Administration → « Source de détection » (*Detection source*), or step 3 of the wizard):

| Action | Route (admin) | Note |
|---|---|---|
| View the config | `GET /api/detection/source` | **secret REMOVED** (`secret_set` only). |
| Save | `POST /api/detection/source` | Persists `settings.detection_source` (secret **write-only**), reloads hot. Ledger `console.detection.source.set`. |
| Test the connection | `POST /api/detection/test` | Single collection: `{reachable, count, sample_mitres, error?}` — **never** the secret. `keep_secret:true` to test without re-entering it. |

Offline diagnostics: `forge doctor --purple` (read-only preflight) and `forge detections
--source <spec> --since N`. See [CLI](CLI.md).

**Readable fail-open**: absent/unreachable source ⇒ `source_reachable:false`, the measurement is declared
impossible — never made up. Prerequisites of the Plume preset: [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).

---

## 3. Connector governance (install/uninstall)

A connector can be **enabled/disabled** by the admin — it is the equivalent of a governed
"install/uninstall". **Disabling a connector REALLY prevents it from firing**: it
is SKIPPED at spawn **even if its binary/service is present**, including when it is the planner (and
not `--modules`) that chose it.

- **UI**: Administration → « Connecteurs » (*Connectors*) (enabled state, availability, web_allowed).
- **API** (admin): `POST /api/modules/:kind` with a strictly typed body:

| Field | Type | Effect |
|---|---|---|
| `enabled` | bool | `false` ⇒ the module is SKIPPED at firing (like a missing tool). |
| `web_allowed` | bool | Allows/forbids launching the module from the web (C2-light). |
| `available_override` | bool \| null | Forces (true/false) or clears (null) the displayed availability state. |

Every change is **ledgered** (actor + effective state). The catalog (`GET /api/modules`) is
the source of truth for the kinds; `POST /api/modules/refresh` (operator) repopulates it from
`forge.cli modules`. Full catalog: [MODULES.md](MODULES.md).

> The connector must exist in the catalog (otherwise **404**). This covers operator connectors
> (msf/burp) as well as any recon/oracle module.

---

## 4. Operator policy & source-CIDR

The **operator** role (C2-light) is **fail-closed**: not provisioned = `/api/run*` returns **403**.
The `settings.operator_policy` policy governs it:

| Field | Meaning | Default |
|---|---|---|
| `source_cidrs` | Allowlist of client IPs allowed to launch a run. | *(absent/empty = no restriction)* |

When `source_cidrs` is configured, the effective client IP **MUST** fall within one of the CIDRs, otherwise
the operator action is refused. Active policy but undetermined IP ⇒ refusal (fail-closed). The
constraint applies **only to the operator C2** — never admin/viewer.

**Behind a proxy**: configure `settings.trusted_proxy` (CIDR of the upstream proxy/proxies). An
`X-Forwarded-For` is honoured only if the TCP peer falls within a trusted CIDR; otherwise **fail-closed**
fallback to the TCP peer. A non-CIDR value ⇒ XFF ignored (the console warns at boot). See
[Security model](SECURITY_MODEL.md).

The C2 **exploit floor**: `exploit`/`destructive` modules are refused (400) except for a **governed
high-impact opt-in** — honoured **only** if `operator + arm=true + reason non vide`. See
[Architecture §3.3](ARCHITECTURE.md#33-the-governed-c2-light-run-flow).

---

## 5. Backup & restore

The archive is **ALWAYS encrypted** (argon2id + XChaCha20-Poly1305) and embeds **the signing
key AND the database** — there is no plaintext path. Full runbook, format, offsite:
**[`BACKUP.md`](BACKUP.md)**.

In short (Administration → « Sauvegarde & restauration » (*Backup & restore*), admin, ledgered):

| Action | Route / CLI |
|---|---|
| Create a backup (download) | `POST /api/backup {passphrase}` · or `forge backup --out … --passphrase-env …` |
| Restore (validates by default; swap = `apply:true`+`confirm:true`, **restart required**) | `POST /api/restore {archive_b64, passphrase, apply?, confirm?}` · or `forge restore --in … --force` |
| Scheduled/offsite policy (redacted on GET) | `GET`/`POST /api/backup/policy` |

In-console scheduler **fail-open** (a failure is logged + ledgered, never crashes). Two environment
knobs: `FORGE_BACKUP_TICK_SECS` (default 60 s), `FORGE_BACKUP_PASSPHRASE` (the ENV **name**
is referenced by `backup_policy.passphrase_env`; the passphrase is never in the DB). Offsite ∈
`{none, local_dir, exec}` (fixed argv, no shell).

---

## 5bis. Outbound notification channel (webhook)

**In-app** notifications (assignment / triage) never leave the process. This channel mirrors
them to an HTTP endpoint. It is **egress from an offensive tool** — a finding carries
evidence — so it is governed exactly like the engine's LLM egress.

Administration → « canal de notification » (*notification channel*) (admin, ledgered) · `GET`/`POST /api/notify/channel`,
`POST /api/notify/channel/test`.

| Guarantee | Implementation | On deviation |
|---|---|---|
| **OFF by default** | no `settings.notify_channel` key ⇒ inert channel | not a single byte goes out; a deployment that touches nothing is unchanged |
| **Body redaction** | `redact::redact_secrets` (**the reports' redactor**, not a 2nd copy) **then** neutralisation of absolute URLs | a JWT / a cloud key / a target URL cannot go out |
| **Anti-SSRF** | **shared** integration deny-list on the **resolved** IP (anti-rebinding) | loopback / RFC1918 / link-local / metadata / ULA refused, unless `FORGE_ALLOW_INTERNAL_INTEGRATIONS=1` |
| **Write-only token** | never served back by `GET` (`secret_set` only), never logged, never ledgered | `keep_secret:true` to edit the endpoint without retyping it |
| **Verified `https://` transport** | single TLS seam (`console/src/tls.rs`) — chain (Mozilla roots **+ enterprise anchors** `FORGE_EXTRA_CA_PEM`), host name **and** validity verified, handshake completed **before** the first byte | Slack / Teams / PagerDuty are reachable; **no** option accepts an untrusted certificate |
| **No credential in plaintext on a public network** | rule **SHARED** (`net::reject_cleartext_secret`) with the detection source fetcher: a token + a **public** target over `http://` = **refusal**, which **no** variable opens; over `https://` = allowed (the token is protected); over `http://` to an allowed **internal** collector = unchanged | switch to `https://` (a private CA is supplied through `FORGE_EXTRA_CA_PEM`), target an internal collector (`FORGE_ALLOW_INTERNAL_INTEGRATIONS=1`), or remove the token |
| **Token encrypted AT REST** | sealed in `settings.notify_channel` by field encryption (`FORGE_FIELD_KEY`, default build); opened at the **single point of use** (`deliver_blocking`) | without a key, the write is refused (**503** `field_key_missing`) and the send **refuses to go out** rather than presenting itself **without authentication** |
| **Logging of the SEND, not of the content** | ledger `console.notify.dispatch`: channel, **redacted recipient** (`scheme://authority` — the path of a Slack/Teams webhook **is** a credential), event, outcome | the message text appears nowhere |
| **Best-effort** | detached and bounded task | a send failure affects neither the in-app notification nor the mutation that triggered it |

**Why there is still no SMTP** — and the TLS seam changes nothing about it. STARTTLS is a **negotiated**
upgrade: the session starts in plaintext and lifts itself on a command exchanged in plaintext, which is a
class of **plaintext command injection** (CVE-2011-0411 and its descendants). And real-world SMTP is practised
with **opportunistic** TLS against relays with self-signed certificates: serving it honestly would require either
accepting untrusted certificates — the verification escape hatch that this foundation refuses on principle —
or imposing on mail relays a PKI they do not have. Starting a TLS client with the protocol with the worst
upgrade semantics would be the wrong order. The remaining case — an on-prem relay without authentication —
is already covered, better, by a webhook to an internal collector; a real SMTP need is delegated to the
Python engine (`smtplib` + `ssl`), which is another layer.

---

## 5ter. Triage SLA

A **scheduler**, not a channel: a periodic sweep flags the findings whose **triage
cycle** has stayed open beyond the budget of their severity. It **opens no output** — what it
finds goes up through the **notifications gate**, and therefore inherits the channel above and **its**
redactions. Same discipline as the backup scheduler (declarative policy, fail-open, ledger).

Administration → « SLA de triage » (*Triage SLA*) (admin, ledgered) · `GET`/`POST /api/notify/sla`.

**What "overdue" means** — derived from **only the fields the model already carries**, no
new column: a finding whose `triage` ∈ {`new`, `triaging`, `reopened`} (the cycle is still waiting for
a decision) and whose age since `finding.ts` exceeds the budget configured for **its severity**.
`confirmed` is not overdue: the decision has been made, what remains is remediation — another
clock, which would require a fix owner that this model does not have.

| Guarantee | Implementation | On deviation |
|---|---|---|
| **OFF by default** | no `settings.sla_policy` key ⇒ sweep is a **total no-op**; `enabled` without a positive budget stays **inert** | no notification, no ledger line |
| **No new egress** | escalation through `notifications::emit` ⇒ same redactions (secrets **then** target URLs) as the channel | the SLA has no socket, no URL, no secret of its own |
| **Leader-only under HA** | `ha::is_leader` read on every tick | N replicas would send N identical notifications |
| **One notification per finding** | dedup **in the query** (`NOT EXISTS … kind='finding.sla'`) | no reminder every 15 min; the sweep ceiling is not consumed by already-handled rows |
| **The ceiling does not make the SLA inert** | it applies to the **rows read** (500): the query reads only what *can* be overdue — open triage, **budgeted severity**, never flagged | without the severity filter, 500 `LOW` without budget would hide **forever** the `CRITICAL` with a higher `id` |
| **A truncation says so** | report and ledger carry `scanned` + `capped`; a truncated sweep is ledgered **even without a notification** | "nothing overdue" and "I did not look" must never look alike |
| **Grant-scoped** | inherited from emission: a recipient without a grant on the engagement receives nothing | multi-tenant isolation is not bypassed by a background task |
| **Unassigned ⇒ never broadcast** | escalation to **one** named login (`escalate_to`) or nobody | an SLA that writes to everyone is an SLA that gets disabled |
| **Never breaks anything** | `spawn_blocking` + fail-open; every error captured in the report and ledgered `console.notify.sla.error` | a sweep can neither block nor make a run fail |
| **Ledger without content** | `console.notify.sla.sweep`: counters only | neither finding title, nor target |

The clock starts from the **creation date** because it is the only date the row carries: there is no
`triage_updated`, and inventing one for an SLA would amount to making the schema carry a peripheral
function. Accepted consequence: **no re-arming** after reopening (one notification per
finding, for life) — the trade-off favours the absence of spam.

The `GET` also carries `overdue_now`: a **read-only preview** (it notifies nobody) of the number of
findings currently overdue according to the **saved** policy — enough to calibrate budgets without
arming the policy and watching who gets spammed. It is counted over the **same window** as the
sweep (`max_sweep_rows`) and therefore carries the same `capped`: a truncated preview says so.

**Accepted limit of the ceiling** — the severity filter removes the structural case (a severity without
a budget cannot be overdue, so it is not read). A residue remains: 500 findings of a severity
**budgeted but still on time**, with a lower `id`, fill the window of a tick. The overdue finding with
a higher `id` is seen at the next sweep as soon as those rows leave open triage — and, in
the meantime, `capped: true` flags it instead of suggesting a healthy database.

---

## 6. Data migration

Take over an existing install (systemd/bare-metal) into Docker/another target **without losing the audit**.
Three **coupled** artefacts travel together: the SQLite database, the `engagement.jsonl` ledger, **and its
`.ed25519` signing key** (otherwise the signed chain becomes unverifiable). Full runbook +
guards + encryption-at-rest option: **[`MIGRATION.md`](MIGRATION.md)**.

```sh
# Primary UX: one-shot container (source opened READ-ONLY, never mutated)
docker run --rm \
  -v /ancien/forge:/import:ro -v forge-db:/data/db -v forge-ledger:/data/ledger \
  forge:0.0.1 \
  forge migrate --from /import --to /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl --verify
```

The API path (`POST /api/setup/migrate`) is **pre-provisioning only** and **disabled by default**
(`FORGE_ALLOW_API_MIGRATE` + `FORGE_CONSOLE_IMPORT_DIR`) — the CLI remains the documented UX.

Post-migration: `GET /api/ledger/verify` (chain intact on the console side) **and** `forge ledger verify`
(signatures OK ⇒ the `.ed25519` key has travelled, at `0600`).

## 7. Test accounts of an engagement — when the session dies

The `auth` block of an engagement carries the **test accounts** (`attacker` / `victim`) that **arm**
the access-control oracles (IDOR, ATO, privesc). Without valid material, these oracles find
nothing — and until now they did not say so: the run returned a **clean, empty report**,
indistinguishable from a healthy target.

**Where to see it, from earliest to latest:**

| When | Where | What appears |
|---|---|---|
| **Before** launching | engagement editor (`GET /api/engagements`) | `auth.accounts[].expires_at` (epoch) and `expired` (boolean) |
| **At launch** | response of `POST /api/run` | `warnings[] = {code: "auth_context_expired", accounts: […]}` |
| **At launch** | ledger `console.run.start` | `auth_expired` field: **labels** of the expired accounts |
| **During** the run | live log (SSE) | line `[AUTH] matériel d'authentification EXPIRÉ pour […]` |
| **During** the run | ledger `engine.auth_expired` | labels + count of `expired` / `valid` / `unknown` |
| **In the report** | findings | one **`status='skipped'`** finding per target, titled "… non testé — matériel d'authentification …" (not tested — authentication material) |

**A run is NOT blocked** by expired accounts: a campaign also does recon, headers,
SSRF — refusing the launch would be overreach. The run starts, and **names** what it cannot
test.

**Reading the states.** `expires_at: null` = **unknown** (opaque cookie without a readable expiry, or database not
yet re-sealed) — this is **not** validity: the engine will retest at firing. Only an account whose
expiry is **read and passed** is flagged; nobody is ever accused without evidence.

**Remedy (no needless re-entry).** Re-edit the engagement and **re-paste the material of the dead
account only**: the other accounts are carried over automatically by label (`keep_existing`), their
secrets never having been served back on read. There is **no** automatic renewal —
neither stored password nor `refresh_token`: see [Security model §5.2](SECURITY_MODEL.md) for the
full reasoning.

> **Operating note** — a `skipped` finding has severity `INFO`; native triage may
> mark it "BRUIT probable" (probable NOISE). It is **never hidden** (no filter deletes a finding), but
> it is the **run-level** signal (ledger + live log + `warnings`) that must serve as the alert.

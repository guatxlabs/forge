# Security model

[English](SECURITY_MODEL.md) | [Français](SECURITY_MODEL.fr.md)

> [Contents](README.md) · See also: [Architecture](ARCHITECTURE.md) · [Concepts](CONCEPTS.md) ·
> [Configuration](CONFIGURATION.md) · [HTTP API](HTTP_API.md)

Forge's security model rests on one principle: **fail-closed by construction**. Missing
configuration, an evaluation error or a missing secret produce a **refusal**, never a default
capability. This page consolidates all the guarantees.

## 1. Trust boundary

- **The modelled attacker** is the world outside the authorised scope. Forge is the tool of the **authorised
  red team**: its charter is *in-scope bug bounty, contracted pentest, CTF, own infrastructure*.
- **Getting past a WAF/Cloudflare is NOT a vulnerability**: it is an access enabler. The ROE gate + the
  scope-guard + the ledger exist to **enforce AND prove** authorisation, not to bypass it.
- The console binds to **loopback** by default; public exposure requires a reverse proxy + auth +
  host allowlist (§4).

## 2. Authorisation (AuthZ) — RBAC & gates

### 2.1 The two middleware guards

All routes except `/health`, `/api/login`, `/api/setup*` go through:

1. **`host_guard`** (anti-DNS-rebinding) — the `Host` (port stripped) must be **non-empty** and in
   the allowlist (`localhost`/`127.0.0.1`/`::1` + `FORGE_CONSOLE_HOST`). Otherwise **421**. Fail-closed on
   a missing `Host`.
2. **`auth_guard`** — the gate engages on `auth_required` = *an env hash set OR an enabled account in
   the database*. Engaged without evidence ⇒ **401**. This **closes the historical dev-open hole**: a fresh
   install with accounts in the database but no env hash is now gated.

### 2.2 The roles and their evidence

| Role | Evidence | Env-hash fallback? |
|---|---|---|
| **viewer** | session (cookie/Bearer) · or Basic (`FORGE_CONSOLE_PASS_HASH`) · or Bearer = ingestion token | yes (Basic) |
| **operator** | operator\|admin session · or `X-Forge-Operator` header (`FORGE_CONSOLE_OPERATOR_HASH`) **+ source-CIDR** | yes (bootstrap) |
| **admin** | **admin session only** | **NO** (strict individual attribution) |
| **token** (machine) | Bearer = ingestion token (`FORGE_CONSOLE_TOKEN`), compared in constant time | — |

Key points:
- **`check_admin` has no env-hash fallback**: an administration mutation MUST be attributable to a
  named individual account, never to a shared "bootstrap" secret.
- A session carries the role **re-read at lookup time**: a changed/disabled role takes effect
  **immediately**, even on an already issued session. Disabled account ⇒ fail-closed.
- **`check_operator`** requires operator|admin AuthN **AND** the source-CIDR constraint (opt-in). A
  viewer with a session never gets through the C2.

### 2.3 The exploit floor (C2-light)

`POST /api/run` refuses `exploit`/`destructive` modules (**400**) **unless** there is a **governed**
high-impact opt-in — honoured only if `operator + arm=true + reason non vide` (non-empty reason) (`high_impact_gate`).
Otherwise the scope written for the run **forces** `allow_exploit=false`. Targets must be ⊆ the server
scope (**400 out_of_scope** before any spawn). **FIFO per engagement**: at most one live run *per
engagement* (**409** on the same engagement; other engagements run in parallel). Each run
applies the scope-guard and writes the ledger **of ITS engagement** — never those of another (fail-closed
isolation by construction).

## 3. The ROE gate (engine)

Four fail-closed layers (`forge/roe.py`): *armed → in-scope → capability → approved*. Out of scope or
unauthorised capability ⇒ **VETO** (never simulated, never fired). Any exception ⇒ VETO. Detail:
[Concepts §1](CONCEPTS.md#1-roe--scope-guard). Membership canonicalises the host and handles globs **and**
CIDR/IPs — an `out_scope` IP cannot be bypassed through a URL or a `host:port`.

## 4. Ledger integrity

- **SHA-256 hash-chain + per-entry signature** (Ed25519 by default, HMAC as a fallback). Altering one byte
  breaks `verify()`.
- **Non-repudiation**: `verify_external(pubkey)` — a third party verifies integrity + scope with the
  **public key alone**, without being able to forge.
- **Anti-downgrade / anti-relabel**: structural alg↔kind binding. `sha256-console` (unsigned
  chain) is legitimate **only** on a `console.*` `kind`; signed algorithms are forbidden on a
  console kind. This closes the rewriting of an engine entry as unsigned **and** the relabelling of a
  signed entry as console. `verify` refuses these cases **before** any signature check.
- **Custody**: the `.ed25519` private key (`0600`) is **local** today. Off-host anchoring
  (`forge/anchor.py`: co-signing witness + `reconcile`, which detects a locally re-signed
  rewrite) is the last step; the asymmetric architecture already allows it (only the public
  key circulates). Documented, not hidden.

## 5. Encryption at rest

- **In transit / default storage**: the SQLite database is **in plaintext** (default build). The
  ledger is **tamper-evident through its chain**, not confidential.
- **SQLCipher opt-in**: `--features encryption` build + `FORGE_DB_KEY` → the console issues `PRAGMA
  key` **before any query**. Without the correct key, the database is **unreadable** (fail-closed) — the
  console does not start on usable data. See [Installation §6](INSTALLATION.md#6-encryption-image-encryption-at-rest--sqlcipher-opt-in)
  and [`MIGRATION.md`](MIGRATION.md) Runbook B.
- **Backups**: **always encrypted** (argon2id + XChaCha20-Poly1305), the archive embeds the signing
  key AND the database. AEAD authenticates body **and** header; a missing/wrong passphrase ⇒
  refusal, nothing written. See [`BACKUP.md`](BACKUP.md).
- **Duration store** (`<ledger>.durations`, ledger sidecar): aggregate **per module kind**
  (`web.testssl` → n observations + ring of durations), **never per target**. A per-target aggregation
  would have been a **reconnaissance log persisting after the engagement** (which hosts existed,
  which were slow, which were filtering); that is why it does not exist. The guard is
  **structural**, not declarative: `DurationStore.record()` refuses any key that is not a
  module identifier (a literal IP, a `host:port`, a URL or a path are rejected), on
  write **as on re-read** of a tampered file. Scope **per engagement** (it follows the
  dedicated ledger) and can be disabled (`FORGE_DURATIONS=0`). It drives **only** the submission order of the
  preheat — no firing decision depends on it.

### 5.1 Expiry of authentication material — "nothing found" is not "not tested"

The `auth` block of an engagement (test accounts `attacker`/`victim`) **arms** the access-control
oracles: `access_control.idor`, `auth.takeover`, `access_control.privesc`. When the session it
carries no longer authenticates, these oracles **do not crash** — all their evidence conjunctions
collapse to `False`, and the run returns a **clean, empty report** that looks like "the target is
healthy". It is a **silent** false negative, and it costs an entire campaign.

**What happens now.** A disarmed oracle returns `status='skipped'` ("I could not test"),
never `tested` ("tested, nothing found"). Two signals, **neither emits an extra request**:

| Signal | Detection | Effect |
|---|---|---|
| **Readable expiry** | the token carries an elapsed `exp` claim (`session.jwt_expiry`) | `skipped` finding **before** any network — no request emitted |
| **Inert material** | the target answers the authenticated account **exactly** as it answers the anonymous probe (same **barrier** status 401/403/3xx, same body) | `skipped` finding, verdict refused |

Three surfaces say it, from earliest to latest: the **engagement editor** (`expires_at` /
`expired` per account), the **launch** (`warnings` in the response + `console.run.start.auth_expired`
in the ledger), then the **run** (`engine.auth_expired` + live `[AUTH]` progress line, and one
`skipped` finding per target).

**What these signals do not prove** (named, not glossed over):
- *Barrier only* — identical 404/5xx on both sides speak about the **object** or the **server**, not
  the session; a 2xx says the account **obtained** access. Neither triggers.
- *Anti-false-positive guard* — if an account from the same probe set **gets in** (2xx) on the same URL, the
  target demonstrably discriminates and no inertness verdict is returned (otherwise a correctly
  blocked privesc would become "not tested").
- *Accepted residual ambiguity* — "identical 403 for the authenticated and the anonymous" can also be
  a **hardened target that does not discriminate its refusals**. The two readings are indistinguishable from
  the response: that is precisely why the honest verdict is "I could not test".
- *Out of reach* — a **single** dead account among several, whose material is **not** a JWT
  (opaque cookie), remains undetectable at firing time; so does a login page rendered as **200** for everyone
  (indistinguishable from a public resource). An unknown `exp` is **never** presented as
  validity.

**`exp` stamp at rest.** Once sealed, the material is unreadable by the console — so neither
the editor nor the launcher can see that a token is dead. The expiry is therefore read **at
sealing time** (the last moment the plaintext is visible) and stored next to the `label`. It is a
**timestamp, not a credential**: it replays nothing, signs nothing, authenticates nowhere —
the invariant "no new **material** field persisted in plaintext" holds. No signature
check is made: we **read** a self-declared date, we do not validate a token.

### 5.2 Automatic session renewal — REFUSED, and why

"Rotating expired sessions without re-entry" **is not implemented, deliberately**. Both
possible paths degrade the posture that was just hardened:

1. **Replaying a login** would require persisting a **password** — a short, revocable secret
   would be traded for a **permanent** secret that opens far more than the session it replaces.
   Refused, unconditionally.
2. **Refreshing via a `refresh_token`** supplied by the operator avoids the password, but:
   - the `refresh_token` is **longer-lived** than the access token it regenerates — the strongest
     credential would be stored to preserve the weakest;
   - **rotating** `refresh_token`s are single-use: a persistence failure after
     consumption **destroys** the operator's test account. The tool would break what it protects;
   - the token endpoint (IdP) is **almost always outside the scope** of the engagement. Refreshing
     it would force emitting authenticated traffic **outside the scope-guard** — exactly
     the fail-closed invariant that nothing must relax.

**What remains available without re-entry**: when editing an engagement, material that is **not re-entered is
carried over per account** (`keep_existing`, cf. anti-silent-erasure) — only the account that is actually dead
must be pasted again. Renewal may be reconsidered if, and only if, the token endpoint
enters the declared scope and rotation is handled transactionally.

## 6. Secrets management

- **Never returned** by a GET, **never logged**, **never written to the ledger**. Treated as
  session secrets, **redacted in depth**:
  - Detection source auth secret: **write-only** (GET returns `secret_set` only).
  - Backup passphrases: transient (request body), discarded after derivation.
  - **Governed session** material (`forge/session.py`): attached **only** to in-scope
    requests, never in a finding / the ledger / the graph / `action.params`.
  - Ingestion token: the log prints only a **sha8 fingerprint**, never the token (except an
    auto-generated token, printed once so that it is usable).
- **Never in argv**: the source config (with secret) is passed to the collector **through ENV**
  (`FORGE_DETECTION_SOURCE`); backup/migration passphrases through `--passphrase-env`/`--key-env`
  (never `--flag`) — no leak via `ps`/shell history.
- **Password hashes**: **argon2id** (never in plaintext), random salt, constant-time
  comparison. `forge hashpw`/`hashpw-operator`.
- **CSPRNG**: session tokens (256 bits via `getrandom`, panic if entropy is lacking rather than
  generate a weak token); backup salts/nonces via the OS CSPRNG.

## 7. Surface hardening

- **Strict input validation**: login/campaign `[A-Za-z0-9._-]{1,64}` (no leading `-`);
  hosts rejecting NUL, whitespace, shell metacharacters and leading `-` (anti CLI option injection).
  Targets are written to a **file** then passed by path, never concatenated into a shell.
- **GXQL**: compiled to **read-only SQL** (allowlisted fields, values as bound params, a single
  SELECT, capped LIMIT, `SQLITE_OPEN_READ_ONLY` connection). A field outside the allowlist ⇒ 400.
- **Migration API**: opt-in (`FORGE_ALLOW_API_MIGRATE`, off by default) + allowlisted path
  validation (`FORGE_CONSOLE_IMPORT_DIR`, anti path-traversal) + pre-provisioning only.
- **X-Forwarded-For**: honoured **only** if the TCP peer belongs to a CIDR in
  `settings.trusted_proxy`; otherwise **fail-closed** fallback to the TCP peer (anti source-IP spoofing).
- **systemd**: hardened unit (`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`,
  seccomp `@system-service`). **Docker**: non-root uid 10001, tini PID1, separate volumes
  (db/ledger/scope), supply chain **pinned by SHA256** (the ProjectDiscovery binaries fail the build
  on a mismatch).

### 7.1 Shared dashboards and panels — multi-tenant operator caveat

The **data** rendered by a panel is filtered **per row** according to the engagements granted to
the caller: the filter is injected by the GXQL compiler at each leaf reading scopable
data, it is AND-joined at every depth, it is **fail-closed** (empty grant ⇒ no rows) and
the user's query cannot widen it. A shared panel displayed by a tenant therefore only returns
that tenant's rows.

On the other hand, the **definition** of a panel (its name and the **text** of its GXQL query) is a
**global** console configuration: the `panel`/`dashboard` tables carry no
owner/tenant column, so any authenticated caller holding a grant sees the list of
definitions.

> ⚠️ **Recommendation**: in a multi-tenant deployment, **do not embed a tenant-sensitive identifier
> in plaintext in the GXQL text of a shared panel** (e.g. the code name of a client
> campaign). This is a **metadata** visibility inherent to the "shared dashboards" model,
> not a data leak. Private dashboards per owner/tenant are a possible
> evolution of the model.

## 8. Governance guarantees (summary)

- **Fail-closed**: empty `in_scope` = nothing fires; operator not provisioned = C2 closed (403);
  detection source absent = measurement impossible (never invented).
- **Proof-oriented**: no over-classification as `vulnerable` without concrete evidence
  ([Concepts §3](CONCEPTS.md#3-evidence-backed-oracles)).
- **Opt-in exploit floor**: `exploit`/`destructive` require an explicit opt-in.
- **Everything is traced**: every decision/action in the ledger + anti-masking section of the report (what was
  simulated/refused/never attempted). Zero silent gap.

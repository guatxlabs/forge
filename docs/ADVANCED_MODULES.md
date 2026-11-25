# Forge — Advanced modules (all open, separable, flag-gated)

[English](ADVANCED_MODULES.md) | [Français](ADVANCED_MODULES.fr.md)

Forge is **entirely open source** under **[AGPL-3.0-or-later](../LICENSE)** — the **whole product**, **with no
paid version and no feature held back behind a paywall**. The complete governance and
cryptographic audit engine is open, and every advanced capability below is too.

**Here, open source means the strong copyleft of AGPL-3.0 — not the absence of rules.** If you run a
(modified) Forge as a network service, you must offer its **corresponding source** to the users of that
service (AGPL §13); any **derivative work stays under AGPL-3.0-or-later**; and the **licence text
as well as the copyright/attribution notices must be preserved**. The freedom to read, run,
modify and share comes **with** the obligations that maintain it — see [`LICENSE`](../LICENSE) for
the binding terms.

What this document describes is a **layering inside the open code base**, not a commercial boundary:

> **The governance + cryptographic audit core is always active.** The **scale-out
> / team / compliance** capabilities are shipped as **separable, flag-gated modules** that are **OFF
> by default** — a clean extension point on the core, never a fork of it, and never a gate that
> weakens or hides the open governance/audit surface. Enable them when you need them;
> leave them disabled and the build is byte-identical to the core.

Because everything is AGPL-3.0, anyone can run Forge solo or across many tenants, read every
line of the security and audit machinery, and verify that the ledger, the scope-guard and the oracles do
exactly what they claim. This transparency is the point: one cannot trust a red-team
governance tool that one cannot read. (GuatX's commercial offer consists of **services** around
the tool — reference engagements, purple coaching, support/SLA, managed hosting — never a
licence on the code.)

---

## The core — always active, no flag

Everything you need to run Forge **solo or as a small team**, on your own
infrastructure, at no cost and with nothing disabled:

- **Governance core**
  - Fail-closed **ROE scope-guard** (inert by default; empty in-scope = nothing fires; `VETO` on
    any evaluation error).
  - **Tamper-evident Ed25519 authorisation ledger** (at append time, hash-chained, publicly
    verifiable from the public key alone).
  - **Proof-oriented oracles** — findings are backed by evidence, not asserted.
- **Techniques**
  - The **extensible technique registry** (declare-once → derive-everywhere) and **all the technique
    classes** shipped with the core.
- **Execution**
  - The **governed C2-light run flow** (arm → scope → capability → approve, every action gated and
    ledgered).
  - The **purple loop** (findings + ATT&CK run-records fed to the detection side and correlated).
- **Console & access**
  - The **console UI + first-boot wizard + RBAC** with the three built-in roles: **admin / operator /
    viewer**.
- **Integration & infrastructure**
  - **Connectors / orchestration**: nuclei, Metasploit (msf), Burp, and the other embedded tool
    integrations.
  - **Infrastructure-agnostic detection** (plug in any BLUE source — Plume, CrowdSec, FortiGate,
    pfSense/OPNsense, Elastic, file, exec — without code).
  - **Encrypted backup / restore** (argon2id + XChaCha20-Poly1305, verified by the ledger).
- **Scale**
  - **Single-scope + small-team use** — single-node SQLite store, local operator policy.

If Forge fits on one node and a small team, the core is the whole product. Nothing of the
security or audit story is held back — nor anything of what follows.

---

## The advanced modules — separable, flag-gated, OFF by default

These capabilities are intended for organisations that run Forge **at scale**, across **many
teams / tenants**, or under **formal compliance**. They are **separable modules** built on top of
the core; the core never depends on them, and each one is engaged only by an explicit flag. **In the default
build, every flag is OFF ⇒ the behaviour is byte-identical to the core** (all existing tests green).

- **Multi-tenant / MSSP** — many isolated engagements/clients on a single deployment, with **cryptographic
  isolation per tenant** (separate keys and ledgers per tenant).
  - **Row-level multi-tenancy** *(implemented — `console/src/tenancy.rs`, flag-gated)*: a
    `TENANT ──< ENGAGEMENT ──< findings/runs` hierarchy plus a `tenant_grant(user_id, tenant_id, role)` map. A
    **fail-closed tenant filter** (deny-by-default, modelled on the ROE) is applied on top of the existing
    engagement isolation + RBAC: a user of tenant A can **never** list, read, or act on
    the engagements / findings / runs / roe / ledger / coverage / reports of tenant B — no grant ⇒ zero
    rows / 403. It is engaged only by the **`FORGE_ADVANCED_TENANCY=1`** flag (or the DB config key
    `advanced.tenancy=on`). **DEFAULT build: flag OFF ⇒ a single implicit tenant #1, all
    users access it, behaviour byte-identical** to before tenancy (all existing tests
    green). The module is separable — the core never depends on it.
  - **Audited super-admin (platform/MSSP operator)** *(implemented — `console/src/tenancy.rs`)*: a
    **NON-DISABLEABLE** capability, **designated at provisioning** (env `FORGE_SUPERADMIN` and/or the DB
    provisioning key `advanced.superadmin` — never a normal UI route) that can **READ across ALL
    tenants**. It is fail-closed (no designation ⇒ nobody is super-admin; requires a valid individual
    `admin` session), the account **can be neither disabled / deleted / demoted** through account
    CRUD, and **every cross-tenant read is ledgered `console.superadmin.access`** (tenant + what).
    It grants cross-tenant access **READ-ONLY** — cross-tenant write/run stays bound to the native
    grants (a normal `tenant_admin` can never cross tenants). Mirrors Plume's audited,
    non-disableable super-admin.
  - **Tenant CRUD + grant management** *(implemented — `console/src/tenancy.rs`)*: create / rename /
    archive tenants and list / add / remove a user's `tenant_grant`, gated to a
    **platform-admin** (a console `admin` session or a super-admin) and ledgered **`console.tenant.*`**.
    Fail-closed guards: never archive the **last active tenant**, never remove the **last
    `tenant_admin` grant** of a tenant. In the default build, the surface is closed (`403 advanced_disabled`).
  - **Per-tenant cryptographic ledger** *(implemented — `console/src/tenancy.rs`)*: each tenant's
    engagement ledgers are grouped under a per-tenant-keyed subdirectory
    (`tenant-<tid>/engagement-<eid>.jsonl`), keeping the **per-ledger Ed25519 signature unchanged** — just
    scoped per tenant. The default build (flag OFF) keeps the historical flat path (byte-identical).
  - **Flag-gated tenant UI** *(implemented — SPA + `console/src/tenancy.rs`)*: the console SPA exposes the
    tenant surface **only when the flag is ON**. A read-only probe `GET /api/tenancy` (served
    by the separable module) returns `{"enabled": false}` in the default build → the SPA shows **no
    tenant selector, no `#tenants` admin view, no nav link** (single-tenant shell,
    byte-identical). Once enabled, it returns the tenants accessible to the caller (super-admin ⇒ all)
    and drives: a **tenant selector** in the header **above the engagement selector** (tenant
    → engagement hierarchy, filtering the list of engagements to the active tenant), and a **`#tenants` admin view**
    (create / rename / archive tenants, manage user grants) shown only to a
    **platform-admin**. The server remains the authority (fail-closed filter + `403` gates); UI gating is
    defence in depth.

**How to enable.** Set the **`FORGE_ADVANCED_TENANCY=1`** flag (env) *or* the per-DB config key
**`advanced.tenancy=on`**; designate the platform operator(s) through **`FORGE_SUPERADMIN`** (env) or the
provisioning key **`advanced.superadmin`** (logins separated by comma/space — never a normal UI
route). With the flag OFF (the **default**), Forge is a **single implicit tenant #1** where all
users have full access and a behaviour **byte-identical** to before tenancy (all existing tests
green). The whole feature is a **separable module** — `console/src/tenancy.rs` (+ a
minimal `mod tenancy;` wiring in `main.rs`); the core never depends on it.
- **Identity at scale** — **SSO / SCIM** (SAML/OIDC login, automated user provisioning/deprovisioning).
  - **OIDC SSO login** *(implemented — `console/src/sso.rs`, flag-gated)*: an **Authorization-Code + PKCE** login flow
    against any OIDC provider. `GET /api/sso/login` redirects to the IdP's `authorize` endpoint
    with a server-side **state + nonce + PKCE `S256` challenge** (persisted per pending-auth); `GET
    /api/sso/callback` validates the state, exchanges the code (+ `code_verifier`) for tokens, and **fully
    validates the ID token** — **RS256 signature through the IdP's JWKS** (pure-Rust `jsonwebtoken`, `rust_crypto` backend, **no
    openssl**), **issuer**, **audience == `client_id`**, **exp**, and the **nonce**. On success, it maps
    the OIDC `sub`/`email` to a Forge user (**matching an existing one** or **auto-provisioning**
    with a configured default role and an unusable local password) and issues **the same
    `forge_session` cookie** as the local login (HttpOnly / SameSite=Strict). The provider config (`GET/POST
    /api/sso/config`) is **admin-gated**, supports **OIDC discovery**
    (`{issuer}/.well-known/openid-configuration`), and the **`client_secret` is write-only** (redacted on GET).
    **Fail-closed**: any state / nonce / issuer / audience / signature / exp mismatch is rejected
    (403); the browser is only ever redirected to an **allowlisted** return target (mirrors the
    `oauth.flow` / `redirect.open` anti-open-redirect discipline); the `client_secret` and the ID/access tokens
    are **never logged, ledgered, or returned**; each login is ledgered `console.sso.login`
    (actor + subject only). It is engaged only by **`FORGE_ADVANCED_SSO=1`** (or the DB config key
    `advanced.sso=on`). **DEFAULT build: flag OFF ⇒ `/api/sso/*` is disabled (404) and LOCAL
    accounts behave byte-identically** to today (all existing tests green). The module
    is separable — `console/src/sso.rs` (+ a `mod sso;` line and a route merge in `main.rs`); the
    core never depends on it.
  - **SCIM 2.0 provisioning** *(implemented — `console/src/scim.rs`, flag-gated)*: automated provisioning +
    deprovisioning of users/groups from an IdP (Okta / Azure AD). `GET/POST /scim/v2/Users`,
    `GET/PUT/PATCH/DELETE /scim/v2/Users/:id`, and `/scim/v2/Groups` implement the SCIM 2.0 core schema
    (`userName`, `active`, `emails`, `name`, `externalId`). It is authenticated by a **SCIM bearer token**
    — a long random token that an admin generates through `GET/POST /api/scim/config` (admin-gated) — which is a
    **secret**: stored **hashed** (SHA-256, like a session token — never the raw token), compared in
    **constant time**, and returned **only once** at rotation (redacted afterwards). It is **not** a
    normal session (an IdP has no `forge_session`); **fail-closed**: token absent/invalid/not configured ⇒ **401**.
    Mapping to Forge: creating / activating a SCIM user **creates / activates** a Forge user (with a
    **scoped default role** — viewer, **never** admin, **never** super-admin — and an unusable local
    password); **deactivating** (`active=false`) or **DELETE** **disables the user and purges their sessions**
    (immediate revocation); group membership maps to a scoped role / tenant grant (tied to the advanced
    RBAC, bounded to viewer|operator). A **designated super-admin login is protected** — SCIM refuses to create /
    disable / delete it (403). Each mutation is ledgered `console.scim.*` (metadata only —
    login / externalId / active / booleans, **never the token**). It is engaged only by **`FORGE_ADVANCED_SCIM=1`**
    (or the DB config key `advanced.scim=on`, or the SSO flag). **DEFAULT build: flag OFF ⇒ `/scim/*` and
    `/api/scim/config` are disabled (404) and LOCAL accounts behave byte-identically** to
    today (all existing tests green). The module is separable — `console/src/scim.rs` (+ a
    `mod scim;` line and a route merge in `main.rs`); the core never depends on it.
  - **Advanced RBAC — IdP group → {role, tenant grant} mapping** *(implemented — `console/src/rbac.rs`,
    flag-gated)*: a CONFIGURABLE mapping from an IdP group name to a Forge authorisation outcome —
    `idp_group → { role: viewer|operator|admin, tenant_id?, tenant_role? }`. **Both** the OIDC SSO login
    path (the ID token's `groups` claim) **and** the SCIM group membership path consult this
    SINGLE table, so that an admin configures group → access in one place (`GET/POST /api/rbac/group-map`,
    `DELETE /api/rbac/group-map/:group` — **admin-gated**, ledgered `console.rbac.*`). It replaces the old
    best-effort heuristic on `displayName`; when no mapping is configured, the behaviour is
    byte-identical to before. **FAIL-CLOSED / least-privilege** (weakening one turns a test RED):
    an SSO/SCIM identity obtains **ONLY** what its group mapping confers — no matching group ⇒
    `role: None` ⇒ the identity keeps its own least-privilege default (`viewer` at most), never more.
    **NEVER super-admin through SSO/SCIM** — super-admin is a *provisioning-only* designation (see
    `tenancy.rs`), is not a `users.role` value, and cannot be expressed in the table; a designated
    super-admin login is moreover never re-roled/re-granted by SSO/SCIM. Roles are validated to
    `viewer|operator|admin` and tenant roles to `tenant_admin|tenant_operator|tenant_viewer` (everything
    else — including `super_admin` — is rejected at config time). When several mapped groups
    match, the **highest role wins** (capped at admin); **SCIM additionally clamps admin → operator**
    (automated mass provisioning never automatically confers console admin). Tenant
    grants are set only when **multi-tenancy** is also engaged. It is engaged as soon as
    **SSO or SCIM** is engaged (`rbac::enabled()` = `sso::enabled() || scim::enabled()`).
    **DEFAULT build: both flags OFF ⇒ `/api/rbac/*` is disabled (404), the mapping table is
    never created, and role assignment stays admin-only exactly as today** (all existing tests
    green). The module is separable — `console/src/rbac.rs` (+ a `mod rbac;` line and a
    route merge in `main.rs`); the core never depends on it.
  - **SAML** login is still on the roadmap (a documented FUTURE follow-up — **OIDC covers the common case**;
    SAML would reuse the same group → role/tenant mapping in `rbac.rs`).
- **Advanced authorisation (going further)** — **composable/custom roles** beyond
  admin/operator/viewer, and **time-limited per-engagement grants**, build on the
  `rbac.rs` mapping above (roadmap).
- **High availability & scale** — **HA / clustering / distributed store** (Postgres instead of single-node
  SQLite), horizontal scale-out.
- **Compliance — legal hold / WORM retention** *(implemented — `console/src/compliance.rs` +
  `forge/compliance_signer.py`, flag-gated)*: a **retention policy** (a configurable retention duration
  for the audit trail + findings/runs) settable **globally / per tenant / per engagement** (the
  most specific wins), and a **legal-hold** flag (global/tenant/engagement) that **blocks any
  deletion/purge regardless of retention** — **the hold always wins** (fail-closed).
  **WORM enforcement**: as long as a ledger record is under retention *or* under legal hold, it **can be
  neither deleted, nor altered, nor purged**. A **governed purge** (`POST /api/compliance/purge`, admin)
  is allowed **only** when retention has **expired** **and** there is **no hold**, and it **never
  deletes silently**: it (a) **first archives the expired segment — encrypted**, reusing the
  backup discipline (`backup_encrypt`, XChaCha20-Poly1305 + argon2id), then (b) **re-anchors** the ledger and
  records a **signed `console.compliance.purge` checkpoint ledger event** (counts, SHA-256 of the
  segment, SHA-256 of the encrypted archive, purged head, time, actor). The **remaining chain stays verifiable**
  under the **existing** verifier (`crate::verify_ledger_chain`) *and* the Python `Ledger.verify` — the audited
  content of the surviving entries is preserved byte for byte (only their `prev`/`hash` are re-linked), so
  that **tamper-evidence and Ed25519 verification are intact**. **Fail-closed corner**: a purge
  **refuses** (409 `signed_survivor`) if a *surviving* entry is Ed25519/HMAC-signed (re-hashing it
  would break its signature) and **refuses** (400) if no archive key is configured (never an unrecoverable
  deletion). The **pluggable checkpoint signer** (`forge/compliance_signer.py`) keeps verification
  **byte-identical** to `signing.verify_with_pubkey` and exposes a **KMS/HSM seam** (`CallableComplianceSigner`)
  so that a hardware-anchored signer can plug in without changing the verification path. It is engaged
  only by **`FORGE_ADVANCED_COMPLIANCE=1`** (or the DB config key `advanced.compliance=on`). **DEFAULT
  build: flag OFF ⇒ every `/api/compliance/*` route is disabled (404), WORM/retention/hold are inert,
  and the ledger + engagement data are byte-identical** (all existing tests green). The module
  is separable — `console/src/compliance.rs` (+ a `mod compliance;` line, a route merge, an SPA flag,
  and a flag-gated WORM delete/archive guard in `main.rs`); the core never depends on it.
- **Compliance — pluggable ledger signer (KMS/HSM/remote key)** *(implemented — `forge/signing.py`,
  flag-gated)*: the audit ledger's **Ed25519 private key** **can live OFF-HOST** — in a KMS/HSM, a
  remote signer endpoint, or a **no-shell `exec` helper** — so that the private key **never lands
  on disk**. Selected by config (`FORGE_LEDGER_SIGNER` = `local` | `kms` | `hsm` | `http` |
  `remote` | `exec`, plus `FORGE_LEDGER_SIGNER_{ENDPOINT,CREDENTIAL,PUBKEY,ARGV,TIMEOUT}`) and gated by
  **`FORGE_ADVANCED_COMPLIANCE=1`**. A `RemoteSigner` produces a **standard Ed25519 signature over the
  same bytes**, so that **verification is UNCHANGED** — `Ledger.verify` /
  `Ledger.verify_external(pubkey)` / `signing.verify_with_pubkey` accept it with the **public key alone**,
  byte-identical whatever the signer. **Fail-closed & no fallback**: an unreachable/misconfigured/non-verifying
  remote signer **raises `RemoteSignerError`** and the append aborts — Forge
  **never writes** an unsigned or unsafe entry and **never silently falls back** to the local key
  (a remote signer requested without the flag is refused). **Secrets**: the endpoint/credential/argv are
  **redacted** (`redact_signer_config`) and never logged/ledgered/leaked (not even in error
  messages or `repr`); the `exec` signer is **no-shell** (fixed argv, configured by the admin — a shell
  string is rejected). **DEFAULT build**: nothing configured ⇒ `make_ledger_signer` returns the
  **`LocalFileSigner`** (the on-disk key `<ledger>.ed25519`) — **byte-identical to before** (all existing ledger
  tests green). Separable — the whole seam is additive in `forge/signing.py` (`LocalFileSigner`,
  `RemoteSigner`, `make_ledger_signer`); the core's default path is unchanged.
- **Compliance — SOC 2 / ISO 27001 evidence export** *(implemented — `console/src/compliance.rs`,
  flag-gated)*: a **read-only** evidence bundle for a **tenant / engagement / time
  range**, assembled from the **existing** ledger + RBAC + backup state (it **never mutates** any
  data). It contains the **authorisation audit trail** (who authorised what, when, on which scope — extracted
  from the tamper-evident ledger), the **RBAC / grant state** (console accounts, tenant grants, IdP group→role
  mappings for *this* tenant), the **access / mutation log**, the **backup attestation** (restore-**proven**,
  from the console ledger), and the **ledger integrity attestation** — **head hash + Ed25519
  public key + result of the chain verification + an external `forge ledger verify` command** (the
  verification needs only the **public key alone**; no secret is included).
  `GET /api/compliance/evidence?engagement_id=&format=json|html|pdf&from=&to=` (admin) returns **JSON** or
  **human-readable HTML** (the HTML **degrades to `?format=html` + print-to-PDF** when no
  PDF engine is present on the host — same `render_pdf_from_html` seam as the branded report). The bundle is
  **isolated per tenant/engagement** (only the ledger + accounts of that engagement, only the grants of
  that tenant) and **secret-redacted** end to end (passphrases / tokens / credentials / `client_secret` / private
  keys → `[REDACTED]`; **public keys are preserved**). The **act of exporting is itself ledgered**
  (`console.compliance.evidence.export` — actor, scope, format, ledger head, chain-ok). Engaged only
  by **`FORGE_ADVANCED_COMPLIANCE=1`** (or the DB config `advanced.compliance=on`); **default build
  (flag OFF) ⇒ the route returns 404 and nothing changes**.
- **Compliance (going further)** — **KMS/HSM-backed keys** are now available both
  for the **audit ledger signer** (`forge/signing.py` `RemoteSigner`, above) and the **compliance
  checkpoint signer** (`forge/compliance_signer.py` `CallableComplianceSigner`); hardware-anchored
  **encryption** (backup/archive at rest) is the remaining seam.

---

## Design principle for contributors

When adding a capability, ask yourself **which layer it belongs to** — both layers are open
AGPL; the question is whether it is always-active core or a separable flag-gated module:

- Does it make **governance or the cryptographic audit trail** stronger, more verifiable, or usable by
  a solo operator / a small team? → **it belongs to the always-active core.**
- Is it fundamentally a matter of **scale-out, multi-tenancy, identity at scale, HA, or
  formal compliance**? → it is an **advanced module**, and it must be built **separable** — a clean
  extension point on the core, OFF by default, never a fork of it, and never a gate that weakens
  or hides the open governance/audit surface.

The rule of thumb: **credibility (governance + crypto audit) is always active; scale/team/compliance
is a switch you flip.** Nothing is ever paid or hidden — the commercial offer consists of
**services**, not the code.

# Forge — Community vs Enterprise (open-core boundary)

Forge is developed as an **open core**. The full **governance and cryptographic-audit engine** is open
source under **[AGPL-3.0-only](LICENSE)** and stays that way forever. A separate, future **Enterprise
edition** (commercial license) adds the **scale / team / compliance** layer on top — never replacing or
gating the open core.

The dividing line is deliberate and simple:

> **The governance + cryptographic-audit core stays OPEN and verifiable — that is the product's whole
> credibility.** The **ENTERPRISE SCALE / TEAM / COMPLIANCE layer** is what is commercial. Enterprise
> features are built as **separable modules** bolted onto the open core, so the core is always usable,
> auditable, and self-hostable on its own.

Because the core is AGPL-3.0, anyone can run Forge solo or as a small team, read every line of the
safety and audit machinery, and verify that the ledger, the scope-guard, and the oracles do exactly what
they claim. That transparency is the point: you cannot trust a red-team governance tool you cannot read.

---

## Community edition — AGPL-3.0, open, free, self-hostable

Everything you need to run Forge **solo or as a small team**, on your own infrastructure, at no cost:

- **Governance core**
  - Fail-closed **ROE scope-guard** (inert by default; in-scope empty = nothing fires; `VETO` on any
    evaluation error).
  - **Ed25519 tamper-evident authorization ledger** (append-time, hash-chained, publicly verifiable from
    the public key alone).
  - **Proof-oriented oracles** — findings are evidence-backed, not asserted.
- **Techniques**
  - The **extensible technique registry** (declare-once → derive-everywhere) and **all technique
    classes** shipped with the core.
- **Execution**
  - The **C2-light governed run flow** (arm → scope → capability → approve, every action gated and
    ledgered).
  - The **purple loop** (findings + ATT&CK run-records fed to the detection side and correlated).
- **Console & access**
  - The **console UI + first-boot wizard + RBAC** with the three built-in roles: **admin / operator /
    viewer**.
- **Integration & infra**
  - **Connectors / orchestration**: nuclei, Metasploit (msf), Burp, and the other bundled tool
    integrations.
  - **Infra-agnostic detection** (plug any BLUE source — Plume, CrowdSec, FortiGate, pfSense/OPNsense,
    Elastic, file, exec — with no code).
  - **Encrypted backup / restore** (argon2id + XChaCha20-Poly1305, ledger-verified).
- **Scale**
  - **Single-scope + small-team use** — single-node SQLite store, local operator policy.

If Forge fits on one node and one small team, the Community edition is the whole product. Nothing about
the safety or audit story is held back.

---

## Enterprise edition — commercial, separate license

A future **commercial edition** (separate license, not AGPL) for organizations that need to run Forge at
**scale**, across **many teams / tenants**, under **formal compliance**. These are **separable modules**;
the open core never depends on them.

- **Multi-tenant / MSSP** — many isolated engagements/customers on one deployment, with **per-tenant
  cryptographic isolation** (separate keys and ledgers per tenant).
  - **Row-level multi-tenancy** *(implemented — `console/src/tenancy.rs`, flag-gated)*: a `TENANT ──<
    ENGAGEMENT ──< findings/runs` hierarchy plus a `tenant_grant(user_id, tenant_id, role)` map. A
    **fail-closed tenant filter** (deny-by-default, mirroring the ROE) is applied on top of the existing
    engagement isolation + RBAC: a user of tenant A can **never** list, read, or act on tenant B's
    engagements / findings / runs / roe / ledger / coverage / reports — no grant ⇒ zero rows / 403. It is
    engaged only by the enterprise flag **`FORGE_ENTERPRISE_TENANCY=1`** (or DB config key
    `enterprise.tenancy=on`). **DEFAULT (community) build: flag OFF ⇒ a single implicit tenant #1, all
    users access it, behaviour byte-identical** to pre-tenancy (all existing tests green). The module is
    separable — the open core never depends on it.
  - **Audited super-admin (platform/MSSP operator)** *(implemented — `console/src/tenancy.rs`)*: a
    **NON-DISABLABLE**, **provisioning-designated** capability (env `FORGE_SUPERADMIN` and/or the DB
    provisioning key `enterprise.superadmin` — never a normal UI route) that can **READ across ALL
    tenants**. It is fail-closed (no designation ⇒ nobody is super-admin; requires a valid individual
    `admin` session), the account **cannot be disabled / deleted / downgraded** through account CRUD, and
    **every cross-tenant read is ledgered `console.superadmin.access`** (tenant + what). It grants
    cross-tenant **READ ONLY** — cross-tenant write/run stays bound to native grants (a normal
    `tenant_admin` can never cross tenants). Mirrors Plume's non-disablable audited super-admin.
  - **Tenant CRUD + grant management** *(implemented — `console/src/tenancy.rs`)*: create / rename /
    archive tenants and list / add / remove a user's `tenant_grant`, gated to a **platform-admin** (a
    console `admin` session or a super-admin) and ledgered **`console.tenant.*`**. Fail-closed guards:
    never archive the **last active tenant**, never remove the **last `tenant_admin` grant** of a tenant.
    In the community build the surface is closed (`403 enterprise_disabled`).
  - **Per-tenant cryptographic ledger** *(implemented — `console/src/tenancy.rs`)*: each tenant's
    engagement ledgers are grouped under a tenant-keyed subdirectory
    (`tenant-<tid>/engagement-<eid>.jsonl`), keeping the **Ed25519 signing per-ledger unchanged** — just
    scoped per tenant. Community (flag OFF) keeps the historical flat path (byte-identical).
  - **Flag-gated tenant UI** *(implemented — SPA + `console/src/tenancy.rs`)*: the console SPA exposes the
    tenant surface **only when the flag is ON**. A read-only probe `GET /api/tenancy` (served by the
    separable module) returns `{"enabled": false}` in the community build → the SPA renders **no tenant
    selector, no `#tenants` admin view, no nav link** (single-tenant shell, byte-identical). When enabled it
    returns the caller's accessible tenants (super-admin ⇒ all) and drives: a **tenant selector** in the
    header **above the engagement selector** (tenant → engagement hierarchy, filtering the engagement list
    to the active tenant), and a **`#tenants` admin view** (create / rename / archive tenants, manage user
    grants) shown only to a **platform-admin**. The server stays the authority (fail-closed filter + `403`
    gates); the UI gating is defence-in-depth.

**How to enable (enterprise).** Set the flag **`FORGE_ENTERPRISE_TENANCY=1`** (env) *or* the per-DB config
key **`enterprise.tenancy=on`**; designate the platform operator(s) via **`FORGE_SUPERADMIN`** (env) or the
provisioning key **`enterprise.superadmin`** (comma/space-separated logins — never a normal UI route). With
the flag OFF (the **community default**), Forge is a **single implicit tenant #1** with all users granted
full access and **byte-identical** pre-tenancy behaviour (all existing tests green). The whole feature is a
**separable module** — `console/src/tenancy.rs` (+ a minimal `mod tenancy;` wiring in `main.rs`); the open
core never depends on it.
- **Enterprise identity** — **SSO / SCIM** (SAML/OIDC login, automated user provisioning/deprovisioning).
- **Advanced authorization** — **composable RBAC** beyond admin/operator/viewer, and **per-engagement
  grants** (scoped, time-boxed authority).
- **High availability & scale** — **HA / clustering / distributed store** (Postgres instead of
  single-node SQLite), horizontal scale-out.
- **Compliance** — **SOC2 / ISO evidence** exports, **legal-hold / WORM retention**, and **KMS/HSM-backed
  keys** (hardware-rooted signing/encryption).
- **Premium connectors** — additional/commercial tool and platform integrations.
- **Support & SLA** — commercial support, response-time guarantees, and roadmap influence.

---

## Design principle for contributors

When adding a capability, ask **which side of the line it belongs on**:

- Does it make the **governance or the cryptographic audit trail** stronger, more verifiable, or usable
  by a solo operator / small team? → **it belongs in the open AGPL core.**
- Is it fundamentally about **scale, multi-tenancy, enterprise identity, HA, or formal compliance**? →
  it is an **Enterprise module**, and it must be built **separable** — a clean extension point on the
  core, never a fork of it, and never a gate that weakens or hides the open governance/audit surface.

The rule of thumb: **credibility (governance + crypto-audit) is open; scale/team/compliance is
commercial.**

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

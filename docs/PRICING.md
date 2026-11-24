# Forge — Services & pricing (PROPOSAL)

[English](PRICING.md) | [Français](PRICING.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Positioning](POSITIONING.md) · [Overview](OVERVIEW.md)

> ⚠️ **Status: working PROPOSAL, not a commercial commitment.** The amounts below are
> orders of magnitude to frame the GTM discussion (see [`POSITIONING.md`](POSITIONING.md)). No
> price is firm until a first reference engagement has validated the coverage value
> (see [`REFERENCE_ENGAGEMENT_TEMPLATE.md`](REFERENCE_ENGAGEMENT_TEMPLATE.md)).

> 💡 **The product is free and open source.** Forge is published under **[AGPL-3.0-or-later](../LICENSE)**,
> with **all** its capabilities — including the advanced modules (multi-tenant/MSSP, SSO/SCIM, advanced RBAC,
> WORM/legal-hold compliance, off-host ledger signer). There is **no paid offering and no feature
> locked behind a paywall**: what is billed is **professional services** around
> the tool, never the tool itself. Module details: [`ADVANCED_MODULES.md`](ADVANCED_MODULES.md).
>
> "Free" holds in the sense of the **AGPL-3.0 freedoms**, not "without obligation": the AGPL is a
> **strong copyleft** — source to be offered on network use (§13), derivatives that stay under the AGPL, license
> notices preserved (see [`LICENSE`](../LICENSE)).

---

## 1. The pricing logic

We do **NOT** price the software (it is free) nor the number of exploits (Forge provides none — it
drives MSF/Burp/nuclei). Billing covers the **service** — the governance and
measured-coverage value that an engagement brings:

- what it costs the client today to **manually prove** that a red team stayed in-scope
  (legal hours + audit risk);
- what it is worth to **put a figure on defensive coverage** (does the SOC see 40 % or 80 % of the techniques?
  how much does an undetected gap cost?);
- the **same-vendor** red × blue effect: a single point of contact for the purple loop, a single
  ATT&CK correlation.

**Market anchor**: Metasploit Pro sells for ~**$15,000/seat/year** for offensive *capability*.
Forge does not sell capability (the client already has it) and sells **no product license** — it sells
**evidence + measurement**, delivered through a service. The value is justified by measured coverage, not
by raw capability nor by a right to use the code.

---

## 2. The services (proposal)

| Service | Content | For whom | Order of magnitude |
|---|---|---|---|
| **Reference engagement** ⭐ | An authorized campaign end to end: scope + ROE gate, **third-party-verifiable Ed25519 ledger**, **ATT&CK coverage matrix** (detected / missed / real MTTD) and delivered report. It is the deliverable that proves the value. | First client / one-off audit that wants to put a figure on its coverage. | Fixed price per engagement. |
| **Purple coaching** | Wiring **Forge × Plume** (blue SOC), setting up the coverage loop, iterative closing of gaps, upskilling of the internal team. | CISO / purple lead who wants to install the loop for the long term. | Fixed price or time and materials. |
| **Support & SLA** | Business-hours support, updates, deployment help — **including the advanced modules** (multi-tenant/MSSP, SSO/SCIM, WORM compliance, off-host ledger anchoring) —, scope review, prioritized response. | Stable internal team / MSSP with a roster of operators. | Annual subscription. |
| **Hosting / managed** | Forge operated by GuatX: off-host ledger anchoring, encrypted backups, updates, monitoring. | Regulated client / without a dedicated ops team. | On quote. |

> The product remains **fully self-hostable and free** in each of these cases. The service
> unlocks no feature: it brings **expert time, assurance and delivered evidence**.

---

## 3. Billing axes (sketch, to be decided)

Two plausible models, not mutually exclusive:

### (a) Per engagement
- **Unit**: one authorized campaign (one scope, one ledger, one delivered coverage matrix).
- **Suited to**: consulting firms / one-off audits, first clients (low initial commitment).
- **Billed deliverable**: the signed engagement report + the purple matrix (see template).

### (b) Support / annual subscription
- **Unit**: support contract per active operator (seat) or per scope.
- **Suited to**: stable internal team, MSSP with a roster of operators.
- **Architecture note**: the default build is **stateful single-replica** (SQLite + ledger on an RWO
  PVC, see [`DEPLOYMENT.md`](DEPLOYMENT.md)) → ideal profile **single operator / small MSSP**. The
  **multi-tenant scale-out** is an **open, flag-gated module** (`FORGE_ENTERPRISE_STORE=postgres`,
  off-host ledger, see [`ADVANCED_MODULES.md`](ADVANCED_MODULES.md)): available in the code,
  but **running it as a managed multi-client service** falls under the hosting service.

> **GTM recommendation**: start **per engagement** (low friction, proves the value on a
> first reference client), then move recurring clients to **support/subscription**.

### Support levels
| Level | Content | |
|---|---|---|
| **Community** | Docs, best-effort, no SLA. | free, with the open source |
| **Standard** | Business-hours support, updates, help wiring Plume. | service |
| **Prioritized** | Prioritized response, assisted onboarding, help with off-host ledger anchoring, scope review, deployment of the advanced modules. | service, on quote |

---

## 4. What justifies the value of purple coaching (argument)

1. **Measured coverage value**: going from a SOC that "thinks it is covered" to "we detect
   N ATT&CK techniques out of M, median MTTD = X min" is a deliverable that can be presented directly to the executive committee
   and to the auditor. It is the native output of the purple loop.
2. **A single point of contact for red + blue**: no fragile third-party integration between the offensive tool
   and the SIEM — the ATT&CK correlation is native (`mitre` field joined read-only).
3. **Evidence of authorization included**: the third-party-verifiable Ed25519 ledger reduces the
   legal/audit cost of each campaign (fewer lawyer hours to "prove we stayed
   in-scope").
4. **Safe-by-default**: lower operational risk (inert by default, fail-closed) = an insurance /
   compliance argument.

---

## 5. Honest limits to tell the prospect

- **Low raw offensive capability**: if the need is "more exploits / post-ex / C2",
  Forge is NOT the answer — keep MSF/CS, add Forge on top.
- **v0.0.1 maturity**: the first clients are **design partners** (service at a reduced rate
  in exchange for field feedback and the right to use them as a reference).
- **Single-replica by default**: the multi-tenant scale-out **exists** as an open flag-gated module,
  but the **managed multi-client offering** (SLA, off-host anchoring operated by GuatX) is a service
  roadmap item, not a given.

---

*See also: [`POSITIONING.md`](POSITIONING.md) (the pitch + competitive teardown) ·
[`ADVANCED_MODULES.md`](ADVANCED_MODULES.md) (the open, flag-gated advanced modules) ·
[`DEPLOYMENT.md`](DEPLOYMENT.md) (single-replica constraint) · [`PLAN.md`](PLAN.md) (roadmap).*

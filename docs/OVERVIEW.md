# Overview

[English](OVERVIEW.md) | [Français](OVERVIEW.fr.md)

> [Table of contents](README.md) · Next: [Architecture](ARCHITECTURE.md) · [Concepts](CONCEPTS.md) ·
> [Offline start](GETTING_STARTED.md)

## What is Forge?

**Forge is a governed red-team assessment platform.** It orchestrates attack modules
(recon → enumeration → evidence oracles → exploitation connectors), but its core is not
the arsenal: it is the **governance, evidence and measurement layer** placed on top of it.

Three invariants define it:

1. **Fail-closed governance** — every action goes through a **four-layer ROE (Rules of Engagement)
   gate**. By default, Forge is **INERT**: nothing can fire until the operator has
   consciously armed every layer. Outside the authorized scope ⇒ hard refusal (`VETO`), never simulated.
2. **Evidence of authorization** — every decision (arming, approval, shot, finding) is sealed
   in an **append-time, tamper-evident engagement ledger**, signed with **Ed25519**. A third party
   (auditor, client, legal) verifies integrity and scope membership with the **public
   key alone**, without ever being able to forge an entry.
3. **Purple measurement** — every fired technique carries a **MITRE ATT&CK** identifier. By joining the
   *fired* techniques (red) to the techniques *detected* by the defense (blue), Forge computes the
   **real detection coverage** and the **MTTD** — technique by technique.

Forge is written in **pure-stdlib Python** (the engine) + **Rust/axum** (the console) + **vanilla-JS**
(the SPA). The deliverable is **one binary + Python sources** (Python **1,371 KB** + web **877 KB** measured;
binary size **not measured** — see [`DEPLOYMENT.md`](DEPLOYMENT.md) §6); the heavy offensive engines (nmap, nuclei, Metasploit, Burp,
browser-automation) are **orchestrated as options**, never bundled, and **neutralize themselves** if they
are absent.

## The problem Forge solves

After an offensive campaign, two questions often remain without a demonstrable answer:

- **"Can you prove to an auditor that the red team stayed within the authorized scope?"**
  → Forge answers with a signed ledger, verifiable without trusting the operator.
- **"How many of these techniques did your SOC actually detect, and how fast?"**
  → Forge answers with an ATT&CK coverage matrix and a measured (not estimated) MTTD.

Forge does **not** try to beat Metasploit or Cobalt Strike on raw offensive capability. It
**drives** them and **measures their defensive impact**. The differentiator is no single line taken in isolation,
but their combination: *red + blue, same vendor, ATT&CK-correlated, signed authorization*.

The full positioning is in [`POSITIONING.md`](POSITIONING.md); the product is **free and
open source**.

## The value proposition in three pillars

### Pillar A — Signed evidence of authorization
- **Fail-closed 4-layer ROE gate** (`forge/roe.py`): a LIVE action goes out ONLY if it has
  passed *armed → in-scope (allowlist, never deny-list) → authorized capability → approved*. Any
  ambiguity or evaluation error ⇒ `VETO`.
- **Engagement ledger** (`forge/ledger.py` + `signing.py`): SHA-256 chain + **per-entry** Ed25519
  signature, external verification with the public key alone (`verify_external`).

### Pillar B — Same-vendor purple loop
- Forge (red) and Plume (blue, the SOC) correlate on the **MITRE** field. "Purple" is not a 3rd
  product: it is the loop. Output: per technique → **detected (exact) / parent_approx / missed /
  MTTD**. The rate and the MTTD only count exact matches: a generic parent rule does not prove the
  detection of the fired sub-technique.
- The **detection source is a configurable plugin**: Plume is only a preset
  (`kind=plume`). CrowdSec, FortiGate, pfSense/OPNsense, Elastic/OpenSearch, a file or a
  command are wired **without code** — see [`DETECTION.md`](DETECTION.md).

### Pillar C — Safe-by-default
- **Forced non-exploit**: `allow_exploit` / `allow_destructive` are explicit per-engagement
  opt-ins. An `exploit=True` module (e.g. `msf.module`) is vetoed as long as the capability is not
  armed.
- **Hard scope-guard**: empty `in_scope` ⇒ nothing fires (fail-closed).
- **No over-classification**: a third-party connector (nuclei, Burp) emits `reported_by_tool`, never
  `vulnerable`, as long as there is no evidence of exploitability.

## Forge works STANDALONE

**Plume (the SOC) and the purple loop are OPTIONAL.** Forge is a complete product without them:

| Without any detection source | Forge still does… |
|---|---|
| ROE scope-guard + per-layer arming | ✅ the whole governance cycle |
| Signed engagement ledger + external verification | ✅ evidence of authorization |
| Recon, evidence oracles, MSF/Burp connectors | ✅ the whole governed red-team |
| Console (findings / ATT&CK coverage / runs), GXQL, dashboards, reports | ✅ the whole store + deliverables |
| Purple loop (detected/missed/MTTD) | ⏸️ inert — **readable fail-open**: `source_reachable:false`, no invented metric |

When no detection source is configured, the purple coverage endpoint answers
honestly "measurement impossible" rather than inventing a figure. Plugging in a source **later**
activates the loop without changing anything else. See the dedicated page
**[Using Forge standalone](STANDALONE.md)**.

## What Forge is NOT

- **NOT a C2 / a beacon**: no implant, no persistent callback, no post-exploitation.
  Forge orchestrates tools at *fire-time* and then records; it does not maintain access. The console's
  "C2-light" run-flow is a **governed and audited campaign launcher**, not a persistent
  command channel.
- **NOT a vulnerability scanner**: nuclei/Burp do the scanning; Forge **governs and correlates** them.
- **NOT a Metasploit replacement**: it **drives** it (`msf.module` → msfrpcd).
- **NOT OSINT / forensics**: `origin.find` recovers an origin IP behind a CDN (scoped technical
  recon); the ledger proves an **engagement authorization**, not endpoint forensic
  evidence.

Anti-confusion details: [`POSITIONING.md`](POSITIONING.md) §4.

## Maturity & constraints (honesty)

- **Version 0.0.1** — the first clients are design partners.
- **Stateful single-replica**: SQLite + ledger on a `ReadWriteOnce` volume → ideal profile
  **single operator / small MSSP**. Multi-tenant scale-out is an evolution (off-host ledger +
  shared store), not a given. See [`DEPLOYMENT.md`](DEPLOYMENT.md) § Architecture constraint.
- **Custody**: the private signing key is currently **local**; off-host anchoring (remote co-signing
  witness, `forge/anchor.py`) is the last step, and the asymmetric architecture already
  allows it (only the public key circulates). Documented, not hidden.

## Next steps

- See Forge running in 10 minutes, 100 % offline → **[Getting started](GETTING_STARTED.md)**.
- Understand how it is built → **[Architecture](ARCHITECTURE.md)** and **[Concepts](CONCEPTS.md)**.
- Deploy a console → **[Installation](INSTALLATION.md)** then **[First deployment](FIRST_DEPLOYMENT.md)**.

# Forge — Positioning (GTM)

[English](POSITIONING.md) | [Français](POSITIONING.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Overview](OVERVIEW.md) · [Plan](PLAN.md)

> **Tagline**
> *"Forge is not a Metasploit replacement — it is the **governance + evidence + purple
> measurement** layer on top of the tools you already have (it drives MSF / Burp / nuclei)."*

Forge is NOT sold on the number of exploits. It is sold on three things that no offensive arsenal
has ever offered together: **proving authorization**, **measuring what the SOC saw**, and **breaking
nothing by default**. It is an **offensive governance** layer, not a new arsenal.

---

## 1. The target segment (and whom we do NOT address)

| | Target buyer | Why |
|---|---|---|
| ✅ | **CISO / Security leadership** | Wants auditable evidence that the red team stayed in-scope, and a defensive coverage figure to present to the executive committee / the regulator. |
| ✅ | **Purple-team lead / detection owner** | Wants to know, ATT&CK technique by technique, what the SOC **detected / missed** and how fast (MTTD). |
| ✅ | **Legal / compliance / DPO** | Wants a signed chain of custody verifiable by a third party: who authorized what, when, on which scope. |
| ❌ | **The exploit-hunting pentester** | Looks for raw capability (0-days, post-exploit, EDR evasion). Forge does NOT play on that field — it **drives** their tools, it does not replace them. |

**The sentence that qualifies a prospect**: *"After an offensive campaign, can you prove
to an auditor that you stayed in-scope, AND put a figure on what your SOC actually detected?"*
If the answer is "no / not easily", it is a Forge prospect.

---

## 2. The three pillars

### Pillar (a) — Signed evidence of authorization

The differentiator that **nobody** in offensive security industrializes: authorization is not an
intention, it is a cryptographic artifact.

- **Fail-closed 4-layer ROE gate** (`forge/roe.py`): a LIVE action goes out ONLY if it has
  passed *armed → in-scope (allowlist, never deny-list) → authorized capability → approved*. Any
  ambiguity or evaluation error ⇒ `VETO` (hard refusal). Out of scope ⇒ never simulated, never fired.
- **Append-time, tamper-evident engagement ledger** (`forge/ledger.py` + `signing.py`):
  SHA-256 hash chain + per-entry **Ed25519** signature. A third party (auditor, client, legal)
  verifies integrity with the **public key alone** (`verify_external(pubkey)`) — without ever
  being able to forge an entry.
- **Custody — honesty**: the private key is still local; **off-host anchoring** (remote co-signing
  witness, `forge/anchor.py`) is the final step, and the asymmetric architecture already
  allows it (only the public key circulates). Documented, not hidden.

**Value sold**: "You sign every action of the engagement. Your auditor verifies it without
trusting you."

### Pillar (b) — Same-vendor PURPLE loop

Forge (red) and **Plume** (blue, the SOC [`guatxlabs/plume`](https://github.com/guatxlabs/plume))
come from the **same vendor** and correlate on the
**MITRE ATT&CK** field. "Purple" is not a 3rd product: it is the loop.

```
Forge tire la technique T ─► run-record {mitre: T} ─► Plume ingère
                                                          │
                       Plume détecte ? alerte {mitre: T} ─┘
   corrélation = égalité du champ `mitre`  ─►  matrice de couverture ATT&CK
   (Forge mesure le VRAI MTTD + le VRAI % de couverture du SOC)
```

Output: per technique → **detected / missed / real MTTD**. Not a marketing score — a
read-only join between what red fired and what blue saw.

**Value sold**: "Here, technique by technique, is what your SOC missed, and how fast
it saw the rest. Here is how to close the gaps."

### Pillar (c) — Safe-by-default

- **Forced non-exploit**: by default Forge is **INERT**. `allow_exploit` / `allow_destructive`
  are explicit per-engagement opt-ins. A module flagged `exploit=True` (e.g. `msf.module`) is
  vetoed as long as the capability is not armed.
- **Opt-in governance**: per-layer arming (`--arm`), per-action approval (`--approve`), or documented
  `auto` mode. Nothing "goes off on its own".
- **Hard scope-guard**: empty `in_scope` ⇒ nothing fires (fail-closed). The `burp.scan` connector
  emits `reported_by_tool`, never `vulnerable`, as long as there is no evidence of exploitability —
  no over-classification.

**Value sold**: "The hardest tool to make a mistake with. By construction."

---

## 3. Competitive teardown (honest)

Where Forge **WINS** and where it **LOSES**. Selling the truth builds a CISO buyer's trust.

| Dimension | Forge | Metasploit (Pro) | Cobalt Strike | Maltego | Splunk (ES) |
|---|---|---|---|---|---|
| **Governance / evidence of authorization** | 🟢 **ROE gate + third-party-verifiable Ed25519 ledger** | 🔴 near zero | 🔴 none | ⚪ N/A | ⚪ N/A |
| **Audit / chain of custody** | 🟢 **append-time, signed** | 🟡 local logs | 🟡 C2 logs | 🔴 | 🟡 logs |
| **Integrated purple loop (same vendor)** | 🟢 **Forge×Plume, ATT&CK correlation, MTTD** | 🔴 | 🟡 via third-party integrations | 🔴 | 🟡 blue side only |
| **Operator UI / dashboards** | 🟢 console + GXQL + panels | 🟡 | 🟡 | 🟢 | 🟢 |
| **Safe-by-default** | 🟢 **inert, opt-in, fail-closed** | 🔴 designed to fire | 🔴 | ⚪ | ⚪ |
| **Footprint / deployability** | 🟢 one binary + stdlib Python (deliverable size **not re-measured**) | 🟡 | 🟡 | 🟡 | 🔴 heavy |
| | | | | | |
| **Raw offensive capability** | 🔴 **low — drives, does not provide** | 🟢 huge | 🟢 elite (C2/post-ex) | 🟡 OSINT | ⚪ |
| **Maturity / track record** | 🔴 **v0.0.1** | 🟢 20+ years | 🟢 red-team standard | 🟢 | 🟢 |
| **Ecosystem / modules / community** | 🟡 **88 modules** (2026-11-24) | 🟢 2000+ | 🟢 | 🟢 | 🟢 |
| **Post-exploitation / C2 / pivot** | 🔴 **none (outside the charter)** | 🟢 | 🟢 | ⚪ | ⚪ |

**Reading**: Forge is **complementary**, not substitutable. It does NOT try to beat MSF on
capability (lost in advance, outside the charter). It is bought **on top of** MSF/Burp/nuclei to govern them
and measure their defensive impact. The moat = *red + blue, same vendor, ATT&CK-correlated, signed
authorization* — something no row of this table has in a single column.

---

## 3bis. Against OSS / AGPL (honest)

The truth that defuses the objection "it is just reNgine with another UI": as a **tool
orchestrator driven from an interface**, Forge is **NOT unique** — mature OSS already covers this
axis well. Forge's differentiator is not orchestration: it is the
**governance + evidence + non-repudiation** layer, which we have not seen industrialized in **any of the OSS
projects listed below** — a wording deliberately bounded to this list, because "no OSS project"
on its own is not a claim we can verify.

| Tool | License | What it does as well (or better) | What is missing vs Forge |
|---|---|---|---|
| **reNgine** | GPL-3.0 | Recon/scan orchestration via a web UI, configurable scan engines, findings. The closest on "driving tools from a UI". | No fail-closed scope-guard, no ledger, no evidence discipline, no purple. Web-recon oriented. |
| **Faraday** (Community) | GPL-3.0 | Collaborative multi-pentest platform: workspaces (≈ engagements), 80+ integrated tools, findings, reporting, RBAC. | It aggregates, it does not fire under constraint; no signed ledger, no coverage-safe planner, no purple. |
| **Osmedeus** | MIT | Workflow-based recon/scan automation framework, fast, CLI-first. | CLI, no UI governance, no evidence/ledger/purple. |
| **DefectDojo** (OWASP) | BSD-2 | Vuln management / ASPM: scan import, dedup, triage, metrics, reporting. | DevSecOps, no active orchestration, no offensive scope-guard, no authorization ledger. |
| **Nuclei / ProjectDiscovery** | MIT | The scan engine that Forge drives. | A building block, not a governed orchestrator. |
| **Metasploit / Sliver / Havoc / Mythic** | BSD/Apache/GPL | Real exploitation & C2 frameworks (post-ex). | Opposite niche: they exploit; Forge excludes exploitation and aims to be provable/auditable — it drives them. |
| **MITRE Caldera** | Apache-2.0 (project in the Apache Incubator since 20/05/2026) | Autonomous adversary emulation, planner, ATT&CK-mapped abilities, multi-OS agents. **The closest on "replaying an ATT&CK-mapped adversary".** | No fail-closed authorization gate nor third-party-verifiable signed ledger; the SIEM-side validation loop does not ship with it. |
| **Splunk Attack Range** | Apache-2.0 (Splunk Threat Research Team) | **Attack → SIEM → automated detection validation, all the way into CI/CD.** It is the most direct prior art on the purple loop. | It provisions a **lab** (cloud/local) around Splunk; it is not a sovereign, self-hosted, low-footprint product, and authorization is not a provable object in it. |

**Reading**: as a UI orchestrator, Forge is **not unique** (reNgine / Faraday are mature), and the
**attack → detection loop is not new either** (Caldera, Attack Range, and the whole
BAS/AEV market — Cymulate, SafeBreach, Picus — sell it). What we have found in none of them is
the combination: **proving authorization** (fail-closed scope-guard), **proving impact**
(oracle → evidence), making it **non-repudiable** (chained Ed25519 ledger), and delivering the purple loop
**in a sovereign self-hosted bundle** (Forge + Plume, same repository, correlated per ATT&CK technique).
That is where the moat is played, not on "a UI on top of tools" nor on "doing BAS".

---

## 4. What Forge is NOT (anti-confusion)

- **NOT a beacon / a C2**: no implant, no persistent callback, no post-exploitation.
  Forge orchestrates tools at fire-time and then records; it does not maintain access.
- **NOT OSINT / Maltego**: it does not map people, social graphs,
  leaks. Its `origin.find` recovers an origin IP behind a CDN — that is scoped technical
  recon, not intelligence.
- **NOT forensics / Cellebrite**: no disk/mobile acquisition, no post-mortem analysis.
  The ledger is evidence of **engagement authorization**, not endpoint forensic evidence.
- **NOT a vulnerability scanner**: nuclei/Burp do the scanning; Forge **governs and correlates** them.
- **NOT a Metasploit replacement**: it **drives** it (`msf.module` → msfrpcd).

---

## 5. The one-page pitch (for a CISO)

> Your pentesters already have Metasploit, Burp, nuclei. What you are missing is: (1) **proving** to
> your auditor that the campaign stayed within the authorized scope — signed, verifiable without
> trusting you; (2) **putting a figure** on what your SOC actually detected, ATT&CK technique by
> technique, with the real detection time; (3) a tool **unable to go off the rails** by default.
> Forge is that layer. It does not replace your tools — it makes them governable and measurable.

---

*See also: [`REFERENCE_ENGAGEMENT_TEMPLATE.md`](REFERENCE_ENGAGEMENT_TEMPLATE.md) ·
[`PLAN.md`](PLAN.md) (roadmap) · [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) (Plume wiring).*

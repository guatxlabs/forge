# Forge — Plan & Roadmap

[English](PLAN.md) | [Français](PLAN.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Overview](OVERVIEW.md) · [Positioning](POSITIONING.md)

> ✅ UPDATE — **Step 2** (sellable P1: reporting + accounts), **Step 3** (offensive
> credibility) and user accounts / individual attribution are **delivered**. Still open:
> ⏳ field feedback from a real engagement. The rest of this plan is kept for context.

## Positioning

Forge = **GOVERNED** red-team orchestration layer + **PURPLE** measurement, companion to
Plume (blue).

- **Segment**: red-team **auditable under compliance + integrated purple**.
- **Buyer**: CISO / purple lead / legal — **NOT** the exploit-hunting pentester.

> **Tagline**: "Forge is not a Metasploit replacement — it is the governance
> + evidence + purple measurement layer on top of the tools you already have (it drives MSF/Burp/nuclei)."

## Red / Blue / Purple

- **Plume = BLUE** (detection / SOC).
- **Forge = RED** (offensive).
- **"Purple" is NOT a 3rd product**: it is the red × blue collaboration loop
  (red + blue = purple). The coverage matrix (fired vs detected → detected / missed / MTTD)
  **IS** that loop.

**The MOAT** = red + blue from the **SAME VENDOR**, correlated through ATT&CK + signed evidence of authorization
(fail-closed ROE + Ed25519 ledger) — something no incumbent (MSF / Cobalt Strike / Maltego / Splunk)
has.

## ✅ Already done

- **Audit**: internal security review carried out, the identified findings were fixed.
- **CLI ↔ UI parity** (+ governed exploit opt-in).
- MSF / Burp **connectors**.
- **P0 foundation**: git v0.0.1, packaging / Makefile / pyproject, Docker / compose / systemd / CI,
  `forge doctor`, LICENSE.
- **Purple loop** (code + tests, verified with mocks).

## Sequenced roadmap

### Step 1 — PURPLE GO LIVE (waiting for Plume to be deployed)

Wire `PLUME_URL` → Plume prod (read-only JOIN) + 1st real purple campaign on an authorized lab target
→ 1st matrix with real SOC detections + real MTTD. (See
[`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).)

### Step 2 — sellable P1

- Client PDF / HTML export (#4).
- User accounts / individual attribution (#6).

### Step 3 — offensive credibility

- Harden the IDOR oracle (fragile: false positives / false negatives).
- 2-3 evidence oracles (callback-verified SSRF, auth / ATO).
- **ITERATIVE** engine (chaining recon → origin → nuclei → idor).
- MSF session-poll connector (real evidence, not a false positive).

### Step 4 — GTM

- Positioning page + pricing of services (value of purple coaching vs MSF Pro ~15k$/seat for raw capability; the product itself is free/open).
- 1 reference engagement write-up.

## Status of the 6 blockers

| # | Blocker | Status |
|---|---|---|
| 1 | secrets / .gitignore | ✅ |
| 2 | versioning / packaging | ✅ |
| 3 | purple loop | ✅ (code + tests; live demo remaining) |
| 4 | PDF deliverable | 🟡 (full console report ✓, branded PDF / HTML export remaining) |
| 5 | real field finding | ⏳ |
| 6 | user accounts | ⏳ |

## Honest offensive assessment

- Native offensive depth **LOW** (1 fragile evidence oracle + wraps + connectors).
- Do **NOT** chase MSF / CS parity (lost in advance, outside the charter).
- Bet on **governance + purple + credible evidence oracles**.
- The project's **BLUE** anchoring is its differentiator (purple measurement, where red meets
  blue).
- **DO NOT**: home-made beacon / C2, Cellebrite / forensics, race for the number of exploits.

## Time-to-sellable

A horizon of several months until a first client convinced by the purple demo.

**Main risk = FOCUS**: the purple loop must stay **#1**, otherwise scattering.

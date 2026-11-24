# Using Forge standalone (without Plume)

[English](STANDALONE.md) | [Français](STANDALONE.fr.md)

> [Contents](README.md) · See also: [Overview](OVERVIEW.md) · [Getting started](GETTING_STARTED.md) ·
> [Concepts: purple loop](CONCEPTS.md#5-the-purple-loop)

**Plume (the SOC) and the purple loop are OPTIONAL.** Forge is a complete product without them. This
page describes what you get standalone and how to plug in a detection source **later**,
without breaking anything.

## What Forge does without any detection source

| Capability | Standalone |
|---|---|
| ROE scope-guard + per-layer arming (inert by default) | ✅ |
| Ed25519-signed engagement ledger + external verification by public key | ✅ |
| Passive/active recon, evidence-backed oracles, MSF/Burp connectors (ROE-gated) | ✅ |
| Console: Findings / ATT&CK Coverage / Runs / Ledger | ✅ |
| GXQL (SPL-style search) + dashboards (saved panels) | ✅ |
| Engagement reports (md / html / pdf) + anti-masking section | ✅ |
| Governed C2-light (campaign launch from the web) | ✅ |
| **Purple coverage (detected / missed / MTTD)** | ⏸️ **inert — readable fail-open** |

**ATT&CK coverage** (`GET /api/coverage`) — *which techniques did I fire, how many reached
`FIRE`* — is **native** and depends on no SOC: it is the "red" half of the matrix. Only the
"blue" half (were we detected?) requires a detection source.

## The fail-open behaviour (honest)

With no source configured, the purple coverage endpoint (`GET /api/detection/coverage`, alias
`/api/purple/coverage`) answers **`source_reachable:false`** with a readable reason — it **never
invents** `detected`/`parent_approx`/`missed`/`MTTD`. This is a design choice: "measurement impossible" is better
than a false number. The `forge doctor --purple` diagnostic prints « boucle purple INCOMPLÈTE » (purple loop INCOMPLETE) with
the exact line that is missing, without firing anything.

## Recommended standalone path

1. **Install** — [Installation](INSTALLATION.md) (Docker `mini` is enough for recon/oracles;
   `full` if you want embedded httpx/nuclei/subfinder + turnkey PDF export).
2. **Provision** — [First deployment](FIRST_DEPLOYMENT.md), **skipping step 3** (detection
   source). Fill in only the admin (+ possibly the operator policy).
3. **Define the scope** — `cp scope.example.json scope.json` and fill in `in_scope` **with
   written authorization**. Check: `forge scope-check <cible> --scope scope.json`.
4. **Hunt** — either in the CLI (`forge campaign …`, see [CLI](CLI.md)), or through the console's
   C2-light (operator). Findings/coverage/runs populate the console.
5. **Deliver** — `GET /api/runs/:id/report?format=html` (branded deliverable, print → PDF), the
   ATT&CK coverage, and the chain of custody: `forge ledger verify --pubkey <clé publique>` proves
   to a third party that nothing left the authorized scope.

A **100 % offline** end-to-end path (with a mock-Plume stub to *see* the purple
matrix without a real SOC) is detailed in [`GETTING_STARTED.md`](GETTING_STARTED.md).

## Enabling the purple loop later

No migration: plugging in a source **hot** is enough.

- **In the UI**: Administration → « Source de détection » (*Detection source*) → choose the `kind`, the endpoint, the auth
  (write-only), the MITRE mapping, **« Tester la connexion »** (*Test the connection*), **« Enregistrer »** (*Save*). The source is reloaded
  immediately. Model and presets: [`DETECTION.md`](DETECTION.md).
- **By env** (backward-compat/headless): `PLUME_URL` + `PLUME_TOKEN` (preset `kind=plume`), or
  `FORGE_DETECTION_SOURCE` (JSON for the rich kinds). See [Configuration §1.7](CONFIGURATION.md#17-purple-loop--detection-source-legacy--collector).

As soon as a source answers, the `detected/parent_approx/missed/MTTD` matrix appears on the techniques already fired —
the "red" half was already there.

## Standalone outside a program (own-infra / CTF / authorized pentest)

Forge does not require any "program": create a scope folder for any **authorized** target
(own-infra, lab, CTF, contracted engagement). The only prerequisite is **authorization** — the ROE gate
and the ledger are there to enforce it and prove it, not to bypass it. See the charter in
[`../LICENSE`](../LICENSE) and the engagement template [`REFERENCE_ENGAGEMENT_TEMPLATE.md`](REFERENCE_ENGAGEMENT_TEMPLATE.md).

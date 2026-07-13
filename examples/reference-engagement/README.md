# Forge — Bundled Reference Engagement (DEMO FIXTURE)

> ⚠️ **100% synthetic. Not a real target, not a real SOC.** Every host uses the RFC 2606
> reserved `.example` TLD and every IP uses an RFC 5737 documentation range. This folder ships
> with Forge so a fresh install is **demoable end-to-end, offline, with zero network I/O**.
> Nothing here was tested against a live system.

This is a small, realistic **own-lab engagement** — "ACME Retail (lab)" — used to populate a fresh
Forge console (Findings / Coverage / Purple / Runs) in one command, and as the sales/onboarding
walkthrough of what a Forge deliverable looks like.

## What's in here

| File | Role |
|---|---|
| `scope.json` | Authorized scope/ROE (grey-box, `allow_exploit=false`, `allow_destructive=false`). In-scope: `shop.lab.example`, `api.lab.example`, `lab.example`. Out-of-scope: `corp.internal.example`, `*.prod.example`. |
| `targets.json` | The three synthetic targets. |
| `findings.jsonl` | 6 findings across 5 ATT&CK techniques, with CWE / severity / status (IDOR, SSRF, permissive CORS, predictable reset token, origin exposure, missing headers). |
| `runrecords.jsonl` | 8 fired ATT&CK run-records (the red-team timeline). Drives the **Coverage** tab and the red side of the **Purple** join. |
| `roe_decisions.jsonl` | 11 governance decisions: 8 `FIRE` + 2 `VETO` (out-of-scope, exploit-not-armed) + 1 `DRY_RUN`. Feeds `/api/roe` (anti-masking transparency). |
| `detections.jsonl` | The **blue** side: 4 MITRE-tagged "SOC detections" served by the mock-Plume stub. Deliberately a *subset* of what was fired, so the matrix shows **detected AND missed** rows. |
| `REFERENCE_ENGAGEMENT.md` | A **filled** copy of [`docs/REFERENCE_ENGAGEMENT_TEMPLATE.md`](../../docs/REFERENCE_ENGAGEMENT_TEMPLATE.md) — the redacted lab-style write-up / deliverable. |

## The purple matrix this produces

Fired techniques (red, from `runrecords.jsonl`) joined with detections (blue, from `detections.jsonl`):

| ATT&CK | Fired | Detected | MTTD | Status |
|---|:---:|:---:|---|---|
| T1595 — Active Scanning | ✅ | ✅ | 4 min | 🟢 detected |
| T1046 — Network Service Discovery | ✅ | ✅ | 2.5 min | 🟢 detected |
| T1190 — Exploit Public-Facing App (IDOR + SSRF) | ✅ | ✅ | 3 min | 🟢 detected |
| T1212 — Exploitation for Credential Access | ✅ | ✅ | 6 min | 🟢 detected |
| T1590.005 — Gather Victim Network Info: IPs | ✅ | ❌ | — | 🔴 **missed** |
| T1595.002 — Vulnerability Scanning | ✅ | ❌ | — | 🔴 **missed** |
| T1539 — Steal Web Session Cookie (CORS) | ✅ | ❌ | — | 🔴 **missed** |

**7 techniques fired · 4 detected · 3 missed → detection rate 57% · MTTD avg ≈ 3.9 min, max 6 min.**

## How to run it

From the repo root (`GUATX/forge/`):

```bash
# Populated console (Findings / Coverage / Runs) — offline, no SOC needed:
make demo            # -> http://127.0.0.1:7100

# Full purple loop (adds the detected/missed/MTTD matrix) with the mock-Plume stub:
make demo-purple     # boots tools/mock_plume.py + console with PLUME_URL set
```

Under the hood `make demo` runs `forge seed-demo --dir examples/reference-engagement`,
which ingests these fixtures **directly into the SQLite DB** (`FORGE_CONSOLE_DB`, default
`forge-demo.db`) — no server round-trip, no network. It is **idempotent**: re-running only
touches the `acme-lab` demo campaign and never any real engagement data in the same DB.

You can also seed manually and point at any DB:

```bash
FORGE_CONSOLE_DB=my.db console/target/release/forge seed-demo --dir examples/reference-engagement
```

## Safety

- `allow_exploit=false` / `allow_destructive=false` in `scope.json` — the findings were obtained by
  **read-only verification** (cross-tenant IDOR *read*, out-of-band SSRF callback, credentialed CORS
  header probe). The two `VETO` rows in `roe_decisions.jsonl` show the scope-guard refusing an
  out-of-scope target and an unarmed exploit module; the `DRY_RUN` row shows an unapproved action
  simulated, never executed.
- `tools/mock_plume.py` is a **stdlib stub**, clearly labelled `DEMO FIXTURE` in every response
  (`_demo:true`, `_warning`, `X-Demo-Fixture` header). **Never** point a real engagement at it.

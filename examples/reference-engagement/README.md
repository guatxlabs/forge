# Forge — Bundled reference engagement (DEMO FIXTURE)

[English](README.md) | [Français](README.fr.md)

> ⚠️ **100 % synthetic. Not a real target, not a real SOC.** Every host uses the reserved
> `.example` TLD (RFC 2606) and every IP uses a documentation range (RFC 5737). This folder
> ships with Forge so that a fresh install is **demonstrable end to end, offline, with
> zero network I/O**. Nothing here was tested against a real system.

This is a small, realistic **home-lab engagement** — "ACME Retail (lab)" — used to populate a
fresh Forge console (Findings / Coverage / Purple / Runs) in a single command, and as a
sales/onboarding demonstration of what a Forge deliverable looks like.

## What is here

| File | Role |
|---|---|
| `scope.json` | Authorized scope/ROE (grey-box, `allow_exploit=false`, `allow_destructive=false`). In-scope: `shop.lab.example`, `api.lab.example`, `lab.example`. Out-of-scope: `corp.internal.example`, `*.prod.example`. |
| `targets.json` | The three synthetic targets. |
| `findings.jsonl` | 6 findings spread over 5 ATT&CK techniques, with CWE / severity / status (IDOR, SSRF, permissive CORS, predictable reset token, origin exposure, missing headers). |
| `runrecords.jsonl` | 8 fired ATT&CK run-records (the red-team timeline). Feeds the **Coverage** tab and the red side of the **Purple** join. |
| `roe_decisions.jsonl` | 11 governance decisions: 8 `FIRE` + 2 `VETO` (out-of-scope, unarmed exploit) + 1 `DRY_RUN`. Feeds `/api/roe` (anti-masking transparency). |
| `detections.jsonl` | The **blue** side: 4 MITRE-tagged "SOC detections", served by the mock-Plume stub. Deliberately a *subset* of what was fired, so that the matrix shows all **three** states — detected, parent-approx and missed. |
| `REFERENCE_ENGAGEMENT.md` | A **filled-in** copy of [`docs/REFERENCE_ENGAGEMENT_TEMPLATE.md`](../../docs/REFERENCE_ENGAGEMENT_TEMPLATE.md) — the write-up / deliverable written lab-style (redacted). |

## The purple matrix this produces

Fired techniques (red, from `runrecords.jsonl`) joined to the detections (blue, from `detections.jsonl`):

| ATT&CK | Fired | Detected | MTTD | Status |
|---|:---:|:---:|---|---|
| T1595 — Active Scanning | ✅ | ✅ exact | 4 min | 🟢 detected-exact |
| T1046 — Network Service Discovery | ✅ | ✅ exact | 2.5 min | 🟢 detected-exact |
| T1190 — Exploit Public-Facing App (IDOR + SSRF) | ✅ | ✅ exact | 3 min | 🟢 detected-exact |
| T1212 — Exploitation for Credential Access | ✅ | ✅ exact | 6 min | 🟢 detected-exact |
| T1595.002 — Vulnerability Scanning | ✅ | ⚠️ parent `T1595` only (3 alerts) | — | 🟠 **detected-parent-approx** |
| T1590.005 — Gather Victim Network Info: IPs | ✅ | ❌ | — | 🔴 **missed** |
| T1539 — Steal Web Session Cookie (CORS) | ✅ | ❌ | — | 🔴 **missed** |

**7 techniques fired · 4 detected-exact · 1 parent-approx · 2 missed → detection rate 57 % ·
avg MTTD 232.5 s (≈ 3.9 min), max 360 s (6 min).**

> Measured, not asserted: `forge seed-demo --dir examples/reference-engagement` + `tools/mock_plume.py`
> + `GET /api/purple/coverage` returns `techniques_fired=7, techniques_detected=4,
> techniques_parent_approx=1, techniques_missed=2, detection_rate=0.5714285714285714,
> mttd_avg_secs=232.5, mttd_max_secs=360`.
>
> **Read the T1595.002 row carefully** — it is the whole point of the three-state join. The SOC does alert on
> `T1595` (Active Scanning), and Forge fired the **sub-technique** `T1595.002` (Vulnerability Scanning).
> A parent rule is **not evidence** that the sub-technique's vector is covered, so it is **not** counted as
> detected: the rate stays **4/7**, and no MTTD is invented for it. It is not thrown away either — it is
> a **named blind spot**: *"you fired T1595.002; all you have is a generic T1595 rule."* This row is the
> deliverable. A two-state matrix would have shown it as a plain `missed`, hiding the fact that a neighboring
> rule exists and only needs tightening.

## How to run it

From the repository root:

```bash
# Populated console (Findings / Coverage / Runs) — offline, no SOC required:
make demo            # -> http://127.0.0.1:7100

# Full purple loop (adds the detected / parent-approx / missed / MTTD matrix) with the mock-Plume stub:
make demo-purple     # starts tools/mock_plume.py + console with PLUME_URL set
```

Under the hood, `make demo` runs `forge seed-demo --dir examples/reference-engagement`,
which ingests these fixtures **directly into the SQLite database** (`FORGE_CONSOLE_DB`, default
`forge-demo.db`) — no server round-trip, no network. It is **idempotent**: a re-run only
touches the `acme-lab` demo campaign and never any real engagement data in the same database.

You can also seed manually and point at any database:

```bash
FORGE_CONSOLE_DB=my.db console/target/release/forge seed-demo --dir examples/reference-engagement
```

## Safety

- `allow_exploit=false` / `allow_destructive=false` in `scope.json` — the findings were obtained by
  **read-only verification** (cross-tenant IDOR *read*, out-of-band SSRF callback, CORS header
  probe with credentials). The two `VETO` rows of `roe_decisions.jsonl` show the scope-guard refusing an
  out-of-scope target and an unarmed exploit module; the `DRY_RUN` row shows an unapproved action
  simulated, never executed.
- `tools/mock_plume.py` is a **stdlib stub**, clearly labeled `DEMO FIXTURE` in every response
  (`_demo:true`, `_warning`, `X-Demo-Fixture` header). **Never** point a real engagement at it.

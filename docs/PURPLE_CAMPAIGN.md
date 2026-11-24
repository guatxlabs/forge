# Runbook — "broad-recon" purple campaign (template)

[English](PURPLE_CAMPAIGN.md) | [Français](PURPLE_CAMPAIGN.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Plume prerequisites](PURPLE_PREREQS.md) · [CLI reference](CLI.md) · [MTTD](MTTD.md)

> **Status: TEMPLATE — nothing runs by reading it.** To be launched only on the operator's explicit
> "go", and only against a target **for which you have written authorisation**. This document
> defines a broad **RECON-ONLY** campaign (more techniques fired → richer purple matrix,
> with visible gaps). The examples use the documentation domain `lab.example`:
> replace it with **your** authorised target. The runbook modifies **nothing** by itself: neither
> `scope.json`, nor the environment.

## 1. Goal

The purple loop measures "technique T fired → detected by Plume?" by equality of **technique** —
multi-technique tags split on both sides (cf. [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md)). A
campaign rich in **recon/non-exploit** techniques fires a range of distinct ATT&CK techniques (T1595,
T1046, T1595.002, T1590.005, T1556) without crossing the high-impact barrier. Expected result: a
coverage matrix with **three** cells — **detected** (the source alerts on exactly this
technique; the only cell counted in the rate and the MTTD), **parent_approx** (fired sub-technique of which
only the **parent** technique is covered: a named blind spot, not a proven detection),
**missed** (technique fired, no correlated detection) — and per-technique MTTDs: exactly the
purple deliverable. A campaign that fires sub-techniques (`T1595.002`, `T1110.001`) while the SOC
only has generic rules (`T1595`, `T1110`) fills the **parent_approx** column: it is the
most compelling finding of the report, and it would be invisible with a two-state matrix.

Step 1 (this runbook) = **PREP + seeding the MTTD matrix**. The high-impact evidence-backed oracles
(IDOR/SSRF/auth/CORS) stay **DRY_RUN/VETO** here (see §6) and will only fire on a separate
high-impact opt-in, outside this campaign.

## 2. Recon / non-exploit modules to include (the ones that FIRE in recon-only)

In recon-only, the ROE authorises at most DRY_RUN for any `exploit=True` action. Only
`exploit=False` modules can reach FIRE (subject to arming + approval/auto mode). The list
below = the modules **that will actually fire** in this campaign and their ATT&CK technique:

| `kind`               | exploit | ATT&CK     | What is fired (recon-only)                                               |
|----------------------|---------|------------|--------------------------------------------------------------------------|
| `recon.httpx`        | no      | T1595      | HTTP fingerprint: status, title, detected technologies.                  |
| `recon.nmap`         | no      | T1046      | Discovery of exposed services (`nmap -sV -Pn`, top 1000 ports).          |
| `web.nuclei`         | no      | T1595.002  | Nuclei template scan (medium/high/critical by default).                  |
| `origin.find`        | no      | T1590.005  | Origin IP behind the CDN (subfinder→DNS→drop-CF→Host-header check).      |
| `evasion.xhr`        | no      | T1190      | Observation of XHR requests via the browser-automation session.          |
| `evasion.turnstile`  | no      | T1556      | Attempt to get past the interactive Turnstile (vision-click-os).         |

Notes:
- `evasion.*` is only fired if the **browser automation service** (port 8080) answers; otherwise
  the module auto-neutralises (`available=False`) and is never fired. The report says so
  explicitly: the technique appears as **not attempted**, never as "tested with no result".
- `recon.nmap` / `recon.httpx` / `web.nuclei` / `origin.find` require the binary **OR** the matching Docker
  image. Check with `forge doctor` before the "go". An unavailable module ⇒
  no action fired ⇒ the matching cell is counted **neither** as detected nor as
  missed: it is **not attempted** in the matrix (this is the anti-masking discipline, not an
  error).
- The techniques `evasion.turnstile` (T1556) and `evasion.xhr`/`evasion.idor_intercept` (T1190)
  share the "access enabler" idea — getting past Cloudflare **is not** a vulnerability, just access.

## 3. EXACT command (copy-pastable) — to run at the "go" only

> ⚠️ DO NOT RUN this command until the operator has said "go". It assumes a
> **recon-only** scope (`allow_exploit=false`, `allow_destructive=false`) listing your authorised target, and
> a reachable console.

```bash
# The console token is passed through an env variable (never in argv — argv is visible to other
# local users). console_client reads FORGE_CONSOLE_TOKEN as a fallback when --console-token is absent.
export FORGE_CONSOLE_TOKEN='<token-ingest-console>'

python3 -m forge.cli campaign \
    --scope    "$SCOPE" \
    --targets  "$TARGETS" \
    --modules  recon.httpx,recon.nmap,web.nuclei,origin.find,evasion.xhr,evasion.turnstile \
    --mode     auto \
    --arm \
    --reason   'purple-lab-large recon-only : amorce matrice MTTD sur lab.example (autorisé)' \
    --console       http://127.0.0.1:7100 \
    --console-token "$FORGE_CONSOLE_TOKEN" \
    --campaign purple-lab-large \
    --purple   runs/purple-lab-large.jsonl \
    --ledger   runs/purple-lab-large.ledger.jsonl \
    --report   runs/purple-lab-large.report.md
```

Where:
- `SCOPE` = path to a **recon-only** scope listing your authorised in-scope target (see §4 —
  documentation example; **do not** overwrite a `scope.json` in service).
- `TARGETS` = path to a targets file (see §5 — documentation example).
- `--mode auto` + `--arm`: needed to reach FIRE without approving each action one by one
  (ROE layer 4). Stays fail-closed on scope (layer 2) and capability (layer 3).
- `--modules`: RESTRICTS the brain's plan to the listed kinds. All are `exploit=False` → they
  can FIRE in recon-only; no impact oracle is included (see §6).
- `--purple <fichier>`: emits the ATT&CK run-records (JSONL) ingestible by Plume.
- `--console …`: pushes findings + run-records + coverage to the console (MTTD JOIN on the console side).

### Techniques expected when firing

`T1595` (httpx), `T1046` (nmap), `T1595.002` (nuclei), `T1590.005` (origin.find), `T1190`
(evasion.xhr), `T1556` (evasion.turnstile, if browser-automation is reachable). Each shot produces a
`mitre`-tagged run-record → the purple matrix correlates these techniques against the Plume detections.

## 4. Recon-only scope example (DOC — do not overwrite the live one)

> Write it to a **separate** file (e.g. `runs/scope.purple-lab-large.json`) and pass it via
> `--scope`. **Do not touch** `scope.json`.

```json
{
  "_comment": "Scope DOC recon-only pour la campagne purple-lab-large — lab.example autorisé.",
  "mode": "grey",
  "in_scope": ["lab.example"],
  "out_scope": [],
  "rate": 5,
  "allow_exploit": false,
  "allow_destructive": false,
  "known_creds": [],
  "idor_targets": [],
  "notes": "Recon-only. allow_exploit/destructive restent false : les oracles d'impact ne peuvent que DRY_RUN/VETO."
}
```

## 5. Targets file example (DOC — do not overwrite the live one)

> Write it to a **separate** file (e.g. `runs/targets.purple-lab-large.json`) and pass it via
> `--targets`. Each target requires `host`; `kind`/`attrs` are optional.

```json
[
  { "host": "lab.example", "kind": "app", "attrs": { "service": "http" } }
]
```

`kind: "app"` + `service: "http"` steers the brain (`HeuristicBrain`) towards the web classes
(recon + scan). The coverage-safe planner guarantees that no qualifying class is starved even
if the brain under-rates it — but here `--modules` already bounds the plan to recon/non-exploit kinds.

## 6. The impact oracles stay DRY_RUN / VETO (recon-only)

These modules are `exploit=True` (and sometimes `destructive=True`). In recon-only (`allow_exploit=false`),
ROE layer 3 puts them in **VETO** if they are proposed while armed, or they stay in **DRY_RUN**
(simulation, generates the PoC, fires nothing). **They are not in `--modules` above** and will
therefore produce no shot in this campaign:

| `kind`                   | exploit | destructive | ATT&CK | Why not in recon-only                                    |
|--------------------------|---------|-------------|--------|----------------------------------------------------------|
| `access_control.idor`    | yes     | no (GET)    | T1190  | Accesses another user's object → `allow_exploit`.        |
| `ssrf.callback`          | yes     | no          | T1190  | Causes an outbound request from the target → `allow_exploit`. |
| `auth.takeover`          | yes     | yes         | T1212  | Takes over an account → `allow_exploit`/`destructive`.   |
| `cors.credentials`       | yes     | no          | T1539  | Authenticated cross-origin read → `allow_exploit`.       |
| `evasion.idor_intercept` | yes     | no          | T1190  | In-flight identifier tampering → `allow_exploit`.        |

These oracles will only fire with a distinct **high-impact opt-in** (scope `allow_exploit=true`,
or even `allow_destructive=true` for `auth.takeover`/IDOR-write), on a separate campaign — **outside
the scope of this runbook**. As long as this opt-in is not set, they stay fail-closed.

## 7. Pre-flight (at the "go")

1. `forge doctor` → check which modules from §2 are OPERATIONAL (an unavailable module =
   technique **not attempted** in the matrix, to be documented as such).
2. Confirm that the target is in scope in the scope passed via `--scope` (`forge scope-check
   lab.example --scope "$SCOPE"` must say IN SCOPE).
3. Confirm Plume reachability + auth on the console side (cf. `PURPLE_PREREQS.md` §5) so that the MTTD
   JOIN works.
4. Run the §3 command, then read `runs/purple-lab-large.report.md` + the coverage matrix
   on the console side (`/api/purple/coverage`).

## ⚠️ Safety

- **Recon-only**: no impact module in `--modules`. The ROE stays fail-closed (scope + capability).
- **Do not** overwrite the live `scope.json` / `targets.json`: use separate DOC files (§4–§5).
- Firing techniques = **only** at a target whose authorisation is written. ROE / scope hard.
- The console token goes through `FORGE_CONSOLE_TOKEN` (env), never in plaintext in the shell history.

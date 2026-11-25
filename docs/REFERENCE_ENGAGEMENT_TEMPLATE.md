# Forge — Reference engagement write-up (TEMPLATE)

[English](REFERENCE_ENGAGEMENT_TEMPLATE.md) | [Français](REFERENCE_ENGAGEMENT_TEMPLATE.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Concepts](CONCEPTS.md) · [Positioning](POSITIONING.md) · [Plume prerequisites](PURPLE_PREREQS.md)

> **Goal**: this skeleton becomes Forge's **commercial evidence**. To be filled in **after the 1st
> live purple campaign** (cf. [`PLAN.md`](PLAN.md) Step 1 + [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md)).
> The closing message that sells: *"Your SOC missed N techniques. Here is which ones, and how to close the gaps."*
>
> ⚠️ **Authorised framework only.** Only fill it in from an engagement that was actually scoped and
> authorised in writing. No unauthorised target, ever. (Takes up the charter of the Forge LICENSE.)

---

## 0. Header

| Field | Value |
|---|---|
| Client / programme | [name] |
| Engagement type | [bug bounty in-scope · pentest under contract · own-infra lab] |
| Period | [start] → [end] |
| Forge operator(s) | [identity / seat] |
| Authorisation reference | [contract no. / written agreement] |
| Ledger fingerprint (root hash) | [sha256 of the last entry — verifiable] |
| Verification public key | [Ed25519 public key for `verify_external`] |

---

## 1. Context & authorised scope

- **Business objective** of the engagement: [what the client wanted to validate].
- **`in_scope` perimeter** (verbatim from `scope.json`): [hosts / domains / apps].
- **`out_scope`** (explicit exclusions): [...].
- **Armed capabilities**: `allow_exploit = <true/false>` · `allow_destructive = <true/false>` ·
  `mode = <grey/black/white>` · `rate = <n>`.
- **Window & constraints**: [hours, NTP synchronised for the MTTD, host monitored by Plume].

> Fill in from the engagement's real `scope.json` (never paste a secret/private key here).

---

## 2. Techniques fired (timeline)

One row per action that ended in a `FIRE` verdict (the `DRY_RUN` / `VETO` appear in the
anti-masking section §6). Source = the campaign's run-records + ledger.

| # | Timestamp (`ts_fired`) | Module (kind) | ATT&CK | Target | ROE verdict | Ledger ref. |
|---|---|---|---|---|---|---|
| 1 | [epoch/ISO] | `recon.httpx` | T1595 | [host] | FIRE | [entry hash] |
| 2 | [...] | `recon.nmap` | T1046 | [...] | FIRE | [...] |
| 3 | [...] | `web.nuclei` | T1595.002 | [...] | FIRE | [...] |
| 4 | [...] | `access_control.idor` | T1190 | [...] | FIRE | [...] |
| … | | | | | | |

---

## 3. PURPLE coverage matrix (the heart of the deliverable)

Read-only JOIN between the Forge run-records (`{mitre: T}`) and the Plume detections
(`GET {PLUME_URL}/api/coverage/detections`). MTTD = `first_ts` (Plume alert) − `ts_fired` (Forge).

| ATT&CK technique | Fired by Forge | Detected by the SOC (Plume) | MTTD | Status |
|---|:---:|:---:|---|---|
| T1595 — Active Scanning | ✅ | ✅ | [X min] | 🟢 detected |
| T1046 — Network Service Discovery | ✅ | ✅ | [X min] | 🟢 detected |
| T1595.002 — Vuln Scanning | ✅ | ❌ | — | 🔴 **missed** |
| T1190 — Exploit Public-Facing App | ✅ | ✅ | [X min] | 🟢 detected |
| T1210 — Exploit Remote Services | ✅ | ❌ | — | 🔴 **missed** |
| … | | | | |

**Coverage summary**:
- Techniques fired: **[M]**
- Detected: **[D]** → **coverage = [D/M %]**
- Missed: **[N]** → *(see §7 "how to close the gaps")*
- **Median MTTD** (over the detected ones): **[X min]**

> This table is the native output of the purple loop (`/api/purple/coverage`). It is the argument
> that no offensive tool alone produces: the SOC's **real** detection rate, measured, not estimated.

---

## 4. Findings with evidence

For each finding reported (the console's red store). No over-classification: a `reported_by_tool`
stays `reported_by_tool` as long as there is no evidence of exploitability.

### Finding [#] — [title]
- **Severity**: [`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`] · **ATT&CK**: [Txxxx] · **Module**: [kind]
- **Target**: [host/endpoint]
- **Status**: [`reported_by_tool` · `vulnerable` (evidence)]
- **Evidence**: [tool output / verified PoC / capture] (ledger ref.: [entry hash])
- **Detected by the SOC?**: [yes (MTTD X) / no — see §3]
- **Suggested remediation**: [technical fix]

*(Repeat per finding.)*

---

## 5. Chain of custody — the signed ledger

The credibility of this whole write-up rests on this: **every action is in a signed ledger,
verifiable by a third party without trusting the operator**.

- **Internal integrity**: `forge ledger verify --ledger <engagement>.jsonl` → [OK / root hash].
- **Third-party verification**: `verify_external(<pubkey>)` → the auditor validates the Ed25519 chain with the
  **public key alone** (they can neither forge nor alter). Result: [OK].
- **Ledger coverage**: [n] chained entries = **all** the ROE decisions (FIRE, DRY_RUN,
  VETO), per-entry MAC (not only at checkpoints).
- **Custody — honest note**: local private key on this engagement; off-host anchoring (remote co-signing
  witness, `anchor.py`) = [enabled / not enabled].

> **Argument**: "You do not have to believe us. Here is the public key. Check for yourself that
> nothing was fired outside the scope you authorised, and that the log has not been rewritten."

---

## 6. Anti-masking — what was NOT fired

Transparency section (carried over from the section that `report.py` produces). An honest report also lists the gaps: zero
silent gap.

- **`DRY_RUN`** (simulated, never executed — capability not armed or not approved): [list].
- **`VETO`** (refused by the gate — out of scope, forbidden capability, fail-closed evaluation error):
  [list + reason].
- **Classes never attempted** (budget / out of scope / outside the charter): [list].
- **Not tested (time budget)**: [list].

---

## 7. Value delivered — "here is how to close the gaps"

The conclusion that turns the matrix into a purchasing decision.

1. **Detection gaps**: "Your SOC missed **[N]** techniques: [T1595.002, T1210, …]."
   For each one → **missing rule / log source** on the Plume side (cf. the
   [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) checklist: `rule.mitre` to tag, log sources to plug in).
2. **MTTD to reduce**: techniques detected but slow (MTTD > [threshold]) → [rule prioritisation /
   correlation].
3. **Posture after remediation**: coverage projection if the [N] gaps are closed →
   "go from **[D/M %]** to **[target %]**".
4. **Next campaign**: re-fire the missed techniques after the fix → **prove** the
   gap is closed (purple loop in continuous improvement).

> **The closing pitch**: *"This engagement cost you a signed, verifiable scope, and gave
> you back a figure you did not have: your SOC sees [D/M %] of the techniques, in [MTTD] min.
> Here are the [N] rules to add. We re-fire on the next run to prove it is closed."*

---

*See also: [`POSITIONING.md`](POSITIONING.md) ·
[`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) (Plume prerequisites for §3).*

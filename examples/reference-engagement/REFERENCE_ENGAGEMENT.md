# Forge — Reference engagement write-up (ACME Retail lab)

[English](REFERENCE_ENGAGEMENT.md) | [Français](REFERENCE_ENGAGEMENT.fr.md)

> **This is a FILLED-IN, REDACTED, LAB-STYLE example** of
> [`docs/REFERENCE_ENGAGEMENT_TEMPLATE.md`](../../docs/REFERENCE_ENGAGEMENT_TEMPLATE.md).
> It is the sales/onboarding artifact: "here is what a Forge deliverable looks like". All data is
> **100 % synthetic** (RFC 2606 `.example` hosts, RFC 5737 documentation IPs). No real system was
> touched. It is the human-readable counterpart of the machine fixtures in this folder, which
> `make demo` / `make demo-purple` load into the console.
>
> The sentence that sells it all: *"Your SOC saw 4 of the 7 techniques we fired. One more, it only sees
> through a generic parent rule. Here they are, and here is how to close them."*

---

## 0. Header

| Field | Value |
|---|---|
| Client / program | ACME Retail — **internal lab** (synthetic) |
| Engagement type | lab on in-house infra (authorized, written self-authorization) |
| Period | 2026-06-26 12:00 → 12:30 UTC |
| Forge operator(s) | `lab-operator` (demo) |
| Authorization ref. | `LAB-SELF-AUTH-2026-06` (in-house infrastructure) |
| Ledger root hash | [computed at run time — verifiable via `forge ledger verify`] |
| Verification public key | [Ed25519 public key for `verify_external` — redacted in this sample] |

---

## 1. Context & authorized scope

- **Business objective**: measure what share of a realistic web red-team chain the lab's SOC actually
  detects, and how fast — before running it for real against production.
- **`in_scope`** (verbatim from `scope.json`): `shop.lab.example`, `api.lab.example`, `lab.example`.
- **`out_scope`** (explicit exclusions): `corp.internal.example`, `*.prod.example`.
- **Armed capabilities**: `allow_exploit = false` · `allow_destructive = false` · `mode = grey` ·
  `rate = 5`.
- **Window & constraints**: 30-minute window, hosts monitored by the lab's Plume SOC, NTP-synchronized for
  MTTD. Findings obtained by **read-only verification only** (no exploitation, no data destruction).

---

## 2. Fired techniques (timeline)

One row per action that reached a `FIRE` verdict. Source = run-records + ROE decisions (see
`runrecords.jsonl` / `roe_decisions.jsonl`). `VETO` / `DRY_RUN` are in §6 (anti-masking).

| # | Timestamp (UTC) | Module (kind) | ATT&CK | Target | ROE verdict |
|---|---|---|---|---|---|
| 1 | 12:00:00 | `recon.httpx` | T1595 | shop.lab.example | FIRE |
| 2 | 12:01:00 | `origin.find` | T1590.005 | lab.example | FIRE |
| 3 | 12:03:00 | `recon.nmap` | T1046 | shop.lab.example | FIRE |
| 4 | 12:07:00 | `web.nuclei` | T1595.002 | shop.lab.example | FIRE |
| 5 | 12:12:00 | `access_control.idor` | T1190 | api.lab.example | FIRE |
| 6 | 12:15:00 | `ssrf.callback` | T1190 | api.lab.example | FIRE |
| 7 | 12:18:00 | `cors.credentials` | T1539 | shop.lab.example | FIRE |
| 8 | 12:20:00 | `auth.takeover` | T1212 | shop.lab.example | FIRE |

---

## 3. PURPLE coverage matrix (the central deliverable)

Read-only JOIN between the Forge run-records (`{mitre}`, `fired=1`) and the Plume detections
(`GET {PLUME_URL}/api/coverage/detections`), on the **techniques** (multi-technique tags split on both
sides). MTTD = `first_ts (alerte Plume) − ts_fired (Forge)`, computed against the **most recent** shot
of each technique, and sampled on **exact** detections only.

| ATT&CK technique | Fired | Detected (SOC) | MTTD | Status |
|---|:---:|:---:|---|---|
| T1595 — Active Scanning | ✅ | ✅ exact | 4 min | 🟢 detected-exact |
| T1046 — Network Service Discovery | ✅ | ✅ exact | 2.5 min | 🟢 detected-exact |
| T1190 — Exploit Public-Facing App | ✅ | ✅ exact | 3 min | 🟢 detected-exact |
| T1212 — Exploitation for Credential Access | ✅ | ✅ exact | 6 min | 🟢 detected-exact |
| T1595.002 — Vulnerability Scanning | ✅ | ⚠️ parent `T1595` only (3 alerts) | — | 🟠 **detected-parent-approx** |
| T1590.005 — Gather Victim Network Info: IP Addresses | ✅ | ❌ | — | 🔴 **missed** |
| T1539 — Steal Web Session Cookie | ✅ | ❌ | — | 🔴 **missed** |

**Coverage summary** (matches the live output of `/api/purple/coverage` for this seed):
- Techniques fired: **7**
- **Exactly** detected: **4** → **coverage = 57 %**
- **Parent-approx**: **1** (T1595.002) → *not* counted in the rate, no invented MTTD — a **named
  blind spot**, see §7
- Missed: **2** → *(see §7 "how to close")*
- **MTTD**: avg **232.5 s (3.9 min)**, max **360 s (6 min)** over the **exactly** detected techniques.

> This table is the native output of the purple loop (`/api/purple/coverage`). It is the argument that no
> offensive tool alone produces: the **real, measured** SOC detection rate — not an estimate.
>
> **Why T1595.002 is orange and not green.** The SOC does alert on `T1595`, and Forge fired the
> sub-technique `T1595.002`. Calling that "detected" would be a claim we cannot back up: a parent rule
> says nothing about the **vector** it covers, and the MTTD would date the vuln-scan shot against an
> unrelated alert. It therefore stays out of the rate and out of the MTTD. Nor is it silently discarded
> — a plain `missed` would have hidden the useful fact that a neighboring rule already exists and only needs
> tightening. Three states, because two would have to lie one way or the other.

---

## 4. Findings with evidence

Source = the red store (`findings.jsonl`). No over-classification: an SSRF that only produced an
out-of-band callback stays `reported_by_tool` as long as exploitability is not proven.

### Finding 1 — IDOR: order invoices readable across tenants
- **Severity**: HIGH · **ATT&CK**: T1190 · **CWE-639** · **Module**: `access_control.idor`
- **Target**: `api.lab.example` — `/api/orders/{id}/invoice`
- **Status**: `vulnerable` (cross-tenant read proven)
- **Evidence**: test tenant B (uid=1042) retrieved tenant A's invoice PDF (order 5581), HTTP 200 — no
  ownership check on the object id.
- **Detected by the SOC?**: yes, as T1190 (MTTD 3 min — see §3).
- **Fix**: server-side ownership check on every object reference (deny-by-default).

### Finding 2 — SSRF: the image proxy fetches the attacker's URL
- **Severity**: HIGH · **ATT&CK**: T1190 · **CWE-918** · **Module**: `ssrf.callback`
- **Target**: `api.lab.example` — `/api/proxy?url=`
- **Status**: `reported_by_tool` (OOB callback only; cloud metadata returned 403 — not escalated)
- **Evidence**: out-of-band callback from the egress in under 1.2 s; `169.254.169.254` blocked (403).
- **Detected by the SOC?**: yes, folded into the T1190 detection.
- **Fix**: strict host/scheme allowlist; block internal IPs and metadata endpoints.

### Finding 3 — Permissive CORS with credentials
- **Severity**: MEDIUM · **ATT&CK**: T1539 · **CWE-942** · **Module**: `cors.credentials`
- **Target**: `shop.lab.example` — `/api/account`
- **Status**: `vulnerable`
- **Evidence**: `Access-Control-Allow-Origin` reflects an arbitrary Origin **and**
  `Access-Control-Allow-Credentials: true` — credentialed cross-origin read of the session profile.
- **Detected by the SOC?**: **no** — 🔴 missed (see §7).
- **Fix**: never reflect an arbitrary Origin with credentials; exact allowlist only.

### Finding 4 — Predictable password reset token
- **Severity**: CRITICAL · **ATT&CK**: T1212 · **CWE-287** · **Module**: `auth.takeover`
- **Target**: `shop.lab.example`
- **Status**: `reported_by_tool` (a test victim's token guessed; no real account affected)
- **Evidence**: reset tokens are zero-padded counters; guessed in ~300 attempts, no rate limit, no
  expiry → full account takeover.
- **Detected by the SOC?**: yes, as T1212 (MTTD 6 min — the slowest detection).
- **Fix**: single-use CSPRNG tokens with short expiry + rate limiting on the reset endpoint.

### Finding 5 — Origin IP exposed behind the CDN
- **Severity**: LOW · **ATT&CK**: T1590.005 · **CWE-200** · **Module**: `origin.find`
- **Target**: `lab.example`
- **Status**: `tested` (information disclosure only)
- **Evidence**: a historical A record + a shared certificate SAN reveal the origin `203.0.113.24`, bypassing the
  CDN's WAF.
- **Detected by the SOC?**: **no** — 🔴 missed (passive, hence expected — see §7).
- **Fix**: rotate the origin IP, restrict the origin to the CDN's egress ranges, clean up the DNS/certificate history.

### Finding 6 — Missing security headers + outdated jQuery
- **Severity**: LOW · **ATT&CK**: T1595.002 · **CWE-693** · **Module**: `web.nuclei`
- **Target**: `shop.lab.example`
- **Status**: `tested`
- **Evidence**: no CSP/HSTS; jQuery 1.12.4 served (known DOM-XSS sinks).
- **Detected by the SOC?**: **not on this sub-technique** — 🟠 parent-approx: the SOC alerts on the parent
  `T1595` (Active Scanning, 3 alerts) but has no rule for `T1595.002` (Vulnerability Scanning). Not
  counted as detected (see §3, §7).
- **Fix**: add CSP + HSTS, update the front-end libraries.

---

## 5. Chain of custody — the signed ledger

The credibility of this write-up rests on this: **every action is in a signed, chained ledger,
verifiable by a third party who does not trust the operator**.

- **Internal integrity**: `forge ledger verify --ledger acme-lab.jsonl` → [OK / root hash].
- **Third-party verification**: `verify_external(<pubkey>)` — the auditor validates the Ed25519 chain
  with the **public key alone** (can neither forge nor alter). Result: [OK].
- **Ledger coverage**: [n] chained entries = **all** ROE decisions (8 FIRE, 1 DRY_RUN, 2 VETO),
  per-entry MAC (not only at checkpoints).
- **Custody note (honest)**: local private key for this lab; off-host anchoring (remote co-signing
  witness, `anchor.py`) = *not enabled* in this sample.

> **The argument**: "You do not have to trust us. Here is the public key. Check for yourself that nothing
> was fired outside the scope you authorized, and that the log was not rewritten."

---

## 6. Anti-masking — what was NOT fired

Honest reporting also lists the gaps — zero silent holes. Source = `roe_decisions.jsonl` + the
run_job's `coverage_gaps` / `skipped_budget`.

- **`DRY_RUN`** (simulated, never executed): `web.sqli` on `shop.lab.example` — not approved by
  the operator.
- **`VETO`** (refused by the gate): `access_control.idor` on `corp.internal.example` (out of scope,
  fail-closed scope-guard); `msf.module` on `api.lab.example` (`allow_exploit=false` — exploitation
  requires a written high-impact opt-in).
- **Classes never attempted**: SQL injection (`injection.sqli`) on `shop.lab.example` — deferred.
- **Not tested (time budget)**: stored XSS (`web.xss`) on `shop.lab.example` — deferred, not dropped.

---

## 7. Value delivered — "here is how to close"

The conclusion that turns the matrix into a decision.

1. **Detection gaps**: "Your SOC missed **2** techniques outright (**T1590.005, T1539**) and covers a
   third one (**T1595.002**) only through its generic parent rule."
   - **T1539 (permissive CORS / cookie theft)** — highest priority: maps to a MEDIUM finding with
     a real cross-origin impact and no detection. Add a rule on responses with an abnormal reflected `Origin`
     / credentialed CORS on `/api/*`.
   - **T1595.002 (vuln scanning)** — 🟠 *parent-approx*, the cheapest win on the board: your `T1595` rule
     already fires on this traffic, it is simply not specific to template scanning. Tighten/duplicate it
     into a `T1595.002` rule (template-scan signatures, bursts of 4xx) and the row turns green — no
     new telemetry required.
   - **T1590.005 (passive IP gathering)** — expected blind spot (no traffic to detect); mitigate at
     the asset level (rotate the origin, clean up the DNS/certificate history) rather than through a SOC rule.
2. **MTTD to reduce**: T1212 (reset-token brute force) detected but the slowest at **6 min** — add a
   dedicated rate/velocity rule on the reset endpoint to bring it under target.
3. **Posture after remediation**: closing T1539 + tightening the parent rule into a real `T1595.002` rule
   moves the measured coverage from **57 %** (4/7) to **≈ 86 %** (6/7) — and the parent-approx row
   disappears, since it becomes a proven detection instead of an assumed one.
4. **Next campaign**: re-fire the missed techniques after the rules are deployed → **prove** that the gap is
   closed (continuous-improvement purple loop).

> **Closing pitch**: *"This engagement cost you a signed, verifiable scope, and handed you a number
> you did not have: your SOC *provably* sees 57 % of the techniques we fired, in ~4 minutes — plus one
> more that it only covers through a generic parent rule, which we do not count for you. Here are the 3 rules
> to add. We re-fire on the next run to prove it is closed."*

---

*See also: [`docs/POSITIONING.md`](../../docs/POSITIONING.md) ·
[`docs/PURPLE_PREREQS.md`](../../docs/PURPLE_PREREQS.md) · [`docs/MTTD.md`](../../docs/MTTD.md).*

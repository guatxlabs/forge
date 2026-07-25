# Forge — Reference Engagement Write-up (ACME Retail lab)

> **This is a FILLED, REDACTED, LAB-STYLE example** of
> [`docs/REFERENCE_ENGAGEMENT_TEMPLATE.md`](../../docs/REFERENCE_ENGAGEMENT_TEMPLATE.md).
> It is the sales/onboarding artifact: "here is what a Forge deliverable looks like." All data is
> **100% synthetic** (RFC 2606 `.example` hosts, RFC 5737 documentation IPs). No real system was
> touched. It is the human-readable companion to the machine fixtures in this folder, which
> `make demo` / `make demo-purple` load into the console.
>
> The one line that sells it: *"Your SOC missed 3 of the 7 techniques we fired. Here they are, and
> here is how to close them."*

---

## 0. Header

| Field | Value |
|---|---|
| Client / program | ACME Retail — **internal lab** (synthetic) |
| Engagement type | own-infra lab (authorized, written self-authorization) |
| Period | 2026-06-26 12:00 → 12:30 UTC |
| Forge operator(s) | `lab-operator` (demo) |
| Authorization ref | `LAB-SELF-AUTH-2026-06` (own infrastructure) |
| Ledger root hash | `<computed at run time — verifiable via forge ledger verify>` |
| Verification public key | `<Ed25519 pubkey for verify_external — redacted in this sample>` |

---

## 1. Context & authorized scope

- **Business objective**: measure how much of a realistic web red-team chain the lab SOC actually
  detects, and how fast — before running it for real against production.
- **`in_scope`** (verbatim from `scope.json`): `shop.lab.example`, `api.lab.example`, `lab.example`.
- **`out_scope`** (explicit exclusions): `corp.internal.example`, `*.prod.example`.
- **Armed capabilities**: `allow_exploit = false` · `allow_destructive = false` · `mode = grey` ·
  `rate = 5`.
- **Window & constraints**: 30-minute window, hosts monitored by the lab Plume SOC, NTP-synced for
  MTTD. Findings obtained by **read-only verification only** (no exploitation, no data destruction).

---

## 2. Techniques fired (timeline)

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

## 3. PURPLE coverage matrix (the core deliverable)

Read-only JOIN between Forge run-records (`{mitre}`, `fired=1`) and Plume detections
(`GET {PLUME_URL}/api/coverage/detections`). MTTD = `first_ts (Plume alert) − ts_fired (Forge)`,
computed against the **most recent** fire of each technique.

| ATT&CK technique | Fired | Detected (SOC) | MTTD | Status |
|---|:---:|:---:|---|---|
| T1595 — Active Scanning | ✅ | ✅ | 4 min | 🟢 detected |
| T1046 — Network Service Discovery | ✅ | ✅ | 2.5 min | 🟢 detected |
| T1190 — Exploit Public-Facing App | ✅ | ✅ | 3 min | 🟢 detected |
| T1212 — Exploitation for Credential Access | ✅ | ✅ | 6 min | 🟢 detected |
| T1590.005 — Gather Victim Network Info: IP Addresses | ✅ | ❌ | — | 🔴 **missed** |
| T1595.002 — Vulnerability Scanning | ✅ | ❌ | — | 🔴 **missed** |
| T1539 — Steal Web Session Cookie | ✅ | ❌ | — | 🔴 **missed** |

**Coverage summary** (matches the live `/api/purple/coverage` output for this seed):
- Techniques fired: **7**
- Detected: **4** → **coverage = 57%**
- Missed: **3** → *(see §7 "how to close")*
- **MTTD**: avg ≈ **232 s (3.9 min)**, max **360 s (6 min)** over the detected techniques.

> This table is the native output of the purple loop (`/api/purple/coverage`). It is the argument no
> offensive tool alone produces: the **real, measured** SOC detection rate — not an estimate.

---

## 4. Findings with evidence

Source = the red store (`findings.jsonl`). No over-classification: an SSRF that only produced an
out-of-band callback stays `reported_by_tool` until exploitability is proven.

### Finding 1 — IDOR: order invoices readable across tenants
- **Severity**: HIGH · **ATT&CK**: T1190 · **CWE-639** · **Module**: `access_control.idor`
- **Target**: `api.lab.example` — `/api/orders/{id}/invoice`
- **Status**: `vulnerable` (proven cross-tenant read)
- **Evidence**: test tenant B (uid=1042) fetched tenant A's invoice PDF (order 5581), HTTP 200 — no
  ownership check on the object id.
- **Detected by SOC?**: yes, as T1190 (MTTD 3 min — see §3).
- **Fix**: server-side ownership check on every object reference (deny-by-default).

### Finding 2 — SSRF: image proxy fetches attacker URL
- **Severity**: HIGH · **ATT&CK**: T1190 · **CWE-918** · **Module**: `ssrf.callback`
- **Target**: `api.lab.example` — `/api/proxy?url=`
- **Status**: `reported_by_tool` (OOB callback only; cloud metadata returned 403 — not escalated)
- **Evidence**: out-of-band callback from the egress within 1.2 s; `169.254.169.254` blocked (403).
- **Detected by SOC?**: yes, folded into T1190 detection.
- **Fix**: strict allowlist of hosts/schemes; block internal IPs and metadata endpoints.

### Finding 3 — Permissive CORS with credentials
- **Severity**: MEDIUM · **ATT&CK**: T1539 · **CWE-942** · **Module**: `cors.credentials`
- **Target**: `shop.lab.example` — `/api/account`
- **Status**: `vulnerable`
- **Evidence**: `Access-Control-Allow-Origin` reflects an arbitrary Origin **and**
  `Access-Control-Allow-Credentials: true` — cross-origin credentialed read of the session profile.
- **Detected by SOC?**: **no** — 🔴 missed (see §7).
- **Fix**: never reflect arbitrary Origin with credentials; exact allowlist only.

### Finding 4 — Predictable password-reset token
- **Severity**: CRITICAL · **ATT&CK**: T1212 · **CWE-287** · **Module**: `auth.takeover`
- **Target**: `shop.lab.example`
- **Status**: `reported_by_tool` (guessed a test victim's token; no real account harmed)
- **Evidence**: reset tokens are zero-padded counters; guessed within ~300 tries, no rate limit, no
  expiry → full account takeover.
- **Detected by SOC?**: yes, as T1212 (MTTD 6 min — the slowest detection).
- **Fix**: CSPRNG single-use tokens with short expiry + rate limiting on the reset endpoint.

### Finding 5 — Origin IP exposed behind CDN
- **Severity**: LOW · **ATT&CK**: T1590.005 · **CWE-200** · **Module**: `origin.find`
- **Target**: `lab.example`
- **Status**: `tested` (info-disclosure only)
- **Evidence**: historical A record + shared cert SAN reveal origin `203.0.113.24`, bypassing the
  CDN WAF.
- **Detected by SOC?**: **no** — 🔴 missed (passive, so expected — see §7).
- **Fix**: rotate origin IP, restrict origin to CDN egress ranges, scrub DNS/cert history.

### Finding 6 — Missing security headers + outdated jQuery
- **Severity**: LOW · **ATT&CK**: T1595.002 · **CWE-693** · **Module**: `web.nuclei`
- **Target**: `shop.lab.example`
- **Status**: `tested`
- **Evidence**: no CSP/HSTS; jQuery 1.12.4 (known DOM-XSS sinks) served.
- **Detected by SOC?**: **no** — 🔴 missed (see §7).
- **Fix**: add CSP + HSTS, upgrade front-end libraries.

---

## 5. Chain of custody — the signed ledger

The credibility of this write-up rests on this: **every action is in a signed, chained ledger,
verifiable by a third party who does not trust the operator**.

- **Internal integrity**: `forge ledger verify --ledger acme-lab.jsonl` → `<OK / root hash>`.
- **Third-party verification**: `verify_external(<pubkey>)` — the auditor validates the Ed25519 chain
  with the **public key only** (cannot forge or alter). Result: `<OK>`.
- **Ledger coverage**: `<n>` chained entries = **all** ROE decisions (8 FIRE, 1 DRY_RUN, 2 VETO),
  per-entry MAC (not just at checkpoints).
- **Custody note (honest)**: local private key for this lab; off-host anchoring (remote co-signing
  witness, `anchor.py`) = *not enabled* in this sample.

> **The argument**: "You don't have to trust us. Here is the public key. Verify yourself that nothing
> was fired outside the scope you authorized, and that the log was not rewritten."

---

## 6. Anti-masking — what was NOT fired

Honest reporting lists the gaps too — zero silent holes. Source = `roe_decisions.jsonl` + the run_job
`coverage_gaps` / `skipped_budget`.

- **`DRY_RUN`** (simulated, never executed): `web.sqli` on `shop.lab.example` — not approved by the
  operator.
- **`VETO`** (refused by the gate): `access_control.idor` on `corp.internal.example` (out of scope,
  scope-guard fail-closed); `msf.module` on `api.lab.example` (`allow_exploit=false` — exploit
  requires written high-impact opt-in).
- **Classes never attempted**: SQL injection (`injection.sqli`) on `shop.lab.example` — deferred.
- **Not tested (time budget)**: stored XSS (`web.xss`) on `shop.lab.example` — deferred, not deleted.

---

## 7. Value delivered — "here's how to close it"

The conclusion that turns the matrix into a decision.

1. **Detection gaps**: "Your SOC missed **3** techniques: **T1590.005, T1595.002, T1539**."
   - **T1539 (permissive CORS / cookie theft)** — highest priority: it maps to a MEDIUM finding with
     real cross-origin impact and no detection. Add a rule on anomalous `Origin`-reflected responses
     / credentialed CORS on `/api/*`.
   - **T1595.002 (vuln scanning)** — add a WAF/log rule for template-scan signatures and 4xx bursts.
   - **T1590.005 (passive IP gathering)** — expected blind spot (no traffic to detect); mitigate at
     the asset level (rotate origin, scrub DNS/cert history) rather than via a SOC rule.
2. **MTTD to reduce**: T1212 (reset-token brute force) detected but slowest at **6 min** — add a
   dedicated rate/velocity rule on the reset endpoint to pull it under the target.
3. **Posture after remediation**: closing T1539 + T1595.002 raises measured coverage from **57%**
   (4/7) to **≈ 86%** (6/7).
4. **Next campaign**: re-fire the missed techniques after the rules ship → **prove** the gap is
   closed (continuous-improvement purple loop).

> **Closing pitch**: *"This engagement cost you a signed, verifiable scope and handed you a number
> you didn't have: your SOC sees 57% of the techniques we fired, in ~4 minutes. Here are the 3 rules
> to add. We re-fire next run to prove it's closed."*

---

*See also: [`docs/POSITIONING.md`](../../docs/POSITIONING.md) · [`docs/PRICING.md`](../../docs/PRICING.md) ·
[`docs/PURPLE_PREREQS.md`](../../docs/PURPLE_PREREQS.md) · [`docs/MTTD.md`](../../docs/MTTD.md).*

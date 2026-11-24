# Concepts

[English](CONCEPTS.md) | [Français](CONCEPTS.fr.md)

> [Contents](README.md) · See also: [Architecture](ARCHITECTURE.md) ·
> [Security model](SECURITY_MODEL.md) · [Module catalogue](MODULES.md)

This page explains Forge's core ideas. Each section points to the code and the references.

- [1. ROE & scope-guard](#1-roe--scope-guard)
- [2. The engagement ledger](#2-the-engagement-ledger)
- [3. Evidence-backed oracles (*tested-unless-proven*)](#3-evidence-backed-oracles)
- [4. Module & technique catalogue (ATT&CK)](#4-module--technique-catalogue)
- [5. The purple loop](#5-the-purple-loop)
- [6. Chaining (iterative engine)](#6-chaining)
- [7. Evasion-backed discovery](#7-evasion-backed-discovery)

---

## 1. ROE & scope-guard

The **ROE (Rules of Engagement)** is the safety core (`forge/roe.py`). It combines the *fail-closed*
scope-guard of the original internal prototype and Plume's per-layer arming model.
**Four layers** must
ALL be passed for a LIVE action to go out:

| Layer | Question | Reach | Failure → |
|---|---|---|---|
| 1 — armed? | is the engagement explicitly armed (`--arm`)? | global | `DRY_RUN` |
| 2 — scope? | target ∈ `in_scope` **and** ∉ `out_scope`? (fail-closed: empty `in_scope` = nothing) | per target | `VETO` |
| 3 — capability? | exploit/destructive ⇒ explicit `allow_exploit`/`allow_destructive`? | per action | `VETO` |
| 4 — approved? | action approved (`--approve`), or `auto` mode? | per action | `DRY_RUN` |

**Verdicts**:
- **`FIRE`** — 1+2+3+4 OK → live action authorised (the only case where `module.fire()` is called).
- **`DRY_RUN`** — in-scope + capability OK but not armed/not approved → safe simulation (`module.dry()`
  generates the PoC, no side effect).
- **`VETO`** — layer 2 or 3 fails → HARD refusal, **never** simulated, **never** fired.

**Fully fail-closed**: any exception, unknown field or evaluation ambiguity ⇒ `VETO`.
Scope membership canonicalises the host (strips scheme/port/path, casefold) and handles globs **and**
CIDR/IPs — an `out_scope` IP cannot be bypassed through a URL or a `host:port`.

The `Scope` (`scope.json`) carries: `mode` (white/grey/black), `in_scope`/`out_scope`, `rate`,
`allow_exploit`, `allow_destructive`, `known_creds`, `idor_targets`, `module_params`,
`disabled_modules`, and the `session`/`sessions` material (SECRET). File template:
[`../scope.example.json`](../scope.example.json).

> **Trust-boundary note**: getting past a WAF/Cloudflare is **not** a vulnerability — it is an access
> enabler. The ROE gate + the ledger exist to **enforce AND prove** authorisation, not to
> bypass it.

---

## 2. The engagement ledger

Every act (ROE decision, arming, approval, finding, run-record, console action) is **chained
and signed on append** (`forge/ledger.py` + `signing.py`):

```
hash_n = SHA256( hash_{n-1} || seq || ts || kind || canonical_json(detail) )
sig_n  = sign(hash_n)                     # Ed25519 by default; HMAC as a fallback if cryptography is missing
```

Properties:
- **Full coverage**: ALL entries are chained (fixes the "only ~8 admin types" weakness
  of the original ledger).
- **Per-entry signature** (not only at the checkpoint): altering one byte breaks `verify()`.
- **Non-repudiation** (Ed25519): `verify_external(pubkey_hex)` lets a **third party** verify
  integrity **and** scope membership with the **public key alone**, without being able to forge.
- **Alg-aware / anti-downgrade**: a single ledger mixes engine entries (`ed25519`/`hmac`) and
  console entries (`sha256-console`, unsigned chain). A structural guard binds the algorithm to the
  `kind`: `sha256-console` is only legitimate on a `console.*` `kind`, and vice versa — which
  closes the downgrade (rewriting an engine entry as unsigned) **and** the relabel.

**Custody (honesty)**: the `.ed25519` private key (0600) is **local** today. Off-host
anchoring (`forge/anchor.py`: remote co-signing witness + `reconcile`, which detects a locally
re-signed rewrite) is the last step; the asymmetric architecture already allows it.

Commands: `forge ledger verify|pubkey|keygen` ([CLI](CLI.md)) · `forge ledger verify`
(chain only, fast) · `GET /api/ledger/verify` (console side, without the private key).

---

## 3. Evidence-backed oracles

The ***tested-unless-proven*** principle: a finding does **NOT** rise to `vulnerable` without **concrete
evidence of impact**. The finding state machine (`schema.py`):

`tested → reported_by_tool → vulnerable` (+ `not_vulnerable`, `informative`, `skipped`, …).

- **`reported_by_tool`** — a third-party tool (nuclei, Burp) reported a hit **at its own
  self-declared severity**. This is NOT a vulnerability confirmed by Forge: no over-classification.
- **`vulnerable`** — reserved for **evidence-backed oracles** that bring differential or
  exploitability evidence, **tied to the operator's account** (never a third party). Examples:

| Oracle | Evidence required for `vulnerable` |
|---|---|
| `access_control.idor` | Account B gets the **same normalised body** as account A's object (anon refused). |
| `ssrf.callback` | A **unique callback** is received on the collector side. |
| `auth.takeover` | After the bypass flow, `whoami` returns the **victim's identity**. |
| `cors.credentials` | ACAO reflects the attacker origin (not `*`) **AND** ACAC=true on an authenticated endpoint. |
| `jwt.weakness` | A **forged token is accepted for the operator's account** (self_marker). |
| `path.traversal` / `ssti.eval` | A **benign marker** (canary) comes back — never a system file nor RCE. |
| `csrf.state_change` | **Critical** action + anti-CSRF absent **AND** SameSite confirmed absent (detection only, no cross-site mutation). |
| `framework.exposure` | **BODY signature specific to the endpoint** (`/beans` → JSON `"beans"`, `/httptrace` → `"traces"`, `/heapdump` → magic `JAVA PROFILE`). Never a 200 code, **never** an HTML response. |
| `race.condition` | Strictly **more successes than the quota**, success being attested by a **body** `success_marker` — or by the status *on a target verified to discriminate its routes*. |

This discipline reflects the "Impact Gate": *which data of another user can I see? which
action on behalf of another user? which asset can I hijack?* If all three are no → no promotion.

### 3.1 A 200 code is not evidence — the *catch-all* control probe

**MEASURED (`kong` campaign, 2026-08-10, signed ledger).** First campaign against a third-party target with
a real anonymous surface. Result: **16 findings, 8 distinct, all `[HIGH] vulnerable`, all FALSE** —
`/actuator/beans`, `/actuator/heapdump`, `/actuator/threaddump`, `/actuator/httptrace`, plus the
Spring Boot 1.x variants `/beans`, `/heapdump`, `/threaddump`, `/trace`. The target is an **SPA that
renders its `index.html` — 3,427 identical bytes, HTTP 200 — for any path** (`/wp-admin`,
`/.git/config`, `/zzz-chemin-inexistant-12345`). There is **no** Actuator on it.

The cause came down to one disjunction: `if is_sensitive and (leaks or path.endswith((...)))` — for these
five paths `path.endswith(...)` is **unconditionally true**, so `leaks` (the only term that
read the body) was **never required**. The verdict rested on `st == 200` alone.

**Why the repository's "0 false positives" had not seen it.** It was measured on 2,410 then 5,318
then 2,771 findings — but only against **walled** targets (Cloudflare, a UAT that returns 404
everywhere). None answered 200 with content. **The defect shows up at the first target
that is actually reachable.**

**The two remedies, and their limits.**

1. **Positive evidence by BODY, endpoint by endpoint** (`exposure._actuator_leak`): each surface has
   its own signature, and a `text/html` response is an actuator in **no** case.
2. **Generic control probe** (`Oracle.path_discrimination`): *any* path discovery is
   inconclusive on a target that does not discriminate its routes. We request **two paths that cannot
   exist** (derived from the origin by SHA-256, hence replayable); if both answer
   2xx, the target is **catch-all** and the module returns **`skipped`** — "I could not
   verify" — never `tested` nor `vulnerable`. Vocabulary and witness reused from
   [`blindness`](#3-evidence-backed-oracles) / `Oracle.degraded()`.

As with `blindness`, two limits prevent the **opposite excess**:

- the probe **never promotes**: its only power is to *silence* a verdict. The 2xx is read on a
  path **fabricated by the caller**, so it is *positive* evidence of non-discrimination — not an
  inference from an absence;
- **two** controls, not one: a single 2xx could be a collision. Partial evidence (one silent
  probe) → **undetermined**, the module keeps its historical behaviour.

**Measured in a loopback lab** (`AVANT` = code from `git HEAD`, `APRÈS` = fixed tree, same servers):

| Loopback target | AVANT (before) | APRÈS (after) |
|---|---|---|
| Catch-all SPA (real body from the campaign) | **8 `vulnerable` HIGH** | 0 `vulnerable`, 1 `skipped` |
| Target that discriminates, but HTML on `/actuator/*` | **8 `vulnerable` HIGH** | 0 `vulnerable`, 1 `tested` |
| **Spring Actuator genuinely exposed** | 5 `vulnerable` + 1 `tested` | **5 `vulnerable` + 1 `tested`** (intact) |

The last row is the half that matters as much as the first: **a genuinely exposed actuator
stays detected**. Locked by `tests/test_catchall_body_proof.py` (both directions) and proven by
mutation (11 mutants, 11 killed).

---

## 4. Module & technique catalogue

`forge/techniques.py` is the **single source of truth** for the taxonomy: a table
`kind`/class/CWE → `Technique` (ATT&CK id, CWE, qualifier, remediation, tactic/phase/capability).
The other files **derive** their views (the planner its `QUALIFYING` set, the brain the
`cls`/`exploit` per kind, the schema the remediation mapping, purple the ATT&CK fallback per kind) —
no more copies that could drift.

Each module carries a **MITRE ATT&CK identifier** (the badge in the console and the purple
join key). The shipped catalogue counts **88 modules** (MEASURED on 2026-11-24: `python3 -m forge.cli modules --json`) covering:

- **Passive recon**: `recon.subdomains` (crt.sh), `recon.dns`, `recon.urls` (Wayback), `recon.tech`,
  `recon.waf`, `recon.js_endpoints`.
- **Governed active recon**: `recon.httpx`, `recon.nmap`, `web.nuclei`, `recon.content` (ffuf,
  rate-limited), `recon.secrets` (trufflehog/gitleaks), `origin.find` (origin IP behind a CDN).
- **Evidence-backed oracles**: `access_control.idor`, `ssrf.callback`, `auth.takeover`, `cors.credentials`,
  `ssti.eval`, `path.traversal`, `sqli.probe`, `xss.reflected`, `redirect.open`, `csrf.state_change`,
  `jwt.weakness`, `graphql.access`.
- **Evasion** (browser-automation): `evasion.xhr`, `evasion.turnstile`, `evasion.idor_intercept`,
  `evasion.discover`.
- **Connectors**: `msf.module` (msfrpcd), `burp.scan` (Burp REST API).
- **Demo**: `demo.fingerprint` (no-op, zero I/O).

The **complete generated table** (`kind`, exploit, destructive, ATT&CK, description, dependency,
availability) is in **[MODULES.md](MODULES.md)**. Actual availability on a machine is
probed with `forge doctor` (a module whose tool is missing is **auto-neutralised**, never fired).

---

## 5. The purple loop

The **purple** loop correlates the techniques **fired** in red (run-records tagged `mitre`) with the
techniques **detected** by the defence — by **equality of TECHNIQUE identifier** — and derives
**three states** + the **MTTD** from it.

```
Forge tire la technique T ─► run-record {mitre: T} ─► console (store rouge)
                                                          │  JOIN lecture seule
Source de détection (Plume/SIEM/IDS) détecte T ? ─────────┘  sur la TECHNIQUE
   ─►  matrice de couverture ATT&CK, TROIS états :
         detected-exact         → la source alerte sur EXACTEMENT T   (compte dans le taux + MTTD)
         detected-parent-approx → T est une SOUS-technique et la source n'a que la PARENTE
         missed                 → ni l'un ni l'autre
       MTTD(T) = first_detection − last_fire, sur les detected-exact UNIQUEMENT
```

**Why three states and not two.** A multi-technique tag (`"T1595.002 T1046"` — the norm at
SigmaHQ: several `attack.` per rule) is **split on both sides** of the join, otherwise the Sigma
corpus fabricates false `missed`. And a rule tagged with the **parent** technique is **not**
evidence of detection of the fired sub-technique: it is counted separately (`parent_approx`), **outside the
headline rate and outside the MTTD**. The join sees an **identifier**, not a detection query:
so it cannot *prove* that the fired vector is covered. Measured example: Forge fires
`T1110.001` (SSH password guessing); three of the `T1110` rules shipped with Plume are limited
to mail, limited to web, or require IP dispersion — none of these three catches a single-source SSH
brute-force; other seeded `T1110` rules could, **depending on the telemetry plugged in and the
rules enabled**. That is precisely why we do not decide: the doubt is **named** rather than
arbitrated in the vendor's favour. Parent-approx is not waste for all that: it is a **named blind
spot** ("you fired `T1110.001`, you only have generic `T1110` rules"), rendered
in its own list. To turn green: tag a rule **for that sub-technique**.

Two invariants:
- **The correlation never changes**; only the detection **SOURCE** is client-specific.
  It is a **configurable plugin**: Plume is only a preset (`kind=plume`). `DetectionSource`
  model, presets (CrowdSec/FortiGate/pfSense/OPNsense/Elastic/file/exec) and MITRE
  mapping: [`DETECTION.md`](DETECTION.md). Plume preset prerequisites: [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).
- **Readable fail-open**: source absent/unreachable ⇒ `source_reachable:false`, the measurement is
  declared **impossible** — never an invented `detected`/`parent_approx`/`missed`/`MTTD`. A source that is
  reachable but empty (fresh SOC) = a **valid** state.

The **MTTD** is a **time-to-ALERT** (it covers ingest + rule evaluation cadence), not
a time-to-event — not to be over-interpreted. Detailed explanation: [`MTTD.md`](MTTD.md).

Endpoint: `GET /api/detection/coverage` (backward-compatible alias `/api/purple/coverage`). Read-only
preflight: `forge doctor --purple`.

---

## 6. Chaining

`engine.campaign()` is **iterative**: `plan → observe → replan`, until a stop criterion.

At each **wave**, the brain (`brain.propose(graph)`) reads the **world-model enriched** by the
previous wave (not only the targets), the planner orders (coverage-safe), the engine fires (gated), and
the findings **enrich the graph** — which lets the brain **chain**:

- a discovered **off-CDN origin** (`origin.find`) → `nuclei`/oracles on the IP;
- a **fingerprint** → the evidence-backed oracles suited to the technology;
- a **discovered endpoint** (JS, WAF bypass) → an IDOR/injection oracle on that endpoint.

Stop criteria: fixed point (no new action), `max_waves` (anti-loop guard), or budget
exhausted for non-qualifying work. **ROE/governance is reapplied at each wave** — nothing
fires without `FIRE`. The **governed session** is inherited along the chain: an in-scope derived
target inherits the auth material of its source (scope-guarded no-op if out of scope), so that the
chained oracles are authenticated — without the secret ever entering the finding/ledger/graph.

### 6.1 Discovery first (`stage`)

Chaining is only worth something if **discovery has happened**: a scanner that runs before `katana`/`gau`/
`subfinder` works on three URLs instead of fifty. Two mechanisms guarantee it, both
**structural** (they apply to any action, whatever path proposed it — including
the **auto-pentest sweep**, which bypassed the ordering intent carried by the brain):

1. **The sort stage.** `planner.order()` sorts by `(étage, -EV)` (stage, -EV). The stage is `STAGE_SURFACE` for the
   kinds that **produce** surface — derived from the `ToolSpec` (`asset_hits`/`emit_*_discovery`:
   katana, gau, subfinder, amass, feroxbuster, naabu, dnsx, gobuster) and from a list of native kinds
   *checked against the modules' source* (httpx, js_endpoints, urls, subdomains, nmap, content,
   evasion.discover) — `STAGE_VERIFY` for everything else. A producer **on an already derived endpoint**
   is not a producer (it widens nothing); nor is `origin.find` (it publishes an **alternative
   route** to the known surface, not new surface).
2. **The replanning boundary.** At the **first wave only**, consumers are
   deferred by one wave: discovery is therefore **replanned** before the first slow scanner
   commits the budget. Deferred ≠ removed — they stay in the denominator (`planned_total`) and, if they
   do not run, come out as "planned, never attempted".

Coverage-safe **unchanged**: this is a re-ordering, nothing is removed, the qualifying floor and
`skipped_budget` are intact. Measured on the harness that replays a real campaign
(`tests/bench_wave_reach.py`, 3 targets, observed durations injected, equal budget): **225 → 1,292
actions**, **0 → 32 distinct URLs reached**, **0 → 1 wave completed**, and **no kind stops
running** (58 → 58) — the slow scanners still run, but on a discovered surface.

Targets derived at runtime are **re-validated fail-closed** against the injected scope
(`in_scope`/`out_scope`) before any emission — a discovery module cannot widen the scope.

---

## 7. Evasion-backed discovery

`evasion.discover` (T1594) browses **behind a managed WAF challenge** via the
browser-automation service (Camoufox + vision-click-os for an interactive Turnstile), then **extracts
in-scope endpoints** (DOM/JS/XHR) and emits them with the discovery marker — which then feeds
the oracle chain (§6). The evasion modules:

| Module | Role | ATT&CK |
|---|---|---|
| `evasion.turnstile` | Gets past the interactive Cloudflare Turnstile (template detection + X11 OS click) — **access enabler** | T1556 |
| `evasion.xhr` | Observes XHR requests via the browser session (WAF/DataDome bypass) | T1190 |
| `evasion.idor_intercept` | Arms in-flight IDOR interception (browser intercept-modify) — evidence via `/intercept-dump` | T1190 |
| `evasion.discover` | Endpoint discovery behind a WAF, scope-locked, non-destructive, bounded, session redacted | T1594 |

Guarantees: **scope-locked** (each discovered endpoint re-validated), **non-destructive**, **bounded**,
**session redacted** (auth material does not leak). The browser-automation service is **optional**
(`FORGE_BROWSER_URL`): unreachable ⇒ the module auto-neutralises (`available:false`), never fired.

> Reminder: getting past a WAF **≠ a vulnerability**. It is an access enabler to combine with an evidence-backed
> oracle. The ledger and the scope-guard stay hard.

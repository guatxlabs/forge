# Architecture — how Forge is built

[English](ARCHITECTURE.md) | [Français](ARCHITECTURE.fr.md)

> [Contents](README.md) · Prerequisite: [Overview](OVERVIEW.md) · Going further:
> [Concepts](CONCEPTS.md) · [Security model](SECURITY_MODEL.md)
>
> The **design rationale** (public/private, shared core, reuse of the original prototype and
> of Plume) lives in
> [`../ARCHITECTURE.md`](../ARCHITECTURE.md). This page describes **the actual components** and their
> wiring, up to date with the code.

## 1. Macro view — three processes, one contract

```
Ce dépôt — Forge (rouge) :
  forge/         MOTEUR Python (gate ROE, ledger, modules, oracles, évasion, collecteurs)
  console/       CONSOLE Rust (axum + rusqlite) — store rouge + API + RBAC + C2-light + dashboards
  console/web/   SPA vanilla-JS (skin Ember, dark) — findings / coverage / purple / runs / admin

Dépendances externes de la famille GUATX (repos séparés, PAS dans ce dépôt) :
  guatx-core     lib Rust NEUTRE, publique — le ~70 % commun (moteur GXQL v0) ; consommée par la console
                 en git-dep publique épinglée (github.com/guatxlabs/core, tag v0.2.6)
  plume          Plume (SOC bleu, public) — détection / BAS  [OPTIONNEL pour Forge]
```

There is **no shared process** between the layers: the Python engine and the Rust console
communicate through an **HTTP/file contract** (`POST /api/ingest`, JSONL run-records, JSONL ledger
on disk). The console **spawns** the engine (`python3 -m forge.cli campaign …`) for runs
launched from the web (see §3, C2-light). The console depends on the `guatx-core` crate through a **pinned
public git-dep** (`tag = "v0.2.6"`, fetched at build time; the migration from the old sibling `path`
dependency is done — see [`DEPLOYMENT.md`](DEPLOYMENT.md) §4).

**Footprint** (`wc -l` on this tree, `__pycache__`/`target` excluded): Python engine **23.9 KLOC**
(`deps=[]`), Rust console **47.2 KLOC** (tests included), `guatx-core` **9.3 KLOC**, UI **10.5 KLOC**.
Shipped sources: Python **1,371 KB**, web **877 KB**; **console binary size: not measured** here
(no `target/release/forge` on this tree). Docker image sizes: **not re-measured** —
the historical ranges (150-250 MB mini / 350-500 MB full) are kept as an indication,
with no measurement attached. Commands and detail: [`DEPLOYMENT.md`](DEPLOYMENT.md) §6.

## 2. The Python engine (`forge/`)

The engine is **pure-stdlib** and INERT by default. Its control loop: `plan → gate ROE →
dry|fire → ledger → findings`.

### 2.1 Safety core

| File | Role |
|---|---|
| `roe.py` | `Scope` (fail-closed membership) + `Roe` (4-layer gate) + `Action`/`Decision`. **The core.** |
| `ledger.py` | Append-time ledger: SHA-256 hash-chain + per-entry signature + `verify()`/`verify_external()`, alg-aware (multi-algorithm). |
| `signing.py` | Signers: `Ed25519Signer` (default, non-repudiation) + `HmacSigner` fallback (stdlib); `CONSOLE_ALG` (`sha256-console`) for entries written by the console. |
| `anchor.py` | Off-host anchoring: `Anchor` interface + co-signing witness + `reconcile` (detects a locally re-signed rewrite). |
| `schema.py` | `Finding` (+ `mitre`, `status`, `cwe`, `fix`, `cvss_*`), `Target`, `Campaign`. Additive fail-open enrichments. |

**Central invariant**: a module is called with `fire()` **only** on a `FIRE` verdict. On
`DRY_RUN`, only `dry()` (generates the PoC, no side effect). On `VETO`, nothing. Any evaluation
error ⇒ `VETO` (fail-closed).

### 2.2 Orchestration

| File | Role |
|---|---|
| `engine.py` | The loop. `execute()` (one action), `run()` (list), `campaign()` (**iterative**: plan → observe → replan over `max_waves`). Applies connector governance, scope injection for discovery, the governed session, memory dedup, emission of purple run-records. |
| `planner.py` | **Coverage-safe planner**: orders by EV = `value·confidence/cost`, with a **FLOOR** on qualifying classes (IDOR/auth/RCE/SSRF/biz…) so that a payable path is never starved. `defer != delete`: over budget → `skipped_budget` (visible). |
| `brain.py` | `Brain.propose(graph) -> [Action]` interface. `HeuristicBrain` = autonomous default (target → classes + chaining on findings). This is the **seam** where the Claude orchestrator can plug in as the brain. |
| `graph.py` | `EngagementGraph` — hosts→services→findings world-model, enriched at each wave (supports chaining). |
| `techniques.py` | **Single technique registry** (source of truth): maps `kind`/class/CWE → `Technique` (ATT&CK, CWE, qualifier, remediation, tactic/phase/capability). `planner`, `brain`, `schema`, `purple` **derive** their views from it (no more copies). |
| `purple.py` | ATT&CK run-records (`{ts, target, kind, mitre, fired, run_id, campaign}`) emitted for each shot; `emit()` as ingestible JSONL. |
| `report.py` | Engagement markdown report + **anti-masking** section (fired / simulated / vetoed / never attempted). |
| `memory.py`, `memory_faiss.py` | Memory: JSONL store + dedup (fuzzy stdlib `JaccardMemory`, optional FAISS bridge that degrades cleanly). |
| `session.py` | **Governed session** (SECRET): auth material attached **only** to in-scope requests, never logged/written to the ledger/put into a finding. |
| `durations.py` | **Observed shot durations, aggregated PER KIND** (never per target: that would be a persistent reconnaissance log). Sidecar `<ledger>.durations` — **per engagement**, bounded size, confidence threshold + median. Feeds ONLY the **submission** order of the intra-wave preheat (`engine._preheat_key`); exact fallback to `action.cost` without a measurement. No firing decision depends on it. |
| `runner.py`, `browser_client.py`, `console_client.py` | Runner (local binary or docker, no install), browser-automation client (`FORGE_BROWSER_URL`), console ingestion client. |

### 2.3 The module registry (`forge/modules/`)

A **module** follows a minimal contract (`registry.py`):

```python
class Module:
    kind = "base"
    exploit = False        # => requires allow_exploit in the scope
    destructive = False    # => requires allow_destructive
    available = True       # False if the underlying tool is missing (auto-neutralisation)
    mitre = ""             # ATT&CK technique (console badge)
    description = ""
    def dry(self, action) -> str: ...          # what it WOULD do (PoC), without sending anything
    def fire(self, action) -> list[Finding]: ... # executes — never called without a FIRE verdict
```

`@register("kind")` records the class in `REGISTRY`. Modules remain orchestrated **standalone
tools** — the engine does not own them. Discipline (inherited from the Plume collectors): OFF by
default, **auto-neutralisation** if the underlying tool is absent, **zero side effect in dry-run**.

The **88 shipped modules** (MEASURED on 2026-11-24: `python3 -m forge.cli modules --json`) cover passive/active recon, evidence-backed oracles (IDOR, SSRF, auth/ATO, CORS,
SSTI, path-traversal, SQLi, XSS, open-redirect, CSRF, JWT, GraphQL), browser-automation evasion, and
connectors (MSF, Burp). A partial table (an EXTRACT: 43 of the 88) is in
**[MODULES.md](MODULES.md)**, the complete list is the output of `python3 -m forge.cli modules --json`; their "evidence-backed" logic in [Concepts §3](CONCEPTS.md#3-evidence-backed-oracles).

### 2.4 The detection collectors (`forge/collectors/`)

For the purple loop, the "rich" BLUE sources (CrowdSec, Elastic/OpenSearch, syslog/filterlog,
file, exec, or HTTP over **mTLS** — the seam does present a client certificate, but a PROCESS
identity, not a per-source one) are **delegated** to the Python collector
(`forge.cli detections --source …`). Each `kind` has a class that normalises its native source into
`[{mitre, count, first_ts}]` and honours the **readable fail-open contract** (`reachable` distinguishes
"reachable but empty" from "unreachable"). Kinds: `plume, generic_http, crowdsec, elastic,
opensearch, fortigate_syslog, pfsense, opnsense, file_jsonl, exec`. Model and MITRE mapping:
[`DETECTION.md`](DETECTION.md).

## 3. The Rust console (`console/src/main.rs`)

Single **axum + rusqlite** binary (bundled SQLite, WAL). Red-model store + API + UI + RBAC +
C2-light. It **contains no offensive capability**: it stores, correlates, governs, and
**spawns** the Python engine for web runs.

### 3.1 Guard layers (middleware)

All routes except `/health`, `/api/login`, `/api/setup*` go through two stacked guards:

1. **`host_guard`** (anti-DNS-rebinding) — the `Host` (port stripped) must be NON-EMPTY and in
   the allowlist (`localhost`/`127.0.0.1`/`::1` by default, + `FORGE_CONSOLE_HOST`). Otherwise **421**.
2. **`auth_guard`** — the gate engages on `auth_required` (an env hash set **OR** an enabled account
   in the database). Engaged without valid evidence ⇒ **401**. Accepted evidence: individual session
   (`forge_session` cookie or `Bearer <session>`), **Basic** viewer (env hash), **Bearer** = ingestion
   token.

Detail of the roles and of per-route authz: [Security model](SECURITY_MODEL.md) and
[API reference](HTTP_API.md).

### 3.2 RBAC — three roles

| Role | Can | Evidence |
|---|---|---|
| **viewer** | Read (findings, coverage, runs, ledger, GXQL, dashboards) | session; or Basic (env hash `FORGE_CONSOLE_PASS_HASH`) |
| **operator** | Launch/cancel a C2-light run (`/api/run*`), refresh the modules | operator|admin session; or `X-Forge-Operator` header (env hash `FORGE_CONSOLE_OPERATOR_HASH`) + source-CIDR policy |
| **admin** | Administration: accounts, settings, connector governance, detection source, backup/restore, setup | **admin session only** (no env-hash fallback — individual attribution mandatory) |

An **ingestion token** (`FORGE_CONSOLE_TOKEN`, Bearer) gates machine writes (`/api/ingest`,
panels/dashboards) — it is the engine→console channel.

### 3.3 The governed "C2-light" run flow

`POST /api/run` **is not** a persistent command channel: it is a **governed and audited campaign
launcher**. On each run:

1. Fail-closed **operator AuthZ** (operator|admin session or env hash) + **source-CIDR** constraint
   if configured.
2. **Strict validation** of the input (campaign, hosts: anti-injection character allowlist).
3. **Server scope**: each target must be ⊆ the server scope's `in_scope`, otherwise **400
   out_of_scope** *before* any spawn.
4. **Exploit floor**: `exploit`/`destructive` modules are **refused (400)** unless there is a **governed
   high-impact opt-in** — honoured **only** if `operator + arm=true + reason non vide` (non-empty reason)
   (`high_impact_gate`). Otherwise the scope written for the run **forces** `allow_exploit=false`.
5. **FIFO PER ENGAGEMENT**: at most one live run *per engagement* (slot indexed by `engagement_id`) —
   a 2nd run on the **same** engagement → **409** (`engagement_id` in the body); a run for **another**
   engagement starts in **parallel** without a 409 (inter-engagement concurrency, isolation by
   dedicated scope + ledger).
6. **Spawn** `python3 -m forge.cli campaign …` (setsid), with a temporary scope.json/targets.json,
   a watchdog (`FORGE_RUN_TIMEOUT`), logs streamed over **SSE** (`/api/runs/:id/events`).

Each step is **written to the ledger** (`console.*`). UI governance (disabling a connector) is
**applied at spawn**: a disabled module is SKIPped even if its binary is present.

### 3.4 Persistence & configuration

- **SQLite** (`FORGE_CONSOLE_DB`): tables `finding`, `runrecord`, coverage `runrecord`, `users`,
  `session`, `settings` (KV), `module` (catalogue + governance), `panel`, `dashboard`, `run_job`.
  Idempotent additive migrations at boot (`migrate()`).
- **Ledger** (`FORGE_CONSOLE_LEDGER`): same file/format as the engine; the console writes its
  own `console.*` entries as `sha256-console` (unsigned chain, integrity through hash-chaining;
  alg↔kind binding that forbids any downgrade).
- **Settings** (`settings` table): `detection_source`, `operator_policy`, `backup_policy`,
  `session_ttl`, `trusted_proxy`, `backup_last_run`. Configurable **in the UI** (admin, written to the ledger).
  See [Configuration](CONFIGURATION.md).
- **GXQL**: SPL-like query language ported from Plume, compiled to **read-only SQL** (allowlisted
  fields, values as bound params, a single SELECT, capped LIMIT, RO connection). `GET
  /api/query`. **Dashboards** are saved GXQL panels (table/bar/stat viz).

## 4. The SPA (`console/web/`)

**Vanilla-JS** SPA (no framework, no CDN — strict CSP), "Ember" skin (dark, the offensive
antithesis of Plume's blue Aurora). At boot, it probes `GET /api/setup/state`:
`needs_setup:true` ⇒ shows the **first-deployment wizard** ([FIRST_DEPLOYMENT.md](FIRST_DEPLOYMENT.md));
otherwise it shows the login portal then the **Findings / ATT&CK Coverage / Purple / Runs /
Ledger / Search (GXQL) / Dashboards / Administration** tabs. Progressive Web App (`sw.js`,
`manifest.webmanifest`).

## 5. The governance model (cross-cutting)

Four structural guarantees, applied to every layer:

- **Fail-closed** — missing config, an evaluation error, a missing secret ⇒ **refusal**,
  never a default capability. Empty `in_scope` = nothing fires. Operator role not provisioned =
  C2 closed (403). Detection source absent = measurement declared impossible (never invented).
- **Proof-oriented (*tested-unless-proven*)** — a finding stays `tested`/`reported_by_tool` until
  an oracle has produced **concrete evidence** (another account's data read, callback received,
  forged token accepted). No over-classification as `vulnerable`.
- **Opt-in exploit floor** — `exploit`/`destructive` require an explicit opt-in per engagement
  (scope) or per run (governed high-impact). An `exploit=True` module is INERT otherwise.
- **Everything is traced** — every decision and action is in the signed append-time ledger, with an
  **anti-masking** section in the report (what was simulated/refused/never attempted). Zero silent
  gap.

These guarantees are detailed in [Concepts](CONCEPTS.md) and [Security model](SECURITY_MODEL.md).

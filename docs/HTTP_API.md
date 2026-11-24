# HTTP API reference

[English](HTTP_API.md) | [Français](HTTP_API.fr.md)

> [Contents](README.md) · See also: [CLI reference](CLI.md) · [Configuration](CONFIGURATION.md) ·
> [Security model](SECURITY_MODEL.md)

The console (`forge`) exposes the API and the SPA on `FORGE_CONSOLE_ADDR` (default
`127.0.0.1:7100`). **All** routes go through **`host_guard`** (anti-DNS-rebinding: `Host`
outside the allowlist ⇒ **421**). Most also go through **`auth_guard`** (auth gate engaged as soon
as an env hash is set OR an enabled account exists in the database).

## Authentication levels

| Level | Accepted proof |
|---|---|
| **public** | outside `auth_guard` (but under `host_guard`) — accessible without a session. |
| **viewer** | any authenticated identity: session (`cookie forge_session` / `Bearer <session>`), viewer **Basic** (`FORGE_CONSOLE_PASS_HASH`), or **Bearer** = ingestion token. In dev-open mode (gate disengaged), passes without proof. |
| **token** | **Bearer** = ingestion token (`FORGE_CONSOLE_TOKEN`). Machine channel (engine→console). |
| **operator** | **operator\|admin** session, or `X-Forge-Operator` header (env hash) — **+** source-CIDR constraint if `operator_policy.source_cidrs` is configured. A viewer never passes. |
| **admin** | **admin session only** (no env-hash fallback — strict individual attribution). |

Details of the model: [Security model](SECURITY_MODEL.md).

---

## Public routes (outside `auth_guard`)

| Method & route | Auth | Purpose |
|---|---|---|
| `GET /health` | public | Liveness. `{status:"ok", version}`. Probe of the Docker/compose healthcheck (expects 200). |
| `POST /api/login` | public | Opens an **individual session** (account). Body `{login, password}` → `forge_session` cookie (HttpOnly, SameSite=Strict) + token. |
| `GET /api/setup/state` | public | First-deployment state: `{provisioned, needs_setup, capabilities:{sqlcipher}}`. Probed by the SPA at boot. |
| `POST /api/setup` | public, **self-disabling** | Wizard: creates the first admin (+ optional `operator_policy`/`detection_source`/`session_ttl`). **409** as soon as an enabled admin exists. Ledger `console.setup.provision`. See [First deployment](FIRST_DEPLOYMENT.md). |
| `POST /api/setup/migrate` | public, **pre-provisioning** | Migration driven from the wizard (server paths). **403** without `FORGE_ALLOW_API_MIGRATE`; **409** once provisioned. Primary UX = `forge migrate` CLI. |

---

## Read (viewer)

| Method & route | Purpose |
|---|---|
| `GET /` | The SPA (dark operator console). |
| `GET /api/whoami` | Effective identity of the caller (`authenticated`, `login`, `role`, `is_operator`). Drives showing/hiding the C2 actions in the UI. |
| `GET /api/findings` | List of findings (red store). |
| `GET /api/findings/:id` | Detail of a finding (evidence, PoC, CWE, CVSS, fix, mitre, status). |
| `GET /api/runrecords` | ATT&CK run-records (techniques fired). |
| `GET /api/coverage` | **ATT&CK coverage** rollup: per technique, number of runs attempted vs fired. |
| `GET /api/detection/coverage` (alias `GET /api/purple/coverage`) | **Purple** matrix: JOIN of `fired` run-records (red) ↔ detections from the source (blue), multi-technique tags split on both sides → **three** states `detected` (exact) / `parent_approx` (sub-technique fired, only the parent covered) / `missed`, + **MTTD**. `detection_rate` and the MTTD count ONLY the exact ones. Fail-open: `source_reachable:false` + `error` if no source. |
| `GET /api/campaigns` | List of campaigns. |
| `GET /api/roe` | Traced ROE decisions (verdict per action — anti-masking). |
| `GET /api/modules` | Module catalog (kind, exploit, mitre, availability, governance). |
| `GET /api/ledger` | Ledger entries (from the on-disk JSONL), paginated (`limit`/`offset`). |
| `GET /api/ledger/verify` | **Console-side** verification of the SHA-256 chain (without private key: `sig_checked:false`). For signature verification, see `forge ledger verify`. |
| `GET /api/query` · `POST /api/query` | **GXQL** (SPL-like) → **read-only** SQL (allowlisted fields, bound params, a single SELECT, capped LIMIT, RO connection). POST for long queries. Field outside the allowlist ⇒ **400**. |
| `GET /api/dashboards` | List of dashboards (`position` order). |
| `GET /api/panels` | List of GXQL panels. |
| `GET /api/panels/:id/data?from=&to=` | Executes the panel's GXQL query (table/bar/stat viz). |
| `GET /api/runs` | List of C2-light runs (most recent first). |
| `GET /api/runs/:id` | Detail of a run. |
| `GET /api/runs/:id/report[?format=md\|html\|pdf]` | **Engagement report**. `md` (default), `html` (branded deliverable, print CSS), `pdf` (if a PDF engine is present, otherwise `pdf_unavailable`). **Leads with the verdict** — see below. |
| `GET /api/runs/:id/logs?after=<ID>` | Log lines of a run (polling fallback for SSE). |
| `GET /api/runs/:id/events` | **SSE** stream: log lines + status transitions of the run. |
| `POST /api/scope-check` | Membership verdict of a target against the server scope (read/governance). |

### `GET /api/runs/:id/report` — structure of the report (parity with `forge.report.build_report`)

The report **leads with the verdict**, not with the list. Order of the sections (`md` and `html`):

1. **partiality banner** — *only* if `run_job.status ∈ {timeout, cancelled, failed, running}`.
   A cut run SAYS SO at the top: an absence of findings there is not worth an absence of vulnerability.
   The console does not receive the engine's plan counters (`forge/console_client.py` does not
   transmit them) — it therefore says that it **does not know** the "executed / planned" ratio instead of
   making one up;
2. **Executive summary** (console only — prose of the client deliverable);
3. **Verdict** — one line ("N actionnable(s)" or "rien d'actionnable trouvé") + the counts of the
   four buckets: actionable (≥ MEDIUM **or** proven status) · to qualify (LOW / reported by a
   tool) · **coverage NOT verified** (`skipped`) · reconnaissance noise (INFO);
   the **"Total émis"** (total emitted) line is **bounded** by the accounting of unstored findings (below);
4. **Actionable — to report** then **Signal to qualify** — one block per template (1 vuln × N
   endpoints) in the shape a triager expects: severity, CWE, CVSS, target, request deduced from the
   PoC, numbered reproduction, **replayable command**, observation, fix;
5. **Coverage NOT verified (coverage gaps)** — the `skipped`, grouped by module, **before**
   any appendix: it is what BOUNDS what the absence of findings allows one to conclude;
6. **Summary** by severity;
7. **Findings — full appendix** — preceded by an **accounting** line: `rendus + repliés =
   émis`. In `pentest` view (default) nothing is folded; in `bounty` view template repetitions
   are folded, **counted, named**, with the means to retrieve them;
8. **Coverage & transparency (ROE)**, **Detection coverage (purple)**, **Appendix — chain of custody**.

**"Total émis" is a STORED total — and the report says so when it matters.** The verdict total
is that of the findings **written to the database**. It equals what the engine emitted only if the accounting
of ingestion refusals (cf. `/api/ingest`) is **measured and zero** — in that case, and only in
that case, no additional line appears. Otherwise the verdict carries, **right after the total**:

| Situation | What the report adds |
|---|---|
| `findings_dropped > 0` | "**N finding(s) émis par le moteur et REFUSÉS au stockage**" (emitted by the engine and REFUSED at storage) — the `campaign+target+title` key is named, as well as what is NOT part of it (`run_id`/`tool`/`severity`), and **the total actually emitted** is given. The run's signed ledger (`kind=finding`) is authoritative. |
| `findings_dropped > 0` **and 0 stored** | in addition: "**AUCUN finding de ce run n'a été stocké**" (NO finding of this run was stored) — signature of a **re-execution of the same campaign** (the key does not carry `run_id`, so the second run's findings are all refused). Without this sentence, an empty report reads as "nothing found". |
| `findings_write_errors > 0` | **separate** sentence: the database could not write (lock, disk, schema). A cause distinct from a collision — confusing them would send someone to fix a uniqueness key while the database is unavailable. |
| `null` columns (run predating the counting) | "**Part NON stockée : INCONNUE**" (NOT stored share: UNKNOWN) — the console cannot assert that its total equals what was emitted. Never rendered as a zero. |

The "Total émis" line itself is left **verbatim**: it is the mirror of
`forge/report_view.py` and the parity guard compares it label by label. It is **bounded**, it is not
rewritten on one side only.

**View**: `FORGE_REPORT_VIEW=pentest|bounty` (same variable as the engine, so that folding is the
same decision on both sides). Default `pentest` = exhaustive.

**Sections of the CLI report not mirrored here, and why** — noise-score triage
(`forge/triage.py`) is not ported to the console side (it does not claim a triage it has not
executed); the ATT&CK techniques exercised are rendered **inside** "Detection coverage (purple)", where
they are additionally joined to the SOC's detections; the engagement header and the engine's ledger have
as equivalents the console header and the chain-of-custody appendix. This correspondence is **verified
by a test** (`report_view_parity_python_vs_rust_same_corpus`) that turns red if the engine adds a
section that nobody has either mirrored or declared.

### `GET /api/engagements/:id/report` — a PARTIAL engagement says so in **all** its formats

The aggregated deliverable (`html` · `pdf` · `docx` · `csv` · `json`) starts from the **stored** findings and
did not check whether the runs that produced them had gone to completion. An engagement in which a run had
expired therefore rendered a report that **looks like** a complete report: "no critical risk" reads there
as a verdict, while part of the plan never ran.

The banner is **derived from `runs[*].status`** (same statuses as the run banner:
`timeout` · `cancelled`/`canceled` · `failed` · `running`), it **names** each cut run with its
cause, and it **precedes the executive summary** that it bounds. An engagement whose runs are all
finished carries no trace of it.

> **The DOCX too** — and it is the format the client opens. It is delegated to
> `python -m forge.report_engagement`, whose `normalize()` rebuilds its output from a **closed
> list of keys**: the `partial` key that the console sets in the report Value was *discarded* there.
> Partiality is therefore derived from `runs[*].status`, which survives `normalize()` and is already part
> of the input contract — **no new field is required from the caller** (Rust console as well as
> `--stdin` CLI pipeline). The status table is the mirror of
> `console/src/report_render/view.rs::partial_cause`, and a test **reads the Rust source** to
> assert it: the two cannot diverge silently.

> **The routes that spawn the engine** launch **one process per request**. Full inventory, by gate:
>
> | Gate (ceiling) | Routes | Time budget |
> |---|---|---|
> | `FORGE_ENGINE_MAX_CONCURRENT` (default 4) — read, open to the viewer | `GET /api/techniques`, `GET /api/workflows`, `GET /api/detection/coverage` (Python collector), `GET /api/engagements/:id/report?format=docx\|pdf`, `GET /api/runs/:id/report?format=pdf`, `GET /api/compliance/evidence?format=pdf` (compliance module, flag-gated) | `FORGE_ENGINE_TIMEOUT` (120 s) |
> | `FORGE_ENGINE_OPERATOR_MAX_CONCURRENT` (default 2) — operator | `POST /api/import`, `POST /api/modules/refresh`, `POST`/`DELETE /api/tools`, and the registry probe at BOOT | `FORGE_IMPORT_TIMEOUT` (600 s) for the import, `FORGE_ENGINE_TIMEOUT` otherwise |
> | `FORGE_PLAN_MAX_CONCURRENT` (default 2) — operator | `POST /api/plan` | `FORGE_PLAN_TIMEOUT` (300 s) |
>
> The total of simultaneous engine processes is the **sum** of the three ceilings, not one of them. A slot is held for the
> **life of the process AND of its descendants**, not for the life of the HTTP request: abandoning the request therefore does not release
> the slot, and the slot is released only after the spawn dies. `POST /api/run` is not in this table: it is a
> supervised run, with its own lifecycle (`FORGE_RUN_TIMEOUT`, FIFO per engagement).
>
> **What "the spawn dies" covers, and what it does not.** The group kill (`setsid`+`killpg`) is the
> fast path, but a descendant can LEAVE the group (`setsid`, double-fork) — measured before the fix:
> `FORGE_ENGINE_MAX_CONCURRENT=4`, 40 abandoned requests → **40 live descendants**, ceiling never reached, no
> refusal. The sweep therefore relies on two properties that a descendant does not inherit by choice: a unique
> **environment marker** per spawn (copied by fork/exec, `setsid` changes nothing about it) and the **parent chain**,
> closed by `PR_SET_CHILD_SUBREAPER` on the leader (an orphan is re-adopted by the leader, not by `init`). After
> the fix, same measurement: **0 live descendants** after 40 abandonments, and the bound refuses (burst of 20 held
> requests: 16 × `429`, process peak = 4 = the ceiling).
>
> **Limits measured, not worked around**: (1) a descendant that DEPRIVES ITSELF OF THE MARKER AND whose leader has already exited
> — which is the case on the nominal path — cannot be attached by either of the two properties: measured, it survives. Mind
> what this REALLY costs the escapee: **it does not have to discard its environment**, it only needs to remove ONE
> variable from it, whose name is a public constant of this repository. Measured side by side (5 requests served, stub engine
> launching 1 detached descendant per spawn): `env -i` → **7 survivors**, `env -u FORGE_ENGINE_SPAWN` → **7
> survivors** (identical); control with the marker kept → **0 survivors**. The inheritance is PASSIVE: a deliberate
> act undoes it, and the price of that act is a single variable. On the abandonment/budget paths, where the leader is still
> alive, the parent chain catches the escapee and it is indeed killed (0 survivors).
> (1-bis) **DELEGATION TO A NON-DESCENDANT leaves the domain of the property** — it is a limit of the same practical class
> as the previous one, and nothing closes it today. The contract is about what a DESCENDANT
> inherits; work handed to the user's service manager (`systemd-run --user`) is nobody's
> descendant, inherits neither the marker nor the parentage, and the slot is released immediately. Measured (stub engine
> `systemd-run --user --collect --unit=… sleep N ; exec sleep 300`, `FORGE_ENGINE_MAX_CONCURRENT=4`, 4 requests
> ABANDONED by an anonymous client): **5 survivors** (the 4 delegations + the registry probe at boot), and the
> next request is **served** (the ceiling is never reached). The client cost is zero, the machine cost is
> not: this is the degradation lever that remains open on a machine where `systemd --user` is available.
> (2) Outside Linux there is no
> `/proc`: the sweep returns an empty list and the guard falls back to the group kill alone (cf. `docs/PLATFORMS.md`).
> (3) The sweep costs one `/proc` pass per spawn: measured on this machine (594 processes), `GET /api/techniques`
> goes from a median of **0.198 s to 0.221 s** (3 interleaved rounds of 15 measurements, real `python3` engine, debug build).
> (4) **The contract has a cost on the NOMINAL path, not only on abandonment** — and this cost DEPENDS ON THE SHAPE OF THE
> DESCENDANT. The previous batch had measured only ONE shape (descendant that REDIRECTS its fds) and had generalised its
> figure to all of them: **it was wrong by two orders of magnitude** for the most common shape, that of a
> `fork`/`Popen` **without redirection**, which INHERITS the spawn's stdout pipe. Collection stopped at the EOF of the pipes;
> a descendant holding the pipe pushes it back indefinitely, so that a **SUCCESSFUL** request was billed the
> **WHOLE ENGINE BUDGET** and the engine's valid output was **DISCARDED** (body `techniques_unavailable` while
> the engine had exited with 0). Measured on the binary, `GET /api/techniques`, 3 measurements per shape, stub engine
> returning a valid output then exiting immediately:
>
> | descendant shape | BEFORE | AFTER |
> |---|---|---|
> | no descendant | **0.030–0.040 s** | **0.030–0.040 s** |
> | redirects its fds, DIES on SIGTERM | **0.133–0.146 s** | **0.133–0.146 s** |
> | redirects its fds, IGNORES SIGTERM | **5.17–5.24 s** (SIGKILL of `CANCEL_GRACE_SECS`) | **unchanged** |
> | **inherits the stdout pipe**, dies on SIGTERM, `FORGE_ENGINE_TIMEOUT=5` | **5.127–5.136 s**, output DISCARDED | **0.380–0.396 s**, output RETURNED |
> | same, `FORGE_ENGINE_TIMEOUT=9` | **9.130–9.140 s** (hence indexed on the BUDGET) | **0.380–0.396 s** |
> | same, **shipped default** (`FORGE_ENGINE_TIMEOUT` not set = 120 s) | **120.061 s** | **0.386 s** |
> | same at BOOT (module registry probe) | **120.66 s** before the `listen` | **1.31 s** |
>
> The cause is fixed, not the symptom: **the response no longer waits for a pipe inherited by a descendant to close
> before being returned**. The work ends when the ENGINE PROCESS exits; what it wrote is then drained
> during a short window (`PIPE_DRAIN_AFTER_EXIT` = 250 ms), then the read is **cut**. The lever named
> previously (`CANCEL_GRACE_SECS`) was not the right one: it was `FORGE_ENGINE_TIMEOUT`.
> **Nothing is truncated**: control measured with 5 MiB of valid output AND a descendant inheriting the pipe — body
> returned **5 243 025 bytes** (`pad` = exactly 5 242 880), valid JSON, **0.79 s**; the same control BEFORE returned
> **351 bytes** of error in **5.13 s**, the 5 MiB discarded.
> **What this choice costs elsewhere, stated and measured**: an engine that CLOSES its two pipes then HANGS is no longer
> bounded by "EOF + `CANCEL_GRACE_SECS`" but by the budget — `FORGE_ENGINE_TIMEOUT=9`: **9.128–9.141 s** versus
> **5.130–5.145 s** before. The outcome is identical (`504`, group killed, no partial output); only the wait
> changes, and it never exceeds the announced budget. **What is no longer captured**: an output written by a
> DESCENDANT AFTER the engine's death (it used to be, at the price above). This matters because detached daemons
> EXIST in this product (`forge/modules/_daemon_reap.py`).
>
> Any bound crossed is **explicit** and NAMES the variable that sets it: documented degradation of the route
> (`techniques_unavailable` / `builtins_unavailable`), `429` `*_busy` (ceiling), `504` `*_timeout` (budget), `502`
> (byte ceiling) — never a silent wait, and never an invented cause. In particular, `501`
> `docx_unavailable` / `pdf_unavailable` is **reserved** for the case where the generator is really absent or has failed:
> saturation returns `429 docx_engine_busy`, an exceeded budget `504 docx_engine_timeout`.
>
> **Measured wall-clock**: the response time of a request cut at its bound equals the budget **plus** the time for the spawn
> to actually die (SIGTERM, then SIGKILL after `CANCEL_GRACE_SECS` = 5 s if a member ignores SIGTERM). Measured with
> `FORGE_ENGINE_TIMEOUT=5` on an engine that exits on SIGTERM: `GET /api/techniques` responds in **5.02–5.06 s**
> (9 consecutive measurements on this batch's binary; before the sweep of detached descendants was added: **5.00–5.03 s**).
> It is THIS figure that the three files stating it must carry (here, `docs/CONFIGURATION.md`, `.env.example`):
> a retracted value had survived in `.env.example` because the clean-up search was on the
> WORDING and not on the FIGURE.

---

## Machine write (ingestion token)

| Method & route | Purpose |
|---|---|
| `POST /api/ingest` | **Junction point** engine→console: receives findings + run-records + coverage + ROE decisions of a campaign. Dedup at the store (`UNIQUE(campaign,target,title)`) — **and the refused share is COUNTED**, see below. |

### What `/api/ingest` returns — and why the refusal count is in it

The `finding` table carries `UNIQUE(campaign, target, title) ON CONFLICT IGNORE`. The key **includes neither
`run_id`, nor `tool`, nor `severity`**: two findings with the same title on the same target — different
modules, or simply **another run of the same campaign** — are absorbed. This absorption is
WHAT MAKES THE INGEST IDEMPOTENT (a flush replayed after a network cut doubles nothing, cf.
`forge/console_client.py::IncrementalIngest`); it is therefore not a defect to remove. The defect
was that it was **silent**: measured on a real campaign, **499 findings out of 5 318 (9.4 %)**
disappeared without a trace, and the report then announced a "Total émis" that was a
**stored** total.

The response now carries the full accounting of the batch:

| Field | Meaning |
|-------|------|
| `findings_attempted` | what the engine **sent** in this POST |
| `findings_ingested` | what was **written** |
| `findings_dropped` | **refused by the uniqueness key** (the triplet already exists) |
| `findings_write_errors` | **lost on write failure** (lock, disk, schema) — distinct cause |
| `runrecords_ingested` · `roe_decisions_ingested` | unchanged |

`findings_attempted == findings_ingested + findings_dropped + findings_write_errors`: nothing can
disappear between the engine and the console without being carried by one of the three counters.

When the POST carries a known `run_id`, `findings_dropped`/`findings_write_errors` are **accumulated**
on `run_job` (each flush carries a delta) and surface in `GET /api/runs`, `GET /api/runs/:id`
and the **run report**. `null` in these columns = run **predating** the counting: the refused share
is *unknown*, which is not the same assertion as "nothing was refused". A POST **without**
`run_id` (ingest outside a run flow, e.g. direct CLI) has no `run_job` row in which to carry the
counter: **the HTTP response is then the only place that states the loss** — the caller must read it.
| `POST /api/dashboards` · `POST /api/dashboards/:id` · `DELETE /api/dashboards/:id` | CRUD of the dashboards. |
| `POST /api/panels` · `POST /api/panels/:id` · `DELETE /api/panels/:id` | CRUD of the GXQL panels. |

---

## C2-light (operator)

| Method & route | Purpose |
|---|---|
| `POST /api/run` | **Launches a governed and audited campaign** (spawns `python3 -m forge.cli campaign`). Body `{campaign, targets[], modules?, mode?, budget?, exhaustive?, reason?, arm?, allow_high_impact?, module_params?}`. Fail-closed: targets ⊆ server scope, **exploit floor** (exploit/destructive refused except high-impact opt-in = operator + `arm=true` + `reason`), **FIFO per engagement** (one live run *per engagement*; 2nd run on the same engagement → **409** with `engagement_id`; other engagements in parallel). Optional `engagement_id` in the body (default = active engagement). See [Architecture §3.3](ARCHITECTURE.md#33-the-governed-c2-light-run-flow). |
| `POST /api/runs/:id/cancel` | Cancels the current run. |
| `POST /api/plan` | **INERT dry-plan** (allow_high_impact=false by construction): shows the ROE verdicts without firing anything. **Operator**: it still spawns an engine process, hence the same gate as `/api/run` (viewer → **403**), bounded time budget (`FORGE_PLAN_TIMEOUT`, default 300 s → **504** `plan_timeout`, engine group killed), bounded concurrency (`FORGE_PLAN_MAX_CONCURRENT`, default 2 → **429** `plan_busy`) and engine output capped in bytes (→ **502** `plan_output_too_large`). |
| `POST /api/modules/refresh` | Repopulates the `module` catalog from `forge.cli modules`. **Bounded** spawn (ceiling `FORGE_ENGINE_OPERATOR_MAX_CONCURRENT`, budget `FORGE_ENGINE_TIMEOUT`): if the probe did not take place, the response carries `probe_error` (and **429** when it is the ceiling) — the catalog returned is then that of the database, not re-probed. |
| `POST /api/import` | Imports a scanner output (parsed by the engine). **Bounded** spawn: ceiling `FORGE_ENGINE_OPERATOR_MAX_CONCURRENT` (→ **429** `import_busy`), budget `FORGE_IMPORT_TIMEOUT` (default 600 s → **504** `import_timeout`, group killed, **no** partial finding inserted), byte ceiling (→ **502**). |

---

## Administration (admin — strict admin session)

| Method & route | Purpose |
|---|---|
| `GET /api/users` | List of accounts (**never** `pass_hash`). |
| `POST /api/users` | Creates an account (`{login, role, password}`; `role ∈ viewer\|operator\|admin`). |
| `POST /api/users/:login` | Updates an account (role, password, `disabled`). The **last enabled admin** is protected. |
| `DELETE /api/users/:login` | Deletes/disables an account. |
| `GET /api/detection/source` | Detection source config — **secret REMOVED** (`secret_set` only). |
| `POST /api/detection/source` | Saves `settings.detection_source` (secret **write-only**), reloads the source hot. Ledger `console.detection.source.set`. |
| `POST /api/detection/test` | Tests a source config (supplied or stored): `{reachable, count, sample_mitres, error?}` — **never** the secret. `keep_secret:true` to test without re-entering it. |
| `POST /api/modules/:kind` | **Connector governance**: `{enabled?, web_allowed?, available_override?}`. Disable ⇒ SKIP at spawn even if the binary is present. Ledger. |
| `GET /api/tools/runtime` | **Tool lifecycle**: state per tool of the manifest (target version, installed version read from the receipt, provenance, pin). Executes no tool. |
| `POST /api/tools/runtime` | `{action, name}` **and nothing else** — `install\|update\|remove` of a tool **from the manifest**. A `url`/`sha256`/`digest`/`version` field makes the request **fail** (400): the source comes from `forge/tools.json`, there is no source parameter. `name` unknown to the manifest, or unreadable manifest ⇒ refusal. Ledger `console.tools.*` + `tools.install` (verified digest) on the installer side. Cf. [`TOOLS_LIFECYCLE.md`](TOOLS_LIFECYCLE.md). |
| `GET /api/notify/channel` | **Outbound notification channel**: config **without the token** (`secret_set` only) + `enabled`. |
| `POST /api/notify/channel` | Saves `settings.notify_channel` (token **write-only**, `keep_secret:true` to avoid retyping it). **OFF by default**: without config, not a single byte goes out. Ledger `console.notify.channel.set` (recipient **redacted**, never the token nor the full URL). |
| `POST /api/notify/channel/test` | Sends a verification message with the **stored** config — the endpoint is **never** a request parameter (otherwise the route would be an SSRF proxy for admins). Ledger `console.notify.dispatch`. |
| `GET /api/notify/sla` | **Triage SLA**: policy (budgets per severity) + `enabled` + `overdue_now` — a **read-only preview** of the number of findings currently overdue (it **notifies nobody**). `capped` says whether the preview hit `max_sweep_rows` (truncated window ≠ healthy database). |
| `POST /api/notify/sla` | Saves `settings.sla_policy` `{enabled, budgets:{SEVERITY:heures}, escalate_to}`. **OFF by default**; `enabled` without a positive budget stays **inert**. Unknown field / severity outside the closed set / non-integer budget ⇒ **400**. Ledger `console.notify.sla.set`. The sweep itself is **leader-only** under HA and ledgers `console.notify.sla.sweep` (**counters only**). |
| `POST /api/backup` | Creates the **encrypted** archive and returns it as a download. Body `{passphrase}`. Ledger `console.backup` (size + sha256, never the passphrase). |
| `POST /api/restore` | Body `{archive_b64, passphrase, apply?, confirm?}`. **By default**: validates + verifies + reports (no write). `apply:true` **requires** `confirm:true` ⇒ in-place swap (**restart required**). |
| `GET /api/backup/policy` | **Redacted** backup policy (secrets `***REDACTED***`; `passphrase_env` = an ENV NAME, kept). |
| `POST /api/backup/policy` | Saves the policy (schedule/retention/offsite). Any `passphrase` in plaintext is removed before persistence. Ledger. |

Backup/restore: [`BACKUP.md`](BACKUP.md). Detection source: [`DETECTION.md`](DETECTION.md).

---

## Conventions

- **Errors**: JSON `{"error": "<code>", "why": "<message lisible>"}` + appropriate HTTP code
  (`400` invalid input, `401` auth required, `403` admin/operator required, `404`, `409` state
  conflict, `421` host not allowed).
- **Secrets**: never returned by a GET, never logged, never ledgered (treated as
  session secrets, redacted in depth).
- **Ledger**: every administration/C2 mutation is sealed (`console.*`) with **metadata
  only** (actor, timestamp, kind), never the secret content.
- **Bind & exposure**: loopback by default. Expose only through a reverse proxy + auth +
  `FORGE_CONSOLE_HOST`. See [Security model](SECURITY_MODEL.md).

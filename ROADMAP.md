# Forge — Roadmap

## In progress

- Nothing mid-flight. Working tree clean. The Postgres/HA program, the UI/UX backlog, the readiness dossier, the **senior code-quality audit** ([`docs/AUDIT.md`](docs/AUDIT.md)) and the **security audit** ([`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md)) have all shipped. Only two items remain, both blocked on an owner decision — see **Backlog (owner input needed)**.

## Recently shipped

- **Security audit (pentest / purple / DevSecOps) + remediation** — see [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md). All HIGH/MEDIUM/LOW exploitable findings fixed: scope-guard redirect bypass + session-secret exfil (`a9678d3`), cross-tenant run IDOR (`5504f5d`), SSO/SCIM hardening (`40ff5dd`), proof-discipline schema-enforcement (`a9678d3`), SSRF deny-list + child-reap + observable audit drops + login lockout (`e1b649e`), ledger truncation high-water-mark (`0d127ee`), k8s/CI hardening (`855c3d1`). Two residual risks accepted + documented (host-root audit integrity → opt-in off-host signer/witness; collector fail-open → reporting-only).
- **Senior code-quality audit + refactor** — see [`docs/AUDIT.md`](docs/AUDIT.md). God-files split behavior-neutral: `launch.js`/`admin.js` → packages (`92759d1`), `runs.rs` → proc/ha/validate (`ac568bd`), `cli.rs` → `cli/` + `compliance.rs` → policy/evidence (`73eaea6`), `state.rs` → schema/detection (`66ae602`), `backup.rs` → crypto/sched (`bcfbf39`), `main()` → dispatch/serve + test redistribution (`bc0244b`), `msf.py` → `_msgpack` (`ab06a3a`); Python mypy on the core (`41c44b4`); canonical secret redaction closing a token leak (`adbf6de`); enterprise swallowed-writes fail-closed + SQL value binding (`6216c70`); `rand_hex`/`err` dedup (`a52e117`).
- **Codebase-quality pass** — `main.rs` decomposed into ~20 focused modules; CONC-1 made cancellation-safe; CSP added; `app.js` split into ES modules. The structural/quality work is done.
- **UI/UX fixes from real usage (2026-07-08/09)** — the full backlog is shipped and browser-validated (commits `2078547`, `4f2ed3b`, `270bc01`). See UI/UX → Done.
- **Postgres program — DELIVERED end-to-end** — the staged plan below is complete: backend enabled (`9e10c67`), governed migrator (`d48ab4b`), HA/ops (`1118f3b`), connection pool + `RETURNING` ids (`e188e2b`). `FORGE_ENTERPRISE_STORE=postgres` runs the whole app, not just the seam.
- **HA / multi-instance / object-store / k8s** — multi-operator presence via the SSE bus (`7ce53f7`); HA foundation (`FORGE_HA` opt-in, leader lease, docker-compose HA harness) (`c07231e`); HA run-leader — leader-only execution, DB-fenced one-run-per-engagement, enqueue/claim (`5a1fb4f`); HA Wave C — ledger single-writer, cross-instance cache invalidation, shared presence (`b85ce1e`); object-store BlobStore — local FS default + S3/MinIO, feature-gated rustls (`0c6fb99`); Kubernetes HA manifests + deny-by-default NetworkPolicies (`3b74963`); HA hardening — audit-ledger never forks under a Postgres outage, monotonic cache epoch, periodic presence GC (`0ff4591`); HA ledger single advisory-lock serializer, closing the disjoint-lock fork window (`0abff20`).

## UI/UX

### Done

- **[UX] Unavailable tools disabled** (commit `2078547`, quick-wins) — tools with `available=false` render disabled/greyed **and** are excluded from the run payload.
- **[UX] Select all / Deselect all** (commit `2078547`) — added to the module/tool selection.
- **[CSS] Text overflow fixed** (commit `2078547`) — module/attack name overflow resolved with forge-scoped CSS.
- **[functional] Live run logs** (commit `4f2ed3b`, run-flow) — engine progress hook + `PYTHONUNBUFFERED`; per-action lines stream to the run view via SSE.
- **[functional] Per-module outcome table** (commit `4f2ed3b`) — the run detail shows per-module outcomes with **SKIP distinct from ERROR**, and carries the real per-module reason.
- **[functional/UX] Inline findings + zero-findings state** (commit `4f2ed3b`) — findings for the run render inline, with a real zero-findings empty state.
- **[functional] SKIP-label neutrality** (commit `270bc01`) — the SKIP tile and zero-findings empty-state no longer hardcode "outils absents"; they use a neutral label (`SKIP/ignoré`, `ignorés`) so a governance-disabled or technique-deselected SKIP isn't mislabeled as a missing tool. The per-module outcome table stays the source of truth for the exact reason.

### Remaining

- None.

## Postgres program (staged) — DONE

- **Stage 0 — DONE** — Store DB-access seam + module conversion (DML-only; PRAGMA/DDL/backup + SoQL's own read-only connection stay backend-specific). Seam coverage-complete, remaining modules converted.
- **Stage 1 — DONE** — SQL dialect normalization behind the seam (`?` vs `$N` placeholders, autoincrement, `INSERT OR REPLACE` → `ON CONFLICT`, `json_extract` → `->>`, PRAGMA guarded). SQLite active and byte-identical.
- **Stage 2 — DONE** — PG backend implemented + integration-tested (docker), feature-gated behind `store-postgres` (OFF by default → community build byte-identical, openssl-free via rustls). PG schema DDL + SoQL reader PG `value` → neutral-`Value` mapping in place.
- **Stage 2b — DONE** (`9e10c67`) — all remaining `db()` DML + boot seeding (`populate_modules` / `ensure_default_engagement` / `tenant` / `dashboard`) routed through the ACTIVE backend, whole app validated against a real Postgres, `FORGE_ENTERPRISE_STORE=postgres` enabled without split-brain. Concurrent-writer safety: connection pool + `RETURNING` ids (`e188e2b`).
- **Stage 3 — DONE** (`d48ab4b`) — governed migrator CLI `forge migrate-store --to <postgres-url> [--from <sqlite>] [--dry-run] [--force]`: FK-order copy, idempotent, dry-run + row-count verify, signed `console.store.migrate` ledger checkpoint (`console/src/cli.rs`).
- **Stage 4 — DONE** (`1118f3b`) — HA/ops: connection pool + timeouts, `/health` DB ping + reconnect, `pg_dump` backup, Postgres in docker-compose enterprise profile, docs. Extended by the HA/multi-instance work listed under Recently shipped.

> Note: the tamper-evident ledger is a file (`jsonl`), not in the DB — Postgres does not affect audit integrity. Under HA it is serialized by a single advisory-lock writer (`0abff20`).

## Enterprise SSO

- **SSO / SAML (readiness #16) — RESOLVED for deployment.** Forge enterprise SSO is **OIDC**
  (`FORGE_ENTERPRISE_SSO`, flag-gated in `console/src/sso.rs`: Authorization-Code + PKCE, RS256/JWKS ID-token
  validation, redirect allowlist, and IdP `groups` → Forge role/grants via the RBAC groups-from-claims seam).
  **SAML-only IdPs are supported via an external OIDC bridge** — front Forge with **Dex** (SAML connector),
  **Keycloak identity brokering**, or **oauth2-proxy**, which terminates SAML and presents OIDC to Forge.
  Rationale: native in-process SAML would pull `samael` → openssl + libxmlsec1 (C toolchain), breaking the
  openssl-free (rustls/ring) posture, and hand-rolled XML-DSig/exclusive-C14N is the XML-Signature-Wrapping
  (XSW) auth-bypass foot-gun class; the bridge keeps Forge's auth surface pure-Rust with zero new deps.
  Documented in [`docs/DEPLOYMENT.md` §3ter](docs/DEPLOYMENT.md). Native in-process SAML stays **DEFERRED**
  behind an optional `saml` cargo feature (samael-backed, openssl+libxmlsec1 build variant; community default
  stays openssl-free) — available on request if a contract hard-requires it, not built today.

## Deferred engineering

- **`significant_drop_tightening` clippy lint — RESOLVED / ENABLED** (`3c7a5c4`). The lint is on; the remaining legitimate lock-hold sites (atomic check-then-act blocks) carry a scoped `#[allow]` with a rationale.
- **`last_insert_id()` session-scoping — RESOLVED** via `Store::execute_returning_id` (`e188e2b`): `RETURNING id` on Postgres in one round-trip, `last_insert_rowid()` on the held SQLite connection — no `lastval()`/session dependency, safe on a pooled backend.

## Backlog (owner input needed)

- **Nothing open.** The two previously-open items shipped (see below). No roadmap / readiness / audit item is unresolved except the deliberately accepted-as-is items.

### Shipped (were the last two owner-decision items)
- **KMS/HSM key custody — DONE (`d7fb893`).** Concrete **PKCS#11 signer** (`Pkcs11Signer`, Ed25519/`CKM_EDDSA`, subclass of `RemoteSigner` → re-verifies its own signature, no local fallback), opt-in (`FORGE_LEDGER_SIGNER=pkcs11`), optional dep (`pip install 'forge[pkcs11]'` — default stays stdlib-only, `LocalFileSigner` byte-identical). SoftHSM2 dev/CI, HSM/CloudHSM/cloud-KMS-via-PKCS#11 prod. Chosen over AWS-KMS because the ledger is Ed25519 and AWS-KMS can't sign Ed25519; generic exec-signer covers GCP-KMS/custom. Closes the F4 audit residual (off-host key) when paired with `WitnessAnchor`. Docs: [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md).
- **Finding ownership — DONE (`6723dab`).** Nullable `finding.assignee`; grant-scoped single + bulk assign (caller must operate the engagement; assignee must hold a grant on it), ledgered `console.finding.assign`; assignee shown in the findings view + filterable via saved-views. Deliberately an ownership pointer, **not** a finding-triage lifecycle state machine (see Possible next).

## Possible next (not scheduled — product decision)
- **Finding-triage workflow.** Forge is already a workflow engine on the *execution* axis (planner + iterative plan→observe→replan campaign over an `EngagementGraph` + governance state machine + `workflows.js`). It is NOT a *finding-triage* workflow: a lifecycle over findings (e.g. new→triaging→retesting→reported→closed) with allowed transitions, ownership routing, and notifications. The substrate exists (`status`, `assignee`, ledger, SSE event bus, saved-views, presence) — this is the natural next feature if a triage lifecycle is wanted.

## Accepted as-is (deliberate, not backlog)

- **`main.rs` router-integration tests (~25) stay in `main.rs`.** The code-quality audit redistributed the cleanly-homed tests (backup/dbmigrate/cli); the remaining ones drive `build_router` end-to-end through a shared helper web — they are genuine main.rs integration tests, not misplaced unit tests. Moving them would be artificial. (A `tests/` integration dir is awkward for a binary crate.)
- **Best-effort `let _ = store.execute(...)` sites** (presence heartbeat/GC, session GC, HA heartbeat, SCIM group membership best-effort, background run-cancel) are intentional fail-soft with no audit attestation — left as-is by design. The audit-bearing swallowed-writes were all fixed.
- **SQLite/Postgres path duplication** (a few `_pg`/`_store` variants) — collapsing onto the seam is a larger effort with no correctness gain; deferred, low priority.

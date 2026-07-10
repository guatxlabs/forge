# Forge — Roadmap

## In progress

- Nothing actively mid-flight. Queued work is the deferred Postgres stages (2b → 3 → 4, see below) and one small SKIP-label cosmetic polish (see UI/UX).

## Recently shipped

- **Codebase-quality pass** — `main.rs` decomposed into ~20 focused modules; CONC-1 made cancellation-safe; CSP added; `app.js` split into ES modules. The structural/quality work is done.
- **UI/UX fixes from real usage (2026-07-08/09)** — see below; the 6 backlog items are shipped and browser-validated (commits `2078547`, `4f2ed3b`), leaving only one cosmetic label tweak.

## UI/UX

### Done

- **[UX] Unavailable tools disabled** (commit `2078547`, quick-wins) — tools with `available=false` render disabled/greyed **and** are excluded from the run payload.
- **[UX] Select all / Deselect all** (commit `2078547`) — added to the module/tool selection.
- **[CSS] Text overflow fixed** (commit `2078547`) — module/attack name overflow resolved with forge-scoped CSS.
- **[functional] Live run logs** (commit `4f2ed3b`, run-flow) — engine progress hook + `PYTHONUNBUFFERED`; per-action lines stream to the run view via SSE.
- **[functional] Per-module outcome table** (commit `4f2ed3b`) — the run detail shows per-module outcomes with **SKIP distinct from ERROR**.
- **[functional/UX] Inline findings + zero-findings state** (commit `4f2ed3b`) — findings for the run render inline, with a real zero-findings empty state.

### Remaining (small cosmetic)

- **SKIP-label neutrality** — the SKIP tile / zero-findings empty-state label hardcodes "outils absents", but SKIP also covers governance-disabled and technique-deselected reasons. Make the label neutral / derived from the actual reasons (the per-module table already shows the true reason). File: `console/web/js/views/launch.js` (`renderRunFindings` / `runCountTilesHtml`).

## Postgres program (staged)

- **Stage 0 — DONE** — Store DB-access seam + module conversion (DML-only; PRAGMA/DDL/backup + SoQL's own read-only connection stay backend-specific). Seam coverage-complete, remaining modules converted.
- **Stage 1 — DONE** — SQL dialect normalization behind the seam (`?` vs `$N` placeholders, autoincrement, `INSERT OR REPLACE` → `ON CONFLICT`, `json_extract` → `->>`, PRAGMA guarded). SQLite active and byte-identical.
- **Stage 2 — implemented + integration-tested (docker), BANKED FAIL-CLOSED behind the `store-postgres` feature — NOT enabled.** `FORGE_ENTERPRISE_STORE=postgres` refuses at startup pending Stage 2b. Cargo feature `store-postgres` OFF by default → community build byte-identical, openssl-free via rustls. PG schema DDL + SoQL reader PG `value` → neutral-`Value` mapping in place.
- **Stage 2b — DEFERRED (until HA is a concrete need)** — route ALL remaining `db()` DML + boot seeding (`populate_modules` / `ensure_default_engagement` / `tenant` / `dashboard`) through the ACTIVE backend, and validate the whole app (not just the seam) against a real Postgres, so `FORGE_ENTERPRISE_STORE=postgres` can be enabled without a split-brain.
- **Stage 3 — DEFERRED** — Governed migrator: CLI `migrate-store --from sqlite --to postgres` (FK-order, idempotent, `--dry-run` + row-count verify, signed `console.store.migrate` ledger checkpoint).
- **Stage 4 — DEFERRED** — HA/ops: connection pool + timeouts, `/health` DB ping, Postgres in docker-compose enterprise profile, backup/restore doc, CI matrix (SQLite + PG).

> Note: the tamper-evident ledger is a file (`jsonl`), not in the DB — Postgres does not affect audit integrity.

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

- **`significant_drop_tightening` clippy lint** — currently OFF (~93 preexisting lock-hold sites out of scope); `await_holding_lock` covers the CONC-1 invariant. Enable after tightening those sites.
- **`last_insert_id()` is session-scoped** — the Stage-2 Postgres backend must use a session-pinned client (or add an `insert_returning_id()` convenience).

# Forge — Roadmap

## In progress

- **Postgres HA backend**, staged 0 → 4 (see [Postgres program](#postgres-program-staged) below). Stage 0 seam (coverage-complete) + pilot done.

## UI/UX backlog (from real usage, 2026-07-08)

- **[functional] Live run logs** — the Launch/C2 view shows only "running" with no real-time output. Wire the `run_sse` / `run_logs` SSE stream into the run view, and make the Python engine emit **progressive per-action events** (started / tool-invoked / result) instead of only the final batch.
- **[UX] Unavailable tools are selectable** — a module/tool with `available=false` can still be selected. Disable/grey it with a "not installed" hint (or block + warn).
- **[UX] No Select all / Deselect all** for the module/tool selection.
- **[functional/investigate] Runs sometimes appear not to execute the tools** — likely unavailable tools degrade to "skipped" invisibly. Surface the per-module outcome in the run view (fired / skipped-unavailable / degraded / error).
- **[UX] Run result not formatted, even with zero findings** — add a clean "no findings" empty state + a formatted per-module outcome summary + a raw output panel.
- **[CSS] Text overflow** — module/attack names overflow their cards/divs in the Launch/modules/techniques views. Fix with `min-width: 0` on flex children + ellipsis/word-break + container overflow (forge-scoped CSS).

## Postgres program (staged)

- **Stage 0** — Store DB-access seam (DML-only; PRAGMA/DDL/backup + SoQL's own read-only connection stay backend-specific). Seam coverage-complete + pilot done; **Stage 0b** converts the remaining ~16 modules to the seam.
- **Stage 1** — SQL dialect normalization behind the seam (`?` vs `$N` placeholders, autoincrement, `INSERT OR REPLACE` → `ON CONFLICT`, `json_extract` → `->>`, PRAGMA guarded). Still SQLite-only.
- **Stage 2** — Postgres backend behind cargo feature `store-postgres` (OFF by default → community byte-identical, openssl-free via rustls). Runtime `FORGE_ENTERPRISE_STORE=postgres` + `FORGE_DB_URL`. PG schema DDL. SoQL reader gets a PG `value` → neutral-`Value` mapping.
- **Stage 3** — Governed migrator: CLI `migrate-store --from sqlite --to postgres` (FK-order, idempotent, `--dry-run` + row-count verify, signed `console.store.migrate` ledger checkpoint).
- **Stage 4** — HA/ops: connection pool + timeouts, `/health` DB ping, Postgres in docker-compose enterprise profile, backup/restore doc, CI matrix (SQLite + PG).

## Deferred engineering

- **`significant_drop_tightening` clippy lint** — currently OFF (~93 preexisting lock-hold sites out of scope); `await_holding_lock` covers the CONC-1 invariant. Enable after tightening those sites.
- **`last_insert_id()` is session-scoped** — the Stage-2 Postgres backend must use a session-pinned client (or add an `insert_returning_id()` convenience).

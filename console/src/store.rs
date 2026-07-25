// SPDX-License-Identifier: AGPL-3.0-or-later
//! PORTABLE DB-ACCESS SEAM (Stage 0) — a thin, backend-agnostic façade over the console's SQLite
//! connection whose PUBLIC API leaks ZERO rusqlite-specific types. Every call site that migrates onto
//! `App::store()` becomes portable: a `Backend::Postgres(..)` arm (Stage 2, behind a `postgres` cargo
//! feature) can satisfy the SAME `Store` / `Row` / `Param` surface WITHOUT touching the call sites.
//!
//! WHY THIS IS BEHAVIOUR-PRESERVING TODAY:
//!   - `App::store()` acquires the SAME `Mutex<Connection>` guard `App::db()` does and HOLDS it for the
//!     `Store`'s lifetime. A sequence of `store.execute(..)` / `store.query(..)` calls therefore runs
//!     under ONE held lock, exactly like `let db = app.db(); db.execute(..); db.execute(..);` does now.
//!     Locking granularity is unchanged, so no concurrency semantics shift.
//!   - The parameter placeholder style is SQLite `?` (unchanged). SQL strings pass through VERBATIM —
//!     dialect normalisation (`?` -> `$1`, `datetime('now')` mapping, …) is Stage 1 and is NOT done here.
//!   - `Param::Bool` binds as `INTEGER 0/1` (identical to rusqlite's `ToSql for bool`), so a converted
//!     `params![some_bool]` is byte-identical on the wire.
//!   - `query_row` returns `Err(StoreError::NoRows)` on an empty result set (mirrors rusqlite's
//!     `QueryReturnedNoRows`), so existing `.is_ok()` / `match … Err(_) => …` call sites are unchanged.
//!
//! STAGE-0 SCOPE: `rusqlite` only. No new dependency. The tamper-evident ledger is a FILE (JSONL) and
//! is NOT reachable through this seam — the seam is DB-only by construction.
//!
//! SEAM COVERAGE BOUNDARY (what the seam abstracts vs. what stays backend-specific):
//!   - The seam abstracts DML ONLY — `execute` / `execute_batch` / `query` / `query_lax` / `query_opt`
//!     / `query_row` / `last_insert_id` / `with_tx`, plus BOTH row-read shapes: the statically-typed
//!     getters (`Row::get_i64` / `get_str` / …) for columns of KNOWN type, and the dynamic/untyped
//!     accessor `Row::get_value` (+ `get_value_by`) for generic readers that must dispatch on the
//!     cell's RUNTIME storage class. Every call site that speaks only this vocabulary becomes
//!     portable, and a `Backend::Postgres(..)` arm satisfies the SAME surface at Stage 2.
//!   - GENERIC SoQL READER (`query.rs::cell` / `exec_soql`): reads columns of unknown runtime type via
//!     `row.get_ref(i)` and dispatches on the storage class (Integer/Real/Text/Blob/Null). The
//!     statically-typed getters CANNOT express this (`get_i64` on a TEXT column errors under rusqlite's
//!     type-strict `FromSql`), so the seam grows `Row::get_value` — the value-driven dual of the typed
//!     getters — which reproduces that dispatch backend-neutrally. `query.rs` is NOT converted in this
//!     stage: `exec_soql` opens its OWN `SQLITE_OPEN_READ_ONLY` `Connection` (a CONNECTION-LEVEL
//!     concern, out of scope here — handled in Stage 0b/2 when that connection is drawn through the
//!     seam). This stage ONLY adds the `get_value` capability and proves it; the SoQL reader will
//!     switch to `get_value` once its connection goes through the seam.
//!   - CONNECTION-LEVEL operations are DELIBERATELY out of scope and remain backend-specific in
//!     boot / migration / CLI: `PRAGMA journal_mode` / `PRAGMA foreign_keys`, `PRAGMA key` (SQLCipher),
//!     SQLCipher `ATTACH`/export, the online backup API (`Connection::backup`), and `ATTACH DATABASE`.
//!     None of these are expressible through a backend-agnostic surface — a Postgres backend has its
//!     OWN connection setup (DSN, TLS, `search_path`, `pg_dump`, logical replication), so pushing them
//!     into the seam would leak the very driver specifics the seam exists to hide. This is BY DESIGN,
//!     not a coverage gap: each backend owns its connection lifecycle; the seam owns the DML on top.
//!   - `last_insert_id()` is SESSION-SCOPED. It reports the last INSERT rowid on THIS `Store`'s held
//!     connection, so it is meaningful ONLY when paired with an `execute(INSERT …)` on the SAME `Store`
//!     with no interleaved INSERT on that connection in between. The pilot call sites guarantee exactly
//!     that: each acquires ONE `App::store()` and runs `execute(INSERT)` then `last_insert_id()`
//!     back-to-back under the one held lock. A Stage-2 Postgres backend MUST therefore bind this to a
//!     SESSION-PINNED client (e.g. `RETURNING id`, or `lastval()` on the same session) — NEVER a
//!     per-call connection drawn from a pool, which could surface another session's insert id.
//!
//! This module intentionally exposes a FULL surface (all typed getters, by-name variants, a tx handle)
//! ahead of the module-by-module migration, so `#![allow(dead_code)]` covers the arms not yet used by
//! the pilot modules (they light up as more modules convert).
#![allow(dead_code)]

use rusqlite::types::Value as SqlValue;

// ================================================================================================
// POSTGRES BACKEND (Stage 2) — everything postgres-specific lives behind `#[cfg(feature =
// "store-postgres")]`. The DEFAULT build compiles NONE of this (byte-identical, openssl-free); the
// feature build stays openssl-free too (rustls + ring, never native-tls/openssl). The seam's PUBLIC
// surface (`Param`/`Value`/`Row`/`Store`/`StoreError`) is UNCHANGED — only new arms/impls are added.
//
// ⚠️ NOT WIRED INTO APP STARTUP YET (Stage 2b pending). This backend is INTEGRATION-TESTED (the
// `pg_tests` module below constructs a `Store::postgres(..)` DIRECTLY against a real Postgres,
// bypassing app startup, so it fully validates the backend) but the running console NEVER selects it:
// `main.rs::enterprise_store_gate` FAILS CLOSED (refuses to start) when `FORGE_ENTERPRISE_STORE=
// postgres`, and `App.pg` is always `None`, so `App::store()` always resolves to SQLite. This is
// deliberate: routing `store()` to Postgres while the >100 raw `db()` call sites and ALL boot seeding
// (`populate_modules` / `ensure_default_*`) still write to SQLite would SPLIT the database. Stage 2b
// MUST route ALL DML + boot seeding through the active backend BEFORE `FORGE_ENTERPRISE_STORE=postgres`
// can be enabled; only then may the startup gate and the `App.pg` wiring be re-activated.
// ================================================================================================

#[cfg(feature = "store-postgres")]
use postgres::types::{IsNull, ToSql, Type};

/// TYPED-NEUTRAL SQL NULL. Postgres statically types every bound parameter from the *prepared
/// statement's* inferred column type, then calls `ToSql::accepts(inferred_type)` — so binding a
/// concrete Rust `Option::<i64>::None` for, say, a `TEXT` column is REJECTED at `accepts` time even
/// though the value is NULL. `PgNull` sidesteps that: `accepts` returns `true` for EVERY type and
/// `to_sql` writes `IsNull::Yes`, so it binds a NULL regardless of the column's inferred type — the
/// portable analogue of `Param::Null` -> `SqlValue::Null` on SQLite.
#[cfg(feature = "store-postgres")]
#[derive(Debug)]
struct PgNull;

#[cfg(feature = "store-postgres")]
impl ToSql for PgNull {
    fn to_sql(
        &self,
        _ty: &Type,
        _out: &mut bytes::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        Ok(IsNull::Yes)
    }
    fn accepts(_ty: &Type) -> bool {
        true
    }
    postgres::types::to_sql_checked!();
}

/// Adapt a backend-neutral `&[Param]` slice to OWNED boxed `ToSql` binds (the postgres client takes
/// `&[&(dyn ToSql + Sync)]`). Binding rules mirror the SQLite lowering EXACTLY:
///   - `Int(i64)`  -> `i64`  (BIGINT — the schema maps every SQLite `INTEGER` to `BIGINT`)
///   - `Real(f64)` -> `f64`  (DOUBLE PRECISION)
///   - `Text`      -> `String`
///   - `Blob`      -> `Vec<u8>` (BYTEA)
///   - `Bool(b)`   -> `i64` 0/1 (NOT PG `bool`: the schema stores booleans as `BIGINT` 0/1 to match
///     SQLite's `INTEGER` 0/1 semantics, identical to `Param::Bool` on SQLite)
///   - `Null`      -> `PgNull` (typed-neutral NULL, see above)
#[cfg(feature = "store-postgres")]
fn pg_binds(params: &[Param]) -> Vec<Box<dyn ToSql + Sync>> {
    params
        .iter()
        .map(|p| -> Box<dyn ToSql + Sync> {
            match p {
                Param::Int(v) => Box::new(*v),
                Param::Real(v) => Box::new(*v),
                Param::Text(v) => Box::new(v.clone()),
                Param::Blob(v) => Box::new(v.clone()),
                Param::Bool(v) => Box::new(if *v { 1_i64 } else { 0_i64 }),
                Param::Null => Box::new(PgNull),
            }
        })
        .collect()
}

/// Translate the seam's SQLite `?` placeholders to postgres `$1, $2, …` LEFT-TO-RIGHT. `?` characters
/// INSIDE single-quoted string literals are left VERBATIM (the console's SQL is static/controlled, but
/// this stays safe against a literal that contains a `?`). SQL-standard doubled-quote escapes (`''`)
/// inside a literal are handled so the literal boundary is tracked correctly.
///
/// SCOPE / LIMITATIONS (STATIC SQL ONLY): this tracks single-quoted literals ONLY. It does NOT skip a
/// `?` that appears inside a SQL comment (`-- …` line / `/* … */` block), a dollar-quoted string
/// (`$$ … ?$$` / `$tag$ … $tag$`), or a double-quoted identifier (`"col?"`). None of those appear in
/// the console's static, hand-written SQL (which is what this seam translates), so this is safe by
/// construction here — but if that assumption ever changes (dynamic SQL, generated identifiers, or a
/// literal `?` inside a comment/dollar-quote), the translator would MIS-COUNT and MUST be extended to
/// track those contexts too. It is NOT a general-purpose SQL rewriter.
#[cfg(feature = "store-postgres")]
fn translate_placeholders(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n: u32 = 0;
    let mut in_squote = false;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if in_squote {
            out.push(c);
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    // Doubled '' escape: consume the second quote, stay inside the literal.
                    out.push('\'');
                    chars.next();
                } else {
                    in_squote = false;
                }
            }
            continue;
        }
        match c {
            '\'' => {
                in_squote = true;
                out.push('\'');
            }
            '?' => {
                n += 1;
                out.push('$');
                out.push_str(&n.to_string());
            }
            other => out.push(other),
        }
    }
    out
}

/// Rewrite the SQLite-only `datetime('now')` timestamp expression to the portable
/// `CAST(CURRENT_TIMESTAMP AS TEXT)` for the Postgres backend — the SAME lowering the boot seeders
/// (`state.rs::ensure_default_*`) already apply INLINE, generalised here so EVERY seam DML site that
/// still writes `datetime('now')` (settings/users/run_job/run_log/engagement/tenant…) is portable
/// without touching each call site. On SQLite the seam does NOT call this (the SQLite arm passes SQL
/// verbatim), so those sites stay byte-identical; on SQLite `CAST(CURRENT_TIMESTAMP AS TEXT)` renders
/// the SAME `YYYY-MM-DD HH:MM:SS` text as `datetime('now')` (parity the seeders already rely on).
///
/// Matched case-insensitively and ONLY OUTSIDE single-quoted string literals — a `datetime('now')`
/// appearing inside a DATA literal is left verbatim (single-quote tracking mirrors
/// `translate_placeholders`, incl. the doubled `''` escape). STATIC SQL ONLY (same controlled-input
/// assumption as the placeholder translator); no other dialect rewrite is done. Byte-preserving: it
/// copies original bytes verbatim and only inserts ASCII, so non-ASCII literals (e.g. `'Défaut'`) round
/// -trip intact.
#[cfg(feature = "store-postgres")]
fn rewrite_datetime_now(sql: &str) -> String {
    const NEEDLE: &[u8] = b"datetime('now')";
    const REPL: &[u8] = b"CAST(CURRENT_TIMESTAMP AS TEXT)";
    let bytes = sql.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(sql.len());
    let mut i = 0;
    let mut in_squote = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_squote {
            out.push(c);
            if c == b'\'' {
                // Doubled '' escape: stay inside the literal, copy both quotes.
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    out.push(b'\'');
                    i += 2;
                    continue;
                }
                in_squote = false;
            }
            i += 1;
            continue;
        }
        // Outside any literal: try to match the whole `datetime('now')` token case-insensitively. The
        // token embeds a `'now'` literal, but matching it as one unit means we never toggle `in_squote`
        // for that inner quote.
        if i + NEEDLE.len() <= bytes.len() && bytes[i..i + NEEDLE.len()].eq_ignore_ascii_case(NEEDLE) {
            out.extend_from_slice(REPL);
            i += NEEDLE.len();
            continue;
        }
        if c == b'\'' {
            in_squote = true;
        }
        out.push(c);
        i += 1;
    }
    // Byte-preserving copy of valid UTF-8 with only ASCII inserted at ASCII boundaries -> valid UTF-8.
    String::from_utf8(out).expect("rewrite_datetime_now: byte-preserving rewrite stays valid UTF-8")
}

/// Full SQLite-`?`-dialect -> Postgres SQL translation for the seam's PG arm: dialect rewrites
/// (`datetime('now')` -> portable timestamp) FIRST, then `?` -> `$n` placeholder numbering. Order is
/// irrelevant to the numbering (the datetime rewrite inserts no `?`), but doing dialect first keeps the
/// placeholder pass operating on the final statement text. SQLite arm never calls this (verbatim SQL).
#[cfg(feature = "store-postgres")]
fn translate_sql(sql: &str) -> String {
    translate_placeholders(&rewrite_datetime_now(sql))
}

/// Map a `postgres::Error` to the seam's `StoreError` (message VERBATIM — same discipline as the
/// rusqlite `From` impl, so `format!("… {e}")` call sites read identically).
#[cfg(feature = "store-postgres")]
fn pg_err(e: postgres::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// Run a BLOCKING postgres-client call safely w.r.t. the tokio runtime.
///
/// WHY THIS EXISTS: the synchronous `postgres` client drives its OWN current-thread tokio runtime via
/// `block_on` for every call. Invoking that from a thread that is ALREADY inside a tokio runtime (an
/// axum handler runs on a multi-thread worker) panics with *"Cannot start a runtime from within a
/// runtime"*. `tokio::task::block_in_place` announces the blocking section so the multi-thread runtime
/// parks the worker and the nested `block_on` becomes legal (empirically validated). Rusqlite needs
/// none of this because it is pure-C synchronous with no runtime.
///
/// OUTSIDE any runtime — the SYNC integration tests, and any CLI/off-runtime caller — we call `f`
/// directly, because `block_in_place` ITSELF panics when there is no current runtime. `Handle::
/// try_current()` distinguishes the two cases. NOTE: the runtime MUST be multi-thread (the console's
/// `#[tokio::main]` default + `rt-multi-thread`); `block_in_place` is unsupported on a current-thread
/// runtime. The matching boot-time requirement is that the client be CONNECTED (and dropped) off the
/// runtime — see `App` wiring in `main.rs` (connect on a dedicated `std::thread`).
#[cfg(feature = "store-postgres")]
fn pg_block<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => tokio::task::block_in_place(f),
        Err(_) => f(),
    }
}

/// Build a SESSION-PINNED synchronous `postgres::Client` for `url` (a `postgres://…` DSN). TLS is
/// openssl-free: a rustls `ClientConfig` on the `ring` crypto provider (NOT aws-lc / native-tls) with
/// Mozilla's webpki-roots as the trust anchor set, wrapped in `tokio-postgres-rustls`'s
/// `MakeRustlsConnect`. TLS is USED when the server offers it (sslmode negotiation); a local server
/// without SSL falls back to plaintext — so the same connector serves a TLS prod DSN and a plaintext
/// docker test DSN. The returned client is the ONE client the `App` holds for its lifetime (see the
/// module docs on `last_insert_id` session-pinning).
/// The synchronous postgres client type the pool holds (re-exported so `main.rs` can name it without a
/// direct `postgres` path dependency).
#[cfg(feature = "store-postgres")]
pub(crate) type PgClient = postgres::Client;

#[cfg(feature = "store-postgres")]
pub(crate) fn connect_postgres(url: &str) -> Result<postgres::Client, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(config);
    postgres::Client::connect(url, tls).map_err(|e| format!("postgres connect ({url}): {e}"))
}

/// CONNECTION POOL of `N` postgres clients BUNDLED with the DSN so a broken client can be
/// RE-ESTABLISHED (Stage 4 HA — PG restart / failover). Held by `App.pg` as `Arc<PgPool>`;
/// `App::store()` calls [`PgPool::checkout`] to grab ONE FREE client (a per-slot `MutexGuard`) and
/// hands BOTH the held guard AND `url` to [`Store::postgres_reconnectable`]. The guard is held for the
/// `Store`'s lifetime and RELEASED on drop (check-in) — so concurrent operators run on DIFFERENT slots
/// and DO NOT serialise on one client. Within a `Store` the SAME checked-out client serves every op
/// (so `with_tx` runs all its statements on ONE connection); across `Store`s the pool spreads load.
///
/// WHY A POOL IS NOW SAFE: the id source is no longer session-scoped `lastval()` — every runtime insert
/// uses [`Store::execute_returning_id`] (`RETURNING id` in ONE statement), so an insert's id never
/// depends on which pooled connection it ran on. On a connection-level failure a READ reconnects+retries
/// ONCE ([`pg_run_read`]); a WRITE / transaction-control op reconnects the client for the NEXT op but is
/// NEVER auto-re-run ([`pg_run_write`]). Reconnect swaps the FRESH client INTO the SAME slot's `Mutex`
/// (the broken client is dropped there), so that slot heals in place for its next checkout — the exact
/// per-connection reconnect logic, now applied to whichever slot a `Store` checked out.
#[cfg(feature = "store-postgres")]
pub(crate) struct PgPool {
    pub(crate) url: String,
    /// One `Mutex<Client>` per slot. A checkout `try_lock`s a FREE slot; a held guard IS the checkout,
    /// released (checked back in) on drop. Reconnect swaps a fresh client into the slot's `Mutex`.
    clients: Vec<std::sync::Mutex<postgres::Client>>,
    /// Round-robin starting index for the checkout scan, so bursts of checkouts fan out across slots
    /// instead of all probing slot 0 first. `Relaxed` is fine — it only biases which slot is TRIED
    /// first, never correctness (the scan still finds any free slot).
    cursor: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "store-postgres")]
impl PgPool {
    /// Build a pool from `n` already-connected clients (connected OFF the tokio runtime — see the
    /// `App` wiring in `main.rs`). `clients` must be non-empty (the caller connects at least one).
    pub(crate) fn new(url: String, clients: Vec<postgres::Client>) -> Self {
        debug_assert!(!clients.is_empty(), "PgPool needs at least one client");
        PgPool {
            url,
            clients: clients.into_iter().map(std::sync::Mutex::new).collect(),
            cursor: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Number of pooled clients (fixed at construction).
    pub(crate) fn size(&self) -> usize {
        self.clients.len()
    }

    /// Check out ONE client for the caller's `Store`. Scans all slots with `try_lock` starting at the
    /// round-robin cursor and returns the FIRST free slot's guard — so up to `N` concurrent operators
    /// each get a DISTINCT client and run in parallel (no serialisation on one mutex). A poisoned-but-
    /// free slot is RECOVERED in place (a prior panic must not strand a connection). If EVERY slot is
    /// currently busy, BLOCK on the round-robin slot (excess load fans in across the `N` slots, bounded).
    /// The returned guard is the checkout; dropping it (end of the `Store`) checks the client back in.
    pub(crate) fn checkout(&self) -> std::sync::MutexGuard<'_, postgres::Client> {
        use std::sync::atomic::Ordering;
        let n = self.clients.len();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        for i in 0..n {
            let idx = (start.wrapping_add(i)) % n;
            match self.clients[idx].try_lock() {
                Ok(g) => return g,
                // Free but poisoned by a prior panic — recover the guard (the sync `postgres::Client`
                // itself is not left in a torn state by a panicked seam op; a failed query returns Err).
                Err(std::sync::TryLockError::Poisoned(p)) => return p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => continue,
            }
        }
        // All slots busy: block on the round-robin slot until it frees (recover poison the same way).
        let idx = start % n;
        self.clients[idx].lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Is `e` a CONNECTION-level failure (client closed / broken pipe / reset / server shutting the session
/// down — e.g. after a PG restart or failover) rather than a server-side SQL error we must surface as-is?
/// A SQLSTATE db-error is normally a REAL query error (constraint/syntax/…) and MUST NOT trigger a
/// reconnect+retry — EXCEPT the fatal connection classes the server sends while tearing a session down:
/// SQLSTATE class `08` (connection exception) and `57P01`/`57P02`/`57P03` (admin/crash shutdown,
/// cannot-connect-now). Otherwise: `is_closed()` catches a terminated connection, and a non-db error
/// whose `source()` chain carries an `io::Error` catches the first failing send after a break.
#[cfg(feature = "store-postgres")]
fn pg_is_conn_error(e: &postgres::Error) -> bool {
    use std::error::Error as _;
    if let Some(db) = e.as_db_error() {
        let code = db.code().code();
        return code.starts_with("08") || matches!(code, "57P01" | "57P02" | "57P03");
    }
    if e.is_closed() {
        return true;
    }
    let mut src = e.source();
    while let Some(s) = src {
        if s.downcast_ref::<std::io::Error>().is_some() {
            return true;
        }
        src = s.source();
    }
    false
}

/// Run one IDEMPOTENT READ `op` (query / query_lax / query_opt) on the held client, with SINGLE-SHOT
/// RECONNECT-AND-RETRY on a connection-level failure (Stage 4 HA). Attempt once; if it fails with a
/// [`pg_is_conn_error`] AND a DSN (`url`) is present, RECONNECT ([`connect_postgres`]) ONCE, swap the
/// fresh client INTO the held Mutex (so subsequent `store()` calls on the shared `Arc` reuse the healed
/// client), and RETRY `op` exactly once; a still-failing retry returns its error. A NON-connection error
/// (SQLSTATE query error) or a `Store` built WITHOUT a url (`postgres` / the CLI/tests) returns the first
/// error immediately — no retry.
///
/// RETRY IS SOUND ONLY BECAUSE THE OP IS AN IDEMPOTENT READ: re-running a `SELECT` after a failover
/// yields the same rows and applies NOTHING. WRITES/TRANSACTION-CONTROL must NEVER take this path — see
/// [`pg_run_write`], which reconnects for the NEXT op but does NOT re-run the failed statement (so a
/// failover in the post-commit/pre-ack window can never SILENTLY DUPLICATE a write). Reconnect is at OP
/// granularity ONLY; `last_insert_id()` is not wrapped, so an `INSERT`+`last_insert_id()` pair can never
/// straddle a reconnect (a break between them surfaces an error / a `0` — never a wrong id from a fresh
/// session).
#[cfg(feature = "store-postgres")]
fn pg_run_read<T>(
    cell: &std::cell::RefCell<std::sync::MutexGuard<'_, postgres::Client>>,
    url: Option<&str>,
    mut op: impl FnMut(&mut postgres::Client) -> Result<T, postgres::Error>,
) -> StoreResult<T> {
    // First attempt on the current client (borrow scoped so it drops before any reconnect re-borrow).
    {
        let mut cl = cell.borrow_mut();
        // `&mut cl` deref-coerces RefMut<MutexGuard<Client>> -> &mut Client at this call site.
        match pg_block(|| op(&mut cl)) {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !(url.is_some() && pg_is_conn_error(&e)) {
                    return Err(pg_err(e));
                }
            }
        }
    }
    // Reconnect ONCE, swap the client held in the Mutex, then RETRY the op — ALL inside ONE
    // `block_in_place`. Connect drives its own `block_on`; the swap DROPS the old broken client, whose
    // sync `postgres` `Drop` closes the connection via ITS OWN `block_on`; and the retried op blocks too.
    // Every one of those nested `block_on`s MUST run under `block_in_place` — dropping the old client on a
    // bare tokio worker would panic "cannot start a runtime from within a runtime". Sharing one blocking
    // section covers connect + drop + retry together. (Sound because `op` is an idempotent read.)
    let url = url.expect("reconnect path is only taken when url is Some");
    let mut cl = cell.borrow_mut();
    pg_block(move || -> StoreResult<T> {
        let fresh = connect_postgres(url).map_err(StoreError::Backend)?;
        **cl = fresh; // old broken client dropped HERE, inside block_in_place
        op(&mut cl).map_err(pg_err)
    })
}

/// Run one WRITE / TRANSACTION-CONTROL `op` (execute / execute_batch — the latter also issues the
/// `BEGIN`/`COMMIT`/`ROLLBACK` of `with_tx`) on the held client. Unlike [`pg_run_read`], a connection
/// failure here NEVER auto-retries the op: re-running an `INSERT`/`UPDATE`/`DELETE` (or a tx-control
/// statement) across a failover risks applying it TWICE — a failover in the narrow post-commit/pre-ack
/// window would turn "at-least-once" into a SILENT DUPLICATE write. Instead, on a [`pg_is_conn_error`]
/// (and when a DSN is present) we RECONNECT the held client — swapping the fresh client into the Mutex so
/// the NEXT op on the shared `Arc` works — but RETURN THE ORIGINAL ERROR without re-executing.
///
/// CONTRACT: the write either SUCCEEDED (and may still surface an error the caller must reconcile — e.g.
/// the ack was lost) or FAILED, but is NEVER automatically re-applied. A transaction that hits a broken
/// connection FAILS AS A WHOLE — the reconnect is never used to continue the tx (the fresh session is not
/// inside the old `BEGIN`); `with_tx` sees the error, runs a best-effort `ROLLBACK` on the healed
/// session, and surfaces the original error so the caller can retry the WHOLE tx. A `Store` without a url,
/// or a non-connection (SQLSTATE) error, returns the first error immediately (no reconnect attempt).
#[cfg(feature = "store-postgres")]
fn pg_run_write<T>(
    cell: &std::cell::RefCell<std::sync::MutexGuard<'_, postgres::Client>>,
    url: Option<&str>,
    mut op: impl FnMut(&mut postgres::Client) -> Result<T, postgres::Error>,
) -> StoreResult<T> {
    let mut cl = cell.borrow_mut();
    // `&mut cl` deref-coerces RefMut<MutexGuard<Client>> -> &mut Client at this call site.
    let e = match pg_block(|| op(&mut cl)) {
        Ok(v) => return Ok(v),
        Err(e) => e,
    };
    // Connection-level failure: RECONNECT the held client so the NEXT op works, but DO NOT re-run this
    // write (no at-least-once duplicate). Connect + drop-old-client share ONE `block_in_place` (both drive
    // nested `block_on`s). Best-effort: if the reconnect itself fails, the (broken) client stays and the
    // NEXT op will attempt to reconnect again; either way the ORIGINAL op error is what the caller sees.
    if pg_is_conn_error(&e) {
        if let Some(url) = url {
            let _ = pg_block(move || -> Result<(), String> {
                let fresh = connect_postgres(url)?;
                **cl = fresh; // old broken client dropped HERE, inside block_in_place
                Ok(())
            });
        }
    }
    Err(pg_err(e))
}

// --- postgres row getters (positional) ----------------------------------------------------------
// Postgres is STATICALLY typed: `Row::try_get::<T>` succeeds only if `T` matches the column's runtime
// type. The seam schema maps every `INTEGER` to `BIGINT` (int8) and `REAL` to `DOUBLE PRECISION`
// (float8), but `SELECT 1` yields int4 and a narrowed column could be int2/float4 — so the integer/
// float getters TRY the widest type first and fall back through narrower ones (widening losslessly),
// reproducing SQLite's permissive numeric reads.

#[cfg(feature = "store-postgres")]
fn pg_get_i64(r: &postgres::Row, idx: usize) -> StoreResult<i64> {
    if let Ok(v) = r.try_get::<_, i64>(idx) {
        return Ok(v);
    }
    if let Ok(v) = r.try_get::<_, i32>(idx) {
        return Ok(v as i64);
    }
    if let Ok(v) = r.try_get::<_, i16>(idx) {
        return Ok(v as i64);
    }
    r.try_get::<_, i64>(idx).map_err(pg_err)
}

#[cfg(feature = "store-postgres")]
fn pg_get_opt_i64(r: &postgres::Row, idx: usize) -> StoreResult<Option<i64>> {
    if let Ok(v) = r.try_get::<_, Option<i64>>(idx) {
        return Ok(v);
    }
    if let Ok(v) = r.try_get::<_, Option<i32>>(idx) {
        return Ok(v.map(|x| x as i64));
    }
    if let Ok(v) = r.try_get::<_, Option<i16>>(idx) {
        return Ok(v.map(|x| x as i64));
    }
    r.try_get::<_, Option<i64>>(idx).map_err(pg_err)
}

#[cfg(feature = "store-postgres")]
fn pg_get_f64(r: &postgres::Row, idx: usize) -> StoreResult<f64> {
    if let Ok(v) = r.try_get::<_, f64>(idx) {
        return Ok(v);
    }
    if let Ok(v) = r.try_get::<_, f32>(idx) {
        return Ok(v as f64);
    }
    r.try_get::<_, f64>(idx).map_err(pg_err)
}

#[cfg(feature = "store-postgres")]
fn pg_get_opt_f64(r: &postgres::Row, idx: usize) -> StoreResult<Option<f64>> {
    if let Ok(v) = r.try_get::<_, Option<f64>>(idx) {
        return Ok(v);
    }
    if let Ok(v) = r.try_get::<_, Option<f32>>(idx) {
        return Ok(v.map(|x| x as f64));
    }
    r.try_get::<_, Option<f64>>(idx).map_err(pg_err)
}

#[cfg(feature = "store-postgres")]
fn pg_get_bool(r: &postgres::Row, idx: usize) -> StoreResult<bool> {
    // Schema stores booleans as BIGINT 0/1, so read the integer and test != 0. Accept a genuine PG
    // BOOL column too (defensive), matching rusqlite's tolerant `get::<bool>`.
    if let Ok(v) = r.try_get::<_, i64>(idx) {
        return Ok(v != 0);
    }
    if let Ok(v) = r.try_get::<_, i32>(idx) {
        return Ok(v != 0);
    }
    if let Ok(v) = r.try_get::<_, bool>(idx) {
        return Ok(v);
    }
    r.try_get::<_, bool>(idx).map_err(pg_err)
}

/// Dynamic/untyped read: dispatch on the column's PG type OID and return the backend-neutral [`Value`]
/// — the postgres dual of `sqlite_value_ref_to_value`. int2/int4/int8 -> `Int`, float4/float8 ->
/// `Real`, text/varchar/bpchar/name -> `Text`, bytea -> `Blob`, bool -> `Int` 0/1 (SQLite has no bool
/// storage class; a boolean reads back as a number, matching the SoQL reader), NULL -> `Null`. Any
/// OTHER PG type falls back to its string form (or `Null` if not string-readable), matching
/// SoQL-over-SQLite's text-leaning generic read.
#[cfg(feature = "store-postgres")]
fn pg_get_value(r: &postgres::Row, idx: usize) -> StoreResult<Value> {
    let ty = r.columns()[idx].type_().clone();
    if ty == Type::INT8 {
        Ok(r.try_get::<_, Option<i64>>(idx).map_err(pg_err)?.map(Value::Int).unwrap_or(Value::Null))
    } else if ty == Type::INT4 {
        Ok(r
            .try_get::<_, Option<i32>>(idx)
            .map_err(pg_err)?
            .map(|v| Value::Int(v as i64))
            .unwrap_or(Value::Null))
    } else if ty == Type::INT2 {
        Ok(r
            .try_get::<_, Option<i16>>(idx)
            .map_err(pg_err)?
            .map(|v| Value::Int(v as i64))
            .unwrap_or(Value::Null))
    } else if ty == Type::FLOAT8 {
        Ok(r.try_get::<_, Option<f64>>(idx).map_err(pg_err)?.map(Value::Real).unwrap_or(Value::Null))
    } else if ty == Type::FLOAT4 {
        Ok(r
            .try_get::<_, Option<f32>>(idx)
            .map_err(pg_err)?
            .map(|v| Value::Real(v as f64))
            .unwrap_or(Value::Null))
    } else if ty == Type::TEXT || ty == Type::VARCHAR || ty == Type::BPCHAR || ty == Type::NAME {
        Ok(r.try_get::<_, Option<String>>(idx).map_err(pg_err)?.map(Value::Text).unwrap_or(Value::Null))
    } else if ty == Type::BYTEA {
        Ok(r.try_get::<_, Option<Vec<u8>>>(idx).map_err(pg_err)?.map(Value::Blob).unwrap_or(Value::Null))
    } else if ty == Type::BOOL {
        Ok(r
            .try_get::<_, Option<bool>>(idx)
            .map_err(pg_err)?
            .map(|b| Value::Int(if b { 1 } else { 0 }))
            .unwrap_or(Value::Null))
    } else {
        // Other PG types -> best-effort string form (Null if not String-readable).
        match r.try_get::<_, Option<String>>(idx) {
            Ok(Some(s)) => Ok(Value::Text(s)),
            _ => Ok(Value::Null),
        }
    }
}

/// Resolve a column NAME to its positional index on a postgres row (postgres exposes `columns()` with
/// names; the by-NAME getters route through this then reuse the positional helpers).
#[cfg(feature = "store-postgres")]
fn pg_col_index(r: &postgres::Row, col: &str) -> StoreResult<usize> {
    r.columns()
        .iter()
        .position(|c| c.name() == col)
        .ok_or_else(|| StoreError::Backend(format!("no such column: {col}")))
}

// ================================================================================================
// PARAM — backend-agnostic bound parameter. Maps 1:1 to a SQLite storage class today; a Postgres
// backend maps the same variants to its own bind types at Stage 2.
// ================================================================================================

/// A single bound parameter, independent of any concrete driver's parameter type.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Param {
    Int(i64),
    Text(String),
    Real(f64),
    Blob(Vec<u8>),
    /// Bound as `INTEGER 0/1` under SQLite (identical to `rusqlite`'s `ToSql for bool`).
    Bool(bool),
    Null,
}

impl Param {
    /// Lower one `Param` to the rusqlite storage value it binds as (SQLite backend, Stage 0).
    fn to_sql_value(&self) -> SqlValue {
        match self {
            Param::Int(v) => SqlValue::Integer(*v),
            Param::Text(v) => SqlValue::Text(v.clone()),
            Param::Real(v) => SqlValue::Real(*v),
            Param::Blob(v) => SqlValue::Blob(v.clone()),
            Param::Bool(v) => SqlValue::Integer(if *v { 1 } else { 0 }),
            Param::Null => SqlValue::Null,
        }
    }
}

// From impls so `Param::from(x)` / the `sql_params!` macro accept native Rust types ergonomically.
impl From<i64> for Param {
    fn from(v: i64) -> Self {
        Param::Int(v)
    }
}
impl From<i32> for Param {
    fn from(v: i32) -> Self {
        Param::Int(v as i64)
    }
}
impl From<usize> for Param {
    fn from(v: usize) -> Self {
        Param::Int(v as i64)
    }
}
impl From<f64> for Param {
    fn from(v: f64) -> Self {
        Param::Real(v)
    }
}
impl From<bool> for Param {
    fn from(v: bool) -> Self {
        Param::Bool(v)
    }
}
impl From<String> for Param {
    fn from(v: String) -> Self {
        Param::Text(v)
    }
}
impl From<&str> for Param {
    fn from(v: &str) -> Self {
        Param::Text(v.to_string())
    }
}
impl From<&String> for Param {
    fn from(v: &String) -> Self {
        Param::Text(v.clone())
    }
}
impl From<Vec<u8>> for Param {
    fn from(v: Vec<u8>) -> Self {
        Param::Blob(v)
    }
}
/// `Option<T>` binds `None` as SQL NULL and `Some(x)` as `x` — the by-value analogue of rusqlite's
/// `ToSql for Option<T>`.
impl<T: Into<Param>> From<Option<T>> for Param {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(x) => x.into(),
            None => Param::Null,
        }
    }
}

/// `params!`-style helper: `sql_params![a, b, c]` -> `[Param; 3]`. Pass by reference to the seam
/// methods (`store.execute(sql, &sql_params![..])`). Every element is `Param::from(_)`-coerced, so
/// mixed native types (`i64`, `&str`, `String`, `Option<i64>`, …) compose in one call.
#[macro_export]
macro_rules! sql_params {
    () => { [] as [$crate::store::Param; 0] };
    ($($x:expr),+ $(,)?) => { [ $($crate::store::Param::from($x)),+ ] };
}

/// Lower a parameter slice to rusqlite storage values (SQLite backend).
fn to_sql_values(params: &[Param]) -> Vec<SqlValue> {
    params.iter().map(Param::to_sql_value).collect()
}

// ================================================================================================
// STORE ERROR — small typed error that does NOT leak `rusqlite::Error` in the public signature (so a
// `PgError` can convert into it identically at Stage 2). Kept tiny (no boxing) to avoid
// `clippy::result_large_err` on `Result<T, StoreError>`.
// ================================================================================================

/// Backend-agnostic store error. `NoRows` mirrors rusqlite's `QueryReturnedNoRows` so `query_row`
/// keeps its "empty result => Err" contract; `Backend` carries the driver's own message as text.
#[derive(Debug)]
pub(crate) enum StoreError {
    NoRows,
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NoRows => write!(f, "query returned no rows"),
            // Print the underlying driver message VERBATIM, so `format!("… {e}")` at converted call
            // sites yields text identical to the pre-seam `rusqlite::Error` Display.
            StoreError::Backend(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NoRows,
            other => StoreError::Backend(other.to_string()),
        }
    }
}

#[cfg(feature = "store-postgres")]
impl From<postgres::Error> for StoreError {
    fn from(e: postgres::Error) -> Self {
        StoreError::Backend(e.to_string())
    }
}

/// Result alias used across the seam.
pub(crate) type StoreResult<T> = Result<T, StoreError>;

// ================================================================================================
// VALUE — backend-agnostic READ-SIDE cell value (the dual of `Param`, which is the BIND side). One
// variant per SQLite storage class. Returned by the dynamic accessor `Row::get_value` for generic
// readers that must dispatch on a cell's RUNTIME type. A Stage-2 Postgres backend maps its column
// value to the SAME neutral `Value`, so generic readers stay portable.
// ================================================================================================

/// A single read-back cell value, independent of any concrete driver's value type. One variant per
/// SQLite storage class. Kept DISTINCT from [`Param`] (the bind side): `Param` also carries `Bool`
/// (a bind convenience lowered to `INTEGER 0/1`), whereas `Value` has NO `Bool` variant — SQLite has
/// no boolean storage class, so a boolean column reads back as [`Value::Int`] (0/1). This matches how
/// the SoQL reader treats booleans today (`ValueRef::Integer` -> a JSON number).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
    Null,
}

/// Map one rusqlite borrowed `ValueRef` to the backend-neutral [`Value`] (SQLite backend, Stage 0).
/// EXACTLY reproduces the storage-class dispatch that `query.rs::cell` performs, so a generic reader
/// routed through `Row::get_value` yields the same variants `cell` derives from `row.get_ref(i)`.
fn sqlite_value_ref_to_value(vr: rusqlite::types::ValueRef<'_>) -> Value {
    use rusqlite::types::ValueRef;
    match vr {
        ValueRef::Integer(n) => Value::Int(n),
        ValueRef::Real(f) => Value::Real(f),
        // Decode lossily from UTF-8 exactly like `cell`'s `String::from_utf8_lossy(t)`.
        ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::Blob(b.to_vec()),
        ValueRef::Null => Value::Null,
    }
}

/// Map a backend-neutral [`Value`] to a `serde_json::Value`, reproducing EXACTLY the cell typing that
/// the SoQL-style readers (`query.rs::cell` via `exec_soql`, and `cli.rs::cli_query_rows`) apply:
/// `Int` -> JSON number, `Real` -> JSON number, `Text` -> JSON string, `Blob` -> `Null`, `Null` ->
/// `Null`. Extracted here so BOTH call sites route their `Row::get_value` result through ONE shared
/// mapping and stay byte-identical (the pre-seam `cell`'s `ValueRef` dispatch produced these exact
/// JSON shapes).
pub(crate) fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Int(n) => serde_json::json!(n),
        Value::Real(f) => serde_json::json!(f),
        Value::Text(s) => serde_json::json!(s),
        Value::Blob(_) => serde_json::Value::Null,
        Value::Null => serde_json::Value::Null,
    }
}

// ================================================================================================
// ROW — typed column accessor exposing ONLY backend-neutral getters (no generic `get<T: FromSql>`,
// which would leak rusqlite). Both a rusqlite row (now) and a postgres row (later) implement these.
// Plus the DYNAMIC accessor `get_value` for readers that dispatch on a cell's RUNTIME type.
// ================================================================================================

/// One result row. `idx` getters are 0-based positional; `*_by` getters take a column NAME.
pub(crate) struct Row<'stmt> {
    inner: RowInner<'stmt>,
}

enum RowInner<'stmt> {
    Sqlite(&'stmt rusqlite::Row<'stmt>),
    #[cfg(feature = "store-postgres")]
    Postgres(&'stmt postgres::Row),
}

impl<'stmt> Row<'stmt> {
    pub(crate) fn sqlite(r: &'stmt rusqlite::Row<'stmt>) -> Self {
        Row { inner: RowInner::Sqlite(r) }
    }

    #[cfg(feature = "store-postgres")]
    pub(crate) fn postgres(r: &'stmt postgres::Row) -> Self {
        Row { inner: RowInner::Postgres(r) }
    }

    // --- positional getters --------------------------------------------------------------------
    pub(crate) fn get_i64(&self, idx: usize) -> StoreResult<i64> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, i64>(idx)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_i64(r, idx),
        }
    }
    pub(crate) fn get_str(&self, idx: usize) -> StoreResult<String> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, String>(idx)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => r.try_get::<_, String>(idx).map_err(pg_err),
        }
    }
    pub(crate) fn get_opt_str(&self, idx: usize) -> StoreResult<Option<String>> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, Option<String>>(idx)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => r.try_get::<_, Option<String>>(idx).map_err(pg_err),
        }
    }
    pub(crate) fn get_opt_i64(&self, idx: usize) -> StoreResult<Option<i64>> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, Option<i64>>(idx)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_opt_i64(r, idx),
        }
    }
    pub(crate) fn get_f64(&self, idx: usize) -> StoreResult<f64> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, f64>(idx)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_f64(r, idx),
        }
    }
    pub(crate) fn get_opt_f64(&self, idx: usize) -> StoreResult<Option<f64>> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, Option<f64>>(idx)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_opt_f64(r, idx),
        }
    }
    pub(crate) fn get_bool(&self, idx: usize) -> StoreResult<bool> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, bool>(idx)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_bool(r, idx),
        }
    }
    pub(crate) fn get_blob(&self, idx: usize) -> StoreResult<Vec<u8>> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, Vec<u8>>(idx)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => r.try_get::<_, Vec<u8>>(idx).map_err(pg_err),
        }
    }

    // --- by-name getters -----------------------------------------------------------------------
    pub(crate) fn get_i64_by(&self, col: &str) -> StoreResult<i64> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, i64>(col)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_i64(r, pg_col_index(r, col)?),
        }
    }
    pub(crate) fn get_str_by(&self, col: &str) -> StoreResult<String> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, String>(col)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => r.try_get::<_, String>(col).map_err(pg_err),
        }
    }
    pub(crate) fn get_opt_str_by(&self, col: &str) -> StoreResult<Option<String>> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, Option<String>>(col)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => r.try_get::<_, Option<String>>(col).map_err(pg_err),
        }
    }
    pub(crate) fn get_opt_i64_by(&self, col: &str) -> StoreResult<Option<i64>> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, Option<i64>>(col)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_opt_i64(r, pg_col_index(r, col)?),
        }
    }
    pub(crate) fn get_f64_by(&self, col: &str) -> StoreResult<f64> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, f64>(col)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_f64(r, pg_col_index(r, col)?),
        }
    }
    pub(crate) fn get_bool_by(&self, col: &str) -> StoreResult<bool> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, bool>(col)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_bool(r, pg_col_index(r, col)?),
        }
    }
    pub(crate) fn get_blob_by(&self, col: &str) -> StoreResult<Vec<u8>> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(r.get::<_, Vec<u8>>(col)?),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => r.try_get::<_, Vec<u8>>(col).map_err(pg_err),
        }
    }

    // --- dynamic / untyped accessor (for GENERIC readers, e.g. SoQL) ---------------------------
    /// Read the cell at positional `idx` as a backend-neutral [`Value`], dispatching on its RUNTIME
    /// storage class rather than a compile-time target type. This is the accessor for GENERIC readers
    /// (the SoQL engine in `query.rs`) that stream columns of UNKNOWN type: the statically-typed
    /// getters cannot serve them — `get_i64` on a TEXT column errors under rusqlite's type-strict
    /// `FromSql`, whereas `get_value` inspects the actual class and returns the matching variant. For
    /// the rusqlite backend it reads via `row.get_ref(idx)` and maps `ValueRef::Integer -> Int`,
    /// `::Real -> Real`, `::Text -> Text` (lossy UTF-8), `::Blob -> Blob`, `::Null -> Null` — the exact
    /// dispatch `query.rs::cell` performs. A Stage-2 Postgres backend maps its column value to the same
    /// neutral `Value`.
    pub(crate) fn get_value(&self, idx: usize) -> StoreResult<Value> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(sqlite_value_ref_to_value(r.get_ref(idx)?)),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_value(r, idx),
        }
    }

    /// By-NAME counterpart of [`Row::get_value`]. Same dynamic storage-class dispatch, column selected
    /// by name instead of position.
    pub(crate) fn get_value_by(&self, col: &str) -> StoreResult<Value> {
        match &self.inner {
            RowInner::Sqlite(r) => Ok(sqlite_value_ref_to_value(r.get_ref(col)?)),
            #[cfg(feature = "store-postgres")]
            RowInner::Postgres(r) => pg_get_value(r, pg_col_index(r, col)?),
        }
    }
}

// ================================================================================================
// STORE — the portable handle. Holds the connection guard for its lifetime (see module docs). A
// single `Backend::Sqlite` arm today; `Backend::Postgres(..)` is added at Stage 2 behind a feature.
// ================================================================================================

/// Backend-agnostic DB handle. Construct via `App::store()`. Not `Send` (holds a `MutexGuard`), same
/// as `App::db()` — never hold one across an `.await`.
pub(crate) struct Store<'a> {
    backend: Backend<'a>,
}

enum Backend<'a> {
    Sqlite(std::sync::MutexGuard<'a, rusqlite::Connection>),
    // Stage 2: a SESSION-PINNED synchronous postgres client held for the `Store`'s lifetime — the SAME
    // Mutex model as `Sqlite` (one held guard, so `execute(INSERT)` + `last_insert_id()` run on ONE
    // session, cf. the module docs). The sync `postgres::Client` DML methods take `&mut self`, whereas
    // the seam methods take `&self`; a `RefCell` provides the interior mutability (the `Store` is
    // single-threaded / `!Send`, so borrows never overlap across the brief per-call `borrow_mut`).
    // Stage 4 HA: `url` is the DSN (borrowed from the `Arc<PgPool>` held by `App.pg`) — `Some` for the
    // runtime `App::store()` handle (reads reconnect+retry via `pg_run_read`; writes/tx reconnect-for-
    // next-op-without-retry via `pg_run_write`), `None` for the CLI/tests (one-shot lifecycles that never
    // outlive a restart). Either helper swaps the client inside the held Mutex on reconnect, so the shared
    // `Arc` heals for every later `store()`.
    #[cfg(feature = "store-postgres")]
    Postgres {
        client: std::cell::RefCell<std::sync::MutexGuard<'a, postgres::Client>>,
        url: Option<&'a str>,
    },
}

impl<'a> Store<'a> {
    /// Wrap a held SQLite connection guard. Called by `App::store()`.
    pub(crate) fn sqlite(guard: std::sync::MutexGuard<'a, rusqlite::Connection>) -> Self {
        Store { backend: Backend::Sqlite(guard) }
    }

    /// Wrap a held postgres client guard (session-pinned for the `Store`'s lifetime). NO reconnect
    /// (`url = None`): used by the CLI subcommands and the integration tests — one-shot lifecycles that
    /// never outlive a server restart. The runtime `App::store()` uses [`Store::postgres_reconnectable`].
    #[cfg(feature = "store-postgres")]
    pub(crate) fn postgres(guard: std::sync::MutexGuard<'a, postgres::Client>) -> Self {
        Store { backend: Backend::Postgres { client: std::cell::RefCell::new(guard), url: None } }
    }

    /// Wrap a held postgres client guard TOGETHER with its DSN (Stage 4 HA). On a connection-level
    /// failure a seam DML op RECONNECTS (`connect_postgres(url)`) and swaps the fresh client into the held
    /// Mutex, so the console heals in place. The RETRY semantics differ by op kind: an IDEMPOTENT READ is
    /// re-run once ([`pg_run_read`]); a WRITE / transaction-control op is NOT re-run — the reconnect only
    /// readies the client for the NEXT op and the original error surfaces ([`pg_run_write`]), so a failover
    /// can never silently duplicate a write and a transaction fails as a whole. Called by `App::store()` at
    /// runtime — where the long-lived console must survive a Postgres restart/failover.
    #[cfg(feature = "store-postgres")]
    pub(crate) fn postgres_reconnectable(
        guard: std::sync::MutexGuard<'a, postgres::Client>,
        url: &'a str,
    ) -> Self {
        Store { backend: Backend::Postgres { client: std::cell::RefCell::new(guard), url: Some(url) } }
    }

    /// Which backend is this `Store` bound to? Lets the ENTERPRISE modules that create their tables
    /// LAZILY (scim_*/sso_*/rbac_group_map — deliberately NOT in `PG_SCHEMA`, since they are flag-gated
    /// and the community DB must never see them) pick the SQLite-vs-Postgres DDL dialect. In the DEFAULT
    /// build (feature OFF) the `Postgres` arm does not exist, so this is a const `false` and those
    /// modules keep their unchanged SQLite DDL (byte-identical).
    pub(crate) fn is_postgres(&self) -> bool {
        match &self.backend {
            Backend::Sqlite(_) => false,
            #[cfg(feature = "store-postgres")]
            Backend::Postgres { .. } => true,
        }
    }

    /// Execute a non-query statement; returns the number of affected rows (mirrors rusqlite's
    /// `Connection::execute`). Placeholder style is SQLite `?`.
    pub(crate) fn execute(&self, sql: &str, params: &[Param]) -> StoreResult<usize> {
        match &self.backend {
            Backend::Sqlite(conn) => {
                let vals = to_sql_values(params);
                Ok(conn.execute(sql, rusqlite::params_from_iter(vals))?)
            }
            #[cfg(feature = "store-postgres")]
            Backend::Postgres { client, url } => {
                let sql = translate_sql(sql);
                let boxed = pg_binds(params);
                let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|b| b.as_ref()).collect();
                // WRITE: on a connection break, reconnect the client for the NEXT op but NEVER auto-retry
                // this statement — re-running an INSERT/UPDATE/DELETE could silently DUPLICATE it. The
                // original error surfaces; the caller must reconcile (see [`pg_run_write`]).
                Ok(pg_run_write(client, *url, |cl| cl.execute(sql.as_str(), &refs))? as usize)
            }
        }
    }

    /// Execute an INSERT and return the id of the inserted row in a SINGLE statement — NO session-scoped
    /// `lastval()` / `last_insert_rowid()` dependency, so it is safe on a POOLED backend where each
    /// checkout may land on a different connection. `Ok(None)` means NO row was inserted (an
    /// `ON CONFLICT DO NOTHING` that fired), mirroring the pre-seam `if n > 0 { last_insert_id() }` guard.
    ///
    ///   - SQLite: `execute(sql)` then `last_insert_rowid()` on THIS held connection when a row landed
    ///     (`n > 0`), else `None`. BYTE-IDENTICAL to the pre-seam `execute` + `last_insert_id` idiom
    ///     (the SQL is passed VERBATIM — no `RETURNING` appended, so the SQLite path is unchanged).
    ///   - Postgres: append ` RETURNING id` to the translated INSERT and read column 0 of the returned
    ///     row from the SAME statement (0 rows -> `None` for a DO-NOTHING conflict; 1 row -> `Some(id)`).
    ///     This removes the `lastval()` session affinity that forced a single pinned client, so inserts
    ///     run correctly on ANY pooled connection. WRITE semantics: routed through [`pg_run_write`] (a
    ///     broken connection reconnects for the NEXT op but the INSERT is NEVER auto-re-applied).
    ///
    /// REQUIREMENT: the target table MUST have an `id` column (every seam table maps its SQLite
    /// `INTEGER PRIMARY KEY` to `id BIGINT GENERATED BY DEFAULT AS IDENTITY`, cf. `PG_SCHEMA`).
    pub(crate) fn execute_returning_id_opt(&self, sql: &str, params: &[Param]) -> StoreResult<Option<i64>> {
        match &self.backend {
            Backend::Sqlite(conn) => {
                let vals = to_sql_values(params);
                let n = conn.execute(sql, rusqlite::params_from_iter(vals))?;
                Ok(if n > 0 { Some(conn.last_insert_rowid()) } else { None })
            }
            #[cfg(feature = "store-postgres")]
            Backend::Postgres { client, url } => {
                let sql = format!("{} RETURNING id", translate_sql(sql));
                let boxed = pg_binds(params);
                let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|b| b.as_ref()).collect();
                // WRITE (INSERT … RETURNING id): single round-trip, no lastval/session dependency. Routed
                // through pg_run_write (NOT pg_run_read) — an INSERT must never be silently re-applied on a
                // connection break. `query` yields 0..1 rows: 0 => ON CONFLICT DO NOTHING fired (-> None).
                let rows = pg_run_write(client, *url, |cl| cl.query(sql.as_str(), &refs))?;
                match rows.first() {
                    Some(r) => Ok(Some(pg_get_i64(r, 0)?)),
                    None => Ok(None),
                }
            }
        }
    }

    /// Execute an INSERT expected to ALWAYS create exactly one row, returning its id in a SINGLE
    /// statement (see [`Store::execute_returning_id_opt`] for the mechanism). `Err(StoreError::NoRows)`
    /// if no row was inserted — use [`Store::execute_returning_id_opt`] for `ON CONFLICT DO NOTHING`
    /// inserts that may legitimately insert nothing. Replaces the `execute(INSERT)` + `last_insert_id()`
    /// pair at every runtime call site so the PG id source is session-independent (pool-safe).
    pub(crate) fn execute_returning_id(&self, sql: &str, params: &[Param]) -> StoreResult<i64> {
        self.execute_returning_id_opt(sql, params)?.ok_or(StoreError::NoRows)
    }

    /// Execute one or more `;`-separated statements with NO parameters (DDL / `CREATE TABLE IF NOT
    /// EXISTS` / migrations). Mirrors rusqlite's `execute_batch`.
    pub(crate) fn execute_batch(&self, sql: &str) -> StoreResult<()> {
        match &self.backend {
            Backend::Sqlite(conn) => Ok(conn.execute_batch(sql)?),
            #[cfg(feature = "store-postgres")]
            // No parameters => no placeholder translation. `batch_execute` runs `;`-separated DDL and the
            // transaction-control words (`BEGIN`/`COMMIT`/`ROLLBACK`) that `with_tx` issues. Wrapped in
            // [`pg_run_write`], NOT [`pg_run_read`]: a broken connection here reconnects the client so the
            // NEXT op works, but the failed statement is NEVER auto-re-run. This is what makes a tx fail
            // AS A WHOLE — the reconnect never continues the old `BEGIN` (the fresh session is not inside
            // it), so `with_tx` catches the error, best-effort `ROLLBACK`s on the healed session, and lets
            // the caller retry the WHOLE tx. Reconnect stays at OP granularity; it never re-executes a
            // statement mid-transaction (which would corrupt atomicity / risk a duplicate write).
            Backend::Postgres { client, url } => {
                pg_run_write(client, *url, |cl| cl.batch_execute(sql))
            }
        }
    }

    /// Run a query and map EVERY row via `map`, collecting into a `Vec`. The closure receives a
    /// backend-neutral `&Row`. STRICT: the FIRST row whose `map` closure returns `Err` (or a per-row
    /// step error) SINKS the whole read — the error propagates and NO rows are returned. Use this when
    /// a malformed row must be a hard error; use [`Store::query_lax`] to skip bad rows instead.
    pub(crate) fn query<T, F>(&self, sql: &str, params: &[Param], mut map: F) -> StoreResult<Vec<T>>
    where
        F: FnMut(&Row) -> StoreResult<T>,
    {
        match &self.backend {
            Backend::Sqlite(conn) => {
                let mut stmt = conn.prepare(sql)?;
                let vals = to_sql_values(params);
                let mut rows = stmt.query(rusqlite::params_from_iter(vals))?;
                let mut out = Vec::new();
                while let Some(r) = rows.next()? {
                    out.push(map(&Row::sqlite(r))?);
                }
                Ok(out)
            }
            #[cfg(feature = "store-postgres")]
            Backend::Postgres { client, url } => {
                let sql = translate_sql(sql);
                let boxed = pg_binds(params);
                let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|b| b.as_ref()).collect();
                // READ: idempotent, so single-shot reconnect+retry on a connection break (Stage 4 HA).
                let rows = pg_run_read(client, *url, |cl| cl.query(sql.as_str(), &refs))?;
                // Postgres materialises the full result set (no per-row step error to skip); STRICT:
                // the FIRST `map` closure `Err` sinks the whole read via `?`, matching the Sqlite arm.
                let mut out = Vec::with_capacity(rows.len());
                for r in &rows {
                    out.push(map(&Row::postgres(r))?);
                }
                Ok(out)
            }
        }
    }

    /// Run a query and map each row via `map`, LENIENTLY. Contract vs. [`Store::query`]:
    ///   - PREPARE and BIND errors PROPAGATE (returned as `Err`) — a broken statement is still a hard
    ///     failure, identical to `query`.
    ///   - Any PER-ROW error is SKIPPED: the `map` closure returning `Err` for a row drops just that
    ///     row and continues to the next; a per-row step error ends the stream (the rusqlite cursor is
    ///     spent after a step error) with the rows gathered so far returned.
    ///
    /// This mirrors the pre-seam idiom `stmt.query_map(..)?.filter_map(|x| x.ok()).collect()` byte for
    /// byte: one malformed row never sinks the whole read (contrast `query`, which fails on the FIRST
    /// bad row). It is the correct target for read paths that must degrade gracefully and return the
    /// rows that DID map — the dominant read idiom across the codebase (~30 sites).
    pub(crate) fn query_lax<T, F>(&self, sql: &str, params: &[Param], mut map: F) -> StoreResult<Vec<T>>
    where
        F: FnMut(&Row) -> StoreResult<T>,
    {
        match &self.backend {
            Backend::Sqlite(conn) => {
                let mut stmt = conn.prepare(sql)?;
                let vals = to_sql_values(params);
                let mut rows = stmt.query(rusqlite::params_from_iter(vals))?;
                let mut out = Vec::new();
                // `while let Ok(Some(r))` reproduces `MappedRows.filter_map(|x| x.ok())` exactly: a
                // step error (`rows.next()` -> `Err`) or end-of-set (`Ok(None)`) both end the loop, and
                // a `map`-closure `Err` on a good row is dropped by the inner `if let Ok`, then the loop
                // advances to the next row — collecting ONLY the rows that mapped to `Ok`.
                while let Ok(Some(r)) = rows.next() {
                    if let Ok(v) = map(&Row::sqlite(r)) {
                        out.push(v);
                    }
                }
                Ok(out)
            }
            #[cfg(feature = "store-postgres")]
            Backend::Postgres { client, url } => {
                let sql = translate_sql(sql);
                let boxed = pg_binds(params);
                let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|b| b.as_ref()).collect();
                // PREPARE/BIND errors PROPAGATE (a broken statement is a hard failure, like Sqlite);
                // a per-row `map` `Err` is SKIPPED (dropped), collecting only rows that mapped to `Ok`.
                // READ: idempotent, so single-shot reconnect+retry on a connection break (Stage 4 HA).
                let rows = pg_run_read(client, *url, |cl| cl.query(sql.as_str(), &refs))?;
                let mut out = Vec::with_capacity(rows.len());
                for r in &rows {
                    if let Ok(v) = map(&Row::postgres(r)) {
                        out.push(v);
                    }
                }
                Ok(out)
            }
        }
    }

    /// Run a query expected to yield AT MOST one row. `Ok(None)` on an empty result set.
    pub(crate) fn query_opt<T, F>(
        &self,
        sql: &str,
        params: &[Param],
        mut map: F,
    ) -> StoreResult<Option<T>>
    where
        F: FnMut(&Row) -> StoreResult<T>,
    {
        match &self.backend {
            Backend::Sqlite(conn) => {
                let mut stmt = conn.prepare(sql)?;
                let vals = to_sql_values(params);
                let mut rows = stmt.query(rusqlite::params_from_iter(vals))?;
                match rows.next()? {
                    Some(r) => Ok(Some(map(&Row::sqlite(r))?)),
                    None => Ok(None),
                }
            }
            #[cfg(feature = "store-postgres")]
            Backend::Postgres { client, url } => {
                let sql = translate_sql(sql);
                let boxed = pg_binds(params);
                let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|b| b.as_ref()).collect();
                // READ: idempotent, so single-shot reconnect+retry on a connection break (Stage 4 HA).
                let rows = pg_run_read(client, *url, |cl| cl.query(sql.as_str(), &refs))?;
                match rows.first() {
                    Some(r) => Ok(Some(map(&Row::postgres(r))?)),
                    None => Ok(None),
                }
            }
        }
    }

    /// Run a query expected to yield EXACTLY one row. `Err(StoreError::NoRows)` on an empty result set
    /// (mirrors rusqlite's `query_row` => `QueryReturnedNoRows`), so `.is_ok()` / `match … Err(_)`
    /// call sites behave identically.
    pub(crate) fn query_row<T, F>(&self, sql: &str, params: &[Param], map: F) -> StoreResult<T>
    where
        F: FnMut(&Row) -> StoreResult<T>,
    {
        self.query_opt(sql, params, map)?.ok_or(StoreError::NoRows)
    }

    /// Rowid of the most recent successful INSERT on this connection (mirrors
    /// `Connection::last_insert_rowid`). SESSION-SCOPED: meaningful only when paired with an
    /// `execute(INSERT …)` on the SAME `Store` (one held guard) with no interleaved INSERT between.
    /// The Postgres arm reads `SELECT lastval()` on the SAME session-pinned client — this is why the
    /// client MUST be session-pinned (a per-call pooled connection could surface another session's
    /// insert id). `lastval()` returns the last value produced by a sequence (an `INSERT` into a
    /// `GENERATED … AS IDENTITY` column advances one), matching SQLite's last-rowid semantics; `0` if
    /// no sequence has advanced on this session yet (mirrors rusqlite's `0` before any INSERT).
    pub(crate) fn last_insert_id(&self) -> i64 {
        match &self.backend {
            Backend::Sqlite(conn) => conn.last_insert_rowid(),
            #[cfg(feature = "store-postgres")]
            // DELIBERATELY NOT wrapped in a reconnect helper: `lastval()` is meaningful ONLY on the SAME session as
            // the preceding `execute(INSERT)`. Reconnecting here would query a FRESH session (no sequence
            // advanced -> wrong id / error). If the connection broke between the INSERT and this call the
            // caller gets `0` — correct/safe: an INSERT+last_insert_id pair must never straddle a reconnect.
            Backend::Postgres { client, .. } => {
                let mut cl = client.borrow_mut();
                pg_block(|| cl.query_one("SELECT lastval()", &[]))
                    .ok()
                    .and_then(|r| r.try_get::<_, i64>(0).ok())
                    .unwrap_or(0)
            }
        }
    }

    /// Run `f` inside a transaction: `BEGIN`, then `COMMIT` if `f` returns `Ok`, else `ROLLBACK`. The
    /// `Tx` handle exposes the same `execute`/`query*` surface, delegating to this held connection.
    ///
    /// RECONNECT CONTRACT (Postgres, Stage 4 HA): a broken connection at ANY point — `BEGIN`, a statement
    /// inside `f` (`Tx::execute`/`execute_batch` -> [`pg_run_write`]), or `COMMIT` — FAILS THE WHOLE TX.
    /// The reconnect is never used to CONTINUE a transaction mid-flight: the fresh session is not inside
    /// the old `BEGIN`, and no write/tx-control statement is ever auto-re-run (so no partial re-apply / no
    /// silent duplicate). On `f`'s `Err` we issue a best-effort `ROLLBACK` (a no-op NOTICE if the healed
    /// session has no open tx) and surface the ORIGINAL error, leaving the caller free to retry the whole
    /// tx on the now-healed client. Reads inside `f` may still reconnect+retry (idempotent) via
    /// [`pg_run_read`], but that never crosses a tx boundary because the enclosing write/tx-control fails
    /// closed first.
    pub(crate) fn with_tx<T, F>(&self, f: F) -> StoreResult<T>
    where
        F: FnOnce(&Tx) -> StoreResult<T>,
    {
        self.execute_batch("BEGIN")?;
        let tx = Tx { store: self };
        match f(&tx) {
            Ok(v) => {
                self.execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                // Best-effort rollback; surface the ORIGINAL error to the caller.
                let _ = self.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }
}

/// Transaction handle passed to `Store::with_tx`. Delegates to the enclosing `Store`'s held
/// connection; `commit`/`rollback` are driven by `with_tx` from `f`'s `Ok`/`Err`.
pub(crate) struct Tx<'s, 'a> {
    store: &'s Store<'a>,
}

impl<'a> Tx<'_, 'a> {
    /// Borrow the enclosing `Store` (same held connection, INSIDE this transaction's `BEGIN`). Lets a
    /// caller pass the transactional handle to a helper that takes `&Store` (e.g. the migrator's
    /// identity-sequence advance / row-count helpers) so those run within the transaction, not on a
    /// separate connection. Gated on `store-postgres`: it is used ONLY by the Postgres migrator, so the
    /// DEFAULT build compiles no new code here and stays byte-identical.
    #[cfg(feature = "store-postgres")]
    pub(crate) fn store(&self) -> &Store<'a> {
        self.store
    }
    pub(crate) fn execute(&self, sql: &str, params: &[Param]) -> StoreResult<usize> {
        self.store.execute(sql, params)
    }
    pub(crate) fn execute_batch(&self, sql: &str) -> StoreResult<()> {
        self.store.execute_batch(sql)
    }
    pub(crate) fn query<T, F>(&self, sql: &str, params: &[Param], map: F) -> StoreResult<Vec<T>>
    where
        F: FnMut(&Row) -> StoreResult<T>,
    {
        self.store.query(sql, params, map)
    }
    pub(crate) fn query_lax<T, F>(&self, sql: &str, params: &[Param], map: F) -> StoreResult<Vec<T>>
    where
        F: FnMut(&Row) -> StoreResult<T>,
    {
        self.store.query_lax(sql, params, map)
    }
    pub(crate) fn query_opt<T, F>(
        &self,
        sql: &str,
        params: &[Param],
        map: F,
    ) -> StoreResult<Option<T>>
    where
        F: FnMut(&Row) -> StoreResult<T>,
    {
        self.store.query_opt(sql, params, map)
    }
    pub(crate) fn query_row<T, F>(&self, sql: &str, params: &[Param], map: F) -> StoreResult<T>
    where
        F: FnMut(&Row) -> StoreResult<T>,
    {
        self.store.query_row(sql, params, map)
    }
    pub(crate) fn last_insert_id(&self) -> i64 {
        self.store.last_insert_id()
    }
}

// ================================================================================================
// TESTS — prove the dynamic/untyped accessor (`get_value`) dispatches on a cell's RUNTIME storage
// class, reproducing the value-driven dispatch `query.rs::cell` needs and that the statically-typed
// getters (`get_i64` / `get_str`) CANNOT do.
// ================================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// One row with a column PER storage class (INTEGER, REAL, TEXT, BLOB) plus a NULL cell. Each cell
    /// is read via `get_value`, asserting the neutral `Value` variant matches — the value-driven
    /// dispatch that the type-strict getters cannot perform. Also shows the one-line `Value ->
    /// serde_json::Value` mapping is byte-identical to `query.rs::cell`'s current output.
    #[test]
    fn get_value_dispatches_on_runtime_storage_class() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE mixed (i INTEGER, r REAL, s TEXT, b BLOB, n TEXT);
             INSERT INTO mixed (i, r, s, b, n) VALUES (42, 3.5, 'hello', x'0102', NULL);",
        )
        .unwrap();

        let mut stmt = conn.prepare("SELECT i, r, s, b, n FROM mixed").unwrap();
        let mut rows = stmt.query([]).unwrap();
        let raw = rows.next().unwrap().unwrap();
        let row = Row::sqlite(raw);

        // Value-driven dispatch: one accessor reads a cell of UNKNOWN compile-time type and returns
        // the variant matching its ACTUAL storage class.
        assert_eq!(row.get_value(0).unwrap(), Value::Int(42));
        assert_eq!(row.get_value(1).unwrap(), Value::Real(3.5));
        assert_eq!(row.get_value(2).unwrap(), Value::Text("hello".to_string()));
        assert_eq!(row.get_value(3).unwrap(), Value::Blob(vec![1, 2]));
        assert_eq!(row.get_value(4).unwrap(), Value::Null);

        // By-name variant reads identically.
        assert_eq!(row.get_value_by("i").unwrap(), Value::Int(42));
        assert_eq!(row.get_value_by("n").unwrap(), Value::Null);

        // The typed getter CANNOT do this: `get_i64` on the TEXT column errors (rusqlite's type-strict
        // `FromSql for i64` rejects a Text cell) — which is exactly why the SoQL reader needs the
        // dynamic `get_value`.
        assert!(row.get_i64(2).is_err());

        // One-line `Value -> serde_json::Value` mapping, IDENTICAL to `query.rs::cell`'s output:
        // Int -> number, Real -> number, Text -> string, Blob -> Null, Null -> Null.
        let to_json = |v: &Value| -> serde_json::Value {
            match v {
                Value::Int(n) => serde_json::json!(n),
                Value::Real(f) => serde_json::json!(f),
                Value::Text(s) => serde_json::json!(s),
                Value::Blob(_) => serde_json::Value::Null,
                Value::Null => serde_json::Value::Null,
            }
        };
        assert_eq!(to_json(&row.get_value(0).unwrap()), serde_json::json!(42));
        assert_eq!(to_json(&row.get_value(1).unwrap()), serde_json::json!(3.5));
        assert_eq!(to_json(&row.get_value(2).unwrap()), serde_json::json!("hello"));
        assert_eq!(to_json(&row.get_value(3).unwrap()), serde_json::Value::Null);
        assert_eq!(to_json(&row.get_value(4).unwrap()), serde_json::Value::Null);
    }
}

// ================================================================================================
// POSTGRES TESTS (feature `store-postgres`).
//   - `pg_translate_placeholders_*` : PURE unit tests of the `?` -> `$n` translator (no server).
//   - `pg_seam_end_to_end` : INTEGRATION test — GATED on `TEST_PG_URL` (skips with a note when unset).
//     Connects to a real Postgres, applies `PG_SCHEMA`, then exercises the WHOLE seam and asserts the
//     results match SQLite semantics: execute INSERT + `last_insert_id`, `query`/`query_lax`/
//     `query_opt`, `get_value` on mixed-type columns (int/real/text/bytea/null), typed getters, a
//     nullable-column read, an `ON CONFLICT DO NOTHING` upsert, and a transaction commit + rollback.
// ================================================================================================
#[cfg(all(test, feature = "store-postgres"))]
mod pg_tests {
    use super::*;

    // Both DB integration tests DROP/CREATE the SAME tables on the shared TEST_PG_URL database. Under
    // cargo's default test parallelism they race (one's DROP CASCADE tears down tables the other is mid-
    // flight on). Serialize the two DB-touching tests on this process-local mutex — NO new crate (no
    // serial_test). `unwrap_or_else(|e| e.into_inner())` recovers the guard even if a prior test panicked
    // while holding it (a poisoned mutex must not cascade the whole PG suite into failures). The pure
    // translator unit tests (no server) don't lock.
    static PG_DB_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn pg_translate_placeholders_basic() {
        assert_eq!(translate_placeholders("SELECT * FROM t WHERE a=? AND b=?"),
                   "SELECT * FROM t WHERE a=$1 AND b=$2");
        assert_eq!(translate_placeholders("INSERT INTO t(a,b,c) VALUES(?,?,?)"),
                   "INSERT INTO t(a,b,c) VALUES($1,$2,$3)");
        // No placeholders -> verbatim.
        assert_eq!(translate_placeholders("SELECT 1"), "SELECT 1");
    }

    #[test]
    fn pg_translate_placeholders_skips_string_literals() {
        // A `?` inside a single-quoted literal is NOT a placeholder.
        assert_eq!(translate_placeholders("SELECT '?' , ? , 'a?b' , ?"),
                   "SELECT '?' , $1 , 'a?b' , $2");
        // Doubled '' escape inside a literal keeps the literal boundary correct.
        assert_eq!(translate_placeholders("UPDATE t SET s='it''s ?' WHERE id=?"),
                   "UPDATE t SET s='it''s ?' WHERE id=$1");
    }

    #[test]
    fn pg_rewrite_datetime_now_and_full_translate() {
        // `datetime('now')` outside a literal -> portable CAST; placeholders still numbered after.
        assert_eq!(
            translate_sql("INSERT INTO settings(key,value,updated) VALUES(?,?,datetime('now'))"),
            "INSERT INTO settings(key,value,updated) VALUES($1,$2,CAST(CURRENT_TIMESTAMP AS TEXT))"
        );
        // Multiple occurrences all rewritten; case-insensitive on the function name.
        assert_eq!(
            rewrite_datetime_now("VALUES(1,DATETIME('now'),datetime('now'))"),
            "VALUES(1,CAST(CURRENT_TIMESTAMP AS TEXT),CAST(CURRENT_TIMESTAMP AS TEXT))"
        );
        // A `datetime('now')` INSIDE a single-quoted data literal is left VERBATIM.
        assert_eq!(
            rewrite_datetime_now("UPDATE t SET note='ran datetime(''now'') once' WHERE id=1"),
            "UPDATE t SET note='ran datetime(''now'') once' WHERE id=1"
        );
        // Non-ASCII literal round-trips intact (byte-preserving).
        assert_eq!(
            rewrite_datetime_now("INSERT INTO tenant(name,created) VALUES('Défaut',datetime('now'))"),
            "INSERT INTO tenant(name,created) VALUES('Défaut',CAST(CURRENT_TIMESTAMP AS TEXT))"
        );
        // No datetime token -> only placeholder translation happens.
        assert_eq!(translate_sql("SELECT * FROM t WHERE a=?"), "SELECT * FROM t WHERE a=$1");
    }

    // Acquire a fresh Store on the shared client. Each op MUST be in its own scope so the guard drops
    // before the next Store locks (a std Mutex is non-reentrant — mirrors one `App::store()` per op).
    fn pg_client_or_skip() -> Option<postgres::Client> {
        match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => Some(connect_postgres(&u).expect("connect TEST_PG_URL")),
            _ => {
                eprintln!("[pg_seam_end_to_end] TEST_PG_URL unset — skipping (set it to run against a real Postgres)");
                None
            }
        }
    }

    #[test]
    fn pg_seam_end_to_end() {
        let _g = PG_DB_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let client = match pg_client_or_skip() {
            Some(c) => c,
            None => return,
        };
        let m = std::sync::Mutex::new(client);

        // 1) DDL: reset test tables, then apply the REAL PG_SCHEMA (proves the schema DDL runs on PG).
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute_batch(
                "DROP TABLE IF EXISTS seam_mixed; DROP TABLE IF EXISTS seam_auto;
                 DROP TABLE IF EXISTS finding CASCADE;",
            ).expect("drop test tables");
            s.execute_batch(crate::schema::PG_SCHEMA).expect("apply PG_SCHEMA");
            s.execute_batch(
                "CREATE TABLE seam_auto(
                   id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT,
                   score DOUBLE PRECISION, active BIGINT);
                 CREATE TABLE seam_mixed(i BIGINT, r DOUBLE PRECISION, s TEXT, b BYTEA, n TEXT);",
            ).expect("create seam test tables");
        }

        // 2) execute(INSERT) + last_insert_id() on the SAME session-pinned client (IDENTITY column).
        let (id1, id2);
        {
            let s = Store::postgres(m.lock().unwrap());
            let n = s.execute(
                "INSERT INTO seam_auto(name, score, active) VALUES(?,?,?)",
                &sql_params!["alpha", 1.5_f64, true],
            ).expect("insert alpha");
            assert_eq!(n, 1, "one row inserted");
            id1 = s.last_insert_id();
            assert!(id1 > 0, "IDENTITY id assigned (lastval on same session): {id1}");
            s.execute(
                "INSERT INTO seam_auto(name, score, active) VALUES(?,?,?)",
                &sql_params!["beta", 2.5_f64, false],
            ).expect("insert beta");
            id2 = s.last_insert_id();
            drop(s);
            assert!(id2 > id1, "second id strictly greater: {id2} > {id1}");
        }

        // 3) Bool binding read-back (Param::Bool -> BIGINT 0/1, NOT PG bool) + typed getters.
        {
            let s = Store::postgres(m.lock().unwrap());
            let (active_alpha, bool_alpha): (i64, bool) = s.query_row(
                "SELECT active FROM seam_auto WHERE name=?",
                &sql_params!["alpha"],
                |r| Ok((r.get_i64(0)?, r.get_bool(0)?)),
            ).expect("read alpha active");
            assert_eq!(active_alpha, 1, "Bool(true) bound as BIGINT 1");
            assert!(bool_alpha, "get_bool reads BIGINT 1 as true");
            let active_beta: i64 = s.query_row(
                "SELECT active FROM seam_auto WHERE name=?",
                &sql_params!["beta"],
                |r| r.get_i64(0),
            ).expect("read beta active");
            drop(s);
            assert_eq!(active_beta, 0, "Bool(false) bound as BIGINT 0");
        }

        // 4) query (strict, all rows) + query_lax (skip a mapping error) + query_opt (Some/None).
        {
            let s = Store::postgres(m.lock().unwrap());
            let all: Vec<String> = s.query(
                "SELECT name FROM seam_auto ORDER BY id",
                &sql_params![],
                |r| r.get_str(0),
            ).expect("query all names");
            assert_eq!(all, vec!["alpha".to_string(), "beta".to_string()]);

            // query_lax: closure returns Err for "beta" -> that row is SKIPPED, "alpha" kept.
            let kept: Vec<String> = s.query_lax(
                "SELECT name FROM seam_auto ORDER BY id",
                &sql_params![],
                |r| {
                    let name = r.get_str(0)?;
                    if name == "beta" { Err(StoreError::Backend("skip".into())) } else { Ok(name) }
                },
            ).expect("query_lax");
            assert_eq!(kept, vec!["alpha".to_string()], "query_lax skips the erroring row");

            // query_opt: present -> Some, absent -> None.
            let present: Option<i64> = s.query_opt(
                "SELECT id FROM seam_auto WHERE name=?",
                &sql_params!["alpha"],
                |r| r.get_i64(0),
            ).expect("query_opt present");
            assert_eq!(present, Some(id1));
            let absent: Option<i64> = s.query_opt(
                "SELECT id FROM seam_auto WHERE name=?",
                &sql_params!["nope"],
                |r| r.get_i64(0),
            ).expect("query_opt absent");
            drop(s);
            assert_eq!(absent, None);
        }

        // 5) get_value on a column PER type (BIGINT/DOUBLE/TEXT/BYTEA/NULL) + a nullable-column read.
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute(
                "INSERT INTO seam_mixed(i, r, s, b, n) VALUES(?,?,?,?,?)",
                &sql_params![42_i64, 3.5_f64, "hello", vec![1_u8, 2_u8], Option::<String>::None],
            ).expect("insert seam_mixed");
            s.query_row(
                "SELECT i, r, s, b, n FROM seam_mixed",
                &sql_params![],
                |r| {
                    // Dynamic dispatch on the PG column type -> neutral Value (matches SQLite).
                    assert_eq!(r.get_value(0)?, Value::Int(42));
                    assert_eq!(r.get_value(1)?, Value::Real(3.5));
                    assert_eq!(r.get_value(2)?, Value::Text("hello".into()));
                    assert_eq!(r.get_value(3)?, Value::Blob(vec![1, 2]));
                    assert_eq!(r.get_value(4)?, Value::Null);
                    // value_to_json parity with SoQL-over-SQLite (blob/null -> JSON null).
                    assert_eq!(value_to_json(&r.get_value(0)?), serde_json::json!(42));
                    assert_eq!(value_to_json(&r.get_value(3)?), serde_json::Value::Null);
                    // Typed getters + nullable-column read.
                    assert_eq!(r.get_i64(0)?, 42);
                    assert_eq!(r.get_f64(1)?, 3.5);
                    assert_eq!(r.get_str(2)?, "hello");
                    assert_eq!(r.get_blob(3)?, vec![1, 2]);
                    assert_eq!(r.get_opt_str(4)?, None, "nullable column reads back None");
                    // by-name variants dispatch identically.
                    assert_eq!(r.get_value_by("i")?, Value::Int(42));
                    assert_eq!(r.get_opt_str_by("n")?, None);
                    Ok(())
                },
            ).expect("read seam_mixed row");
        }

        // 6) ON CONFLICT DO NOTHING upsert on the REAL finding table (UNIQUE(campaign,target,title)).
        {
            let s = Store::postgres(m.lock().unwrap());
            let n1 = s.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING",
                &sql_params!["2026-01-01", "c1", "t1", "dup-title", "LOW"],
            ).expect("first finding insert");
            assert_eq!(n1, 1, "first insert creates the row");
            let fid = s.last_insert_id();
            assert!(fid > 0, "finding IDENTITY id: {fid}");
            let n2 = s.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING",
                &sql_params!["2026-01-02", "c1", "t1", "dup-title", "HIGH"],
            ).expect("duplicate finding insert");
            assert_eq!(n2, 0, "duplicate (campaign,target,title) is a no-op via ON CONFLICT DO NOTHING");
            // Row count is still 1 for that key, and severity unchanged (DO NOTHING, not DO UPDATE).
            let sev: String = s.query_row(
                "SELECT severity FROM finding WHERE campaign=? AND target=? AND title=?",
                &sql_params!["c1", "t1", "dup-title"],
                |r| r.get_str(0),
            ).expect("read finding severity");
            drop(s);
            assert_eq!(sev, "LOW", "DO NOTHING left the original row untouched");
        }

        // 7) transaction COMMIT — inserted row persists.
        {
            let s = Store::postgres(m.lock().unwrap());
            s.with_tx(|tx| {
                tx.execute(
                    "INSERT INTO seam_auto(name, score, active) VALUES(?,?,?)",
                    &sql_params!["committed", 9.0_f64, 1_i64],
                )?;
                Ok(())
            }).expect("tx commit");
        }
        {
            
            let cnt: i64 = (Store::postgres(m.lock().unwrap())).query_row(
                "SELECT COUNT(*) FROM seam_auto WHERE name=?",
                &sql_params!["committed"],
                |r| r.get_i64(0),
            ).expect("count committed");
            assert_eq!(cnt, 1, "committed row persisted");
        }

        // 8) transaction ROLLBACK — closure returns Err, the insert is undone.
        {
            
            let res: StoreResult<()> = (Store::postgres(m.lock().unwrap())).with_tx(|tx| {
                tx.execute(
                    "INSERT INTO seam_auto(name, score, active) VALUES(?,?,?)",
                    &sql_params!["rolledback", 9.0_f64, 1_i64],
                )?;
                Err(StoreError::Backend("force rollback".into()))
            });
            assert!(res.is_err(), "with_tx surfaces the closure error");
        }
        {
            
            let cnt: i64 = (Store::postgres(m.lock().unwrap())).query_row(
                "SELECT COUNT(*) FROM seam_auto WHERE name=?",
                &sql_params!["rolledback"],
                |r| r.get_i64(0),
            ).expect("count rolledback");
            assert_eq!(cnt, 0, "rolled-back row absent");
        }
    }

    /// WHOLE-APP round-trip on a REAL Postgres (Stage 2b batch 5) — proves the WIRED backend behaves:
    /// apply `PG_SCHEMA`, run the SHARED boot seeders (dashboard #1 / engagement #1 / tenant #1 / module
    /// catalog) through the seam, provision + read back a login, and drive a run/ingest round-trip
    /// (run_job + finding + runrecord + roe_decision) — every `datetime('now')` site exercising the
    /// seam's Postgres dialect rewrite. Also proves settings read/write and that `is_postgres()` is true.
    /// Each op is its own `Store` scope (the shared std Mutex is non-reentrant) — the same
    /// one-`App::store()`-per-op discipline the runtime uses.
    #[test]
    fn pg_boot_seed_login_run_roundtrip() {
        let _g = PG_DB_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let client = match pg_client_or_skip() {
            Some(c) => c,
            None => return,
        };
        let m = std::sync::Mutex::new(client);

        // 0) Clean slate: drop the base tables, then apply the REAL PG_SCHEMA (the boot DDL branch).
        {
            let s = Store::postgres(m.lock().unwrap());
            assert!(s.is_postgres(), "backend routed to Postgres");
            s.execute_batch(
                "DROP TABLE IF EXISTS finding CASCADE; DROP TABLE IF EXISTS runrecord CASCADE;
                 DROP TABLE IF EXISTS roe_decision CASCADE; DROP TABLE IF EXISTS run_job CASCADE;
                 DROP TABLE IF EXISTS run_log CASCADE; DROP TABLE IF EXISTS module CASCADE;
                 DROP TABLE IF EXISTS dashboard CASCADE; DROP TABLE IF EXISTS panel CASCADE;
                 DROP TABLE IF EXISTS engagement CASCADE; DROP TABLE IF EXISTS tenant CASCADE;
                 DROP TABLE IF EXISTS tenant_grant CASCADE; DROP TABLE IF EXISTS settings CASCADE;
                 DROP TABLE IF EXISTS users CASCADE; DROP TABLE IF EXISTS session CASCADE;
                 DROP TABLE IF EXISTS finding_template CASCADE; DROP TABLE IF EXISTS campaign CASCADE;
                 DROP TABLE IF EXISTS ledger_entry CASCADE;",
            ).expect("drop base tables");
            s.execute_batch(crate::schema::PG_SCHEMA).expect("apply PG_SCHEMA");
        }

        // 1) BOOT SEEDING through the seam — the SAME seeder functions main.rs calls at boot.
        {
            let s = Store::postgres(m.lock().unwrap());
            crate::schema::ensure_default_dashboard(&s);
            // Portable temp path (no hardcoded /tmp — respects TMPDIR / platform temp dir). The value is
            // an inert ledger-path label here (never opened by this seeding test): behaviour-neutral.
            let eng_ledger = std::env::temp_dir().join("forge-pg-eng.jsonl");
            crate::schema::ensure_default_engagement(&s, &["a.example.com".to_string()], "grey", &eng_ledger.to_string_lossy());
            crate::schema::ensure_default_tenant(&s);
            // module catalog (populate_modules spawns python; here we seed one row via the shared upsert).
            crate::schema::upsert_probed_module(&s, "recon.web", false, false, true, "T1595", "web recon", "[]", "[]");
        }
        {
            let s = Store::postgres(m.lock().unwrap());
            let dash: i64 = s.query_row("SELECT COUNT(*) FROM dashboard WHERE id=1", &sql_params![], |r| r.get_i64(0)).unwrap();
            let eng: i64 = s.query_row("SELECT COUNT(*) FROM engagement WHERE id=1", &sql_params![], |r| r.get_i64(0)).unwrap();
            let ten: i64 = s.query_row("SELECT COUNT(*) FROM tenant WHERE id=1", &sql_params![], |r| r.get_i64(0)).unwrap();
            let modl: i64 = s.query_row("SELECT COUNT(*) FROM module WHERE kind=?", &sql_params!["recon.web"], |r| r.get_i64(0)).unwrap();
            drop(s);
            assert_eq!((dash, eng, ten, modl), (1, 1, 1, 1), "boot seeding landed in PG");
        }

        // 1b) IDENTITY sequence desync fix: the seeders inserted an EXPLICIT id=1 into
        // dashboard/engagement/tenant, which on PG does NOT advance the GENERATED-BY-DEFAULT IDENTITY
        // sequence. advance_pg_identity_sequences() setval's each to max(id); the NEXT runtime
        // INSERT-without-id must then yield id>1 (not a colliding id=1 -> duplicate key). This is the
        // exact boot ordering main.rs uses (seed -> advance).
        {
            let s = Store::postgres(m.lock().unwrap());
            crate::schema::advance_pg_identity_sequences(&s);
        }
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute(
                "INSERT INTO dashboard(name,descr,position,created,updated) \
                 VALUES(?,?,?,CAST(CURRENT_TIMESTAMP AS TEXT),CAST(CURRENT_TIMESTAMP AS TEXT))",
                &sql_params!["dash2", "second", 1_i64],
            ).expect("runtime dashboard insert (no id)");
            let new_id = s.last_insert_id();
            drop(s);
            assert!(new_id > 1, "IDENTITY advanced past seeded id=1 (got {new_id}) — no duplicate-key collision");
        }

        // 2) LOGIN provisioning — upsert_user_store uses `datetime('now')` (seam rewrite) + ON CONFLICT.
        {
            
            let role = crate::state::upsert_user_store(&(Store::postgres(m.lock().unwrap())), "admin", "admin", "argon2-hash-placeholder")
                .expect("provision admin");
            assert_eq!(role, "admin");
        }
        {
            let s = Store::postgres(m.lock().unwrap());
            let (login, role): (String, String) = s.query_row(
                "SELECT login, role FROM users WHERE login=?",
                &sql_params!["admin"],
                |r| Ok((r.get_str(0)?, r.get_str(1)?)),
            ).expect("read back admin");
            assert_eq!((login.as_str(), role.as_str()), ("admin", "admin"), "admin login readable in PG");
            // `created` was written via datetime('now') -> CAST(CURRENT_TIMESTAMP AS TEXT): a non-empty TEXT.
            let created: String = s.query_row("SELECT created FROM users WHERE login=?", &sql_params!["admin"], |r| r.get_str(0)).unwrap();
            drop(s);
            assert!(!created.is_empty(), "datetime('now') rewrite produced a timestamp: {created:?}");
        }

        // 3) RUN CREATE — run_job insert (run_create path) uses datetime('now') + ON CONFLICT(run_id).
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode,pid,started_by,reason,targets,modules,started,engagement_id)
                 VALUES(?,?,datetime('now'),'running',?,?,?,?,?,?,datetime('now'),?)
                 ON CONFLICT(run_id) DO UPDATE SET status='running', pid=excluded.pid, started=excluded.started",
                &sql_params!["run-1", "camp", "grey", 4242_i64, "admin", "manual", "[\"a.example.com\"]", "[\"recon.web\"]", 1_i64],
            ).expect("run_job insert");
        }

        // 4) INGEST — finding (ON CONFLICT DO NOTHING) + runrecord + roe_decision + run_job upsert.
        {
            let s = Store::postgres(m.lock().unwrap());
            let n = s.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score,engagement_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                &sql_params!["2026-07-09", "camp", "a.example.com", "IDOR", "HIGH", "idor", "T1190", "vulnerable",
                    "ev", "oracle.idor", "poc", "fix", "run-1", "CWE-639", "", 0.0_f64, 1_i64],
            ).expect("finding insert");
            assert_eq!(n, 1, "finding inserted");
            s.execute(
                "INSERT INTO runrecord(ts,campaign,target,kind,mitre,fired,detail,run_id,engagement_id) VALUES(?,?,?,?,?,?,?,?,?)",
                &sql_params!["2026-07-09", "camp", "a.example.com", "recon.web", "T1595", 1_i64, "d", "run-1", 1_i64],
            ).expect("runrecord insert");
            s.execute(
                "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons,engagement_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                &sql_params!["2026-07-09", "camp", "run-1", "a1", "a.example.com", "recon.web", "FIRE", 0_i64, 0_i64, "[]", 1_i64],
            ).expect("roe_decision insert");
            s.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps)
                 VALUES(?,?,datetime('now'),'done',?,?,?,?,?,?,?)
                 ON CONFLICT(run_id) DO UPDATE SET status='done', mode=excluded.mode, fired=excluded.fired",
                &sql_params!["run-1", "camp", "grey", 1_i64, 0_i64, 0_i64, 0_i64, "[]", "{}"],
            ).expect("run_job upsert (ingest)");
        }
        {
            let s = Store::postgres(m.lock().unwrap());
            let f: i64 = s.query_row("SELECT COUNT(*) FROM finding WHERE run_id=?", &sql_params!["run-1"], |r| r.get_i64(0)).unwrap();
            let rr: i64 = s.query_row("SELECT COUNT(*) FROM runrecord WHERE run_id=?", &sql_params!["run-1"], |r| r.get_i64(0)).unwrap();
            let rd: i64 = s.query_row("SELECT COUNT(*) FROM roe_decision WHERE run_id=?", &sql_params!["run-1"], |r| r.get_i64(0)).unwrap();
            let rj: String = s.query_row("SELECT status FROM run_job WHERE run_id=?", &sql_params!["run-1"], |r| r.get_str(0)).unwrap();
            drop(s);
            assert_eq!((f, rr, rd), (1, 1, 1), "run produced finding/runrecord/roe_decision rows in PG");
            assert_eq!(rj, "done", "run_job upsert transitioned running->done in PG");
        }

        // 5) SETTINGS read/write round-trip (settings_set_store uses datetime('now') -> seam rewrite).
        {
            let s = Store::postgres(m.lock().unwrap());
            crate::state::settings_set_store(&s, "detection_source", "{\"kind\":\"none\"}").expect("settings write");
        }
        {
            let s = Store::postgres(m.lock().unwrap());
            let v = crate::state::settings_get_store(&s, "detection_source");
            drop(s);
            assert_eq!(v.as_deref(), Some("{\"kind\":\"none\"}"), "settings round-trip in PG");
        }
    }

    /// STAGE 4 HA — read reconnect+retry (`postgres_reconnectable` / `pg_run_read`). Proves an idempotent
    /// READ op transparently RECONNECTS+RETRIES when the pinned session is torn down (the deterministic
    /// analogue of a PG restart /
    /// failover), WITHOUT restarting the server: capture the pinned client's backend PID, terminate THAT
    /// backend from a SEPARATE connection (so the pinned client is dead but the test's own connection is
    /// not), then assert the NEXT op on the reconnectable store SUCCEEDS and now runs on a NEW backend PID
    /// (proving the healed client was swapped into the shared Mutex). Gated on `TEST_PG_URL`.
    #[test]
    fn pg_reconnect_after_session_terminated() {
        let _g = PG_DB_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_reconnect_after_session_terminated] TEST_PG_URL unset — skipping");
                return;
            }
        };
        let m = std::sync::Mutex::new(connect_postgres(&url).expect("connect pinned client"));

        // Baseline: the reconnectable store works, and capture the pinned session's backend PID.
        let pid: i64 = {
            let s = Store::postgres_reconnectable(m.lock().unwrap_or_else(|e| e.into_inner()), &url);
            assert_eq!(s.query_row("SELECT 1", &sql_params![], |r| r.get_i64(0)).unwrap(), 1);
            s.query_row("SELECT pg_backend_pid()", &sql_params![], |r| r.get_i64(0)).unwrap()
        };

        // Kill THAT backend from a throwaway connection (NOT the reconnecting store — avoids cascading the
        // self-terminate through its retry), then WAIT until the backend is actually GONE from
        // pg_stat_activity. `pg_terminate_backend` returns once the SIGTERM is SENT, not once the backend
        // has exited — polling to disappearance removes that race so the next pinned-store op is guaranteed
        // to hit a dead session (deterministic reconnect).
        {
            let k = std::sync::Mutex::new(connect_postgres(&url).expect("connect killer"));
            let ks = Store::postgres(k.lock().unwrap_or_else(|e| e.into_inner()));
            // pid is a trusted integer from pg_backend_pid() — INTERPOLATE it. A bound `?::int` makes
            // Postgres infer the param as int4 and tokio-postgres rejects the i64 bind (WrongType
            // Int4/i64); that error, if swallowed, would leave the backend ALIVE and make this test pass
            // WITHOUT ever terminating the session (a vacuous reconnect test). Assert the kill ran.
            ks.execute(&format!("SELECT pg_terminate_backend({pid})"), &sql_params![])
                .expect("pg_terminate_backend must actually run");
            let mut gone = false;
            for _ in 0..200 {
                let alive: i64 = ks
                    .query_row(
                        &format!("SELECT count(*) FROM pg_stat_activity WHERE pid = {pid}"),
                        &sql_params![],
                        |r| r.get_i64(0),
                    )
                    .expect("poll pg_stat_activity");
                if alive == 0 {
                    gone = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            drop(ks); // ks last-used inside the poll loop; release after the loop, before the assert
            assert!(gone, "terminated backend {pid} did not disappear from pg_stat_activity");
        }

        // The NEXT op on the pinned store MUST reconnect once and succeed (would error without HA).
        {
            
            let two: i64 = (Store::postgres_reconnectable(m.lock().unwrap_or_else(|e| e.into_inner()), &url))
                .query_row("SELECT 2", &sql_params![], |r| r.get_i64(0))
                .expect("store op reconnects after the pinned session was terminated");
            assert_eq!(two, 2);
        }

        // The reconnect SWAPPED the healed client INTO the shared Mutex — proven pid-reuse-immune: a
        // NON-reconnectable store on the SAME mutex now SUCCEEDS. If the swap had NOT persisted (e.g. the
        // reconnect healed only a local client), the mutex would still hold the DEAD client and this
        // no-retry store would ERROR. (A pid comparison is unreliable: PostgreSQL recycles backend pids.)
        {
            
            let four: i64 = (Store::postgres(m.lock().unwrap_or_else(|e| e.into_inner())))
                .query_row("SELECT 4", &sql_params![], |r| r.get_i64(0))
                .expect("shared mutex holds the healed client (non-reconnectable store succeeds)");
            assert_eq!(four, 4);
        }
        let _ = pid; // captured only to terminate the pinned session above
    }

    /// STAGE 4 HA — WRITE break MUST NOT auto-re-apply (`pg_run_write`). Proves the write path's
    /// at-most-once contract: an `execute(INSERT)` whose pinned session is torn down mid-flight returns
    /// an ERROR to the caller (never a silent success), the failed statement is NEVER auto-retried (so the
    /// row is not duplicated), and the held client is HEALED so the NEXT op works. Deterministic analogue
    /// of a PG restart/failover, same technique as `pg_reconnect_after_session_terminated`: capture the
    /// pinned backend PID, terminate THAT backend from a SEPARATE connection, wait until it is gone, then
    /// drive a WRITE on the reconnectable store. Gated on `TEST_PG_URL`.
    #[test]
    fn pg_write_break_does_not_duplicate() {
        let _g = PG_DB_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_write_break_does_not_duplicate] TEST_PG_URL unset — skipping");
                return;
            }
        };
        let m = std::sync::Mutex::new(connect_postgres(&url).expect("connect pinned client"));

        // Fresh single-row-per-tag probe table on the pinned session; capture that session's backend PID.
        let pid: i64 = {
            let s = Store::postgres_reconnectable(m.lock().unwrap_or_else(|e| e.into_inner()), &url);
            s.execute_batch(
                "DROP TABLE IF EXISTS dup_probe; CREATE TABLE dup_probe(id BIGINT GENERATED BY DEFAULT AS IDENTITY, tag TEXT)",
            )
            .expect("create dup_probe");
            s.query_row("SELECT pg_backend_pid()", &sql_params![], |r| r.get_i64(0)).unwrap()
        };

        // Kill THAT backend from a throwaway connection, then WAIT until it is actually gone (SIGTERM is
        // async): guarantees the next pinned-store op hits a DEAD session (deterministic break).
        {
            let k = std::sync::Mutex::new(connect_postgres(&url).expect("connect killer"));
            let ks = Store::postgres(k.lock().unwrap_or_else(|e| e.into_inner()));
            // pid is a trusted integer from pg_backend_pid() — interpolate it (binding `?::int` fails with
            // a WrongType Int4/i64 mismatch that would be silently swallowed, leaving the backend alive).
            let killed = ks.execute(&format!("SELECT pg_terminate_backend({pid})"), &sql_params![]);
            assert!(killed.is_ok(), "pg_terminate_backend must actually run: {killed:?}");
            let mut gone = false;
            for _ in 0..200 {
                let alive: i64 = ks
                    .query_row(
                        &format!("SELECT count(*) FROM pg_stat_activity WHERE pid = {pid}"),
                        &sql_params![],
                        |r| r.get_i64(0),
                    )
                    .expect("poll pg_stat_activity");
                if alive == 0 {
                    gone = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            drop(ks); // ks last-used inside the poll loop; release after the loop, before the assert
            assert!(gone, "terminated backend {pid} did not disappear from pg_stat_activity");
        }

        // WRITE on the DEAD session: the caller MUST receive an error — the write is NOT silently retried
        // and NOT silently reported as success. (`pg_run_write` reconnects for the NEXT op but returns the
        // ORIGINAL error without re-executing.)
        {
            
            let r = (Store::postgres_reconnectable(m.lock().unwrap_or_else(|e| e.into_inner()), &url)).execute(
                "INSERT INTO dup_probe(tag) VALUES(?)",
                &sql_params!["broke"],
            );
            assert!(r.is_err(), "write against a torn-down session surfaces an error (no silent success)");
        }

        // The failed write was NEVER auto-re-applied: exactly ZERO rows for that tag (at-most-once — the
        // statement never reached a live backend, and `pg_run_write` did not retry it). Must never be >= 1
        // (a retry would have produced a row) and never == 2 (a duplicate). Runs on the HEALED client that
        // `pg_run_write` swapped into the shared Mutex — a NON-reconnectable store proves the heal persisted.
        {
            
            let cnt: i64 = (Store::postgres(m.lock().unwrap_or_else(|e| e.into_inner())))
                .query_row(
                    "SELECT count(*) FROM dup_probe WHERE tag = ?",
                    &sql_params!["broke"],
                    |r| r.get_i64(0),
                )
                .expect("shared mutex holds the healed client after the broken WRITE");
            assert_eq!(cnt, 0, "the broken write was neither applied nor auto-duplicated");
        }

        // The healed client is fully usable for subsequent WRITES too (a real INSERT now lands exactly once).
        {
            let s = Store::postgres_reconnectable(m.lock().unwrap_or_else(|e| e.into_inner()), &url);
            s.execute("INSERT INTO dup_probe(tag) VALUES(?)", &sql_params!["ok"])
                .expect("write on the healed client succeeds");
            let cnt: i64 = s
                .query_row("SELECT count(*) FROM dup_probe WHERE tag = ?", &sql_params!["ok"], |r| r.get_i64(0))
                .unwrap();
            drop(s);
            assert_eq!(cnt, 1, "post-heal write landed exactly once");
        }
        let _ = pid;
    }

    /// STAGE 4 HA — a transaction that hits a broken connection FAILS AS A WHOLE (`with_tx` + `pg_run_write`):
    /// no mid-tx reconnect, no partial commit. Break the session INSIDE `with_tx` (kill the pinned backend
    /// between two statements of the closure), assert `with_tx` returns an ERROR, and assert NEITHER
    /// statement's row is present (the whole tx is gone — the reconnect never continued the old `BEGIN`).
    /// Gated on `TEST_PG_URL`.
    #[test]
    fn pg_tx_break_fails_whole_no_partial_commit() {
        let _g = PG_DB_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_tx_break_fails_whole_no_partial_commit] TEST_PG_URL unset — skipping");
                return;
            }
        };
        let m = std::sync::Mutex::new(connect_postgres(&url).expect("connect pinned client"));
        let killer_url = url.clone();

        {
            let s = Store::postgres_reconnectable(m.lock().unwrap_or_else(|e| e.into_inner()), &url);
            s.execute_batch("DROP TABLE IF EXISTS tx_probe; CREATE TABLE tx_probe(tag TEXT)")
                .expect("create tx_probe");

            let res: StoreResult<()> = s.with_tx(|tx| {
                // First statement lands inside the BEGIN.
                tx.execute("INSERT INTO tx_probe(tag) VALUES(?)", &sql_params!["first"])?;
                // Tear down THIS session's backend from a separate connection, wait until gone, so the
                // NEXT tx statement hits a dead connection mid-transaction.
                let pid: i64 = tx
                    .query_row("SELECT pg_backend_pid()", &sql_params![], |r| r.get_i64(0))?;
                let k = std::sync::Mutex::new(connect_postgres(&killer_url).expect("connect killer"));
                let ks = Store::postgres(k.lock().unwrap_or_else(|e| e.into_inner()));
                // pid is trusted (from pg_backend_pid) — interpolate; a bound `?::int` mismatches i64/Int4.
                ks.execute(&format!("SELECT pg_terminate_backend({pid})"), &sql_params![])
                    .expect("terminate the in-tx backend");
                for _ in 0..200 {
                    let alive: i64 = ks
                        .query_row(&format!("SELECT count(*) FROM pg_stat_activity WHERE pid = {pid}"), &sql_params![], |r| r.get_i64(0))
                        .expect("poll pg_stat_activity");
                    if alive == 0 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                drop(ks); // ks last-used inside the poll loop; release after the loop, before the assert
                // Second statement on the now-dead session: pg_run_write errors (and heals for next op),
                // the `?` bubbles the error out of the closure -> with_tx best-effort ROLLBACKs + surfaces it.
                tx.execute("INSERT INTO tx_probe(tag) VALUES(?)", &sql_params!["second"])?;
                Ok(())
            });
            drop(s);
            assert!(res.is_err(), "a tx that hits a broken connection fails as a whole");
        }

        // NEITHER row is present: the BEGIN died with its session, no partial commit, the reconnect never
        // continued the tx. Runs on the healed client.
        {
            
            let cnt: i64 = (Store::postgres(m.lock().unwrap_or_else(|e| e.into_inner())))
                .query_row("SELECT count(*) FROM tx_probe", &sql_params![], |r| r.get_i64(0))
                .expect("healed client reads back the tx_probe table");
            assert_eq!(cnt, 0, "no row from the broken tx committed (whole-tx failure, no partial/duplicate)");
        }
    }

    /// POOL — CONCURRENT WRITERS do NOT serialise (the whole point of the pool). Build a `PgPool` of
    /// `N` clients, fire `N` threads that EACH check out a client and run a SLOW insert
    /// (`… SELECT ?::text FROM pg_sleep(D) … RETURNING id`) at the same time, and assert:
    ///   (a) every insert returns a DISTINCT new id via `execute_returning_id` (no lastval/session dep);
    ///   (b) exactly `N` rows land — none lost, none duplicated;
    ///   (c) wall-clock is ~1×D, NOT `N`×D — proving the writers ran in PARALLEL on different pooled
    ///       connections rather than serialising on one client (a single-client backend would take N×D).
    /// Gated on `TEST_PG_URL`.
    #[test]
    fn pg_pool_concurrent_writers() {
        let _g = PG_DB_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_pool_concurrent_writers] TEST_PG_URL unset — skipping");
                return;
            }
        };
        const N: usize = 8;
        const SLEEP_S: f64 = 0.4;

        // Connect N clients OFF any runtime (the sync client drives its own block_on) and build the pool.
        let clients: Vec<postgres::Client> =
            (0..N).map(|_| connect_postgres(&url).expect("connect pool client")).collect();
        let pool = std::sync::Arc::new(PgPool::new(url.clone(), clients));
        assert_eq!(pool.size(), N, "pool holds N clients");

        // Fresh probe table (own scope so the guard drops before the threads check out).
        {
            let s = Store::postgres_reconnectable(pool.checkout(), &pool.url);
            s.execute_batch(
                "DROP TABLE IF EXISTS pool_probe; \
                 CREATE TABLE pool_probe(id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, tag TEXT)",
            )
            .expect("create pool_probe");
        }

        // N threads, each: check out a client, run a SLOW insert returning its id. If the pool truly
        // parallelises, all N sleeps overlap -> ~1×SLEEP_S; if it serialised on one client -> N×SLEEP_S.
        let start = std::time::Instant::now();
        let ids: Vec<i64> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..N)
                .map(|i| {
                    let pool = std::sync::Arc::clone(&pool);
                    scope.spawn(move || {
                        let s = Store::postgres_reconnectable(pool.checkout(), &pool.url);
                        s.execute_returning_id(
                            "INSERT INTO pool_probe(tag) SELECT ?::text FROM pg_sleep(0.4)",
                            &sql_params![format!("w{i}")],
                        )
                        .expect("concurrent slow insert returns its id")
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("writer thread panicked")).collect()
        });
        let elapsed = start.elapsed().as_secs_f64();

        // (a) distinct ids.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), N, "every concurrent insert got a DISTINCT id: {ids:?}");

        // (b) exactly N rows, none lost/duplicated.
        {
            
            let cnt: i64 = (Store::postgres_reconnectable(pool.checkout(), &pool.url))
                .query_row("SELECT count(*) FROM pool_probe", &sql_params![], |r| r.get_i64(0))
                .expect("count pool_probe");
            assert_eq!(cnt, N as i64, "exactly N rows persisted (no lost/duplicate writes)");
        }

        // (c) parallel, not serial: wall-clock well under the serialised bound N×SLEEP_S. Half of it is a
        // generous margin (parallel ~= SLEEP_S + overhead; serial would be ~N×SLEEP_S = {:.1}s).
        let serial_bound = N as f64 * SLEEP_S;
        eprintln!(
            "[pg_pool_concurrent_writers] {N} writers, {SLEEP_S}s each: wall={elapsed:.2}s \
             (serialised would be ~{serial_bound:.1}s) ; ids={ids:?}"
        );
        assert!(
            elapsed < serial_bound * 0.5,
            "concurrent writers ran in PARALLEL: {elapsed:.2}s (serialised would be ~{serial_bound:.1}s)"
        );
    }

    /// POOL — a BROKEN pooled connection is HEALED in place on its next use. Size-1 pool so the checked-
    /// out slot is DETERMINISTIC: capture the slot's backend PID, terminate it from a separate connection,
    /// wait until it is gone, then assert the NEXT checkout+op RECONNECTS+SUCCEEDS (read reconnect+retry)
    /// and a subsequent WRITE lands on the healed slot. Gated on `TEST_PG_URL`.
    #[test]
    fn pg_pool_slot_heals_after_break() {
        let _g = PG_DB_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_pool_slot_heals_after_break] TEST_PG_URL unset — skipping");
                return;
            }
        };
        // Size-1 pool: every checkout returns the SAME slot -> deterministic target for the kill/heal.
        let pool = std::sync::Arc::new(PgPool::new(
            url.clone(),
            vec![connect_postgres(&url).expect("connect single pool client")],
        ));

        let pid: i64 = {
            let s = Store::postgres_reconnectable(pool.checkout(), &pool.url);
            s.execute_batch("DROP TABLE IF EXISTS pool_heal; CREATE TABLE pool_heal(tag TEXT)")
                .expect("create pool_heal");
            s.query_row("SELECT pg_backend_pid()", &sql_params![], |r| r.get_i64(0)).unwrap()
        };

        // Kill THAT backend from a throwaway connection, wait until it disappears (SIGTERM is async).
        {
            let k = std::sync::Mutex::new(connect_postgres(&url).expect("connect killer"));
            let ks = Store::postgres(k.lock().unwrap_or_else(|e| e.into_inner()));
            ks.execute(&format!("SELECT pg_terminate_backend({pid})"), &sql_params![])
                .expect("pg_terminate_backend runs");
            let mut gone = false;
            for _ in 0..200 {
                let alive: i64 = ks
                    .query_row(
                        &format!("SELECT count(*) FROM pg_stat_activity WHERE pid = {pid}"),
                        &sql_params![],
                        |r| r.get_i64(0),
                    )
                    .expect("poll pg_stat_activity");
                if alive == 0 {
                    gone = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            drop(ks); // ks last-used inside the poll loop; release after the loop, before the assert
            assert!(gone, "terminated backend {pid} did not disappear");
        }

        // Next checkout on the (now-dead) slot: an idempotent READ reconnects+retries and succeeds.
        {
            
            let two: i64 = (Store::postgres_reconnectable(pool.checkout(), &pool.url))
                .query_row("SELECT 2", &sql_params![], |r| r.get_i64(0))
                .expect("pooled slot reconnects+retries the read after its backend was terminated");
            assert_eq!(two, 2);
        }
        // The healed slot serves subsequent WRITES too (reconnect swapped a fresh client into the slot).
        {
            let s = Store::postgres_reconnectable(pool.checkout(), &pool.url);
            s.execute("INSERT INTO pool_heal(tag) VALUES(?)", &sql_params!["ok"])
                .expect("write on the healed pooled slot lands");
            let cnt: i64 = s
                .query_row("SELECT count(*) FROM pool_heal WHERE tag=?", &sql_params!["ok"], |r| r.get_i64(0))
                .unwrap();
            drop(s);
            assert_eq!(cnt, 1, "post-heal write landed exactly once on the pooled slot");
        }
    }
}

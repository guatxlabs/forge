// SPDX-License-Identifier: AGPL-3.0-or-later
//! `store` — PLOMBERIE POSTGRES EXTRAITE (PURE MOVE depuis `console/src/store.rs`).
//! Corps IDENTIQUE ; ENFANT de `store`, il voit donc toujours ses items privés (`use super::*;`).
//! Deux seules différences, mécaniques : (1) les 23 `#[cfg(feature = "store-postgres")]` répétés
//! item par item sont COLLAPSÉS dans le `mod pg;` gaté du parent — le module entier n'existe que
//! sous la feature, exactement comme avant ; (2) 15 helpers privés passent `pub(super)` (visibles
//! du seul module `store`) parce que `impl Row`/`impl Store` les appellent depuis `mod.rs`.
//! La surface hors-seam (`crate::store::PgClient|PgPool|connect_postgres`) est re-exportée par
//! `mod.rs` : AUCUN chemin d'appel externe ne change.
use super::*;

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

pub(super) use postgres::types::{IsNull, ToSql, Type};

/// TYPED-NEUTRAL SQL NULL. Postgres statically types every bound parameter from the *prepared
/// statement's* inferred column type, then calls `ToSql::accepts(inferred_type)` — so binding a
/// concrete Rust `Option::<i64>::None` for, say, a `TEXT` column is REJECTED at `accepts` time even
/// though the value is NULL. `PgNull` sidesteps that: `accepts` returns `true` for EVERY type and
/// `to_sql` writes `IsNull::Yes`, so it binds a NULL regardless of the column's inferred type — the
/// portable analogue of `Param::Null` -> `SqlValue::Null` on SQLite.
#[derive(Debug)]
struct PgNull;

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
pub(super) fn pg_binds(params: &[Param]) -> Vec<Box<dyn ToSql + Sync>> {
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
pub(super) fn translate_placeholders(sql: &str) -> String {
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
pub(super) fn rewrite_datetime_now(sql: &str) -> String {
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
pub(super) fn translate_sql(sql: &str) -> String {
    translate_placeholders(&rewrite_datetime_now(sql))
}

/// Map a `postgres::Error` to the seam's `StoreError` (message VERBATIM — same discipline as the
/// rusqlite `From` impl, so `format!("… {e}")` call sites read identically).
pub(super) fn pg_err(e: postgres::Error) -> StoreError {
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
pub(super) fn pg_block<T>(f: impl FnOnce() -> T) -> T {
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
pub(crate) type PgClient = postgres::Client;

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
pub(super) fn pg_run_read<T>(
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
pub(super) fn pg_run_write<T>(
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

pub(super) fn pg_get_i64(r: &postgres::Row, idx: usize) -> StoreResult<i64> {
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

pub(super) fn pg_get_opt_i64(r: &postgres::Row, idx: usize) -> StoreResult<Option<i64>> {
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

pub(super) fn pg_get_f64(r: &postgres::Row, idx: usize) -> StoreResult<f64> {
    if let Ok(v) = r.try_get::<_, f64>(idx) {
        return Ok(v);
    }
    if let Ok(v) = r.try_get::<_, f32>(idx) {
        return Ok(v as f64);
    }
    r.try_get::<_, f64>(idx).map_err(pg_err)
}

pub(super) fn pg_get_opt_f64(r: &postgres::Row, idx: usize) -> StoreResult<Option<f64>> {
    if let Ok(v) = r.try_get::<_, Option<f64>>(idx) {
        return Ok(v);
    }
    if let Ok(v) = r.try_get::<_, Option<f32>>(idx) {
        return Ok(v.map(|x| x as f64));
    }
    r.try_get::<_, Option<f64>>(idx).map_err(pg_err)
}

pub(super) fn pg_get_bool(r: &postgres::Row, idx: usize) -> StoreResult<bool> {
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
pub(super) fn pg_get_value(r: &postgres::Row, idx: usize) -> StoreResult<Value> {
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
pub(super) fn pg_col_index(r: &postgres::Row, col: &str) -> StoreResult<usize> {
    r.columns()
        .iter()
        .position(|c| c.name() == col)
        .ok_or_else(|| StoreError::Backend(format!("no such column: {col}")))
}

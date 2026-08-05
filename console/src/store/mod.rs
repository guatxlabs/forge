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
// BACKEND POSTGRES (Stage 2) — plomberie EXTRAITE dans `store/pg.rs` (PURE MOVE). Le module ENTIER
// est gaté par la feature : le build par défaut (community) n'en compile RIEN, ce qui remplace à
// l'identique les 23 `#[cfg(feature = "store-postgres")]` que portait chaque item. Le glob
// `pub(crate) use pg::*` garde INCHANGÉS et les appels internes du seam (`pg_err`, `translate_sql`,
// `pg_run_read`, `pg_get_*`, …) et les chemins externes `crate::store::{PgClient, PgPool,
// connect_postgres}` utilisés par `boot.rs` / `state.rs` / `cli/mod.rs`.
// ================================================================================================
#[cfg(feature = "store-postgres")]
mod pg;
#[cfg(feature = "store-postgres")]
pub(crate) use pg::*;

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
mod tests;

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
mod tests_pg;

// SPDX-License-Identifier: AGPL-3.0-only
//! ENTERPRISE — Advanced RBAC: IdP-group -> {Forge role, tenant grant} mapping (SEPARABLE, FLAG-GATED).
//!
//! Open-core discipline (mirrors `tenancy.rs` / `sso.rs` / `scim.rs`): this is the ENTERPRISE
//! "advanced authorization" slice. The COMMUNITY (default) build behaves EXACTLY as today — LOCAL
//! accounts, roles assigned only by a console admin. This module is INERT unless enterprise SSO **or**
//! SCIM is engaged (`enabled()` = `sso::enabled() || scim::enabled()`); with both flags OFF every
//! `/api/rbac/*` route 404s and the mapping table is never created (community DB byte-identical).
//!
//! WHAT IT ADDS: a CONFIGURABLE mapping from an IdP group name to a Forge authorization outcome —
//!   `idp_group -> { role: viewer|operator|admin, tenant_id?, tenant_role? }`.
//! Both the SSO login path (the ID-token `groups` claim) and the SCIM group-membership path consult
//! this ONE table, so an admin configures group -> access in a single place. It replaces the previous
//! best-effort `displayName` heuristic with an explicit, auditable mapping.
//!
//! FAIL-CLOSED / LEAST-PRIVILEGE (weaken any of these and a test flips RED):
//!   - An SSO/SCIM identity gets ONLY the grants its group mapping confers. No matching group => the
//!     mapping resolves to `role: None` (the caller falls back to its own least-privilege default —
//!     `viewer` at most); it NEVER silently grants more.
//!   - NEVER super-admin via SSO/SCIM. Super-admin is a PROVISIONING-ONLY designation (see
//!     `tenancy.rs`) — it is not a `users.role` value and cannot be expressed in this table. A
//!     designated super-admin login is additionally NEVER mutated by `apply_to_user` (guard).
//!   - The console role is validated to `viewer|operator|admin` and the tenant role to
//!     `tenant_admin|tenant_operator|tenant_viewer`; anything else (incl. "super_admin") is rejected
//!     at config time and can never be resolved.
//!   - When multiple mapped groups match, the HIGHEST role wins (viewer < operator < admin), still
//!     capped at admin. SCIM callers additionally clamp admin -> operator (SCIM's documented stance:
//!     automated bulk provisioning never auto-confers console admin).
//!
//! SECRETS: this module handles NO secret (no token, no client_secret). Mutations are ledgered
//! `console.rbac.*` with metadata only (group / role / counts).

use crate::App;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;

// ============================================================================================
// FLAG — advanced RBAC is engaged iff enterprise SSO OR SCIM is engaged (it governs their group
// mappings; on its own, with local-only accounts, it has nothing to map). Community default = OFF.
// ============================================================================================

/// Is the advanced-RBAC surface engaged?  false => community (every `/api/rbac/*` route 404s, the
/// mapping table is never created, role assignment is admin-only exactly as today).
pub fn enabled(app: &App) -> bool {
    crate::sso::enabled(app) || crate::scim::enabled(app)
}

/// Flag-OFF response: the route behaves as ABSENT (community build shows no advanced-RBAC surface).
fn disabled() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response()
}

/// Standard typed-error response (shared substrate; byte-identical `{"error","why"}`). Never a secret.
fn err(status: StatusCode, code: &'static str, why: impl Into<String>) -> Response {
    crate::error::ApiError::new(status, code, why).into_response()
}

// ============================================================================================
// SCHEMA — created LAZILY (only when a flag-gated route runs => community DB is never touched).
// ============================================================================================

/// The group-mapping table. `idp_group` is the IdP's group name (exact match). `role` is a console
/// role (viewer|operator|admin). `tenant_id`/`tenant_role` are OPTIONAL: when set, membership also
/// lands a scoped tenant grant (E1 multi-tenancy). Created lazily — the community DB never sees it.
fn ensure_schema(store: &crate::store::Store) {
    // POSTGRES dialect (feature `store-postgres` + backend actif PG) : `INTEGER`->`BIGINT` (parité binds
    // i64 du seam pour tenant_id/created). `idp_group TEXT PRIMARY KEY` inchangé. Table flag-gated créée
    // paresseusement — HORS de PG_SCHEMA (la base community ne la voit jamais).
    #[cfg(feature = "store-postgres")]
    if store.is_postgres() {
        let _ = store.execute_batch(
            "CREATE TABLE IF NOT EXISTS rbac_group_map(
               idp_group   TEXT PRIMARY KEY,
               role        TEXT NOT NULL,
               tenant_id   BIGINT,
               tenant_role TEXT,
               created     BIGINT NOT NULL DEFAULT 0);",
        );
        return;
    }
    let _ = store.execute_batch(
        "CREATE TABLE IF NOT EXISTS rbac_group_map(
           idp_group   TEXT PRIMARY KEY,
           role        TEXT NOT NULL,
           tenant_id   INTEGER,
           tenant_role TEXT,
           created     INTEGER NOT NULL DEFAULT 0);",
    );
}

/// PG-ONLY — crée la table enterprise RBAC `rbac_group_map` (mappings IdP-groupe -> rôle) sur la CIBLE
/// Postgres pour le migrateur de données (`cli::migrate-store`) : hors de `PG_SCHEMA` (créée paresseusement),
/// le migrateur doit invoquer ce chemin pour que la cible la possède AVANT la copie (sinon absente ->
/// hard-fail, jamais de skip silencieux — sinon les autorisations IdP->rôle seraient perdues en silence).
/// Délègue à `ensure_schema` (branche `is_postgres()`). Entièrement gardé `store-postgres` : le build
/// community ne compile pas cette fonction.
#[cfg(feature = "store-postgres")]
pub(crate) fn ensure_pg_schema(store: &crate::store::Store) {
    ensure_schema(store);
}

// ============================================================================================
// ROUTES — admin-gated CRUD of the mapping (merged in the OUTER router; self-gates like sso/scim).
// ============================================================================================

/// Advanced-RBAC routes. Merged into the OUTER router (like `sso::routes` / `scim::routes`) so the
/// module owns its own surface; each handler self-gates on the flag + `check_admin` (fail-closed).
pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/rbac/group-map", get(map_list).post(map_set))
        .route("/api/rbac/group-map/:group", axum::routing::delete(map_delete))
}

/// GET /api/rbac/group-map — list every group mapping (admin-only). Returns `{enabled, mappings:[…]}`.
async fn map_list(State(app): State<App>, headers: HeaderMap) -> Response {
    if !enabled(&app) {
        return disabled();
    }
    if !crate::check_admin(&app, &headers) {
        return err(StatusCode::FORBIDDEN, "admin_required", "advanced-RBAC config is admin-only");
    }
    let mappings = list_mappings(&app);
    (StatusCode::OK, Json(json!({ "enabled": true, "mappings": mappings }))).into_response()
}

/// POST /api/rbac/group-map — upsert ONE mapping (admin-only). Body:
///   `{ "group": "<idp group>", "role": "viewer|operator|admin",
///     "tenant_id": <int, optional>, "tenant_role": "tenant_admin|tenant_operator|tenant_viewer" (opt) }`
/// Fail-closed validation: unknown role / tenant_role is rejected (super_admin can never be stored).
/// Ledgered `console.rbac.map.set` (group + role + tenant only — no secret).
async fn map_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !enabled(&app) {
        return disabled();
    }
    if !crate::check_admin(&app, &headers) {
        return err(StatusCode::FORBIDDEN, "admin_required", "advanced-RBAC config is admin-only");
    }
    let group = body.get("group").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if group.is_empty() || group.len() > 200 {
        return err(StatusCode::BAD_REQUEST, "bad_group", "group required (1..200 chars)");
    }
    let role_in = body.get("role").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    // Validate to viewer|operator|admin — rejects "super_admin"/"super-admin"/anything unknown.
    let role = match crate::validate_role(&role_in) {
        Ok(r) => r,
        Err(_) => return err(StatusCode::BAD_REQUEST, "bad_role", "role must be viewer|operator|admin (never super-admin)"),
    };
    // Optional tenant grant. tenant_id must be a positive int; tenant_role (if given) must be valid.
    let tenant_id: Option<i64> = match body.get("tenant_id") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_i64() {
            Some(n) if n > 0 => Some(n),
            _ => return err(StatusCode::BAD_REQUEST, "bad_tenant_id", "tenant_id must be a positive integer"),
        },
    };
    let tenant_role: Option<String> = match body.get("tenant_role").and_then(|v| v.as_str()) {
        None => None,
        Some(s) if valid_tenant_role(s) => Some(s.to_string()),
        Some(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_tenant_role",
                "tenant_role must be tenant_admin|tenant_operator|tenant_viewer",
            )
        }
    };
    if tenant_role.is_some() && tenant_id.is_none() {
        return err(StatusCode::BAD_REQUEST, "tenant_role_without_id", "tenant_role requires a tenant_id");
    }
    {
        let store = app.store();
        ensure_schema(&store);
        if let Err(e) = store.execute(
            "INSERT INTO rbac_group_map(idp_group,role,tenant_id,tenant_role,created)
             VALUES(?,?,?,?,?)
             ON CONFLICT(idp_group) DO UPDATE SET role=excluded.role, tenant_id=excluded.tenant_id, tenant_role=excluded.tenant_role",
            &crate::sql_params![
                group.clone(),
                role.clone(),
                tenant_id,
                tenant_role.clone(),
                crate::now_epoch()
            ],
        ) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed", e.to_string());
        }
    }
    crate::append_console_ledger(
        &app,
        "console.rbac.map.set",
        json!({
            "actor": crate::attribution_login(&app, &headers),
            "group": group,
            "role": role,
            "tenant_id": tenant_id,
            "tenant_role": tenant_role,
        }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "mappings": list_mappings(&app) }))).into_response()
}

/// DELETE /api/rbac/group-map/:group — remove a mapping (admin-only). Ledgered `console.rbac.map.delete`.
async fn map_delete(State(app): State<App>, headers: HeaderMap, Path(group): Path<String>) -> Response {
    if !enabled(&app) {
        return disabled();
    }
    if !crate::check_admin(&app, &headers) {
        return err(StatusCode::FORBIDDEN, "admin_required", "advanced-RBAC config is admin-only");
    }
    let removed = {
        let store = app.store();
        ensure_schema(&store);
        store
            .execute("DELETE FROM rbac_group_map WHERE idp_group=?", &crate::sql_params![group.clone()])
            .unwrap_or(0)
    };
    if removed == 0 {
        return err(StatusCode::NOT_FOUND, "not_found", "no mapping for that group");
    }
    crate::append_console_ledger(
        &app,
        "console.rbac.map.delete",
        json!({ "actor": crate::attribution_login(&app, &headers), "group": group }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "mappings": list_mappings(&app) }))).into_response()
}

/// Every mapping as a JSON array (admin view). Never carries a secret.
fn list_mappings(app: &App) -> Vec<Value> {
    let store = app.store();
    ensure_schema(&store);
    // LENIENT read (pre-seam: `filter_map(|x| x.ok()).collect()`): a per-row error skips that row and
    // returns the rest; `unwrap_or_default()` only swallows a prepare/bind `Err` to `[]`, exactly as
    // the pre-seam `if let Ok(stmt)/if let Ok(rows)` guards did. (NOT `query()`, which would collapse
    // the whole list to `[]` on the FIRST bad row.)
    store
        .query_lax(
            "SELECT idp_group, role, tenant_id, tenant_role FROM rbac_group_map ORDER BY idp_group",
            &[],
            |r| {
                Ok(json!({
                    "group": r.get_str(0)?,
                    "role": r.get_str(1)?,
                    "tenant_id": r.get_opt_i64(2)?,
                    "tenant_role": r.get_opt_str(3)?,
                }))
            },
        )
        .unwrap_or_default()
}

// ============================================================================================
// RESOLUTION (pure over the mapping table) — group names -> least-privilege authorization outcome.
// ============================================================================================

/// The authorization outcome a set of IdP groups confers. `role: None` => NO matching group =>
/// least privilege (the caller keeps its own default). NEVER carries a super-admin capability.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Resolved {
    /// Highest console role among matching groups (viewer|operator|admin), or None if none matched.
    pub role: Option<String>,
    /// Scoped tenant grants (tenant_id, tenant_role) — deduped per tenant, highest tenant role wins.
    pub tenant_grants: Vec<(i64, String)>,
}

/// Resolve a set of IdP group names to a least-privilege outcome over the configured mapping. Reads
/// the table only (creates it lazily). Fail-closed: unknown/empty groups contribute nothing; the
/// result is capped at `admin` and can NEVER be super-admin (not representable in the table).
pub(crate) fn resolve(app: &App, groups: &[String]) -> Resolved {
    if groups.is_empty() {
        return Resolved::default();
    }
    let store = app.store();
    ensure_schema(&store);
    let mut role: Option<String> = None;
    let mut grants: HashMap<i64, String> = HashMap::new();
    for g in groups {
        let g = g.trim();
        if g.is_empty() {
            continue;
        }
        let row = store.query_row(
            "SELECT role, tenant_id, tenant_role FROM rbac_group_map WHERE idp_group=?",
            &crate::sql_params![g],
            |r| Ok((r.get_str(0)?, r.get_opt_i64(1)?, r.get_opt_str(2)?)),
        );
        let (r, tid, trole) = match row {
            Ok(v) => v,
            Err(_) => continue, // no mapping for this group => contributes nothing (least privilege)
        };
        // Console role: only accept a VALID role (defence in depth vs. a hand-edited DB); highest wins.
        if crate::validate_role(&r).is_ok() {
            role = Some(match role {
                Some(cur) if crate::role_rank(&cur) >= crate::role_rank(&r) => cur,
                _ => r.clone(),
            });
        }
        // Optional tenant grant.
        if let Some(tid) = tid {
            let tr = trole
                .filter(|s| valid_tenant_role(s))
                .unwrap_or_else(|| derive_tenant_role(&r));
            let keep = match grants.get(&tid) {
                Some(cur) if tenant_rank(cur) >= tenant_rank(&tr) => cur.clone(),
                _ => tr,
            };
            grants.insert(tid, keep);
        }
    }
    drop(store); // release DB lock after the read loop; only in-memory aggregation remains
    let mut tenant_grants: Vec<(i64, String)> = grants.into_iter().collect();
    tenant_grants.sort_by_key(|(t, _)| *t);
    Resolved { role, tenant_grants }
}

/// Apply a resolved outcome to a Forge user (bounded, fail-closed). Sets the console role (clamped to
/// `operator` when `cap_operator` — the SCIM stance) and lands the scoped tenant grants when E1
/// tenancy is engaged. NEVER touches a DESIGNATED super-admin login. Ledgers `console.rbac.apply`
/// (metadata only) when something actually changed. Returns the applied role, if any.
// ALLOW significant_drop_tightening: the block holds ONE store lock across the role UPDATE + the loop of
// tenant_grant upserts so the whole RBAC application lands as a single atomic DB section; clippy would drop
// the guard inside the loop (uncompilable) or between writes, splitting the atomic apply. Hold is required.
#[allow(clippy::significant_drop_tightening)]
pub(crate) fn apply_to_user(
    app: &App,
    user_id: i64,
    login: &str,
    resolved: &Resolved,
    cap_operator: bool,
) -> Option<String> {
    // FAIL-CLOSED FLOOR: a provisioning-designated super-admin is never re-roled/re-granted by SSO/SCIM.
    if crate::tenancy::is_superadmin_login(app, login) {
        return None;
    }
    let tenancy_on = crate::tenancy::enabled(app);
    let mut applied_role: Option<String> = None;
    let mut n_grants = 0usize;
    {
        let store = app.store();
        // FAIL-CLOSED (attestation honnête) : ce n'est PAS un handler HTTP (pas de statut à renvoyer) mais il
        // ledgerise `console.rbac.apply`. On n'ATTESTE une mutation (applied_role / n_grants -> ledger) QUE si
        // l'écriture a réellement réussi : un échec silencieux ne doit jamais faire ledgeriser un re-role /
        // grant jamais appliqué (divergence ledger↔DB). Fail-safe : un échec transitoire laisse le rôle/grant
        // courant (le login SSO/SCIM continue), simplement NON attesté (rien de faux dans la piste).
        if let Some(r) = &resolved.role {
            let role = clamp_role(r, cap_operator);
            if store.execute(
                "UPDATE users SET role=? WHERE id=?",
                &crate::sql_params![role.clone(), user_id],
            ).is_ok() {
                applied_role = Some(role);
            }
        }
        if tenancy_on {
            for (tid, trole) in &resolved.tenant_grants {
                let trole = clamp_tenant_role(trole, cap_operator);
                if store.execute(
                    "INSERT INTO tenant_grant(user_id,tenant_id,role,created)
                     VALUES(?,?,?,datetime('now'))
                     ON CONFLICT(user_id,tenant_id) DO UPDATE SET role=excluded.role",
                    &crate::sql_params![user_id, *tid, trole],
                ).is_ok() {
                    n_grants += 1;
                }
            }
        }
    }
    if applied_role.is_some() || n_grants > 0 {
        crate::append_console_ledger(
            app,
            "console.rbac.apply",
            json!({
                "login": login,
                "role": applied_role,
                "tenant_grants": n_grants,
                "capped": cap_operator,
            }),
        );
    }
    applied_role
}

// ============================================================================================
// SMALL PURE HELPERS
// ============================================================================================

/// Clamp a console role to at most `operator` when `cap` is set (SCIM never auto-confers admin).
fn clamp_role(role: &str, cap: bool) -> String {
    if cap && role == "admin" {
        "operator".to_string()
    } else {
        role.to_string()
    }
}

/// Clamp a tenant role to at most `tenant_operator` when `cap` is set (parity with `clamp_role`).
fn clamp_tenant_role(role: &str, cap: bool) -> String {
    if cap && role == "tenant_admin" {
        "tenant_operator".to_string()
    } else {
        role.to_string()
    }
}

/// A valid tenant-grant role (mirrors tenancy::valid_tenant_role; that fn is private to tenancy.rs).
fn valid_tenant_role(r: &str) -> bool {
    matches!(r, "tenant_admin" | "tenant_operator" | "tenant_viewer")
}

/// Default tenant role for a console role when the mapping omits `tenant_role` (viewer->tenant_viewer,
/// operator->tenant_operator, admin->tenant_admin). Fail-closed to tenant_viewer for anything unknown.
fn derive_tenant_role(console_role: &str) -> String {
    match console_role {
        "admin" => "tenant_admin",
        "operator" => "tenant_operator",
        _ => "tenant_viewer",
    }
    .to_string()
}

/// Privilege rank of a tenant role (tenant_viewer < tenant_operator < tenant_admin). Unknown -> 0.
fn tenant_rank(r: &str) -> i32 {
    match r {
        "tenant_admin" => 3,
        "tenant_operator" => 2,
        "tenant_viewer" => 1,
        _ => 0,
    }
}

/// Extract the OIDC `groups` claim as a list of strings. Accepts an array of strings (the common
/// case) or a single string; anything else yields an empty list (fail-closed => least privilege).
pub(crate) fn groups_from_claims(claims: &Value) -> Vec<String> {
    match claims.get("groups") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// The console role SCIM should assign for a group's `displayName`, consulting the CONFIGURABLE mapping
/// first (clamped to viewer|operator — SCIM never auto-confers admin) and falling back to `fallback`
/// (the legacy best-effort heuristic) when no mapping matches. Keeps SCIM behaviour byte-identical when
/// no advanced mapping is configured.
pub(crate) fn scim_role_for_group(app: &App, display: &str, fallback: &str) -> String {
    match resolve(app, std::slice::from_ref(&display.to_string())).role {
        Some(r) => clamp_role(&r, true),
        None => fallback.to_string(),
    }
}

/// The scoped tenant grants SCIM should land for a group's `displayName` (clamped to
/// tenant_operator). Empty => the caller keeps its existing default (a scoped grant on tenant #1).
pub(crate) fn scim_tenant_grants_for_group(app: &App, display: &str) -> Vec<(i64, String)> {
    resolve(app, std::slice::from_ref(&display.to_string()))
        .tenant_grants
        .into_iter()
        .map(|(t, r)| (t, clamp_tenant_role(&r, true)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    /// Cross-platform temp path (no hardcoded /tmp — portability guard).
    fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        p.to_string_lossy().into_owned()
    }

    /// App backed by an in-memory DB (mirrors sso.rs's `sso_test_app`; the crate helper is in a sibling
    /// module not reachable here). Fields are crate-private but visible to this descendant module.
    fn rbac_test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        let (events, _) = broadcast::channel::<crate::RunEvent>(64);
        App {
            db: Arc::new(Mutex::new(conn)),
            #[cfg(feature = "store-postgres")]
            pg: None,
            #[cfg(feature = "store-postgres")]
            ha: false,
            #[cfg(feature = "store-postgres")]
            instance_id: Arc::new("test-instance".into()),
            #[cfg(feature = "store-postgres")]
            is_leader: Arc::new(AtomicBool::new(true)),
            db_path: Arc::new(":memory:".into()),
            token_sha: Arc::new(crate::sha_hex("t")),
            token_raw: Arc::new("t".into()),
            user: Arc::new("forge".into()),
            pass_hash: Arc::new(String::new()),
            auth_required: Arc::new(AtomicBool::new(false)),
            operator_hash: Arc::new(String::new()),
            allowed_hosts: Arc::new(vec!["localhost".into()]),
            ledger_path: Arc::new(ledger_path.to_string()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(crate::RunState { current: HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(crate::LedgerHead::default())),
        }
    }

    /// Turn advanced RBAC ON by engaging the SCIM flag (per-DB, test-isolated — no env).
    fn enable(app: &App) {
        let db = app.db();
        crate::settings_set(&db, "enterprise.scim", "on").unwrap();
    }

    fn add_user(app: &App, login: &str, role: &str) -> i64 {
        let db = app.db();
        db.execute(
            "INSERT INTO users(login,role,pass_hash,disabled,created) VALUES(?,?,'x',0,datetime('now'))",
            rusqlite::params![login, role],
        )
        .unwrap();
        db.last_insert_rowid()
    }

    fn set_map(app: &App, group: &str, role: &str, tenant: Option<i64>, trole: Option<&str>) {
        let store = app.store();
        ensure_schema(&store);
        store.execute(
            "INSERT INTO rbac_group_map(idp_group,role,tenant_id,tenant_role,created) VALUES(?,?,?,?,0)
             ON CONFLICT(idp_group) DO UPDATE SET role=excluded.role, tenant_id=excluded.tenant_id, tenant_role=excluded.tenant_role",
            &crate::sql_params![group, role, tenant, trole],
        )
        .unwrap();
    }

    #[test]
    fn unmapped_groups_confer_nothing() {
        let app = rbac_test_app(&tmp_path("rbac-none"));
        let r = resolve(&app, &["nope".into(), "unknown".into()]);
        assert_eq!(r.role, None, "no matching group => least privilege (role None)");
        assert!(r.tenant_grants.is_empty(), "no grants for unmapped groups");
    }

    #[test]
    fn empty_groups_confer_nothing() {
        let app = rbac_test_app(&tmp_path("rbac-empty"));
        set_map(&app, "eng", "admin", None, None);
        let r = resolve(&app, &[]);
        assert_eq!(r, Resolved::default(), "no groups claim => nothing (fail-closed)");
    }

    #[test]
    fn highest_role_wins_capped_at_admin() {
        let app = rbac_test_app(&tmp_path("rbac-high"));
        set_map(&app, "readers", "viewer", None, None);
        set_map(&app, "ops", "operator", None, None);
        set_map(&app, "admins", "admin", None, None);
        // viewer + operator => operator
        assert_eq!(resolve(&app, &["readers".into(), "ops".into()]).role.as_deref(), Some("operator"));
        // + admin => admin (the ceiling — there is no rank above admin)
        assert_eq!(
            resolve(&app, &["readers".into(), "ops".into(), "admins".into()]).role.as_deref(),
            Some("admin")
        );
    }

    #[test]
    fn super_admin_is_never_resolvable() {
        let app = rbac_test_app(&tmp_path("rbac-su"));
        // Even a hand-forged DB row with an out-of-band role value must NOT resolve to a role.
        set_map(&app, "evil", "super_admin", None, None);
        set_map(&app, "evil2", "root", None, None);
        let r = resolve(&app, &["evil".into(), "evil2".into()]);
        assert_eq!(r.role, None, "invalid/forged roles are rejected in resolve => None (never super-admin)");
    }

    #[test]
    fn tenant_grant_resolves_and_derives_role() {
        let app = rbac_test_app(&tmp_path("rbac-tg"));
        set_map(&app, "t7-ops", "operator", Some(7), None); // tenant_role omitted -> derived
        set_map(&app, "t7-adm", "admin", Some(7), Some("tenant_admin"));
        // Two groups on tenant 7: operator(derived tenant_operator) + tenant_admin => tenant_admin wins.
        let r = resolve(&app, &["t7-ops".into(), "t7-adm".into()]);
        assert_eq!(r.tenant_grants, vec![(7, "tenant_admin".to_string())]);
        // Single derived grant.
        let r2 = resolve(&app, &["t7-ops".into()]);
        assert_eq!(r2.tenant_grants, vec![(7, "tenant_operator".to_string())]);
    }

    #[test]
    fn apply_never_touches_super_admin_login() {
        let app = rbac_test_app(&tmp_path("rbac-apply-su"));
        // Designate "root" as super-admin (provisioning-only, per-DB, test-isolated).
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.superadmin", "root").unwrap();
        }
        let uid = add_user(&app, "root", "admin");
        let resolved = Resolved { role: Some("viewer".into()), tenant_grants: vec![] };
        let applied = apply_to_user(&app, uid, "root", &resolved, false);
        assert_eq!(applied, None, "super-admin login is never re-roled by SSO/SCIM");
        
        let role: String = app.db().query_row("SELECT role FROM users WHERE id=?", [uid], |r| r.get(0)).unwrap();
        assert_eq!(role, "admin", "super-admin role left intact (fail-closed floor)");
    }

    #[test]
    fn apply_sets_role_and_scim_caps_admin() {
        let app = rbac_test_app(&tmp_path("rbac-apply"));
        let uid = add_user(&app, "alice", "viewer");
        // SSO path (cap_operator=false): admin mapping is honored.
        apply_to_user(&app, uid, "alice", &Resolved { role: Some("admin".into()), tenant_grants: vec![] }, false);
        {
            
            let role: String = app.db().query_row("SELECT role FROM users WHERE id=?", [uid], |r| r.get(0)).unwrap();
            assert_eq!(role, "admin", "SSO honors an admin group mapping");
        }
        // SCIM path (cap_operator=true): admin is clamped to operator.
        let bob = add_user(&app, "bob", "viewer");
        apply_to_user(&app, bob, "bob", &Resolved { role: Some("admin".into()), tenant_grants: vec![] }, true);
        
        let role: String = app.db().query_row("SELECT role FROM users WHERE id=?", [bob], |r| r.get(0)).unwrap();
        assert_eq!(role, "operator", "SCIM clamps admin -> operator (never auto-confers console admin)");
    }

    #[test]
    fn scim_role_for_group_prefers_mapping_else_fallback() {
        let app = rbac_test_app(&tmp_path("rbac-scim-role"));
        set_map(&app, "Corp Operators", "operator", None, None);
        set_map(&app, "Corp Bosses", "admin", None, None); // clamps to operator for SCIM
        assert_eq!(scim_role_for_group(&app, "Corp Operators", "viewer"), "operator");
        assert_eq!(scim_role_for_group(&app, "Corp Bosses", "viewer"), "operator", "admin clamped for SCIM");
        assert_eq!(scim_role_for_group(&app, "Unmapped", "viewer"), "viewer", "falls back to heuristic role");
    }

    #[test]
    fn groups_claim_parsing() {
        assert_eq!(groups_from_claims(&json!({"groups":["a","b"]})), vec!["a".to_string(), "b".to_string()]);
        assert_eq!(groups_from_claims(&json!({"groups":"solo"})), vec!["solo".to_string()]);
        assert!(groups_from_claims(&json!({"groups":123})).is_empty());
        assert!(groups_from_claims(&json!({})).is_empty());
    }

    #[test]
    fn flag_off_means_disabled() {
        let app = rbac_test_app(&tmp_path("rbac-flag"));
        assert!(!enabled(&app), "community default: advanced RBAC OFF");
        enable(&app);
        assert!(enabled(&app), "engaging SCIM engages advanced RBAC");
    }

    // ------------------------------------------------------------------------------------------------
    // HTTP-level — flag OFF => /api/rbac/* absent (404) + whoami/setup-state show no enterprise identity;
    // flag ON => admin-gated CRUD, super_admin rejected. Uses the FULL router (crate::build_router).
    // ------------------------------------------------------------------------------------------------
    use std::net::SocketAddr;
    use std::time::Duration;

    async fn serve(app: App) -> SocketAddr {
        let router = crate::build_router(app, "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;
        addr
    }
    async fn http_raw(addr: SocketAddr, req: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        s.write_all(req.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.expect("read");
        String::from_utf8_lossy(&buf).into_owned()
    }
    fn get_req(path: &str, extra: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\r\n")
    }
    fn post_req(path: &str, body: &str, extra: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
    }
    fn del_req(path: &str, extra: &str) -> String {
        format!("DELETE {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\r\n")
    }
    fn parse_status(resp: &str) -> u16 {
        resp.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).unwrap_or(0)
    }
    fn body_of(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }
    fn cookie_token(resp: &str) -> Option<String> {
        let head = resp.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(resp);
        for line in head.lines() {
            if line.to_ascii_lowercase().starts_with("set-cookie:") {
                if let Some(i) = line.find("forge_session=") {
                    let rest = &line[i + "forge_session=".len()..];
                    let end = rest.find(';').unwrap_or(rest.len());
                    return Some(rest[..end].to_string());
                }
            }
        }
        None
    }
    /// Provision a local admin + open a session; return the forge_session cookie value.
    async fn admin_cookie(app: &App, addr: SocketAddr) -> String {
        {
            let hash = crate::hash_pw("pw");
            let db = app.db();
            crate::upsert_user(&db, "root", "admin", &hash).unwrap();
        }
        app.recompute_auth_required();
        let lr = http_raw(addr, &post_req("/api/login", "{\"login\":\"root\",\"password\":\"pw\"}", "")).await;
        cookie_token(&lr).expect("login cookie")
    }

    #[tokio::test]
    async fn flag_off_rbac_absent_and_no_enterprise_identity() {
        let ledger = tmp_path("rbac-off-ledger");
        let app = rbac_test_app(&ledger);
        // flag NOT engaged (community default).
        let addr = serve(app.clone()).await;
        let cookie = admin_cookie(&app, addr).await;
        let auth = format!("Cookie: forge_session={cookie}\r\n");
        // Every /api/rbac/* route behaves as ABSENT (404) even for an admin session.
        let r = http_raw(addr, &get_req("/api/rbac/group-map", &auth)).await;
        assert_eq!(parse_status(&r), 404, "flag off -> GET rbac disabled (404): {r}");
        let r = http_raw(addr, &post_req("/api/rbac/group-map", "{\"group\":\"g\",\"role\":\"admin\"}", &auth)).await;
        assert_eq!(parse_status(&r), 404, "flag off -> POST rbac disabled (404): {r}");
        let r = http_raw(addr, &del_req("/api/rbac/group-map/g", &auth)).await;
        assert_eq!(parse_status(&r), 404, "flag off -> DELETE rbac disabled (404): {r}");
        // whoami advertises NO enterprise identity; setup/state advertises NO SSO login button.
        let w = http_raw(addr, &get_req("/api/whoami", &auth)).await;
        assert!(body_of(&w).contains("\"rbac\":false"), "whoami: rbac false in community: {}", body_of(&w));
        assert!(body_of(&w).contains("\"sso\":false"), "whoami: sso false in community");
        let s = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert!(body_of(&s).contains("\"sso\":{\"enabled\":false}"), "setup/state: no SSO button: {}", body_of(&s));
        let _ = std::fs::remove_file(&ledger);
    }

    #[tokio::test]
    async fn flag_on_rbac_crud_admin_gated_and_rejects_super_admin() {
        let ledger = tmp_path("rbac-on-ledger");
        let app = rbac_test_app(&ledger);
        enable(&app); // engage advanced RBAC via the SCIM flag
        let addr = serve(app.clone()).await;

        // Without an admin session the config is admin-gated (403, NOT 404 — the flag IS on).
        let r = http_raw(addr, &get_req("/api/rbac/group-map", "")).await;
        assert_eq!(parse_status(&r), 403, "flag on, no admin -> 403 admin_required: {r}");

        let cookie = admin_cookie(&app, addr).await;
        let auth = format!("Cookie: forge_session={cookie}\r\n");

        // Admin can list (empty), then upsert a valid mapping.
        let r = http_raw(addr, &get_req("/api/rbac/group-map", &auth)).await;
        assert_eq!(parse_status(&r), 200, "admin list ok: {r}");
        assert!(body_of(&r).contains("\"mappings\":[]"), "empty initially: {}", body_of(&r));

        let r = http_raw(addr, &post_req("/api/rbac/group-map", "{\"group\":\"Ops\",\"role\":\"operator\"}", &auth)).await;
        assert_eq!(parse_status(&r), 200, "admin upsert ok: {r}");
        assert!(body_of(&r).contains("\"group\":\"Ops\""), "mapping stored: {}", body_of(&r));

        // A super_admin role is REJECTED (never storable) — the floor.
        let r = http_raw(addr, &post_req("/api/rbac/group-map", "{\"group\":\"Evil\",\"role\":\"super_admin\"}", &auth)).await;
        assert_eq!(parse_status(&r), 400, "super_admin rejected: {r}");
        assert!(body_of(&r).contains("bad_role"), "bad_role error: {}", body_of(&r));

        // Delete the mapping.
        let r = http_raw(addr, &del_req("/api/rbac/group-map/Ops", &auth)).await;
        assert_eq!(parse_status(&r), 200, "admin delete ok: {r}");
        let r = http_raw(addr, &get_req("/api/rbac/group-map", &auth)).await;
        assert!(body_of(&r).contains("\"mappings\":[]"), "empty after delete: {}", body_of(&r));

        // whoami now advertises the enterprise identity surface (rbac engaged via SCIM flag).
        let w = http_raw(addr, &get_req("/api/whoami", &auth)).await;
        assert!(body_of(&w).contains("\"rbac\":true"), "whoami: rbac true when engaged: {}", body_of(&w));
        let _ = std::fs::remove_file(&ledger);
    }
}

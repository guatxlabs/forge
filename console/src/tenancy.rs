//! ENTERPRISE — Row-level multi-tenancy (SEPARABLE, FLAG-GATED module).
//!
//! Open-core discipline: this module is an ENTERPRISE feature. The COMMUNITY (default) build behaves as
//! a SINGLE IMPLICIT TENANT (#1) with BYTE-IDENTICAL behavior — every function here is a NO-OP unless the
//! enterprise flag is engaged (`enabled()` false => community). It never weakens the open governance/audit
//! surface; it only ADDS a fail-closed tenant filter ON TOP of the existing engagement isolation + RBAC.
//!
//! MODEL (see main.rs SCHEMA):
//!   TENANT ──< ENGAGEMENT ──< findings / runs / roe / ledger        (data inherits tenant via engagement_id)
//!   tenant_grant(user_id, tenant_id, role)  =  which users may access which tenants.
//!
//! ENFORCEMENT (fail-closed, mirrors ROE deny-by-default): a caller may only see/act on engagements whose
//! `tenant_id` is in THEIR granted set. No grant to a tenant => ZERO rows / error (never another tenant's
//! data). A user of tenant A can NEVER see or act on tenant B's engagements/findings/runs/ledger.
//!
//! Community behaviour is preserved because `enabled()` is false by default: the callers in main.rs take
//! the historical code path unchanged, and the helpers below are simply not consulted.
//!
//! This module ALSO carries the ENTERPRISE platform surface bolted on top of the row filter (all still
//! flag-gated / fail-closed):
//!   - SUPER-ADMIN (§ super-admin): a NON-DISABLABLE, provisioning-designated capability that can READ
//!     across ALL tenants (platform/MSSP operator). Every cross-tenant read is AUDITED (`console.superadmin
//!     .access`). A normal tenant_admin can NEVER cross tenants. Mirrors Plume's non-disablable audited
//!     super-admin. Cross-tenant WRITE/run is NOT granted — engagement isolation for mutations is preserved.
//!   - TENANT CRUD + GRANTS (§ tenant admin): create / rename / archive tenants and list/add/remove a
//!     user's tenant_grant, gated to a PLATFORM-ADMIN (console admin or super-admin) and ledgered
//!     `console.tenant.*`. Fail-closed guards: never archive the last active tenant; never remove the last
//!     tenant_admin grant of a tenant.
//!   - PER-TENANT LEDGER (§ ledger): each tenant's engagement ledgers are grouped under a tenant-keyed
//!     subdirectory (`tenant-<tid>/engagement-<eid>.jsonl`), Ed25519 signing per-ledger UNCHANGED — just
//!     scoped per tenant. Cross-tenant ledger reads are impossible for a non-super-admin (the read resolves
//!     to NO_ENGAGEMENT).

use crate::App;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::{Path as FsPath, PathBuf};

/// Sentinel engagement id that matches NO row. In enterprise mode a read that resolves to a
/// not-granted / non-existent engagement yields THIS id, so every `... WHERE engagement_id={id}`
/// query returns ZERO rows (fail-closed) without any per-query change.
pub const NO_ENGAGEMENT: i64 = -1;

/// The single implicit tenant of the community edition (and the default of every existing row).
/// Exported vocabulary of the module (asserted by tests; consumable by enterprise callers); the runtime
/// seeding lives in main.rs::ensure_default_tenant (literal id 1 in SQL) — hence not yet read at runtime.
#[allow(dead_code)]
pub const DEFAULT_TENANT: i64 = 1;

/// Is enterprise row-level tenancy ENGAGED?  Community default = OFF (byte-identical single-tenant).
/// Two sources (either engages it): the deployment env flag `FORGE_ENTERPRISE_TENANCY` (truthy), or the
/// DB config key `enterprise.tenancy` (on|1|true|yes). Config is per-DB, so tests toggle it in isolation.
pub fn enabled(app: &App) -> bool {
    crate::flags::enterprise_enabled(app, "FORGE_ENTERPRISE_TENANCY", "enterprise.tenancy")
}

/// user_id of the caller's INDIVIDUAL session (non-expired, enabled account) — or None.
/// FAIL-CLOSED: the env-hash bootstrap identity and anonymous dev-open have NO tenant grants (enterprise
/// requires a provisioned individual account). Mirrors resolve_session_identity's account re-check.
fn caller_user_id(app: &App, headers: &HeaderMap) -> Option<i64> {
    let tok = crate::session_token_from_headers(headers);
    if tok.is_empty() {
        return None;
    }
    let token_sha = crate::sha_hex(&tok);
    let store = app.store();
    store
        .query_row(
            "SELECT u.id FROM session s JOIN users u ON u.id = s.user_id
          WHERE s.token_sha = ? AND u.disabled = 0 AND s.expires > ?",
            &crate::sql_params![token_sha, crate::now_epoch()],
            |r| r.get_i64(0),
        )
        .ok()
}

/// The SET of tenant_ids the caller is granted (their access universe). ENTERPRISE-only semantics.
/// FAIL-CLOSED: no individual session / no grant rows => EMPTY set (access to nothing).
pub fn granted_tenants(app: &App, headers: &HeaderMap) -> HashSet<i64> {
    let uid = match caller_user_id(app, headers) {
        Some(u) => u,
        None => return HashSet::new(),
    };
    let store = app.store();
    let mut set = HashSet::new();
    for t in store
        .query_lax("SELECT tenant_id FROM tenant_grant WHERE user_id = ?", &crate::sql_params![uid], |r| r.get_i64(0))
        .unwrap_or_default()
    {
        set.insert(t);
    }
    set
}

/// tenant_id owning engagement `eid` (data inherits tenant via engagement_id). None if the engagement
/// does not exist. Pure lookup.
fn tenant_of_engagement(app: &App, eid: i64) -> Option<i64> {
    let store = app.store();
    store.query_row("SELECT tenant_id FROM engagement WHERE id = ?", &crate::sql_params![eid], |r| r.get_i64(0)).ok()
}

/// Is engagement `eid` VISIBLE to the caller?  ── THE CENTRAL FAIL-CLOSED FILTER ──
/// Community (enabled=false) => always true (NO-OP, single implicit tenant). Enterprise => the engagement
/// must EXIST and its `tenant_id` must be in the caller's granted set; anything else (no grant, wrong
/// tenant, unknown engagement) => false. Weakening the membership test here makes an isolation test flip RED.
pub fn engagement_visible(app: &App, headers: &HeaderMap, eid: i64) -> bool {
    if !enabled(app) {
        return true; // community no-op — byte-identical single-tenant behaviour
    }
    let granted = granted_tenants(app, headers);
    if granted.is_empty() {
        return false; // no grant => access to nothing (deny-by-default)
    }
    match tenant_of_engagement(app, eid) {
        Some(tid) => granted.contains(&tid),
        None => false, // unknown engagement — never disclose
    }
}

/// SQL-safe CSV of the granted tenant ids (all i64 — safe to inline). Empty set => "-1" (a tenant id
/// no row has), so `tenant_id IN (-1)` matches nothing (fail-closed).
fn tenants_csv(granted: &HashSet<i64>) -> String {
    if granted.is_empty() {
        return NO_ENGAGEMENT.to_string();
    }
    let mut ids: Vec<i64> = granted.iter().copied().collect();
    ids.sort_unstable(); // deterministic SQL
    ids.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(",")
}

/// ENTERPRISE resolution of the engagement id for a VIEW/READ (fail-closed). Called ONLY when enabled().
///   - explicit `?engagement=<id>` not visible to the caller  => NO_ENGAGEMENT (zero rows) ;
///   - no explicit id => the most-recent ACTIVE engagement WITHIN the caller's granted tenants, else the
///     most-recent grantable engagement, else NO_ENGAGEMENT ;
///   - no grant at all => NO_ENGAGEMENT.
pub fn view_engagement_id(app: &App, headers: &HeaderMap, requested: Option<i64>) -> i64 {
    let native = granted_tenants(app, headers);
    // SUPER-ADMIN (platform/MSSP) may READ across ALL tenants; every cross-tenant read is AUDITED below.
    let sa = is_superadmin(app, headers);
    if native.is_empty() && !sa {
        return NO_ENGAGEMENT; // no grant and not super-admin => access to nothing (deny-by-default)
    }
    // Explicit target.
    if let Some(id) = requested {
        if engagement_in(app, id, &native) {
            return id; // caller's OWN tenant — no cross-tenant audit
        }
        if sa {
            // Cross-tenant read by the super-admin: the engagement must EXIST; audit tenant + what.
            if let Some(tid) = tenant_of_engagement(app, id) {
                audit_superadmin_read(app, headers, tid, &format!("view:engagement:{id}"));
                return id;
            }
        }
        return NO_ENGAGEMENT; // not granted / unknown — never disclose another tenant's data
    }
    // Default resolution — prefer the caller's OWN tenants (never audited: it is their own data).
    if !native.is_empty() {
        let csv = tenants_csv(&native);
        let own = {
            let store = app.store();
            store
                .query_row(
                    &format!("SELECT id FROM engagement WHERE status='active' AND tenant_id IN ({csv}) ORDER BY id DESC LIMIT 1"),
                    &[],
                    |r| r.get_i64(0),
                )
                .or_else(|_| {
                    store.query_row(
                        &format!("SELECT id FROM engagement WHERE tenant_id IN ({csv}) ORDER BY id DESC LIMIT 1"),
                        &[],
                        |r| r.get_i64(0),
                    )
                })
        };
        if let Ok(id) = own {
            return id;
        }
    }
    // SUPER-ADMIN with NO engagement in their own tenant(s): fall back across ALL tenants (AUDITED).
    if sa {
        let found = {
            let store = app.store();
            store
                .query_row(
                    "SELECT id, tenant_id FROM engagement WHERE status='active' ORDER BY id DESC LIMIT 1",
                    &[],
                    |r| Ok((r.get_i64(0)?, r.get_i64(1)?)),
                )
                .or_else(|_| {
                    store.query_row(
                        "SELECT id, tenant_id FROM engagement ORDER BY id DESC LIMIT 1",
                        &[],
                        |r| Ok((r.get_i64(0)?, r.get_i64(1)?)),
                    )
                })
        };
        if let Ok((id, tid)) = found {
            audit_superadmin_read(app, headers, tid, &format!("view:default:{id}"));
            return id;
        }
    }
    NO_ENGAGEMENT
}

/// ENTERPRISE resolution of the engagement id for a RUN (oldest-active default, matching the historical
/// resolve_engagement contract). Called ONLY when enabled(). Fail-closed: an explicit not-granted id =>
/// Err (indistinguishable from "unknown" — no existence leak); no grant => Err.
pub fn run_engagement_id(app: &App, headers: &HeaderMap, requested: Option<i64>) -> Result<i64, String> {
    let granted = granted_tenants(app, headers);
    if granted.is_empty() {
        return Err("aucun engagement accessible (aucun tenant accordé)".into());
    }
    if let Some(id) = requested {
        return if engagement_in(app, id, &granted) {
            Ok(id)
        } else {
            Err(format!("engagement {id} introuvable"))
        };
    }
    let csv = tenants_csv(&granted);
    let store = app.store();
    store
        .query_row(
            &format!("SELECT id FROM engagement WHERE status='active' AND tenant_id IN ({csv}) ORDER BY id LIMIT 1"),
            &[],
            |r| r.get_i64(0),
        )
        .or_else(|_| {
            store.query_row(
                &format!("SELECT id FROM engagement WHERE tenant_id IN ({csv}) ORDER BY id LIMIT 1"),
                &[],
                |r| r.get_i64(0),
            )
        })
        .map_err(|_| "aucun engagement accessible".to_string())
}

/// Membership test: does engagement `eid` belong to one of `granted`'s tenants?  (central filter helper)
fn engagement_in(app: &App, eid: i64, granted: &HashSet<i64>) -> bool {
    matches!(tenant_of_engagement(app, eid), Some(tid) if granted.contains(&tid))
}

/// ENTERPRISE SQL WHERE-fragment restricting an engagement listing to the caller's granted tenants.
/// Community => None (no filter, byte-identical listing). Enterprise => `Some("e.tenant_id IN (...)")`
/// (empty grant => `e.tenant_id IN (-1)` => zero rows). `alias` is the `engagement` table alias in the query.
pub fn list_filter_sql(app: &App, headers: &HeaderMap, alias: &str) -> Option<String> {
    if !enabled(app) {
        return None;
    }
    // SUPER-ADMIN (platform/MSSP) lists engagements ACROSS ALL tenants (no WHERE filter). The cross-tenant
    // visibility is AUDITED (`console.superadmin.access`) — but only when it actually reveals tenants
    // BEYOND the caller's own (no audit noise on a single-tenant / own-only view).
    if is_superadmin(app, headers) {
        audit_superadmin_list(app, headers);
        return None;
    }
    let granted = granted_tenants(app, headers);
    Some(format!("{alias}.tenant_id IN ({})", tenants_csv(&granted)))
}

/// ENTERPRISE resolution of the tenant a NEWLY-created engagement lands in (fail-closed): the caller can
/// only create WITHIN a tenant they are granted. `body.tenant_id` (if given) must be granted; otherwise,
/// if the caller has exactly one granted tenant it is used; ambiguous / none => Err. Called ONLY when enabled().
pub fn resolve_create_tenant(app: &App, headers: &HeaderMap, body: &Value) -> Result<i64, String> {
    let granted = granted_tenants(app, headers);
    if granted.is_empty() {
        return Err("aucun tenant accordé — création d'engagement refusée".into());
    }
    if let Some(t) = body.get("tenant_id").and_then(|v| v.as_i64()) {
        return if granted.contains(&t) {
            Ok(t)
        } else {
            Err(format!("tenant {t} non accordé"))
        };
    }
    if granted.len() == 1 {
        // len==1 invariant guarantees Some; ok_or_else removes the panic path without changing behaviour.
        let only = granted
            .iter()
            .next()
            .copied()
            .ok_or_else(|| "aucun tenant accordé — création d'engagement refusée".to_string())?;
        return Ok(only);
    }
    Err("tenant_id requis (plusieurs tenants accordés)".into())
}

// =====================================================================================
// § PER-ENGAGEMENT RBAC (readiness #14) — composable grants scoped to (user, tenant, engagement, role).
//
// TODAY (E1) the tenant_grant.role gates only VISIBILITY (granted_tenants) — a user with ANY grant on a
// tenant could run/mutate every engagement of that tenant (authz was the console-GLOBAL users.role). This
// adds a COMPOSABLE, MOST-SPECIFIC-WINS effective role PER ENGAGEMENT so a user can be OPERATOR on engagement
// A yet only VIEWER on engagement B:
//   1) an ENGAGEMENT-SPECIFIC grant (engagement_grant on (user, eid)) OVERRIDES everything ;
//   2) else the user's TENANT-WIDE grant (tenant_grant on (user, tenant_of(eid))) ;
//   3) else None => FAIL-CLOSED (no grant path => no effective role => operate/admin DENIED).
// Community (flag OFF) => the per-engagement gate is a NO-OP (callers keep the console-global authority,
// byte-identical). Enterprise (flag ON) => this effective role governs the engagement-scoped operator/admin
// actions (fail-closed). The super-admin / console-admin PLATFORM surface (E1) is unchanged: cross-tenant
// WRITE/run stays bound to native grants (a super-admin does NOT get operate on an un-granted engagement).
// =====================================================================================

/// Does an effective grant role allow engagement-scoped OPERATE (run / finding & engagement mutation)?
/// tenant_admin | tenant_operator. Pure.
pub(crate) fn role_allows_operate(role: &str) -> bool {
    matches!(role, "tenant_admin" | "tenant_operator")
}

/// Does an effective grant role allow engagement-scoped ADMIN (archive / delete / grant management)?
/// tenant_admin only. Pure.
pub(crate) fn role_allows_admin(role: &str) -> bool {
    role == "tenant_admin"
}

/// EFFECTIVE per-engagement role of the caller (MOST-SPECIFIC-WINS, fail-closed). See section header.
/// Requires a VALID INDIVIDUAL session (caller_user_id) — the env-hash bootstrap / anonymous have NO grants
/// (mirror of granted_tenants). None => no engagement-specific AND no tenant-wide grant => deny.
pub fn effective_engagement_role(app: &App, headers: &HeaderMap, eid: i64) -> Option<String> {
    let uid = caller_user_id(app, headers)?; // takes+releases the DB lock itself
    let tid = tenant_of_engagement(app, eid); // takes+releases the DB lock itself (Option)
    let store = app.store();
    // (1) ENGAGEMENT-SPECIFIC override — most specific, wins over the tenant-wide grant.
    if let Ok(role) = store.query_row(
        "SELECT role FROM engagement_grant WHERE user_id = ? AND engagement_id = ?",
        &crate::sql_params![uid, eid],
        |r| r.get_str(0),
    ) {
        return Some(role);
    }
    // (2) TENANT-WIDE grant fallback (existing behaviour). Unknown engagement (no tenant) => None.
    let tid = tid?;
    store
        .query_row(
            "SELECT role FROM tenant_grant WHERE user_id = ? AND tenant_id = ?",
            &crate::sql_params![uid, tid],
            |r| r.get_str(0),
        )
        .ok()
}

/// FAIL-CLOSED per-engagement OPERATE capability (ENTERPRISE). No effective role => false. Consulted by the
/// engagement-scoped mutation handlers when `enabled()` (community never calls it — global role governs).
pub fn can_operate_engagement(app: &App, headers: &HeaderMap, eid: i64) -> bool {
    matches!(effective_engagement_role(app, headers, eid), Some(r) if role_allows_operate(&r))
}

/// FAIL-CLOSED per-engagement ADMIN capability (ENTERPRISE). No effective role or non-admin role => false.
/// Purely grant-based (no super-admin cross-tenant WRITE bypass — E1 invariant: super-admin READS only).
pub fn can_admin_engagement(app: &App, headers: &HeaderMap, eid: i64) -> bool {
    matches!(effective_engagement_role(app, headers, eid), Some(r) if role_allows_admin(&r))
}

// =====================================================================================
// § SUPER-ADMIN — non-disablable, provisioning-designated, audited cross-tenant READ.
//
// The platform/MSSP operator needs to READ across ALL tenants. That capability is:
//   (a) DESIGNATED ONLY AT PROVISIONING — env `FORGE_SUPERADMIN` and/or the per-DB provisioning key
//       `enterprise.superadmin` (both comma/space separated logins). NEITHER is writable through the
//       normal admin/tenant UI (there is no settings-write API for arbitrary keys), so it cannot be
//       turned on from inside the product — mirror of Plume's out-of-band super-admin marker.
//   (b) NON-DISABLABLE — a designated super-admin account cannot be disabled / deleted / downgraded
//       through the account CRUD (guard_superadmin_user_mutation, wired into main.rs). Fail-closed.
//   (c) AUDITED — every cross-tenant read emits `console.superadmin.access` (tenant + what).
//   (d) FAIL-CLOSED — no designation => NOBODY is super-admin. It grants cross-tenant READ ONLY; it never
//       relaxes cross-tenant WRITE/run (those stay bound to native grants — engagement isolation intact).
// A normal tenant_admin (a grant-level role) is NOT a super-admin and can never cross tenants.
// =====================================================================================

/// Parse a provisioning list of super-admin logins (comma / whitespace separated). Malformed tokens are
/// dropped (validate_login). EMPTY => empty set (fail-closed: nobody designated).
fn parse_logins(s: &str) -> HashSet<String> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .filter_map(|t| crate::validate_login(t).ok())
        .collect()
}

/// The SET of logins DESIGNATED super-admin — union of the two PROVISIONING-ONLY sources: env
/// `FORGE_SUPERADMIN` and the per-DB key `enterprise.superadmin`. Neither is mutable through a normal UI
/// route. Fail-closed: no source => empty set.
fn superadmin_logins(app: &App) -> HashSet<String> {
    let mut set = parse_logins(&std::env::var("FORGE_SUPERADMIN").unwrap_or_default());
    let db_val = {
        let store = app.store();
        crate::settings_get_store(&store, "enterprise.superadmin")
    };
    if let Some(v) = db_val {
        set.extend(parse_logins(&v));
    }
    set
}

/// Is `login` a DESIGNATED super-admin? (membership in the provisioning-only set). Drives both the
/// caller's capability and the NON-DISABLABLE account guard.
pub fn is_superadmin_login(app: &App, login: &str) -> bool {
    superadmin_logins(app).contains(login)
}

/// Is the CALLER a super-admin? FAIL-CLOSED (mirror of check_admin, stricter):
///   - requires a VALID INDIVIDUAL admin session (role=admin) whose login is DESIGNATED — never the
///     shared bootstrap env-hash, never anonymous dev-open;
///   - no designation at all => false (nobody is super-admin).
///
/// Grants cross-tenant READ (audited). Does NOT grant cross-tenant WRITE/run.
pub fn is_superadmin(app: &App, headers: &HeaderMap) -> bool {
    let designated = superadmin_logins(app);
    if designated.is_empty() {
        return false;
    }
    match crate::resolve_session_identity(app, headers) {
        Some(id) => id.role == "admin" && designated.contains(&id.login),
        None => false,
    }
}

/// NON-DISABLABLE super-admin guard (fail-closed marker). A DESIGNATED super-admin login cannot be
/// disabled, deleted, or downgraded below `admin` through account CRUD — the designation lives in
/// provisioning config, but the ACCOUNT that exercises it must remain a functioning admin. Called from
/// main.rs admin_update_user / admin_delete_user BEFORE any mutation. A non-super-admin login => Ok (no-op:
/// normal CRUD rules, incl. the last-admin guard, still apply). Not gated on `enabled()`: the marker holds
/// in community too (a provisioned super-admin never silently disappears).
pub fn guard_superadmin_user_mutation(
    app: &App,
    target_login: &str,
    disabling: bool,
    new_role: Option<&str>,
    deleting: bool,
) -> Result<(), String> {
    if !is_superadmin_login(app, target_login) {
        return Ok(());
    }
    if deleting {
        return Err("super-admin non supprimable (fail-closed — désigné au provisioning)".into());
    }
    if disabling {
        return Err("super-admin non désactivable (fail-closed)".into());
    }
    if let Some(r) = new_role {
        if r != "admin" {
            return Err("super-admin ne peut être rétrogradé sous le rôle admin (fail-closed)".into());
        }
    }
    Ok(())
}

/// All tenant ids currently present (for computing what a super-admin list reveals beyond native tenants).
fn all_tenant_ids(app: &App) -> HashSet<i64> {
    let store = app.store();
    let mut set = HashSet::new();
    for t in store.query_lax("SELECT id FROM tenant", &[], |r| r.get_i64(0)).unwrap_or_default() {
        set.insert(t);
    }
    set
}

/// AUDIT one cross-tenant READ by the super-admin into the CONSOLE ledger (platform audit trail):
/// `console.superadmin.access` {actor, tenant, what}. The console ledger keeps its own tamper-evident
/// SHA-256 chain; a tenant's dedicated ledger is left untouched (the access is the PLATFORM operator's act).
fn audit_superadmin_read(app: &App, headers: &HeaderMap, tenant_id: i64, what: &str) {
    let actor = crate::attribution_login(app, headers);
    crate::append_console_ledger(
        app,
        "console.superadmin.access",
        json!({ "actor": actor, "tenant": tenant_id, "what": what }),
    );
}

/// AUDIT a cross-tenant LIST by the super-admin — but ONLY when it reveals tenants BEYOND the caller's
/// own (otherwise there is no cross-tenant disclosure to record, and we avoid audit noise).
fn audit_superadmin_list(app: &App, headers: &HeaderMap) {
    let native = granted_tenants(app, headers);
    let all = all_tenant_ids(app);
    let mut cross: Vec<i64> = all.difference(&native).copied().collect();
    cross.sort_unstable();
    if cross.is_empty() {
        return;
    }
    let actor = crate::attribution_login(app, headers);
    crate::append_console_ledger(
        app,
        "console.superadmin.access",
        json!({ "actor": actor, "tenant": "all", "cross_tenants": cross, "what": "list:engagements" }),
    );
}

// =====================================================================================
// § PER-TENANT LEDGER — group each tenant's engagement ledgers under a tenant-keyed subdirectory.
// =====================================================================================

/// PER-TENANT ledger path (ENTERPRISE). Groups a tenant's engagement ledgers under a tenant-keyed
/// SUBDIRECTORY `tenant-<tid>/engagement-<eid>.jsonl`, SIBLING to the console ledger. The Ed25519 signing
/// key stays PER-LEDGER (its `.ed25519` sidecar travels with the file) — crypto UNCHANGED, just scoped per
/// tenant. Community (flag OFF) => None: the caller keeps its historical FLAT `engagement-<eid>.jsonl`
/// (byte-identical single-tenant behaviour). Cross-platform (PathBuf joins, no hardcoded separators).
pub fn scoped_engagement_ledger_path(
    app: &App,
    base_ledger: &str,
    engagement_id: i64,
    tenant_id: i64,
) -> Option<String> {
    if !enabled(app) {
        return None; // community — caller uses the flat path (byte-identical)
    }
    let rel = PathBuf::from(format!("tenant-{tenant_id}")).join(format!("engagement-{engagement_id}.jsonl"));
    // Place the tenant subtree NEXT TO the console ledger (same parent dir). Empty / parent-less base =>
    // a relative tenant-scoped path.
    let joined = match FsPath::new(base_ledger).parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(&rel),
        None => rel,
    };
    Some(joined.to_string_lossy().into_owned())
}

// =====================================================================================
// § TENANT ADMIN — CRUD (create/rename/archive) + grant management, PLATFORM-ADMIN gated, ledgered.
//
// Gate = PLATFORM-ADMIN (a console `admin` session OR a super-admin) AND enterprise engaged. A grant-level
// tenant_admin/operator/viewer that is NOT a console admin can NEVER administer tenants (fail-closed 403 —
// a tenant_admin of A gets 403 on B). Each mutation is attributed + ledgered `console.tenant.*`. Fail-closed
// guards: never archive the LAST active tenant; never remove the LAST tenant_admin grant of a tenant.
// =====================================================================================

/// Sub-router — MERGED into build_router's protected router (inherits auth_guard/host_guard). The static
/// `/grants` segment and the `:id` / `:login` params do not collide (matchit). `/api/tenancy` (the SPA
/// context probe) is a DISTINCT path — no `:id` overlap.
pub(crate) fn routes() -> Router<App> {
    Router::new()
        // SPA context — readable by ANY authenticated caller (NOT platform-admin gated). Drives whether
        // the tenant UI renders at all + which tenants the caller may switch between. See tenancy_context.
        .route("/api/tenancy", get(tenancy_context))
        .route("/api/tenants", get(tenants_list).post(tenants_create))
        .route("/api/tenants/:id", post(tenants_update))
        .route("/api/tenants/:id/grants", get(tenant_grants_list).post(tenant_grant_add))
        .route("/api/tenants/:id/grants/:login", delete(tenant_grant_remove))
        // PER-ENGAGEMENT RBAC (readiness #14) — engagement-specific grant management (platform-admin). The
        // `:id` param name matches the sibling `/api/engagements/:id` (main router) / `/api/engagements/:id/
        // report` (reports router) — matchit requires the SAME param name at that position (it is `:id`).
        .route("/api/engagements/:id/grants", get(engagement_grants_list).post(engagement_grant_add))
        .route("/api/engagements/:id/grants/:login", delete(engagement_grant_remove))
}

/// GET /api/tenancy — the caller's tenant CONTEXT for the SPA (ANY authenticated caller; not gated to
/// platform-admin). This is what makes the tenant UI FLAG-GATED end-to-end:
///   - COMMUNITY (flag OFF)  => `{"enabled": false}` ONLY. The SPA renders NO tenant selector, NO
///     `#tenants` admin view, NO nav link — byte-identical single-tenant shell.
///   - ENTERPRISE (flag ON)  => `{enabled:true, is_superadmin, is_platform_admin, tenants:[{id,name,
///     status}]}` where `tenants` is the caller's ACCESSIBLE set (a SUPER-ADMIN sees ALL tenants; anyone
///     else only the tenants in their granted set). The SPA shows the tenant selector above the engagement
///     selector (tenant → engagement hierarchy) and, for a platform-admin, the `#tenants` admin view.
///
/// FAIL-CLOSED: the accessible list never contains a tenant the caller cannot access; an anonymous /
/// grant-less caller gets an EMPTY list (nothing to switch to). Read-only; no mutation, no audit
/// (listing your OWN accessible tenants is not a cross-tenant disclosure — see audit_superadmin_list for
/// the engagement listing that IS audited).
pub(crate) async fn tenancy_context(State(app): State<App>, headers: HeaderMap) -> Response {
    if !enabled(&app) {
        // Community: the ONLY signal the SPA needs — no tenant surface at all.
        return (StatusCode::OK, Json(json!({ "enabled": false }))).into_response();
    }
    // Resolve capabilities + accessible-tenant scope BEFORE locking the DB (each of these helpers takes
    // and releases the DB mutex itself — never call them while holding `app.db()`).
    let sa = is_superadmin(&app, &headers);
    let pa = platform_admin_ok(&app, &headers);
    // super-admin => ALL tenants ; otherwise the caller's granted set (empty => no rows, fail-closed).
    let granted: Option<HashSet<i64>> = if sa { None } else { Some(granted_tenants(&app, &headers)) };
    let tenants = accessible_tenants(&app, &granted);
    (
        StatusCode::OK,
        Json(json!({
            "enabled": true,
            "is_superadmin": sa,
            "is_platform_admin": pa,
            "tenants": tenants,
        })),
    )
        .into_response()
}

/// The tenants the caller may SEE in the SPA selector. `granted == None` => super-admin => ALL tenants;
/// `Some(set)` => exactly the granted tenants (empty set => `id IN (-1)` => zero rows, fail-closed). Pure
/// read; ids are i64 (safe to inline in SQL). Ordered by id for a deterministic selector.
fn accessible_tenants(app: &App, granted: &Option<HashSet<i64>>) -> Vec<Value> {
    let store = app.store();
    let sql = match granted {
        None => "SELECT id, name, status FROM tenant ORDER BY id".to_string(),
        Some(set) => format!(
            "SELECT id, name, status FROM tenant WHERE id IN ({}) ORDER BY id",
            tenants_csv(set)
        ),
    };
    store
        .query_lax(&sql, &[], |r| {
            Ok(json!({
                "id": r.get_i64(0)?,
                "name": r.get_str(1)?,
                "status": r.get_opt_str(2)?.unwrap_or_else(|| "active".into()),
            }))
        })
        .unwrap_or_default()
}

/// A platform-admin: a console `admin` session (check_admin) OR a super-admin. FAIL-CLOSED.
fn platform_admin_ok(app: &App, headers: &HeaderMap) -> bool {
    crate::check_admin(app, headers) || is_superadmin(app, headers)
}

/// Well-formed tenant name: 1..80 printable chars (letters/digits/space + `. _ - / ( ) #`), not empty,
/// no leading `-`. Mirrors valid_engagement_name. Pure.
fn valid_tenant_name(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.chars().count() <= 80
        && !t.starts_with('-')
        && t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-' | '/' | '(' | ')' | '#'))
}

/// Valid tenant-grant role (applicative constraint). None (fail-closed) for anything else.
fn valid_tenant_role(r: &str) -> Option<&'static str> {
    match r {
        "tenant_admin" => Some("tenant_admin"),
        "tenant_operator" => Some("tenant_operator"),
        "tenant_viewer" => Some("tenant_viewer"),
        _ => None,
    }
}

fn err(status: StatusCode, code: &'static str, why: impl Into<String>) -> Response {
    crate::error::ApiError::new(status, code, why).into_response()
}

/// Common gate for every tenant-admin route: enterprise engaged + platform-admin. Returns the error
/// Response to short-circuit with, or None to proceed. Fail-closed.
fn gate(app: &App, headers: &HeaderMap) -> Option<Response> {
    if !enabled(app) {
        return Some(err(
            StatusCode::FORBIDDEN,
            "enterprise_disabled",
            "multi-tenancy enterprise non activée (FORGE_ENTERPRISE_TENANCY / enterprise.tenancy)",
        ));
    }
    if !platform_admin_ok(app, headers) {
        return Some(err(
            StatusCode::FORBIDDEN,
            "platform_admin_required",
            "administration des tenants réservée à un admin plateforme (session admin ou super-admin)",
        ));
    }
    None
}

/// GET /api/tenants — list tenants + counts (engagements / grants). Platform-admin.
pub(crate) async fn tenants_list(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let store = app.store();
    let rows: Vec<Value> = match store.query_lax(
        "SELECT t.id, t.name, t.status, t.created, t.updated,
                (SELECT COUNT(*) FROM engagement e WHERE e.tenant_id=t.id),
                (SELECT COUNT(*) FROM tenant_grant g WHERE g.tenant_id=t.id)
         FROM tenant t ORDER BY t.id",
        &[],
        |r| {
            Ok(json!({
                "id": r.get_i64(0)?,
                "name": r.get_str(1)?,
                "status": r.get_opt_str(2)?.unwrap_or_else(|| "active".into()),
                "created": r.get_opt_str(3)?.unwrap_or_default(),
                "updated": r.get_opt_str(4)?.unwrap_or_default(),
                "counts": {"engagements": r.get_i64(5)?, "grants": r.get_i64(6)?},
            }))
        },
    ) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db", e.to_string()),
    };
    (StatusCode::OK, Json(json!({ "tenants": rows }))).into_response()
}

/// POST /api/tenants {name} — create a tenant (platform-admin). Ledgered `console.tenant.create`. The
/// creating individual account is auto-granted tenant_admin so the new tenant always has ≥1 admin
/// (supports the last-admin protection).
pub(crate) async fn tenants_create(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !valid_tenant_name(&name) {
        return err(StatusCode::BAD_REQUEST, "bad_name", "nom de tenant invalide (1..80, pas de '-' en tête)");
    }
    let actor = crate::attribution_login(&app, &headers);
    let (id, self_grant): (i64, bool) = {
        let store = app.store();
        // execute_returning_id : id du tenant lu du MÊME INSERT (RETURNING id sur PG), sans lastval() —
        // session-indépendant, sûr sur backend poolé. Le SELECT users et l'INSERT tenant_grant viennent
        // APRÈS (id du tenant déjà capturé dans `id`).
        let id = match store.execute_returning_id(
            "INSERT INTO tenant(name,status,created,updated) VALUES(?,?,datetime('now'),datetime('now'))",
            &crate::sql_params![&name, "active"],
        ) {
            Ok(id) => id,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "create_failed", e.to_string()),
        };
        let uid: Option<i64> = store.query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![&actor], |r| r.get_i64(0)).ok();
        let mut sg = false;
        if let Some(u) = uid {
            let _ = store.execute(
                "INSERT INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,?,?,datetime('now'))",
                &crate::sql_params![u, id, "tenant_admin"],
            );
            sg = true;
        }
        (id, sg)
    };
    crate::append_console_ledger(
        &app,
        "console.tenant.create",
        json!({ "actor": actor, "tenant_id": id, "name": name, "self_grant_admin": self_grant }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "tenant": {"id": id, "name": name, "status": "active"} }))).into_response()
}

/// POST /api/tenants/:id {name?, status?} — rename and/or archive/activate (platform-admin). Ledgered
/// `console.tenant.rename|archive|activate`. FAIL-CLOSED: never archive the LAST active tenant.
pub(crate) async fn tenants_update(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let new_name: Option<String> = match body.get("name") {
        None => None,
        Some(n) => {
            let n = n.as_str().unwrap_or("").trim().to_string();
            if !valid_tenant_name(&n) {
                return err(StatusCode::BAD_REQUEST, "bad_name", "nom de tenant invalide (1..80, pas de '-' en tête)");
            }
            Some(n)
        }
    };
    let new_status: Option<String> = match body.get("status").and_then(|v| v.as_str()) {
        None => None,
        Some(s) if matches!(s, "active" | "archived") => Some(s.to_string()),
        Some(s) => return err(StatusCode::BAD_REQUEST, "bad_status", format!("status '{s}' invalide (active|archived)")),
    };
    if new_name.is_none() && new_status.is_none() {
        return err(StatusCode::BAD_REQUEST, "no_change", "aucun changement fourni (name|status)");
    }
    // existence + last-active guard + mutations under ONE db guard (atomic, anti-TOCTOU).
    let action: &str = {
        let store = app.store();
        let cur_status: String = match store.query_row("SELECT status FROM tenant WHERE id=?", &crate::sql_params![id], |r| r.get_str(0)) {
            Ok(s) => s,
            Err(_) => return err(StatusCode::NOT_FOUND, "unknown_tenant", format!("tenant {id} introuvable")),
        };
        let archiving = new_status.as_deref() == Some("archived") && cur_status == "active";
        if archiving {
            let active: i64 = store.query_row("SELECT COUNT(*) FROM tenant WHERE status='active'", &[], |r| r.get_i64(0)).unwrap_or(0);
            if active <= 1 {
                return err(StatusCode::CONFLICT, "last_active_tenant", "impossible : dernier tenant actif (archivage refusé, fail-closed)");
            }
        }
        if let Some(n) = &new_name {
            let _ = store.execute("UPDATE tenant SET name=?, updated=datetime('now') WHERE id=?", &crate::sql_params![n, id]);
        }
        if let Some(s) = &new_status {
            let _ = store.execute("UPDATE tenant SET status=?, updated=datetime('now') WHERE id=?", &crate::sql_params![s, id]);
        }
        if new_status.as_deref() == Some("archived") {
            "archive"
        } else if new_status.as_deref() == Some("active") && cur_status == "archived" {
            "activate"
        } else {
            "rename"
        }
    };
    crate::append_console_ledger(
        &app,
        &format!("console.tenant.{action}"),
        json!({ "actor": crate::attribution_login(&app, &headers), "tenant_id": id, "name": new_name, "status": new_status }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "tenant_id": id, "action": action }))).into_response()
}

/// GET /api/tenants/:id/grants — list a tenant's grants (login/role). Platform-admin.
pub(crate) async fn tenant_grants_list(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let store = app.store();
    if store.query_row("SELECT 1 FROM tenant WHERE id=?", &crate::sql_params![id], |_| Ok(())).is_err() {
        return err(StatusCode::NOT_FOUND, "unknown_tenant", format!("tenant {id} introuvable"));
    }
    let rows: Vec<Value> = match store.query_lax(
        "SELECT u.login, g.role, g.created FROM tenant_grant g JOIN users u ON u.id=g.user_id
          WHERE g.tenant_id=? ORDER BY u.login",
        &crate::sql_params![id],
        |r| {
            Ok(json!({
                "login": r.get_str(0)?,
                "role": r.get_str(1)?,
                "created": r.get_opt_str(2)?.unwrap_or_default(),
            }))
        },
    ) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db", e.to_string()),
    };
    (StatusCode::OK, Json(json!({ "tenant_id": id, "grants": rows }))).into_response()
}

/// POST /api/tenants/:id/grants {login, role} — grant (or re-role) a user on a tenant (platform-admin).
/// Ledgered `console.tenant.grant`. The user and tenant must exist (404 otherwise, fail-closed).
pub(crate) async fn tenant_grant_add(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let login = match crate::validate_login(body.get("login").and_then(|v| v.as_str()).unwrap_or("")) {
        Ok(l) => l,
        Err(e) => return err(StatusCode::BAD_REQUEST, "bad_login", e),
    };
    let role = match valid_tenant_role(body.get("role").and_then(|v| v.as_str()).unwrap_or("")) {
        Some(r) => r,
        None => return err(StatusCode::BAD_REQUEST, "bad_role", "rôle invalide (tenant_admin|tenant_operator|tenant_viewer)"),
    };
    let actor = crate::attribution_login(&app, &headers);
    {
        let store = app.store();
        if store.query_row("SELECT 1 FROM tenant WHERE id=?", &crate::sql_params![id], |_| Ok(())).is_err() {
            return err(StatusCode::NOT_FOUND, "unknown_tenant", format!("tenant {id} introuvable"));
        }
        let uid: i64 = match store.query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![&login], |r| r.get_i64(0)) {
            Ok(u) => u,
            Err(_) => return err(StatusCode::NOT_FOUND, "unknown_user", format!("compte '{login}' introuvable")),
        };
        // one grant per (user,tenant): UPDATE the role if it exists, else INSERT (two steps — unambiguous
        // vs the table-level ON CONFLICT IGNORE constraint).
        let updated = store
            .execute("UPDATE tenant_grant SET role=? WHERE user_id=? AND tenant_id=?", &crate::sql_params![role, uid, id])
            .unwrap_or(0);
        if updated == 0 {
            let _ = store.execute(
                "INSERT INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,?,?,datetime('now'))",
                &crate::sql_params![uid, id, role],
            );
        }
    }
    crate::append_console_ledger(
        &app,
        "console.tenant.grant",
        json!({ "actor": actor, "tenant_id": id, "login": login, "role": role }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "tenant_id": id, "login": login, "role": role }))).into_response()
}

/// DELETE /api/tenants/:id/grants/:login — revoke a user's grant on a tenant (platform-admin). Ledgered
/// `console.tenant.revoke`. FAIL-CLOSED: never remove the LAST tenant_admin grant of a tenant (its last admin).
pub(crate) async fn tenant_grant_remove(
    State(app): State<App>,
    headers: HeaderMap,
    Path((id, login)): Path<(i64, String)>,
) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let login = match crate::validate_login(&login) {
        Ok(l) => l,
        Err(e) => return err(StatusCode::BAD_REQUEST, "bad_login", e),
    };
    let actor = crate::attribution_login(&app, &headers);
    {
        let store = app.store();
        if store.query_row("SELECT 1 FROM tenant WHERE id=?", &crate::sql_params![id], |_| Ok(())).is_err() {
            return err(StatusCode::NOT_FOUND, "unknown_tenant", format!("tenant {id} introuvable"));
        }
        let uid: i64 = match store.query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![&login], |r| r.get_i64(0)) {
            Ok(u) => u,
            Err(_) => return err(StatusCode::NOT_FOUND, "unknown_user", format!("compte '{login}' introuvable")),
        };
        let cur_role: String = match store.query_row(
            "SELECT role FROM tenant_grant WHERE user_id=? AND tenant_id=?",
            &crate::sql_params![uid, id],
            |r| r.get_str(0),
        ) {
            Ok(r) => r,
            Err(_) => return err(StatusCode::NOT_FOUND, "no_grant", format!("aucun grant pour '{login}' sur le tenant {id}")),
        };
        if cur_role == "tenant_admin" {
            let admins: i64 = store
                .query_row("SELECT COUNT(*) FROM tenant_grant WHERE tenant_id=? AND role='tenant_admin'", &crate::sql_params![id], |r| r.get_i64(0))
                .unwrap_or(0);
            if admins <= 1 {
                return err(
                    StatusCode::CONFLICT,
                    "last_tenant_admin",
                    "impossible : dernier admin du tenant (retrait du grant refusé, fail-closed)",
                );
            }
        }
        let _ = store.execute("DELETE FROM tenant_grant WHERE user_id=? AND tenant_id=?", &crate::sql_params![uid, id]);
    }
    crate::append_console_ledger(
        &app,
        "console.tenant.revoke",
        json!({ "actor": actor, "tenant_id": id, "login": login }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "tenant_id": id, "revoked": login }))).into_response()
}

// =====================================================================================
// § PER-ENGAGEMENT GRANT ADMIN (readiness #14) — CRUD of engagement-specific role overrides, PLATFORM-ADMIN
// gated (same `gate()` as tenant grants) + ledgered `console.engagement.grant|revoke`. An engagement-specific
// grant OVERRIDES the tenant-wide grant for THAT engagement only (most-specific-wins, effective_engagement_role).
// Removing an engagement grant simply REVERTS the user to their tenant-wide role (no last-admin guard needed —
// the tenant still has its own last_tenant_admin protection on tenant_grant).
// =====================================================================================

/// tenant_id owning engagement `id`, or None if the engagement does not exist. Public existence probe for the
/// grant admin routes (fail-closed 404 on None).
fn engagement_tenant(app: &App, id: i64) -> Option<i64> {
    let store = app.store();
    store.query_row("SELECT tenant_id FROM engagement WHERE id=?", &crate::sql_params![id], |r| r.get_i64(0)).ok()
}

/// GET /api/engagements/:id/grants — the engagement-specific grants, the INHERITED tenant grants (of the
/// engagement's tenant), and the computed EFFECTIVE grant per user (engagement-specific wins). Platform-admin.
pub(crate) async fn engagement_grants_list(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let tid = match engagement_tenant(&app, id) {
        Some(t) => t,
        None => return err(StatusCode::NOT_FOUND, "unknown_engagement", format!("engagement {id} introuvable")),
    };
    let store = app.store();
    // Engagement-specific overrides (login -> role).
    let eng_grants: Vec<Value> = store
        .query_lax(
            "SELECT u.login, g.role, g.created FROM engagement_grant g JOIN users u ON u.id=g.user_id
              WHERE g.engagement_id=? ORDER BY u.login",
            &crate::sql_params![id],
            |r| Ok(json!({"login": r.get_str(0)?, "role": r.get_str(1)?, "created": r.get_opt_str(2)?.unwrap_or_default(), "scope": "engagement"})),
        )
        .unwrap_or_default();
    // Inherited tenant-wide grants (of this engagement's tenant).
    let tenant_grants: Vec<Value> = store
        .query_lax(
            "SELECT u.login, g.role, g.created FROM tenant_grant g JOIN users u ON u.id=g.user_id
              WHERE g.tenant_id=? ORDER BY u.login",
            &crate::sql_params![tid],
            |r| Ok(json!({"login": r.get_str(0)?, "role": r.get_str(1)?, "created": r.get_opt_str(2)?.unwrap_or_default(), "scope": "tenant"})),
        )
        .unwrap_or_default();
    // EFFECTIVE (most-specific-wins) : start from the tenant grants, then override with engagement-specific.
    let mut eff: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for g in &tenant_grants {
        let login = g.get("login").and_then(|v| v.as_str()).unwrap_or("").to_string();
        eff.insert(login, json!({"login": g.get("login"), "role": g.get("role"), "source": "tenant"}));
    }
    for g in &eng_grants {
        let login = g.get("login").and_then(|v| v.as_str()).unwrap_or("").to_string();
        eff.insert(login, json!({"login": g.get("login"), "role": g.get("role"), "source": "engagement"}));
    }
    let effective: Vec<Value> = eff.into_values().collect();
    (
        StatusCode::OK,
        Json(json!({
            "engagement_id": id, "tenant_id": tid,
            "grants": eng_grants, "inherited": tenant_grants, "effective": effective,
        })),
    )
        .into_response()
}

/// POST /api/engagements/:id/grants {login, role} — grant (or re-role) a user's ENGAGEMENT-SPECIFIC override
/// (platform-admin). Ledgered `console.engagement.grant`. Engagement + user must exist (404, fail-closed).
pub(crate) async fn engagement_grant_add(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let login = match crate::validate_login(body.get("login").and_then(|v| v.as_str()).unwrap_or("")) {
        Ok(l) => l,
        Err(e) => return err(StatusCode::BAD_REQUEST, "bad_login", e),
    };
    let role = match valid_tenant_role(body.get("role").and_then(|v| v.as_str()).unwrap_or("")) {
        Some(r) => r,
        None => return err(StatusCode::BAD_REQUEST, "bad_role", "rôle invalide (tenant_admin|tenant_operator|tenant_viewer)"),
    };
    let actor = crate::attribution_login(&app, &headers);
    let tid = match engagement_tenant(&app, id) {
        Some(t) => t,
        None => return err(StatusCode::NOT_FOUND, "unknown_engagement", format!("engagement {id} introuvable")),
    };
    {
        let store = app.store();
        let uid: i64 = match store.query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![&login], |r| r.get_i64(0)) {
            Ok(u) => u,
            Err(_) => return err(StatusCode::NOT_FOUND, "unknown_user", format!("compte '{login}' introuvable")),
        };
        // one override per (user,engagement): UPDATE the role if it exists, else INSERT (two steps —
        // unambiguous vs the table-level UNIQUE(user,engagement) ON CONFLICT IGNORE).
        let updated = store
            .execute("UPDATE engagement_grant SET role=? WHERE user_id=? AND engagement_id=?", &crate::sql_params![role, uid, id])
            .unwrap_or(0);
        if updated == 0 {
            let _ = store.execute(
                "INSERT INTO engagement_grant(user_id,engagement_id,role,created) VALUES(?,?,?,datetime('now'))",
                &crate::sql_params![uid, id, role],
            );
        }
    }
    crate::append_console_ledger(
        &app,
        "console.engagement.grant",
        json!({ "actor": actor, "engagement_id": id, "tenant_id": tid, "login": login, "role": role }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "engagement_id": id, "login": login, "role": role }))).into_response()
}

/// DELETE /api/engagements/:id/grants/:login — remove a user's ENGAGEMENT-SPECIFIC override (platform-admin).
/// The user REVERTS to their tenant-wide role (if any). Ledgered `console.engagement.revoke`.
pub(crate) async fn engagement_grant_remove(
    State(app): State<App>,
    headers: HeaderMap,
    Path((id, login)): Path<(i64, String)>,
) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let login = match crate::validate_login(&login) {
        Ok(l) => l,
        Err(e) => return err(StatusCode::BAD_REQUEST, "bad_login", e),
    };
    let actor = crate::attribution_login(&app, &headers);
    if engagement_tenant(&app, id).is_none() {
        return err(StatusCode::NOT_FOUND, "unknown_engagement", format!("engagement {id} introuvable"));
    }
    {
        let store = app.store();
        let uid: i64 = match store.query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![&login], |r| r.get_i64(0)) {
            Ok(u) => u,
            Err(_) => return err(StatusCode::NOT_FOUND, "unknown_user", format!("compte '{login}' introuvable")),
        };
        if store.query_row("SELECT 1 FROM engagement_grant WHERE user_id=? AND engagement_id=?", &crate::sql_params![uid, id], |_| Ok(())).is_err() {
            return err(StatusCode::NOT_FOUND, "no_grant", format!("aucun grant per-engagement pour '{login}' sur l'engagement {id}"));
        }
        let _ = store.execute("DELETE FROM engagement_grant WHERE user_id=? AND engagement_id=?", &crate::sql_params![uid, id]);
    }
    crate::append_console_ledger(
        &app,
        "console.engagement.revoke",
        json!({ "actor": actor, "engagement_id": id, "login": login }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "engagement_id": id, "revoked": login }))).into_response()
}

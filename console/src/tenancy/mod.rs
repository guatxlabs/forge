// SPDX-License-Identifier: AGPL-3.0-or-later
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
/// requires a provisioned individual account).
/// pub(crate) so the notifications layer can resolve the ACTOR's user_id (skip self-notify) and the
/// RECIPIENT scoping of `GET/POST /api/notifications` reuse the SAME session→user_id resolution.
///
/// M3 — resolved via the SAME dual-candidate logic as `auth_guard` (`resolve_session_identity`: Bearer
/// OR cookie, each validated INDEPENDENTLY against `session` with the disabled/expiry re-check). Reusing
/// the resolved `user_id` guarantees AUTH and TENANCY can never diverge: a caller admitted by auth (e.g.
/// a VALID cookie accompanied by a STALE/foreign Bearer — a common residue of an old front build) now
/// resolves to the SAME individual account for grants, instead of the previous single-candidate
/// (Bearer-first) lookup that returned None and left them grantless in enterprise mode.
pub(crate) fn caller_user_id(app: &App, headers: &HeaderMap) -> Option<i64> {
    crate::resolve_session_identity(app, headers).map(|id| id.user_id)
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
    drop(store);
    set
}

/// H1 — the SET of engagement ids the caller may READ, materialized for the mandatory raw-SoQL row-filter
/// (`soql::Schema::with_row_filter("engagement_id", …)`). ENTERPRISE-only (callers gate on `enabled()` and
/// pass the result straight to the core compiler, which ANDs `engagement_id IN (<these>)` — or `1=0` when
/// EMPTY — into every compiled base). Semantics mirror `engagement_visible` (an engagement is visible iff
/// its tenant is in the caller's granted set), just expanded to the full id list:
///   - SUPER-ADMIN (platform/MSSP) => ALL engagement ids (legitimate cross-tenant read of the raw surface) ;
///   - otherwise => every engagement id whose `tenant_id` is in the caller's granted tenants ;
///   - NO grant & not super-admin => EMPTY vec => the core row-filter matches NOTHING (fail-closed: zero
///     rows, never all). Ids sorted for a deterministic compiled statement.
pub fn granted_engagement_ids(app: &App, headers: &HeaderMap) -> Vec<i64> {
    // Super-admin first: acquires+releases its own db handle BEFORE we take a store guard (no re-lock).
    if is_superadmin(app, headers) {
        let store = app.store();
        let mut ids: Vec<i64> = store
            .query_lax("SELECT id FROM engagement", &[], |r| r.get_i64(0))
            .unwrap_or_default();
        ids.sort_unstable();
        return ids;
    }
    // `granted_tenants` takes+releases its OWN store guard -> must run BEFORE we acquire ours (no deadlock).
    let granted = granted_tenants(app, headers);
    if granted.is_empty() {
        return Vec::new(); // fail-closed: no grant => empty scope => row-filter matches nothing
    }
    let (ph, params) = tenants_in_bind(&granted);
    let store = app.store();
    let mut ids: Vec<i64> = store
        .query_lax(
            &format!("SELECT id FROM engagement WHERE tenant_id IN ({ph})"),
            &params,
            |r| r.get_i64(0),
        )
        .unwrap_or_default();
    ids.sort_unstable();
    ids
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

/// Placeholder list + BOUND Params for an `IN (...)` over the granted tenant ids (all i64). Returns
/// (`"?,?,…"`, `[Param::Int(id), …]`) so the ids reach SQL as BOUND parameters, never string-interpolated
/// (no future-regression injection surface even though i64s are non-injectable today). Empty set => `IN (?)`
/// bound to `NO_ENGAGEMENT` (-1, a tenant id no row has) => matches nothing (fail-closed) — semantically
/// identical to the previous `IN (-1)`. Ids are sorted for a deterministic statement (stable prepared-plan
/// cache) even though binding makes ordering irrelevant to correctness.
fn tenants_in_bind(granted: &HashSet<i64>) -> (String, Vec<crate::store::Param>) {
    let mut ids: Vec<i64> = if granted.is_empty() {
        vec![NO_ENGAGEMENT]
    } else {
        granted.iter().copied().collect()
    };
    ids.sort_unstable();
    let placeholders = vec!["?"; ids.len()].join(",");
    (placeholders, ids.into_iter().map(crate::store::Param::Int).collect())
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
        let (ph, tparams) = tenants_in_bind(&native);
        let own = {
            let store = app.store();
            store
                .query_row(
                    &format!("SELECT id FROM engagement WHERE status='active' AND tenant_id IN ({ph}) ORDER BY id DESC LIMIT 1"),
                    &tparams,
                    |r| r.get_i64(0),
                )
                .or_else(|_| {
                    store.query_row(
                        &format!("SELECT id FROM engagement WHERE tenant_id IN ({ph}) ORDER BY id DESC LIMIT 1"),
                        &tparams,
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
    let (ph, tparams) = tenants_in_bind(&granted);
    let store = app.store();
    store
        .query_row(
            &format!("SELECT id FROM engagement WHERE status='active' AND tenant_id IN ({ph}) ORDER BY id LIMIT 1"),
            &tparams,
            |r| r.get_i64(0),
        )
        .or_else(|_| {
            store.query_row(
                &format!("SELECT id FROM engagement WHERE tenant_id IN ({ph}) ORDER BY id LIMIT 1"),
                &tparams,
                |r| r.get_i64(0),
            )
        })
        .map_err(|_| "aucun engagement accessible".to_string())
}

/// Membership test: does engagement `eid` belong to one of `granted`'s tenants?  (central filter helper)
fn engagement_in(app: &App, eid: i64, granted: &HashSet<i64>) -> bool {
    matches!(tenant_of_engagement(app, eid), Some(tid) if granted.contains(&tid))
}

/// ENTERPRISE SQL WHERE-fragment restricting an engagement listing to the caller's granted tenants, plus
/// the BOUND Params for it. Community => None (no filter, byte-identical listing). Enterprise =>
/// `Some(("e.tenant_id IN (?,?,…)", [Param::Int(id), …]))` — the tenant ids are BOUND, never string-
/// interpolated (empty grant => `IN (?)` bound to -1 => zero rows, fail-closed). `alias` is the `engagement`
/// table alias in the query; the caller MUST bind the returned Params in the query's placeholder order.
pub fn list_filter_sql(app: &App, headers: &HeaderMap, alias: &str) -> Option<(String, Vec<crate::store::Param>)> {
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
    let (ph, params) = tenants_in_bind(&granted);
    Some((format!("{alias}.tenant_id IN ({ph})"), params))
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

/// Does the EXPLICIT user `user_id` have ANY effective grant on engagement `eid` — i.e. are they a
/// legitimate ASSIGNEE/OWNER candidate for a finding in that engagement? MOST-SPECIFIC-WINS like
/// effective_engagement_role, but keyed by a caller-supplied user_id (the target assignee) instead of the
/// session identity. ENTERPRISE semantics — the caller gates on `enabled()` before consulting this (in
/// COMMUNITY there are no grants and the global role governs, so this is never called). An
/// engagement-specific grant OR the tenant-wide grant on the engagement's tenant qualifies. FAIL-CLOSED:
/// no grant / unknown engagement => false (you can only assign to someone who is actually on the engagement).
pub fn user_has_engagement_grant(app: &App, user_id: i64, eid: i64) -> bool {
    let tid = tenant_of_engagement(app, eid); // acquires+releases the DB lock itself (Option)
    let store = app.store();
    // (1) ENGAGEMENT-SPECIFIC grant — most specific.
    if store
        .query_row(
            "SELECT 1 FROM engagement_grant WHERE user_id = ? AND engagement_id = ?",
            &crate::sql_params![user_id, eid],
            |_| Ok(()),
        )
        .is_ok()
    {
        return true;
    }
    // (2) TENANT-WIDE grant on the engagement's tenant. Unknown engagement (no tenant) => false.
    match tid {
        Some(t) => store
            .query_row(
                "SELECT 1 FROM tenant_grant WHERE user_id = ? AND tenant_id = ?",
                &crate::sql_params![user_id, t],
                |_| Ok(()),
            )
            .is_ok(),
        None => false,
    }
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
    drop(store);
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
// § ADMIN API — EXTRAITE dans `tenancy/admin_api.rs` (PURE MOVE, corps byte-identique).
// Les deux sections `§ TENANT ADMIN` et `§ PER-ENGAGEMENT GRANT ADMIN` (routeur + 17 symboles)
// ne sont référencées PAR AUCUN symbole du cœur ci-dessus : le seam est à SENS UNIQUE. Enfant de
// `tenancy`, `admin_api` voit toujours les helpers PRIVÉS du cœur (`tenants_in_bind`, …) — aucune
// bump de visibilité. Le glob `pub(crate) use admin_api::*` garde INCHANGÉS les chemins d'appel
// externes (`tenancy::routes()` dans router.rs, `tenancy::tenants_create` … dans les tests).
// =====================================================================================
mod admin_api;
pub(crate) use admin_api::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// `tenants_in_bind` (Tâche B — `IN (...)` LIÉ) : le nombre de placeholders `?` DOIT égaler le nombre de
    /// Params. Un off-by-one = erreur de bind à l'exécution (la garantie clé quand on remplace un CSV inliné
    /// par des paramètres liés). Empty grant -> `?` UNIQUE lié à NO_ENGAGEMENT (-1) => zéro ligne (fail-closed),
    /// équivalent EXACT à l'ancien `IN (-1)` inliné. Ids dédupliqués/triés => statement déterministe.
    #[test]
    fn tenants_in_bind_placeholder_count_matches_params() {
        for ids in [vec![], vec![7i64], vec![3i64, 1, 9]] {
            let set: HashSet<i64> = ids.iter().copied().collect();
            let (ph, params) = tenants_in_bind(&set);
            assert_eq!(ph.matches('?').count(), params.len(), "un ? par Param (pas d'off-by-one)");
            assert!(!params.is_empty(), "au moins un Param lié (jamais un IN () vide)");
            // chaque Param est un entier (jamais du texte) — non-injectable par construction.
            assert!(params.iter().all(|p| matches!(p, crate::store::Param::Int(_))), "tenant ids liés en Int");
        }
        // empty -> EXACTEMENT un placeholder lié à NO_ENGAGEMENT (fail-closed, équivalent à `IN (-1)`).
        let (ph, params) = tenants_in_bind(&HashSet::new());
        assert_eq!(ph, "?");
        assert_eq!(params, vec![crate::store::Param::Int(NO_ENGAGEMENT)]);
        // non vide -> autant de `?` que d'ids distincts, séparés par des virgules.
        let (ph3, params3) = tenants_in_bind(&HashSet::from([5i64, 2, 8]));
        assert_eq!(ph3, "?,?,?");
        assert_eq!(params3.len(), 3);
    }
}

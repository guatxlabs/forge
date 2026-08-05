// SPDX-License-Identifier: AGPL-3.0-or-later
//! `tenancy` — SURFACE D'ADMINISTRATION EXTRAITE (PURE MOVE depuis `console/src/tenancy.rs`).
//! Corps IDENTIQUE ; ENFANT de `tenancy`, il voit donc toujours ses items privés (`use super::*;`)
//! — le cœur (filtre de lignes / RBAC par engagement / super-admin / ledger par tenant) reste dans
//! `mod.rs` et n'appelle AUCUN symbole d'ici (seam à sens unique, vérifié symbole par symbole).
//! Porte les deux sections `§ TENANT ADMIN` (CRUD tenants + grants) et `§ PER-ENGAGEMENT GRANT
//! ADMIN`, plus le sous-routeur `routes()` mergé par `router.rs`.
use super::*;

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
        .route("/api/tenants/{id}", post(tenants_update))
        .route("/api/tenants/{id}/grants", get(tenant_grants_list).post(tenant_grant_add))
        .route("/api/tenants/{id}/grants/{login}", delete(tenant_grant_remove))
        // PER-ENGAGEMENT RBAC (readiness #14) — engagement-specific grant management (platform-admin). The
        // `:id` param name matches the sibling `/api/engagements/:id` (main router) / `/api/engagements/:id/
        // report` (reports router) — matchit requires the SAME param name at that position (it is `:id`).
        .route("/api/engagements/{id}/grants", get(engagement_grants_list).post(engagement_grant_add))
        .route("/api/engagements/{id}/grants/{login}", delete(engagement_grant_remove))
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
/// `Some(set)` => exactly the granted tenants (empty set => `id IN (?)` bound to -1 => zero rows, fail-closed).
/// Pure read; the tenant ids are BOUND Params (never string-interpolated). Ordered by id for a deterministic selector.
fn accessible_tenants(app: &App, granted: &Option<HashSet<i64>>) -> Vec<Value> {
    let store = app.store();
    let (sql, params): (String, Vec<crate::store::Param>) = match granted {
        None => ("SELECT id, name, status FROM tenant ORDER BY id".to_string(), Vec::new()),
        Some(set) => {
            let (ph, p) = tenants_in_bind(set);
            (format!("SELECT id, name, status FROM tenant WHERE id IN ({ph}) ORDER BY id"), p)
        }
    };
    store
        .query_lax(&sql, &params, |r| {
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

// `err` consolidé dans `common` (corps + signature byte-identiques à compliance/sso — dedup Wave).
use crate::common::err;

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
    drop(store);
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
            // FAIL-CLOSED : l'auto-grant tenant_admin garantit le ≥1 admin du nouveau tenant. Un échec silencieux
            // laisserait un tenant SANS admin tout en renvoyant `self_grant_admin:true` + un ledger l'attestant
            // (fausse attestation). On MATCHE le Result -> 500 AVANT le ledger.
            if let Err(e) = store.execute(
                "INSERT INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,?,?,datetime('now'))",
                &crate::sql_params![u, id, "tenant_admin"],
            ) {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "grant_failed", format!("auto-grant admin du tenant échoué: {e}"));
            }
            drop(store);
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
        // ÉCRITURE ATOMIQUE + FAIL-CLOSED (même classe que finding_update) : un SEUL UPDATE porte name et/ou
        // status -> aucun état partiel. On MATCHE le Result : un échec (lock/disque/pg) -> 500 AVANT le ledger
        // (sinon la piste tamper-evident attesterait un rename/archive jamais appliqué + faux `ok:true`).
        // >=1 SET garanti (no_change déjà rejeté 400 plus haut).
        let mut sets: Vec<&str> = Vec::new();
        let mut params: Vec<crate::store::Param> = Vec::new();
        if let Some(n) = &new_name { sets.push("name=?"); params.push(crate::store::Param::Text(n.clone())); }
        if let Some(s) = &new_status { sets.push("status=?"); params.push(crate::store::Param::Text(s.clone())); }
        params.push(crate::store::Param::Int(id));
        let sql = format!("UPDATE tenant SET {}, updated=datetime('now') WHERE id=?", sets.join(", "));
        if let Err(e) = store.execute(&sql, &params) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "update_failed", format!("écriture du tenant échouée: {e}"));
        }
        drop(store); // libère le guard avant le calcul de `action` (qui ne touche pas la DB) ; clippy tightening
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
    drop(store);
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
        // vs the table-level ON CONFLICT IGNORE constraint). FAIL-CLOSED : on MATCHE chaque écriture -> un
        // échec (lock/disque/pg) rend 500 AVANT le ledger (sinon `console.tenant.grant` attesterait un grant
        // jamais appliqué + faux `ok:true`).
        let updated = match store.execute("UPDATE tenant_grant SET role=? WHERE user_id=? AND tenant_id=?", &crate::sql_params![role, uid, id]) {
            Ok(n) => n,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "grant_failed", format!("écriture du grant échouée: {e}")),
        };
        if updated == 0 {
            if let Err(e) = store.execute(
                "INSERT INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,?,?,datetime('now'))",
                &crate::sql_params![uid, id, role],
            ) {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "grant_failed", format!("écriture du grant échouée: {e}"));
            }
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
        // FAIL-CLOSED : un échec du DELETE -> 500 AVANT le ledger (sinon `console.tenant.revoke` attesterait
        // un retrait de grant jamais appliqué + faux `ok:true`).
        if let Err(e) = store.execute("DELETE FROM tenant_grant WHERE user_id=? AND tenant_id=?", &crate::sql_params![uid, id]) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "revoke_failed", format!("retrait du grant échoué: {e}"));
        }
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
    drop(store);
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
        // unambiguous vs the table-level UNIQUE(user,engagement) ON CONFLICT IGNORE). FAIL-CLOSED : on MATCHE
        // chaque écriture -> 500 AVANT le ledger (sinon `console.engagement.grant` attesterait un override
        // jamais appliqué + faux `ok:true`).
        let updated = match store.execute("UPDATE engagement_grant SET role=? WHERE user_id=? AND engagement_id=?", &crate::sql_params![role, uid, id]) {
            Ok(n) => n,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "grant_failed", format!("écriture du grant échouée: {e}")),
        };
        if updated == 0 {
            if let Err(e) = store.execute(
                "INSERT INTO engagement_grant(user_id,engagement_id,role,created) VALUES(?,?,?,datetime('now'))",
                &crate::sql_params![uid, id, role],
            ) {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "grant_failed", format!("écriture du grant échouée: {e}"));
            }
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
        // FAIL-CLOSED : un échec du DELETE -> 500 AVANT le ledger (sinon `console.engagement.revoke`
        // attesterait un retrait d'override jamais appliqué + faux `ok:true`).
        if let Err(e) = store.execute("DELETE FROM engagement_grant WHERE user_id=? AND engagement_id=?", &crate::sql_params![uid, id]) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "revoke_failed", format!("retrait de l'override échoué: {e}"));
        }
    }
    crate::append_console_ledger(
        &app,
        "console.engagement.revoke",
        json!({ "actor": actor, "engagement_id": id, "login": login }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "engagement_id": id, "revoked": login }))).into_response()
}

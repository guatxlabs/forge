// SPDX-License-Identifier: AGPL-3.0-only
//! ENTERPRISE — SCIM 2.0 provisioning (SEPARABLE, FLAG-GATED module).
//!
//! Open-core discipline (mirrors `sso.rs` / `tenancy.rs`): this is an ENTERPRISE feature. The COMMUNITY
//! (default) build behaves EXACTLY as today — LOCAL accounts only, managed by the admin console. Every
//! `/scim/*` route (and the admin `/api/scim/config`) is a NO-OP (404 `not_found`) unless the enterprise
//! flag is ENGAGED (`enabled()` false => community, byte-identical). It never weakens the open
//! governance/audit surface; it only ADDS an automated user/group provisioning path for an IdP
//! (Okta / Azure AD / etc.) that maps SCIM identities onto the SAME `users` table local login already uses.
//!
//! SURFACE (SCIM 2.0 core — RFC 7643/7644, subset):
//!   GET/POST                    /scim/v2/Users        — list (filter `userName eq "x"`) / create.
//!   GET/PUT/PATCH/DELETE        /scim/v2/Users/:id    — read / replace / partial-update / de-provision.
//!   GET/POST                    /scim/v2/Groups       — list / create (best-effort membership → role).
//!   GET/PUT/PATCH/DELETE        /scim/v2/Groups/:id   — read / replace / patch members / delete.
//!   GET                         /scim/v2/ServiceProviderConfig — IdP capability discovery.
//!   GET/POST                    /api/scim/config      — admin-gated bearer-token management (rotate/revoke).
//!
//! AUTHENTICATION (fail-closed — weaken it and a test flips RED):
//!   - `/scim/v2/*` is authenticated by a SCIM BEARER TOKEN — a long random token an admin generates via
//!     `/api/scim/config`. It is a SECRET: stored HASHED (SHA-256, like a session token — never the raw
//!     token) in `settings.scim.token_sha`, compared CONSTANT-TIME (`ct_eq_str`). It is NOT a normal
//!     session — an IdP never has a `forge_session`. No valid SCIM token => 401 (unconfigured => 401 too).
//!   - `/api/scim/config` is a NORMAL admin route (`check_admin`, session) — the admin manages the token
//!     with their own session; the raw token is returned ONCE at rotation and NEVER again (redacted).
//!
//! MAPPING (SCIM → Forge):
//!   - create / activate (active=true) => create / ENABLE a Forge user (scoped DEFAULT role — viewer,
//!     never admin, never super-admin; unusable local password — SCIM/SSO-only). Community accounts are
//!     untouched (SCIM only ever lists / mutates users it PROVISIONED — those with a `scim_user` row).
//!   - deactivate (active=false), and DELETE (de-provision) => DISABLE the user AND PURGE its sessions
//!     (immediate revocation — a de-provisioned user loses access at once).
//!   - group membership => a scoped role / tenant-grant (ties to the advanced-RBAC slice). Best-effort,
//!     bounded: viewer|operator only — a SCIM group can NEVER confer admin or super-admin.
//!   - a DESIGNATED super-admin login (provisioning-only, `tenancy.rs`) is PROTECTED — SCIM refuses to
//!     create / deactivate / delete it (403), so an IdP can never de-provision the platform operator.
//!
//! SECURITY: the SCIM token is redacted / never logged / never ledgered / never returned; every
//! provisioning mutation is ledgered `console.scim.*` (METADATA only — login/externalId/active/booleans,
//! NEVER the token). Flag OFF => `/scim/*` disabled (404) and LOCAL accounts are byte-identical to today.

use crate::App;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;

/// settings KV key holding the SHA-256 (hex) of the active SCIM bearer token. Empty/absent => SCIM auth
/// fails closed (401) until an admin rotates a token. Only the HASH is ever stored (leak-inert).
const TOKEN_KEY: &str = "scim.token_sha";
/// settings KV key: the scoped default role for a SCIM-provisioned user (`viewer`|`operator`; default
/// `viewer`). Admin cannot set `admin` here (auto-provisioning admin from an IdP is refused — fail-closed).
const DEFAULT_ROLE_KEY: &str = "scim.default_role";

/// SCIM 2.0 schema URNs (RFC 7643/7644).
const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCHEMA_LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCHEMA_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

// ============================================================================================
// FLAG — is enterprise SCIM ENGAGED? Community default = OFF (every /scim/* route 404s, local unchanged).
// Sources (ANY engages it): env `FORGE_ENTERPRISE_SCIM` (truthy) OR the per-DB key `enterprise.scim`
// (on|1|true|yes) OR the enterprise-SSO flag (`sso::enabled` — SCIM ships with the same identity bundle).
// Config is per-DB so tests toggle it in isolation. Mirrors sso/tenancy.
// ============================================================================================

/// Is enterprise SCIM engaged?  false => community (every `/scim/*` + `/api/scim/config` route 404s).
pub fn enabled(app: &App) -> bool {
    // Own env flag OR per-DB config (shared substrate), OR — SCIM ships in the enterprise-identity
    // bundle — the SSO flag engages it too (single toggle). Same short-circuit order as before.
    crate::flags::enterprise_enabled(app, "FORGE_ENTERPRISE_SCIM", "enterprise.scim")
        || crate::sso::enabled(app)
}

// ============================================================================================
// RESPONSE HELPERS
// ============================================================================================

/// A SCIM JSON response with the `application/scim+json` content type (RFC 7644 §3.1).
fn scim_json(status: StatusCode, v: Value) -> Response {
    (status, [(header::CONTENT_TYPE, "application/scim+json")], v.to_string()).into_response()
}

/// A SCIM error response (`urn:...:Error`). `detail` is a non-secret human string; `scim_type` is the
/// optional RFC 7644 §3.12 error keyword (e.g. `uniqueness`, `invalidValue`).
fn scim_err(status: StatusCode, detail: impl Into<String>, scim_type: Option<&str>) -> Response {
    let mut body = json!({
        "schemas": [SCHEMA_ERROR],
        "status": status.as_u16().to_string(),
        "detail": detail.into(),
    });
    if let Some(t) = scim_type {
        body["scimType"] = json!(t);
    }
    scim_json(status, body)
}

// `disabled` consolidé dans `common` (corps byte-identique à compliance/sso — dedup Wave). `cfg_err` reste
// local (nom distinct — hors périmètre de ce dedup exact-copy).
use crate::common::disabled;

/// Admin-config typed error (shared substrate; byte-identical `{"error","why"}`) — never a secret.
fn cfg_err(status: StatusCode, code: &'static str, why: impl Into<String>) -> Response {
    crate::error::ApiError::new(status, code, why).into_response()
}

// ============================================================================================
// SCIM BEARER-TOKEN AUTHENTICATION — fail-closed (401), constant-time, NOT a session.
// ============================================================================================

/// Extract the raw bearer token from `Authorization: Bearer <t>`. Empty if absent/malformed.
fn bearer(headers: &HeaderMap) -> String {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Authenticate a `/scim/v2/*` request. FAIL-CLOSED: returns the 401 Response to short-circuit with, or
/// `None` to proceed. NEVER a session — an IdP presents ONLY the SCIM bearer token, compared CONSTANT-TIME
/// against the stored SHA-256. No token configured, no token presented, or a mismatch => 401.
fn scim_auth(app: &App, headers: &HeaderMap) -> Option<Response> {
    let stored = {
        let store = app.store();
        crate::settings_get_store(&store, TOKEN_KEY).unwrap_or_default()
    };
    if stored.is_empty() {
        // No SCIM token provisioned => the provisioning surface is closed (fail-closed).
        return Some(scim_err(StatusCode::UNAUTHORIZED, "SCIM provisioning token not configured", None));
    }
    let presented = bearer(headers);
    if presented.is_empty() {
        return Some(scim_err(StatusCode::UNAUTHORIZED, "missing SCIM bearer token", None));
    }
    // Compare HASHES in constant time (both fixed-length hex → no length/byte timing oracle on the token).
    if !crate::ct_eq_str(&crate::sha_hex(&presented), &stored) {
        return Some(scim_err(StatusCode::UNAUTHORIZED, "invalid SCIM bearer token", None));
    }
    None
}

/// Combined gate for a `/scim/v2/*` handler: flag first (404 if OFF — route ABSENT in community), then
/// bearer-token auth (401 fail-closed). Returns the short-circuit Response, or `None` to proceed.
fn gate(app: &App, headers: &HeaderMap) -> Option<Response> {
    if !enabled(app) {
        return Some(disabled());
    }
    scim_auth(app, headers)
}

// ============================================================================================
// LAZY SCHEMA — SCIM provisioning metadata. Created on first use (flag OFF => routes 404 before this
// runs) so the COMMUNITY DB is UNTOUCHED. `scim_user` marks which `users` rows SCIM owns and round-trips
// the IdP-specific attributes (externalId, email, name) that the core `users` table does not carry.
// ============================================================================================

fn ensure_schema(store: &crate::store::Store) {
    // POSTGRES dialect (feature `store-postgres` + backend actif PG) : `INTEGER`->`BIGINT` (parité avec
    // le mapping de PG_SCHEMA + les binds i64 du seam), `scim_group.id` en IDENTITY (l'INSERT sans id
    // s'appuie sur last_insert_id/lastval), et la clause `ON CONFLICT IGNORE` (SQLite-only) DROPPÉE de la
    // contrainte UNIQUE (l'INSERT add_member utilise déjà `ON CONFLICT DO NOTHING`, portable). `scim_user
    // .user_id` reste un PK explicite (= users.id fourni). Ces tables restent HORS de PG_SCHEMA : elles
    // sont flag-gated et créées paresseusement au 1er usage (la base community ne les voit jamais).
    #[cfg(feature = "store-postgres")]
    if store.is_postgres() {
        let _ = store.execute_batch(
            "CREATE TABLE IF NOT EXISTS scim_user(
               user_id     BIGINT PRIMARY KEY,
               external_id TEXT NOT NULL DEFAULT '',
               email       TEXT NOT NULL DEFAULT '',
               given_name  TEXT NOT NULL DEFAULT '',
               family_name TEXT NOT NULL DEFAULT '',
               display_name TEXT NOT NULL DEFAULT '',
               created     BIGINT NOT NULL,
               updated     BIGINT NOT NULL);
             CREATE INDEX IF NOT EXISTS idx_scim_user_ext ON scim_user(external_id);
             CREATE TABLE IF NOT EXISTS scim_group(
               id           BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
               display_name TEXT NOT NULL,
               external_id  TEXT NOT NULL DEFAULT '',
               role         TEXT NOT NULL DEFAULT 'viewer',
               created      BIGINT NOT NULL,
               updated      BIGINT NOT NULL);
             CREATE TABLE IF NOT EXISTS scim_group_member(
               group_id BIGINT NOT NULL,
               user_id  BIGINT NOT NULL,
               UNIQUE(group_id, user_id));",
        );
        return;
    }
    let _ = store.execute_batch(
        "CREATE TABLE IF NOT EXISTS scim_user(
           user_id     INTEGER PRIMARY KEY,
           external_id TEXT NOT NULL DEFAULT '',
           email       TEXT NOT NULL DEFAULT '',
           given_name  TEXT NOT NULL DEFAULT '',
           family_name TEXT NOT NULL DEFAULT '',
           display_name TEXT NOT NULL DEFAULT '',
           created     INTEGER NOT NULL,
           updated     INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS idx_scim_user_ext ON scim_user(external_id);
         CREATE TABLE IF NOT EXISTS scim_group(
           id           INTEGER PRIMARY KEY,
           display_name TEXT NOT NULL,
           external_id  TEXT NOT NULL DEFAULT '',
           role         TEXT NOT NULL DEFAULT 'viewer',
           created      INTEGER NOT NULL,
           updated      INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS scim_group_member(
           group_id INTEGER NOT NULL,
           user_id  INTEGER NOT NULL,
           UNIQUE(group_id, user_id) ON CONFLICT IGNORE);",
    );
}

/// PG-ONLY — crée les tables enterprise SCIM (`scim_user`/`scim_group`/`scim_group_member`) sur la CIBLE
/// Postgres pour le migrateur de données (`cli::migrate-store`) : ces tables sont HORS de `PG_SCHEMA` (créées
/// paresseusement au 1er usage runtime), donc le migrateur doit invoquer explicitement ce chemin pour que la
/// cible les possède AVANT la copie (sinon elles seraient absentes -> hard-fail au lieu d'un skip silencieux).
/// Délègue à `ensure_schema` (branche `is_postgres()`). Entièrement gardé `store-postgres` : le build
/// community ne compile pas cette fonction (byte-identical).
#[cfg(feature = "store-postgres")]
pub(crate) fn ensure_pg_schema(store: &crate::store::Store) {
    ensure_schema(store);
}

// ============================================================================================
// ROUTES — merged into the OUTER router (like sso), NOT behind `auth_guard`: the IdP has no session, it
// authenticates with the SCIM bearer token INTERNALLY. Under host_guard like everything else. Each route
// self-gates on the flag (404 while OFF). `/api/scim/config` enforces `check_admin` internally.
// ============================================================================================

pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/scim/v2/Users", get(users_list).post(users_create))
        .route(
            "/scim/v2/Users/:id",
            get(user_get).put(user_put).patch(user_patch).delete(user_delete),
        )
        .route("/scim/v2/Groups", get(groups_list).post(groups_create))
        .route(
            "/scim/v2/Groups/:id",
            get(group_get).put(group_patch).patch(group_patch).delete(group_delete),
        )
        .route("/scim/v2/ServiceProviderConfig", get(service_provider_config))
        .route("/api/scim/config", get(config_get).post(config_set))
}

// ============================================================================================
// ADMIN CONFIG — SCIM bearer-token management (admin session; token stored HASHED; raw returned ONCE).
// ============================================================================================

/// GET /api/scim/config — SCIM provisioning status for the admin UI. Flag-gated + admin-only. NEVER
/// returns the token (only whether one is set + the default role + the base path).
async fn config_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !enabled(&app) {
        return disabled();
    }
    if !crate::check_admin(&app, &headers) {
        return cfg_err(StatusCode::FORBIDDEN, "admin_required", "SCIM config is admin-only");
    }
    let (token_set, role) = {
        let store = app.store();
        (
            crate::settings_get_store(&store, TOKEN_KEY).map(|s| !s.is_empty()).unwrap_or(false),
            crate::settings_get_store(&store, DEFAULT_ROLE_KEY).unwrap_or_else(|| "viewer".to_string()),
        )
    };
    (
        StatusCode::OK,
        Json(json!({
            "enabled": true,
            "token_set": token_set,       // presence only — the token itself is NEVER returned
            "default_role": role,
            "endpoint": "/scim/v2",
        })),
    )
        .into_response()
}

/// POST /api/scim/config — manage the SCIM bearer token (admin-only). Body actions:
///   `{"rotate": true}`        → generate a fresh 256-bit token, store its SHA-256, return the RAW token
///                               ONCE (`token` field) — never retrievable again.
///   `{"revoke": true}`        → clear the token (SCIM auth then fails closed → 401).
///   `{"default_role": "..."}` → set the scoped default role for provisioned users (viewer|operator).
/// Ledgered `console.scim.config` (action + booleans — NEVER the token). At least one action required.
async fn config_set(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    if !enabled(&app) {
        return disabled();
    }
    if !crate::check_admin(&app, &headers) {
        return cfg_err(StatusCode::FORBIDDEN, "admin_required", "SCIM config is admin-only");
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
    let rotate = body.get("rotate").and_then(|v| v.as_bool()).unwrap_or(false);
    let revoke = body.get("revoke").and_then(|v| v.as_bool()).unwrap_or(false);
    let new_role = body.get("default_role").and_then(|v| v.as_str()).map(|s| s.to_string());
    if !rotate && !revoke && new_role.is_none() {
        return cfg_err(StatusCode::BAD_REQUEST, "no_action", "provide rotate | revoke | default_role");
    }
    if rotate && revoke {
        return cfg_err(StatusCode::BAD_REQUEST, "conflict", "rotate and revoke are mutually exclusive");
    }

    // default_role: bounded to viewer|operator — SCIM never auto-provisions admin (let alone super-admin).
    if let Some(r) = &new_role {
        if r != "viewer" && r != "operator" {
            return cfg_err(
                StatusCode::BAD_REQUEST,
                "bad_default_role",
                "default_role must be 'viewer' or 'operator' (admin is never SCIM-provisioned)",
            );
        }
    }

    // The RAW token: generated here on rotate, returned ONCE, NEVER stored/logged/ledgered in the clear.
    let mut raw_token: Option<String> = None;
    {
        let store = app.store();
        if rotate {
            let tok = rand_hex(32); // 256-bit
            if let Err(e) = crate::settings_set_store(&store, TOKEN_KEY, &crate::sha_hex(&tok)) {
                return cfg_err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed", e);
            }
            raw_token = Some(tok);
        }
        if revoke {
            if let Err(e) = crate::settings_set_store(&store, TOKEN_KEY, "") {
                return cfg_err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed", e);
            }
        }
        if let Some(r) = &new_role {
            if let Err(e) = crate::settings_set_store(&store, DEFAULT_ROLE_KEY, r) {
                return cfg_err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed", e);
            }
        }
    }

    let actor = crate::attribution_login(&app, &headers);
    let action = if rotate {
        "rotate"
    } else if revoke {
        "revoke"
    } else {
        "default_role"
    };
    crate::append_console_ledger(
        &app,
        "console.scim.config",
        json!({ "actor": actor, "action": action, "token_set": rotate, "default_role": new_role }),
    );

    // Response: echo the RAW token ONLY on rotate (once). Otherwise redacted status.
    let token_set = {
        let store = app.store();
        crate::settings_get_store(&store, TOKEN_KEY).map(|s| !s.is_empty()).unwrap_or(false)
    };
    let mut resp = json!({ "ok": true, "token_set": token_set });
    if let Some(t) = raw_token {
        resp["token"] = json!(t); // shown exactly once — the admin copies it into the IdP now
    }
    (StatusCode::OK, Json(resp)).into_response()
}

// ============================================================================================
// USERS
// ============================================================================================

/// GET /scim/v2/Users[?filter=userName eq "x"][&startIndex&count] — list SCIM-PROVISIONED users only
/// (never the local admin accounts). Supports the single `userName eq "…"` filter Okta/Azure use to probe
/// existence before create.
async fn users_list(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let filter_login = q.get("filter").and_then(|f| parse_username_filter(f));
    let start_index: i64 = q.get("startIndex").and_then(|s| s.parse().ok()).filter(|&n| n >= 1).unwrap_or(1);
    let count: i64 = q.get("count").and_then(|s| s.parse().ok()).filter(|&n| n >= 0).unwrap_or(100);

    let ids: Vec<i64> = {
        let store = app.store();
        ensure_schema(&store);
        let sql = "SELECT s.user_id FROM scim_user s JOIN users u ON u.id = s.user_id \
                   WHERE (?1 = '' OR u.login = ?1) ORDER BY s.user_id";
        let key = filter_login.clone().unwrap_or_default();
        let has_filter = filter_login.is_some();
        // When a filter is present but no match, `key` is a concrete login → empty result (correct).
        // When absent, `key=''` matches all (the `?1=''` short-circuit).
        let bind = if has_filter { key } else { String::new() };
        store.query_lax(sql, &crate::sql_params![&bind], |r| r.get_i64(0)).unwrap_or_default()
    };
    let total = ids.len() as i64;
    let page: Vec<Value> = ids
        .into_iter()
        .skip((start_index - 1).max(0) as usize)
        .take(count as usize)
        .filter_map(|id| user_resource(&app, id))
        .collect();
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": [SCHEMA_LIST],
            "totalResults": total,
            "startIndex": start_index,
            "itemsPerPage": page.len(),
            "Resources": page,
        }),
    )
}

/// POST /scim/v2/Users — create (provision) a Forge user from a SCIM User resource. Maps userName→login,
/// active→enabled, and stores externalId/email/name. The account gets the SCOPED default role (viewer,
/// never admin/super-admin) and an UNUSABLE local password (SCIM/SSO-only). 409 if the login already
/// exists (SCIM `uniqueness`). Ledgered `console.scim.user.create`.
async fn users_create(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let res: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return scim_err(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}"), Some("invalidValue")),
    };
    let attrs = UserAttrs::from_resource(&res);
    let user_name = attrs.user_name.clone().unwrap_or_default();
    let login = match derive_login(&user_name, attrs.external_id.as_deref().unwrap_or("")) {
        Ok(l) => l,
        Err(e) => return scim_err(StatusCode::BAD_REQUEST, e, Some("invalidValue")),
    };
    // PROTECT the platform super-admin: an IdP can never (re)provision a designated super-admin login.
    if crate::tenancy::is_superadmin_login(&app, &login) {
        return scim_err(StatusCode::FORBIDDEN, "login is a protected super-admin (not SCIM-managed)", Some("mutability"));
    }
    let active = attrs.active.unwrap_or(true);
    let role = default_role(&app);
    // Unusable local password (argon2id of a random secret nobody knows → local login can never succeed).
    let hash = crate::hash_pw(&rand_hex(32));

    let id = {
        let store = app.store();
        ensure_schema(&store);
        if store.query_row("SELECT 1 FROM users WHERE login=?", &crate::sql_params![&login], |_| Ok(())).is_ok() {
            return scim_err(StatusCode::CONFLICT, format!("user '{login}' already exists"), Some("uniqueness"));
        }
        // execute_returning_id : id du user lu du MÊME INSERT (RETURNING id sur PG), sans lastval() —
        // session-indépendant, sûr sur backend poolé. L'INSERT scim_user suivant vient APRÈS (id capturé).
        let id = match store.execute_returning_id(
            "INSERT INTO users(login,role,pass_hash,disabled,created) VALUES(?,?,?,?,datetime('now'))",
            &crate::sql_params![&login, &role, &hash, (!active) as i64],
        ) {
            Ok(id) => id,
            Err(e) => return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("create failed: {e}"), None),
        };
        let now = crate::now_epoch();
        // FAIL-CLOSED : la ligne scim_user (mapping IdP) est ce qui rend le compte SCIM-managed. Un échec
        // silencieux laisserait un users sans mapping tout en renvoyant 201 Created + un ledger
        // `console.scim.user.create` (fausse attestation). On MATCHE -> 500 AVANT le ledger.
        if let Err(e) = store.execute(
            "INSERT INTO scim_user(user_id,external_id,email,given_name,family_name,display_name,created,updated)
             VALUES(?,?,?,?,?,?,?,?)",
            &crate::sql_params![
                id,
                attrs.external_id.clone().unwrap_or_default(),
                attrs.email.clone().unwrap_or_default(),
                attrs.given.clone().unwrap_or_default(),
                attrs.family.clone().unwrap_or_default(),
                attrs.display.clone().unwrap_or_default(),
                now,
                now
            ],
        ) {
            return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("create failed: {e}"), None);
        }
        drop(store); // libère le guard avant de sortir du bloc (pas de contention inutile ; clippy tightening)
        id
    };
    // A new ENABLED account changes the auth-gate DB state (mirror the account-CRUD discipline).
    app.recompute_auth_required();
    app.bump_cache_epoch(); // B6 (HA): invalidate peers' auth_required cache (SCIM-provisioned account)
    crate::append_console_ledger(
        &app,
        "console.scim.user.create",
        json!({ "actor": "scim", "login": login, "external_id": attrs.external_id, "role": role, "active": active }),
    );
    match user_resource(&app, id) {
        Some(r) => scim_json(StatusCode::CREATED, r),
        None => scim_err(StatusCode::INTERNAL_SERVER_ERROR, "created but could not render resource", None),
    }
}

/// GET /scim/v2/Users/:id — one SCIM-provisioned user. 404 if unknown / not SCIM-managed.
async fn user_get(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let uid = match parse_id(&id) {
        Some(n) => n,
        None => return scim_err(StatusCode::NOT_FOUND, "user not found", None),
    };
    match user_resource(&app, uid) {
        Some(r) => scim_json(StatusCode::OK, r),
        None => scim_err(StatusCode::NOT_FOUND, "user not found", None),
    }
}

/// PUT /scim/v2/Users/:id — replace the user resource (Okta/Azure use this to toggle `active` and update
/// attributes). Absent attributes are LEFT UNCHANGED (safer than clearing — documented deviation). If the
/// replacement sets active=false, the user is disabled AND its sessions purged.
async fn user_put(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let uid = match parse_id(&id) {
        Some(n) => n,
        None => return scim_err(StatusCode::NOT_FOUND, "user not found", None),
    };
    let res: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return scim_err(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}"), Some("invalidValue")),
    };
    let attrs = UserAttrs::from_resource(&res);
    apply_update(&app, uid, &attrs)
}

/// PATCH /scim/v2/Users/:id — partial update (RFC 7644 §3.5.2). Parses `Operations` (op replace|add) with
/// either a `path` (e.g. `active`) or a value OBJECT. The canonical de-provision op
/// (`{op:replace, value:{active:false}}` / `{op:replace, path:"active", value:false}`) disables the user
/// AND purges its sessions.
async fn user_patch(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let uid = match parse_id(&id) {
        Some(n) => n,
        None => return scim_err(StatusCode::NOT_FOUND, "user not found", None),
    };
    let doc: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return scim_err(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}"), Some("invalidValue")),
    };
    let attrs = UserAttrs::from_patch(&doc);
    apply_update(&app, uid, &attrs)
}

/// DELETE /scim/v2/Users/:id — DE-PROVISION. Disables the Forge user, PURGES its sessions (immediate
/// revocation), and drops the `scim_user` mapping (no longer SCIM-managed → subsequent GET 404s). The
/// underlying `users` row is KEPT DISABLED (attribution/audit preserved), never hard-deleted. 204.
async fn user_delete(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let uid = match parse_id(&id) {
        Some(n) => n,
        None => return scim_err(StatusCode::NOT_FOUND, "user not found", None),
    };
    let login = {
        let store = app.store();
        ensure_schema(&store);
        // Must be a SCIM-managed user (has a scim_user row) — SCIM never touches local accounts.
        match store.query_row(
            "SELECT u.login FROM users u JOIN scim_user s ON s.user_id = u.id WHERE u.id = ?",
            &crate::sql_params![uid],
            |r| r.get_str(0),
        ) {
            Ok(l) => l,
            Err(_) => return scim_err(StatusCode::NOT_FOUND, "user not found", None),
        }
    };
    if crate::tenancy::is_superadmin_login(&app, &login) {
        return scim_err(StatusCode::FORBIDDEN, "protected super-admin cannot be de-provisioned via SCIM", Some("mutability"));
    }
    {
        let store = app.store();
        // Disable + purge sessions + drop mapping ATOMIQUEMENT (with_tx : tout-ou-rien). FAIL-CLOSED : un
        // échec en cours de séquence -> ROLLBACK + 500 AVANT le ledger (pas d'état partiel : un compte
        // désactivé mais mapping intact, ou des sessions non purgées, tout en ledgerisant la de-provision).
        if let Err(e) = store.with_tx(|tx| {
            tx.execute("UPDATE users SET disabled=1 WHERE id=?", &crate::sql_params![uid])?;
            tx.execute("DELETE FROM session WHERE user_id=?", &crate::sql_params![uid])?;
            tx.execute("DELETE FROM scim_user WHERE user_id=?", &crate::sql_params![uid])?;
            tx.execute("DELETE FROM scim_group_member WHERE user_id=?", &crate::sql_params![uid])?;
            Ok(())
        }) {
            return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("de-provision failed: {e}"), None);
        }
    }
    app.recompute_auth_required();
    app.bump_cache_epoch(); // B6 (HA): invalidate peers' auth_required cache (SCIM account deprovisioned)
    crate::append_console_ledger(
        &app,
        "console.scim.user.delete",
        json!({ "actor": "scim", "login": login, "sessions_purged": true }),
    );
    (StatusCode::NO_CONTENT, ()).into_response()
}

/// Apply a parsed set of attribute changes to a SCIM-managed user (shared by PUT + PATCH). Enforces the
/// super-admin protection, updates users.disabled / scim_user attributes, and — when the change DISABLES
/// the account — PURGES its sessions (immediate revocation). Ledgered `console.scim.user.update`.
fn apply_update(app: &App, uid: i64, attrs: &UserAttrs) -> Response {
    let (login, was_disabled) = {
        let store = app.store();
        ensure_schema(&store);
        match store.query_row(
            "SELECT u.login, u.disabled FROM users u JOIN scim_user s ON s.user_id = u.id WHERE u.id = ?",
            &crate::sql_params![uid],
            |r| Ok((r.get_str(0)?, r.get_i64(1)?)),
        ) {
            Ok((l, d)) => (l, d != 0),
            Err(_) => return scim_err(StatusCode::NOT_FOUND, "user not found", None),
        }
    };
    if crate::tenancy::is_superadmin_login(app, &login) {
        return scim_err(StatusCode::FORBIDDEN, "protected super-admin cannot be modified via SCIM", Some("mutability"));
    }

    // FAIL-CLOSED + ATOMIQUE (with_tx) : disable + purge + updates d'attributs tout-ou-rien. Un échec ->
    // ROLLBACK + 500 AVANT le ledger `console.scim.user.update` (sinon il attesterait un patch / une
    // désactivation / une purge de sessions jamais appliqués). `now_disabled`/`purged` (dérivés de l'INPUT,
    // pas du résultat d'écriture) sont retournés par la closure -> reflètent l'état RÉELLEMENT commité.
    let (now_disabled, purged) = {
        let store = app.store();
        match store.with_tx(|tx| {
            let mut now_disabled = was_disabled;
            let mut purged = false;
            if let Some(active) = attrs.active {
                let disabled = !active;
                tx.execute("UPDATE users SET disabled=? WHERE id=?", &crate::sql_params![disabled as i64, uid])?;
                now_disabled = disabled;
                // DISABLING (or a de-provision) must revoke access IMMEDIATELY → purge sessions.
                if disabled {
                    tx.execute("DELETE FROM session WHERE user_id=?", &crate::sql_params![uid])?;
                    purged = true;
                }
            }
            let now = crate::now_epoch();
            if let Some(v) = &attrs.external_id {
                tx.execute("UPDATE scim_user SET external_id=?, updated=? WHERE user_id=?", &crate::sql_params![v, now, uid])?;
            }
            if let Some(v) = &attrs.email {
                tx.execute("UPDATE scim_user SET email=?, updated=? WHERE user_id=?", &crate::sql_params![v, now, uid])?;
            }
            if let Some(v) = &attrs.given {
                tx.execute("UPDATE scim_user SET given_name=?, updated=? WHERE user_id=?", &crate::sql_params![v, now, uid])?;
            }
            if let Some(v) = &attrs.family {
                tx.execute("UPDATE scim_user SET family_name=?, updated=? WHERE user_id=?", &crate::sql_params![v, now, uid])?;
            }
            if let Some(v) = &attrs.display {
                tx.execute("UPDATE scim_user SET display_name=?, updated=? WHERE user_id=?", &crate::sql_params![v, now, uid])?;
            }
            Ok((now_disabled, purged))
        }) {
            Ok(v) => v,
            Err(e) => return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("update failed: {e}"), None),
        }
    };
    app.recompute_auth_required();
    app.bump_cache_epoch(); // B6 (HA): invalidate peers' auth_required cache (SCIM account patched)
    crate::append_console_ledger(
        app,
        "console.scim.user.update",
        json!({ "actor": "scim", "login": login, "active": attrs.active, "disabled": now_disabled, "sessions_purged": purged }),
    );
    match user_resource(app, uid) {
        Some(r) => scim_json(StatusCode::OK, r),
        None => scim_err(StatusCode::NOT_FOUND, "user not found", None),
    }
}

// ============================================================================================
// GROUPS (best-effort) — membership maps to a SCOPED role (ties to the advanced-RBAC slice). A group can
// only ever confer viewer|operator (never admin, never super-admin). When enterprise tenancy is engaged,
// membership additionally lands a scoped tenant_grant on the default tenant.
// ============================================================================================

/// GET /scim/v2/Groups — list groups.
async fn groups_list(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let ids: Vec<i64> = {
        let store = app.store();
        ensure_schema(&store);
        store.query_lax("SELECT id FROM scim_group ORDER BY id", &[], |r| r.get_i64(0)).unwrap_or_default()
    };
    let total = ids.len() as i64;
    let res: Vec<Value> = ids.into_iter().filter_map(|id| group_resource(&app, id)).collect();
    scim_json(
        StatusCode::OK,
        json!({ "schemas": [SCHEMA_LIST], "totalResults": total, "startIndex": 1, "itemsPerPage": res.len(), "Resources": res }),
    )
}

/// POST /scim/v2/Groups — create a group. `displayName` maps to a SCOPED role (`operator` if it mentions
/// "operator", else `viewer` — NEVER admin). Any `members` are applied immediately. Ledgered
/// `console.scim.group.create`.
async fn groups_create(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let res: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return scim_err(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}"), Some("invalidValue")),
    };
    let display = res.get("displayName").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if display.is_empty() {
        return scim_err(StatusCode::BAD_REQUEST, "displayName required", Some("invalidValue"));
    }
    let external_id = res.get("externalId").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // Role: prefer the CONFIGURABLE advanced-RBAC mapping for this group (clamped to viewer|operator —
    // SCIM never auto-confers console admin), else fall back to the legacy best-effort heuristic. When no
    // mapping is configured this is byte-identical to the previous behaviour.
    let role = crate::rbac::scim_role_for_group(&app, &display, &role_for_group(&display));
    let gid = {
        let store = app.store();
        ensure_schema(&store);
        let now = crate::now_epoch();
        // execute_returning_id : id du scim_group lu du MÊME INSERT (RETURNING id sur PG), sans lastval()
        // — session-indépendant, sûr sur backend poolé.
        match store.execute_returning_id(
            "INSERT INTO scim_group(display_name,external_id,role,created,updated) VALUES(?,?,?,?,?)",
            &crate::sql_params![&display, &external_id, &role, now, now],
        ) {
            Ok(id) => id,
            Err(e) => return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("create failed: {e}"), None),
        }
    };
    // Apply any initial members. FAIL-CLOSED (F8): a guard/write failure aborts BEFORE the ledger so a
    // `console.scim.group.create` is never emitted for a mutation that did not land.
    let member_ids = member_ids_from_resource(&res);
    for uid in &member_ids {
        if let Err(e) = add_member(&app, gid, *uid, &role) {
            return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("member add failed: {e}"), None);
        }
    }
    crate::append_console_ledger(
        &app,
        "console.scim.group.create",
        json!({ "actor": "scim", "display_name": display, "role": role, "members": member_ids.len() }),
    );
    match group_resource(&app, gid) {
        Some(r) => scim_json(StatusCode::CREATED, r),
        None => scim_err(StatusCode::INTERNAL_SERVER_ERROR, "created but could not render resource", None),
    }
}

/// GET /scim/v2/Groups/:id — one group.
async fn group_get(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let gid = match parse_id(&id) {
        Some(n) => n,
        None => return scim_err(StatusCode::NOT_FOUND, "group not found", None),
    };
    match group_resource(&app, gid) {
        Some(r) => scim_json(StatusCode::OK, r),
        None => scim_err(StatusCode::NOT_FOUND, "group not found", None),
    }
}

/// PUT/PATCH /scim/v2/Groups/:id — update membership. PUT replaces `members`; PATCH applies `Operations`
/// (add/remove members). Best-effort: recomputes each affected member's scoped role. Ledgered
/// `console.scim.group.update`.
async fn group_patch(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let gid = match parse_id(&id) {
        Some(n) => n,
        None => return scim_err(StatusCode::NOT_FOUND, "group not found", None),
    };
    let role = {
        let store = app.store();
        ensure_schema(&store);
        match store.query_row("SELECT role FROM scim_group WHERE id=?", &crate::sql_params![gid], |r| r.get_str(0)) {
            Ok(r) => r,
            Err(_) => return scim_err(StatusCode::NOT_FOUND, "group not found", None),
        }
    };
    let doc: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return scim_err(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}"), Some("invalidValue")),
    };
    // PUT replace: full members list. PATCH: Operations add/remove members.
    let mut added = 0usize;
    let mut removed = 0usize;
    if let Some(members) = doc.get("members").and_then(|m| m.as_array()) {
        // PUT-style full replace of membership.
        {
            let store = app.store();
            let _ = store.execute("DELETE FROM scim_group_member WHERE group_id=?", &crate::sql_params![gid]);
        }
        for uid in members.iter().filter_map(member_id_of) {
            if let Err(e) = add_member(&app, gid, uid, &role) {
                return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("member add failed: {e}"), None);
            }
            added += 1;
        }
    }
    if let Some(ops) = doc.get("Operations").and_then(|o| o.as_array()) {
        for op in ops {
            let action = op.get("op").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
            let path = op.get("path").and_then(|v| v.as_str()).unwrap_or("");
            // Members may be in `value` (array of {value:id}) or, for a remove, targeted by `path`.
            let vals = op.get("value");
            match action.as_str() {
                "add" | "replace" => {
                    if let Some(arr) = vals.and_then(|v| v.as_array()) {
                        for uid in arr.iter().filter_map(member_id_of) {
                            if let Err(e) = add_member(&app, gid, uid, &role) {
                                return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("member add failed: {e}"), None);
                            }
                            added += 1;
                        }
                    } else if let Some(uid) = vals.and_then(member_id_of) {
                        if let Err(e) = add_member(&app, gid, uid, &role) {
                            return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("member add failed: {e}"), None);
                        }
                        added += 1;
                    }
                }
                "remove" => {
                    // path like: members[value eq "42"]  → extract the id.
                    if let Some(uid) = extract_member_path_id(path).or_else(|| vals.and_then(member_id_of)) {
                        
                        let _ = app.store().execute("DELETE FROM scim_group_member WHERE group_id=? AND user_id=?", &crate::sql_params![gid, uid]);
                        removed += 1;
                    }
                }
                _ => {}
            }
        }
    }
    {
        let store = app.store();
        let _ = store.execute("UPDATE scim_group SET updated=? WHERE id=?", &crate::sql_params![crate::now_epoch(), gid]);
    }
    crate::append_console_ledger(
        &app,
        "console.scim.group.update",
        json!({ "actor": "scim", "group_id": gid, "added": added, "removed": removed }),
    );
    match group_resource(&app, gid) {
        Some(r) => scim_json(StatusCode::OK, r),
        None => scim_err(StatusCode::NOT_FOUND, "group not found", None),
    }
}

/// DELETE /scim/v2/Groups/:id — delete the group + its memberships (the users themselves are untouched).
async fn group_delete(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let gid = match parse_id(&id) {
        Some(n) => n,
        None => return scim_err(StatusCode::NOT_FOUND, "group not found", None),
    };
    {
        let store = app.store();
        ensure_schema(&store);
        if store.query_row("SELECT 1 FROM scim_group WHERE id=?", &crate::sql_params![gid], |_| Ok(())).is_err() {
            return scim_err(StatusCode::NOT_FOUND, "group not found", None);
        }
        // FAIL-CLOSED + ATOMIQUE : membres + groupe supprimés tout-ou-rien. Un échec -> ROLLBACK + 500 AVANT
        // le ledger `console.scim.group.delete` (sinon il attesterait une suppression jamais appliquée).
        if let Err(e) = store.with_tx(|tx| {
            tx.execute("DELETE FROM scim_group_member WHERE group_id=?", &crate::sql_params![gid])?;
            tx.execute("DELETE FROM scim_group WHERE id=?", &crate::sql_params![gid])?;
            Ok(())
        }) {
            return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("delete failed: {e}"), None);
        }
    }
    crate::append_console_ledger(&app, "console.scim.group.delete", json!({ "actor": "scim", "group_id": gid }));
    (StatusCode::NO_CONTENT, ()).into_response()
}

/// Add a user to a group and apply the group's SCOPED role. Bounded: only viewer|operator, and only to a
/// SCIM-managed user whose current role is NOT admin (SCIM never touches a local admin's role, and never
/// elevates to admin/super-admin). When enterprise tenancy is engaged, also land a scoped tenant_grant.
///
/// FAIL-CLOSED (SCIM F7/F8). F8: applies `guard_superadmin_user_mutation` (a designated super-admin is
/// never re-roled by SCIM) and PROPAGATES write errors (`Result`) so the caller can refuse to ledger a
/// mutation that never landed (no ledger↔DB divergence — mirrors the other SCIM write paths' hardening).
/// F7: SCOPES membership to SCIM-PROVISIONED users only — a `user_id` with no `scim_user` row is IGNORED
/// (never inserted into `scim_group_member`), so `Groups/:id` can never disclose a local account's login.
#[allow(clippy::significant_drop_tightening)]
fn add_member(app: &App, gid: i64, uid: i64, role: &str) -> Result<(), String> {
    // Resolve enterprise state + this group's CONFIGURABLE tenant grant BEFORE taking the db guard below.
    // Both read the db mutex; computing them up front avoids re-locking the (non-reentrant) guard while it
    // is held (`app.db()` returns a MutexGuard). `mapped_grant` (clamped to tenant_operator for SCIM) comes
    // from the advanced-RBAC group mapping; when unconfigured it is None => the legacy default (a scoped
    // grant on the default tenant #1) applies, byte-identical to before.
    let tenancy_on = crate::tenancy::enabled(app);
    let mapped_grant = if tenancy_on {
        let display: String = {
            let store = app.store();
            store.query_row("SELECT display_name FROM scim_group WHERE id=?", &crate::sql_params![gid], |r| r.get_str(0))
                .unwrap_or_default()
        };
        crate::rbac::scim_tenant_grants_for_group(app, &display).into_iter().next()
    } else {
        None
    };

    // Resolve the target login + SCIM-provisioned status in a SHORT-LIVED store scope, dropped BEFORE the
    // super-admin guard (which re-locks the store internally — the guard MUST run outside any held guard).
    let (login, is_scim): (Option<String>, bool) = {
        let store = app.store();
        let login = store.query_row("SELECT login FROM users WHERE id=?", &crate::sql_params![uid], |r| r.get_str(0)).ok();
        let is_scim = store
            .query_row("SELECT 1 FROM scim_user WHERE user_id=?", &crate::sql_params![uid], |_| Ok(()))
            .is_ok();
        (login, is_scim)
    };
    // F8 — designated super-admin protection (fail-closed). A SCIM group can never re-role a super-admin.
    if let Some(l) = &login {
        crate::tenancy::guard_superadmin_user_mutation(app, l, false, Some(role), false)?;
    }
    // F7 — membership is SCIM-scoped: a non-provisioned (local) account is never added to a SCIM group and
    // therefore never disclosed through the group's members list.
    if !is_scim {
        return Ok(());
    }

    let store = app.store();
    store
        .execute(
            "INSERT INTO scim_group_member(group_id,user_id) VALUES(?,?) ON CONFLICT DO NOTHING",
            &crate::sql_params![gid, uid],
        )
        .map_err(|e| format!("add member failed: {e}"))?;
    // Only re-role SCIM-managed, non-admin accounts (never elevate to admin/super-admin).
    let managed_nonadmin: bool = store
        .query_row(
            "SELECT 1 FROM users u JOIN scim_user s ON s.user_id=u.id WHERE u.id=? AND u.role != 'admin'",
            &crate::sql_params![uid],
            |_| Ok(()),
        )
        .is_ok();
    if managed_nonadmin && (role == "viewer" || role == "operator") {
        store
            .execute("UPDATE users SET role=? WHERE id=?", &crate::sql_params![role, uid])
            .map_err(|e| format!("re-role failed: {e}"))?;
        // Scoped tenant-grant when tenancy is engaged: the group's mapped grant (clamped to tenant_operator
        // — never tenant_admin via SCIM) if configured, else the default tenant #1 grant derived from role.
        if tenancy_on {
            let (tid, trole) = mapped_grant.clone().unwrap_or_else(|| {
                (1i64, if role == "operator" { "tenant_operator".to_string() } else { "tenant_viewer".to_string() })
            });
            store
                .execute(
                    "INSERT INTO tenant_grant(user_id,tenant_id,role,created)
                     VALUES(?,?,?,datetime('now'))
                     ON CONFLICT(user_id,tenant_id) DO UPDATE SET role=excluded.role",
                    &crate::sql_params![uid, tid, trole],
                )
                .map_err(|e| format!("tenant grant failed: {e}"))?;
        }
    }
    Ok(())
}

// ============================================================================================
// ServiceProviderConfig — IdP capability discovery (token-gated, fail-closed like every /scim route).
// ============================================================================================

async fn service_provider_config(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://forge.local/docs/scim",
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": 100 },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication via the SCIM bearer token (Authorization: Bearer <token>)."
            }]
        }),
    )
}

// ============================================================================================
// SCIM RESOURCE (de)serialization + mapping helpers.
// ============================================================================================

/// The subset of SCIM User attributes Forge round-trips. `None` = "not provided" (leave unchanged on
/// update); `Some` = an explicit value.
#[derive(Default)]
struct UserAttrs {
    user_name: Option<String>,
    external_id: Option<String>,
    active: Option<bool>,
    email: Option<String>,
    given: Option<String>,
    family: Option<String>,
    display: Option<String>,
}

impl UserAttrs {
    /// Parse a full SCIM User resource (POST / PUT body).
    fn from_resource(v: &Value) -> Self {
        UserAttrs {
            user_name: v.get("userName").and_then(|x| x.as_str()).map(|s| s.to_string()),
            external_id: v.get("externalId").and_then(|x| x.as_str()).map(|s| s.to_string()),
            active: v.get("active").and_then(coerce_bool),
            email: primary_email(v),
            given: v.get("name").and_then(|n| n.get("givenName")).and_then(|x| x.as_str()).map(|s| s.to_string()),
            family: v.get("name").and_then(|n| n.get("familyName")).and_then(|x| x.as_str()).map(|s| s.to_string()),
            display: v.get("displayName").and_then(|x| x.as_str()).map(|s| s.to_string()),
        }
    }

    /// Parse a SCIM PATCH document (`Operations`) into attribute changes. Handles op `replace`/`add` with
    /// either a `path` (e.g. `active`) or a value OBJECT (Okta sends `{value:{active:false}}`; Azure sends
    /// `{path:"active", value:"False"}`).
    fn from_patch(doc: &Value) -> Self {
        let mut a = UserAttrs::default();
        let ops = match doc.get("Operations").and_then(|o| o.as_array()) {
            Some(o) => o,
            None => return a,
        };
        for op in ops {
            let action = op.get("op").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
            if action != "replace" && action != "add" {
                continue;
            }
            let path = op.get("path").and_then(|v| v.as_str()).unwrap_or("").trim().trim_matches('"').to_ascii_lowercase();
            let val = op.get("value");
            if !path.is_empty() {
                match path.as_str() {
                    "active" => a.active = val.and_then(coerce_bool),
                    "externalid" => a.external_id = val.and_then(|v| v.as_str()).map(|s| s.to_string()),
                    "displayname" => a.display = val.and_then(|v| v.as_str()).map(|s| s.to_string()),
                    "name.givenname" => a.given = val.and_then(|v| v.as_str()).map(|s| s.to_string()),
                    "name.familyname" => a.family = val.and_then(|v| v.as_str()).map(|s| s.to_string()),
                    "emails" | "emails[primary eq true].value" => {
                        a.email = val.and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| primary_email_from_value(v)))
                    }
                    _ => {}
                }
            } else if let Some(obj) = val {
                // value is a partial resource object.
                if let Some(b) = obj.get("active").and_then(coerce_bool) {
                    a.active = Some(b);
                }
                if let Some(s) = obj.get("externalId").and_then(|x| x.as_str()) {
                    a.external_id = Some(s.to_string());
                }
                if let Some(s) = obj.get("displayName").and_then(|x| x.as_str()) {
                    a.display = Some(s.to_string());
                }
                if let Some(e) = primary_email(obj) {
                    a.email = Some(e);
                }
                if let Some(s) = obj.get("name").and_then(|n| n.get("givenName")).and_then(|x| x.as_str()) {
                    a.given = Some(s.to_string());
                }
                if let Some(s) = obj.get("name").and_then(|n| n.get("familyName")).and_then(|x| x.as_str()) {
                    a.family = Some(s.to_string());
                }
            }
        }
        a
    }
}

/// Coerce a SCIM boolean that may arrive as a real bool OR a string ("true"/"false", any case — Azure AD
/// sends the string form). None if uninterpretable.
fn coerce_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// The primary (or first) email value from a SCIM `emails` array on a resource.
fn primary_email(v: &Value) -> Option<String> {
    primary_email_from_value(v.get("emails")?)
}

fn primary_email_from_value(emails: &Value) -> Option<String> {
    let arr = emails.as_array()?;
    // Prefer primary==true, else the first with a value.
    arr.iter()
        .find(|e| e.get("primary").and_then(|p| p.as_bool()).unwrap_or(false))
        .and_then(|e| e.get("value").and_then(|x| x.as_str()))
        .or_else(|| arr.iter().find_map(|e| e.get("value").and_then(|x| x.as_str())))
        .map(|s| s.to_string())
}

/// Build a SCIM User resource JSON for a Forge user id (joined with its `scim_user` row). None if the id
/// is unknown OR the user is not SCIM-managed (no `scim_user` row).
fn user_resource(app: &App, uid: i64) -> Option<Value> {
    let store = app.store();
    let row = store
        .query_row(
            "SELECT u.login, u.role, u.disabled, u.created,
                    s.external_id, s.email, s.given_name, s.family_name, s.display_name
               FROM users u JOIN scim_user s ON s.user_id = u.id
              WHERE u.id = ?",
            &crate::sql_params![uid],
            |r| {
                Ok((
                    r.get_str(0)?,
                    r.get_str(1)?,
                    r.get_i64(2)?,
                    r.get_opt_str(3)?.unwrap_or_default(),
                    r.get_str(4)?,
                    r.get_str(5)?,
                    r.get_str(6)?,
                    r.get_str(7)?,
                    r.get_str(8)?,
                ))
            },
        )
        .ok()?;
    drop(store);
    let (login, role, disabled, created, external_id, email, given, family, display) = row;
    let mut res = json!({
        "schemas": [SCHEMA_USER],
        "id": uid.to_string(),
        "userName": login,
        "active": disabled == 0,
        "roles": [{ "value": role, "primary": true }],
        "meta": {
            "resourceType": "User",
            "location": format!("/scim/v2/Users/{uid}"),
            "created": created,
        },
    });
    if !external_id.is_empty() {
        res["externalId"] = json!(external_id);
    }
    if !email.is_empty() {
        res["emails"] = json!([{ "value": email, "primary": true }]);
    }
    if !given.is_empty() || !family.is_empty() || !display.is_empty() {
        res["name"] = json!({ "givenName": given, "familyName": family });
    }
    if !display.is_empty() {
        res["displayName"] = json!(display);
    }
    Some(res)
}

/// Build a SCIM Group resource for a group id (with its members). None if unknown.
fn group_resource(app: &App, gid: i64) -> Option<Value> {
    let store = app.store();
    let (display, external_id): (String, String) = store
        .query_row("SELECT display_name, external_id FROM scim_group WHERE id=?", &crate::sql_params![gid], |r| Ok((r.get_str(0)?, r.get_str(1)?)))
        .ok()?;
    // F7 (defence in depth): JOIN `scim_user` so ONLY SCIM-provisioned members are disclosed — a local
    // (non-SCIM) account can never be surfaced through a group's members list, even if a stale
    // `scim_group_member` row exists (mirrors `users_list`, which already JOINs `scim_user`).
    let members: Vec<Value> = store
        .query_lax(
            "SELECT u.id, u.login FROM scim_group_member m \
             JOIN users u ON u.id=m.user_id \
             JOIN scim_user s ON s.user_id=u.id \
             WHERE m.group_id=? ORDER BY u.id",
            &crate::sql_params![gid],
            |r| {
                let id: i64 = r.get_i64(0)?;
                let login: String = r.get_str(1)?;
                Ok(json!({ "value": id.to_string(), "display": login }))
            },
        )
        .ok()?;
    drop(store);
    let mut res = json!({
        "schemas": [SCHEMA_GROUP],
        "id": gid.to_string(),
        "displayName": display,
        "members": members,
        "meta": { "resourceType": "Group", "location": format!("/scim/v2/Groups/{gid}") },
    });
    if !external_id.is_empty() {
        res["externalId"] = json!(external_id);
    }
    Some(res)
}

/// The scoped default role for a SCIM-provisioned user: `settings.scim.default_role` if set to a valid
/// scoped role (viewer|operator), else `viewer`. NEVER admin (SCIM does not auto-provision admins).
fn default_role(app: &App) -> String {
    let store = app.store();
    match crate::settings_get_store(&store, DEFAULT_ROLE_KEY).as_deref() {
        Some("operator") => "operator".to_string(),
        _ => "viewer".to_string(),
    }
}

/// Map a group displayName to a SCOPED Forge role — `operator` if it clearly names operators, else
/// `viewer`. NEVER admin/super-admin (a SCIM group cannot confer admin — hard bound).
fn role_for_group(display: &str) -> String {
    if display.to_ascii_lowercase().contains("operator") {
        "operator".to_string()
    } else {
        "viewer".to_string()
    }
}

/// Derive a Forge login (`[A-Za-z0-9._-]{1,64}`, no leading separator) from a SCIM `userName` (often an
/// email), falling back to `externalId`. Lowercases, `@`→`.`, other disallowed chars→`-`, trims leading
/// separators, truncates to 64, then enforces `validate_login`. Fail-closed if nothing valid remains.
fn derive_login(user_name: &str, external_id: &str) -> Result<String, String> {
    let raw = if !user_name.trim().is_empty() { user_name } else { external_id };
    if raw.trim().is_empty() {
        return Err("userName (or externalId) required".to_string());
    }
    let mut s = String::with_capacity(raw.len());
    for c in raw.trim().to_ascii_lowercase().chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            s.push(c);
        } else if c == '@' {
            s.push('.');
        } else {
            s.push('-');
        }
    }
    let s: String = s.trim_start_matches(['-', '.']).chars().take(64).collect();
    crate::validate_login(&s).map_err(|e| format!("cannot derive a valid login from userName: {e}"))
}

/// Parse a single `userName eq "value"` SCIM filter → the value. None for anything else (we only support
/// the equality-on-userName probe Okta/Azure use before create).
fn parse_username_filter(filter: &str) -> Option<String> {
    let f = filter.trim();
    let lower = f.to_ascii_lowercase();
    let rest = lower.strip_prefix("username")?.trim_start();
    let rest = rest.strip_prefix("eq")?.trim_start();
    // The value keeps original case → slice from the same offset in the original string.
    let val_start = f.len() - rest.len();
    let val = f[val_start..].trim().trim_matches('"').to_string();
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

/// A member id from a SCIM member entry (`{"value": "42"}`) → i64. None if absent/unparseable.
fn member_id_of(m: &Value) -> Option<i64> {
    m.get("value").and_then(|v| v.as_str()).and_then(|s| s.trim().parse::<i64>().ok())
}

/// All member ids from a Group resource's `members` array.
fn member_ids_from_resource(res: &Value) -> Vec<i64> {
    res.get("members")
        .and_then(|m| m.as_array())
        .map(|a| a.iter().filter_map(member_id_of).collect())
        .unwrap_or_default()
}

/// Extract the user id from a PATCH remove path like `members[value eq "42"]`.
fn extract_member_path_id(path: &str) -> Option<i64> {
    let start = path.find('"')? + 1;
    let end = path[start..].find('"')? + start;
    path[start..end].trim().parse::<i64>().ok()
}

/// Parse a SCIM resource id (string) into the Forge integer id. None if not a positive integer.
fn parse_id(id: &str) -> Option<i64> {
    id.trim().parse::<i64>().ok().filter(|&n| n > 0)
}

/// CSPRNG hex of `nbytes` bytes (OS entropy). Panics on entropy failure rather than emit a weak secret
/// (fail-closed on entropy — mirrors sso::rand_hex / gen_session_token).
fn rand_hex(nbytes: usize) -> String {
    let mut b = vec![0u8; nbytes];
    getrandom::getrandom(&mut b).expect("CSPRNG (getrandom) unavailable — refusing to emit a weak SCIM secret");
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::App;
    use rusqlite::Connection;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    // ---- minimal HTTP helpers (self-contained; mirror sso.rs's test harness) ----
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
    fn body_req(method: &str, path: &str, body: &str, extra: &str) -> String {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/scim+json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
    }
    fn parse_status(resp: &str) -> u16 {
        resp.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).unwrap_or(0)
    }
    fn body_of(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }
    fn json_of(resp: &str) -> Value {
        serde_json::from_str(body_of(resp)).unwrap_or(json!({}))
    }
    fn bearer_hdr(tok: &str) -> String {
        format!("Authorization: Bearer {tok}\r\n")
    }

    fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        p.push(uniq);
        p.to_string_lossy().into_owned()
    }

    /// App backed by an in-memory DB (mirrors sso::tests::sso_test_app).
    fn scim_test_app(ledger_path: &str) -> App {
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

    /// Engage the enterprise SCIM flag on THIS db (per-DB, isolated — no env mutation).
    fn engage_flag(app: &App) {
        let db = app.db();
        crate::settings_set(&db, "enterprise.scim", "on").unwrap();
    }

    /// Set a SCIM bearer token directly (store its SHA). Returns the raw token.
    fn set_token(app: &App, raw: &str) {
        let db = app.db();
        crate::settings_set(&db, TOKEN_KEY, &crate::sha_hex(raw)).unwrap();
    }

    /// Provision a local admin + open an admin session; returns the session token.
    fn admin_session(app: &App) -> String {
        let hash = crate::hash_pw("adminpw");
        let db = app.db();
        crate::upsert_user(&db, "root", "admin", &hash).unwrap();
        let id: i64 = db.query_row("SELECT id FROM users WHERE login=?", ["root"], |r| r.get(0)).unwrap();
        drop(db);
        app.recompute_auth_required();
        crate::create_session(app, id).0
    }

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

    fn scim_user_body(user_name: &str, active: bool, external_id: &str) -> String {
        json!({
            "schemas": [SCHEMA_USER],
            "userName": user_name,
            "externalId": external_id,
            "active": active,
            "name": { "givenName": "Alice", "familyName": "Example" },
            "emails": [{ "value": user_name, "primary": true }],
        })
        .to_string()
    }

    // ------------------------------------------------------------------------------------------------
    // 1) HAPPY PATH — POST /scim/v2/Users with a valid token creates a Forge user; it is ledgered.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn valid_token_creates_forge_user_and_ledgers() {
        let ledger = tmp_path("scim-create-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "scim-secret-token-value");
        let addr = serve(app.clone()).await;

        let body = scim_user_body("Alice@Corp.com", true, "okta-0001");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("scim-secret-token-value"))).await;
        assert_eq!(parse_status(&r), 201, "valid SCIM create should 201: {r}");
        let v = json_of(&r);
        assert_eq!(v["userName"], "alice.corp.com", "userName→login mapping: {v}");
        assert_eq!(v["active"], true, "created active: {v}");
        assert_eq!(v["externalId"], "okta-0001");
        // Content type is SCIM.
        assert!(r.to_ascii_lowercase().contains("application/scim+json"), "scim content type: {r}");

        // Forge user really exists, ENABLED, with the SCOPED default role (viewer — never admin).
        {
            
            let (role, disabled): (String, i64) = app.db()
                .query_row("SELECT role, disabled FROM users WHERE login=?", ["alice.corp.com"], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("forge user created");
            assert_eq!(role, "viewer", "scoped default role, never admin");
            assert_eq!(disabled, 0, "created enabled");
        }

        // Ledgered console.scim.user.create — token NEVER present.
        let lines = crate::read_ledger_lines(&ledger);
        let last = lines.last().expect("ledger entry");
        assert_eq!(last["kind"], "console.scim.user.create");
        assert_eq!(last["detail"]["login"], "alice.corp.com");
        assert_eq!(last["detail"]["active"], true);
        let ser = serde_json::to_string(&lines).unwrap();
        assert!(!ser.contains("scim-secret-token-value"), "SCIM token must never be ledgered");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 2) FAIL-CLOSED — no token / wrong token ⇒ 401 (no user created).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn missing_or_wrong_token_is_401() {
        let ledger = tmp_path("scim-401-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "the-real-token");
        let addr = serve(app.clone()).await;
        let body = scim_user_body("bob@corp.com", true, "ext-2");

        // No Authorization header.
        let r0 = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, "")).await;
        assert_eq!(parse_status(&r0), 401, "missing token → 401: {r0}");
        // Wrong token.
        let r1 = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("not-the-token"))).await;
        assert_eq!(parse_status(&r1), 401, "wrong token → 401: {r1}");
        // A GET is equally fail-closed.
        let r2 = http_raw(addr, &get_req("/scim/v2/Users", &bearer_hdr("nope"))).await;
        assert_eq!(parse_status(&r2), 401, "wrong token on GET → 401: {r2}");

        // No user was created by any of the rejected requests.
        {
            
            let n: i64 = app.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "no user created under failed auth");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 3) FAIL-CLOSED (unconfigured) — flag ON but NO token set ⇒ 401 even with an Authorization header.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn no_token_configured_is_401() {
        let ledger = tmp_path("scim-noconf-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app); // flag ON but token NOT provisioned
        let addr = serve(app).await;
        let r = http_raw(addr, &get_req("/scim/v2/Users", &bearer_hdr("anything"))).await;
        assert_eq!(parse_status(&r), 401, "no token configured → 401: {r}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 4) DE-PROVISION — active=false (PATCH) disables the user AND purges its sessions (immediate).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn deactivate_disables_and_purges_sessions() {
        let ledger = tmp_path("scim-deact-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-deact");
        let addr = serve(app.clone()).await;

        // Create the user via SCIM.
        let body = scim_user_body("carol@corp.com", true, "ext-carol");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("tok-deact"))).await;
        assert_eq!(parse_status(&r), 201, "create: {r}");
        let uid: i64 = json_of(&r)["id"].as_str().unwrap().parse().unwrap();

        // Open a live session for that user, and prove it resolves.
        let sess = crate::create_session(&app, uid).0;
        let w = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={sess}\r\n"))).await;
        assert!(body_of(&w).contains("\"login\":\"carol.corp.com\""), "session live pre-deactivation: {}", body_of(&w));

        // SCIM PATCH active=false (Azure-style string value to exercise coercion).
        let patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "replace", "path": "active", "value": "False" }]
        })
        .to_string();
        let p = http_raw(addr, &body_req("PATCH", &format!("/scim/v2/Users/{uid}"), &patch, &bearer_hdr("tok-deact"))).await;
        assert_eq!(parse_status(&p), 200, "patch deactivate: {p}");
        assert_eq!(json_of(&p)["active"], false, "resource now inactive: {}", body_of(&p));

        // User disabled + session purged (immediate revocation).
        {
            let db = app.db();
            let disabled: i64 = db.query_row("SELECT disabled FROM users WHERE id=?", [uid], |r| r.get(0)).unwrap();
            assert_eq!(disabled, 1, "user disabled");
            let sessions: i64 = db.query_row("SELECT COUNT(*) FROM session WHERE user_id=?", [uid], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(sessions, 0, "sessions purged");
        }
        // And the (now-purged) session no longer authenticates.
        let w2 = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={sess}\r\n"))).await;
        assert!(body_of(&w2).contains("\"authenticated\":false"), "purged session dead: {}", body_of(&w2));

        // Ledgered as an update with sessions_purged=true.
        let lines = crate::read_ledger_lines(&ledger);
        let last = lines.last().expect("ledger");
        assert_eq!(last["kind"], "console.scim.user.update");
        assert_eq!(last["detail"]["sessions_purged"], true);
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 4b) DELETE de-provisions: disables + purges + no longer SCIM-managed (subsequent GET 404).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn delete_deprovisions_user() {
        let ledger = tmp_path("scim-del-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-del");
        let addr = serve(app.clone()).await;
        let body = scim_user_body("dave@corp.com", true, "ext-dave");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("tok-del"))).await;
        let uid: i64 = json_of(&r)["id"].as_str().unwrap().parse().unwrap();
        let sess = crate::create_session(&app, uid).0;

        let d = http_raw(addr, &body_req("DELETE", &format!("/scim/v2/Users/{uid}"), "", &bearer_hdr("tok-del"))).await;
        assert_eq!(parse_status(&d), 204, "delete → 204: {d}");
        {
            let db = app.db();
            let disabled: i64 = db.query_row("SELECT disabled FROM users WHERE id=?", [uid], |r| r.get(0)).unwrap();
            assert_eq!(disabled, 1, "user disabled after delete");
            let sessions: i64 = db.query_row("SELECT COUNT(*) FROM session WHERE user_id=?", [uid], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(sessions, 0, "sessions purged after delete");
        }
        let _ = sess;
        // No longer SCIM-managed → GET now 404.
        let g = http_raw(addr, &get_req(&format!("/scim/v2/Users/{uid}"), &bearer_hdr("tok-del"))).await;
        assert_eq!(parse_status(&g), 404, "deprovisioned user GET → 404: {g}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 5) TOKEN HASHED / REDACTED — rotate returns the token ONCE; DB stores only the hash; GET redacts.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn token_is_hashed_and_redacted() {
        let ledger = tmp_path("scim-tok-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        let admin_tok = admin_session(&app);
        let addr = serve(app.clone()).await;
        let auth = bearer_hdr(&admin_tok);

        // Rotate a token via the admin config route.
        let rot = http_raw(addr, &body_req("POST", "/api/scim/config", "{\"rotate\":true}", &auth)).await;
        assert_eq!(parse_status(&rot), 200, "rotate: {rot}");
        let raw = json_of(&rot)["token"].as_str().expect("raw token returned once").to_string();
        assert!(raw.len() >= 32, "token looks random: {raw}");

        // DB stores the SHA, never the raw token.
        {
            
            let stored = crate::settings_get(&app.db(), TOKEN_KEY).unwrap();
            assert_eq!(stored, crate::sha_hex(&raw), "DB stores SHA of the token");
            assert_ne!(stored, raw, "DB does not store the raw token");
        }
        // GET config never returns the token, only presence.
        let g = http_raw(addr, &get_req("/api/scim/config", &auth)).await;
        assert_eq!(parse_status(&g), 200, "config get: {g}");
        assert!(!body_of(&g).contains(&raw), "GET must not echo the token: {}", body_of(&g));
        assert_eq!(json_of(&g)["token_set"], true, "presence flagged");

        // Ledger never carries the token.
        let lines = crate::read_ledger_lines(&ledger);
        assert!(!serde_json::to_string(&lines).unwrap().contains(&raw), "token never ledgered");

        // And the rotated token actually authenticates a SCIM call.
        let body = scim_user_body("erin@corp.com", true, "ext-erin");
        let c = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr(&raw))).await;
        assert_eq!(parse_status(&c), 201, "rotated token authenticates: {c}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 6) FLAG OFF — every /scim/* and /api/scim/config route is disabled (404), even with a valid token.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn flag_off_disables_scim() {
        let ledger = tmp_path("scim-off-ledger");
        let app = scim_test_app(&ledger);
        // NOTE: flag NOT engaged. Even set a token in the DB to prove the flag — not the token — gates.
        set_token(&app, "valid-but-flag-off");
        // Provision a local admin so /api/login stays exercised as byte-identical community behaviour.
        {
            let hash = crate::hash_pw("localpw");
            let db = app.db();
            crate::upsert_user(&db, "root", "admin", &hash).unwrap();
        }
        app.recompute_auth_required();
        let addr = serve(app).await;

        for (method, path) in [
            ("GET", "/scim/v2/Users"),
            ("GET", "/scim/v2/Users/1"),
            ("GET", "/scim/v2/Groups"),
            ("GET", "/scim/v2/ServiceProviderConfig"),
            ("GET", "/api/scim/config"),
        ] {
            let req = if method == "GET" {
                get_req(path, &bearer_hdr("valid-but-flag-off"))
            } else {
                body_req(method, path, "{}", &bearer_hdr("valid-but-flag-off"))
            };
            let r = http_raw(addr, &req).await;
            assert_eq!(parse_status(&r), 404, "flag off → {method} {path} disabled (404): {r}");
        }
        // POST create is also absent.
        let c = http_raw(
            addr,
            &body_req("POST", "/scim/v2/Users", &scim_user_body("x@y.com", true, "e"), &bearer_hdr("valid-but-flag-off")),
        )
        .await;
        assert_eq!(parse_status(&c), 404, "flag off → POST /scim/v2/Users disabled: {c}");

        // LOCAL login is unchanged.
        let lr = http_raw(addr, &format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            "{\"login\":\"root\",\"password\":\"localpw\"}".len(),
            "{\"login\":\"root\",\"password\":\"localpw\"}"
        )).await;
        assert_eq!(parse_status(&lr), 200, "local login still works: {lr}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 7) GET filter + PUT reactivation round-trip.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn filter_and_put_reactivate() {
        let ledger = tmp_path("scim-filter-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-f");
        let addr = serve(app.clone()).await;
        let body = scim_user_body("frank@corp.com", true, "ext-frank");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("tok-f"))).await;
        let uid: i64 = json_of(&r)["id"].as_str().unwrap().parse().unwrap();

        // Filter by userName (login) → exactly one result.
        let f = http_raw(
            addr,
            &get_req("/scim/v2/Users?filter=userName%20eq%20%22frank.corp.com%22", &bearer_hdr("tok-f")),
        )
        .await;
        assert_eq!(parse_status(&f), 200, "filter list: {f}");
        assert_eq!(json_of(&f)["totalResults"], 1, "one match: {}", body_of(&f));

        // Filter miss → zero.
        let f0 = http_raw(addr, &get_req("/scim/v2/Users?filter=userName%20eq%20%22nobody%22", &bearer_hdr("tok-f"))).await;
        assert_eq!(json_of(&f0)["totalResults"], 0, "no match: {}", body_of(&f0));

        // PUT active=false then active=true reactivates.
        let put_off = json!({ "schemas": [SCHEMA_USER], "userName": "frank@corp.com", "active": false }).to_string();
        let _ = http_raw(addr, &body_req("PUT", &format!("/scim/v2/Users/{uid}"), &put_off, &bearer_hdr("tok-f"))).await;
        let put_on = json!({ "schemas": [SCHEMA_USER], "userName": "frank@corp.com", "active": true }).to_string();
        let on = http_raw(addr, &body_req("PUT", &format!("/scim/v2/Users/{uid}"), &put_on, &bearer_hdr("tok-f"))).await;
        assert_eq!(json_of(&on)["active"], true, "reactivated: {}", body_of(&on));
        {
            
            let disabled: i64 = app.db().query_row("SELECT disabled FROM users WHERE id=?", [uid], |r| r.get(0)).unwrap();
            assert_eq!(disabled, 0, "user re-enabled");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 8) SUPER-ADMIN PROTECTION — SCIM cannot create a designated super-admin login.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn scim_cannot_provision_superadmin() {
        let ledger = tmp_path("scim-sa-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-sa");
        {
            let db = app.db();
            // Designate 'root.corp.com' as a super-admin (provisioning-only key).
            crate::settings_set(&db, "enterprise.superadmin", "root.corp.com").unwrap();
        }
        let addr = serve(app.clone()).await;
        let body = scim_user_body("root@corp.com", true, "ext-root");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("tok-sa"))).await;
        assert_eq!(parse_status(&r), 403, "SCIM cannot provision a super-admin login: {r}");
        {
            
            let n: i64 = app.db().query_row("SELECT COUNT(*) FROM users WHERE login=?", ["root.corp.com"], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "no super-admin account created via SCIM");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 9) SCIM F7 — a group's members list NEVER discloses a local (non-SCIM) account, and a non-SCIM
    //    user is never added to a SCIM group (membership is SCIM-scoped).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn group_members_does_not_disclose_local_account() {
        let ledger = tmp_path("scim-f7-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-f7");
        // A LOCAL (non-SCIM) admin — must never surface through a SCIM group members list.
        let local_uid: i64 = {
            let db = app.db();
            let hash = crate::hash_pw("localpw");
            crate::upsert_user(&db, "localadmin", "admin", &hash).unwrap();
            db.query_row("SELECT id FROM users WHERE login=?", ["localadmin"], |r| r.get(0)).unwrap()
        };
        let addr = serve(app.clone()).await;
        // Provision a genuine SCIM user (gets a scim_user row).
        let cr = http_raw(
            addr,
            &body_req("POST", "/scim/v2/Users", &scim_user_body("scimuser@corp.com", true, "ext-s"), &bearer_hdr("tok-f7")),
        )
        .await;
        assert_eq!(parse_status(&cr), 201, "scim user created: {cr}");
        let scim_uid = json_of(&cr)["id"].as_str().unwrap().to_string();
        // Create a group whose members include BOTH the local admin and the SCIM user.
        let gbody = json!({
            "schemas": [SCHEMA_GROUP],
            "displayName": "Forge Readers",
            "members": [{ "value": local_uid.to_string() }, { "value": scim_uid }],
        })
        .to_string();
        let gr = http_raw(addr, &body_req("POST", "/scim/v2/Groups", &gbody, &bearer_hdr("tok-f7"))).await;
        assert_eq!(parse_status(&gr), 201, "group created: {gr}");
        // The local (non-SCIM) admin must NOT appear; the SCIM member does.
        assert!(!body_of(&gr).contains("localadmin"), "local admin login must NOT be disclosed: {}", body_of(&gr));
        assert!(body_of(&gr).contains("scimuser.corp.com"), "SCIM member disclosed: {}", body_of(&gr));
        // The local admin's role is untouched, and it was never inserted into scim_group_member.
        {
            let db = app.db();
            let role: String = db.query_row("SELECT role FROM users WHERE id=?", [local_uid], |r| r.get(0)).unwrap();
            let n: i64 = db.query_row("SELECT COUNT(*) FROM scim_group_member WHERE user_id=?", [local_uid], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(role, "admin", "local admin role untouched by SCIM");
            assert_eq!(n, 0, "non-SCIM user never added to a SCIM group");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 10) SCIM F8 — add_member is guarded against mutating a designated super-admin; the op fails BEFORE
    //     ledgering and the super-admin's role is never downgraded.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn group_add_member_guards_superadmin() {
        let ledger = tmp_path("scim-f8-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-f8");
        let sa_uid: i64 = {
            let db = app.db();
            crate::settings_set(&db, "enterprise.superadmin", "super.admin").unwrap();
            let hash = crate::hash_pw("sapw");
            crate::upsert_user(&db, "super.admin", "admin", &hash).unwrap();
            db.query_row("SELECT id FROM users WHERE login=?", ["super.admin"], |r| r.get(0)).unwrap()
        };
        let addr = serve(app.clone()).await;
        let before = crate::read_ledger_lines(&ledger).len();
        // "Forge Operators" -> operator role; adding the super-admin must be guarded (op fails).
        let gbody = json!({
            "schemas": [SCHEMA_GROUP],
            "displayName": "Forge Operators",
            "members": [{ "value": sa_uid.to_string() }],
        })
        .to_string();
        let gr = http_raw(addr, &body_req("POST", "/scim/v2/Groups", &gbody, &bearer_hdr("tok-f8"))).await;
        assert_eq!(parse_status(&gr), 500, "super-admin member add is guarded (op fails): {gr}");
        {
            let db = app.db();
            let role: String = db.query_row("SELECT role FROM users WHERE id=?", [sa_uid], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(role, "admin", "super-admin role NEVER downgraded by SCIM group");
        }
        // No group.create ledger for the aborted op (guard fired before ledgering).
        let lines = crate::read_ledger_lines(&ledger);
        assert_eq!(lines.len(), before, "guarded op does not ledger a mutation");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 11) UNIT — pure helpers.
    // ------------------------------------------------------------------------------------------------
    #[test]
    fn unit_helpers() {
        assert_eq!(derive_login("Alice@Corp.com", "").unwrap(), "alice.corp.com");
        assert_eq!(derive_login("", "okta|abc").unwrap(), "okta-abc");
        assert!(derive_login("", "").is_err());
        assert_eq!(parse_username_filter("userName eq \"Bob@x.com\"").as_deref(), Some("Bob@x.com"));
        assert_eq!(parse_username_filter("displayName eq \"x\""), None);
        assert_eq!(coerce_bool(&json!(false)), Some(false));
        assert_eq!(coerce_bool(&json!("False")), Some(false));
        assert_eq!(coerce_bool(&json!("TRUE")), Some(true));
        assert_eq!(coerce_bool(&json!(3)), None);
        assert_eq!(role_for_group("Forge Operators"), "operator");
        assert_eq!(role_for_group("readers"), "viewer");
        assert_eq!(extract_member_path_id("members[value eq \"42\"]"), Some(42));
        assert_eq!(parse_id("7"), Some(7));
        assert_eq!(parse_id("0"), None);
        assert_eq!(parse_id("abc"), None);
        // PATCH value-object form (Okta deprovision).
        let doc = json!({"Operations":[{"op":"replace","value":{"active":false}}]});
        assert_eq!(UserAttrs::from_patch(&doc).active, Some(false));
    }

    /// FAIL-CLOSED (user_delete de-provision — écriture avalée corrigée) — INJECTION D'ÉCHEC : un trigger
    /// `BEFORE DELETE ON scim_user RAISE(ABORT)` fait ÉCHOUER la séquence de de-provision (`with_tx`). Le
    /// handler DOIT alors : (a) renvoyer 500 (PAS un faux 204), (b) N'ÉCRIRE AUCUNE entrée ledger
    /// `console.scim.user.delete` (anti divergence ledger↔DB — la piste tamper-evident ne doit jamais
    /// attester une de-provision qui n'a pas eu lieu), (c) laisser le compte INTOUCHÉ (ROLLBACK : toujours
    /// SCIM-managed, NON désactivé). Régression directe du write avalé (`let _ = store.execute`).
    #[tokio::test]
    async fn user_delete_db_failure_500_and_no_ledger() {
        let ledger = tmp_path("scim-del-fail-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "scim-secret-token-value");
        let addr = serve(app.clone()).await;
        // provisionne un user SCIM (mapping scim_user présent) via le vrai chemin POST.
        let body = scim_user_body("Bob@Corp.com", true, "okta-bob");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("scim-secret-token-value"))).await;
        assert_eq!(parse_status(&r), 201, "seed create doit 201: {r}");
        let uid: i64 = app.db().query_row("SELECT id FROM users WHERE login=?", ["bob.corp.com"], |r| r.get(0)).unwrap();
        // injecte l'échec d'ÉCRITURE : tout DELETE de scim_user est ABORTé (les SELECT/existence restent OK).
        app.db().execute_batch(
            "CREATE TRIGGER t_block_del_scim BEFORE DELETE ON scim_user BEGIN SELECT RAISE(ABORT,'boom'); END;"
        ).unwrap();
        let before = crate::read_ledger_lines(&ledger).len();

        let r = http_raw(addr, &body_req("DELETE", &format!("/scim/v2/Users/{uid}"), "", &bearer_hdr("scim-secret-token-value"))).await;
        assert_eq!(parse_status(&r), 500, "de-provision échouée -> 500 (PAS un faux 204): {r}");

        // (b) aucune entrée ledger ajoutée (ne ledgerise PAS une de-provision non appliquée).
        let lines = crate::read_ledger_lines(&ledger);
        assert_eq!(lines.len(), before, "un échec d'écriture NE ledgerise PAS");
        if let Some(last) = lines.last() {
            assert_ne!(last["kind"], "console.scim.user.delete", "aucune attestation de de-provision");
        }
        // (c) ROLLBACK : le compte reste SCIM-managed ET non désactivé (aucune mutation partielle).
        let (disabled, mapped): (i64, i64) = app.db().query_row(
            "SELECT u.disabled, (SELECT COUNT(*) FROM scim_user s WHERE s.user_id=u.id) FROM users u WHERE u.id=?",
            [uid], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(disabled, 0, "ROLLBACK : compte NON désactivé");
        assert_eq!(mapped, 1, "ROLLBACK : mapping scim_user intact (toujours SCIM-managed)");
    }
}

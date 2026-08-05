// SPDX-License-Identifier: AGPL-3.0-or-later
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
            "/scim/v2/Users/{id}",
            get(user_get).put(user_put).patch(user_patch).delete(user_delete),
        )
        .route("/scim/v2/Groups", get(groups_list).post(groups_create))
        .route(
            "/scim/v2/Groups/{id}",
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
// § USERS / § GROUPS — EXTRAITES dans `scim/users.rs` et `scim/groups.rs` (PURE MOVE, corps
// byte-identiques). Les deux sections sont DISJOINTES : aucun symbole de l'une n'est référencé par
// l'autre (vérifié symbole par symbole), et leurs helpers privés respectifs — `apply_update` (USERS)
// et `add_member` (GROUPS) — n'ont d'appelant que dans leur propre section : ils voyagent avec elle.
// Les helpers PARTAGÉS (`scim_err` 44 réf., `gate`, `parse_id`, `scim_json`, `ensure_schema`,
// `user_resource`, `group_resource`, `UserAttrs`+son `impl`, `derive_login`, `coerce_bool`, …)
// RESTENT ICI, comme `cli/mod.rs` garde `print_table` : enfants de `scim`, les deux modules voient
// les items PRIVÉS du parent — aucun bump de visibilité dans ce sens.
// Le sens INVERSE en exige : `routes()` (ci-dessus) nomme les 11 handlers, et le parent n'est PAS un
// descendant — d'où `pub(super)` sur eux seuls, réimportés ici par les deux globs.
// ============================================================================================
mod users;
mod groups;
use users::*;
use groups::*;

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

/// CSPRNG hex of `nbytes` bytes — delegates to the SHARED `common::rand_hex` (dedup Wave; byte-identical).
/// `what="SCIM"` names the secret in the fail-closed entropy panic message.
fn rand_hex(nbytes: usize) -> String {
    crate::common::rand_hex(nbytes, "SCIM")
}


#[cfg(test)]
mod tests;

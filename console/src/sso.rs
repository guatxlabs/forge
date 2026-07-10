// SPDX-License-Identifier: AGPL-3.0-only
//! ENTERPRISE — OIDC SSO login (SEPARABLE, FLAG-GATED module).
//!
//! Open-core discipline (mirrors `tenancy.rs`): this is an ENTERPRISE feature. The COMMUNITY (default)
//! build behaves EXACTLY as today — LOCAL accounts only (`users` table + argon2id + `forge_session`
//! cookie + admin/operator/viewer RBAC). Every route here is a NO-OP (404 `not_found`) unless the
//! enterprise flag is ENGAGED (`enabled()` false => community, byte-identical). It never weakens the
//! open governance/audit surface; it only ADDS an OIDC Authorization-Code login path that, on success,
//! issues THE SAME `forge_session` cookie the local `/api/login` issues.
//!
//! FLOW (Authorization-Code + PKCE, fail-closed at every step):
//!   GET /api/sso/login    → build authorize URL (state + nonce + PKCE S256 challenge, all persisted
//!                           server-side per pending-auth in `sso_pending`), 302 to the IdP.
//!   GET /api/sso/callback → validate state (server-side, one-time), exchange code+code_verifier for
//!                           tokens at the token endpoint, VALIDATE the ID token (RS256 signature via
//!                           the IdP JWKS [jsonwebtoken], issuer, audience==client_id, exp, nonce), map
//!                           the OIDC subject/email to a Forge user (match existing or auto-provision),
//!                           issue the `forge_session` cookie, 302 to an ALLOWLISTED return target.
//!   GET/POST /api/sso/config → admin-gated OIDC provider config (client_secret WRITE-ONLY, redacted).
//!
//! SECURITY (fail-closed — weaken any check and a test flips RED):
//!   - reject on any state / nonce / issuer / audience / signature / exp mismatch (403);
//!   - only redirect the browser to an ALLOWLISTED return target (mirrors the `oauth.flow`/`redirect.open`
//!     discipline — never an attacker-controlled open redirect);
//!   - the `client_secret`, the ID/access tokens and the authorization code are NEVER logged, ledgered,
//!     or returned by any GET (redacted / omitted);
//!   - flag OFF or SSO unconfigured => `/api/sso/*` disabled (404 / 403) and LOCAL login is unchanged.
//!
//! TLS note: OIDC discovery / JWKS / token endpoints are fetched via the crate's existing plaintext HTTP
//! client (`crate::http_get_blocking` + a sibling POST helper). Per the repo's transport discipline (see
//! `http_get_blocking`), TLS is terminated upstream (reverse proxy) — point the issuer at the IdP's
//! internal `http://` endpoint (or a TLS-terminating forward proxy). The ID token itself is still fully
//! cryptographically validated (RS256 over JWKS), independent of the fetch transport.

use crate::App;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

/// settings KV key holding the OIDC provider config (JSON object). `client_secret` is stored here
/// verbatim (same substrate as `detection_source`'s secret) but is NEVER returned/logged/ledgered.
const CFG_KEY: &str = "sso.config";
/// Requested OIDC scopes (space-separated). `openid` is mandatory; email/profile feed user mapping.
const SCOPES: &str = "openid email profile";
/// Lifetime of a pending-auth row (state/nonce/verifier) — short-lived, one-time. Purged on expiry.
const PENDING_TTL_SECS: i64 = 600;

// ============================================================================================
// FLAG — is enterprise OIDC SSO ENGAGED? Community default = OFF (local login only, byte-identical).
// Two sources (either engages it): env `FORGE_ENTERPRISE_SSO` (truthy) OR the per-DB config key
// `enterprise.sso` (on|1|true|yes). Config is per-DB so tests toggle it in isolation. Mirrors tenancy.
// ============================================================================================

/// Is enterprise OIDC SSO engaged?  false => community (every `/api/sso/*` route 404s, local login unchanged).
pub fn enabled(app: &App) -> bool {
    crate::flags::enterprise_enabled(app, "FORGE_ENTERPRISE_SSO", "enterprise.sso")
}

/// Is an interactive SSO login available right now?  true iff the flag is engaged AND the OIDC provider
/// is configured (so `/api/sso/login` would not 403). Drives the "Sign in with SSO" button on the
/// PRE-AUTH login screen (surfaced via `GET /api/setup/state`). PUBLIC signal — not a secret (it reveals
/// only that SSO is offered, exactly what the button itself does). false in the community default.
pub fn login_available(app: &App) -> bool {
    enabled(app) && load_config(app).is_some()
}

/// HTTP fetch timeout for discovery / JWKS / token exchange (env `FORGE_SSO_HTTP_TIMEOUT`, default 10s).
fn http_timeout() -> Duration {
    let secs = std::env::var("FORGE_SSO_HTTP_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(10);
    Duration::from_secs(secs)
}

// ============================================================================================
// CONFIG — OIDC provider settings (admin-gated to set). client_secret is write-only.
// ============================================================================================

/// Parsed, validated OIDC provider config. `None` from `load_config` means UNCONFIGURED (a required
/// field is missing) — the login/callback routes then 403 `sso_unconfigured` (fail-closed).
struct SsoConfig {
    issuer: String,
    client_id: String,
    client_secret: String,
    /// The OIDC `redirect_uri` registered at the IdP (this console's `/api/sso/callback`).
    redirect_uri: String,
    /// Allowlist of acceptable POST-LOGIN return targets (the browser is only ever redirected here).
    allowed_redirect_uris: Vec<String>,
    /// `match` (default) = the OIDC identity must map to an EXISTING Forge user; `auto` = auto-provision.
    provisioning: String,
    /// Role assigned to an auto-provisioned account (validated; default `viewer`).
    default_role: String,
    /// Which claim maps to the Forge login: `email` (default) or `sub`.
    user_claim: String,
}

/// Load + validate the stored config. Returns `None` (UNCONFIGURED) if issuer/client_id/client_secret/
/// redirect_uri is missing — the flow is disabled until an admin sets them.
fn load_config(app: &App) -> Option<SsoConfig> {
    let raw = {
        let store = app.store();
        crate::settings_get_store(&store, CFG_KEY)?
    };
    let v: Value = serde_json::from_str(&raw).ok()?;
    let issuer = v.get("issuer").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let client_id = v.get("client_id").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let client_secret = v.get("client_secret").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let redirect_uri = v.get("redirect_uri").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if issuer.is_empty() || client_id.is_empty() || client_secret.is_empty() || redirect_uri.is_empty() {
        return None; // unconfigured — fail-closed
    }
    let allowed_redirect_uris = v
        .get("allowed_redirect_uris")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let provisioning = v.get("provisioning").and_then(|x| x.as_str()).unwrap_or("match").to_string();
    let default_role = v.get("default_role").and_then(|x| x.as_str()).unwrap_or("viewer").to_string();
    let user_claim = v.get("user_claim").and_then(|x| x.as_str()).unwrap_or("email").to_string();
    Some(SsoConfig {
        issuer,
        client_id,
        client_secret,
        redirect_uri,
        allowed_redirect_uris,
        provisioning,
        default_role,
        user_claim,
    })
}

/// Standard typed-error response (shared substrate; byte-identical `{"error","why"}`). Never a secret.
fn err(status: StatusCode, code: &'static str, why: impl Into<String>) -> Response {
    crate::error::ApiError::new(status, code, why).into_response()
}

/// Flag-OFF response: the route behaves as ABSENT (community build shows no SSO surface).
fn disabled() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response()
}

// ============================================================================================
// ROUTES
// ============================================================================================

/// SSO routes. Merged into the OUTER router (alongside `/api/login`) so `login`/`callback` are reachable
/// WITHOUT a prior session (that is the whole point of SSO) — they self-gate on the flag + config. The
/// admin-only `config` routes bypass `auth_guard` too but enforce `check_admin` internally (fail-closed).
pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/sso/login", get(login_start))
        .route("/api/sso/callback", get(callback))
        .route("/api/sso/config", get(config_get).post(config_set))
}

/// GET /api/sso/login[?return_to=<url>] — start the Authorization-Code + PKCE flow. Validates the return
/// target against the allowlist UP FRONT (fail-closed), discovers the IdP endpoints, persists state +
/// nonce + code_verifier server-side, and 302-redirects to the IdP authorize endpoint.
async fn login_start(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !enabled(&app) {
        return disabled();
    }
    let cfg = match load_config(&app) {
        Some(c) => c,
        None => return err(StatusCode::FORBIDDEN, "sso_unconfigured", "OIDC SSO not configured"),
    };
    // Return target: explicit ?return_to, else the first allowlisted URI, else same-origin root.
    let return_to = q
        .get("return_to")
        .map(|s| s.to_string())
        .unwrap_or_else(|| cfg.allowed_redirect_uris.first().cloned().unwrap_or_else(|| "/".to_string()));
    if !redirect_allowed(&cfg, &return_to) {
        // mirror redirect.open / oauth.flow discipline — never carry an attacker-chosen redirect through login
        return err(StatusCode::FORBIDDEN, "redirect_not_allowed", "return_to is not in the allowlist");
    }

    // Discover the IdP endpoints (blocking IO off the async worker).
    let issuer = cfg.issuer.clone();
    let to = http_timeout();
    let disc = match tokio::task::spawn_blocking(move || discover_blocking(issuer, to)).await {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => return err(StatusCode::BAD_GATEWAY, "discovery_failed", e),
        Err(_) => return err(StatusCode::BAD_GATEWAY, "discovery_failed", "discovery task join error"),
    };

    // PKCE + anti-CSRF (state) + anti-replay (nonce). All persisted server-side per pending-auth.
    let state = rand_hex(32);
    let nonce = rand_hex(32);
    let code_verifier = rand_hex(32); // 64 hex chars — within the 43..128 PKCE range, unreserved charset
    let challenge = code_challenge(&code_verifier);
    {
        let store = app.store();
        ensure_schema(&store);
        let now = crate::now_epoch();
        // OR REPLACE -> ON CONFLICT DO UPDATE (portable PG). Équivalent EXACT : `sso_pending` = (state PK +
        // 7 colonnes), l'INSERT liste TOUTES les colonnes, aucun trigger DELETE ni FK ON DELETE CASCADE ->
        // DELETE-then-INSERT et UPDATE ciblé coïncident.
        let _ = store.execute(
            "INSERT INTO sso_pending(state,nonce,code_verifier,return_to,token_endpoint,jwks_uri,created,expires)
             VALUES(?,?,?,?,?,?,?,?)
             ON CONFLICT(state) DO UPDATE SET nonce=excluded.nonce, code_verifier=excluded.code_verifier, return_to=excluded.return_to, token_endpoint=excluded.token_endpoint, jwks_uri=excluded.jwks_uri, created=excluded.created, expires=excluded.expires",
            &crate::sql_params![
                &state,
                &nonce,
                &code_verifier,
                &return_to,
                &disc.token_endpoint,
                &disc.jwks_uri,
                now,
                now + PENDING_TTL_SECS
            ],
        );
    }

    let sep = if disc.authorization_endpoint.contains('?') { '&' } else { '?' };
    let authorize = format!(
        "{}{}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        disc.authorization_endpoint,
        sep,
        pct_encode(&cfg.client_id),
        pct_encode(&cfg.redirect_uri),
        pct_encode(SCOPES),
        pct_encode(&state),
        pct_encode(&nonce),
        pct_encode(&challenge),
    );
    (StatusCode::FOUND, [(header::LOCATION, authorize)], "redirecting to identity provider").into_response()
}

/// GET /api/sso/callback?code=&state= — finish the flow. Validates state (server-side, one-time),
/// exchanges the code (with the PKCE verifier) for tokens, validates the ID token, maps to a Forge user,
/// issues the `forge_session` cookie and 302s to the (re-validated) allowlisted return target.
async fn callback(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !enabled(&app) {
        return disabled();
    }
    let cfg = match load_config(&app) {
        Some(c) => c,
        None => return err(StatusCode::FORBIDDEN, "sso_unconfigured", "OIDC SSO not configured"),
    };
    // The IdP may redirect back with an error (access_denied, etc.) — fail-closed, no session.
    if let Some(e) = q.get("error") {
        return err(StatusCode::FORBIDDEN, "idp_error", format!("identity provider returned error: {e}"));
    }
    let state = q.get("state").map(|s| s.as_str()).unwrap_or("");
    let code = q.get("code").map(|s| s.as_str()).unwrap_or("");
    if state.is_empty() || code.is_empty() {
        return err(StatusCode::BAD_REQUEST, "bad_request", "missing code or state");
    }

    // STATE validation: look up + CONSUME the pending row (one-time use, anti-replay). Missing => reject.
    let pend = {
        let store = app.store();
        ensure_schema(&store);
        match take_pending(&store, state) {
            Some(p) => p,
            None => return err(StatusCode::FORBIDDEN, "invalid_state", "unknown or already-used state"),
        }
    };
    if crate::now_epoch() >= pend.expires {
        return err(StatusCode::FORBIDDEN, "expired", "authorization request expired");
    }

    // Exchange code + code_verifier for tokens (client_secret_basic). Blocking IO off the async worker.
    let token_endpoint = pend.token_endpoint.clone();
    let basic = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", cfg.client_id, cfg.client_secret));
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_id={}",
        pct_encode(code),
        pct_encode(&cfg.redirect_uri),
        pct_encode(&pend.code_verifier),
        pct_encode(&cfg.client_id),
    );
    let to = http_timeout();
    let token_body = match tokio::task::spawn_blocking(move || {
        http_post_form_blocking(&token_endpoint, &basic, &body, to)
    })
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return err(StatusCode::BAD_GATEWAY, "token_exchange_failed", e),
        Err(_) => return err(StatusCode::BAD_GATEWAY, "token_exchange_failed", "token task join error"),
    };
    let token_json: Value = match serde_json::from_str(&token_body) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_GATEWAY, "token_exchange_failed", format!("bad token response: {e}")),
    };
    let id_token = token_json.get("id_token").and_then(|v| v.as_str()).unwrap_or("");
    if id_token.is_empty() {
        return err(StatusCode::FORBIDDEN, "no_id_token", "token endpoint returned no id_token");
    }

    // Fetch JWKS (blocking IO) then VALIDATE the ID token (signature/iss/aud/exp/nonce) — pure, testable.
    let jwks_uri = pend.jwks_uri.clone();
    let jwks = match tokio::task::spawn_blocking(move || fetch_jwks_blocking(jwks_uri, to)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return err(StatusCode::BAD_GATEWAY, "jwks_fetch_failed", e),
        Err(_) => return err(StatusCode::BAD_GATEWAY, "jwks_fetch_failed", "jwks task join error"),
    };
    let (sub, email, groups) = match validate_id_token(&cfg, &pend.nonce, id_token, &jwks) {
        Ok(x) => x,
        Err(e) => return err(StatusCode::FORBIDDEN, "invalid_id_token", e),
    };

    // ADVANCED RBAC (enterprise): resolve the IdP `groups` claim to a least-privilege outcome over the
    // configurable mapping. `role: None` => no matching group => the identity keeps the configured default
    // role (least privilege). NEVER super-admin (not representable in the mapping). Computed here so the
    // AUTO-provisioning role below reflects the group mapping from the very first login.
    let resolved = crate::rbac::resolve(&app, &groups);
    let provision_role = resolved.role.clone().unwrap_or_else(|| cfg.default_role.clone());

    // Map the OIDC identity to a Forge user (match existing or auto-provision per config). A new account
    // is provisioned with the group-resolved role (fallback = configured default).
    let (user_id, login, provisioned) = match map_user(&app, &cfg, &sub, &email, &provision_role) {
        Ok(x) => x,
        Err(e) => return err(StatusCode::FORBIDDEN, "user_mapping_failed", e),
    };
    if provisioned {
        // A new individual account exists now — re-arm the auth gate on DB state (mirrors account CRUD).
        app.recompute_auth_required();
        app.bump_cache_epoch(); // B6 (HA): invalidate peers' auth_required cache (SSO JIT-provisioned account)
    }
    // Sync the account's role + tenant grants to what its groups confer (fail-closed least privilege; a
    // designated super-admin login is never touched). `cap_operator=false`: an admin-configured group ->
    // admin mapping is honored for an interactive SSO login. No matching group => role stays as-is.
    crate::rbac::apply_to_user(&app, user_id, &login, &resolved, false);

    // Re-validate the stored return target (defence in depth) before redirecting the browser.
    if !redirect_allowed(&cfg, &pend.return_to) {
        return err(StatusCode::FORBIDDEN, "redirect_not_allowed", "return_to is not in the allowlist");
    }

    // Issue THE SAME session cookie the local /api/login issues (HttpOnly, SameSite=Strict).
    let (token, _expires) = crate::create_session(&app, user_id);
    let ttl = crate::session_ttl_secs();
    let cookie = format!("forge_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}");

    // Ledger the login — NEVER the id/access token, the code, or the client_secret. `sub` is an opaque
    // identifier (needed for attribution), not a secret.
    crate::append_console_ledger(
        &app,
        "console.sso.login",
        json!({
            "actor": login,
            "subject": sub,
            "provisioned": provisioned,
            "issuer": cfg.issuer,
        }),
    );

    (
        StatusCode::FOUND,
        [(header::SET_COOKIE, cookie), (header::LOCATION, pend.return_to)],
        "authenticated",
    )
        .into_response()
}

/// GET /api/sso/config — return the OIDC provider config with the `client_secret` REDACTED (replaced by a
/// `client_secret_set` boolean). Flag-gated + admin-only (fail-closed).
async fn config_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !enabled(&app) {
        return disabled();
    }
    if !crate::check_admin(&app, &headers) {
        return err(StatusCode::FORBIDDEN, "admin_required", "OIDC SSO config is admin-only");
    }
    (StatusCode::OK, Json(json!({ "enabled": true, "config": redacted_config(&app) }))).into_response()
}

/// POST /api/sso/config — set the OIDC provider config (admin-only). `client_secret` is WRITE-ONLY: sent
/// non-empty => updated; absent/empty => the existing stored secret is KEPT (so an admin can edit other
/// fields without re-entering it). Ledgered `console.sso.config` (never the secret). Response redacts.
async fn config_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !enabled(&app) {
        return disabled();
    }
    if !crate::check_admin(&app, &headers) {
        return err(StatusCode::FORBIDDEN, "admin_required", "OIDC SSO config is admin-only");
    }
    let issuer = body.get("issuer").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let client_id = body.get("client_id").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let redirect_uri = body.get("redirect_uri").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !is_http_url(&issuer) {
        return err(StatusCode::BAD_REQUEST, "bad_issuer", "issuer must be an http(s) URL");
    }
    if client_id.is_empty() {
        return err(StatusCode::BAD_REQUEST, "bad_client_id", "client_id required");
    }
    if !is_http_url(&redirect_uri) {
        return err(StatusCode::BAD_REQUEST, "bad_redirect_uri", "redirect_uri must be an http(s) URL");
    }
    // allowed_redirect_uris: array of strings (may be empty). Reject a non-array if present.
    let allowed: Vec<String> = match body.get("allowed_redirect_uris") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
        Some(_) => return err(StatusCode::BAD_REQUEST, "bad_allowlist", "allowed_redirect_uris must be an array of strings"),
    };
    // provisioning / user_claim / default_role — validated (fail-closed on unknown values).
    let provisioning = body.get("provisioning").and_then(|v| v.as_str()).unwrap_or("match").to_string();
    if provisioning != "match" && provisioning != "auto" {
        return err(StatusCode::BAD_REQUEST, "bad_provisioning", "provisioning must be 'match' or 'auto'");
    }
    let user_claim = body.get("user_claim").and_then(|v| v.as_str()).unwrap_or("email").to_string();
    if user_claim != "email" && user_claim != "sub" {
        return err(StatusCode::BAD_REQUEST, "bad_user_claim", "user_claim must be 'email' or 'sub'");
    }
    let default_role = body.get("default_role").and_then(|v| v.as_str()).unwrap_or("viewer").to_string();
    if crate::validate_role(&default_role).is_err() {
        return err(StatusCode::BAD_REQUEST, "bad_default_role", "default_role must be viewer|operator|admin");
    }

    // client_secret is WRITE-ONLY: keep the existing one if the request omits it.
    let existing_secret = load_config(&app).map(|c| c.client_secret).unwrap_or_default();
    let new_secret = body
        .get("client_secret")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let secret = new_secret.unwrap_or(existing_secret);
    if secret.is_empty() {
        return err(StatusCode::BAD_REQUEST, "bad_client_secret", "client_secret required on first configuration");
    }

    let cfg = json!({
        "issuer": issuer,
        "client_id": client_id,
        "client_secret": secret,          // stored verbatim; NEVER returned/logged/ledgered
        "redirect_uri": redirect_uri,
        "allowed_redirect_uris": allowed,
        "provisioning": provisioning,
        "default_role": default_role,
        "user_claim": user_claim,
    });
    {
        let store = app.store();
        if let Err(e) = crate::settings_set_store(&store, CFG_KEY, &cfg.to_string()) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed", e);
        }
    }
    let actor = crate::resolve_session_identity(&app, &headers)
        .map(|i| i.login)
        .unwrap_or_else(|| "admin".to_string());
    crate::append_console_ledger(
        &app,
        "console.sso.config",
        json!({
            "actor": actor,
            "issuer": issuer,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "allowed_redirect_uris": allowed.len(),
            "provisioning": provisioning,
            "client_secret_set": !secret.is_empty(),
        }),
    );
    (StatusCode::OK, Json(json!({ "enabled": true, "config": redacted_config(&app) }))).into_response()
}

/// The stored config as a JSON object with `client_secret` REMOVED and a `client_secret_set` boolean
/// added. Never exposes the secret.
fn redacted_config(app: &App) -> Value {
    let raw = {
        let store = app.store();
        crate::settings_get_store(&store, CFG_KEY)
    };
    let mut v = raw
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(|| json!({}));
    let secret_set = v.get("client_secret").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
    if let Some(o) = v.as_object_mut() {
        o.remove("client_secret");
        o.insert("client_secret_set".to_string(), json!(secret_set));
    }
    v
}

// ============================================================================================
// ID-TOKEN VALIDATION (pure, testable) — signature via JWKS [jsonwebtoken] + iss/aud/exp + nonce.
// ============================================================================================

/// Validate the ID token against the IdP JWKS and the flow's expectations. Returns `(sub, email, groups)`
/// on success (`groups` = the OIDC `groups` claim, empty if absent — feeds advanced RBAC, fail-closed to
/// least privilege). FAIL-CLOSED on ANY mismatch: unsupported alg, unknown kid, bad signature, wrong
/// issuer, wrong audience, expired, or a nonce that does not match the pending-auth nonce.
fn validate_id_token(
    cfg: &SsoConfig,
    expected_nonce: &str,
    token: &str,
    jwks: &Value,
) -> Result<(String, String, Vec<String>), String> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    // Header: enforce RS256 (asymmetric, JWKS). Reject `none`/HS* to prevent alg-confusion downgrades.
    let header = decode_header(token).map_err(|e| format!("bad token header: {e}"))?;
    if header.alg != Algorithm::RS256 {
        return Err(format!("unsupported signing alg {:?} (RS256 required)", header.alg));
    }
    let (n, e) = select_jwk(jwks, header.kid.as_deref())?;
    let key = DecodingKey::from_rsa_components(&n, &e).map_err(|e| format!("bad JWKS key: {e}"))?;

    let mut val = Validation::new(Algorithm::RS256);
    val.set_issuer(&[cfg.issuer.as_str()]); // token `iss` must EXACTLY equal the configured issuer
    val.set_audience(&[cfg.client_id.as_str()]); // token `aud` must contain client_id
    val.validate_exp = true; // reject expired tokens (jsonwebtoken enforces exp with default leeway)

    let data = decode::<Value>(token, &key, &val).map_err(|e| format!("token rejected: {e}"))?;
    let claims = data.claims;

    // NONCE binding (jsonwebtoken does not validate nonce) — must match the per-flow pending nonce.
    let nonce = claims.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    if nonce.is_empty() || !crate::ct_eq_str(nonce, expected_nonce) {
        return Err("nonce mismatch".to_string());
    }
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if sub.is_empty() {
        return Err("id token missing sub".to_string());
    }
    let email = claims.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // OIDC `groups` claim (array of strings, or a single string) — feeds the advanced-RBAC group mapping.
    // Absent/malformed => empty => the identity keeps its least-privilege default (fail-closed).
    let groups = crate::rbac::groups_from_claims(&claims);
    Ok((sub, email, groups))
}

/// Select the RSA signing key `(n, e)` from a JWKS. With a `kid` in the token header, require an EXACT
/// kid match (fail-closed — never fall back to another key). Without a kid, the JWKS must have exactly
/// one RSA key (ambiguity => reject).
fn select_jwk(jwks: &Value, kid: Option<&str>) -> Result<(String, String), String> {
    let keys = jwks.get("keys").and_then(|k| k.as_array()).ok_or("JWKS has no keys array")?;
    let rsa: Vec<&Value> = keys
        .iter()
        .filter(|k| k.get("kty").and_then(|v| v.as_str()) == Some("RSA"))
        .collect();
    if rsa.is_empty() {
        return Err("JWKS has no RSA key".to_string());
    }
    let chosen = match kid {
        Some(want) => rsa
            .iter()
            .copied()
            .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(want))
            .ok_or("no JWKS key matches the token kid")?,
        None => {
            if rsa.len() != 1 {
                return Err("ambiguous JWKS (token has no kid and >1 RSA key)".to_string());
            }
            rsa[0]
        }
    };
    let n = chosen.get("n").and_then(|v| v.as_str()).ok_or("JWKS key missing n")?;
    let e = chosen.get("e").and_then(|v| v.as_str()).ok_or("JWKS key missing e")?;
    Ok((n.to_string(), e.to_string()))
}

// ============================================================================================
// USER MAPPING — OIDC subject/email -> Forge user (match existing or auto-provision).
// ============================================================================================

/// Map the OIDC identity to a Forge user. Returns `(user_id, login, provisioned)`. In `match` mode a
/// missing account is rejected (fail-closed). In `auto` mode a missing account is provisioned with the
/// supplied `provision_role` (the group-resolved role, else the configured default) and an UNUSABLE local
/// password (SSO-only — no argon2 preimage is ever known). `provision_role` is re-validated (fail-closed).
fn map_user(app: &App, cfg: &SsoConfig, sub: &str, email: &str, provision_role: &str) -> Result<(i64, String, bool), String> {
    let raw = if cfg.user_claim == "sub" {
        sub
    } else if !email.is_empty() {
        email
    } else {
        sub
    };
    let login = sanitize_login(raw)?;

    // Existing account?
    {
        let store = app.store();
        if let Ok(id) = store.query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![&login], |r| r.get_i64(0)) {
            return Ok((id, login, false));
        }
    }
    if cfg.provisioning != "auto" {
        return Err(format!(
            "no Forge account for '{login}' and auto-provisioning is disabled (provisioning=match)"
        ));
    }
    let role = crate::validate_role(provision_role)
        .or_else(|_| crate::validate_role(&cfg.default_role))
        .unwrap_or_else(|_| "viewer".to_string());
    // Unusable local password: argon2id of a random 256-bit secret nobody knows -> local /api/login can
    // never succeed for this account (SSO-only). Hash OUTSIDE the DB lock (argon2 is deliberately slow).
    let hash = crate::hash_pw(&rand_hex(32));
    let (id, inserted) = {
        let store = app.store();
        let inserted = store
            .execute(
                "INSERT INTO users(login,role,pass_hash,disabled,created)
                 VALUES(?,?,?,0,datetime('now')) ON CONFLICT DO NOTHING",
                &crate::sql_params![&login, &role, &hash],
            )
            .unwrap_or(0);
        let id = store
            .query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![&login], |r| r.get_i64(0))
            .map_err(|e| format!("provision lookup failed: {e}"))?;
        (id, inserted)
    };
    Ok((id, login, inserted > 0))
}

/// Derive a Forge login (`[A-Za-z0-9._-]{1,64}`, no leading `-`) from an OIDC claim. Lowercases, maps `@`
/// to `.`, replaces any other disallowed char with `-`, trims leading separators, truncates to 64, then
/// enforces `validate_login`. Fail-closed if nothing valid remains.
fn sanitize_login(raw: &str) -> Result<String, String> {
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
    crate::validate_login(&s).map_err(|e| format!("cannot derive a valid login from the OIDC claim: {e}"))
}

// ============================================================================================
// REDIRECT ALLOWLIST — mirror the redirect.open / oauth.flow discipline (never an open redirect).
// ============================================================================================

/// Is `ret` an acceptable post-login browser redirect target? Allowed iff it is EXACTLY in the config
/// allowlist, or the same-origin root `/`, or a safe same-origin relative path (leading single `/`, no
/// protocol-relative `//` or backslash trick). Any absolute off-list URL is refused (fail-closed).
fn redirect_allowed(cfg: &SsoConfig, ret: &str) -> bool {
    if ret == "/" {
        return true;
    }
    if cfg.allowed_redirect_uris.iter().any(|a| a == ret) {
        return true;
    }
    safe_relative(ret)
}

/// A same-origin relative path that cannot escape the origin: starts with a single `/`, not `//`
/// (protocol-relative), not `/\` (backslash treated as `/` by some browsers).
fn safe_relative(s: &str) -> bool {
    s.starts_with('/') && !s.starts_with("//") && !s.starts_with("/\\")
}

/// Minimal absolute-http(s)-URL check for config validation (no external URL crate).
fn is_http_url(s: &str) -> bool {
    (s.starts_with("http://") && s.len() > "http://".len())
        || (s.starts_with("https://") && s.len() > "https://".len())
}

// ============================================================================================
// PENDING-AUTH STORAGE (server-side state/nonce/verifier) — created lazily (community DB untouched).
// ============================================================================================

/// A consumed pending-auth record.
struct Pending {
    nonce: String,
    code_verifier: String,
    return_to: String,
    token_endpoint: String,
    jwks_uri: String,
    expires: i64,
}

/// Create the pending-auth table if absent (idempotent) and purge expired rows. Called lazily from the
/// login/callback handlers so the COMMUNITY DB (flag OFF => routes 404 before this runs) is untouched.
fn ensure_schema(store: &crate::store::Store) {
    // POSTGRES dialect (feature `store-postgres` + backend actif PG) : `INTEGER`->`BIGINT` (parité binds
    // i64 du seam pour created/expires). `state TEXT PRIMARY KEY` inchangé (portable). Table flag-gated
    // créée paresseusement — HORS de PG_SCHEMA (la base community ne la voit jamais).
    #[cfg(feature = "store-postgres")]
    if store.is_postgres() {
        let _ = store.execute_batch(
            "CREATE TABLE IF NOT EXISTS sso_pending(
               state TEXT PRIMARY KEY,
               nonce TEXT NOT NULL,
               code_verifier TEXT NOT NULL,
               return_to TEXT NOT NULL,
               token_endpoint TEXT NOT NULL,
               jwks_uri TEXT NOT NULL,
               created BIGINT NOT NULL,
               expires BIGINT NOT NULL);",
        );
        let _ = store.execute("DELETE FROM sso_pending WHERE expires <= ?", &crate::sql_params![crate::now_epoch()]);
        return;
    }
    let _ = store.execute_batch(
        "CREATE TABLE IF NOT EXISTS sso_pending(
           state TEXT PRIMARY KEY,
           nonce TEXT NOT NULL,
           code_verifier TEXT NOT NULL,
           return_to TEXT NOT NULL,
           token_endpoint TEXT NOT NULL,
           jwks_uri TEXT NOT NULL,
           created INTEGER NOT NULL,
           expires INTEGER NOT NULL);",
    );
    let _ = store.execute("DELETE FROM sso_pending WHERE expires <= ?", &crate::sql_params![crate::now_epoch()]);
}

/// PG-ONLY — crée la table enterprise SSO `sso_pending` sur la CIBLE Postgres pour le migrateur de données
/// (`cli::migrate-store`) : hors de `PG_SCHEMA` (créée paresseusement), le migrateur doit invoquer ce chemin
/// pour que la cible la possède AVANT la copie (sinon absente -> hard-fail, jamais de skip silencieux).
/// Délègue à `ensure_schema` (branche `is_postgres()` ; le DELETE des rows expirées y est un no-op sur une
/// cible neuve). Entièrement gardé `store-postgres` : le build community ne compile pas cette fonction.
#[cfg(feature = "store-postgres")]
pub(crate) fn ensure_pg_schema(store: &crate::store::Store) {
    ensure_schema(store);
}

/// Look up AND delete (one-time use) the pending-auth row for `state`. `None` if unknown/already-used.
fn take_pending(store: &crate::store::Store, state: &str) -> Option<Pending> {
    let p = store
        .query_row(
            "SELECT nonce,code_verifier,return_to,token_endpoint,jwks_uri,expires FROM sso_pending WHERE state=?",
            &crate::sql_params![state],
            |r| {
                Ok(Pending {
                    nonce: r.get_str(0)?,
                    code_verifier: r.get_str(1)?,
                    return_to: r.get_str(2)?,
                    token_endpoint: r.get_str(3)?,
                    jwks_uri: r.get_str(4)?,
                    expires: r.get_i64(5)?,
                })
            },
        )
        .ok()?;
    let _ = store.execute("DELETE FROM sso_pending WHERE state=?", &crate::sql_params![state]);
    Some(p)
}

// ============================================================================================
// OIDC HTTP — discovery / JWKS via the existing GET client; a sibling POST helper for token exchange.
// ============================================================================================

/// Resolved IdP endpoints from the discovery document.
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// Fetch + validate `{issuer}/.well-known/openid-configuration` via the crate's existing HTTP client.
/// Enforces that the document's `issuer` matches the configured issuer (OIDC spec) and that the three
/// endpoints are present. Blocking — call via `spawn_blocking`.
fn discover_blocking(issuer: String, timeout: Duration) -> Result<Discovery, String> {
    let base = issuer.trim_end_matches('/');
    let url = format!("{base}/.well-known/openid-configuration");
    let body = crate::http_get_blocking(&url, &crate::HttpAuth::None, timeout, true)?;
    let v: Value = serde_json::from_str(&body).map_err(|e| format!("bad discovery JSON: {e}"))?;
    let disc_issuer = v.get("issuer").and_then(|x| x.as_str()).unwrap_or("");
    if disc_issuer.trim_end_matches('/') != base {
        return Err(format!("discovery issuer '{disc_issuer}' does not match configured issuer '{issuer}'"));
    }
    let authorization_endpoint = v.get("authorization_endpoint").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let token_endpoint = v.get("token_endpoint").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let jwks_uri = v.get("jwks_uri").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if authorization_endpoint.is_empty() || token_endpoint.is_empty() || jwks_uri.is_empty() {
        return Err("discovery missing authorization_endpoint/token_endpoint/jwks_uri".to_string());
    }
    Ok(Discovery { authorization_endpoint, token_endpoint, jwks_uri })
}

/// Fetch the JWKS document. Blocking — call via `spawn_blocking`.
fn fetch_jwks_blocking(jwks_uri: String, timeout: Duration) -> Result<Value, String> {
    let body = crate::http_get_blocking(&jwks_uri, &crate::HttpAuth::None, timeout, true)?;
    serde_json::from_str(&body).map_err(|e| format!("bad JWKS JSON: {e}"))
}

/// Minimal blocking HTTP/1.1 POST of an `application/x-www-form-urlencoded` body with optional
/// `Authorization: Basic` (client_secret_basic). Plaintext `http://` only (TLS terminated upstream, per
/// the crate's transport discipline — mirrors `http_get_blocking`). Anti-CRLF-injection on the header.
fn http_post_form_blocking(url: &str, basic_b64: &str, body: &str, timeout: Duration) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "token endpoint must be http:// (TLS terminated upstream)".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = authority.split(':').next().unwrap_or(authority);
    let port: u16 = authority.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(80);
    let no_crlf = |s: &str| !s.contains('\r') && !s.contains('\n');
    if !no_crlf(basic_b64) || !no_crlf(authority) {
        return Err("refusing CRLF in request header".to_string());
    }
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}:{port} failed: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for {host}:{port}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect {addr} failed: {e}"))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: forge-console-sso\r\nAccept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if !basic_b64.is_empty() {
        req.push_str(&format!("Authorization: Basic {basic_b64}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).map_err(|e| format!("write failed: {e}"))?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| format!("read failed: {e}"))?;
    let text = String::from_utf8_lossy(&raw);
    let split = text.find("\r\n\r\n").ok_or_else(|| "malformed HTTP response".to_string())?;
    let head = &text[..split];
    let status_line = head.lines().next().unwrap_or("");
    if !(status_line.contains(" 200") || status_line.contains(" 201")) {
        return Err(format!("unexpected token endpoint status: {status_line}"));
    }
    let body_out = &text[split + 4..];
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        // IDIO-1 : dé-chunk sur les OCTETS BRUTS (en-tête ASCII => `split + 4` est le même offset dans `raw`).
        Ok(crate::dechunk(&raw[split + 4..]))
    } else {
        Ok(body_out.to_string())
    }
}

// ============================================================================================
// SMALL PURE HELPERS
// ============================================================================================

/// CSPRNG hex of `nbytes` bytes (OS entropy). Panics on entropy failure rather than emit a weak secret
/// (fail-closed on entropy — mirrors `gen_session_token`).
fn rand_hex(nbytes: usize) -> String {
    let mut b = vec![0u8; nbytes];
    getrandom::getrandom(&mut b).expect("CSPRNG (getrandom) unavailable — refusing to emit a weak SSO secret");
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// PKCE S256 code_challenge = base64url-nopad(SHA-256(code_verifier)).
fn code_challenge(verifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}

/// Percent-encode a query/form value (RFC 3986 unreserved kept; everything else %XX). Used for both
/// the authorize URL query and the token request body — no CRLF/`&`/`=`/space can smuggle through.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::App;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rusqlite::Connection;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    // --- Test RSA keys (generated offline, PKCS#8). GOOD is published in the mock JWKS; ROGUE is used to
    //     forge a bad-signature token (JWKS only ever carries GOOD -> a ROGUE-signed token must be rejected).
    const GOOD_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDgydj5CrnsjonD
g1hGnaE+Mbquba+mxoZ/11HR8z6XRW9avqATc1bFg2eltd6FM1iqNtoojisd2XH6
2e8afdK7Gucysg7vqkO6W4VjqEEow4SXVlmfwLaK2Cq68m+t6D38V5aCMcXNe0rj
XPB+3r4ytK7h5fUe4ecirW82Lqo9qRS3VHLmuqKE5WjVZEiKjlobDpDWEXDf7X6Z
h25fK0IK3Umnz0xyeys2rPSoNMpSv+o0D0wtnoEGlSEUg5qAkI3ZszeAjwoT3wjG
0yRH651nFH/crEGNmSyrafo54tGQWq4x6ZbfyTMpD2d2ZDDgz1th39WvenEPQDnT
O7t5MWM/AgMBAAECggEABNW4/PvmE9h2muXwUbronokJr60pFThstcM3CoHMDtgU
SEQuKgm8P0AcTDKLnrUEBMufomlGAO/0XtjhJuJRIThRULdtUTcjgP0G8wwwNDHZ
+dQgCV4Ajx8nJbsHlYExR1D69vUeTaHuDAXe7MINuGytqXfKVee1+PqR/pa/KQq3
oV6Ow5+Ac4K8SZGm+puiAEfggNorNyiyqR4/mmVMrXPflVYMyK42q3h9w67ol0Kx
UDbMDHLCziAycJnEtrHjeypTsDJF15kq5uumEQBXJPVV9R1tc8voIMV8BLYh/9gD
oSowR4jZfp5P6BIWw7LXUusISI6pMYmbsKoGrHJPAQKBgQD60g54iDCfXvXtfHcW
D27lXNeo+o72lo7/jeHpaGKRzFkRh/JudoOqzFfedKFMCUUxog2jG2CJ/HPVilCV
yDYEsh4stpAUB8ObTvPX7pX+T6lutFtvMMeMGtppXKP5/5yKX+p3Vys95zozp6J9
/HHdQhrFvQNIRuohtBcJz87JDwKBgQDlbiysY4DYd5cuuXt7OUSvT3QTT9ZMIk1P
7rbSuN87OOU6z4L72pZGkypwGpwD/skSs/vySfV0sv4IRXCHGx0ed07uJQbfVTjn
NG46pqCQeNH7ymzVC8qFkB9nfmqpuxeWrOh8fx0LcBHpIcpWTwGztP1vL63CwNqF
QdiuviDi0QKBgQDhOH2F/cSrVrm95mWIiZMqoZOFSHfXNJpzHxQcYn8gLD5OX6Rx
TDouxA6i0leDz08yojFcpNirDuV0eh6iYIUg8k/mFoiJc+9RJjQPUU2ebinWHl18
GnEUfYhh063qbnxCRJ5lSwCpNVgtyfk+58/WveUMagzoecUDPpLxXIhyQQKBgBGs
AtTkdTA3RfXbY5+CMcAvJom2RJNosPvPL1Xb15YAM+frw/MSSzD0dPhdlFbacTJ3
mph3CekLQHXyo1BEzmFiXzoIsBbTwaZNa5Ao9YUrSUFTvj5Kwja3ezPFkQGx34dD
mkS8pcgTwc1rROKRA1iMQFkoGwI9SJerEr2i93WBAoGBAK7vEgmNN13r8JCqqM0A
EEcSrFIn/saqZM9Zwh5QW7MF/m0LnyXnipX+A2CWrJwFbbYLaEqMDAhUtZWMugPn
JBP2J1Y29oJwigBRnLE2K9AWHqIdKomikIecgf4SjZKOqRzusy6SlXQsh1EUvzNv
MSwrwH8+FMHL/yIMTRGUjMNm
-----END PRIVATE KEY-----";
    // GOOD public key JWK components (base64url of the RSA modulus / exponent).
    const GOOD_N: &str = "4MnY-Qq57I6Jw4NYRp2hPjG6rm2vpsaGf9dR0fM-l0VvWr6gE3NWxYNnpbXehTNYqjbaKI4rHdlx-tnvGn3SuxrnMrIO76pDuluFY6hBKMOEl1ZZn8C2itgquvJvreg9_FeWgjHFzXtK41zwft6-MrSu4eX1HuHnIq1vNi6qPakUt1Ry5rqihOVo1WRIio5aGw6Q1hFw3-1-mYduXytCCt1Jp89McnsrNqz0qDTKUr_qNA9MLZ6BBpUhFIOagJCN2bM3gI8KE98IxtMkR-udZxR_3KxBjZksq2n6OeLRkFquMemW38kzKQ9ndmQw4M9bYd_Vr3pxD0A50zu7eTFjPw";
    const GOOD_E: &str = "AQAB";
    const ROGUE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDmYrVowayPQs55
t6dS1Bjccj1/ztrWp+fLo3NMzVK49Q6PMmkJ9LyM+ykDgtpo1IlZ3fuAg60CdyQM
cLEQmr4EJSuhmbAFSCZ4zOGexVt5gXJK5l1WDx+uXvTzOYrHx77nZFpz+yX7lPsi
GVYC/9YScohDR8eD0K0ENYIOGa/Na7xZuZDr6zEVHKSwClsQk83U9YI0PlX09PzZ
TvpANoOCJJIgMAbUMHM8S5M+ba74NuRXG2vjN1E/rs4idmYasyyNsi5kDqFJx0/b
FIvcZoquD0z+82XXRTTKdURzlxsCDpkTc/39/GQY2Yac1J/MD5eBDiq5jIDdnNPr
N98oX5arAgMBAAECggEAUWpgoXyP9rCtNuZoAyVhA8Z7ZUc8ns8HYzeH74Q/z40K
cCBoblRGrau0esErXhB92XxQ/MGLymtAGgVZDX0h2WUpXhpp0fQFZHtC4FDuWqoc
McvnABqoH37/IVUcbi1wkWUtcf83FQk5FnvNoZG3nR1MejpLj5GXEv210DXTosvc
FMXh4JTaq36+243bM780rCgqjYHBskr2uuYrUJJ6bL31Sxlunl9sPYshAHRUNXuP
9e4V8A02wOK9UYL0GdLShqsEMQrA+if8iIsXanqHFmoC7TRSEv2pzCIfTGb4tGhx
+kksLk7f9pit5aW901vtWmmL9+ihtL/EOmCMphN3gQKBgQD+qtpdpwuLCt9OStwN
m/JxTE5+LhUtC/pjHd0LSpE4MitMx6eqZNgBYC2S2EUmjv8SoEHBkhNGZckzndw/
7SAcUxlAoR1SWFHB2SkdFqpmGjaXUeagBdXx+uxn8kccAl6QL6JgJ269v7mufjpm
IG9RkRdMlupo+vNGKf+Sjl+RyQKBgQDnl1QHbPIYG9I5isyaXtmvh+Q47g+GPuE1
1PJZ4iCeWu9BiB8GIYzal64+hkmNslnNzpIVgz6sKlmkMrbqK7q4OerIInT0sSlB
bDbzcRZpL/+xFhxuuUvs1qdra+6UfmSI52jYj2xU2F2bH1urBfr+JuP2Qpfn/HeU
t4dGx83+0wKBgQCVmQPBc/lB6lcXBL6TeAJJL8wEL0ndNmYVh1tr4JfB7SamabpC
TA7fcAIVetnUNrf71wwJi6eq+OviWF8jZkYwnVf+MSaqUptkRg7yuXfLlqZu6XuS
kRsGlKH+xcGj4HhwNqsp1MAm0tNef2QKzg7WWWbYZOa6WIBDvTQWgW/+kQKBgCqH
VKwEarTYrxNYFNioYGtmlheKSBmMBImBMHwnFXxfEJ7FI4VZtecSgbIDsRAvV2R+
8b63mlO9dza7BXIdU62vHRlhkn645e2YtMKh2s64PMlFWTVQG8xDYv1MFcT5LPcj
H9LdC7TNAuuQp6HReFUhyS0Y75Jvf3o09ceeu4p3AoGBAPv5wwgjLfP4vYm3azyJ
vvNKria3WmmbTH46x0FIEp21UyrdAu5PWq1OuFV0n8156jAUgE1IpH20uo/gLS7h
oVGTEwS7LY+Ncvq0vhIDT4uhs29Iju2b+yoNefutM77abV96Zl5934hz14dI4rdY
byHb5g3JqJSE6WJSuyEQrUob
-----END PRIVATE KEY-----";
    const KID: &str = "test-key-1";

    // ---- minimal HTTP helpers (self-contained; the crate's own test helpers live in a sibling module) ----
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
    fn parse_status(resp: &str) -> u16 {
        resp.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).unwrap_or(0)
    }
    fn body_of(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }
    fn header_val(resp: &str, name: &str) -> Option<String> {
        let head = resp.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(resp);
        let want = format!("{}:", name.to_ascii_lowercase());
        for line in head.lines() {
            if line.to_ascii_lowercase().starts_with(&want) {
                return Some(line[want.len()..].trim().to_string());
            }
        }
        None
    }
    fn cookie_token(resp: &str) -> Option<String> {
        let sc = header_val(resp, "set-cookie")?;
        let idx = sc.find("forge_session=")?;
        let rest = &sc[idx + "forge_session=".len()..];
        let end = rest.find(';').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
    fn qparam(url: &str, key: &str) -> Option<String> {
        let q = url.split_once('?')?.1;
        for kv in q.split('&') {
            if let Some((k, v)) = kv.split_once('=') {
                if k == key {
                    return Some(v.to_string());
                }
            }
        }
        None
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

    /// App backed by an in-memory DB (mirrors crate::tests::test_app; that helper is in a sibling module,
    /// not reachable here). Fields are crate-private but visible to this descendant module.
    fn sso_test_app(ledger_path: &str) -> App {
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

    /// Engage the enterprise SSO flag on THIS db (per-DB, isolated — no env mutation).
    fn engage_flag(app: &App) {
        let db = app.db();
        crate::settings_set(&db, "enterprise.sso", "on").unwrap();
    }

    /// Write an SSO config directly into settings (bypasses the admin route — for flow tests).
    fn set_config(app: &App, issuer: &str, allowed: Vec<&str>, provisioning: &str, default_role: &str, user_claim: &str) {
        let cfg = json!({
            "issuer": issuer,
            "client_id": "forge-client",
            "client_secret": "s3cr3t-value",
            "redirect_uri": "http://localhost/api/sso/callback",
            "allowed_redirect_uris": allowed,
            "provisioning": provisioning,
            "default_role": default_role,
            "user_claim": user_claim,
        });
        let db = app.db();
        crate::settings_set(&db, CFG_KEY, &cfg.to_string()).unwrap();
    }

    /// Forge an ID token (RS256) with `pem`, embedding the given claims.
    #[allow(clippy::too_many_arguments)]
    fn make_id_token(pem: &str, kid: &str, iss: &str, aud: &str, sub: &str, email: &str, nonce: &str, exp_offset: i64) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let now = crate::now_epoch();
        let claims = json!({
            "iss": iss, "aud": aud, "sub": sub, "email": email, "nonce": nonce,
            "exp": now + exp_offset, "iat": now
        });
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
        encode(&header, &claims, &key).expect("sign")
    }

    /// Spawn a mock OIDC IdP. Serves discovery + JWKS (GOOD key) statically; `/token` returns whatever
    /// ID token the test has placed in the returned slot. Loops until the runtime tears down.
    async fn spawn_mock_idp() -> (String, Arc<Mutex<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock idp");
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let discovery = json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
        })
        .to_string();
        let jwks = json!({
            "keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": GOOD_N, "e": GOOD_E}]
        })
        .to_string();
        let slot = Arc::new(Mutex::new(String::new()));
        let slot2 = slot.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let mut buf = vec![0u8; 16384];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("");
                let payload = if path.starts_with("/.well-known/openid-configuration") {
                    discovery.clone()
                } else if path.starts_with("/jwks") {
                    jwks.clone()
                } else if path.starts_with("/token") {
                    json!({
                        "access_token": "mock-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "id_token": slot2.lock().unwrap().clone(),
                    })
                    .to_string()
                } else {
                    "{}".to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        (base, slot)
    }

    /// Boot the FULL router (build_router — parity with prod) and return its address.
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

    /// Drive login -> parse state+nonce from the authorize redirect -> return (state, nonce).
    async fn start_login(addr: SocketAddr, return_to: &str) -> (String, String, String) {
        let r = http_raw(addr, &get_req(&format!("/api/sso/login?return_to={}", pct_encode(return_to)), "")).await;
        assert_eq!(parse_status(&r), 302, "login should 302 to the IdP: {r}");
        let loc = header_val(&r, "location").expect("Location header on login");
        let state = qparam(&loc, "state").expect("state in authorize url");
        let nonce = qparam(&loc, "nonce").expect("nonce in authorize url");
        (state, nonce, loc)
    }

    // ------------------------------------------------------------------------------------------------
    // 1) HAPPY PATH — a valid OIDC callback issues a session + maps to a (auto-provisioned) user.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn valid_callback_issues_session_and_maps_user() {
        let ledger = tmp_path("sso-happy-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "operator", "email");
        let addr = serve(app.clone()).await;

        // login -> authorize redirect carries S256 PKCE + our client_id + return target's state/nonce.
        let (state, nonce, loc) = start_login(addr, "http://localhost/app").await;
        assert!(loc.starts_with(&format!("{issuer}/authorize?")), "authorize endpoint: {loc}");
        assert!(loc.contains("code_challenge_method=S256"), "PKCE S256: {loc}");
        assert!(loc.contains("client_id=forge-client"), "client_id present: {loc}");

        // IdP returns an ID token bound to OUR nonce, aud, issuer.
        let idt = make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "oidc-sub-123", "Alice@Corp.com", &nonce, 3600);
        *slot.lock().unwrap() = idt;

        let r = http_raw(addr, &get_req(&format!("/api/sso/callback?code=authz-code&state={state}"), "")).await;
        assert_eq!(parse_status(&r), 302, "valid callback should 302: {r}");
        assert_eq!(header_val(&r, "location").as_deref(), Some("http://localhost/app"), "redirect to allowlisted target");
        let tok = cookie_token(&r).expect("forge_session cookie issued");
        let sc = header_val(&r, "set-cookie").unwrap();
        assert!(sc.contains("HttpOnly") && sc.contains("SameSite=Strict"), "hardened cookie: {sc}");

        // The session identifies the mapped user (email 'Alice@Corp.com' -> login 'alice.corp.com', operator).
        let w = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&w), 200, "whoami with SSO session: {w}");
        assert!(body_of(&w).contains("\"login\":\"alice.corp.com\""), "mapped login: {}", body_of(&w));
        assert!(body_of(&w).contains("\"role\":\"operator\""), "provisioned role: {}", body_of(&w));

        // Ledger: login recorded, secret/tokens NEVER present.
        let lines = crate::read_ledger_lines(&ledger);
        let last = lines.last().expect("ledger entry");
        assert_eq!(last["kind"], "console.sso.login");
        assert_eq!(last["detail"]["actor"], "alice.corp.com");
        assert_eq!(last["detail"]["provisioned"], true);
        let ser = serde_json::to_string(&last).unwrap();
        assert!(!ser.contains("s3cr3t-value"), "client_secret must never be ledgered");
        assert!(!ser.contains("id_token") && !ser.contains("mock-access-token"), "tokens must never be ledgered");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 2) FAIL-CLOSED — mismatched state is rejected (no session).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn mismatched_state_is_rejected() {
        let ledger = tmp_path("sso-state-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        set_config(&app, "http://idp.invalid", vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        // callback with a state that was never issued -> 403, no cookie.
        let r = http_raw(addr, &get_req("/api/sso/callback?code=c&state=deadbeefdoesnotexist", "")).await;
        assert_eq!(parse_status(&r), 403, "unknown state -> 403: {r}");
        assert!(body_of(&r).contains("invalid_state"), "reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none(), "no session on state mismatch");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 3) FAIL-CLOSED — mismatched nonce is rejected.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn mismatched_nonce_is_rejected() {
        let ledger = tmp_path("sso-nonce-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        let (state, _nonce, _) = start_login(addr, "http://localhost/app").await;
        // ID token carries the WRONG nonce.
        let idt = make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "sub-x", "u@x.com", "not-the-nonce", 3600);
        *slot.lock().unwrap() = idt;
        let r = http_raw(addr, &get_req(&format!("/api/sso/callback?code=c&state={state}"), "")).await;
        assert_eq!(parse_status(&r), 403, "nonce mismatch -> 403: {r}");
        assert!(body_of(&r).contains("invalid_id_token"), "reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none());
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 4) FAIL-CLOSED — wrong audience is rejected.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let ledger = tmp_path("sso-aud-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        let (state, nonce, _) = start_login(addr, "http://localhost/app").await;
        // aud is some OTHER client.
        let idt = make_id_token(GOOD_PEM, KID, &issuer, "someone-else", "sub-x", "u@x.com", &nonce, 3600);
        *slot.lock().unwrap() = idt;
        let r = http_raw(addr, &get_req(&format!("/api/sso/callback?code=c&state={state}"), "")).await;
        assert_eq!(parse_status(&r), 403, "aud mismatch -> 403: {r}");
        assert!(body_of(&r).contains("invalid_id_token"), "reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none());
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 5) FAIL-CLOSED — bad signature (token signed by a key NOT in the JWKS) is rejected.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn bad_signature_is_rejected() {
        let ledger = tmp_path("sso-sig-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        let (state, nonce, _) = start_login(addr, "http://localhost/app").await;
        // Signed with ROGUE key but claims KID=test-key-1 (which the JWKS maps to the GOOD key) -> sig fails.
        let idt = make_id_token(ROGUE_PEM, KID, &issuer, "forge-client", "sub-x", "u@x.com", &nonce, 3600);
        *slot.lock().unwrap() = idt;
        let r = http_raw(addr, &get_req(&format!("/api/sso/callback?code=c&state={state}"), "")).await;
        assert_eq!(parse_status(&r), 403, "bad signature -> 403: {r}");
        assert!(body_of(&r).contains("invalid_id_token"), "reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none());
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 6) REDIRECT ALLOWLIST — a non-allowlisted return target is refused up front (fail-closed).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn non_allowlisted_redirect_is_refused() {
        let ledger = tmp_path("sso-redir-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        set_config(&app, "http://idp.invalid", vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        let r = http_raw(
            addr,
            &get_req(&format!("/api/sso/login?return_to={}", pct_encode("https://evil.example/steal")), ""),
        )
        .await;
        assert_eq!(parse_status(&r), 403, "off-list redirect -> 403: {r}");
        assert!(body_of(&r).contains("redirect_not_allowed"), "reason: {}", body_of(&r));
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 7) CONFIG — client_secret is write-only: redacted on GET, but persisted in the DB.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn client_secret_redacted_on_config_get() {
        let ledger = tmp_path("sso-cfg-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        // Provision an admin + open a session (config routes require an admin session).
        let admin_tok = {
            let hash = crate::hash_pw("adminpw");
            let db = app.db();
            crate::upsert_user(&db, "root", "admin", &hash).unwrap();
            let id: i64 = db.query_row("SELECT id FROM users WHERE login=?", ["root"], |r| r.get(0)).unwrap();
            drop(db);
            crate::create_session(&app, id).0
        };
        app.recompute_auth_required();
        let addr = serve(app.clone()).await;
        let auth = format!("Cookie: forge_session={admin_tok}\r\n");

        // POST config WITH a secret.
        let cfg = json!({
            "issuer": "http://idp.invalid",
            "client_id": "forge-client",
            "client_secret": "top-secret-oidc",
            "redirect_uri": "http://localhost/api/sso/callback",
            "allowed_redirect_uris": ["http://localhost/app"],
            "provisioning": "match"
        })
        .to_string();
        let r = http_raw(addr, &post_req("/api/sso/config", &cfg, &auth)).await;
        assert_eq!(parse_status(&r), 200, "admin config POST: {r}");
        assert!(!body_of(&r).contains("top-secret-oidc"), "POST response must not echo the secret: {}", body_of(&r));

        // GET config — secret redacted, but presence flagged.
        let g = http_raw(addr, &get_req("/api/sso/config", &auth)).await;
        assert_eq!(parse_status(&g), 200, "admin config GET: {g}");
        assert!(!body_of(&g).contains("top-secret-oidc"), "secret must be redacted on GET: {}", body_of(&g));
        assert!(body_of(&g).contains("\"client_secret_set\":true"), "secret presence flagged: {}", body_of(&g));
        assert!(!body_of(&g).contains("\"client_secret\""), "no client_secret key at all: {}", body_of(&g));

        // But the secret IS persisted (write-only store).
        {
            let db = app.db();
            let stored = crate::settings_get(&db, CFG_KEY).unwrap();
            assert!(stored.contains("top-secret-oidc"), "secret persisted verbatim in settings");
        }
        // Ledger never carries the secret.
        let lines = crate::read_ledger_lines(&ledger);
        let last = lines.last().expect("config ledger entry");
        assert_eq!(last["kind"], "console.sso.config");
        assert!(!serde_json::to_string(&last).unwrap().contains("top-secret-oidc"), "secret never ledgered");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 8) FLAG OFF — /api/sso/* disabled (404) and LOCAL login is unchanged.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn flag_off_disables_sso_and_keeps_local_login() {
        let ledger = tmp_path("sso-off-ledger");
        let app = sso_test_app(&ledger);
        // NOTE: flag NOT engaged. Provision a local admin so /api/login has something to authenticate.
        {
            let hash = crate::hash_pw("localpw");
            let db = app.db();
            crate::upsert_user(&db, "root", "admin", &hash).unwrap();
        }
        app.recompute_auth_required();
        let addr = serve(app).await;

        // Every /api/sso/* route behaves as absent (404) with the flag off.
        for path in ["/api/sso/login", "/api/sso/callback?code=c&state=s", "/api/sso/config"] {
            let r = http_raw(addr, &get_req(path, "")).await;
            assert_eq!(parse_status(&r), 404, "flag off -> {path} disabled (404): {r}");
        }

        // LOCAL login is completely unchanged: valid creds -> 200 + forge_session cookie.
        let lr = http_raw(addr, &post_req("/api/login", "{\"login\":\"root\",\"password\":\"localpw\"}", "")).await;
        assert_eq!(parse_status(&lr), 200, "local login still works: {lr}");
        assert!(cookie_token(&lr).is_some(), "local login still issues forge_session");
        // Bad creds still rejected.
        let br = http_raw(addr, &post_req("/api/login", "{\"login\":\"root\",\"password\":\"wrong\"}", "")).await;
        assert_eq!(parse_status(&br), 401, "local login still rejects bad creds: {br}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 9) UNIT — sanitize_login / redirect_allowed / pct_encode / code_challenge edge cases.
    // ------------------------------------------------------------------------------------------------
    #[test]
    fn unit_helpers() {
        assert_eq!(sanitize_login("Alice@Corp.com").unwrap(), "alice.corp.com");
        assert_eq!(sanitize_login("auth0|abc123").unwrap(), "auth0-abc123");
        assert!(sanitize_login("@@@").is_err(), "nothing valid remains -> err");
        let cfg = SsoConfig {
            issuer: "http://i".into(),
            client_id: "c".into(),
            client_secret: "s".into(),
            redirect_uri: "http://localhost/cb".into(),
            allowed_redirect_uris: vec!["http://localhost/app".into()],
            provisioning: "match".into(),
            default_role: "viewer".into(),
            user_claim: "email".into(),
        };
        assert!(redirect_allowed(&cfg, "http://localhost/app"), "exact allowlist match");
        assert!(redirect_allowed(&cfg, "/dashboard"), "safe same-origin relative");
        assert!(redirect_allowed(&cfg, "/"), "root allowed");
        assert!(!redirect_allowed(&cfg, "https://evil/x"), "off-list absolute refused");
        assert!(!redirect_allowed(&cfg, "//evil.example"), "protocol-relative refused");
        assert_eq!(pct_encode("a b&c=d"), "a%20b%26c%3Dd");
        // Known RFC 7636 PKCE S256 test vector.
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
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
/// Name of the browser-binding cookie carrying the OAuth `state` (SSO F2 login-CSRF defence). Set at
/// `login_start`, required to match the returned `state` at `callback`, then cleared.
const STATE_COOKIE: &str = "forge_sso_state";

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
    /// When the login key is derived from `email`, REQUIRE the ID token's `email_verified` to be true
    /// (fail-closed anti-collision — an IdP with unverified/mutable email must not let an attacker collide
    /// with a privileged local login). Default `true`; an admin can opt out only deliberately.
    require_email_verified: bool,
}

/// L6 — clamp the SSO auto-provisioning DEFAULT role to at most `operator` (SSO never auto-confers admin).
/// Parity with `rbac::scim_role_for_group`'s `clamp_role(_, true)`. `admin` -> `operator`; a valid
/// `operator`/`viewer` is kept; anything unknown -> `viewer` (fail-closed).
fn clamp_sso_default_role(role: &str) -> String {
    match role {
        "operator" | "admin" => "operator",
        _ => "viewer",
    }
    .to_string()
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
    // L6 — the SSO auto-provisioning DEFAULT role is BOUNDED to viewer|operator: SSO must NEVER auto-confer
    // admin (parity with SCIM's `scim_role_for_group` clamp). This bounds ONLY the default fallback used when
    // no IdP group maps; an EXPLICIT group→admin mapping is still honoured for an interactive SSO login (that
    // path flows through `rbac::resolve`/`apply_to_user`, not this field). Clamp at LOAD so every consumer
    // (map_user provisioning, the F6 downgrade target) sees the bounded value, even for a stored config that
    // predates the clamp. admin -> operator; unknown -> viewer (fail-closed).
    let default_role = clamp_sso_default_role(v.get("default_role").and_then(|x| x.as_str()).unwrap_or("viewer"));
    let user_claim = v.get("user_claim").and_then(|x| x.as_str()).unwrap_or("email").to_string();
    // Default TRUE (fail-closed): absent/malformed => require email_verified. Only an explicit `false`
    // (bool) opts out.
    let require_email_verified = v.get("require_email_verified").and_then(|x| x.as_bool()).unwrap_or(true);
    Some(SsoConfig {
        issuer,
        client_id,
        client_secret,
        redirect_uri,
        allowed_redirect_uris,
        provisioning,
        default_role,
        user_claim,
        require_email_verified,
    })
}

// `err` / `disabled` consolidés dans `common` (corps + signatures byte-identiques à compliance/scim — dedup Wave).
use crate::common::{disabled, err};

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
    // BIND `state` to THIS browser (login-CSRF / session-fixation defence, SSO F2): a short-lived
    // HttpOnly cookie carrying the state. `SameSite=Lax` (NOT Strict) so it survives the top-level GET
    // the IdP uses to redirect back to /callback; `Secure` by default (opt-out via FORGE_COOKIE_INSECURE
    // for local plain-HTTP dev). The callback requires cookie == returned `state` before consuming the
    // pending entry — a forged callback in a victim's browser (which never started this flow) has no
    // matching cookie and is rejected (fail-closed).
    let state_cookie = format!(
        "{STATE_COOKIE}={state}; HttpOnly; SameSite=Lax; Path=/api/sso; Max-Age={PENDING_TTL_SECS}{}",
        if crate::env_flag_enabled("FORGE_COOKIE_INSECURE") { "" } else { "; Secure" }
    );
    (
        StatusCode::FOUND,
        [(header::LOCATION, authorize), (header::SET_COOKIE, state_cookie)],
        "redirecting to identity provider",
    )
        .into_response()
}

/// GET /api/sso/callback?code=&state= — finish the flow. Validates state (server-side, one-time),
/// exchanges the code (with the PKCE verifier) for tokens, validates the ID token, maps to a Forge user,
/// issues the `forge_session` cookie and 302s to the (re-validated) allowlisted return target.
async fn callback(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
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

    // BROWSER BINDING (SSO F2): the state cookie set at login_start MUST be present AND equal the returned
    // `state`. Absent or mismatched => reject BEFORE consuming the pending entry (fail-closed anti login-CSRF
    // / session-fixation — a callback replayed into a browser that never initiated this flow has no cookie).
    let cookie_state = cookie_value(&headers, STATE_COOKIE).unwrap_or_default();
    if cookie_state.is_empty() || !crate::ct_eq_str(&cookie_state, state) {
        return err(StatusCode::FORBIDDEN, "state_binding_failed", "missing or mismatched state cookie");
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
    let (sub, email, email_verified, groups) = match validate_id_token(&cfg, &pend.nonce, id_token, &jwks) {
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
    let (user_id, login, provisioned) = match map_user(&app, &cfg, &sub, &email, email_verified, &provision_role) {
        Ok(x) => x,
        Err(e) => return err(StatusCode::FORBIDDEN, "user_mapping_failed", e),
    };
    if provisioned {
        // A new individual account exists now — re-arm the auth gate on DB state (mirrors account CRUD).
        app.recompute_auth_required();
        app.bump_cache_epoch(); // B6 (HA): invalidate peers' auth_required cache (SSO JIT-provisioned account)
    }
    // F6 — this account's role is SSO-owned once SSO JIT-provisions it OR its groups confer a role. The
    // marker bounds the fail-closed downgrade below to accounts SSO controls (never a local/non-SSO admin).
    if provisioned || resolved.role.is_some() {
        let store = app.store();
        mark_sso_managed(&store, user_id);
    }
    // Sync the account's role + tenant grants to what its groups confer (fail-closed least privilege; a
    // designated super-admin login is never touched). `cap_operator=false`: an admin-configured group ->
    // admin mapping is honored for an interactive SSO login. No matching group => role stays as-is.
    crate::rbac::apply_to_user(&app, user_id, &login, &resolved, false);

    // F6 — STALE-PRIVILEGE DE-PROVISIONING (fail-closed): the IdP asserted a groups claim on this login but
    // NONE mapped to a role (e.g. an admin group was removed at the IdP). `apply_to_user` leaves the role
    // untouched in that case, which would strand a stale elevated role. So DOWNGRADE the account to the
    // configured default role — but ONLY when (a) the account is SSO-managed (never a local admin who never
    // logged in via SSO), (b) it is not a designated super-admin, and (c) this strictly LOWERS privilege
    // (never an accidental upgrade). No groups claim at all => leave the role as-is (the IdP asserted nothing).
    if resolved.role.is_none() && !groups.is_empty() && !crate::tenancy::is_superadmin_login(&app, &login) {
        let default_role = crate::validate_role(&cfg.default_role).unwrap_or_else(|_| "viewer".to_string());
        let downgrade: Option<String> = {
            let store = app.store();
            if is_sso_managed(&store, user_id) {
                let current: String = store
                    .query_row("SELECT role FROM users WHERE id=?", &crate::sql_params![user_id], |r| r.get_str(0))
                    .unwrap_or_default();
                if crate::role_rank(&current) > crate::role_rank(&default_role)
                    && store
                        .execute("UPDATE users SET role=? WHERE id=?", &crate::sql_params![&default_role, user_id])
                        .is_ok()
                {
                    Some(current)
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(from) = downgrade {
            crate::append_console_ledger(
                &app,
                "console.sso.downgrade",
                json!({ "login": login, "from": from, "to": default_role, "reason": "no_mapped_group" }),
            );
        }
    }

    // Re-validate the stored return target (defence in depth) before redirecting the browser.
    if !redirect_allowed(&cfg, &pend.return_to) {
        return err(StatusCode::FORBIDDEN, "redirect_not_allowed", "return_to is not in the allowlist");
    }

    // Issue THE SAME session cookie the local /api/login issues (HttpOnly, SameSite=Strict, Secure).
    // Propagate a session-persist failure as 500 rather than handing out a non-persisted (dead) token.
    let (token, _expires) = match crate::try_create_session(&app, user_id) {
        Ok(t) => t,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "session_persist_failed", format!("could not persist session: {e}")),
    };
    let ttl = crate::session_ttl_secs();
    // `Secure` par défaut (durcissement) — le cookie de session ne transite jamais en clair ; l'opt-out
    // `FORGE_COOKIE_INSECURE=1` (dev http-loopback) est géré DANS session_cookie. Plus de dépendance au
    // `X-Forwarded-Proto` spoofable pour ce flag. Le callback OIDC arrive via une navigation top-level.
    let cookie = crate::session_cookie(&token, ttl);
    // Clear the one-time state-binding cookie now that the flow completed (hygiene).
    let clear_state = format!("{STATE_COOKIE}=; HttpOnly; SameSite=Lax; Path=/api/sso; Max-Age=0");

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
        axum::response::AppendHeaders([
            (header::SET_COOKIE, cookie),
            (header::SET_COOKIE, clear_state),
            (header::LOCATION, pend.return_to),
        ]),
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
    // Fail-closed default: require email_verified unless the admin explicitly sends `false`.
    let require_email_verified = body.get("require_email_verified").and_then(|v| v.as_bool()).unwrap_or(true);

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
        "require_email_verified": require_email_verified,
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
            "require_email_verified": require_email_verified,
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
) -> Result<(String, String, bool, Vec<String>), String> {
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
    // `email_verified` — OIDC allows either a JSON bool `true` or the STRING `"true"` (some IdPs emit the
    // latter). Anything else (absent, false, "false", other) => NOT verified (fail-closed). Consumed by
    // `map_user` when the login key is derived from email (anti-collision, finding SSO F1).
    let email_verified = match claims.get("email_verified") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    };
    // OIDC `groups` claim (array of strings, or a single string) — feeds the advanced-RBAC group mapping.
    // Absent/malformed => empty => the identity keeps its least-privilege default (fail-closed).
    let groups = crate::rbac::groups_from_claims(&claims);
    Ok((sub, email, email_verified, groups))
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
fn map_user(app: &App, cfg: &SsoConfig, sub: &str, email: &str, email_verified: bool, provision_role: &str) -> Result<(i64, String, bool), String> {
    // The login key is `sub` when configured; otherwise `email` if present, else `sub` as a last resort.
    let use_email_key = cfg.user_claim != "sub" && !email.is_empty();
    // FAIL-CLOSED anti-collision (SSO F1): when the login key comes from `email`, the ID token MUST assert
    // `email_verified: true` — an IdP that permits unverified/mutable email could otherwise let an attacker
    // collide with a privileged local login. Configurable, defaults to required. `sub`-keyed mapping is a
    // stable opaque identifier and is exempt (no email in the login key).
    if use_email_key && cfg.require_email_verified && !email_verified {
        return Err(format!(
            "email '{email}' is not verified by the IdP (email_verified != true) — refusing to map by email (fail-closed)"
        ));
    }
    let raw = if use_email_key { email } else { sub };
    let login = sanitize_login(raw)?;

    // Existing account?
    {
        let store = app.store();
        if let Ok(id) = store.query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![&login], |r| r.get_i64(0)) {
            // M4 — NO AUTO-ADOPT of an UNMARKED LOCAL account (fail-closed). Only an account that already
            // carries an explicit IdP-provisioning marker may be authenticated-as by an SSO identity:
            //   - `sso_managed` — set when SSO auto-provisions it, or by a future admin link; OR
            //   - `scim_user`   — a SCIM-provisioned account (combined SCIM+SSO: an IdP provisions users via
            //     SCIM, those users then interactively sign in via SSO — a legitimate enterprise pattern).
            // A pre-existing UNMARKED LOCAL account (created via /api/setup or admin CRUD, never via SSO or
            // SCIM) is NEVER adopted by a colliding IdP claim: otherwise an attacker whose sanitised
            // `sub`/`email` collides with a privileged local login could authenticate AS it — and the
            // caller's `apply_to_user` would then re-role it from the IdP `groups`. Refusing here also
            // PREVENTS that re-role (the caller returns 403 before it). The security property is unchanged:
            // an IdP claim can never hijack a plain local account; only an account the IdP already OWNS
            // (via SSO or SCIM provisioning) can be signed into via SSO.
            if is_sso_managed(&store, id) || is_scim_managed(&store, id) {
                return Ok((id, login, false));
            }
            return Err(format!(
                "account '{login}' already exists and is neither SSO- nor SCIM-managed — refusing to auto-adopt a local account (fail-closed; an admin must explicitly link it to SSO, or it must be SCIM-provisioned, before an SSO identity can sign in as it)"
            ));
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
        drop(store);
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
/// (protocol-relative), not `/\` (backslash treated as `/` by some browsers), and contains NO ASCII
/// control character (CR/LF/TAB/NUL/… — header/redirect smuggling in a `Location:` value).
fn safe_relative(s: &str) -> bool {
    s.starts_with('/')
        && !s.starts_with("//")
        && !s.starts_with("/\\")
        && !s.chars().any(|c| c.is_ascii_control())
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
               expires BIGINT NOT NULL);
             CREATE TABLE IF NOT EXISTS sso_managed(
               user_id BIGINT PRIMARY KEY);",
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
           expires INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS sso_managed(
           user_id INTEGER PRIMARY KEY);",
    );
    let _ = store.execute("DELETE FROM sso_pending WHERE expires <= ?", &crate::sql_params![crate::now_epoch()]);
}

/// Mark `user_id` as SSO-managed (its role is authoritatively driven by the IdP group mapping). Idempotent.
/// Used to bound the F6 privilege-downgrade to accounts SSO owns (never a local/non-SSO admin).
fn mark_sso_managed(store: &crate::store::Store, user_id: i64) {
    let _ = store.execute(
        "INSERT INTO sso_managed(user_id) VALUES(?) ON CONFLICT DO NOTHING",
        &crate::sql_params![user_id],
    );
}

/// Is `user_id` an SSO-managed account (role owned by the IdP group mapping)?
fn is_sso_managed(store: &crate::store::Store, user_id: i64) -> bool {
    store
        .query_row("SELECT 1 FROM sso_managed WHERE user_id=?", &crate::sql_params![user_id], |_| Ok(()))
        .is_ok()
}

/// Is `user_id` a SCIM-provisioned account (has a `scim_user` mapping row — the same predicate SCIM uses
/// everywhere to decide an account it OWNS)? Used to allow combined SCIM+SSO: a SCIM-provisioned account
/// may interactively sign in via SSO. In a SCIM-less deployment the `scim_user` table does not exist, the
/// query errs, and this returns `false` (fail-closed — no bearing on the M4 unmarked-local-account gate).
fn is_scim_managed(store: &crate::store::Store, user_id: i64) -> bool {
    store
        .query_row("SELECT 1 FROM scim_user WHERE user_id=?", &crate::sql_params![user_id], |_| Ok(()))
        .is_ok()
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
    // SSRF / client_secret-exfil defence (SSO F5): PIN every discovered endpoint to the SAME ORIGIN
    // (scheme+host+port) as the VALIDATED issuer. A hostile or redirected discovery document could
    // otherwise steer the client_secret token POST, the JWKS fetch, or the browser authorize redirect to
    // an attacker-controlled or internal target. Same-origin required — fail-closed on any cross-origin.
    let issuer_origin = origin_of(&issuer)
        .ok_or_else(|| format!("configured issuer '{issuer}' has no parseable http(s) origin"))?;
    for (name, ep) in [
        ("token_endpoint", &token_endpoint),
        ("jwks_uri", &jwks_uri),
        ("authorization_endpoint", &authorization_endpoint),
    ] {
        match origin_of(ep) {
            Some(o) if o == issuer_origin => {}
            _ => {
                return Err(format!(
                    "discovery {name} '{ep}' is not same-origin as the issuer '{issuer}' (rejected — anti-SSRF)"
                ))
            }
        }
    }
    Ok(Discovery { authorization_endpoint, token_endpoint, jwks_uri })
}

/// Parse the ORIGIN `(scheme, host_lowercased, port)` of an http(s) URL, normalising the default port
/// (80 for http, 443 for https) so `http://h` and `http://h:80` compare equal. Returns `None` for a
/// non-http(s) or malformed URL (caller treats that as a mismatch → fail-closed).
fn origin_of(url: &str) -> Option<(String, String, u16)> {
    let (scheme, default_port, rest) = match url.split_once("://") {
        Some(("https", r)) => ("https".to_string(), 443u16, r),
        Some(("http", r)) => ("http".to_string(), 80u16, r),
        _ => return None,
    };
    // Authority = up to the first '/', '?' or '#'.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    // Strip any userinfo (never expected here, but never let it spoof the host component).
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let parsed: u16 = p.parse().ok()?;
            (h, parsed)
        }
        None => (hostport, default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host.to_ascii_lowercase(), port))
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
    // SSRF defense-in-depth (CONSOLE integration): the OIDC token endpoint is an admin/discovery-configured
    // URL the console fetches itself — NOT an engine scope-guarded target. Reject internal/metadata/private
    // targets on the RESOLVED connect IP (anti-DNS-rebinding), unless the escape hatch is set. Same guard as
    // the GET client so discovery/JWKS (via http_get_blocking) and this token POST are covered identically.
    crate::guard_integration_addr(&addr)?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect {addr} failed: {e}"))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: forge-sso\r\nAccept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if !basic_b64.is_empty() {
        req.push_str(&format!("Authorization: Basic {basic_b64}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).map_err(|e| format!("write failed: {e}"))?;
    let mut raw = Vec::new();
    // BORNE MÉMOIRE (anti-OOM) : `take(MAX_RESPONSE_BYTES)` cape la lecture d'une réponse token illimitée
    // d'un IdP hostile/compromis — miroir de net.rs::http_get_blocking (L11). Le read-timeout borne la
    // latence ; ce cap borne la mémoire.
    (&mut stream)
        .take(crate::net::MAX_RESPONSE_BYTES)
        .read_to_end(&mut raw)
        .map_err(|e| format!("read failed: {e}"))?;
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

/// CSPRNG hex of `nbytes` bytes — delegates to the SHARED `common::rand_hex` (dedup Wave; byte-identical).
/// `what="SSO"` names the secret in the fail-closed entropy panic message.
fn rand_hex(nbytes: usize) -> String {
    crate::common::rand_hex(nbytes, "SSO")
}

/// Read a named cookie's value from the request `Cookie` header (first match). `None` if absent/empty.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())?;
    let want = format!("{name}=");
    for part in raw.split(';') {
        let p = part.trim();
        if let Some(val) = p.strip_prefix(&want) {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
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
mod tests;

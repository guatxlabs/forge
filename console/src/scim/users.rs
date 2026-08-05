// SPDX-License-Identifier: AGPL-3.0-or-later
//! `scim` — § USERS EXTRAITE (PURE MOVE depuis `console/src/scim/mod.rs`, corps byte-identique).
//! Porte les 6 handlers `/scim/v2/Users` et `/scim/v2/Users/:id` (list / create / get / put / patch
//! / delete) ainsi que `apply_update`, le helper que PUT et PATCH partagent et qui n'est référencé
//! nulle part ailleurs. ENFANT de `scim`, ce module voit les items PRIVÉS du parent (`use super::*;`) :
//! les helpers partagés (`scim_err`, `gate`, `ensure_schema`, `parse_id`, `user_resource`,
//! `UserAttrs`, `derive_login`, `parse_username_filter`, …) restent dans `mod.rs` et sont consommés
//! d'ici SANS aucun bump de visibilité. Seule transformation : les 6 handlers que `routes()` nomme
//! depuis le parent sont `pub(super)` (le parent n'est pas un descendant, il ne verrait pas leur
//! forme privée). Aucun symbole de `§ GROUPS` n'est référencé ici.
use super::*;

// ============================================================================================
// USERS
// ============================================================================================

/// GET /scim/v2/Users[?filter=userName eq "x"][&startIndex&count] — list SCIM-PROVISIONED users only
/// (never the local admin accounts). Supports the single `userName eq "…"` filter Okta/Azure use to probe
/// existence before create.
pub(super) async fn users_list(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
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
pub(super) async fn users_create(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
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
pub(super) async fn user_get(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
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
pub(super) async fn user_put(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
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
pub(super) async fn user_patch(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
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
pub(super) async fn user_delete(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
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

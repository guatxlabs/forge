// SPDX-License-Identifier: AGPL-3.0-or-later
//! `scim` — § GROUPS EXTRAITE (PURE MOVE depuis `console/src/scim/mod.rs`, corps byte-identique).
//! Porte les 5 handlers `/scim/v2/Groups` et `/scim/v2/Groups/:id` (list / create / get / patch —
//! branché aussi sur PUT — / delete) ainsi que `add_member`, le helper fail-closed que create et
//! patch partagent et qui n'est référencé nulle part ailleurs. ENFANT de `scim`, ce module voit les
//! items PRIVÉS du parent (`use super::*;`) : les helpers partagés (`scim_err`, `gate`,
//! `ensure_schema`, `parse_id`, `group_resource`, `role_for_group`, `member_id_of`,
//! `member_ids_from_resource`, `extract_member_path_id`, …) restent dans `mod.rs` et sont consommés
//! d'ici SANS aucun bump de visibilité. Seule transformation : les 5 handlers que `routes()` nomme
//! depuis le parent sont `pub(super)`. Aucun symbole de `§ USERS` n'est référencé ici.
use super::*;

// ============================================================================================
// GROUPS (best-effort) — membership maps to a SCOPED role (ties to the advanced-RBAC slice). A group can
// only ever confer viewer|operator (never admin, never super-admin). When enterprise tenancy is engaged,
// membership additionally lands a scoped tenant_grant on the default tenant.
// ============================================================================================

/// GET /scim/v2/Groups — list groups.
pub(super) async fn groups_list(State(app): State<App>, headers: HeaderMap) -> Response {
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
pub(super) async fn groups_create(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
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
pub(super) async fn group_get(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
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
pub(super) async fn group_patch(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
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
        // PUT-style full replace of membership. FAIL-CLOSED + TRANSACTIONAL (L7): the membership wipe runs in
        // a `with_tx` and its Result is MATCHED — a DB error ROLLS BACK and 500s BEFORE any re-add or the
        // ledger, so `console.scim.group.update` never attests a replace whose wipe silently failed (was a
        // swallowed `let _ = …execute()`). Mirrors the group_delete tx pattern.
        {
            let store = app.store();
            if let Err(e) = store.with_tx(|tx| {
                tx.execute("DELETE FROM scim_group_member WHERE group_id=?", &crate::sql_params![gid])?;
                Ok(())
            }) {
                return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("membership replace failed: {e}"), None);
            }
        }
        for uid in members.iter().filter_map(member_id_of) {
            if let Err(e) = add_member(&app, gid, uid, &role) {
                return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("member add failed: {e}"), None);
            }
            added += 1;
        }
    }
    // Collect membership REMOVALS during the ops scan, then apply them ATOMICALLY below (L7). Adds are applied
    // in-loop (add_member re-locks the store and re-roles the member, so it cannot run inside a held tx guard).
    let mut remove_uids: Vec<i64> = Vec::new();
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
                        remove_uids.push(uid);
                        removed += 1;
                    }
                }
                _ => {}
            }
        }
    }
    // Apply all membership removals ATOMICALLY (L7): one `with_tx`, each DELETE's Result MATCHED — a partial
    // failure ROLLS BACK (no inconsistent membership) and 500s BEFORE the ledger (no false `success`
    // attestation of a removal that never landed). Was a swallowed `let _ = app.store().execute()`.
    if !remove_uids.is_empty() {
        let store = app.store();
        if let Err(e) = store.with_tx(|tx| {
            for uid in &remove_uids {
                tx.execute("DELETE FROM scim_group_member WHERE group_id=? AND user_id=?", &crate::sql_params![gid, *uid])?;
            }
            Ok(())
        }) {
            return scim_err(StatusCode::INTERNAL_SERVER_ERROR, format!("membership remove failed: {e}"), None);
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
pub(super) async fn group_delete(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
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

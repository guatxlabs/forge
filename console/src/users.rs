// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — ADMINISTRATION WEB DES COMPTES (#4) + GOUVERNANCE DES CONNECTEURS extraites de main.rs
//! (PURE MOVE). Regroupe le CRUD des comptes réservé `check_admin` (session admin, fail-closed) — chaque
//! mutation ATTRIBUÉE à l'admin acteur et LEDGERISÉE (`append_console_ledger`), jamais de `pass_hash` ni de
//! mot de passe dans le ledger ni dans les réponses — et la gouvernance opérateur des modules :
//!   - helpers : `role_rank` (rang de privilège, détection de rétrogradation) et `enabled_admin_count`
//!     (garde-fou « dernier admin », fail-closed) ;
//!   - cœurs : `admin_list_users`/`admin_create_user`/`admin_update_user`/`admin_delete_user` (CRUD) et
//!     `admin_set_module` (intention opérateur sur un connecteur : enabled/available_override/web_allowed) ;
//!   - handlers HTTP : `users_list` (GET /api/users), `users_create` (POST /api/users), `users_update`
//!     (POST /api/users/:login), `users_delete` (DELETE /api/users/:login) et `module_governance`
//!     (POST /api/modules/:kind).
//!
//! Les structs d'ÉTAT (App) RESTENT à la racine de crate (stage `state`) et sont référencées via `crate::*`.
//! Réutilise App + les helpers de la racine (`validate_login`/`validate_role`/`validate_campaign`/`gs`/
//! `hash_pw`/`upsert_user`/`modules_catalog`/`append_console_ledger`/`check_admin`/`admin_denied`/
//! `attribution_login`/`tenancy::guard_superadmin_user_mutation` …) via `use crate::*`, et est re-exporté à
//! la racine par `pub(crate) use crate::users::*` — les routes de build_router (`get(users_list).post(
//! users_create)`, `post(users_update).delete(users_delete)`, `post(module_governance)`), les appelants
//! inter-modules (`crate::role_rank` depuis rbac) ET les tests inline de main.rs (`super::*`) résolvent donc
//! ces handlers/helpers INCHANGÉS.
use crate::*;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

// =====================================================================================
// ADMINISTRATION WEB DES COMPTES (#4) — CRUD réservé check_admin (session admin, fail-closed),
// chaque mutation ATTRIBUÉE à l'admin acteur et LEDGERISÉE (append_console_ledger). Aucune route ne
// renvoie jamais `pass_hash`. Après chaque mutation, `auth_required` est recalculé (la gate d'auth
// s'engage/se désengage sur l'ÉTAT DB — cf. recompute_auth_required). Les mots de passe/hash n'entrent
// JAMAIS dans le ledger (login/rôle/booléens seuls). Roles conservés tels quels : viewer|operator|admin.
// =====================================================================================

/// Rang de privilège d'un rôle (viewer < operator < admin). Sert à détecter une RÉTROGRADATION (rang
/// décroissant) qui doit purger les sessions du compte pour un effet immédiat. Rôle inconnu -> 0.
pub(crate) fn role_rank(r: &str) -> i32 {
    match r {
        "admin" => 3,
        "operator" => 2,
        "viewer" => 1,
        _ => 0,
    }
}

/// Nombre d'admins ACTIVÉS (`role='admin' AND disabled=0`). Substrat du garde-fou « dernier admin » :
/// on n'autorise JAMAIS une opération qui laisserait 0 admin activé (verrouillage total de l'admin).
/// À appeler EN TENANT DÉJÀ le guard `db` (pas de re-lock) pour que le check+mutation soient ATOMIQUES
/// sous le même mutex (anti-TOCTOU). Échec de lecture -> 0 => l'opération est refusée (fail-closed).
pub(crate) fn enabled_admin_count(store: &crate::store::Store) -> i64 {
    store.query_row("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0", &[], |r| r.get_i64(0)).unwrap_or(0)
}

/// Liste les comptes pour l'admin — `{login, role, disabled, created}`. Ne SÉLECTIONNE même pas
/// `pass_hash` (fuite structurellement impossible). Ordre alphabétique. Lecture pure (aucun ledger).
pub(crate) fn admin_list_users(app: &App) -> Vec<Value> {
    let store = app.store();
    store.query_lax("SELECT login, role, disabled, created FROM users ORDER BY login", &[], |r| {
        Ok(json!({
            "login": r.get_str(0)?,
            "role": r.get_str(1)?,
            "disabled": r.get_i64(2)? != 0,
            "created": r.get_opt_str(3)?.unwrap_or_default(),
        }))
    })
    .unwrap_or_default()
}

/// Crée un compte individuel. Valide login/rôle (fail-closed), hash argon2id HORS mutex, refuse un login
/// déjà pris (409 — l'édition sert à muter). Recalcule `auth_required` (1er compte activé -> gate) et
/// ledgerise avec l'admin acteur (login/rôle seuls, JAMAIS le mot de passe). Retourne la vue publique.
// ALLOW significant_drop_tightening: the block is a check-then-act (SELECT the login exists? -> INSERT)
// under ONE store lock. Tightening (clippy would drop the guard between the existence check and the insert)
// opens a TOCTOU where two concurrent creates both pass the check and both insert. Hold is load-bearing.
#[allow(clippy::significant_drop_tightening)]
pub(crate) fn admin_create_user(app: &App, actor: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    let login = validate_login(&gs(body, "login")).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let role = validate_role(&gs(body, "role")).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let password = gs(body, "password");
    if password.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "mot de passe vide refusé".into()));
    }
    // argon2id est coûteux -> on hash AVANT de prendre le mutex DB (ne pas geler l'API pendant le KDF).
    let hash = hash_pw(&password);
    {
        let store = app.store();
        // création STRICTE : un login déjà présent -> 409 (passer par l'édition pour modifier).
        if store.query_row("SELECT 1 FROM users WHERE login=?", &crate::sql_params![&login], |_| Ok(())).is_ok() {
            return Err((StatusCode::CONFLICT, format!("le compte '{login}' existe déjà (utilisez l'édition)")));
        }
        crate::upsert_user_store(&store, &login, &role, &hash).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    app.recompute_auth_required();
    app.bump_cache_epoch(); // B6 (HA): invalidate peers' auth_required cache (new/changed account)
    append_console_ledger(app, "console.admin.user.create", json!({"actor": actor, "login": login, "role": role}));
    Ok(json!({"login": login, "role": role, "disabled": false}))
}

/// Modifie un compte : changement de rôle, réinitialisation de mot de passe, (dé)activation (champs tous
/// optionnels). GARDE-FOU dernier admin (fail-closed, 409) : refuse toute opération qui retirerait le
/// DERNIER admin activé (désactivation ou rétrogradation du seul admin). PURGE les sessions du compte
/// quand l'effet doit être immédiat : désactivation, rétrogradation (rang décroissant) OU reset de mot
/// de passe (une session volée ne survit pas au reset). Check dernier-admin + mutations + purge sous UN
/// SEUL guard DB (atomique, anti-TOCTOU). Recalcule `auth_required`, ledgerise (jamais le mot de passe).
pub(crate) fn admin_update_user(app: &App, actor: &str, target_login: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    let target_login = validate_login(target_login).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let new_role: Option<String> = if body.get("role").is_some() {
        Some(validate_role(&gs(body, "role")).map_err(|e| (StatusCode::BAD_REQUEST, e))?)
    } else {
        None
    };
    let password = gs(body, "password");
    let reset_pw = !password.is_empty();
    let new_disabled: Option<bool> = body.get("disabled").and_then(|v| v.as_bool());
    if new_role.is_none() && !reset_pw && new_disabled.is_none() {
        return Err((StatusCode::BAD_REQUEST, "aucun changement fourni (role|password|disabled)".into()));
    }
    // hash HORS section critique (argon2id coûteux).
    let new_hash: Option<String> = if reset_pw { Some(hash_pw(&password)) } else { None };

    // ENTERPRISE (fail-closed marker) : un super-admin DÉSIGNÉ (provisioning) est NON-DÉSACTIVABLE — on
    // refuse toute désactivation / rétrogradation sous `admin`. No-op pour un login non super-admin.
    // Appelé HORS du guard DB (guard_superadmin_user_mutation reverrouille son propre lock).
    tenancy::guard_superadmin_user_mutation(app, &target_login, new_disabled == Some(true), new_role.as_deref(), false)
        .map_err(|e| (StatusCode::CONFLICT, e))?;

    let (purge, eff_role, eff_disabled) = {
        let store = app.store();
        let (old_role, old_disabled_i): (String, i64) = store
            .query_row("SELECT role, disabled FROM users WHERE login=?", &crate::sql_params![&target_login], |r| Ok((r.get_str(0)?, r.get_i64(1)?)))
            .map_err(|_| (StatusCode::NOT_FOUND, format!("compte '{target_login}' introuvable")))?;
        let old_disabled = old_disabled_i != 0;
        let eff_role = new_role.clone().unwrap_or_else(|| old_role.clone());
        let eff_disabled = new_disabled.unwrap_or(old_disabled);
        // GARDE-FOU dernier admin : si le compte ÉTAIT un admin activé et ne l'est PLUS après l'op,
        // refuser tant qu'il ne reste qu'un seul admin activé (fail-closed : jamais 0 admin -> lockout).
        let was_enabled_admin = old_role == "admin" && !old_disabled;
        let still_enabled_admin = eff_role == "admin" && !eff_disabled;
        if was_enabled_admin && !still_enabled_admin && enabled_admin_count(&store) <= 1 {
            return Err((
                StatusCode::CONFLICT,
                "impossible : dernier admin activé (désactivation/rétrogradation refusée, fail-closed)".into(),
            ));
        }
        if let Some(r) = &new_role {
            store.execute("UPDATE users SET role=? WHERE login=?", &crate::sql_params![r, &target_login])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj rôle échouée: {e}")))?;
        }
        if let Some(h) = &new_hash {
            store.execute("UPDATE users SET pass_hash=? WHERE login=?", &crate::sql_params![h, &target_login])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj mot de passe échouée: {e}")))?;
        }
        if let Some(d) = new_disabled {
            store.execute("UPDATE users SET disabled=? WHERE login=?", &crate::sql_params![d as i64, &target_login])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj état échouée: {e}")))?;
        }
        let downgrade = new_role.as_ref().map(|r| role_rank(r) < role_rank(&old_role)).unwrap_or(false);
        let disabling = new_disabled == Some(true);
        let purge = disabling || downgrade || reset_pw;
        if purge {
            // effet IMMÉDIAT : révoque toutes les sessions actives du compte (même mutex que l'update).
            // FAIL-CLOSED : la purge est une révocation de sécurité — un échec silencieux laisserait des
            // sessions VIVANTES sur un compte désactivé/rétrogradé tout en ledgerisant `sessions_purged:true`
            // (fausse attestation). On MATCHE le Result -> 500 typé AVANT le ledger (les UPDATE ci-dessus,
            // déjà `?`-vérifiés, sont durables : un retry re-purge idempotemment).
            store.execute(
                "DELETE FROM session WHERE user_id=(SELECT id FROM users WHERE login=?)",
                &crate::sql_params![&target_login],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("purge des sessions échouée: {e}")))?;
            drop(store);
        }
        (purge, eff_role, eff_disabled)
    };
    app.recompute_auth_required();
    app.bump_cache_epoch(); // B6 (HA): invalidate peers' auth_required cache (role/disable change)
    append_console_ledger(app, "console.admin.user.update", json!({
        "actor": actor,
        "login": target_login,
        "role": new_role,
        "disabled": new_disabled,
        "password_reset": reset_pw,
        "sessions_purged": purge,
    }));
    Ok(json!({
        "login": target_login,
        "role": eff_role,
        "disabled": eff_disabled,
        "sessions_purged": purge,
        "password_reset": reset_pw,
    }))
}

/// Supprime un compte. GARDE-FOU (fail-closed, 409) : refuse de supprimer le DERNIER admin activé
/// (verrouillage total de l'administration). Purge d'abord ses sessions, puis la ligne `users`, sous
/// UN SEUL guard DB (atomique). Recalcule `auth_required` et ledgerise l'action avec l'admin acteur.
pub(crate) fn admin_delete_user(app: &App, actor: &str, target_login: &str) -> Result<Value, (StatusCode, String)> {
    let target_login = validate_login(target_login).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // ENTERPRISE (fail-closed marker) : un super-admin DÉSIGNÉ est NON-SUPPRIMABLE. No-op pour un login
    // ordinaire. Appelé HORS du guard DB (reverrouille son propre lock).
    tenancy::guard_superadmin_user_mutation(app, &target_login, false, None, true)
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    {
        let store = app.store();
        let (role, disabled): (String, i64) = store
            .query_row("SELECT role, disabled FROM users WHERE login=?", &crate::sql_params![&target_login], |r| Ok((r.get_str(0)?, r.get_i64(1)?)))
            .map_err(|_| (StatusCode::NOT_FOUND, format!("compte '{target_login}' introuvable")))?;
        if role == "admin" && disabled == 0 && enabled_admin_count(&store) <= 1 {
            return Err((StatusCode::CONFLICT, "impossible de supprimer le dernier admin activé (fail-closed)".into()));
        }
        // révoque les sessions AVANT la suppression de la ligne (effet immédiat + pas d'orphelin).
        // FAIL-CLOSED : un échec de la purge -> 500 typé AVANT le DELETE users (donc rien n'est supprimé,
        // aucun état partiel) et AVANT le ledger. Un retry re-purge puis supprime idempotemment.
        store.execute(
            "DELETE FROM session WHERE user_id=(SELECT id FROM users WHERE login=?)",
            &crate::sql_params![&target_login],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("purge des sessions échouée: {e}")))?;
        store.execute("DELETE FROM users WHERE login=?", &crate::sql_params![&target_login])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("suppression échouée: {e}")))?;
    }
    app.recompute_auth_required();
    app.bump_cache_epoch(); // B6 (HA): invalidate peers' auth_required cache (account deleted)
    append_console_ledger(app, "console.admin.user.delete", json!({"actor": actor, "login": target_login}));
    Ok(json!({"deleted": target_login}))
}

/// GOUVERNANCE CONNECTEUR (#4) — mute l'intention opérateur sur un module : `enabled` (install/uninstall
/// opérationnel), `available_override` (NULL=suivre la sonde host, true/false=forcer), `web_allowed`.
/// Chaque champ est OPTIONNEL (présence = mutation, absence = inchangé) ; `available_override` accepte
/// aussi `null` (EFFACER l'override). Le connecteur doit exister dans le registre (404 sinon — l'admin ne
/// crée pas de module fantôme). Mutation attribuée + ledgerisée (jamais de secret). Renvoie la vue à-jour
/// (avec `effective_available`). L'enforcement au tir vit ailleurs (scope.json disabled_modules + filtre
/// --modules + refus validate_modules) : ici on ne fait QUE persister l'intention.
// ALLOW significant_drop_tightening: the `let view = { … }` block holds ONE store lock across the
// existence check + the enabled/web_allowed/override UPDATEs + the modules_catalog read-back, so the view
// returned reflects exactly the writes just made with no concurrent writer interleaving (write-then-read
// consistency). clippy would drop the guard before the read-back, splitting that atomic section.
#[allow(clippy::significant_drop_tightening)]
pub(crate) fn admin_set_module(app: &App, actor: &str, kind: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    // kind = clé de module bien formée (même grammaire que validate_campaign) — anti entrée hostile.
    let kind = validate_campaign(kind).map_err(|e| (StatusCode::BAD_REQUEST, format!("kind invalide: {e}")))?;

    // Trois champs optionnels, typés stricts. available_override distingue 3 états (inchangé/effacé/forcé).
    #[derive(Clone, Copy)]
    enum Ov { Unchanged, Clear, Set(bool) }
    let enabled: Option<bool> = match body.get("enabled") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err((StatusCode::BAD_REQUEST, "enabled doit être un booléen".into())),
    };
    let web_allowed: Option<bool> = match body.get("web_allowed") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err((StatusCode::BAD_REQUEST, "web_allowed doit être un booléen".into())),
    };
    let ov: Ov = match body.get("available_override") {
        None => Ov::Unchanged,
        Some(Value::Null) => Ov::Clear,
        Some(Value::Bool(b)) => Ov::Set(*b),
        Some(_) => return Err((StatusCode::BAD_REQUEST, "available_override doit être un booléen ou null".into())),
    };
    if enabled.is_none() && web_allowed.is_none() && matches!(ov, Ov::Unchanged) {
        return Err((StatusCode::BAD_REQUEST, "aucun changement fourni (enabled|available_override|web_allowed)".into()));
    }

    let view = {
        let store = app.store();
        // le connecteur doit exister (catalogue = source de vérité des kinds, peuplé au boot).
        if store.query_row("SELECT 1 FROM module WHERE kind=?", &crate::sql_params![&kind], |_| Ok(())).is_err() {
            return Err((StatusCode::NOT_FOUND, format!("connecteur '{kind}' inconnu du registre")));
        }
        if let Some(e) = enabled {
            store.execute("UPDATE module SET enabled=? WHERE kind=?", &crate::sql_params![e as i64, &kind])
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj enabled échouée: {err}")))?;
        }
        if let Some(w) = web_allowed {
            store.execute("UPDATE module SET web_allowed=? WHERE kind=?", &crate::sql_params![w as i64, &kind])
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj web_allowed échouée: {err}")))?;
        }
        match ov {
            Ov::Unchanged => {}
            Ov::Clear => {
                store.execute("UPDATE module SET available_override=NULL WHERE kind=?", &crate::sql_params![&kind])
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj available_override échouée: {err}")))?;
            }
            Ov::Set(b) => {
                store.execute("UPDATE module SET available_override=? WHERE kind=?", &crate::sql_params![b as i64, &kind])
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj available_override échouée: {err}")))?;
            }
        }
        // vue à-jour (un seul row) pour la réponse ET le ledger (effective_available inclus).
        modules_catalog(&store)
            .into_iter()
            .find(|m| m.get("kind").and_then(|v| v.as_str()) == Some(kind.as_str()))
            .unwrap_or_else(|| json!({"kind": kind}))
    };
    // LEDGER : mutation d'administration attribuée à l'acteur (qui/quoi/quand). Aucun secret n'entre ici.
    append_console_ledger(app, "console.admin.module.set", json!({
        "actor": actor,
        "kind": kind,
        "enabled": enabled,
        "available_override": match ov { Ov::Unchanged => Value::Null, Ov::Clear => Value::String("cleared".into()), Ov::Set(b) => Value::Bool(b) },
        "web_allowed": web_allowed,
        "effective_available": view.get("effective_available").cloned().unwrap_or(Value::Null),
    }));
    Ok(view)
}

/// GET /api/users — liste des comptes (admin, fail-closed 403 sinon). Jamais `pass_hash`.
pub(crate) async fn users_list(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    (StatusCode::OK, Json(json!({"users": admin_list_users(&app)}))).into_response()
}

/// POST /api/users {login,role,password} — crée un compte (admin). Mutation attribuée + ledgerisée.
pub(crate) async fn users_create(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_create_user(&app, &actor, &body) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "user_create_failed", "why": why}))).into_response(),
    }
}

/// POST /api/users/:login {role?,password?,disabled?} — modifie un compte (admin). Purge les sessions
/// sur désactivation/rétrogradation/reset ; bloque le retrait du dernier admin activé (409).
pub(crate) async fn users_update(State(app): State<App>, headers: HeaderMap, Path(login): Path<String>, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_update_user(&app, &actor, &login, &body) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "user_update_failed", "why": why}))).into_response(),
    }
}

/// DELETE /api/users/:login — supprime un compte (admin). Bloque la suppression du dernier admin (409).
pub(crate) async fn users_delete(State(app): State<App>, headers: HeaderMap, Path(login): Path<String>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_delete_user(&app, &actor, &login) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "user_delete_failed", "why": why}))).into_response(),
    }
}

/// POST /api/modules/:kind {enabled?, available_override?, web_allowed?} — GOUVERNE un connecteur
/// (install/uninstall opérationnel). Réservé admin (check_admin, fail-closed 403 sinon). Mutation
/// attribuée à l'admin acteur + ledgerisée. Désactiver un connecteur l'empêche RÉELLEMENT de tirer
/// (scope.json disabled_modules + filtre --modules + refus validate_modules), y compris pour les modules
/// choisis par le planner. Cette route est la contrepartie « écriture » de GET /api/modules (lecture).
pub(crate) async fn module_governance(State(app): State<App>, headers: HeaderMap, Path(kind): Path<String>, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_set_module(&app, &actor, &kind, &body) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "module_set_failed", "why": why}))).into_response(),
    }
}

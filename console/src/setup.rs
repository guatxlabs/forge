// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — LOGIN + WIZARD DE 1er DÉPLOIEMENT (self-deploy).
//! Bloc déplacé depuis main.rs (PURE MOVE). Handlers PUBLICS (hors auth_guard, sous host_guard).
//! `POST /api/login` : vérifie login/mot de passe (argon2id, timing uniforme anti-énum), pose une
//! session (cookie forge_session + bearer). `GET /api/setup/state` avec `POST /api/setup` : sonde
//! d'état et provisioning AUTO-DÉSACTIVANT du 1er admin (409 une fois provisionné).
//! `POST /api/setup/migrate` : import pré-provision — GARDE-FOU conservé VERBATIM, désactivé (gate
//! `FORGE_ALLOW_API_MIGRATE`) + confinement anti-traversal `validate_api_migrate_paths`.
//! Réutilise App + les helpers de la racine de crate (`gs`/`verify_pw`/`create_session`/
//! `session_ttl_secs`/`validate_login`/`hash_pw`/`upsert_user`/`settings_set`/`append_console_ledger`/
//! `env_flag_enabled`/`validate_api_migrate_paths`/`MigrateOpts`/`run_migration` + le module `sso`) via
//! `use crate::*`, et est re-exporté à la racine par `pub(crate) use crate::setup::*` — les routes de
//! build_router ET les tests inline de main.rs (`super::*`) résolvent donc ces handlers INCHANGÉS.
use crate::*;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// =====================================================================================
// ANTI-BRUTE-FORCE du login local (LOW / defense-in-depth) — verrou par compte à seuil.
//
// ANTI-ÉNUMÉRATION : la clé de throttle est LE LOGIN SOUMIS, indépendamment de l'existence du compte.
// Un login inconnu et un login existant-mais-verrouillé sont throttlés par le MÊME mécanisme et renvoient
// EXACTEMENT la même réponse 401 générique => un compte verrouillé est INDISTINGUABLE d'un compte inconnu
// (l'attaquant contrôle lui-même l'état de verrou en martelant n'importe quelle chaîne). La vérification
// argon2 reste à timing uniforme (hash réel/factice) sur le chemin NON verrouillé ; sur le chemin
// verrouillé on rejette après un délai FIXE (uniforme), sans court-circuit révélateur de l'existence.
// État EN MÉMOIRE (propriété du déploiement, pas d'une requête) ; fail-closed (verrou empoisonné => on
// throttle quand même). Reset sur login réussi ; le verrou expire (pas de lock-out permanent des légitimes).
// =====================================================================================

pub(crate) const LOGIN_MAX_FAILS: u32 = 5; // échecs consécutifs dans la fenêtre avant verrou (pub(crate) : lu par les tests)
const LOGIN_FAIL_WINDOW: Duration = Duration::from_secs(300); // la série d'échecs se périme après 5 min sans échec
const LOGIN_LOCKOUT: Duration = Duration::from_secs(300); // durée du verrou une fois déclenché
const LOGIN_LOCK_DELAY: Duration = Duration::from_millis(700); // délai UNIFORME appliqué à un rejet verrouillé

struct LoginAttempt {
    fails: u32,
    first_fail: Instant,      // ancre de fenêtre : 1er échec de la série courante
    locked_until: Option<Instant>, // posé au franchissement du seuil : rejet jusqu'à cet instant
}

fn login_attempts() -> &'static Mutex<HashMap<String, LoginAttempt>> {
    static M: OnceLock<Mutex<HashMap<String, LoginAttempt>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `true` si `key` (login soumis) est ACTUELLEMENT verrouillé -> la requête doit être rejetée uniformément
/// SANS même tenter argon2. Expire au passage un verrou/fenêtre périmé (ne pas verrouiller les légitimes
/// pour toujours). Travail indépendant de l'existence du compte (clé = login soumis).
fn login_is_locked(key: &str, now: Instant) -> bool {
    let mut map = login_attempts().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(a) = map.get_mut(key) {
        if let Some(until) = a.locked_until {
            if now < until {
                return true;
            }
            map.remove(key); // verrou expiré -> on oublie la série (reset)
        } else if now.duration_since(a.first_fail) > LOGIN_FAIL_WINDOW {
            map.remove(key); // fenêtre écoulée sans verrou -> on oublie
        }
    }
    false
}

/// Enregistre un échec pour `key` ; déclenche le verrou au franchissement du seuil dans la fenêtre. Appelé
/// UNIQUEMENT sur un vrai échec d'identifiants (compte existant OU non — même espace de clés).
fn login_note_failure(key: &str, now: Instant) {
    let mut map = login_attempts().lock().unwrap_or_else(|e| e.into_inner());
    let a = map.entry(key.to_string()).or_insert(LoginAttempt { fails: 0, first_fail: now, locked_until: None });
    if now.duration_since(a.first_fail) > LOGIN_FAIL_WINDOW {
        a.fails = 0; // série périmée -> nouvelle fenêtre
        a.first_fail = now;
        a.locked_until = None;
    }
    a.fails += 1;
    if a.fails >= LOGIN_MAX_FAILS {
        a.locked_until = Some(now + LOGIN_LOCKOUT);
    }
    drop(map); // relâche le verrou explicitement (tightening : la section critique s'arrête ici)
}

/// Efface la série d'échecs d'un login après une authentification RÉUSSIE.
fn login_clear(key: &str) {
    let mut map = login_attempts().lock().unwrap_or_else(|e| e.into_inner());
    map.remove(key);
}

/// POST /api/login {login,password} -> pose une session COURTE (cookie + bearer renvoyés).
/// Vérifie le couple contre la table `users` (argon2id), refuse un compte désactivé. Réponse 200 :
///   {"token": <bearer>, "login", "role", "expires"} + en-tête Set-Cookie `forge_session=<token>`
///   (HttpOnly, SameSite=Strict, Path=/, Max-Age=TTL). Le client peut ensuite s'authentifier soit par
///   le cookie (UI), soit par `Authorization: Bearer <token>` (CLI/API). 401 sur identifiants invalides.
/// NB : route NON gardée par auth_guard (sinon impossible de se connecter quand pass_hash est posé) ;
/// elle est sous host_guard comme tout le reste. Échec d'identifiant -> message générique (anti-énum).
pub(crate) async fn login(State(app): State<App>, Json(body): Json<Value>) -> Response {
    let login_in = body.get("login").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if login_in.is_empty() || password.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "login et password requis"}))).into_response();
    }
    let now = Instant::now();
    // THROTTLE anti-brute-force — clé = login SOUMIS (existence-agnostique). Si verrouillé : rejet avec un
    // délai UNIFORME et la MÊME réponse 401 générique que tout autre échec (aucun signal « verrouillé »
    // distinct, aucun oracle d'existence — le verrou s'applique aussi aux logins inconnus). Fail-closed.
    if login_is_locked(login_in, now) {
        tokio::time::sleep(LOGIN_LOCK_DELAY).await;
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_credentials"}))).into_response();
    }
    // lookup compte. On vérifie TOUJOURS le hash (même si compte introuvable : timing uniforme via un
    // hash factice) pour limiter l'oracle d'énumération de login.
    let (user_id, role, pass_hash, disabled): (i64, String, String, i64) = {
        let store = app.store();
        store.query_row(
            "SELECT id, role, pass_hash, disabled FROM users WHERE login=?",
            &crate::sql_params![login_in],
            |r| Ok((r.get_i64(0)?, r.get_str(1)?, r.get_str(2)?, r.get_i64(3)?)),
        )
        .unwrap_or((-1, String::new(), String::new(), 1))
    };
    // hash de référence : réel si compte trouvé, sinon un hash jetable (verify_pw échouera mais consomme
    // un temps comparable — pas de court-circuit révélateur de l'existence du login).
    let reference = if pass_hash.is_empty() {
        "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
    } else {
        pass_hash.clone()
    };
    let ok = verify_pw(password, &reference) && user_id >= 0 && disabled == 0;
    if !ok {
        // Échec réel -> compte la tentative (existant OU non : même clé) ; peut déclencher le verrou.
        login_note_failure(login_in, now);
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_credentials"}))).into_response();
    }
    login_clear(login_in); // succès -> reset la série d'échecs de ce login
    // Session persistée AVANT de renvoyer un succès : un échec d'écriture -> 500 (pas de token non persisté).
    let (token, expires) = match try_create_session(&app, user_id) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "session_persist_failed", "why": e.to_string()}))).into_response(),
    };
    let ttl = session_ttl_secs();
    let cookie = session_cookie(&token, ttl);
    (
        StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(json!({"token": token, "login": login_in, "role": role, "expires": expires})),
    )
        .into_response()
}

// =====================================================================================
// WIZARD DE 1er DÉPLOIEMENT (self-deploy) — provisionner une install fraîche DEPUIS LE NAVIGATEUR.
//
// Deux routes PUBLIQUES (hors auth_guard, mais sous host_guard anti-rebinding) :
//   - GET  /api/setup/state : sonde d'état (provisioned/needs_setup/capabilities) — le SPA l'appelle
//     au boot pour décider s'il affiche le wizard.
//   - POST /api/setup       : AUTO-DÉSACTIVANTE — provisionne le PREMIER admin puis se ferme (409).
//
// PRINCIPE : ZÉRO défaut codé en dur. Chaque champ optionnel (operator_policy/detection_source/
// session_ttl) n'est persisté QUE s'il est fourni ; absent = rien stocké. La gate d'auth s'engage sur
// l'état DB (recompute_auth_required) dès qu'un admin activé existe.
// =====================================================================================

/// GET /api/setup/state — PUBLIC. `provisioned` = un admin ACTIVÉ existe en base OU un hash d'amorçage
/// env est posé (FORGE_CONSOLE_PASS_HASH). `needs_setup` = !provisioned. `capabilities.sqlcipher` =
/// capacité de chiffrement AU REPOS compilée (`cfg!(feature="encryption")`) — false dans le build par
/// défaut (l'implémentation arrive dans la tranche suivante ; le cfg est câblé dès maintenant). Aucun
/// secret exposé (ni hash, ni token, ni détail de compte).
pub(crate) async fn setup_state(State(app): State<App>) -> impl IntoResponse {
    let provisioned = app.provisioned();
    Json(json!({
        "provisioned": provisioned,
        "needs_setup": !provisioned,
        "capabilities": { "sqlcipher": cfg!(feature = "encryption") },
        // ENTERPRISE (flag-gated) — whether an interactive OIDC SSO login is offered. false in the
        // community default (flag OFF or unconfigured) => the login screen shows NO SSO button, LOCAL
        // login unchanged. Not a secret (only "SSO is available", like the button itself).
        "sso": { "enabled": sso::login_available(&app) },
    }))
}

/// POST /api/setup — PUBLIC mais AUTO-DÉSACTIVANTE : 409 dès que `provisioned()` est vrai. Corps :
///   {admin_login, admin_password, session_ttl?, operator_policy?, detection_source?, scope_json?}
/// Valide le login (validate_login) et exige un mot de passe non vide (parité admin_create_user), hash
/// argon2id (hash_pw), upsert du compte role="admin". `operator_policy`/`detection_source` sont stockés
/// VERBATIM dans `settings` UNIQUEMENT s'ils sont fournis (objets JSON) — sinon rien (aucun défaut).
/// `session_ttl` (entier positif) est persisté comme substrat de config s'il est fourni. `scope_json`
/// (PÉRIMÈTRE/ROE, objet {mode?, in_scope?, out_scope?}) est OPTIONNEL : validé VERBATIM via
/// `validate_engagement_scope` (invalide -> 400, AUCUN provisioning : fail-closed) puis écrit dans
/// l'engagement #1 par le MÊME chemin de mise à jour validé que l'éditeur d'engagement
/// (`engagement_do_update`). Absent = engagement #1 garde son scope VIDE (fail-closed, réglable ensuite
/// dans l'UI). Recalcule la gate d'auth (un admin activé existe désormais), ouvre une session (cookie
/// forge_session) pour que le navigateur atterrisse connecté, et ledgerise `console.setup.provision`
/// (attribution = le login admin ; JAMAIS le mot de passe ni le hash).
pub(crate) async fn setup_provision(State(app): State<App>, Json(body): Json<Value>) -> Response {
    // AUTO-DÉSACTIVANTE : une console déjà provisionnée ne peut plus être (re)provisionnée anonymement.
    if app.provisioned() {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "already_provisioned",
                "why": "console déjà provisionnée (un admin activé ou un hash d'amorçage existe) — /api/setup est fermée"
            })),
        )
            .into_response();
    }
    let login = match validate_login(&gs(&body, "admin_login")) {
        Ok(l) => l,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_login", "why": e}))).into_response(),
    };
    let password = gs(&body, "admin_password");
    if password.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_password", "why": "mot de passe vide refusé"}))).into_response();
    }
    // PÉRIMÈTRE (ROE) OPTIONNEL — validé AVANT toute écriture (fail-closed : un ROE invalide n'entraîne
    // AUCUN provisioning). `scope_json` (objet {mode?, in_scope?, out_scope?}) passe par la MÊME validation
    // pure que l'éditeur d'engagement ; invalide -> 400. Absent/non-objet -> engagement #1 garde son scope
    // VIDE (rien lançable tant que l'opérateur ne le renseigne pas dans l'UI).
    let scope_provided = body.get("scope_json").map(|v| v.is_object()).unwrap_or(false);
    if scope_provided {
        if let Err(e) = validate_engagement_scope(body.get("scope_json").unwrap()) {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_scope", "why": e}))).into_response();
        }
    }
    // argon2id est coûteux -> hash HORS mutex DB (ne pas geler l'API pendant le KDF).
    let hash = hash_pw(&password);
    let op_set = body.get("operator_policy").map(|v| v.is_object()).unwrap_or(false);
    let det_set = body.get("detection_source").map(|v| v.is_object()).unwrap_or(false);
    let ttl_set = body.get("session_ttl").and_then(|v| v.as_i64()).map(|n| n > 0).unwrap_or(false);

    let user_id: i64 = {
        let store = app.store();
        // course anti-TOCTOU : re-vérifier sous le mutex qu'aucun admin activé n'a surgi entre-temps.
        if store.query_row("SELECT 1 FROM users WHERE role='admin' AND disabled=0 LIMIT 1", &[], |_| Ok(())).is_ok() {
            return (StatusCode::CONFLICT, Json(json!({"error": "already_provisioned", "why": "un admin a été provisionné entre-temps"}))).into_response();
        }
        if let Err(e) = crate::upsert_user_store(&store, &login, "admin", &hash) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "provision_failed", "why": e}))).into_response();
        }
        // settings optionnels — VERBATIM, uniquement si l'appelant les fournit (objets JSON). Un `null`
        // ou tout non-objet est ignoré silencieusement (aucun défaut inventé, cf. principe ZÉRO-défaut).
        if let Some(v) = body.get("operator_policy").filter(|v| v.is_object()) {
            let _ = crate::settings_set_store(&store, "operator_policy", &v.to_string());
        }
        if let Some(v) = body.get("detection_source").filter(|v| v.is_object()) {
            let _ = crate::settings_set_store(&store, "detection_source", &v.to_string());
        }
        if let Some(ttl) = body.get("session_ttl").and_then(|v| v.as_i64()).filter(|&n| n > 0) {
            let _ = crate::settings_set_store(&store, "session_ttl", &ttl.to_string());
        }
        store.query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![&login], |r| r.get_i64(0)).unwrap_or(-1)
    };
    if user_id < 0 {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "provision_failed", "why": "compte introuvable après création"}))).into_response();
    }
    // PÉRIMÈTRE (ROE) : écrit dans l'engagement #1 par le MÊME chemin validé/atomique/ledgerisé que
    // l'éditeur d'engagement (`engagement_do_update` -> validate_engagement_scope + UPDATE + ledger
    // console.engagement.edit). Hors du bloc `store` ci-dessus (engagement_do_update prend son propre
    // verrou DB — éviter un double-lock). Le scope a déjà été validé plus haut (fail-closed) ; un échec
    // ici ne peut venir que de l'absence de l'engagement #1 ou d'une I/O DB -> 500 typé.
    let mut scope_set = false;
    if scope_provided {
        let upd = json!({"scope_json": body.get("scope_json").cloned().unwrap_or_else(|| json!({}))});
        match engagement_do_update(&app, 1, &login, &upd) {
            Ok(_) => scope_set = true,
            Err((code, why)) => return (code, Json(json!({"error": "scope_write_failed", "why": why}))).into_response(),
        }
    }
    // la gate d'auth s'engage : un admin activé existe désormais (état DB fait autorité).
    app.recompute_auth_required();
    // la source de détection a pu être écrite dans settings -> recharge le cache (sinon la couverture
    // resterait sur la config du boot, obsolète). No-op si detection_source n'a pas été fourni.
    if det_set {
        app.reload_detection_source();
    }
    app.bump_cache_epoch(); // B6 (HA): 1er admin (auth gate) + éventuelle detection_source -> invalide les pairs
    // session immédiate -> le navigateur atterrit connecté en tant que nouvel admin. Échec d'écriture de
    // session -> 500 (le compte admin EST provisionné ; l'opérateur se connectera via /api/login).
    let (token, expires) = match try_create_session(&app, user_id) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "session_persist_failed", "why": e.to_string()}))).into_response(),
    };
    let ttl = session_ttl_secs();
    let cookie = session_cookie(&token, ttl);
    // ledger : provision attribuée au nouvel admin. JAMAIS le mot de passe/hash (login + booléens seuls).
    append_console_ledger(&app, "console.setup.provision", json!({
        "actor": login,
        "admin_login": login,
        "operator_policy_set": op_set,
        "detection_source_set": det_set,
        "session_ttl_set": ttl_set,
        "scope_set": scope_set,
    }));
    (
        StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(json!({"provisioned": true, "token": token, "login": login, "role": "admin", "expires": expires})),
    )
        .into_response()
}

/// POST /api/setup/migrate — PUBLIC mais PRÉ-PROVISION UNIQUEMENT (409 dès que `provisioned()`).
/// Lance la MÊME migration que la sous-commande CLI depuis une source POINTÉE (chemins serveur), et
/// renvoie le rapport (dont le résultat de vérification du ledger). VOIE MINIMALE : l'UX documentée
/// primaire reste `forge-console migrate` dans un conteneur one-shot ; cet endpoint dépanne le wizard.
/// Corps : {from:<dir|db>, to:<db>, ledger?:<path>, verify?:bool, encrypt?:bool, key_env?:<ENVVAR>}.
/// Le chiffrement exige la feature `encryption` (400 clair sinon). ZÉRO défaut : `from`/`to` requis.
pub(crate) async fn setup_migrate(State(app): State<App>, Json(body): Json<Value>) -> Response {
    // AUTO-DÉSACTIVANTE : un import de données n'a de sens qu'AVANT le 1er provisioning (sinon on
    // écraserait un install déjà en service). Une console provisionnée ferme la route (409).
    if app.provisioned() {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "already_provisioned",
                "why": "console déjà provisionnée — /api/setup/migrate est fermée (import réservé au pré-déploiement)"
            })),
        )
            .into_response();
    }
    // COUCHE 1 — OPT-IN : la migration via API est DÉSACTIVÉE par défaut (CLI-seule). Sans le flag,
    // on refuse AVANT toute I/O -> retire la primitive d'écriture/suppression de fichier non-auth du
    // déploiement par défaut. La voie CLI (`forge-console migrate …`, invocation locale de confiance)
    // reste pleinement fonctionnelle et NON restreinte (ce garde-fou ne touche QUE cet endpoint web).
    if !env_flag_enabled("FORGE_ALLOW_API_MIGRATE") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "api_migrate_disabled",
                "why": "migration via API désactivée — utiliser la CLI `forge-console migrate …` (poser FORGE_ALLOW_API_MIGRATE=1 pour ouvrir l'endpoint web)"
            })),
        )
            .into_response();
    }
    let from = gs(&body, "from");
    let to = gs(&body, "to");
    if from.is_empty() || to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "champs `from` et `to` requis"}))).into_response();
    }
    let ledger = body.get("ledger").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from);
    let encrypt = body.get("encrypt").and_then(|v| v.as_bool()).unwrap_or(false);
    if encrypt && !cfg!(feature = "encryption") {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "encryption_unavailable",
            "why": "chiffrement au repos non compilé (feature `encryption` absente) — recompiler avec --features encryption"
        }))).into_response();
    }
    // COUCHE 2 — le flag est actif : confinement anti-traversal des chemins SOUS la racine allowlistée
    // (racine de données console / $FORGE_CONSOLE_IMPORT_DIR). Rejette `..`, chemins absolus hors base,
    // et l'écrasement d'une cible préexistante hors base. UNIQUEMENT ici (jamais sur la voie CLI).
    if let Err(why) = validate_api_migrate_paths(&from, &to, ledger.as_deref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "path_rejected", "why": why})),
        )
            .into_response();
    }
    let opts = MigrateOpts {
        from,
        to,
        ledger,
        verify: body.get("verify").and_then(|v| v.as_bool()).unwrap_or(false),
        encrypt,
        key_env: body.get("key_env").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from),
        actor: "api:setup/migrate".to_string(),
    };
    // migration = I/O SQLite/FS bloquant -> hors du runtime async (spawn_blocking) pour ne pas geler
    // l'exécuteur. `opts` (Strings/bools) est Send ; la Connection est créée DANS run_migration.
    match tokio::task::spawn_blocking(move || run_migration(&opts)).await {
        Ok(Ok(report)) => (StatusCode::OK, Json(report)).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(json!({"error": "migrate_failed", "why": e}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "migrate_panicked", "why": e.to_string()}))).into_response(),
    }
}

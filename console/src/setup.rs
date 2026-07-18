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
use crate::store::Store;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};
use std::time::Duration;

// =====================================================================================
// ANTI-BRUTE-FORCE du login local (LOW / defense-in-depth) — verrou par compte à seuil, CLUSTER-WIDE.
//
// ANTI-ÉNUMÉRATION : la clé de throttle est LE LOGIN SOUMIS, indépendamment de l'existence du compte.
// Un login inconnu et un login existant-mais-verrouillé sont throttlés par le MÊME mécanisme et renvoient
// EXACTEMENT la même réponse 401 générique => un compte verrouillé est INDISTINGUABLE d'un compte inconnu
// (l'attaquant contrôle lui-même l'état de verrou en martelant n'importe quelle chaîne). La vérification
// argon2 reste à timing uniforme (hash réel/factice) sur le chemin NON verrouillé ; sur le chemin
// verrouillé on rejette après un délai FIXE (uniforme), sans court-circuit révélateur de l'existence.
// Reset sur login réussi ; le verrou expire (pas de lock-out permanent des légitimes).
//
// HA / MULTI-INSTANCE (le durcissement de cette tranche) : l'état est ADOSSÉ AU STORE PARTAGÉ (table
// `login_throttle`, seam SQLite/Postgres) — plus une map par-processus. AVANT, N réplicas derrière un load-
// balancer donnaient à un attaquant ~N×LOGIN_MAX_FAILS tentatives par fenêtre (chaque process comptait seul) ;
// désormais le compteur + la fenêtre de verrou sont AUTORITAIRES cross-réplica (toute instance lit/écrit la
// MÊME ligne). MONO-INSTANCE : comportement IDENTIQUE à l'ancien compteur mémoire (mêmes seuil/fenêtre) — le
// store est simplement l'unique lecteur/écrivain. ATOMICITÉ : l'incrément passe par un INSERT … ON CONFLICT
// DO UPDATE (une instruction -> pas de lost-update sous échecs concurrents ; row-lock côté PG). FAIL-SAFE :
// la lecture de verrou FAIL-OPEN (store indisponible / boot très précoce -> on ne PRÉTEND pas verrouillé :
// ne pas exclure un légitime sur un hoquet infra ; l'auth reste gatée par argon2id + le lookup user, qui
// échouerait lui aussi si le store était mort). L'écriture d'échec est best-effort (un échec de write ne
// débloque jamais un compte : au pire on ne compte pas cette tentative-là). La table est BORNÉE par une purge
// opportuniste des lignes périmées à chaque échec (miroir du sweep in-memory remplacé).
// =====================================================================================

pub(crate) const LOGIN_MAX_FAILS: u32 = 5; // échecs consécutifs dans la fenêtre avant verrou (pub(crate) : lu par les tests)
const LOGIN_FAIL_WINDOW: Duration = Duration::from_secs(300); // la série d'échecs se périme après 5 min sans échec
const LOGIN_LOCKOUT: Duration = Duration::from_secs(300); // durée du verrou une fois déclenché
const LOGIN_LOCK_DELAY: Duration = Duration::from_millis(700); // délai UNIFORME appliqué à un rejet verrouillé
/// Longueur max d'un login accepté par `/api/login` (parité `validate_login`). Au-delà = jamais un compte
/// valide -> rejeté AVANT tout suivi de throttle (n'écrit pas de ligne, ne stocke pas une clé sur-longue).
const MAX_LOGIN_LEN: usize = 64;

/// Fenêtre de série / durée de verrou en epoch-secondes (le store persiste des epochs BIGINT, pas des
/// `Instant` monotones par-processus). Dérivées des constantes `Duration` ci-dessus -> seuil/fenêtre INCHANGÉS.
fn fail_window_secs() -> i64 {
    LOGIN_FAIL_WINDOW.as_secs() as i64
}
fn lockout_secs() -> i64 {
    LOGIN_LOCKOUT.as_secs() as i64
}

/// `true` si `key` (login soumis) est ACTUELLEMENT verrouillé selon le STORE PARTAGÉ (autorité cluster-wide)
/// -> la requête doit être rejetée uniformément SANS même tenter argon2. Purge OPPORTUNISTE la ligne si le
/// verrou/fenêtre a expiré (miroir du `map.remove` in-memory : ne pas verrouiller les légitimes pour toujours).
/// Existence-agnostique (clé = login soumis). FAIL-OPEN sur erreur de store (voir l'en-tête du module) :
/// un store indisponible ne DOIT PAS verrouiller — l'auth reste gatée en aval par argon2id + le lookup user.
fn login_is_locked(store: &Store, key: &str, now: i64) -> bool {
    let row = store.query_opt(
        "SELECT first_ts, locked_until FROM login_throttle WHERE login=?",
        &crate::sql_params![key],
        |r| Ok((r.get_i64(0)?, r.get_i64(1)?)),
    );
    match row {
        Ok(Some((first_ts, locked_until))) => {
            if locked_until > 0 && now < locked_until {
                return true; // verrou encore actif -> rejet uniforme
            }
            // On n'atteint ce point que si le verrou est nul OU expiré. Ligne périmée (verrou expiré, ou
            // fenêtre écoulée sans verrou) -> purge opportuniste ; une série PRE-verrou encore vivante est
            // conservée (l'attaquant approche du seuil). Best-effort (un échec de DELETE ne change rien).
            if locked_until > 0 || now - first_ts > fail_window_secs() {
                let _ = store.execute("DELETE FROM login_throttle WHERE login=?", &crate::sql_params![key]);
            }
            false
        }
        Ok(None) => false, // jamais vu -> pas verrouillé
        Err(_) => false,   // FAIL-OPEN : store indisponible -> ne pas prétendre verrouillé
    }
}

/// Enregistre un échec pour `key` dans le STORE PARTAGÉ et arme le verrou au franchissement du seuil dans la
/// fenêtre — ATOMIQUEMENT via un INSERT … ON CONFLICT DO UPDATE (incrément + reset de fenêtre inline en CASE ;
/// une seule instruction -> AUCUN lost-update sous échecs concurrents, row-lock côté PG). Purge d'abord les
/// lignes périmées (borne la table). Appelé UNIQUEMENT sur un vrai échec d'identifiants (compte existant OU
/// non — même espace de clés). Best-effort : un échec d'écriture ne débloque jamais un compte (au pire cette
/// tentative n'est pas comptée) — jamais un affaiblissement d'auth.
fn login_note_failure(store: &Store, key: &str, now: i64) {
    let w = fail_window_secs();
    let lock = lockout_secs();
    let max = LOGIN_MAX_FAILS as i64;
    let _ = store.with_tx(|tx| {
        // PURGE opportuniste : lignes dont le verrou est levé (locked_until<=now) ET la fenêtre écoulée
        // (first_ts<=now-w) ne portent plus d'info de throttle -> supprimées (borne mémoire de la table,
        // miroir du sweep in-memory). Ne touche jamais une série vivante ni un verrou actif.
        tx.execute(
            "DELETE FROM login_throttle WHERE locked_until <= ? AND first_ts <= ?",
            &crate::sql_params![now, now - w],
        )?;
        // INCRÉMENT ATOMIQUE. Ligne absente -> nouvelle série (fails=1, ancre=now, pas de verrou). Ligne
        // présente : si la fenêtre est écoulée (now-first_ts>w) on RESET (fails=1, ré-ancre now), sinon +1 ;
        // le verrou est armé (locked_until=now+lock) dès que le NOUVEAU compteur atteint le seuil, sinon 0.
        // Le même CASE de reset est réévalué dans chaque colonne -> cohérence (une seule ligne réécrite).
        tx.execute(
            "INSERT INTO login_throttle(login, fails, first_ts, locked_until) VALUES(?, 1, ?, 0) \
             ON CONFLICT(login) DO UPDATE SET \
               fails = CASE WHEN ? - login_throttle.first_ts > ? THEN 1 ELSE login_throttle.fails + 1 END, \
               first_ts = CASE WHEN ? - login_throttle.first_ts > ? THEN ? ELSE login_throttle.first_ts END, \
               locked_until = CASE \
                 WHEN (CASE WHEN ? - login_throttle.first_ts > ? THEN 1 ELSE login_throttle.fails + 1 END) >= ? \
                 THEN ? + ? ELSE 0 END",
            &crate::sql_params![key, now, now, w, now, w, now, now, w, max, now, lock],
        )?;
        Ok(())
    });
}

/// Efface la série d'échecs d'un login après une authentification RÉUSSIE (store partagé). Best-effort.
fn login_clear(store: &Store, key: &str) {
    let _ = store.execute("DELETE FROM login_throttle WHERE login=?", &crate::sql_params![key]);
}

/// POST /api/login {login,password} -> pose une session COURTE (cookie + bearer renvoyés).
/// Vérifie le couple contre la table `users` (argon2id), refuse un compte désactivé. Réponse 200 :
///   {"token": <bearer>, "login", "role", "expires"} + en-tête Set-Cookie `forge_session=<token>`
///   (HttpOnly, SameSite=Strict, Path=/, Max-Age=TTL). Le client peut ensuite s'authentifier soit par
///   le cookie (UI), soit par `Authorization: Bearer <token>` (CLI/API). 401 sur identifiants invalides.
/// NB : route NON gardée par auth_guard (sinon impossible de se connecter quand pass_hash est posé) ;
/// elle est sous host_guard comme tout le reste. Échec d'identifiant -> message générique (anti-énum).
pub(crate) async fn login(State(app): State<App>, _headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let login_in = body.get("login").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if login_in.is_empty() || password.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "login et password requis"}))).into_response();
    }
    // ANTI-DoS : un login déraisonnablement long n'est JAMAIS un compte valide (parité validate_login).
    // On le rejette AVANT tout suivi de throttle -> il ne peut ni peupler la map ni allonger une clé
    // (épuisement mémoire non authentifié). Réponse générique identique (anti-énumération).
    if login_in.len() > MAX_LOGIN_LEN {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_credentials"}))).into_response();
    }
    let now = crate::now_epoch();
    // THROTTLE anti-brute-force CLUSTER-WIDE — clé = login SOUMIS (existence-agnostique). L'état vit dans le
    // STORE PARTAGÉ (autorité cross-réplica). Si verrouillé : rejet avec un délai UNIFORME et la MÊME réponse
    // 401 générique que tout autre échec (aucun signal « verrouillé » distinct, aucun oracle d'existence — le
    // verrou s'applique aussi aux logins inconnus). Le `Store` (guard !Send) est acquis puis RELÂCHÉ dans ce
    // bloc AVANT le `.await` du sleep. Fail-open sur store indisponible (cf. login_is_locked / en-tête module).
    let locked = { let store = app.store(); login_is_locked(&store, login_in, now) };
    if locked {
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
        // Échec réel -> compte la tentative (existant OU non : même clé) dans le store partagé ; peut armer
        // le verrou cluster-wide. Store acquis/relâché dans le bloc (pas d'await ensuite avant le return).
        { let store = app.store(); login_note_failure(&store, login_in, now); }
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_credentials"}))).into_response();
    }
    { let store = app.store(); login_clear(&store, login_in); } // succès -> reset la série d'échecs (store partagé)
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
pub(crate) async fn setup_provision(State(app): State<App>, _headers: HeaderMap, Json(body): Json<Value>) -> Response {
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
/// primaire reste `forge migrate` dans un conteneur one-shot ; cet endpoint dépanne le wizard.
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
    // déploiement par défaut. La voie CLI (`forge migrate …`, invocation locale de confiance)
    // reste pleinement fonctionnelle et NON restreinte (ce garde-fou ne touche QUE cet endpoint web).
    if !env_flag_enabled("FORGE_ALLOW_API_MIGRATE") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "api_migrate_disabled",
                "why": "migration via API désactivée — utiliser la CLI `forge migrate …` (poser FORGE_ALLOW_API_MIGRATE=1 pour ouvrir l'endpoint web)"
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

// =====================================================================================
// TESTS — throttle login CLUSTER-WIDE adossé au store partagé. INLINE car les helpers de throttle sont
// PRIVÉS au module setup (une sonde depuis un module de test frère n'y accéderait pas). Les tests directs
// des helpers utilisent un `Mutex<Connection>` SQLite mémoire partagé : chaque acquisition d'un `Store`
// frais = un « réplica » différent lisant le MÊME store -> c'est ce qui PROUVE l'autorité cross-instance
// (aucun état par-processus ne subsiste). Mirroir du patron des tests de `ha.rs`.
// =====================================================================================
#[cfg(test)]
mod throttle_tests {
    use super::*;
    use crate::testutil::*;
    use crate::store::Store;

    /// SQLite mémoire portant le SCHEMA de base (dont `login_throttle`), en `Mutex` -> on peut remettre à
    /// `Store::sqlite` un guard frais PAR APPEL (modèle held-guard de `App::store()` / des tests `ha.rs`).
    fn mem() -> std::sync::Mutex<rusqlite::Connection> {
        let conn = rusqlite::Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        std::sync::Mutex::new(conn)
    }

    /// Nombre de lignes dans `login_throttle` (sonde de la borne de table), via un `Store` frais.
    fn row_count(m: &std::sync::Mutex<rusqlite::Connection>) -> i64 {
        Store::sqlite(m.lock().unwrap())
            .query_row("SELECT COUNT(*) FROM login_throttle", &crate::sql_params![], |r| r.get_i64(0))
            .unwrap()
    }

    /// [HA — LOCKOUT CROSS-RÉPLICA, LE CŒUR DE LA TRANCHE] LOGIN_MAX_FAILS échecs enregistrés par une
    /// « instance A » (une acquisition de Store) VERROUILLENT le login lu par une « instance B » (un Store
    /// FRAÎCHEMENT acquis, sans aucun état partagé en mémoire). Prouve que le verrou est AUTORITAIRE dans le
    /// store partagé, pas par-processus. Sous le seuil, B ne voit PAS encore de verrou (parité de seuil).
    #[test]
    fn lockout_is_cross_replica_db_authoritative() {
        let m = mem();
        let t0: i64 = 1_000_000;
        // « Instance A » : LOGIN_MAX_FAILS-1 échecs -> PAS encore verrouillé côté « instance B ».
        for _ in 0..(LOGIN_MAX_FAILS - 1) {
            login_note_failure(&Store::sqlite(m.lock().unwrap()), "victim", t0);
        }
        assert!(
            !login_is_locked(&Store::sqlite(m.lock().unwrap()), "victim", t0),
            "sous le seuil : une instance FRAÎCHE ne voit pas de verrou (même seuil qu'avant)"
        );
        // Le franchissement du seuil sur « A » -> « B » (Store frais) voit le verrou : cross-réplica.
        login_note_failure(&Store::sqlite(m.lock().unwrap()), "victim", t0);
        assert!(
            login_is_locked(&Store::sqlite(m.lock().unwrap()), "victim", t0),
            "au seuil : le verrou est LU par une instance distincte via le store partagé (autorité DB)"
        );
    }

    /// [c — le succès efface] Après une série d'échecs (verrouillé), `login_clear` retire la ligne -> une
    /// instance fraîche ne voit plus de verrou et la table est vide (pas de fuite d'état).
    #[test]
    fn successful_login_clears_lockout() {
        let m = mem();
        let t0: i64 = 2_000_000;
        for _ in 0..LOGIN_MAX_FAILS {
            login_note_failure(&Store::sqlite(m.lock().unwrap()), "u", t0);
        }
        assert!(login_is_locked(&Store::sqlite(m.lock().unwrap()), "u", t0), "verrouillé après N échecs");
        login_clear(&Store::sqlite(m.lock().unwrap()), "u");
        assert!(!login_is_locked(&Store::sqlite(m.lock().unwrap()), "u", t0), "clear -> plus de verrou");
        assert_eq!(row_count(&m), 0, "clear supprime la ligne (aucun résidu)");
    }

    /// [d — expiration de fenêtre] Un login verrouillé à `t0` n'est PLUS verrouillé une fois `LOGIN_LOCKOUT`
    /// écoulé (lecture à `t0 + lockout + 1`), et la ligne périmée est purgée opportunément à la lecture.
    #[test]
    fn window_expiry_unlocks() {
        let m = mem();
        let t0: i64 = 3_000_000;
        for _ in 0..LOGIN_MAX_FAILS {
            login_note_failure(&Store::sqlite(m.lock().unwrap()), "z", t0);
        }
        assert!(login_is_locked(&Store::sqlite(m.lock().unwrap()), "z", t0), "verrouillé à t0");
        let later = t0 + lockout_secs() + 1;
        assert!(!login_is_locked(&Store::sqlite(m.lock().unwrap()), "z", later), "verrou expiré -> déverrouillé");
        assert_eq!(row_count(&m), 0, "la lecture post-expiration purge la ligne périmée (borne de table)");
    }

    /// [f — mono-instance : seuils INCHANGÉS] EXACTEMENT LOGIN_MAX_FAILS échecs déclenchent le verrou (ni un
    /// de moins, ni un de plus) sur un unique store — parité avec l'ancien compteur mémoire. Un échec HORS
    /// fenêtre (série périmée) RESET le compteur au lieu de s'accumuler (nouvelle fenêtre = 1 échec).
    #[test]
    fn single_instance_threshold_and_window_reset_unchanged() {
        let m = mem();
        let t0: i64 = 4_000_000;
        // LOGIN_MAX_FAILS-1 échecs -> pas de verrou ; le N-ième -> verrou (seuil exact).
        for _ in 0..(LOGIN_MAX_FAILS - 1) {
            login_note_failure(&Store::sqlite(m.lock().unwrap()), "acct", t0);
        }
        assert!(!login_is_locked(&Store::sqlite(m.lock().unwrap()), "acct", t0), "N-1 échecs -> pas de verrou");
        login_note_failure(&Store::sqlite(m.lock().unwrap()), "acct", t0);
        assert!(login_is_locked(&Store::sqlite(m.lock().unwrap()), "acct", t0), "N échecs -> verrou (seuil inchangé)");

        // RESET de fenêtre : un login neuf, un seul échec très espacé du précédent -> jamais verrouillé
        // (le compteur repart à 1 par fenêtre, il ne s'accumule pas sur des échecs hors fenêtre).
        let far = t0;
        for k in 0..(LOGIN_MAX_FAILS + 3) {
            // chaque échec est décalé de plus d'une fenêtre du précédent -> reset systématique à 1.
            let ts = far + (k as i64) * (fail_window_secs() + 5);
            login_note_failure(&Store::sqlite(m.lock().unwrap()), "spaced", ts);
            let now = far + (k as i64) * (fail_window_secs() + 5);
            assert!(
                !login_is_locked(&Store::sqlite(m.lock().unwrap()), "spaced", now),
                "échecs espacés > fenêtre -> reset à 1, jamais de verrou"
            );
        }
    }

    /// [bound — table purgée] Une rafale d'échecs sur des logins DISTINCTS puis un échec après expiration de
    /// la fenêtre purge les lignes périmées (la purge opportuniste de `login_note_failure` borne la table —
    /// miroir du sweep in-memory remplacé). Après la purge, seules subsistent les lignes encore vivantes.
    #[test]
    fn stale_rows_pruned_bounds_table() {
        let m = mem();
        let t0: i64 = 5_000_000;
        for i in 0..50 {
            login_note_failure(&Store::sqlite(m.lock().unwrap()), &format!("attacker-{i}"), t0);
        }
        assert_eq!(row_count(&m), 50, "50 logins distincts -> 50 lignes (série vivante)");
        // Un nouvel échec BIEN après la fenêtre : la purge retire les 50 lignes périmées, il n'en reste
        // qu'UNE (la nouvelle série de `late`).
        let later = t0 + fail_window_secs() + lockout_secs() + 10;
        login_note_failure(&Store::sqlite(m.lock().unwrap()), "late", later);
        assert_eq!(row_count(&m), 1, "les 50 lignes périmées purgées -> table bornée (reste la série vivante)");
    }

    /// [e — login sur-long rejeté AVANT tout suivi] Un login > MAX_LOGIN_LEN n'est JAMAIS un compte valide :
    /// `/api/login` le rejette 401 générique SANS écrire de ligne dans `login_throttle` (rejet avant tout
    /// suivi de throttle -> ne peuple pas la table, ne stocke pas une clé sur-longue). Bout-en-bout via `login()`.
    #[tokio::test]
    async fn overlong_login_rejected_without_tracking() {
        let app = test_app(&tmp_path("login-overlong"));
        { let db = app.db(); upsert_user(&db, "real", "viewer", &hash_pw("pw")).unwrap(); }
        let longkey = "a".repeat(MAX_LOGIN_LEN + 1);
        let resp = login(State(app.clone()), HeaderMap::new(), Json(json!({"login": longkey, "password": "x"}))).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "login sur-long -> 401 générique (anti-énumération)");
        let tracked: i64 = {
            let store = app.store();
            store.query_row(
                "SELECT COUNT(*) FROM login_throttle WHERE login=?",
                &crate::sql_params![longkey],
                |r| r.get_i64(0),
            ).unwrap()
        };
        assert_eq!(tracked, 0, "la clé sur-longue n'est JAMAIS suivie (rejet avant login_note_failure)");
    }

    /// [a — lockout end-to-end via `login()`] Sur un `App` mono-instance, LOGIN_MAX_FAILS mauvais mots de
    /// passe verrouillent le compte : le BON mot de passe est ensuite refusé (le verrou DB mord dans le
    /// handler). Complète l'intégration `login_lockout_triggers_without_user_enumeration` de tests_auth_session.
    #[tokio::test]
    async fn handler_locks_after_threshold_failures() {
        let app = test_app(&tmp_path("login-lock-e2e"));
        { let db = app.db(); upsert_user(&db, "e2euser", "operator", &hash_pw("goodpw")).unwrap(); }
        for _ in 0..LOGIN_MAX_FAILS {
            let r = login(State(app.clone()), HeaderMap::new(), Json(json!({"login": "e2euser", "password": "bad"}))).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        }
        let r = login(State(app.clone()), HeaderMap::new(), Json(json!({"login": "e2euser", "password": "goodpw"}))).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "compte verrouillé : bon mdp refusé (verrou DB dans le handler)");
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SAVED VIEWS (#8) : jeux de filtres SAUVEGARDÉS de la vue Findings.
//!
//! Un `saved_view` capture l'état de filtre de la vue Findings (severity/status/TLP/target/campaign/
//! texte…) sous forme d'un blob JSON opaque (`filter_json`), pour le RÉAPPLIQUER d'un clic. Une vue est
//! **PERSONNELLE** : elle est scopée à `user_id` = login d'ATTRIBUTION de l'appelant (jamais partagée) —
//! un utilisateur ne LISTE ni ne SUPPRIME JAMAIS les vues d'un autre (fail-closed). `engagement_id` est
//! **NULLABLE** : NULL = vue GLOBALE (proposée quel que soit l'engagement) ; un id = vue rattachée à CET
//! engagement (proposée quand il est actif).
//!
//! Gouvernance (miroir des autres mutations console, fail-closed) :
//!   - `GET    /api/saved-views`      → liste (les vues DE L'APPELANT : globales + engagement actif)
//!   - `POST   /api/saved-views`      → créer   (OPÉRATEUR)
//!   - `DELETE /api/saved-views/:id`  → supprimer (OPÉRATEUR, et SEULEMENT si la vue appartient à l'appelant)
//!
//! Chaque mutation est ATTRIBUÉE (login acteur = `user_id` propriétaire) et LEDGERISÉE
//! `console.saved_view.*` (chaîne SHA-256 tamper-evident). Un refus 403 ne mute jamais.
//!
//! Ce module réutilise `App` + les helpers d'auth/ledger de `main.rs` (visibles depuis un module
//! descendant de la racine de crate). Il n'ajoute AUCUN état ni aucune dépendance nouvelle. Tout le DML
//! passe par le SEAM (`app.store()`), en SQL dialect-portable (placeholders `?`, `datetime('now')` réécrit
//! par le seam pour le backend Postgres) — SQLite (défaut communauté) et `store-postgres` compilent tous deux.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get},
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::store::{Row, StoreResult};
use crate::{
    append_console_ledger, attribution_login, check_operator, operator_denied,
    resolve_view_engagement_id, App,
};

/// Colonnes projetées dans l'ordre attendu par [`row_to_json`].
const SELECT_COLS: &str = "id,user_id,engagement_id,name,filter_json,created";

/// Sous-routeur des vues sauvegardées — FUSIONNÉ dans le routeur protégé de `build_router` (hérite donc
/// de l'auth_guard/host_guard). Le segment `:id` (i64) ne collisionne pas avec la racine statique.
pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/saved-views", get(sv_list).post(sv_create))
        .route("/api/saved-views/:id", delete(sv_delete))
}

// --- helpers de réponse (JSON stable, non-fuiteur) ---------------------------------------------

fn bad(why: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": why.into()}))).into_response()
}
fn not_found(why: impl Into<String>) -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"error": "not_found", "why": why.into()}))).into_response()
}
fn internal(why: impl Into<String>) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal", "why": why.into()}))).into_response()
}

/// Nom de vue valide : non vide après trim, ≤ 120 caractères. Substrat neutre (un nom est un libellé
/// humain), juste des bornes anti-abus.
fn valid_name(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.chars().count() <= 120
}

/// Canonicalise `filter_json` depuis le corps : accepte un OBJET (préféré) ou une CHAÎNE JSON d'objet.
/// Toute autre forme (absent, non-objet) -> `"{}"`. Sérialisé COMPACT. Bornage anti-abus : ≤ 4096 octets
/// (les filtres de la vue Findings sont petits) — au-delà -> `Err`. PURE.
fn canon_filter_json(body: &Value) -> Result<String, String> {
    let obj: Value = match body.get("filter_json") {
        Some(Value::Object(m)) => Value::Object(m.clone()),
        Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
            Ok(v @ Value::Object(_)) => v,
            _ => return Err("filter_json (chaîne) doit décoder un objet JSON".into()),
        },
        None | Some(Value::Null) => json!({}),
        _ => return Err("filter_json attendu : objet JSON {clef: valeur}".into()),
    };
    let s = serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string());
    if s.len() > 4096 {
        return Err("filter_json trop volumineux (≤ 4096 octets)".into());
    }
    Ok(s)
}

/// Sérialise une ligne `saved_view` (colonnes = SELECT_COLS) en JSON d'API. `engagement_id` NULL ->
/// `null` (vue globale) ; `filter_json` re-parsé en objet pour un round-trip propre côté client (repli
/// sur `{}` si stocké malformé).
fn row_to_json(r: &Row) -> StoreResult<Value> {
    let filter_raw = r.get_str(4)?;
    let filter = serde_json::from_str::<Value>(&filter_raw).unwrap_or_else(|_| json!({}));
    Ok(json!({
        "id": r.get_i64(0)?,
        "user_id": r.get_str(1)?,
        "engagement_id": r.get_opt_i64(2)?,
        "name": r.get_str(3)?,
        "filter_json": filter,
        "created": r.get_str(5)?,
    }))
}

// --- handlers ----------------------------------------------------------------------------------

/// GET /api/saved-views — LISTE les vues DE L'APPELANT (scopées à `user_id` = attribution) : les vues
/// GLOBALES (engagement_id NULL) + celles rattachées à l'engagement ACTIF (résolu par le query
/// `?engagement=`). Un utilisateur ne voit JAMAIS les vues d'un autre. Triées par nom (insensible casse).
async fn sv_list(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let user = attribution_login(&app, &headers);
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let store = app.store();
    // engagement_id RÉSOLU (entier) inliné sans risque (parité avec les vues) ; `user_id` en paramètre lié.
    let sql = format!(
        "SELECT {SELECT_COLS} FROM saved_view WHERE user_id=? AND (engagement_id IS NULL OR engagement_id={eid}) ORDER BY name COLLATE NOCASE ASC, id ASC"
    );
    let rows: Vec<Value> = match store.query_lax(&sql, &crate::sql_params![user.clone()], row_to_json) {
        Ok(rows) => rows,
        Err(e) => return internal(e.to_string()),
    };
    drop(store);
    (StatusCode::OK, Json(json!({"views": rows, "count": rows.len(), "user_id": user}))).into_response()
}

/// POST /api/saved-views — CRÉE une vue PERSONNELLE (OPÉRATEUR, fail-closed 403). Corps :
/// `{name, filter_json:{}, scope_engagement?:bool}`. `scope_engagement=true` rattache la vue à
/// l'engagement ACTIF (résolu) ; sinon la vue est GLOBALE (engagement_id NULL). Propriétaire = login
/// d'attribution. Attribué + ledgerisé `console.saved_view.create`.
async fn sv_create(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if valid_name(n) => n.trim().to_string(),
        _ => return bad("nom de vue invalide (1..120 caractères, non vide)"),
    };
    let filter_json = match canon_filter_json(&body) {
        Ok(s) => s,
        Err(why) => return bad(why),
    };
    // scope_engagement=true -> rattache à l'engagement ACTIF (résolu du query `?engagement=`, repli sur
    // l'actif le plus récent) ; sinon NULL (vue GLOBALE). Découplé du query param (toujours présent en
    // lecture) : SEUL le flag explicite décide du rattachement, pour préserver le choix « globale ».
    let scope_eng = body.get("scope_engagement").and_then(|v| v.as_bool()).unwrap_or(false);
    let engagement_id: Option<i64> = if scope_eng {
        Some(resolve_view_engagement_id(&app, &headers, &q))
    } else {
        None
    };
    let user = attribution_login(&app, &headers);
    let id = {
        let store = app.store();
        // execute_returning_id : id de la vue lu du MÊME INSERT (RETURNING id sur PG), sans lastval()
        // — session-indépendant, sûr sur backend poolé.
        match store.execute_returning_id(
            "INSERT INTO saved_view(user_id,engagement_id,name,filter_json,created)
             VALUES(?,?,?,?,datetime('now'))",
            &crate::sql_params![user.clone(), engagement_id, name.clone(), filter_json.clone()],
        ) {
            Ok(id) => id,
            Err(e) => return internal(format!("création de la vue échouée: {e}")),
        }
    };
    let actor = user.clone();
    append_console_ledger(&app, "console.saved_view.create", json!({
        "actor": actor, "id": id, "name": name, "engagement_id": engagement_id,
    }));
    (StatusCode::OK, Json(json!({
        "ok": true,
        "view": {"id": id, "user_id": user, "name": name, "engagement_id": engagement_id}
    }))).into_response()
}

/// DELETE /api/saved-views/:id — SUPPRIME une vue (OPÉRATEUR, fail-closed 403). ISOLATION : ne supprime
/// QUE si la vue appartient à l'APPELANT (`user_id` = attribution) — la vue d'un AUTRE utilisateur est
/// intouchable et renvoie 404 (jamais divulguée). Attribué + ledgerisé `console.saved_view.delete`.
async fn sv_delete(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    let user = attribution_login(&app, &headers);
    // existence + PROPRIÉTÉ (fail-closed : on ne supprime jamais la vue d'un autre, et on ne divulgue pas
    // qu'un id existe pour un autre utilisateur).
    let owned = {
        let store = app.store();
        store
            .query_row(
                "SELECT 1 FROM saved_view WHERE id=? AND user_id=?",
                &crate::sql_params![id, user.clone()],
                |_| Ok(()),
            )
            .is_ok()
    };
    if !owned {
        return not_found(format!("vue {id} introuvable"));
    }
    {
        let store = app.store();
        if let Err(e) = store.execute(
            "DELETE FROM saved_view WHERE id=? AND user_id=?",
            &crate::sql_params![id, user.clone()],
        ) {
            return internal(format!("suppression de la vue échouée: {e}"));
        }
    }
    append_console_ledger(&app, "console.saved_view.delete", json!({
        "actor": user, "id": id,
    }));
    (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response()
}

// =====================================================================================
//  TESTS — CRUD gouverné (rôle operator) + ledgerisé + ISOLATION PAR UTILISATEUR (un utilisateur ne
//  liste/supprime jamais les vues d'un autre) + rattachement engagement optionnel (NULL = global).
//
//  Auto-portants : App de test (DB in-memory, SCHEMA + migrate comme au boot) + appel direct des handlers.
// =====================================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_session, hash_pw, read_ledger_lines, upsert_user, LedgerHead, RunEvent, RunState};
    use rusqlite::Connection;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    fn tmp_ledger(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "forge-sv-{}-{}-{}.jsonl",
            tag,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        p.push(uniq);
        p.to_string_lossy().into_owned()
    }

    fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        crate::migrate(&conn);
        let (events, _) = broadcast::channel::<RunEvent>(64);
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
            run_state: Arc::new(AsyncMutex::new(RunState { current: std::collections::HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        }
    }

    fn seed_engagement(app: &App, id: i64, name: &str) {
        let db = app.db();
        db.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(?,?, 'active','grey','{}','',datetime('now'),datetime('now'))",
            rusqlite::params![id, name],
        )
        .unwrap();
    }

    fn bearer(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {tok}").parse().unwrap());
        h
    }
    fn uid_of(app: &App, login: &str) -> i64 {
        let db = app.db();
        db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
    }
    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:9".parse().unwrap())
    }
    fn noq() -> Query<HashMap<String, String>> {
        Query(HashMap::new())
    }
    async fn to_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    fn sv_count(app: &App) -> i64 {
        let db = app.db();
        db.query_row("SELECT COUNT(*) FROM saved_view", [], |r| r.get(0)).unwrap()
    }
    /// Seed operator o1 + o2 (deux comptes operator distincts) et renvoie leurs tokens de session.
    fn seed_two_operators(app: &App) -> (String, String) {
        {
            let db = app.db();
            upsert_user(&db, "o1", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "o2", "operator", &hash_pw("pw")).unwrap();
        }
        let (t1, _) = create_session(app, uid_of(app, "o1"));
        let (t2, _) = create_session(app, uid_of(app, "o2"));
        (t1, t2)
    }

    /// canon_filter_json : objet accepté & compacté, chaîne-objet acceptée, non-objet refusé, absent -> {}.
    #[test]
    fn filter_json_canon() {
        assert_eq!(canon_filter_json(&json!({"filter_json": {"severity": "HIGH"}})).unwrap(), r#"{"severity":"HIGH"}"#);
        assert_eq!(canon_filter_json(&json!({})).unwrap(), "{}");
        assert_eq!(canon_filter_json(&json!({"filter_json": "{\"status\":\"new\"}"})).unwrap(), r#"{"status":"new"}"#);
        assert!(canon_filter_json(&json!({"filter_json": [1, 2]})).is_err(), "un tableau n'est pas un objet");
        assert!(canon_filter_json(&json!({"filter_json": "not json"})).is_err(), "chaîne non-JSON refusée");
    }

    /// CREATE role-gated (viewer/anonyme refusé) + persistance + ledger attribué + engagement NULL/actif.
    #[tokio::test]
    async fn create_is_operator_gated_and_scoped() {
        let led = tmp_ledger("create");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        // anonyme (aucune session, operator_hash vide) -> 403, aucune création.
        let r = sv_create(State(app.clone()), peer(), HeaderMap::new(), noq(),
            Json(json!({"name": "crit-open", "filter_json": {"severity": "CRITICAL"}}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "anonyme refusé (fail-closed)");
        assert_eq!(sv_count(&app), 0, "un 403 ne crée rien");

        let (o1, _o2) = seed_two_operators(&app);
        // GLOBAL (scope_engagement absent) -> engagement_id NULL.
        let r = sv_create(State(app.clone()), peer(), bearer(&o1), noq(),
            Json(json!({"name": "crit-global", "filter_json": {"severity": "CRITICAL"}}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        // ENGAGEMENT-scoped.
        let r = sv_create(State(app.clone()), peer(), bearer(&o1), noq(),
            Json(json!({"name": "eng-new", "filter_json": {"status": "new"}, "scope_engagement": true}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(sv_count(&app), 2);
        let (n_null, eid): (i64, Option<i64>) = {
            let db = app.db();
            let n: i64 = db.query_row("SELECT COUNT(*) FROM saved_view WHERE engagement_id IS NULL", [], |r| r.get(0)).unwrap();
            let e: Option<i64> = db.query_row("SELECT engagement_id FROM saved_view WHERE name='eng-new'", [], |r| r.get(0)).unwrap();
            drop(db);
            (n, e)
        };
        assert_eq!(n_null, 1, "la vue globale a engagement_id NULL");
        assert_eq!(eid, Some(1), "la vue scopée porte l'engagement actif #1");
        let last = read_ledger_lines(&led);
        assert_eq!(last.last().unwrap()["kind"], "console.saved_view.create");
        assert_eq!(last.last().unwrap()["detail"]["actor"], "o1");

        // nom vide -> 400.
        let r = sv_create(State(app.clone()), peer(), bearer(&o1), noq(), Json(json!({"name": "  "}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&led);
    }

    /// ISOLATION PAR UTILISATEUR : o2 ne LISTE ni ne SUPPRIME les vues de o1 (fail-closed).
    #[tokio::test]
    async fn views_are_per_user_isolated() {
        let led = tmp_ledger("iso");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        let (o1, o2) = seed_two_operators(&app);
        // o1 crée 2 vues (une globale, une engagement).
        sv_create(State(app.clone()), peer(), bearer(&o1), noq(),
            Json(json!({"name": "g1", "filter_json": {"severity": "HIGH"}}))).await;
        sv_create(State(app.clone()), peer(), bearer(&o1), noq(),
            Json(json!({"name": "e1", "scope_engagement": true}))).await;
        // o2 crée 1 vue.
        sv_create(State(app.clone()), peer(), bearer(&o2), noq(), Json(json!({"name": "g2"}))).await;

        // o1 liste -> voit SES 2 vues seulement.
        let r = sv_list(State(app.clone()), bearer(&o1), noq()).await;
        let b = to_json(r).await;
        assert_eq!(b["count"], 2, "o1 voit ses 2 vues");
        // o2 liste -> voit SA vue seulement (jamais celles de o1).
        let r = sv_list(State(app.clone()), bearer(&o2), noq()).await;
        let b = to_json(r).await;
        assert_eq!(b["count"], 1, "o2 ne voit que sa vue");
        assert_eq!(b["views"][0]["name"], "g2");

        // o2 tente de supprimer une vue de o1 -> 404 (intouchable) et la vue survit.
        let o1_view_id: i64 = { let db = app.db(); db.query_row("SELECT id FROM saved_view WHERE name='g1'", [], |r| r.get(0)).unwrap() };
        let r = sv_delete(State(app.clone()), peer(), bearer(&o2), Path(o1_view_id)).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "o2 ne peut pas supprimer la vue de o1");
        assert_eq!(sv_count(&app), 3, "aucune suppression cross-utilisateur");

        // o1 supprime SA vue -> 200.
        let r = sv_delete(State(app.clone()), peer(), bearer(&o1), Path(o1_view_id)).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(sv_count(&app), 2);
        assert_eq!(read_ledger_lines(&led).last().unwrap()["kind"], "console.saved_view.delete");
        let _ = std::fs::remove_file(&led);
    }

    /// GLOBAL vs ENGAGEMENT : une vue globale apparaît sous TOUT engagement ; une vue engagement n'apparaît
    /// que sous le sien.
    #[tokio::test]
    async fn list_mixes_global_and_active_engagement() {
        let led = tmp_ledger("mix");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_engagement(&app, 2, "eng-B");
        let (o1, _o2) = seed_two_operators(&app);
        // globale.
        sv_create(State(app.clone()), peer(), bearer(&o1), noq(), Json(json!({"name": "glob"}))).await;
        // engagement #1 : scope_engagement=true + query ?engagement=1 (résolution de l'engagement actif).
        let q1: Query<HashMap<String, String>> = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        sv_create(State(app.clone()), peer(), bearer(&o1), q1, Json(json!({"name": "for-1", "scope_engagement": true}))).await;

        // liste sous engagement #2 -> globale seulement (for-1 masquée).
        let q2: Query<HashMap<String, String>> = Query(HashMap::from([("engagement".to_string(), "2".to_string())]));
        let r = sv_list(State(app.clone()), bearer(&o1), q2).await;
        let b = to_json(r).await;
        assert_eq!(b["count"], 1, "sous eng #2 : seule la vue globale");
        assert_eq!(b["views"][0]["name"], "glob");

        // liste sous engagement #1 -> globale + for-1.
        let q1b: Query<HashMap<String, String>> = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let r = sv_list(State(app.clone()), bearer(&o1), q1b).await;
        let b = to_json(r).await;
        assert_eq!(b["count"], 2, "sous eng #1 : globale + engagement");
        let _ = std::fs::remove_file(&led);
    }

    #[test]
    fn routes_build() {
        let _r: Router<App> = routes();
    }
}

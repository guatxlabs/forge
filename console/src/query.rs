// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SOUS-SYSTÈME QUERY / DASHBOARDS extrait de main.rs (PURE MOVE). Contient le moteur
//! soql read-only (`exec_soql`/`exec_soql_time` + helpers `cell`/`soql_stats`), les endpoints
//! `/api/query` (GET+POST), et le CRUD des dashboards (vues) + panels soql sauvegardés (modèle
//! query-driven de Plume). Le moteur ouvre une connexion `SQLITE_OPEN_READ_ONLY` (défense en
//! profondeur). Les écritures (dashboards/panels) sont gatées par `check_writer` (session admin|operator,
//! racine de crate) — l'utilisateur CONNECTÉ édite ses panneaux sans coller de token d'ingest.
//! Réutilise App + `check_writer`/`gs`/`soql` via `use crate::*`, et est re-exporté à la racine par
//! `pub(crate) use crate::query::*` — les routes de build_router (`get(query).post(query_post)`,
//! `get(dashboards_list)`, `get(panels_list)`, …) ET les tests inline de main.rs (`super::*`)
//! résolvent donc ces handlers INCHANGÉS. `exec_soql_time` est aussi consommé par `coverage`
//! (findings.rs) et `panel_data` (ici) via la ré-exportation racine.
use crate::*;

use guatx_core::soql; // cœur partagé (extrait) — moteur soql compile/schema

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Lit la cellule à l'index `i` d'une ligne de type SQLite INCONNU à la compilation (moteur SoQL) via
/// la couche seam : `Row::get_value` dispatch sur la classe de stockage RUNTIME (Int/Real/Text/Blob/
/// Null) puis `store::value_to_json` la mappe en JSON. Byte-identique à l'ancien dispatch `ValueRef` :
/// Int/Real -> nombre, Text -> chaîne, Blob/Null -> Null, et toute erreur de lecture -> Null. Helper
/// PARTAGÉ par `exec_soql` (ici) et `cli::cli_query_rows` (même typage de cellule).
pub(crate) fn cell(row: &rusqlite::Row, i: usize) -> Value {
    match crate::store::Row::sqlite(row).get_value(i) {
        Ok(v) => crate::store::value_to_json(&v),
        Err(_) => Value::Null,
    }
}

/// Compile soql -> SQL et l'exécute sur une connexion SQLITE_OPEN_READ_ONLY (défense en profondeur).
/// Réutilisé par /api/query (GET+POST) et /api/panels/:id/data.
/// Réponse : {columns, rows, total, stats, compiled}.
///   - `total` : nb de lignes renvoyées (après LIMIT éventuel du pipeline soql) ;
///   - `stats` : agrégats légers par colonne numérique (min/max/sum) — utile aux viz du dashboard.
pub(crate) fn exec_soql(db_path: &str, q: &str) -> Result<Value, (StatusCode, String)> {
    exec_soql_time(db_path, q, 0, 0)
}

/// Variante avec bornes temporelles (epoch ; 0 = pas de borne) — utilisée par panel_data (from/to).
pub(crate) fn exec_soql_time(db_path: &str, q: &str, from: i64, to: i64) -> Result<Value, (StatusCode, String)> {
    let c = soql::compile_with_time(q, from, to, &soql::Schema::forge()).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(3));
    let mut stmt = conn.prepare(&c.sql).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let ncol = c.columns.len();
    let rows: Vec<Value> = stmt
        .query_map([], |row| {                       // SQL inline (valeurs échappées), pas de params liés
            Ok(Value::Array((0..ncol).map(|i| cell(row, i)).collect()))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    let stats = soql_stats(&c.columns, &rows);
    Ok(json!({"columns": c.columns, "rows": rows, "total": rows.len(), "stats": stats, "compiled": c.sql}))
}

/// BACKEND-ROUTED SoQL (Stage 2b) — compile+run une requête SoQL sur le backend ACTIF de l'App.
/// SQLite (aujourd'hui, `App.pg` toujours `None` — gate fail-closed) => le chemin read-only
/// SQLite EXISTANT (`exec_soql_time`), BYTE-IDENTIQUE. Postgres (feature `store-postgres` + `App.pg`
/// = Some) => `exec_soql_time_pg` (session PG read-only). Les handlers qui DISPOSENT de l'App
/// (`query`/`query_post`/`panel_data`) passent par ICI ; la sous-commande CLI `query` (sans App)
/// garde `exec_soql` (SQLite) ou route elle-même vers PG (cli.rs). L'isolation READ-ONLY est
/// préservée sur les DEUX backends.
pub(crate) fn exec_soql_app(app: &App, q: &str) -> Result<Value, (StatusCode, String)> {
    exec_soql_time_app(app, q, 0, 0)
}

/// Variante bornée dans le temps de [`exec_soql_app`] (from/to epoch ; 0 = pas de borne).
pub(crate) fn exec_soql_time_app(app: &App, q: &str, from: i64, to: i64) -> Result<Value, (StatusCode, String)> {
    // POSTGRES (feature `store-postgres`) : si l'App tient un client PG session-pinné, on lit dessus
    // (transaction READ ONLY). Sinon — et TOUJOURS dans le build community (bloc non compilé) — on
    // retombe sur le chemin SQLite read-only INCHANGÉ ci-dessous.
    #[cfg(feature = "store-postgres")]
    if app.pg.is_some() {
        let store = app.store();
        return exec_soql_time_pg_store(&store, q, from, to);
    }
    exec_soql_time(&app.db_path, q, from, to)
}

/// CHEMIN LECTURE POSTGRES du moteur SoQL (feature `store-postgres`). ATTEIGNABLE uniquement quand
/// `App.pg` est `Some` — la gate de démarrage reste fail-closed, donc ce chemin n'est JAMAIS exercé
/// dans le build community (compilé, prouvé par `store.rs::pg_tests`, mais pas câblé au runtime).
/// Reproduit EXACTEMENT le typage par cellule du chemin SQLite : compile la MÊME SoQL -> SQL, puis lit
/// chaque cellule via l'accesseur dynamique du seam `Row::get_value` + le helper PARTAGÉ
/// `store::value_to_json` (Int/Real -> nombre, Text -> chaîne, Blob/Null -> Null, erreur de lecture ->
/// Null) — byte-identique au dispatch `ValueRef` de `cell`. ISOLATION READ-ONLY : la SoQL arbitraire de
/// l'utilisateur tourne dans une transaction `READ ONLY` sur le client session-pinné du store (défense
/// en profondeur — un bug ne peut pas muter la base), l'analogue PG de la connexion
/// `SQLITE_OPEN_READ_ONLY`. LAX : on saute une ligne malformée exactement comme le
/// `query_map(..).filter_map(|r| r.ok())` du chemin SQLite.
#[cfg(feature = "store-postgres")]
pub(crate) fn exec_soql_time_pg_store(
    store: &crate::store::Store,
    q: &str,
    from: i64,
    to: i64,
) -> Result<Value, (StatusCode, String)> {
    let c = soql::compile_with_time(q, from, to, &soql::Schema::forge()).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let ncol = c.columns.len();
    // Transaction READ ONLY = la MÊME isolation read-only que le SQLITE_OPEN_READ_ONLY du chemin SQLite.
    // Un BEGIN qui échoue est une erreur dure (aucune tx ouverte -> on sort). Le COMMIT best-effort est
    // TOUJOURS émis après la lecture (READ ONLY : rien à persister ; sur tx avortée, COMMIT = ROLLBACK)
    // pour ne JAMAIS laisser une transaction ouverte sur le client session-pinné réutilisé.
    store
        .execute_batch("BEGIN TRANSACTION READ ONLY")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let result = store.query_lax(&c.sql, &crate::sql_params![], |row| {
        Ok(Value::Array(
            (0..ncol)
                .map(|i| match row.get_value(i) {
                    Ok(v) => crate::store::value_to_json(&v),
                    Err(_) => Value::Null,
                })
                .collect(),
        ))
    });
    let _ = store.execute_batch("COMMIT");
    let rows: Vec<Value> = result.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let stats = soql_stats(&c.columns, &rows);
    Ok(json!({"columns": c.columns, "rows": rows, "total": rows.len(), "stats": stats, "compiled": c.sql}))
}

/// Stats par colonne sur le jeu de résultats : pour chaque colonne entièrement numérique,
/// renvoie {min,max,sum,count}. Léger (pas de 2e requête SQL) — calculé en mémoire sur les rows.
pub(crate) fn soql_stats(columns: &[String], rows: &[Value]) -> Value {
    let mut out = serde_json::Map::new();
    for (i, col) in columns.iter().enumerate() {
        let mut count = 0i64;
        let (mut min, mut max, mut sum) = (f64::INFINITY, f64::NEG_INFINITY, 0.0f64);
        let mut all_num = true;
        for row in rows {
            let v = row.get(i);
            let n = match v {
                Some(Value::Number(n)) => n.as_f64(),
                Some(Value::String(s)) => s.parse::<f64>().ok(),
                Some(Value::Null) | None => continue,
                _ => None,
            };
            match n {
                Some(f) => { count += 1; min = min.min(f); max = max.max(f); sum += f; }
                None => { all_num = false; break; }
            }
        }
        if all_num && count > 0 {
            out.insert(col.clone(), json!({"min": min, "max": max, "sum": sum, "count": count}));
        }
    }
    Value::Object(out)
}

pub(crate) async fn query(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let qs = q.get("q").cloned().unwrap_or_else(|| "search".to_string());
    match exec_soql_app(&app, &qs) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err((s, e)) => (s, Json(json!({"error": e}))),
    }
}

/// POST /api/query {"soql": "...", "q": "..."} -> {columns, rows, total, stats, compiled}.
/// Accepte `soql` ou `q` (alias). Même moteur read-only que le GET ; permet des requêtes
/// longues qui ne tiennent pas en query-string.
pub(crate) async fn query_post(State(app): State<App>, Json(body): Json<Value>) -> impl IntoResponse {
    let qs = body
        .get("soql")
        .or_else(|| body.get("q"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "search".to_string());
    match exec_soql_app(&app, &qs) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err((s, e)) => (s, Json(json!({"error": e}))),
    }
}

// --- dashboards / vues : regroupement de panels (CRUD) ---
//
// Un « dashboard » (alias « vue ») est un conteneur nommé de panels. Le panel porte `dashboard_id`
// (défaut 1 = dashboard par défaut, garanti au boot). CRUD gaté par la SESSION de l'utilisateur
// (check_writer : admin|operator), comme les panels ; les lectures sont sous auth_guard comme le reste.

/// GET /api/dashboards — liste les dashboards (ordre `position`, id). Lecture (viewer).
pub(crate) async fn dashboards_list(State(app): State<App>) -> impl IntoResponse {
    
    let out: Vec<Value> = app.store()
        .query_lax(
            "SELECT d.id, d.name, d.descr, d.position, d.created, d.updated,
                    (SELECT COUNT(*) FROM panel p WHERE p.dashboard_id=d.id) AS panels
             FROM dashboard d ORDER BY d.position, d.id",
            &[],
            |r| {
                Ok(json!({
                    "id": r.get_i64(0)?,
                    "name": r.get_str(1)?,
                    "descr": r.get_opt_str(2)?.unwrap_or_default(),
                    "position": r.get_opt_i64(3)?.unwrap_or(0),
                    "created": r.get_opt_str(4)?.unwrap_or_default(),
                    "updated": r.get_opt_str(5)?.unwrap_or_default(),
                    "panels": r.get_i64(6)?,
                }))
            },
        )
        .unwrap_or_default();
    Json(Value::Array(out))
}

/// POST /api/dashboards {name, descr?, position?} -> {id}. Écriture (session admin|operator).
pub(crate) async fn dashboard_create(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_writer(&app, &headers) {
        return writer_denied();
    }
    let name = gs(&body, "name");
    if name.is_empty() || name.len() > 128 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "name requis (1..128)"})));
    }
    let descr = gs(&body, "descr");
    let position = body.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    let store = app.store();
    // execute_returning_id : l'id de la ligne insérée vient du MÊME statement (RETURNING id sur PG),
    // sans dépendance de session lastval() — sûr sur backend poolé (plus de client épinglé requis).
    match store.execute_returning_id(
        "INSERT INTO dashboard(name,descr,position,created,updated) VALUES(?,?,?,datetime('now'),datetime('now'))",
        &crate::sql_params![&name, &descr, position],
    ) {
        Ok(id) => (StatusCode::OK, Json(json!({"id": id}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

/// POST /api/dashboards/:id {name?, descr?, position?} — met à jour (champs présents). Écriture (session admin|operator).
pub(crate) async fn dashboard_update(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_writer(&app, &headers) {
        return writer_denied();
    }
    let store = app.store();
    let mut sets: Vec<String> = Vec::new();
    let mut args: Vec<crate::store::Param> = Vec::new();
    if let Some(v) = body.get("name").and_then(|v| v.as_str()) {
        if v.is_empty() || v.len() > 128 {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "name invalide (1..128)"})));
        }
        sets.push("name=?".into()); args.push(crate::store::Param::Text(v.to_string()));
    }
    if let Some(v) = body.get("descr").and_then(|v| v.as_str()) { sets.push("descr=?".into()); args.push(crate::store::Param::Text(v.to_string())); }
    if let Some(v) = body.get("position").and_then(|v| v.as_i64()) { sets.push("position=?".into()); args.push(crate::store::Param::Int(v)); }
    if sets.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "aucun champ à mettre à jour"})));
    }
    sets.push("updated=datetime('now')".into());
    args.push(crate::store::Param::Int(id));
    let sql = format!("UPDATE dashboard SET {} WHERE id=?", sets.join(","));
    match store.execute(&sql, &args) {
        Ok(0) => (StatusCode::NOT_FOUND, Json(json!({"error": "dashboard introuvable"}))),
        Ok(_) => (StatusCode::OK, Json(json!({"updated": id}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

/// DELETE /api/dashboards/:id — supprime un dashboard et réassigne ses panels au dashboard #1.
/// Le dashboard #1 (défaut) est PROTÉGÉ (409) — il garantit la rétro-compat. Écriture (session admin|operator).
pub(crate) async fn dashboard_delete(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>) -> impl IntoResponse {
    if !check_writer(&app, &headers) {
        return writer_denied();
    }
    if id == 1 {
        return (StatusCode::CONFLICT, Json(json!({"error": "default_protected", "why": "le dashboard par défaut (#1) ne peut pas être supprimé"})));
    }
    let store = app.store();
    // les panels du dashboard supprimé retombent sur le défaut (jamais perdus/orphelins). FAIL-CLOSED : un
    // échec de la réassignation -> 500 AVANT le DELETE (sinon les panels seraient ORPHELINS pointant un
    // dashboard supprimé, et la réponse affirmerait faussement `panels_reassigned_to:1`).
    if let Err(e) = store.execute("UPDATE panel SET dashboard_id=1 WHERE dashboard_id=?", &crate::sql_params![id]) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()})));
    }
    match store.execute("DELETE FROM dashboard WHERE id=?", &crate::sql_params![id]) {
        Ok(0) => (StatusCode::NOT_FOUND, Json(json!({"error": "dashboard introuvable"}))),
        Ok(_) => (StatusCode::OK, Json(json!({"deleted": id, "panels_reassigned_to": 1}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

// --- dashboards : panels soql sauvegardés (modèle query-driven de Plume) ---

/// GET /api/panels?dashboard_id=N — liste les panels, optionnellement filtrés par dashboard.
/// Sans `dashboard_id` : tous les panels (rétro-compat). `dashboard_id` est lié (param), pas inliné.
pub(crate) async fn panels_list(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    
    let (where_, args): (&str, Vec<crate::store::Param>) = match q.get("dashboard_id").and_then(|s| s.parse::<i64>().ok()) {
        Some(d) => (" WHERE dashboard_id=?", vec![crate::store::Param::Int(d)]),
        None => ("", vec![]),
    };
    let sql = format!("SELECT id,name,query,viz,position,descr,col_span,updated,dashboard_id FROM panel{where_} ORDER BY position, id");
    let out: Vec<Value> = app.store()
        .query_lax(&sql, &args, |r| {
            Ok(json!({
                "id": r.get_i64(0)?,
                "name": r.get_str(1)?,
                "query": r.get_str(2)?,
                "viz": r.get_opt_str(3)?.unwrap_or_else(|| "table".to_string()),
                "position": r.get_opt_i64(4)?.unwrap_or(0),
                "descr": r.get_opt_str(5)?.unwrap_or_default(),
                "col_span": r.get_opt_i64(6)?.unwrap_or(1),
                "updated": r.get_opt_str(7)?.unwrap_or_default(),
                "dashboard_id": r.get_opt_i64(8)?.unwrap_or(1),
            }))
        })
        .unwrap_or_default();
    Json(Value::Array(out))
}

pub(crate) async fn panel_create(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_writer(&app, &headers) {
        return writer_denied();
    }
    let name = gs(&body, "name");
    let qy = gs(&body, "query");
    let viz = { let v = gs(&body, "viz"); if v.is_empty() { "table".to_string() } else { v } };
    let descr = gs(&body, "descr");
    let col_span = body.get("col_span").and_then(|v| v.as_i64()).unwrap_or(1).clamp(1, 4);
    let position = body.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    // dashboard_id : défaut 1 (dashboard par défaut). On vérifie l'existence pour ne pas créer un
    // panel orphelin (FK soft) ; absent => défaut.
    let dashboard_id = body.get("dashboard_id").and_then(|v| v.as_i64()).unwrap_or(1);
    if name.is_empty() || qy.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "name et query requis"})));
    }
    if let Err(e) = soql::compile(&qy, &soql::Schema::forge()) {     // ne sauve pas un panel à la requête invalide
        return (StatusCode::BAD_REQUEST, Json(json!({"error": format!("query invalide: {e}")})));
    }
    let store = app.store();
    let exists: bool = store.query_row("SELECT 1 FROM dashboard WHERE id=?", &crate::sql_params![dashboard_id], |_| Ok(())).is_ok();
    if !exists {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "unknown_dashboard", "why": format!("dashboard #{dashboard_id} inexistant")})));
    }
    // execute_returning_id : id du panel inséré lu depuis le MÊME statement (RETURNING id sur PG),
    // sans lastval() — indépendant de la session, sûr sur backend poolé.
    match store.execute_returning_id(
        "INSERT INTO panel(name,query,viz,descr,col_span,position,dashboard_id,updated) VALUES(?,?,?,?,?,?,?,datetime('now'))",
        &crate::sql_params![&name, &qy, &viz, &descr, col_span, position, dashboard_id],
    ) {
        Ok(id) => (StatusCode::OK, Json(json!({"id": id}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

/// POST /api/panels/:id — met à jour un panel existant (champs présents seulement).
/// Corps : {name?, query?, viz?, descr?, col_span?, position?}. La query, si fournie, est validée.
pub(crate) async fn panel_update(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_writer(&app, &headers) {
        return writer_denied();
    }
    if let Some(qy) = body.get("query").and_then(|v| v.as_str()) {
        if let Err(e) = soql::compile(qy, &soql::Schema::forge()) {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": format!("query invalide: {e}")})));
        }
    }
    let store = app.store();
    let mut sets: Vec<String> = Vec::new();
    let mut args: Vec<crate::store::Param> = Vec::new();
    if let Some(v) = body.get("name").and_then(|v| v.as_str()) { sets.push("name=?".into()); args.push(crate::store::Param::Text(v.to_string())); }
    if let Some(v) = body.get("query").and_then(|v| v.as_str()) { sets.push("query=?".into()); args.push(crate::store::Param::Text(v.to_string())); }
    if let Some(v) = body.get("viz").and_then(|v| v.as_str()) { sets.push("viz=?".into()); args.push(crate::store::Param::Text(v.to_string())); }
    if let Some(v) = body.get("descr").and_then(|v| v.as_str()) { sets.push("descr=?".into()); args.push(crate::store::Param::Text(v.to_string())); }
    if let Some(v) = body.get("col_span").and_then(|v| v.as_i64()) { sets.push("col_span=?".into()); args.push(crate::store::Param::Int(v.clamp(1, 4))); }
    if let Some(v) = body.get("position").and_then(|v| v.as_i64()) { sets.push("position=?".into()); args.push(crate::store::Param::Int(v)); }
    // ré-assignation de dashboard : vérifiée pour éviter l'orphelinage (FK soft).
    if let Some(v) = body.get("dashboard_id").and_then(|v| v.as_i64()) {
        let exists: bool = store.query_row("SELECT 1 FROM dashboard WHERE id=?", &crate::sql_params![v], |_| Ok(())).is_ok();
        if !exists {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "unknown_dashboard", "why": format!("dashboard #{v} inexistant")})));
        }
        sets.push("dashboard_id=?".into()); args.push(crate::store::Param::Int(v));
    }
    if sets.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "aucun champ à mettre à jour"})));
    }
    sets.push("updated=datetime('now')".into());
    args.push(crate::store::Param::Int(id));
    let sql = format!("UPDATE panel SET {} WHERE id=?", sets.join(","));
    match store.execute(&sql, &args) {
        Ok(0) => (StatusCode::NOT_FOUND, Json(json!({"error": "panel introuvable"}))),
        Ok(_) => (StatusCode::OK, Json(json!({"updated": id}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

pub(crate) async fn panel_delete(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>) -> impl IntoResponse {
    if !check_writer(&app, &headers) {
        return writer_denied();
    }
    
    let _ = app.store().execute("DELETE FROM panel WHERE id=?", &crate::sql_params![id]);
    (StatusCode::OK, Json(json!({"deleted": id})))
}

/// GET /api/panels/:id/data?from=&to= — exécute la query du panel.
/// `from`/`to` (epoch seconds) bornent `ts` via compile_with_time (0 = pas de borne).
pub(crate) async fn panel_data(State(app): State<App>, Path(id): Path<i64>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let qy: Option<String> = {
        let store = app.store();
        store.query_row("SELECT query FROM panel WHERE id=?", &crate::sql_params![id], |r| r.get_str(0)).ok()
    };
    let from = q.get("from").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let to = q.get("to").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    match qy {
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "panel introuvable"}))),
        Some(q) => match exec_soql_time_app(&app, &q, from, to) {
            Ok(v) => (StatusCode::OK, Json(v)),
            Err((s, e)) => (s, Json(json!({"error": e}))),
        },
    }
}

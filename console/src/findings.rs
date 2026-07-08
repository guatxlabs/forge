// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — HANDLERS DE LECTURE du modèle ROUGE (finding / runrecord / campaign / roe /
//! coverage) extraits de main.rs (PURE MOVE). Toutes ces vues sont ISOLÉES par engagement actif
//! (`resolve_view_engagement_id`, fail-closed) — un engagement ne voit JAMAIS les données d'un autre.
//! Réutilise App + les helpers de la racine de crate (`resolve_view_engagement_id`/`paginate`/`gs`/
//! `exec_soql_time`) via `use crate::*`, et est re-exporté à la racine par
//! `pub(crate) use crate::findings::*` — les routes de build_router (`get(findings)`, `get(coverage)`,
//! …) ET les tests inline de main.rs (`super::*`) résolvent donc ces handlers INCHANGÉS.
use crate::*;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use crate::store::Param;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;

// NOTE: `rows_to_json` below is DEAD CODE that takes a raw `&Connection` (not an `App`), so it is not
// an `app.db()` DML site — it stays on rusqlite and is left unconverted (no `App::store()` in scope).
#[allow(dead_code)] // helper générique conservé (colonnes texte) ; les handlers typés le court-circuitent.
pub(crate) fn rows_to_json(db: &Connection, sql: &str, args: &[String], cols: &[&str]) -> Vec<Value> {
    let mut stmt = match db.prepare(sql) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let ncol = cols.len();
    let mapped = stmt.query_map(rusqlite::params_from_iter(args.iter()), |row| {
        let mut o = serde_json::Map::new();
        for (i, c) in cols.iter().enumerate() {
            let v = row.get::<_, Option<String>>(i).unwrap_or(None);
            o.insert((*c).to_string(), json!(v.unwrap_or_default()));
        }
        let _ = ncol;
        Ok(Value::Object(o))
    });
    match mapped {
        Ok(it) => it.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    }
}

pub(crate) async fn findings(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT (objet de 1re classe) : la vue ne montre QUE les findings de l'engagement actif
    // (fail-closed : un engagement ne voit JAMAIS les findings d'un autre). `engagement_id` est un
    // entier RÉSOLU (jamais du texte client) -> inliné sans risque d'injection.
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let store = app.store();
    let (mut conds, mut args): (Vec<String>, Vec<String>) = (vec![format!("engagement_id={eid}")], vec![]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?".into()); args.push(c.clone()); }
    if let Some(s) = q.get("severity") { conds.push("severity=?".into()); args.push(s.clone()); }
    if let Some(s) = q.get("status") { conds.push("status=?".into()); args.push(s.clone()); }
    if let Some(t) = q.get("target") { conds.push("target=?".into()); args.push(t.clone()); }
    if let Some(m) = q.get("mitre") { conds.push("mitre=?".into()); args.push(m.clone()); }
    if let Some(r) = q.get("run_id") { conds.push("run_id=?".into()); args.push(r.clone()); }
    let where_ = format!(" WHERE {}", conds.join(" AND "));
    let params: Vec<Param> = args.iter().map(|s| Param::Text(s.clone())).collect();
    let total: i64 = store
        .query_row(&format!("SELECT COUNT(*) FROM finding{where_}"), &params, |r| r.get_i64(0))
        .unwrap_or(0);
    let (limit, offset) = paginate(&q, 200, 1000);
    let sql = format!(
        "SELECT id,ts,campaign,target,title,severity,category,mitre,status,tool,run_id FROM finding{where_} ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
    );
    // requête typée : `id` est un entier (rows_to_json le rendrait vide en le lisant comme String).
    // LENIENT (query_lax): un prepare échoué -> Err -> unwrap_or_default -> findings vides + total, à
    // l'identique de l'early-return d'avant ; une ligne malformée est ignorée (filter_map(ok)).
    let rows: Vec<Value> = store
        .query_lax(&sql, &params, |r| {
            Ok(json!({
                "id": r.get_i64(0)?,
                "ts": r.get_opt_str(1)?.unwrap_or_default(),
                "campaign": r.get_opt_str(2)?.unwrap_or_default(),
                "target": r.get_opt_str(3)?.unwrap_or_default(),
                "title": r.get_opt_str(4)?.unwrap_or_default(),
                "severity": r.get_opt_str(5)?.unwrap_or_default(),
                "category": r.get_opt_str(6)?.unwrap_or_default(),
                "mitre": r.get_opt_str(7)?.unwrap_or_default(),
                "status": r.get_opt_str(8)?.unwrap_or_default(),
                "tool": r.get_opt_str(9)?.unwrap_or_default(),
                "run_id": r.get_opt_str(10)?.unwrap_or_default(),
            }))
        })
        .unwrap_or_default();
    Json(json!({"total": total, "limit": limit, "offset": offset, "findings": rows}))
}

pub(crate) async fn finding_detail(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ISOLATION : le détail n'est servi QUE si le finding appartient à l'engagement actif (un id d'un
    // AUTRE engagement -> 404, jamais divulgué). engagement_id résolu (entier) inliné sans risque.
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let store = app.store();
    let row = store.query_row(
        &format!("SELECT id,ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id FROM finding WHERE id=? AND engagement_id={eid}"),
        &crate::sql_params![id],
        |r| {
            Ok(json!({
                "id": r.get_i64(0)?,
                "ts": r.get_opt_str(1)?.unwrap_or_default(),
                "campaign": r.get_opt_str(2)?.unwrap_or_default(),
                "target": r.get_opt_str(3)?.unwrap_or_default(),
                "title": r.get_opt_str(4)?.unwrap_or_default(),
                "severity": r.get_opt_str(5)?.unwrap_or_default(),
                "category": r.get_opt_str(6)?.unwrap_or_default(),
                "mitre": r.get_opt_str(7)?.unwrap_or_default(),
                "status": r.get_opt_str(8)?.unwrap_or_default(),
                "evidence": r.get_opt_str(9)?.unwrap_or_default(),
                "tool": r.get_opt_str(10)?.unwrap_or_default(),
                "poc": r.get_opt_str(11)?.unwrap_or_default(),
                "fix": r.get_opt_str(12)?.unwrap_or_default(),
                "run_id": r.get_opt_str(13)?.unwrap_or_default(),
            }))
        },
    );
    match row {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({"error": "finding introuvable"}))),
    }
}

pub(crate) async fn runrecords(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : les runrecords de la vue sont ceux de l'engagement actif UNIQUEMENT (isolation).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let store = app.store();
    let (mut conds, mut args): (Vec<String>, Vec<String>) = (vec![format!("engagement_id={eid}")], vec![]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?".into()); args.push(c.clone()); }
    if let Some(t) = q.get("target") { conds.push("target=?".into()); args.push(t.clone()); }
    if let Some(m) = q.get("mitre") { conds.push("mitre=?".into()); args.push(m.clone()); }
    if let Some(r) = q.get("run_id") { conds.push("run_id=?".into()); args.push(r.clone()); }
    if q.get("fired").map(|v| v == "1" || v == "true").unwrap_or(false) { conds.push("fired=1".into()); }
    let where_ = format!(" WHERE {}", conds.join(" AND "));
    let (limit, offset) = paginate(&q, 500, 2000);
    let sql = format!(
        "SELECT id,ts,campaign,target,kind,mitre,fired,detail,run_id FROM runrecord{where_} ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
    );
    // `fired` est un entier (0/1) — colonne réelle ; on la rend telle quelle via une requête typée.
    // LENIENT: prepare échoué -> Err -> unwrap_or_default -> [] (idem early-return), lignes mal formées ignorées.
    let params: Vec<Param> = args.iter().map(|s| Param::Text(s.clone())).collect();
    let out: Vec<Value> = store
        .query_lax(&sql, &params, |r| {
            Ok(json!({
                "id": r.get_i64(0)?,
                "ts": r.get_opt_str(1)?.unwrap_or_default(),
                "campaign": r.get_opt_str(2)?.unwrap_or_default(),
                "target": r.get_opt_str(3)?.unwrap_or_default(),
                "kind": r.get_opt_str(4)?.unwrap_or_default(),
                "mitre": r.get_opt_str(5)?.unwrap_or_default(),
                "fired": r.get_opt_i64(6)?.unwrap_or(0),
                "detail": r.get_opt_str(7)?.unwrap_or_default(),
                "run_id": r.get_opt_str(8)?.unwrap_or_default(),
            }))
        })
        .unwrap_or_default();
    Json(Value::Array(out))
}

pub(crate) async fn campaigns(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : `campaign` est un sous-label LIBRE AU SEIN d'un engagement — on n'agrège donc QUE
    // les campagnes de l'engagement actif (une même chaîne dans un autre engagement reste invisible ici).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let store = app.store();
    // Agrège depuis les findings (source réelle) + table campaign (métadonnées). Pas de JOIN strict :
    // on liste les campagnes vues côté findings + celles déclarées, avec leurs compteurs.
    // LENIENT: prepare échoué -> Err -> unwrap_or_default -> [] (idem early-return), lignes mal formées ignorées.
    let out: Vec<Value> = store
        .query_lax(
            &format!("SELECT campaign, COUNT(*) AS findings, MAX(ts) AS last_ts FROM finding WHERE campaign<>'' AND engagement_id={eid} GROUP BY campaign ORDER BY last_ts DESC"),
            &[],
            |r| {
                Ok(json!({
                    "campaign": r.get_str(0)?,
                    "findings": r.get_i64(1)?,
                    "last_ts": r.get_opt_str(2)?.unwrap_or_default(),
                }))
            },
        )
        .unwrap_or_default();
    Json(Value::Array(out))
}

pub(crate) async fn roe(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : les décisions du garde-fou sont celles de l'engagement actif UNIQUEMENT (isolation).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let store = app.store();
    let (mut conds, mut args): (Vec<String>, Vec<String>) = (vec![format!("engagement_id={eid}")], vec![]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?".into()); args.push(c.clone()); }
    if let Some(r) = q.get("run_id") { conds.push("run_id=?".into()); args.push(r.clone()); }
    if let Some(v) = q.get("verdict") { conds.push("verdict=?".into()); args.push(v.clone()); }
    let where_ = format!(" WHERE {}", conds.join(" AND "));
    let (limit, offset) = paginate(&q, 500, 2000);
    let sql = format!(
        "SELECT id,ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons FROM roe_decision{where_} ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
    );
    // LENIENT: prepare échoué -> Err -> unwrap_or_default -> [] (idem early-return), lignes mal formées ignorées.
    let params: Vec<Param> = args.iter().map(|s| Param::Text(s.clone())).collect();
    let out: Vec<Value> = store
        .query_lax(&sql, &params, |r| {
            // reasons stocké en JSON (array) — on le re-parse pour le rendre structuré au front.
            let reasons_raw: String = r.get_opt_str(10)?.unwrap_or_default();
            let reasons = serde_json::from_str::<Value>(&reasons_raw).unwrap_or(Value::String(reasons_raw));
            Ok(json!({
                "id": r.get_i64(0)?,
                "ts": r.get_opt_str(1)?.unwrap_or_default(),
                "campaign": r.get_opt_str(2)?.unwrap_or_default(),
                "run_id": r.get_opt_str(3)?.unwrap_or_default(),
                "action_id": r.get_opt_str(4)?.unwrap_or_default(),
                "target": r.get_opt_str(5)?.unwrap_or_default(),
                "kind": r.get_opt_str(6)?.unwrap_or_default(),
                "verdict": r.get_opt_str(7)?.unwrap_or_default(),
                "exploit": r.get_i64(8)? != 0,
                "destructive": r.get_i64(9)? != 0,
                "reasons": reasons,
            }))
        })
        .unwrap_or_default();
    Json(Value::Array(out))
}

pub(crate) async fn coverage(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : couverture ATT&CK de l'engagement actif UNIQUEMENT (engagement_id résolu, inliné).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let store = app.store();
    // filtre campaign optionnel (param lié — pas d'inlining).
    let (sql, args): (String, Vec<String>) = match q.get("campaign") {
        Some(c) => (
            format!("SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' AND engagement_id={eid} AND campaign=? GROUP BY mitre ORDER BY n DESC"),
            vec![c.clone()],
        ),
        None => (
            format!("SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' AND engagement_id={eid} GROUP BY mitre ORDER BY n DESC"),
            vec![],
        ),
    };
    // LENIENT: prepare échoué -> Err -> unwrap_or_default -> [] (idem early-return), lignes mal formées ignorées.
    let params: Vec<Param> = args.iter().map(|s| Param::Text(s.clone())).collect();
    let out: Vec<Value> = store
        .query_lax(&sql, &params, |row| {
            Ok(json!({
                "mitre": row.get_str(0)?,
                "runs": row.get_i64(1)?,
                "fired": row.get_i64(2)?
            }))
        })
        .unwrap_or_default();
    Json(Value::Array(out))
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — HANDLERS DE LECTURE du modèle ROUGE (finding / runrecord / campaign / roe /
//! coverage) extraits de main.rs (PURE MOVE). Toutes ces vues sont ISOLÉES par engagement actif
//! (`resolve_view_engagement_id`, fail-closed) — un engagement ne voit JAMAIS les données d'un autre.
//! Réutilise App + les helpers de la racine de crate (`resolve_view_engagement_id`/`paginate`/`gs`/
//! `exec_soql_time`) via `use crate::*`, et est re-exporté à la racine par
//! `pub(crate) use crate::findings::*` — les routes de build_router (`get(findings)`, `get(coverage)`,
//! …) ET les tests inline de main.rs (`super::*`) résolvent donc ces handlers INCHANGÉS.
use crate::*;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use crate::store::Param;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

// =====================================================================================
//  VOCABULAIRES VALIDÉS (#15) — TLP 2.0 (classification/diffusion) + CYCLE DE VIE d'un finding.
//  Contraintes APPLICATIVES (pas SQL — les colonnes restent TEXT), fail-closed à l'écriture. Partagés
//  avec engagements.rs (validation de la classification d'engagement) via `crate::*`.
// =====================================================================================

/// Labels TLP 2.0 (FIRST.org) — jeu FERMÉ. Une valeur hors de cet ensemble est refusée (400).
/// L'ordre = du moins au plus restrictif (CLEAR < GREEN < AMBER < AMBER+STRICT < RED).
pub(crate) const TLP_CLASSES: [&str; 5] = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"];

/// Cycle de vie d'un finding (SOC/pentest) — jeu FERMÉ pour les TRANSITIONS validées. La colonne
/// `finding.status` reste TOLÉRANTE en LECTURE (valeurs libres héritées affichées telles quelles) ;
/// seule une transition via l'API est contrainte à ce vocabulaire (additif, pas une migration dure).
pub(crate) const FINDING_STATUSES: [&str; 7] =
    ["new", "triaged", "confirmed", "remediated", "false_positive", "accepted", "wontfix"];

/// Normalise + valide un label TLP (casse insensible, préfixe `TLP:` toléré, espace -> `+`). Chaîne
/// VIDE => `Some("")` (non classifié : autorisé, le label est optionnel). Valeur non vide hors du jeu
/// TLP => `None` (refus 400). Fonction PURE.
pub(crate) fn norm_tlp(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        return Some(String::new());
    }
    let up = t.to_ascii_uppercase();
    let up = up.strip_prefix("TLP:").unwrap_or(&up).trim();
    let canon = up.replace(' ', "+");
    if TLP_CLASSES.contains(&canon.as_str()) { Some(canon) } else { None }
}

/// Normalise + valide un statut de cycle de vie (casse insensible). `None` si hors [`FINDING_STATUSES`].
/// Fonction PURE.
pub(crate) fn norm_finding_status(s: &str) -> Option<String> {
    let low = s.trim().to_ascii_lowercase();
    if FINDING_STATUSES.contains(&low.as_str()) { Some(low) } else { None }
}

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
        "SELECT id,ts,campaign,target,title,severity,category,mitre,status,tool,run_id,classification FROM finding{where_} ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
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
                "classification": r.get_opt_str(11)?.unwrap_or_default(),
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
        &format!("SELECT id,ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,classification FROM finding WHERE id=? AND engagement_id={eid}"),
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
                "classification": r.get_opt_str(14)?.unwrap_or_default(),
            }))
        },
    );
    match row {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({"error": "finding introuvable"}))),
    }
}

/// POST /api/findings/:id {status?, classification?} — MUTE le cycle de vie et/ou la classification TLP
/// d'un finding (OPÉRATEUR, fail-closed 403). ISOLATION : n'agit QUE si le finding appartient à
/// l'engagement actif (un id d'un AUTRE engagement -> 404, jamais divulgué). VALIDATION fail-closed :
/// `status` ∈ [`FINDING_STATUSES`] (transition contrainte, tolérant en lecture des valeurs héritées),
/// `classification` ∈ TLP 2.0 (vide autorisé = non classifié). Mutation ATTRIBUÉE + LEDGERISÉE
/// (`console.finding.update`). Au moins un champ requis (400 sinon).
pub(crate) async fn finding_update(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    // engagement_id RÉSOLU (entier, jamais du texte client) -> inliné sans risque d'injection (parité
    // avec les vues). L'existence est vérifiée DANS cet engagement (isolation fail-closed).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let store = app.store();
    let exists = store
        .query_row(
            &format!("SELECT 1 FROM finding WHERE id=? AND engagement_id={eid}"),
            &crate::sql_params![id],
            |_| Ok(()),
        )
        .is_ok();
    if !exists {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not_found", "why": "finding introuvable"}))).into_response();
    }
    let mut new_status: Option<String> = None;
    if let Some(v) = body.get("status") {
        let s = v.as_str().unwrap_or("");
        match norm_finding_status(s) {
            Some(x) => new_status = Some(x),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "bad_status", "why": format!("statut '{s}' invalide ({})", FINDING_STATUSES.join("|"))})),
                )
                    .into_response()
            }
        }
    }
    let mut new_class: Option<String> = None;
    if let Some(v) = body.get("classification") {
        let s = v.as_str().unwrap_or("");
        match norm_tlp(s) {
            Some(x) => new_class = Some(x),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "bad_classification", "why": format!("classification '{s}' invalide (TLP: {})", TLP_CLASSES.join("|"))})),
                )
                    .into_response()
            }
        }
    }
    if new_status.is_none() && new_class.is_none() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_change", "why": "aucun changement fourni (status|classification)"}))).into_response();
    }
    if let Some(s) = &new_status {
        let _ = store.execute(&format!("UPDATE finding SET status=? WHERE id=? AND engagement_id={eid}"), &crate::sql_params![s, id]);
    }
    if let Some(c) = &new_class {
        let _ = store.execute(&format!("UPDATE finding SET classification=? WHERE id=? AND engagement_id={eid}"), &crate::sql_params![c, id]);
    }
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.finding.update", json!({
        "actor": actor, "engagement_id": eid, "finding_id": id,
        "status": new_status, "classification": new_class,
    }));
    (StatusCode::OK, Json(json!({"ok": true, "finding_id": id, "status": new_status, "classification": new_class}))).into_response()
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

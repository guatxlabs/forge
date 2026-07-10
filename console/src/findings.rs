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
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
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
    // Guard SCOPÉ (libéré immédiatement) : ne pas le tenir jusqu'à attribution_login (auto-deadlock).
    let exists = {
        let store = app.store();
        store
            .query_row(
                &format!("SELECT 1 FROM finding WHERE id=? AND engagement_id={eid}"),
                &crate::sql_params![id],
                |_| Ok(()),
            )
            .is_ok()
    };
    if !exists {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not_found", "why": "finding introuvable"}))).into_response();
    }
    // ENTERPRISE PER-ENGAGEMENT RBAC (readiness #14) — checked AFTER the isolation 404 (a cross-tenant id is
    // already 404 via resolve_view_engagement_id => NO_ENGAGEMENT). For a VISIBLE engagement the caller's
    // EFFECTIVE per-engagement role must allow OPERATE; a tenant_viewer is DENIED 403. Community => NO-OP.
    if tenancy::enabled(&app) && !tenancy::can_operate_engagement(&app, &headers, eid) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "engagement_operator_required", "why": "rôle operator requis sur cet engagement (fail-closed)"}))).into_response();
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
    // Le guard `store` (acquis plus haut pour la vérification d'existence) est RE-SCOPÉ ici et LIBÉRÉ avant
    // `attribution_login`/`append_console_ledger` : ces derniers re-verrouillent le MÊME Mutex de connexion
    // quand une session cookie est présente (resolve_session_identity), ce qui AUTO-DEADLOCKerait le thread
    // si le guard restait tenu. (Le premier lock ne se manifestait pas via le repli operator-header, qui
    // court-circuite resolve_session_identity avant tout app.store().)
    {
        let store = app.store();
        if let Some(s) = &new_status {
            let _ = store.execute(&format!("UPDATE finding SET status=? WHERE id=? AND engagement_id={eid}"), &crate::sql_params![s, id]);
        }
        if let Some(c) = &new_class {
            let _ = store.execute(&format!("UPDATE finding SET classification=? WHERE id=? AND engagement_id={eid}"), &crate::sql_params![c, id]);
        }
    }
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.finding.update", json!({
        "actor": actor, "engagement_id": eid, "finding_id": id,
        "status": new_status, "classification": new_class,
    }));
    (StatusCode::OK, Json(json!({"ok": true, "finding_id": id, "status": new_status, "classification": new_class}))).into_response()
}

// =====================================================================================
//  BULK-OPS (#8) — opérations de MASSE sur des findings SÉLECTIONNÉS (ids). TENANT/ENGAGEMENT-SCOPED
//  FAIL-CLOSED : chaque id est confiné à l'engagement ACTIF (`engagement_id={eid}`) — un id d'un AUTRE
//  engagement n'est JAMAIS muté ni exporté (il est simplement SKIPPÉ / absent du résultat, jamais divulgué).
// =====================================================================================

/// Borne dure du nombre d'ids acceptés en une opération (anti-abus / anti-DoS). Au-delà -> 400.
const BULK_MAX_IDS: usize = 1000;

/// Extrait un tableau d'ids ENTIERS depuis `body["ids"]` (dédupliqué, ordre préservé). Chaque élément
/// doit être un entier JSON (`as_i64`) — un élément non entier -> `Err`. Vide ou absent -> `Err`. PURE.
fn parse_ids(body: &Value) -> Result<Vec<i64>, String> {
    let arr = match body.get("ids").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Err("champ 'ids' attendu : tableau d'entiers non vide".into()),
    };
    if arr.is_empty() {
        return Err("aucun finding sélectionné ('ids' vide)".into());
    }
    if arr.len() > BULK_MAX_IDS {
        return Err(format!("trop de findings sélectionnés (max {BULK_MAX_IDS})"));
    }
    let mut out: Vec<i64> = Vec::with_capacity(arr.len());
    for v in arr {
        match v.as_i64() {
            Some(n) => {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
            None => return Err("'ids' doit ne contenir que des entiers".into()),
        }
    }
    Ok(out)
}

/// POST /api/findings/bulk/status {ids:[i64], status} — applique UNE transition de cycle de vie VALIDÉE
/// à un LOT de findings (OPÉRATEUR, fail-closed 403). VALIDATION fail-closed : `status` ∈
/// [`FINDING_STATUSES`] (sinon 400, AUCUNE mutation). ISOLATION : chaque UPDATE est confiné à
/// l'engagement ACTIF (`engagement_id={eid}`) — un id d'un AUTRE engagement (ou inexistant) est SKIPPÉ
/// (0 ligne affectée), jamais muté. Réponse : `{applied:[ids], skipped:[ids], ...}`. ATTRIBUÉ + LEDGERISÉ
/// (`console.finding.bulk_status`).
pub(crate) async fn findings_bulk_status(
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
    // VALIDATION du statut AVANT toute écriture (fail-closed : un statut invalide ne mute rien).
    let status = match body.get("status").and_then(|v| v.as_str()) {
        Some(s) => match norm_finding_status(s) {
            Some(x) => x,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "bad_status", "why": format!("statut '{s}' invalide ({})", FINDING_STATUSES.join("|"))})),
                )
                    .into_response()
            }
        },
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "champ 'status' requis"}))).into_response(),
    };
    let ids = match parse_ids(&body) {
        Ok(v) => v,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": why}))).into_response(),
    };
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // ENTERPRISE PER-ENGAGEMENT RBAC (readiness #14) — the caller's EFFECTIVE role on the target engagement
    // must allow OPERATE (fail-closed). A non-visible engagement resolves to NO_ENGAGEMENT => no effective
    // role => 403 (no rows would be touched anyway). Community (flag OFF) => NO-OP (byte-identical).
    if tenancy::enabled(&app) && !tenancy::can_operate_engagement(&app, &headers, eid) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "engagement_operator_required", "why": "rôle operator requis sur cet engagement (fail-closed)"}))).into_response();
    }
    let (mut applied, mut skipped): (Vec<i64>, Vec<i64>) = (Vec::new(), Vec::new());
    {
        // Le guard `store` est SCOPÉ ce bloc et LIBÉRÉ avant `attribution_login`/`append_console_ledger`
        // (qui re-verrouillent le MÊME Mutex de connexion quand une session cookie est présente) — sinon
        // AUTO-DEADLOCK sur le thread. Même discipline que finding_templates.rs.
        let store = app.store();
        for id in &ids {
            // UPDATE confiné à l'engagement actif : une ligne d'un AUTRE engagement -> 0 affectée -> SKIP.
            // Chaque id est un i64 (parsé de JSON) ; `eid` est un entier résolu (jamais du texte client).
            let n = store
                .execute(
                    &format!("UPDATE finding SET status=? WHERE id=? AND engagement_id={eid}"),
                    &crate::sql_params![status.clone(), *id],
                )
                .unwrap_or(0);
            if n > 0 {
                applied.push(*id);
            } else {
                skipped.push(*id);
            }
        }
    }
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.finding.bulk_status", json!({
        "actor": actor, "engagement_id": eid, "status": status,
        "applied": applied, "skipped": skipped,
    }));
    (StatusCode::OK, Json(json!({
        "ok": true, "status": status, "engagement_id": eid,
        "applied": applied, "skipped": skipped,
        "applied_count": applied.len(), "skipped_count": skipped.len(),
    }))).into_response()
}

/// Échappe un champ pour un CSV RFC-4180 : toujours entre guillemets, les guillemets internes doublés.
/// Neutralise en passant un éventuel préfixe de FORMULA INJECTION (=,+,-,@) en le préfixant d'une
/// apostrophe (défense tableur ; le champ reste lisible). PURE.
fn csv_field(s: &str) -> String {
    let guarded = match s.chars().next() {
        Some('=') | Some('+') | Some('-') | Some('@') => format!("'{s}"),
        _ => s.to_string(),
    };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

/// POST /api/findings/bulk/export {ids:[i64], format:"csv"|"json"} — EXPORTE les findings SÉLECTIONNÉS
/// (CSV ou JSON), SERVEUR. ISOLATION : ne renvoie QUE les findings de l'engagement ACTIF
/// (`engagement_id={eid}`) — un id hors scope est absent du résultat (jamais divulgué). Projection =
/// colonnes de la LISTE (aucune donnée sensible evidence/PoC). Lecture (pas de mutation), scopée à
/// l'engagement comme toute vue ; réservée aux appelants qui voient déjà cet engagement (auth_guard).
pub(crate) async fn findings_bulk_export(
    State(app): State<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    let ids = match parse_ids(&body) {
        Ok(v) => v,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": why}))).into_response(),
    };
    let fmt = body.get("format").and_then(|v| v.as_str()).unwrap_or("json").to_ascii_lowercase();
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // IN-liste d'ENTIERS validés (i64 parsés de JSON) : inlining SANS risque d'injection (parité avec eid).
    let in_list = ids.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    let sql = format!(
        "SELECT id,ts,campaign,target,title,severity,category,mitre,status,classification,tool,run_id \
         FROM finding WHERE engagement_id={eid} AND id IN ({in_list}) ORDER BY id DESC"
    );
    let rows: Vec<Value> = app
        .store()
        .query_lax(&sql, &[], |r| {
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
                "classification": r.get_opt_str(9)?.unwrap_or_default(),
                "tool": r.get_opt_str(10)?.unwrap_or_default(),
                "run_id": r.get_opt_str(11)?.unwrap_or_default(),
            }))
        })
        .unwrap_or_default();

    if fmt == "csv" {
        let cols = ["id", "ts", "campaign", "target", "title", "severity", "category", "mitre", "status", "classification", "tool", "run_id"];
        let mut out = String::new();
        out.push_str(&cols.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
        for row in &rows {
            let line = cols
                .iter()
                .map(|c| {
                    let v = &row[*c];
                    let s = match v {
                        Value::String(s) => s.clone(),
                        Value::Null => String::new(),
                        other => other.to_string(),
                    };
                    csv_field(&s)
                })
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&line);
            out.push_str("\r\n");
        }
        let mut resp = (StatusCode::OK, out).into_response();
        resp.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
        resp.headers_mut().insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=\"forge-findings-selection.csv\""));
        return resp;
    }
    // JSON par défaut : payload structuré (findings sélectionnés + compteur), en pièce jointe.
    let body_str = serde_json::to_string_pretty(&json!({
        "engagement_id": eid, "count": rows.len(), "findings": rows,
    }))
    .unwrap_or_else(|_| "{}".to_string());
    let mut resp = (StatusCode::OK, body_str).into_response();
    resp.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    resp.headers_mut().insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=\"forge-findings-selection.json\""));
    resp
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

// =====================================================================================
//  TESTS — BULK-OPS (#8) : transition de statut de masse (validée, engagement-scopée fail-closed) +
//  export CSV/JSON de la sélection. Les handlers sont exercés via une SESSION (bearer) : cela couvre le
//  chemin resolve_session_identity -> app.store() et GARDE contre l'AUTO-DEADLOCK de re-verrouillage du
//  Mutex de connexion (un guard tenu à travers attribution_login ferait FIGER ces tests, pas juste échouer).
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
        p.push(format!(
            "forge-fbulk-{}-{}-{}.jsonl",
            tag,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
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
    /// Insère un finding dans un engagement donné, renvoie son id.
    fn seed_finding(app: &App, eid: i64, title: &str, status: &str) -> i64 {
        let db = app.db();
        db.execute(
            "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,engagement_id)
             VALUES(datetime('now'),'c','t.example',?,'HIGH','','T1',?,'','','',?)",
            rusqlite::params![title, status, eid],
        )
        .unwrap();
        db.last_insert_rowid()
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
    async fn to_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }
    fn status_of(app: &App, id: i64) -> String {
        let db = app.db();
        db.query_row("SELECT status FROM finding WHERE id=?", [id], |r| r.get(0)).unwrap()
    }
    fn seed_roles(app: &App) -> (String, String) {
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
        }
        let (v, _) = create_session(app, uid_of(app, "vv"));
        let (o, _) = create_session(app, uid_of(app, "oo"));
        (v, o)
    }

    /// parse_ids : entiers dédupliqués, vide/absent/non-entier -> Err, borne max respectée.
    #[test]
    fn parse_ids_rules() {
        assert_eq!(parse_ids(&json!({"ids": [3, 1, 3, 2]})).unwrap(), vec![3, 1, 2]);
        assert!(parse_ids(&json!({"ids": []})).is_err());
        assert!(parse_ids(&json!({})).is_err());
        assert!(parse_ids(&json!({"ids": [1, "x"]})).is_err());
        let big: Vec<i64> = (0..(BULK_MAX_IDS as i64 + 1)).collect();
        assert!(parse_ids(&json!({"ids": big})).is_err(), "au-delà de la borne -> Err");
    }

    /// csv_field : guillemets doublés + garde anti-formule.
    #[test]
    fn csv_field_escapes() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("=SUM(1)"), "\"'=SUM(1)\"");
    }

    /// BULK STATUS : operator-gated (viewer 403), statut invalide -> 400 (rien muté), applique aux ids DE
    /// L'ENGAGEMENT et SKIP ceux d'un autre (isolation fail-closed), ledgerisé. Exercé via SESSION (bearer)
    /// -> couvre resolve_session_identity + garde anti-deadlock (un guard tenu figerait ce test).
    #[tokio::test]
    async fn bulk_status_gated_validated_and_isolated() {
        let led = tmp_ledger("status");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let f1 = seed_finding(&app, 1, "f1", "reported_by_tool");
        let f2 = seed_finding(&app, 1, "f2", "vulnerable");
        let fx = seed_finding(&app, 2, "fx-other-eng", "new"); // AUTRE engagement
        let (vtok, otok) = seed_roles(&app);

        // viewer -> 403, aucune mutation.
        let r = findings_bulk_status(State(app.clone()), peer(), bearer(&vtok), noq(),
            Json(json!({"ids": [f1, f2], "status": "triaged"}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(status_of(&app, f1), "reported_by_tool", "403 ne mute rien");

        // statut invalide -> 400, aucune mutation.
        let r = findings_bulk_status(State(app.clone()), peer(), bearer(&otok),
            Query(HashMap::from([("engagement".into(), "1".into())])),
            Json(json!({"ids": [f1], "status": "BOGUS"}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(status_of(&app, f1), "reported_by_tool", "statut invalide ne mute rien");

        // operator sur engagement #1 : f1,f2 appliqués ; fx (eng #2) SKIPPÉ (isolation), f9999 SKIPPÉ.
        let r = findings_bulk_status(State(app.clone()), peer(), bearer(&otok),
            Query(HashMap::from([("engagement".into(), "1".into())])),
            Json(json!({"ids": [f1, f2, fx, 9999], "status": "confirmed"}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        let applied: Vec<i64> = b["applied"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
        let skipped: Vec<i64> = b["skipped"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
        assert_eq!(applied, vec![f1, f2], "seuls les findings de l'engagement actif sont appliqués");
        assert!(skipped.contains(&fx) && skipped.contains(&9999), "hors-scope + inexistant SKIPPÉS");
        assert_eq!(status_of(&app, f1), "confirmed");
        assert_eq!(status_of(&app, f2), "confirmed");
        assert_eq!(status_of(&app, fx), "new", "le finding d'un AUTRE engagement est INTOUCHÉ");
        assert_eq!(read_ledger_lines(&led).last().unwrap()["kind"], "console.finding.bulk_status");
        let _ = std::fs::remove_file(&led);
    }

    /// BULK EXPORT : ISOLATION — n'exporte QUE les findings de l'engagement actif (un id d'un AUTRE
    /// engagement est ABSENT du résultat). CSV (en-tête + lignes) et JSON (count + findings).
    #[tokio::test]
    async fn bulk_export_is_engagement_scoped() {
        let led = tmp_ledger("export");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let f1 = seed_finding(&app, 1, "in-scope", "new");
        let fx = seed_finding(&app, 2, "other-eng", "new");
        let (_v, otok) = seed_roles(&app);
        let q1 = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));

        // JSON : demande f1 + fx, seul f1 (eng #1) est renvoyé.
        let r = findings_bulk_export(State(app.clone()), bearer(&otok), q1,
            Json(json!({"ids": [f1, fx], "format": "json"}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        assert_eq!(b["count"], 1, "fx (eng #2) est exclu de l'export");
        assert_eq!(b["findings"][0]["id"], f1);

        // CSV : en-tête + 1 ligne de données pour f1.
        let q1b = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let r = findings_bulk_export(State(app.clone()), bearer(&otok), q1b,
            Json(json!({"ids": [f1, fx], "format": "csv"}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let csv = to_text(r).await;
        let lines: Vec<&str> = csv.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "en-tête + 1 ligne (fx exclu)");
        assert!(lines[0].contains("\"status\"") && lines[0].contains("\"classification\""), "en-tête projeté");
        assert!(lines[1].contains("in-scope"), "la ligne exportée est bien f1");
        let _ = std::fs::remove_file(&led);
    }
}

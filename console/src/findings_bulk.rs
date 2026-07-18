// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — BULK-OPS (#8) sur le modele ROUGE (finding) : PURE MOVE extrait de `findings.rs`.
//! Operations de MASSE sur des findings SELECTIONNES (ids) — statut (`findings_bulk_status`), assignation
//! (`findings_bulk_assign`), triage (`findings_bulk_triage`) et export CSV/JSON (`findings_bulk_export`),
//! + les helpers `parse_ids`/`csv_field`. TENANT/ENGAGEMENT-SCOPED FAIL-CLOSED : chaque id est confine a
//! l'engagement ACTIF (`engagement_id=?`) — un id d'un AUTRE engagement n'est JAMAIS mute ni exporte.
//! Reutilise App + les helpers de la racine (check_operator/resolve_view_engagement_id/attribution_login/
//! append_console_ledger + les validateurs de findings.rs : norm_finding_status/norm_triage/resolve_assignee/
//! current_triage/triage_allows) via `use crate::*` ; re-exporte `pub(crate)` a la racine — routes de
//! build_router (`post(findings_bulk_status)`, …) ET tests inline (`super::*`) resolus INCHANGES.
use crate::*;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use crate::store::Param;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

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
    let (mut applied, mut skipped, mut errored): (Vec<i64>, Vec<i64>, Vec<i64>) = (Vec::new(), Vec::new(), Vec::new());
    {
        // Le guard `store` est SCOPÉ ce bloc et LIBÉRÉ avant `attribution_login`/`append_console_ledger`
        // (qui re-verrouillent le MÊME Mutex de connexion quand une session cookie est présente) — sinon
        // AUTO-DEADLOCK sur le thread. Même discipline que finding_templates.rs.

        for id in &ids {
            // UPDATE confiné à l'engagement actif. On CLASSE selon le Result (l'échec n'est PLUS avalé) :
            //   Ok(n>0) = muté ; Ok(0) = id d'un AUTRE engagement / inexistant -> SKIP légitime ;
            //   Err     = ÉCRITURE ÉCHOUÉE (lock/disque/pg) -> `errored`, JAMAIS confondu avec un skip
            //             (sinon un échec DB passerait pour un « non trouvé » et l'appelant croirait à un
            //             succès partiel silencieux). Chaque id est un i64 ; `eid` est un entier résolu.
            match app.store().execute(
                "UPDATE finding SET status=? WHERE id=? AND engagement_id=?",
                &crate::sql_params![status.clone(), *id, eid],
            ) {
                Ok(n) if n > 0 => applied.push(*id),
                Ok(_) => skipped.push(*id),
                Err(_) => errored.push(*id),
            }
        }
    }
    let actor = attribution_login(&app, &headers);
    // Le ledger reflète la RÉALITÉ DB : `applied` ne contient QUE des mutations réellement durables
    // (aucune attestation d'une écriture qui n'a pas eu lieu). `errored` n'est ajouté au ledger QUE s'il
    // y a eu des échecs -> le chemin nominal (aucune erreur) reste BYTE-IDENTIQUE (ledger + réponse).
    let mut detail = json!({
        "actor": actor, "engagement_id": eid, "status": status,
        "applied": applied, "skipped": skipped,
    });
    if !errored.is_empty() {
        detail.as_object_mut().unwrap().insert("errored".into(), json!(errored));
    }
    append_console_ledger(&app, "console.finding.bulk_status", detail);
    // Des écritures ONT ÉCHOUÉ -> 500 + liste `errored`, pour que l'appelant NE prenne PAS un échec
    // partiel pour un succès total (anti false-200). Aucune erreur -> 200 BYTE-IDENTIQUE à avant.
    if !errored.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "ok": false, "error": "db_write_failed", "status": status, "engagement_id": eid,
            "applied": applied, "skipped": skipped, "errored": errored,
            "applied_count": applied.len(), "skipped_count": skipped.len(), "errored_count": errored.len(),
        }))).into_response();
    }
    (StatusCode::OK, Json(json!({
        "ok": true, "status": status, "engagement_id": eid,
        "applied": applied, "skipped": skipped,
        "applied_count": applied.len(), "skipped_count": skipped.len(),
    }))).into_response()
}

/// POST /api/findings/bulk/assign {ids:[i64], assignee:<user_id|null>} — DÉFINIT/EFFACE le propriétaire d'un
/// LOT de findings (OPÉRATEUR, fail-closed 403). VALIDATION fail-closed AVANT toute écriture : l'assigné
/// (resolve_assignee) doit exister + (enterprise) détenir un grant sur l'engagement, sinon 400/403 et AUCUNE
/// mutation. ISOLATION : chaque UPDATE est confiné à l'engagement ACTIF (`engagement_id=?`) — un id d'un AUTRE
/// engagement (ou inexistant) est SKIPPÉ (0 ligne), jamais assigné. On CLASSE selon le Result (Ok(n>0)=applied,
/// Ok(0)=skipped, Err=errored -> 500, jamais confondu avec un skip). ATTRIBUÉ + LEDGERISÉ
/// (`console.finding.bulk_assign`) — `applied` ne reflète QUE des mutations réellement durables.
pub(crate) async fn findings_bulk_assign(
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
    let ids = match parse_ids(&body) {
        Ok(v) => v,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": why}))).into_response(),
    };
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // ENTERPRISE PER-ENGAGEMENT RBAC : l'appelant doit OPÉRER cet engagement (fail-closed). Community => no-op.
    if tenancy::enabled(&app) && !tenancy::can_operate_engagement(&app, &headers, eid) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "engagement_operator_required", "why": "rôle operator requis sur cet engagement (fail-closed)"}))).into_response();
    }
    // VALIDATION de l'assigné AVANT toute écriture (fail-closed : un assigné invalide/hors-grant ne mute rien).
    let assignee = match resolve_assignee(&app, eid, &body) {
        Ok(a) => a,
        Err((s, j)) => return (s, Json(j)).into_response(),
    };
    let (mut applied, mut skipped, mut errored): (Vec<i64>, Vec<i64>, Vec<i64>) = (Vec::new(), Vec::new(), Vec::new());
    {
        // Guard `store` SCOPÉ ce bloc et LIBÉRÉ avant attribution_login/append_console_ledger (anti auto-deadlock).
        for id in &ids {
            let assignee_param = match assignee { Some(u) => Param::Int(u), None => Param::Null };
            match app.store().execute(
                "UPDATE finding SET assignee=? WHERE id=? AND engagement_id=?",
                &[assignee_param, Param::Int(*id), Param::Int(eid)],
            ) {
                Ok(n) if n > 0 => applied.push(*id),
                Ok(_) => skipped.push(*id),
                Err(_) => errored.push(*id),
            }
        }
    }
    let actor = attribution_login(&app, &headers);
    let mut detail = json!({
        "by": actor, "engagement_id": eid, "assignee": assignee,
        "applied": applied, "skipped": skipped,
    });
    if !errored.is_empty() {
        detail.as_object_mut().unwrap().insert("errored".into(), json!(errored));
    }
    append_console_ledger(&app, "console.finding.bulk_assign", detail);
    // NOTIFICATION (triage enrichi) — best-effort, UNIQUEMENT sur une ASSIGNATION (Some) et pour les findings
    // RÉELLEMENT mutés (`applied`). Acteur (user_id + login) résolu UNE fois hors de la boucle (évite N
    // résolutions de session). `notify_assigned_by` saute l'auto-assignation + applique le grant-scope.
    if let Some(uid) = assignee {
        let actor_uid = tenancy::caller_user_id(&app, &headers);
        for id in &applied {
            notifications::notify_assigned_by(&app, actor_uid, &actor, eid, *id, uid);
        }
    }
    if !errored.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "ok": false, "error": "db_write_failed", "assignee": assignee, "engagement_id": eid,
            "applied": applied, "skipped": skipped, "errored": errored,
            "applied_count": applied.len(), "skipped_count": skipped.len(), "errored_count": errored.len(),
        }))).into_response();
    }
    (StatusCode::OK, Json(json!({
        "ok": true, "assignee": assignee, "engagement_id": eid,
        "applied": applied, "skipped": skipped,
        "applied_count": applied.len(), "skipped_count": skipped.len(),
    }))).into_response()
}

/// POST /api/findings/bulk/triage {ids:[i64], to:<state>} — TRANSITIONNE un LOT de findings vers l'état
/// `to` (OPÉRATEUR, fail-closed 403). VALIDATION fail-closed : `to` ∈ [`TRIAGE_STATES`] (sinon 400, AUCUNE
/// mutation). PER-FINDING : chaque finding est transitionné DEPUIS SON état COURANT — la transition est
/// validée finding par finding contre la matrice fermée. ISOLATION : chaque accès est confiné à l'engagement
/// ACTIF (`engagement_id=?`). CLASSEMENT :
///   - id d'un AUTRE engagement / inexistant      -> SKIPPÉ (introuvable) ;
///   - transition ILLÉGALE depuis l'état courant   -> SKIPPÉ (fail-closed, jamais appliqué) ;
///   - transition légale + UPDATE Ok(n>0)          -> APPLIQUÉ ;
///   - UPDATE Err (lock/disque/pg)                 -> ERRORED -> 500 (jamais confondu avec un skip).
///
/// Le `status` de PREUVE n'est JAMAIS touché. ATTRIBUÉ + LEDGERISÉ (`console.finding.bulk_triage`) — `applied`
/// ne reflète QUE des mutations durables ; un event SSE (`FINDINGS_TOPIC`) est émis si ≥1 finding appliqué.
pub(crate) async fn findings_bulk_triage(
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
    // VALIDATION de la cible AVANT toute écriture (fail-closed : un état invalide ne mute rien).
    let to = match body.get("to").and_then(|v| v.as_str()) {
        Some(s) => match norm_triage(s) {
            Some(x) => x,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "bad_triage", "why": format!("état de triage '{s}' invalide ({})", TRIAGE_STATES.join("|"))})),
                )
                    .into_response()
            }
        },
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "champ 'to' requis (état de triage cible)"}))).into_response(),
    };
    let ids = match parse_ids(&body) {
        Ok(v) => v,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": why}))).into_response(),
    };
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // ENTERPRISE PER-ENGAGEMENT RBAC : l'appelant doit OPÉRER cet engagement (fail-closed). Community => no-op.
    if tenancy::enabled(&app) && !tenancy::can_operate_engagement(&app, &headers, eid) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "engagement_operator_required", "why": "rôle operator requis sur cet engagement (fail-closed)"}))).into_response();
    }
    let (mut applied, mut skipped, mut errored): (Vec<i64>, Vec<i64>, Vec<i64>) = (Vec::new(), Vec::new(), Vec::new());
    // (id, from) des transitions RÉELLEMENT durables — sert à composer les notifications per-finding (chaque
    // finding transitionne DEPUIS SON état courant, donc le `from` diffère). Parallèle à `applied`.
    let mut applied_from: Vec<(i64, String)> = Vec::new();
    for id in &ids {
        // État courant PER-FINDING (confiné à l'engagement) : introuvable ou transition illégale -> SKIP.
        let current = match current_triage(&app, *id, eid) {
            Some(c) => c,
            None => { skipped.push(*id); continue; }
        };
        if !triage_allows(&current, &to) {
            skipped.push(*id); // transition illégale depuis l'état courant -> ignorée (fail-closed)
            continue;
        }
        // Guard `store` SCOPÉ à ce statement (temporaire libéré aussitôt) — anti auto-deadlock.
        match app.store().execute(
            "UPDATE finding SET triage=? WHERE id=? AND engagement_id=?",
            &crate::sql_params![to.clone(), *id, eid],
        ) {
            Ok(n) if n > 0 => { applied.push(*id); applied_from.push((*id, current.clone())); }
            Ok(_) => skipped.push(*id),
            Err(_) => errored.push(*id),
        }
    }
    let actor = attribution_login(&app, &headers);
    let mut detail = json!({
        "by": actor, "engagement_id": eid, "to": to,
        "applied": applied, "skipped": skipped,
    });
    if !errored.is_empty() {
        detail.as_object_mut().unwrap().insert("errored".into(), json!(errored));
    }
    append_console_ledger(&app, "console.finding.bulk_triage", detail);
    // EVENT SSE (temps réel) — UNIQUEMENT si ≥1 transition durable (guard `store` déjà libéré).
    if !applied.is_empty() {
        let _ = app.events.send(RunEvent {
            run_id: FINDINGS_TOPIC.to_string(),
            kind: "finding.triage".to_string(),
            payload: json!({"finding_ids": applied, "to": to, "engagement": eid, "by": actor}),
        });
    }
    // NOTIFICATION (triage enrichi) — best-effort : notifie l'ASSIGNÉ de CHAQUE finding réellement transitionné
    // (depuis SON `from`). Acteur (user_id) résolu UNE fois hors de la boucle. Grant-scopé + no-self dans
    // `notify_triage_by`. N'affecte pas les mutations (déjà réussies/ledgerisées).
    if !applied_from.is_empty() {
        let actor_uid = tenancy::caller_user_id(&app, &headers);
        for (id, from) in &applied_from {
            notifications::notify_triage_by(&app, actor_uid, &actor, eid, *id, from, &to);
        }
    }
    if !errored.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "ok": false, "error": "db_write_failed", "to": to, "engagement_id": eid,
            "applied": applied, "skipped": skipped, "errored": errored,
            "applied_count": applied.len(), "skipped_count": skipped.len(), "errored_count": errored.len(),
        }))).into_response();
    }
    (StatusCode::OK, Json(json!({
        "ok": true, "to": to, "engagement_id": eid,
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

// =====================================================================================
//  TESTS — BULK-OPS (#8) : parse_ids/csv_field, transition de statut/assign/triage de masse
//  (validees, engagement-scopees fail-closed) + export CSV/JSON de la selection. Exerces via
//  SESSION (bearer) : garde anti auto-deadlock du re-verrouillage du Mutex de connexion.
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

    fn assignee_of(app: &App, id: i64) -> Option<i64> {
        let db = app.db();
        db.query_row("SELECT assignee FROM finding WHERE id=?", [id], |r| r.get::<_, Option<i64>>(0)).unwrap()
    }
    fn seed_user(app: &App, login: &str, role: &str) -> i64 {
        {
            let db = app.db();
            upsert_user(&db, login, role, &hash_pw("pw")).unwrap();
        }
        uid_of(app, login)
    }
    fn q_eng(eid: &str) -> Query<HashMap<String, String>> {
        Query(HashMap::from([("engagement".to_string(), eid.to_string())]))
    }

    fn triage_of(app: &App, id: i64) -> String {
        let db = app.db();
        db.query_row("SELECT triage FROM finding WHERE id=?", [id], |r| r.get::<_, Option<String>>(0))
            .unwrap()
            .unwrap_or_default()
    }
    /// Force l'état de triage EN BASE (bypass matrice) — SEEDING pour tester des transitions depuis un état
    /// arbitraire. N'utilise PAS l'API (donc pas de validation) : uniquement pour préparer les fixtures.
    fn set_triage(app: &App, id: i64, state: &str) {
        let db = app.db();
        db.execute("UPDATE finding SET triage=? WHERE id=?", rusqlite::params![state, id]).unwrap();
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

    /// BULK STATUS — INJECTION D'ÉCHEC : avec le même trigger, TOUTES les écritures échouent. Le handler
    /// DOIT : (a) 500 (pas un succès total), (b) classer les ids en `errored` (JAMAIS en `skipped`, sinon
    /// un échec DB passerait pour un « non trouvé »), (c) NE PAS muter, (d) si un ledger est écrit, son
    /// `applied` est VIDE (aucune fausse attestation de mutation).
    #[tokio::test]
    async fn bulk_status_db_failure_marks_errored_not_skipped() {
        let led = tmp_ledger("bulk-fail");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let f2 = seed_finding(&app, 1, "f2", "new");
        let (_v, otok) = seed_roles(&app);
        {
            let db = app.db();
            db.execute_batch("CREATE TRIGGER t_block_upd BEFORE UPDATE ON finding BEGIN SELECT RAISE(ABORT,'boom'); END;")
                .unwrap();
        }
        let r = findings_bulk_status(State(app.clone()), peer(), bearer(&otok),
            Query(HashMap::from([("engagement".into(), "1".into())])),
            Json(json!({"ids": [f1, f2], "status": "confirmed"}))).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR, "des écritures échouées -> 500");
        let b = to_json(r).await;
        let errored: Vec<i64> = b["errored"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
        assert!(errored.contains(&f1) && errored.contains(&f2), "ids en ERRORED, pas en skipped");
        assert_eq!(b["applied"].as_array().unwrap().len(), 0, "rien appliqué");
        assert_eq!(status_of(&app, f1), "new", "aucune mutation (échec DB)");
        // Si une entrée ledger a été écrite, elle n'atteste AUCUNE mutation (applied vide).
        if let Some(last) = read_ledger_lines(&led).last() {
            if last["kind"] == "console.finding.bulk_status" {
                assert_eq!(last["detail"]["applied"].as_array().map(|a| a.len()).unwrap_or(0), 0,
                    "le ledger n'atteste aucune mutation qui n'a pas eu lieu");
            }
        }
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

    /// BULK ASSIGN : applique aux ids DE L'ENGAGEMENT et SKIP ceux d'un autre (isolation), ledgerisé.
    #[tokio::test]
    async fn bulk_assign_applies_to_given_ids_only() {
        let led = tmp_ledger("bulk-assign");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let f2 = seed_finding(&app, 1, "f2", "new");
        let fx = seed_finding(&app, 2, "fx-other", "new");
        let (_v, otok) = seed_roles(&app);
        let bob = seed_user(&app, "bob", "viewer");

        let r = findings_bulk_assign(State(app.clone()), peer(), bearer(&otok), q_eng("1"),
            Json(json!({"ids": [f1, f2, fx, 9999], "assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        let applied: Vec<i64> = b["applied"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
        assert_eq!(applied, vec![f1, f2], "seuls les findings de l'engagement actif");
        assert_eq!(assignee_of(&app, f1), Some(bob));
        assert_eq!(assignee_of(&app, f2), Some(bob));
        assert_eq!(assignee_of(&app, fx), None, "finding d'un AUTRE engagement INTOUCHÉ");
        assert_eq!(read_ledger_lines(&led).pop().unwrap()["kind"], "console.finding.bulk_assign");
        let _ = std::fs::remove_file(&led);
    }

    /// BULK : applique UNIQUEMENT les transitions LÉGALES depuis l'état courant de chaque finding ; SKIP les
    /// illégales et les ids d'un autre engagement. Ledgerisé (`console.finding.bulk_triage`).
    #[tokio::test]
    async fn bulk_triage_applies_only_legal() {
        let led = tmp_ledger("bulk-triage");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let f1 = seed_finding(&app, 1, "f1", "new"); // new -> triaging LÉGAL
        let f2 = seed_finding(&app, 1, "f2", "new");
        set_triage(&app, f2, "confirmed"); // confirmed -> triaging ILLÉGAL -> skip
        let fx = seed_finding(&app, 2, "fx", "new"); // AUTRE engagement -> skip
        let (_v, otok) = seed_roles(&app);

        let r = findings_bulk_triage(State(app.clone()), peer(), bearer(&otok), q_eng("1"),
            Json(json!({"ids": [f1, f2, fx, 9999], "to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        let applied: Vec<i64> = b["applied"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
        let skipped: Vec<i64> = b["skipped"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
        assert_eq!(applied, vec![f1], "seule la transition LÉGALE est appliquée");
        assert!(skipped.contains(&f2), "transition illégale (confirmed->triaging) SKIPPÉE");
        assert!(skipped.contains(&fx), "finding d'un AUTRE engagement SKIPPÉ");
        assert_eq!(triage_of(&app, f1), "triaging");
        assert_eq!(triage_of(&app, f2), "confirmed", "illégal -> intouché");
        assert_eq!(triage_of(&app, fx), "new", "cross-engagement -> intouché");
        assert_eq!(read_ledger_lines(&led).pop().unwrap()["kind"], "console.finding.bulk_triage");
        let _ = std::fs::remove_file(&led);
    }
}

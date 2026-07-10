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

pub(crate) async fn findings(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
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
    // KEYSET (seek) pagination — OPT-IN pour les TRÈS GROS sets (P1-4). `?cursor=<opaque>` (jeton signé
    // opaque) ou `?after_id=<int>` (commodité brute) bascule d'OFFSET vers un SEEK sur l'ordre UNIQUE +
    // MONOTONE `id DESC` : les pages profondes ne dégradent plus (pas de skip-scan OFFSET) et, sous inserts
    // concurrents, aucune ligne n'est SAUTÉE ni DUPLIQUÉE à la frontière (là où OFFSET décale). FAIL-CLOSED :
    // un curseur/after_id malformé -> 400 (JAMAIS un scan de table non borné). ABSENCE des DEUX paramètres
    // -> le chemin OFFSET ci-dessous s'exécute BYTE-IDENTIQUE (compat ascendante totale des callers actuels).
    if q.contains_key("cursor") || q.contains_key("after_id") {
        // Borne de seek : `None` = PREMIÈRE page keyset (aucune borne — `cursor=`/`after_id=` VIDES entrent en
        // mode keyset depuis le haut) ; `Some(id)` = seek `id < id`. Un jeton/entier NON VIDE mais INVALIDE ->
        // 400 FAIL-CLOSED (jamais un scan non borné). Le décodage rend un `i64` STRICTEMENT parsé, LIÉ ensuite
        // comme `Param::Int` (aucune interpolation SQL).
        let after: Option<i64> = if let Some(c) = q.get("cursor").filter(|c| !c.is_empty()) {
            match decode_id_cursor(c) {
                Some(v) => Some(v),
                None => {
                    drop(store);
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_cursor", "why": "curseur `cursor` malformé (jeton opaque invalide)"}))).into_response();
                }
            }
        } else if let Some(a) = q.get("after_id").filter(|a| !a.is_empty()) {
            match a.parse::<i64>().ok() {
                Some(v) => Some(v),
                None => {
                    drop(store);
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_cursor", "why": "`after_id` doit être un entier"}))).into_response();
                }
            }
        } else {
            None // `cursor=`/`after_id=` vide -> première page keyset (aucune borne)
        };
        // Tri UNIQUE + MONOTONE `id DESC` : `id` est la clé de tri ET un tiebreaker UNIQUE (PK), donc aucun
        // skip/dupe sur égalité de clé. La borne `id<?` (si présente) est LIÉE en paramètre — le seam traduit
        // `?`->`$n` pour Postgres. `limit` (entier clampé par paginate) inliné comme le chemin OFFSET ; PAS d'OFFSET.
        let (seek_cond, ks_params): (&str, Vec<Param>) = match after {
            Some(id) => {
                let mut p = params.clone();
                p.push(Param::Int(id));
                (" AND id<?", p)
            }
            None => ("", params.clone()),
        };
        let ks_sql = format!(
            "SELECT id,ts,campaign,target,title,severity,category,mitre,status,tool,run_id,classification FROM finding{where_}{seek_cond} ORDER BY id DESC LIMIT {limit}"
        );
        let rows: Vec<Value> = store
            .query_lax(&ks_sql, &ks_params, |r| {
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
        drop(store);
        // next_cursor : renseigné UNIQUEMENT si la page est PLEINE (`len == limit`) — une page partielle
        // signifie qu'il ne reste rien après. Encode l'`id` de la DERNIÈRE ligne (le plus petit, tri DESC),
        // d'où le seek suivant reprend STRICTEMENT après (`id < ce_dernier`). null => fin de pagination.
        let next_cursor = if rows.len() as i64 == limit {
            rows.last().and_then(|v| v["id"].as_i64()).map(encode_id_cursor)
        } else {
            None
        };
        return Json(json!({"total": total, "limit": limit, "next_cursor": next_cursor, "findings": rows})).into_response();
    }
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
    drop(store);
    Json(json!({"total": total, "limit": limit, "offset": offset, "findings": rows})).into_response()
}

pub(crate) async fn finding_detail(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ISOLATION : le détail n'est servi QUE si le finding appartient à l'engagement actif (un id d'un
    // AUTRE engagement -> 404, jamais divulgué). engagement_id résolu (entier) inliné sans risque.
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    
    let row = app.store().query_row(
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
            drop(store);
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
        
        for id in &ids {
            // UPDATE confiné à l'engagement actif : une ligne d'un AUTRE engagement -> 0 affectée -> SKIP.
            // Chaque id est un i64 (parsé de JSON) ; `eid` est un entier résolu (jamais du texte client).
            let n = app.store()
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
    let out: Vec<Value> = app.store()
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
    
    // Agrège depuis les findings (source réelle) + table campaign (métadonnées). Pas de JOIN strict :
    // on liste les campagnes vues côté findings + celles déclarées, avec leurs compteurs.
    // LENIENT: prepare échoué -> Err -> unwrap_or_default -> [] (idem early-return), lignes mal formées ignorées.
    let out: Vec<Value> = app.store()
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
    let out: Vec<Value> = app.store()
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
    let out: Vec<Value> = app.store()
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
//  MATRICE ATT&CK PAR ENGAGEMENT (#P2-1) — grille TACTIQUE × TECHNIQUE (kill-chain), pas une simple
//  liste classée. Réutilise la couverture ENGAGEMENT-SCOPÉE (runrecord : runs=exercé, fired=détecté)
//  et range chaque technique dans sa colonne ATT&CK. Le CATALOGUE de référence (mêmes ids que
//  forge/techniques_data.py) fournit les cellules NON-EXERCÉES (la grille montre le tableau complet,
//  colonne vide = trou de couverture). Toute technique EXERCÉE dont l'id est hors catalogue tombe dans
//  « Unmapped/Other » — JAMAIS silencieusement supprimée (anti fabricated-completeness). Le MTTD est
//  fusionné côté client depuis /api/purple/coverage (best-effort). Aucun schéma, aucune dépendance.
// =====================================================================================

/// Colonnes ATT&CK Enterprise dans l'ordre du kill-chain (les 14 tactiques).
pub(crate) const ATTACK_TACTICS: [&str; 14] = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
];

/// Colonne hors kill-chain : techniques EXERCÉES à l'id inconnu (anti silent-drop).
pub(crate) const ATTACK_TACTIC_OTHER: &str = "Unmapped/Other";

/// Catalogue de référence : (technique_id ATT&CK, tactique). MIROIR FIGÉ de forge/techniques_data.py
/// (champ `mitre` -> `attck_tactic`). T1190 est canoniquement Initial Access (une entrée evasion.* le
/// taggue Defense Evasion — on retient la tactique ATT&CK canonique). Sert de grille de référence
/// (cellules NON-EXERCÉES) ; il n'est PAS engagement-scopé (c'est le tableau ATT&CK, pas des données).
pub(crate) const ATTACK_CATALOG: [(&str, &str); 25] = [
    ("T1046", "Discovery"),
    ("T1059", "Execution"),
    ("T1068", "Privilege Escalation"),
    ("T1110.001", "Credential Access"),
    ("T1190", "Initial Access"),
    ("T1204", "Execution"),
    ("T1204.001", "Execution"),
    ("T1210", "Lateral Movement"),
    ("T1212", "Credential Access"),
    ("T1406", "Discovery"),
    ("T1528", "Credential Access"),
    ("T1539", "Credential Access"),
    ("T1552.001", "Credential Access"),
    ("T1556", "Defense Evasion"),
    ("T1584.001", "Resource Development"),
    ("T1590", "Reconnaissance"),
    ("T1590.002", "Reconnaissance"),
    ("T1590.005", "Reconnaissance"),
    ("T1592.002", "Reconnaissance"),
    ("T1594", "Reconnaissance"),
    ("T1595", "Reconnaissance"),
    ("T1595.002", "Reconnaissance"),
    ("T1595.003", "Reconnaissance"),
    ("T1596", "Reconnaissance"),
    ("T1606", "Credential Access"),
];

/// Résout la tactique ATT&CK d'un id de technique. Ordre : (1) match exact ; (2) sous-technique
/// `T1595.003` -> base `T1595` ; (3) base `T1595` -> première sous-technique cataloguée `T1595.x`.
/// None => id vraiment hors catalogue -> l'appelant le range dans Unmapped/Other (jamais dropé).
pub(crate) fn attack_tactic_for(mitre: &str) -> Option<&'static str> {
    if let Some((_, t)) = ATTACK_CATALOG.iter().find(|(id, _)| *id == mitre) {
        return Some(t);
    }
    if let Some((base, _)) = mitre.split_once('.') {
        if let Some((_, t)) = ATTACK_CATALOG.iter().find(|(id, _)| *id == base) {
            return Some(t);
        }
    } else {
        let prefix = format!("{mitre}.");
        if let Some((_, t)) = ATTACK_CATALOG.iter().find(|(id, _)| id.starts_with(&prefix)) {
            return Some(t);
        }
    }
    None
}

/// Tri des techniques d'une colonne : EXERCÉES d'abord (les cellules « allumées » remontent), puis
/// par id croissant. Ordre déterministe -> rendu stable de la grille.
fn attack_sort_techs(v: &mut [Value]) {
    v.sort_by(|a, b| {
        let ea = a.get("exercised").and_then(|x| x.as_bool()).unwrap_or(false);
        let eb = b.get("exercised").and_then(|x| x.as_bool()).unwrap_or(false);
        eb.cmp(&ea).then_with(|| {
            let ia = a.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let ib = b.get("id").and_then(|x| x.as_str()).unwrap_or("");
            ia.cmp(ib)
        })
    });
}

pub(crate) async fn attack_matrix(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : matrice de l'engagement actif UNIQUEMENT (engagement_id résolu, inliné) — mêmes
    // filtres que /api/coverage, donc AUCUNE fuite cross-engagement/tenant (le catalogue de référence
    // est statique, pas des données d'un autre engagement).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let (sql, args): (String, Vec<String>) = match q.get("campaign") {
        Some(c) => (
            format!("SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' AND engagement_id={eid} AND campaign=? GROUP BY mitre"),
            vec![c.clone()],
        ),
        None => (
            format!("SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' AND engagement_id={eid} GROUP BY mitre"),
            vec![],
        ),
    };
    let params: Vec<Param> = args.iter().map(|s| Param::Text(s.clone())).collect();
    // exercised = techniques réellement présentes dans les run-records de CET engagement.
    let rows: Vec<(String, i64, i64)> = app.store()
        .query_lax(&sql, &params, |row| Ok((row.get_str(0)?, row.get_i64(1)?, row.get_i64(2)?)))
        .unwrap_or_default();
    let mut exercised: HashMap<String, (i64, i64)> = HashMap::new();
    for (m, n, f) in rows {
        let e = exercised.entry(m).or_insert((0, 0));
        e.0 += n;
        e.1 += f;
    }

    // buckets tactique -> [cellules]. Une cellule = {id, exercised, detected(=fired>0), runs, fired}.
    let cell = |id: &str, ex: &HashMap<String, (i64, i64)>| -> Value {
        let (runs, fired) = ex.get(id).copied().unwrap_or((0, 0));
        json!({"id": id, "exercised": runs > 0, "detected": fired > 0, "runs": runs, "fired": fired})
    };
    let mut cells: HashMap<&str, Vec<Value>> = HashMap::new();
    let mut placed: std::collections::HashSet<String> = std::collections::HashSet::new();
    // 1) catalogue de référence -> cellule dans sa tactique (exercée OU non).
    for (id, tactic) in ATTACK_CATALOG.iter() {
        placed.insert((*id).to_string());
        cells.entry(tactic).or_default().push(cell(id, &exercised));
    }
    // 2) techniques EXERCÉES hors catalogue -> tactique résolue (repli sous-/base-technique) ou
    //    Unmapped/Other. On ne dépose JAMAIS silencieusement : chaque id exercé apparaît quelque part.
    let mut extra: Vec<(&String, (i64, i64))> =
        exercised.iter().filter(|(id, _)| !placed.contains(*id)).map(|(id, v)| (id, *v)).collect();
    extra.sort_by(|a, b| a.0.cmp(b.0));
    for (id, (runs, fired)) in extra {
        let tactic = attack_tactic_for(id).unwrap_or(ATTACK_TACTIC_OTHER);
        cells.entry(tactic).or_default().push(json!({
            "id": id, "exercised": runs > 0, "detected": fired > 0, "runs": runs, "fired": fired
        }));
    }

    // sortie ordonnée : les 14 colonnes du kill-chain TOUJOURS présentes (colonne vide = trou visible).
    let mut out: Vec<Value> = Vec::with_capacity(ATTACK_TACTICS.len() + 1);
    for tactic in ATTACK_TACTICS.iter() {
        let mut techs = cells.remove(*tactic).unwrap_or_default();
        attack_sort_techs(&mut techs);
        out.push(json!({"tactic": tactic, "techniques": techs}));
    }
    // Unmapped/Other -> seulement si non vide.
    if let Some(mut techs) = cells.remove(ATTACK_TACTIC_OTHER) {
        if !techs.is_empty() {
            attack_sort_techs(&mut techs);
            out.push(json!({"tactic": ATTACK_TACTIC_OTHER, "techniques": techs}));
        }
    }
    // défense en profondeur : toute clé résiduelle (tactique hors des 14 — ne devrait pas arriver)
    // est émise plutôt que perdue. Garantit qu'aucune technique n'est jamais silencieusement dropée.
    let mut leftover: Vec<&str> = cells.keys().copied().collect();
    leftover.sort_unstable();
    for k in leftover {
        if let Some(mut techs) = cells.remove(k) {
            if !techs.is_empty() {
                attack_sort_techs(&mut techs);
                out.push(json!({"tactic": k, "techniques": techs}));
            }
        }
    }
    Json(json!({"engagement_id": eid, "tactics": out}))
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

    // -------------------------------------------------------------------------------------------
    //  MATRICE ATT&CK (#P2-1)
    // -------------------------------------------------------------------------------------------

    /// attack_tactic_for : match exact, repli sous-technique -> base, repli base -> sous-technique,
    /// et None pour un id vraiment hors catalogue (rangé plus tard dans Unmapped/Other).
    #[test]
    fn attack_tactic_resolution() {
        assert_eq!(attack_tactic_for("T1190"), Some("Initial Access"));
        assert_eq!(attack_tactic_for("T1595.002"), Some("Reconnaissance"));
        // sous-technique inconnue -> tactique de la base cataloguée.
        assert_eq!(attack_tactic_for("T1595.999"), Some("Reconnaissance"));
        // base d'une sous-technique cataloguée -> tactique de la sous-technique.
        assert_eq!(attack_tactic_for("T1584"), Some("Resource Development"));
        assert_eq!(attack_tactic_for("T9999"), None);
    }

    fn seed_runrecord(app: &App, eid: i64, mitre: &str, fired: i64) {
        let db = app.db();
        db.execute(
            "INSERT INTO runrecord(ts,campaign,target,kind,mitre,fired,detail,run_id,engagement_id)
             VALUES(datetime('now'),'c','t.example','k',?,?,'','r',?)",
            rusqlite::params![mitre, fired, eid],
        )
        .unwrap();
    }
    fn col<'a>(v: &'a Value, tactic: &str) -> Option<&'a Vec<Value>> {
        v["tactics"].as_array()?.iter().find(|t| t["tactic"] == tactic)?["techniques"].as_array()
    }
    fn tech<'a>(techs: &'a [Value], id: &str) -> Option<&'a Value> {
        techs.iter().find(|t| t["id"] == id)
    }

    /// MATRICE : grille tactique × technique ENGAGEMENT-SCOPÉE. Vérifie (a) exercé×détecté par colonne,
    /// (b) 14 colonnes kill-chain toujours présentes, (c) cellules NON-EXERCÉES du catalogue, (d) id hors
    /// catalogue -> Unmapped/Other (jamais dropé), (e) AUCUNE fuite d'un autre engagement.
    #[tokio::test]
    async fn attack_matrix_scoped_bucketed_no_drop() {
        let led = tmp_ledger("amx");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        // engagement #1 : T1190 exercé+détecté (2 runs, 1 fired), T1595.002 exercé non détecté (1 run),
        // T9999 exercé+détecté mais id INCONNU (-> Unmapped/Other).
        seed_runrecord(&app, 1, "T1190", 1);
        seed_runrecord(&app, 1, "T1190", 0);
        seed_runrecord(&app, 1, "T1595.002", 0);
        seed_runrecord(&app, 1, "T9999", 1);
        // engagement #2 : T1046 détecté — NE DOIT PAS apparaître comme exercé dans la matrice de #1.
        seed_runrecord(&app, 2, "T1046", 1);

        let q1 = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let resp = attack_matrix(State(app.clone()), HeaderMap::new(), q1).await.into_response();
        let v = to_json(resp).await;
        assert_eq!(v["engagement_id"], 1);

        // (b) 14 colonnes kill-chain présentes + Unmapped/Other (car T9999).
        let names: Vec<String> = v["tactics"].as_array().unwrap().iter().map(|t| t["tactic"].as_str().unwrap().to_string()).collect();
        for t in ATTACK_TACTICS.iter() {
            assert!(names.contains(&t.to_string()), "colonne {t} manquante");
        }
        assert!(names.contains(&ATTACK_TACTIC_OTHER.to_string()), "Unmapped/Other présent car id inconnu exercé");

        // (a) Initial Access : T1190 exercé+détecté, runs=2, fired=1.
        let ia = tech(col(&v, "Initial Access").unwrap(), "T1190").unwrap();
        assert_eq!(ia["exercised"], true);
        assert_eq!(ia["detected"], true);
        assert_eq!(ia["runs"], 2);
        assert_eq!(ia["fired"], 1);

        // Reconnaissance : T1595.002 exercé non détecté ; T1590 catalogué mais NON exercé (cellule grise).
        let recon = col(&v, "Reconnaissance").unwrap();
        let scan = tech(recon, "T1595.002").unwrap();
        assert_eq!(scan["exercised"], true);
        assert_eq!(scan["detected"], false);
        let dns = tech(recon, "T1590").expect("catalogue T1590 présent même non exercé");
        assert_eq!(dns["exercised"], false, "cellule NON-EXERCÉE rendue (pas silencieusement omise)");

        // (e) T1046 (exercé dans #2) apparaît dans #1 comme NON exercé -> aucune fuite cross-engagement.
        let disc = tech(col(&v, "Discovery").unwrap(), "T1046").unwrap();
        assert_eq!(disc["exercised"], false, "donnée de l'engagement #2 NE fuit PAS dans #1");

        // (c/d) T9999 rangé dans Unmapped/Other (jamais dropé).
        let other = col(&v, ATTACK_TACTIC_OTHER).unwrap();
        assert!(tech(other, "T9999").is_some(), "id hors catalogue préservé");

        let _ = std::fs::remove_file(&led);
    }

    // -------------------------------------------------------------------------------------------
    //  KEYSET / CURSOR PAGINATION (#P1-4) — seek pour très gros sets, offset intact
    // -------------------------------------------------------------------------------------------

    /// Petit helper : lit la liste d'ids d'une page de findings.
    fn ids_of(b: &Value) -> Vec<i64> {
        b["findings"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect()
    }

    /// (a) COUVERTURE : paginer TOUT le set via `?cursor` rend CHAQUE ligne EXACTEMENT une fois, dans le
    /// même ordre que le set complet trié (`id DESC`) — zéro trou, zéro doublon — et `next_cursor` devient
    /// null à la fin.
    #[tokio::test]
    async fn keyset_full_coverage_no_gaps_no_dupes() {
        let led = tmp_ledger("ks-cov");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let mut all: Vec<i64> = Vec::new();
        for i in 0..25 {
            all.push(seed_finding(&app, 1, &format!("f{i}"), "new"));
        }
        all.sort_unstable();
        let expected: Vec<i64> = all.iter().rev().cloned().collect(); // id DESC = ordre de référence

        let mut got: Vec<i64> = Vec::new();
        // Première page : `cursor=""` (vide) entre en mode keyset depuis le haut.
        let mut cursor: String = String::new();
        let mut guard = 0;
        loop {
            guard += 1;
            assert!(guard < 100, "boucle de pagination non bornée");
            let qp = HashMap::from([
                ("engagement".to_string(), "1".to_string()),
                ("limit".to_string(), "7".to_string()),
                ("cursor".to_string(), cursor.clone()),
            ]);
            let resp = findings(State(app.clone()), HeaderMap::new(), Query(qp)).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let b = to_json(resp).await;
            let page = ids_of(&b);
            assert!(page.len() <= 7, "la page respecte le limit");
            got.extend(page);
            match b["next_cursor"].as_str() {
                Some(c) => cursor = c.to_string(),
                None => break,
            }
        }
        assert_eq!(got, expected, "keyset couvre chaque ligne exactement une fois, dans l'ordre id DESC");
        let mut uniq = got.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), got.len(), "aucun doublon sur l'ensemble des pages");
        let _ = std::fs::remove_file(&led);
    }

    /// (b) STABILITÉ SOUS INSERT CONCURRENT : après avoir lu la page 1, insérer de NOUVELLES lignes (ids
    /// plus grands) NE fait PAS sauter/dupliquer les lignes d'origine via keyset — alors que le chemin
    /// OFFSET, lui, DÉRAILLE (fenêtre décalée -> skip + dupe).
    #[tokio::test]
    async fn keyset_stable_under_concurrent_insert() {
        let led = tmp_ledger("ks-conc");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let mut orig: Vec<i64> = Vec::new();
        for i in 0..10 {
            orig.push(seed_finding(&app, 1, &format!("o{i}"), "new"));
        }

        // Page 1 (limit 5, `cursor=""` -> mode keyset depuis le haut) — le client voit les 5 ids les plus hauts.
        let q1 = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("limit".to_string(), "5".to_string()),
            ("cursor".to_string(), String::new()),
        ]));
        let b1 = to_json(findings(State(app.clone()), HeaderMap::new(), q1).await).await;
        let p1 = ids_of(&b1);
        assert_eq!(p1.len(), 5);
        let cur = b1["next_cursor"].as_str().expect("page pleine -> next_cursor présent").to_string();

        // Insert concurrent de 3 lignes (ids strictement plus grands que tous les orig).
        for i in 0..3 {
            seed_finding(&app, 1, &format!("n{i}"), "new");
        }

        // Page 2 via CURSEUR — reprend STRICTEMENT après la position, insensible aux inserts.
        let mut q2m = HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("limit".to_string(), "5".to_string()),
        ]);
        q2m.insert("cursor".to_string(), cur);
        let b2 = to_json(findings(State(app.clone()), HeaderMap::new(), Query(q2m)).await).await;
        let p2 = ids_of(&b2);

        let mut seen = p1.clone();
        seen.extend(p2.iter().cloned());
        let mut seen_sorted = seen.clone();
        seen_sorted.sort_unstable();
        let mut orig_sorted = orig.clone();
        orig_sorted.sort_unstable();
        assert_eq!(seen_sorted, orig_sorted, "keyset : les 10 lignes d'origine couvertes exactement une fois malgré les inserts");
        let mut u = seen.clone();
        u.sort_unstable();
        u.dedup();
        assert_eq!(u.len(), seen.len(), "keyset : aucun doublon sous insert concurrent");

        // CONTRASTE : OFFSET page 2 (offset=5) APRÈS les inserts déraille (skip + dupe) -> union != orig.
        let qo = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("limit".to_string(), "5".to_string()),
            ("offset".to_string(), "5".to_string()),
        ]));
        let bo = to_json(findings(State(app.clone()), HeaderMap::new(), qo).await).await;
        let po = ids_of(&bo);
        let mut off_union = p1.clone();
        off_union.extend(po.iter().cloned());
        off_union.sort_unstable();
        assert_ne!(off_union, orig_sorted, "OFFSET saute/duplique sous insert concurrent (ce que keyset évite)");
        let _ = std::fs::remove_file(&led);
    }

    /// (c) FAIL-CLOSED : un curseur/after_id malformé -> 400 `bad_cursor` (JAMAIS un scan complet). Un
    /// curseur VALIDE et un `after_id` entier restent 200.
    #[tokio::test]
    async fn keyset_malformed_cursor_is_400() {
        use base64::Engine as _;
        let led = tmp_ledger("ks-bad");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let id = seed_finding(&app, 1, "f", "new");

        let enc = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        // base64 invalide, mauvaise version, entier non parsable, pas de préfixe, entier vide.
        let bads = vec![
            "****not-base64****".to_string(),
            enc("f2:5"),
            enc("f1:abc"),
            enc("nope"),
            enc("f1:"),
        ];
        for bad in &bads {
            let q = Query(HashMap::from([
                ("engagement".to_string(), "1".to_string()),
                ("cursor".to_string(), bad.clone()),
            ]));
            let resp = findings(State(app.clone()), HeaderMap::new(), q).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "curseur malformé '{bad}' -> 400");
            let b = to_json(resp).await;
            assert_eq!(b["error"], "bad_cursor");
        }
        // after_id non entier -> 400 également.
        let q = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("after_id".to_string(), "not-an-int".to_string()),
        ]));
        assert_eq!(findings(State(app.clone()), HeaderMap::new(), q).await.status(), StatusCode::BAD_REQUEST);

        // Curseur VALIDE (encode l'id existant + 1 pour capter la ligne) -> 200 + la ligne.
        let good = super::encode_id_cursor(id + 1);
        let q = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("cursor".to_string(), good),
        ]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(ids_of(&b), vec![id], "curseur valide -> seek correct");

        // after_id entier -> 200.
        let q = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("after_id".to_string(), (id + 1).to_string()),
        ]));
        assert_eq!(findings(State(app.clone()), HeaderMap::new(), q).await.status(), StatusCode::OK);
        let _ = std::fs::remove_file(&led);
    }

    /// (d) OFFSET INCHANGÉ : sans cursor/after_id, la forme de réponse reste `{total,limit,offset,findings}`
    /// (avec `offset`, SANS `next_cursor`) — compat ascendante byte-identique. Le chemin keyset, lui, expose
    /// `next_cursor` et PAS `offset`.
    #[tokio::test]
    async fn offset_path_shape_unchanged() {
        let led = tmp_ledger("ks-off");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        for i in 0..3 {
            seed_finding(&app, 1, &format!("f{i}"), "new");
        }
        // Chemin OFFSET (par défaut) : garde `offset`, PAS de `next_cursor`.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert!(b.get("offset").is_some(), "offset path conserve `offset`");
        assert!(b.get("next_cursor").is_none(), "offset path n'ajoute PAS `next_cursor`");
        assert_eq!(b["findings"].as_array().unwrap().len(), 3);

        // Chemin KEYSET : expose `next_cursor` (clé présente, ici null car page partielle), PAS `offset`.
        let q = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("after_id".to_string(), "999999".to_string()),
        ]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert!(b.get("next_cursor").is_some(), "keyset path expose la clé `next_cursor`");
        assert!(b["next_cursor"].is_null(), "page partielle -> next_cursor null");
        assert!(b.get("offset").is_none(), "keyset path n'expose PAS `offset`");
        let _ = std::fs::remove_file(&led);
    }
}

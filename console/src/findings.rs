// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — CRUD + TRIAGE/ASSIGN du modele ROUGE (finding). Liste (`findings`, keyset/offset),
//! detail (`finding_detail`), mutation cycle de vie + classification (`finding_update`), OWNERSHIP
//! (`findings_assignable`/`resolve_assignee`/`finding_assign`) et WORKFLOW DE TRIAGE (machine a etats
//! fermee : `finding_triage`/`current_triage`/`illegal_transition` + flux SSE `finding_events`). Toutes
//! les vues/mutations sont ISOLEES par engagement actif (`resolve_view_engagement_id`, fail-closed) — un
//! engagement ne voit/mute JAMAIS les donnees d'un autre. Les BULK-OPS et les vues de REPORTING ont ete
//! extraites (PURE MOVE) vers `findings_bulk` / `findings_report`. Reutilise App + les helpers de la
//! racine via `use crate::*`, re-exporte par `pub(crate) use crate::findings::*` — routes de build_router
//! (`get(findings)`, …) ET tests inline (`super::*`) resolus INCHANGES.
use crate::*;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use crate::store::Param;
use futures_util::Stream;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::broadcast;

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

// =====================================================================================
//  TRIAGE WORKFLOW — machine à états GOUVERNÉE du CYCLE DE TRIAGE, distincte du `status` (statut de
//  PREUVE : tested/vulnerable/…). Les DEUX champs sont INDÉPENDANTS : une transition de triage n'altère
//  JAMAIS `status`, et réciproquement. La matrice de transitions est FERMÉE (fail-closed) : tout couple
//  (from, to) hors table est REFUSÉ. UNIQUE source de vérité serveur ; le client en a un miroir UX mais
//  le serveur RE-VALIDE systématiquement.
// =====================================================================================

/// États du cycle de TRIAGE d'un finding — jeu FERMÉ. `new` est l'état initial (DEFAULT en base ; les
/// findings hérités sont backfillés à `new` par la migration). Distinct de [`FINDING_STATUSES`].
pub(crate) const TRIAGE_STATES: [&str; 7] =
    ["new", "triaging", "confirmed", "false_positive", "duplicate", "resolved", "reopened"];

/// MATRICE FERMÉE des transitions AUTORISÉES `(from -> &[to])`. TABLE UNIQUE, revue en un coup d'œil :
///   new            -> triaging | false_positive | duplicate
///   triaging       -> confirmed | false_positive | duplicate
///   confirmed      -> resolved | false_positive
///   false_positive -> triaging            (réouverture)
///   duplicate      -> triaging            (réouverture)
///   resolved       -> reopened
///   reopened       -> triaging | confirmed | resolved
/// Tout couple ABSENT de cette table est REFUSÉ (fail-closed). Le endpoint de transition valide
/// `(current, to) ∈ matrice` AVANT toute écriture.
pub(crate) const TRIAGE_TRANSITIONS: &[(&str, &[&str])] = &[
    ("new", &["triaging", "false_positive", "duplicate"]),
    ("triaging", &["confirmed", "false_positive", "duplicate"]),
    ("confirmed", &["resolved", "false_positive"]),
    ("false_positive", &["triaging"]),
    ("duplicate", &["triaging"]),
    ("resolved", &["reopened"]),
    ("reopened", &["triaging", "confirmed", "resolved"]),
];

/// Normalise (trim + casse insensible) + valide un état de triage. `None` si hors [`TRIAGE_STATES`]. PURE.
pub(crate) fn norm_triage(s: &str) -> Option<String> {
    let low = s.trim().to_ascii_lowercase();
    if TRIAGE_STATES.contains(&low.as_str()) { Some(low) } else { None }
}

/// Les états ATTEIGNABLES depuis `from` selon la matrice fermée (slice VIDE si `from` inconnu — fail-closed :
/// un état hérité/hors-vocabulaire n'autorise AUCUNE transition). PURE.
pub(crate) fn triage_next(from: &str) -> &'static [&'static str] {
    for (f, tos) in TRIAGE_TRANSITIONS {
        if *f == from {
            return tos;
        }
    }
    &[]
}

/// Vrai ssi `(from -> to)` ∈ matrice. Fail-closed (états inconnus => false). PURE.
pub(crate) fn triage_allows(from: &str, to: &str) -> bool {
    triage_next(from).contains(&to)
}

/// `run_id` synthétique porté par les events de TRIAGE sur le bus SSE partagé (`App.events`, typé pour les
/// runs). Hors de l'espace des vrais run_id (préfixe `__`, cf. `presence::PRESENCE_TOPIC`) : `run_sse` et
/// `presence_events` filtrent sur LEUR topic et n'y toucheront jamais, et `finding_events` ne remonte QUE
/// les events dont `run_id == FINDINGS_TOPIC` (topics disjoints). Réutilise le bus existant (pas de 2e canal).
pub(crate) const FINDINGS_TOPIC: &str = "__findings__";

/// Cadence (s) du heartbeat/keep-alive du flux SSE de triage (parité avec le heartbeat de présence).
const FINDINGS_SSE_TICK_SECS: u64 = 20;

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
    // `engagement_id` (entier RÉSOLU) est LIÉ en Param (plus d'interpolation de valeur dans le SQL) : la
    // 1re condition -> 1er placeholder, donc `eid` est le PREMIER Param, avant les filtres optionnels.
    let (mut conds, mut params): (Vec<String>, Vec<Param>) = (vec!["engagement_id=?".into()], vec![Param::Int(eid)]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?".into()); params.push(Param::Text(c.clone())); }
    if let Some(s) = q.get("severity") { conds.push("severity=?".into()); params.push(Param::Text(s.clone())); }
    if let Some(s) = q.get("status") { conds.push("status=?".into()); params.push(Param::Text(s.clone())); }
    if let Some(t) = q.get("target") { conds.push("target=?".into()); params.push(Param::Text(t.clone())); }
    if let Some(m) = q.get("mitre") { conds.push("mitre=?".into()); params.push(Param::Text(m.clone())); }
    if let Some(r) = q.get("run_id") { conds.push("run_id=?".into()); params.push(Param::Text(r.clone())); }
    // OWNERSHIP FILTER (P1-4) : `?assignee=unassigned` -> findings SANS propriétaire (assignee IS NULL) ;
    // `?assignee=<user_id>` -> findings de CE propriétaire (valeur LIÉE en Param — pas d'interpolation, pas
    // d'injection). Une valeur non entière et non "unassigned" est IGNORÉE (best-effort, comme les autres
    // filtres) plutôt que de renvoyer une erreur — les saved-views peuvent ainsi filtrer par owner sans risque.
    if let Some(a) = q.get("assignee") {
        if a == "unassigned" {
            conds.push("assignee IS NULL".into());
        } else if let Ok(uid) = a.parse::<i64>() {
            conds.push("assignee=?".into());
            params.push(Param::Int(uid));
        }
    }
    // TRIAGE FILTER : `?triage=<state>` -> findings dans CET état de triage. La valeur est NORMALISÉE +
    // VALIDÉE contre la matrice ([`TRIAGE_STATES`]) puis LIÉE en Param (pas d'interpolation, pas d'injection).
    // Une valeur hors vocabulaire est IGNORÉE (best-effort, comme le filtre assignee) — les saved-views
    // filtrent par état sans risque.
    if let Some(t) = q.get("triage") {
        if let Some(norm) = norm_triage(t) {
            conds.push("triage=?".into());
            params.push(Param::Text(norm));
        }
    }
    let where_ = format!(" WHERE {}", conds.join(" AND "));
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
        let (seek_cond, mut ks_params): (&str, Vec<Param>) = match after {
            Some(id) => {
                let mut p = params.clone();
                p.push(Param::Int(id));
                (" AND id<?", p)
            }
            None => ("", params.clone()),
        };
        // `limit` (entier clampé par paginate) LIÉ en dernier Param (placeholder final `LIMIT ?`).
        ks_params.push(Param::Int(limit));
        // `assignee` (user_id, nullable) + login résolu via sous-requête CORRÉLÉE (pas de JOIN -> aucune
        // ambiguïté sur `id`, ORDER/LIMIT/keyset INCHANGÉS). Portable SQLite+PG. NULL -> assignee null +
        // assignee_login null (non assigné).
        let ks_sql = format!(
            "SELECT id,ts,campaign,target,title,severity,category,mitre,status,tool,run_id,classification,assignee,(SELECT login FROM users u WHERE u.id=finding.assignee),triage FROM finding{where_}{seek_cond} ORDER BY id DESC LIMIT ?"
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
                    "assignee": r.get_opt_i64(12)?,
                    "assignee_login": r.get_opt_str(13)?,
                    "triage": r.get_opt_str(14)?.unwrap_or_else(|| "new".into()),
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
    // `limit`/`offset` (entiers clampés par paginate) LIÉS en derniers Params (placeholders finaux).
    let mut off_params = params.clone();
    off_params.push(Param::Int(limit));
    off_params.push(Param::Int(offset));
    let sql = format!(
        "SELECT id,ts,campaign,target,title,severity,category,mitre,status,tool,run_id,classification,assignee,(SELECT login FROM users u WHERE u.id=finding.assignee),triage FROM finding{where_} ORDER BY id DESC LIMIT ? OFFSET ?"
    );
    // requête typée : `id` est un entier (rows_to_json le rendrait vide en le lisant comme String).
    // LENIENT (query_lax): un prepare échoué -> Err -> unwrap_or_default -> findings vides + total, à
    // l'identique de l'early-return d'avant ; une ligne malformée est ignorée (filter_map(ok)).
    let rows: Vec<Value> = store
        .query_lax(&sql, &off_params, |r| {
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
                "assignee": r.get_opt_i64(12)?,
                "assignee_login": r.get_opt_str(13)?,
                "triage": r.get_opt_str(14)?.unwrap_or_else(|| "new".into()),
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
        // `engagement_id` (entier résolu) LIÉ en Param — plus d'interpolation de valeur (défense anti-régression).
        "SELECT id,ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,classification,assignee,(SELECT login FROM users u WHERE u.id=finding.assignee),triage FROM finding WHERE id=? AND engagement_id=?",
        &crate::sql_params![id, eid],
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
                "assignee": r.get_opt_i64(15)?,
                "assignee_login": r.get_opt_str(16)?,
                "triage": r.get_opt_str(17)?.unwrap_or_else(|| "new".into()),
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
                "SELECT 1 FROM finding WHERE id=? AND engagement_id=?",
                &crate::sql_params![id, eid],
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
    // ÉCRITURE ATOMIQUE + FAIL-CLOSED : un SEUL UPDATE porte les colonnes optionnelles (status et/ou
    // classification), donc AUCUN état partiel possible sur le chemin d'erreur. On MATCHE le Result :
    // si l'écriture ÉCHOUE (lock/disque plein/erreur Postgres) -> 500 typé et on N'ÉCRIT PAS le ledger,
    // sinon la piste tamper-evident attesterait une mutation qui n'a jamais atteint la base
    // (divergence ledger↔DB, et l'appelant recevrait un faux `ok:true`). Le guard `store` est libéré à
    // la fermeture du bloc AVANT attribution_login/append_console_ledger (anti auto-deadlock inchangé).
    {
        let store = app.store();
        let mut sets: Vec<&str> = Vec::new();
        let mut params: Vec<Param> = Vec::new();
        if let Some(s) = &new_status { sets.push("status=?"); params.push(Param::Text(s.clone())); }
        if let Some(c) = &new_class { sets.push("classification=?"); params.push(Param::Text(c.clone())); }
        params.push(Param::Int(id)); // borne WHERE (>=1 SET garanti : no_change déjà rejeté 400 plus haut)
        params.push(Param::Int(eid)); // `engagement_id` LIÉ (plus d'interpolation de valeur) — placeholder final
        let sql = format!("UPDATE finding SET {} WHERE id=? AND engagement_id=?", sets.join(", "));
        if let Err(e) = store.execute(&sql, &params) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "db_write_failed", "why": format!("écriture du finding échouée: {e}")}))).into_response();
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
//  OWNERSHIP (readiness P1-4) — pointeur LÉGER d'assignation (`finding.assignee` = user_id) + bulk-assign.
//  PAS un moteur de workflow : juste « qui possède ce finding ». GRANT-SCOPED des DEUX CÔTÉS (enterprise) :
//  l'appelant doit OPÉRER l'engagement ET l'assigné (non-null) doit avoir un grant sur CE MÊME engagement.
// =====================================================================================

/// GET /api/findings/assignable — l'ensemble des utilisateurs ASSIGNABLES sur l'engagement ACTIF (le jeu
/// légitime de propriétaires pour le sélecteur d'assignation). Alimente l'UI d'assignation ; l'action
/// d'assigner reste OPÉRATEUR (gate serveur). ENTERPRISE : UNIQUEMENT les users détenant un grant
/// (engagement-spécifique OU tenant-wide) sur l'engagement actif — le MÊME jeu que `resolve_assignee` valide
/// (fail-closed : caller sans grant -> NO_ENGAGEMENT -> liste vide). COMMUNITY : tous les users actifs (aucun
/// grant n'existe). Divulgation minimale (id + login) nécessaire à la fonctionnalité. Réponse
/// `{engagement_id, users:[{id,login}]}`.
pub(crate) async fn findings_assignable(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // `tenancy::enabled` acquiert LUI-MÊME le Mutex de connexion (settings) — l'appeler AVANT de tenir le
    // guard `store` ci-dessous, sinon auto-deadlock du thread (le même verrou repris de façon réentrante).
    let ent = tenancy::enabled(&app);
    let store = app.store();
    let users: Vec<Value> = if ent {
        // Union grant engagement-spécifique + grant tenant-wide (tenant résolu par sous-requête). `eid` LIÉ.
        store
            .query_lax(
                "SELECT u.id, u.login FROM users u WHERE u.disabled=0 AND (
                    EXISTS(SELECT 1 FROM engagement_grant g WHERE g.user_id=u.id AND g.engagement_id=?)
                    OR EXISTS(SELECT 1 FROM tenant_grant tg WHERE tg.user_id=u.id AND tg.tenant_id=(SELECT tenant_id FROM engagement WHERE id=?))
                 ) ORDER BY u.login",
                &crate::sql_params![eid, eid],
                |r| Ok(json!({"id": r.get_i64(0)?, "login": r.get_str(1)?})),
            )
            .unwrap_or_default()
    } else {
        store
            .query_lax(
                "SELECT id, login FROM users WHERE disabled=0 ORDER BY login",
                &[],
                |r| Ok(json!({"id": r.get_i64(0)?, "login": r.get_str(1)?})),
            )
            .unwrap_or_default()
    };
    drop(store);
    Json(json!({"engagement_id": eid, "users": users})).into_response()
}

/// Parse + VALIDE le champ `assignee` d'une requête d'assignation contre l'engagement `eid`, GRANT-SCOPÉ
/// fail-closed. Retourne `Ok(Some(uid))` (assigner) / `Ok(None)` (désassigner) ou `Err((status, json))` prêt
/// à renvoyer. Règles :
///   - clé ABSENTE          -> 400 (l'assignation doit être EXPLICITE) ;
///   - `null` JSON          -> `Ok(None)` — EFFACE le propriétaire (désassignation) ;
///   - entier JSON user_id   -> l'utilisateur doit EXISTER et ne pas être désactivé (sinon 400) ET, quand la
///     tenancy est ACTIVÉE, détenir un grant sur `eid` (sinon 403 — on n'assigne qu'à quelqu'un réellement sur
///     l'engagement). En COMMUNITY le contrôle de grant est un NO-OP (aucun grant n'existe) : seule l'existence
///     est requise (permissif/sain, comme le reste) ;
///   - toute autre valeur    -> 400.
pub(crate) fn resolve_assignee(app: &App, eid: i64, body: &Value) -> Result<Option<i64>, (StatusCode, Value)> {
    let v = match body.get("assignee") {
        Some(v) => v,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                json!({"error": "bad_request", "why": "champ 'assignee' requis (user_id entier, ou null pour désassigner)"}),
            ))
        }
    };
    if v.is_null() {
        return Ok(None); // désassignation explicite
    }
    let uid = match v.as_i64() {
        Some(n) => n,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                json!({"error": "bad_assignee", "why": "'assignee' doit être un entier (user_id) ou null"}),
            ))
        }
    };
    // L'assigné doit EXISTER et être actif (sain en community ET enterprise — jamais un propriétaire fantôme).
    let exists = {
        let store = app.store();
        store
            .query_row("SELECT 1 FROM users WHERE id=? AND disabled=0", &crate::sql_params![uid], |_| Ok(()))
            .is_ok()
    };
    if !exists {
        return Err((
            StatusCode::BAD_REQUEST,
            json!({"error": "unknown_assignee", "why": format!("utilisateur {uid} inconnu ou désactivé")}),
        ));
    }
    // ENTERPRISE : l'assigné doit AUSSI être sur CET engagement (grant-scopé des deux côtés). Community => no-op.
    if tenancy::enabled(app) && !tenancy::user_has_engagement_grant(app, uid, eid) {
        return Err((
            StatusCode::FORBIDDEN,
            json!({"error": "assignee_not_on_engagement", "why": format!("l'utilisateur {uid} n'a pas de grant sur cet engagement (fail-closed)")}),
        ));
    }
    Ok(Some(uid))
}

/// POST /api/findings/:id/assign {assignee: <user_id|null>} — DÉFINIT/EFFACE le propriétaire (assignee) d'un
/// finding (OPÉRATEUR, fail-closed 403). ISOLATION : n'agit QUE sur un finding de l'engagement ACTIF (un id
/// d'un AUTRE engagement -> 404, jamais divulgué). GRANT-SCOPÉ DES DEUX CÔTÉS (enterprise) : l'appelant doit
/// OPÉRER l'engagement ET l'assigné (non-null) doit détenir un grant sur ce MÊME engagement (resolve_assignee).
/// Écriture MATCHÉE -> 500 sur Err AVANT le ledger (pas de fausse attestation) ; ledger `console.finding.assign`
/// {finding_id, assignee, by} UNIQUEMENT en cas de succès.
pub(crate) async fn finding_assign(
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
    // engagement_id RÉSOLU (entier, jamais du texte client). L'existence est vérifiée DANS cet engagement
    // (isolation fail-closed) — un id d'un AUTRE engagement est 404, jamais assigné (pas de cross-engagement).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let exists = {
        let store = app.store();
        store
            .query_row("SELECT 1 FROM finding WHERE id=? AND engagement_id=?", &crate::sql_params![id, eid], |_| Ok(()))
            .is_ok()
    };
    if !exists {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not_found", "why": "finding introuvable"}))).into_response();
    }
    // ENTERPRISE PER-ENGAGEMENT RBAC : l'appelant doit OPÉRER cet engagement (fail-closed). Community => no-op.
    if tenancy::enabled(&app) && !tenancy::can_operate_engagement(&app, &headers, eid) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "engagement_operator_required", "why": "rôle operator requis sur cet engagement (fail-closed)"}))).into_response();
    }
    let assignee = match resolve_assignee(&app, eid, &body) {
        Ok(a) => a,
        Err((s, j)) => return (s, Json(j)).into_response(),
    };
    // ÉCRITURE FAIL-CLOSED : le guard `store` est SCOPÉ + LIBÉRÉ avant attribution_login/append_console_ledger
    // (anti auto-deadlock). On MATCHE le Result : échec (lock/disque/pg) -> 500 typé, SANS ledger (pas de
    // divergence ledger↔DB). `assignee` LIÉ en Param (Int ou Null) — aucune interpolation de valeur.
    {
        let store = app.store();
        let assignee_param = match assignee { Some(u) => Param::Int(u), None => Param::Null };
        if let Err(e) = store.execute(
            "UPDATE finding SET assignee=? WHERE id=? AND engagement_id=?",
            &[assignee_param, Param::Int(id), Param::Int(eid)],
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "db_write_failed", "why": format!("écriture du finding échouée: {e}")}))).into_response();
        }
    }
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.finding.assign", json!({
        "by": actor, "engagement_id": eid, "finding_id": id, "assignee": assignee,
    }));
    // NOTIFICATION (triage enrichi) — best-effort, APRÈS un succès durable + ledger (guard `store` libéré ;
    // aucun verrou tenu à travers l'émission/SSE). UNIQUEMENT sur une ASSIGNATION (Some) — jamais sur une
    // désassignation. `notify_assigned` saute l'auto-assignation + applique le grant-scope. Un échec d'insert
    // de notif NE casse NI ne fausse cette assignation (déjà réussie/ledgerisée) et NE double PAS le ledger.
    if let Some(uid) = assignee {
        notifications::notify_assigned(&app, &headers, eid, id, uid);
    }
    (StatusCode::OK, Json(json!({"ok": true, "finding_id": id, "assignee": assignee}))).into_response()
}

// =====================================================================================
//  TRIAGE WORKFLOW — transition GOUVERNÉE du cycle de triage (machine à états fermée fail-closed). Le
//  champ `triage` est INDÉPENDANT de `status` (statut de PREUVE) : une transition n'écrit QUE `triage`.
//  Les DEUX endpoints (single + bulk) sont OPÉRATEUR + engagement-scopés fail-closed, ledgerisés, et
//  émettent un event SSE (`FINDINGS_TOPIC`) — les autres opérateurs voient la transition EN DIRECT.
// =====================================================================================

/// Lit l'état de triage COURANT d'un finding CONFINÉ à l'engagement `eid` (sert aussi de test d'existence :
/// `None` = introuvable / cross-engagement). Un `triage` NULL hérité est normalisé en `new` (état initial).
/// Guard `store` scopé + libéré immédiatement (anti auto-deadlock). PURE lecture.
pub(crate) fn current_triage(app: &App, id: i64, eid: i64) -> Option<String> {
    let store = app.store();
    // `.ok()` : Err (row introuvable / cross-engagement) -> None (test d'existence fail-closed).
    store
        .query_row(
            "SELECT triage FROM finding WHERE id=? AND engagement_id=?",
            &crate::sql_params![id, eid],
            |r| Ok(r.get_opt_str(0)?.unwrap_or_else(|| "new".into())),
        )
        .ok()
}

/// Réponse 409 CONFLICT normalisée pour une transition ILLÉGALE : rappelle l'état COURANT + les états
/// ATTEIGNABLES (dérivés de la matrice fermée) pour guider l'appelant. PURE.
fn illegal_transition(current: &str, to: &str) -> (StatusCode, Value) {
    (
        StatusCode::CONFLICT,
        json!({
            "error": "illegal_transition",
            "why": format!("transition de triage '{current}' -> '{to}' non autorisée (matrice fermée)"),
            "current": current,
            "allowed": triage_next(current),
        }),
    )
}

/// POST /api/findings/:id/triage {to:<state>} — TRANSITIONNE le cycle de triage d'UN finding (OPÉRATEUR,
/// fail-closed 403). ISOLATION : n'agit QUE sur un finding de l'engagement ACTIF (un id d'un AUTRE
/// engagement -> 404, jamais divulgué). VALIDATION fail-closed : `to` ∈ [`TRIAGE_STATES`] (sinon 400) ET
/// `(current, to) ∈ TRIAGE_TRANSITIONS` (sinon 409, AUCUNE écriture — la réponse rappelle l'état courant +
/// les états atteignables). Le `status` de PREUVE n'est JAMAIS touché (champs indépendants). Écriture MATCHÉE
/// -> 500 sur Err AVANT le ledger (pas de fausse attestation) ; sur succès : ledger `console.finding.triage`
/// {finding_id, from, to, by} PUIS event SSE sur `FINDINGS_TOPIC` (temps réel).
pub(crate) async fn finding_triage(
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
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // ÉTAT COURANT + existence DANS l'engagement (fail-closed) : un id d'un AUTRE engagement -> 404.
    let current = match current_triage(&app, id, eid) {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "not_found", "why": "finding introuvable"}))).into_response(),
    };
    // ENTERPRISE PER-ENGAGEMENT RBAC : l'appelant doit OPÉRER cet engagement (fail-closed). Community => no-op.
    if tenancy::enabled(&app) && !tenancy::can_operate_engagement(&app, &headers, eid) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "engagement_operator_required", "why": "rôle operator requis sur cet engagement (fail-closed)"}))).into_response();
    }
    // Cible VALIDÉE contre le vocabulaire (400 si absente/hors jeu) — AVANT le check de matrice.
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
    // MATRICE FERMÉE : transition non autorisée -> 409, AUCUNE écriture (fail-closed, server-authoritative).
    if !triage_allows(&current, &to) {
        let (s, j) = illegal_transition(&current, &to);
        return (s, Json(j)).into_response();
    }
    // ÉCRITURE FAIL-CLOSED : guard `store` scopé + libéré avant attribution/ledger (anti auto-deadlock). On
    // MATCHE le Result -> 500 SANS ledger si l'écriture échoue (pas de divergence ledger↔DB). `to` LIÉ en Param.
    {
        let store = app.store();
        if let Err(e) = store.execute(
            "UPDATE finding SET triage=? WHERE id=? AND engagement_id=?",
            &crate::sql_params![to.clone(), id, eid],
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "db_write_failed", "why": format!("écriture du finding échouée: {e}")}))).into_response();
        }
    }
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.finding.triage", json!({
        "by": actor, "engagement_id": eid, "finding_id": id, "from": current, "to": to,
    }));
    // EVENT SSE (temps réel) — émis APRÈS un succès durable, guard `store` déjà libéré (aucun verrou tenu à
    // travers l'envoi : `broadcast::Sender::send` ne re-verrouille pas le Mutex de connexion -> pas de deadlock).
    let _ = app.events.send(RunEvent {
        run_id: FINDINGS_TOPIC.to_string(),
        kind: "finding.triage".to_string(),
        payload: json!({"finding_id": id, "from": current, "to": to, "engagement": eid, "by": actor}),
    });
    // NOTIFICATION (triage enrichi) — best-effort : notifie l'ASSIGNÉ du finding (s'il existe et != acteur)
    // de la transition. Grant-scopée + no-self dans `notify_triage`. N'affecte pas la mutation (déjà réussie).
    notifications::notify_triage(&app, &headers, eid, id, &current, &to);
    (StatusCode::OK, Json(json!({"ok": true, "finding_id": id, "from": current, "to": to}))).into_response()
}

/// GET /api/findings/events — flux SSE des transitions de TRIAGE (temps réel : les autres opérateurs voient
/// la transition en direct). Réutilise le bus `App.events` (topic `FINDINGS_TOPIC`) — même patron que
/// `presence_events`, sans registre ni guard (aucune présence à suivre). Chaque event = signal « une
/// transition a eu lieu -> re-fetch la liste ». Un `sync` initial amorce le client ; un débordement de buffer
/// (Lagged) demande une resync ; la fermeture du bus termine le flux.
/// M5 — décision de FORWARD d'un event `FINDINGS_TOPIC` vers un abonné SSE : `true` SEULEMENT si l'`engagement`
/// porté par le payload est VISIBLE au caller (`tenancy::engagement_visible`). Payload sans champ `engagement`
/// entier (ne devrait jamais arriver sur ce topic) => `false` (fail-closed). Community (tenancy off) =>
/// `engagement_visible` renvoie toujours `true` (no-op, comportement byte-identique au single-tenant).
fn finding_event_visible_for(app: &App, headers: &HeaderMap, payload: &Value) -> bool {
    payload
        .get("engagement")
        .and_then(|v| v.as_i64())
        .map(|eid| tenancy::engagement_visible(app, headers, eid))
        .unwrap_or(false)
}

pub(crate) async fn finding_events(State(app): State<App>, headers: HeaderMap) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = app.events.subscribe();
    let mut ticker = tokio::time::interval(Duration::from_secs(FINDINGS_SSE_TICK_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // M5 — SCOPING PER-TENANT : `app` + `headers` sont FILÉS dans l'état de l'unfold (comme le `guard` de
    // `presence_events`) pour que chaque event bus soit re-vérifié contre la visibilité d'engagement du caller.
    // Community (tenancy off) => `engagement_visible` renvoie true (no-op, comportement byte-identique).
    let stream = futures_util::stream::unfold(
        (rx, ticker, false, app, headers),
        move |(mut rx, mut ticker, mut synced, app, headers)| async move {
            if !synced {
                synced = true;
                let ev = Event::default()
                    .event("finding")
                    .json_data(json!({"event": "sync"}))
                    .unwrap_or_else(|_| Event::default().comment("sync"));
                return Some((Ok(ev), (rx, ticker, synced, app, headers)));
            }
            loop {
                tokio::select! {
                    r = rx.recv() => match r {
                        Ok(ev) if ev.run_id == FINDINGS_TOPIC => {
                            // FAIL-CLOSED : on ne forwarde l'event QUE si son `engagement` est visible au caller.
                            if !finding_event_visible_for(&app, &headers, &ev.payload) {
                                continue; // event d'un tenant/engagement non visible — jamais divulgué
                            }
                            let ev2 = Event::default()
                                .event("finding")
                                .json_data(&ev.payload)
                                .unwrap_or_else(|_| Event::default().comment("finding"));
                            return Some((Ok(ev2), (rx, ticker, synced, app, headers)));
                        }
                        Ok(_) => continue, // event d'un run / de présence — pas du triage
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            let ev = Event::default()
                                .event("finding")
                                .json_data(json!({"event": "resync"}))
                                .unwrap_or_else(|_| Event::default().comment("resync"));
                            return Some((Ok(ev), (rx, ticker, synced, app, headers)));
                        }
                        Err(broadcast::error::RecvError::Closed) => return None,
                    },
                    _ = ticker.tick() => {
                        return Some((Ok(Event::default().comment("hb")), (rx, ticker, synced, app, headers)));
                    }
                }
            }
        },
    );
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(FINDINGS_SSE_TICK_SECS)).text("keep-alive"))
}

// =====================================================================================
//  TESTS — concern 1 (CRUD + ownership/assign + triage workflow + keyset/offset pagination).
//  Exerces via SESSION (bearer) : couvre resolve_session_identity -> app.store() et garde contre
//  l'AUTO-DEADLOCK de re-verrouillage du Mutex de connexion (un guard tenu figerait ces tests).
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

    /// FINDING UPDATE — INJECTION D'ÉCHEC : un TRIGGER `BEFORE UPDATE ... RAISE(ABORT)` fait ÉCHOUER
    /// l'écriture (les SELECT d'existence passent). Le handler DOIT alors : (a) renvoyer 500 typé
    /// `db_write_failed` (PAS un faux `ok:true`), (b) N'ÉCRIRE AUCUNE entrée au ledger (anti divergence
    /// ledger↔DB — la piste tamper-evident ne doit jamais attester une mutation qui n'a pas eu lieu),
    /// (c) laisser le finding INTOUCHÉ. Régression directe du bug audité (write avalé -> faux 200 + ledger).
    #[tokio::test]
    async fn finding_update_db_failure_500_and_no_ledger() {
        let led = tmp_ledger("upd-fail");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);
        // Injecte un échec d'ÉCRITURE : tout UPDATE de finding est ABORTé (les lectures restent OK).
        {
            let db = app.db();
            db.execute_batch("CREATE TRIGGER t_block_upd BEFORE UPDATE ON finding BEGIN SELECT RAISE(ABORT,'boom'); END;")
                .unwrap();
        }
        let before = read_ledger_lines(&led).len();
        let r = finding_update(State(app.clone()), peer(), bearer(&otok), Path(f1),
            Query(HashMap::from([("engagement".into(), "1".into())])),
            Json(json!({"status": "confirmed", "classification": "GREEN"}))).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR, "écriture échouée -> 500");
        let b = to_json(r).await;
        assert_eq!(b["error"], "db_write_failed", "erreur typée (enveloppe existante)");
        assert_eq!(status_of(&app, f1), "new", "aucune mutation appliquée (état intouché)");
        assert_eq!(read_ledger_lines(&led).len(), before, "un échec d'écriture NE ledgerise PAS");
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

    /// BOUND engagement_id — le filtre d'isolation `engagement_id=?` LIÉ (Param) rend EXACTEMENT les mêmes
    /// résultats que l'ancien `engagement_id={eid}` inliné : la liste `findings` d'un engagement ne contient
    /// QUE ses propres findings (aucun cross-engagement), et `finding_detail` 404 un id d'un AUTRE engagement.
    /// Prouve la neutralité comportementale de la conversion valeur-interpolée -> valeur-liée (Tâche B).
    #[tokio::test]
    async fn engagement_id_binding_isolates_identically() {
        let led = tmp_ledger("eid-bind");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let a1 = seed_finding(&app, 1, "a1", "new");
        let _a2 = seed_finding(&app, 1, "a2", "new");
        let b1 = seed_finding(&app, 2, "b1", "new");

        // liste engagement 1 -> exactement SES 2 findings, aucun de l'engagement 2.
        let q1 = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let body = to_json(findings(State(app.clone()), HeaderMap::new(), q1).await).await;
        assert_eq!(body["total"], 2, "engagement 1 voit ses 2 findings (bound eid)");
        let titles: Vec<String> = body["findings"].as_array().unwrap().iter()
            .map(|f| f["title"].as_str().unwrap_or("").to_string()).collect();
        assert!(titles.contains(&"a1".to_string()) && titles.contains(&"a2".to_string()), "ses findings présents");
        assert!(!titles.contains(&"b1".to_string()), "AUCUN finding cross-engagement (isolation liée)");

        // detail : b1 (engagement 2) est INVISIBLE depuis l'engagement 1 -> 404 via engagement_id=? lié.
        let q1b = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let r = finding_detail(State(app.clone()), HeaderMap::new(), Path(b1), q1b).await.into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "id d'un AUTRE engagement -> 404 (isolation liée)");
        // detail : a1 (engagement 1) est VISIBLE depuis l'engagement 1.
        let q1c = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let r = finding_detail(State(app.clone()), HeaderMap::new(), Path(a1), q1c).await.into_response();
        assert_eq!(r.status(), StatusCode::OK, "propre finding visible (bound eid)");
        let _ = std::fs::remove_file(&led);
    }

    // -------------------------------------------------------------------------------------------
    //  OWNERSHIP (P1-4) — assign / bulk-assign : grant-scopé, isolé par engagement, ledgerisé
    // -------------------------------------------------------------------------------------------

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

    /// ASSIGN (community) : operator assigne un finding à un user (persistance colonne + ledger
    /// `console.finding.assign`), puis DÉSASSIGNE (assignee:null). Viewer -> 403 (aucune mutation).
    #[tokio::test]
    async fn assign_persists_unassign_and_ledgered() {
        let led = tmp_ledger("assign");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (vtok, otok) = seed_roles(&app);
        let bob = seed_user(&app, "bob", "viewer");

        // viewer -> 403, aucune mutation.
        let r = finding_assign(State(app.clone()), peer(), bearer(&vtok), Path(f1), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(assignee_of(&app, f1), None, "403 ne mute rien");

        // operator assigne à bob.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        assert_eq!(b["assignee"], bob);
        assert_eq!(assignee_of(&app, f1), Some(bob), "assignation persistée");
        let last = read_ledger_lines(&led).pop().unwrap();
        assert_eq!(last["kind"], "console.finding.assign");
        assert_eq!(last["detail"]["assignee"], bob);
        assert_eq!(last["detail"]["finding_id"], f1);

        // détail : assignee + login résolu.
        let d = finding_detail(State(app.clone()), HeaderMap::new(), Path(f1), q_eng("1")).await.into_response();
        let dj = to_json(d).await;
        assert_eq!(dj["assignee"], bob);
        assert_eq!(dj["assignee_login"], "bob");

        // désassignation (null).
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": null}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(assignee_of(&app, f1), None, "désassigné");
        let _ = std::fs::remove_file(&led);
    }

    /// ASSIGN : champ absent -> 400 ; assigné inconnu -> 400 (aucune mutation).
    #[tokio::test]
    async fn assign_bad_and_unknown_user_400() {
        let led = tmp_ledger("assign-bad");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);

        // champ 'assignee' absent -> 400.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        // user inexistant -> 400, aucune mutation.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": 99999}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(assignee_of(&app, f1), None, "assigné inconnu ne mute rien");
        let _ = std::fs::remove_file(&led);
    }

    /// ASSIGN : ISOLATION — un finding d'un AUTRE engagement -> 404 (jamais assigné, pas de cross-engagement).
    #[tokio::test]
    async fn assign_cross_engagement_is_404() {
        let led = tmp_ledger("assign-xeng");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let fx = seed_finding(&app, 2, "fx", "new"); // AUTRE engagement
        let (_v, otok) = seed_roles(&app);
        let bob = seed_user(&app, "bob", "viewer");

        // engagement actif #1, cible fx (#2) -> 404, intouché.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(fx), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "id d'un AUTRE engagement -> 404");
        assert_eq!(assignee_of(&app, fx), None, "finding cross-engagement INTOUCHÉ");
        let _ = std::fs::remove_file(&led);
    }

    /// ASSIGN — INJECTION D'ÉCHEC : trigger BEFORE UPDATE ABORT -> 500 `db_write_failed`, AUCUN ledger,
    /// finding intouché (régression anti write-avalé).
    #[tokio::test]
    async fn assign_db_failure_500_and_no_ledger() {
        let led = tmp_ledger("assign-fail");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);
        let bob = seed_user(&app, "bob", "viewer");
        {
            let db = app.db();
            db.execute_batch("CREATE TRIGGER t_block_upd BEFORE UPDATE ON finding BEGIN SELECT RAISE(ABORT,'boom'); END;")
                .unwrap();
        }
        let before = read_ledger_lines(&led).len();
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(to_json(r).await["error"], "db_write_failed");
        assert_eq!(assignee_of(&app, f1), None, "aucune mutation");
        assert_eq!(read_ledger_lines(&led).len(), before, "un échec d'écriture NE ledgerise PAS");
        let _ = std::fs::remove_file(&led);
    }

    /// FILTER : `?assignee=<uid>` rend les findings de ce propriétaire ; `?assignee=unassigned` rend les
    /// non assignés — chacun le bon sous-ensemble.
    #[tokio::test]
    async fn filter_by_assignee() {
        let led = tmp_ledger("filter-assignee");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let f2 = seed_finding(&app, 1, "f2", "new");
        let _f3 = seed_finding(&app, 1, "f3", "new"); // reste non assigné
        let (_v, otok) = seed_roles(&app);
        let bob = seed_user(&app, "bob", "viewer");

        // assigne f1 et f2 à bob.
        for f in [f1, f2] {
            let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f), q_eng("1"),
                Json(json!({"assignee": bob}))).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        // filtre par bob -> f1,f2.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("assignee".to_string(), bob.to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        let ids: Vec<i64> = b["findings"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert_eq!(b["total"], 2);
        assert!(ids.contains(&f1) && ids.contains(&f2) && !ids.contains(&_f3), "filtre owner exact");
        // filtre unassigned -> seulement f3.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("assignee".to_string(), "unassigned".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(b["total"], 1, "un seul non assigné");
        assert_eq!(b["findings"][0]["id"], _f3);
        let _ = std::fs::remove_file(&led);
    }

    fn seed_tenant_grant(app: &App, uid: i64, tid: i64, role: &str) {
        let db = app.db();
        db.execute(
            "INSERT INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,?,?,datetime('now'))",
            rusqlite::params![uid, tid, role],
        )
        .unwrap();
    }

    /// ENTERPRISE (tenancy ON) : GRANT-SCOPÉ DES DEUX CÔTÉS. L'appelant operator (grant tenant) peut assigner
    /// à un user QUI A un grant sur l'engagement, mais est REJETÉ (403) pour un user SANS grant. Prouve que
    /// `resolve_assignee` gate l'assigné sur l'engagement (on n'assigne qu'à quelqu'un réellement dessus).
    #[tokio::test]
    async fn assign_grant_scoped_enterprise() {
        let led = tmp_ledger("assign-ent");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A"); // tenant_id défaut = 1
        let f1 = seed_finding(&app, 1, "f1", "new");
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
        }
        // caller operator (rôle global operator + grant tenant_operator sur tenant 1 => voit+opère eng 1).
        let (_v, otok) = seed_roles(&app);
        seed_tenant_grant(&app, uid_of(&app, "oo"), 1, "tenant_operator");
        // assigné AVEC grant sur le tenant 1.
        let insider = seed_user(&app, "insider", "viewer");
        seed_tenant_grant(&app, insider, 1, "tenant_viewer");
        // assigné SANS aucun grant.
        let outsider = seed_user(&app, "outsider", "viewer");

        // assigné hors-grant -> 403, aucune mutation.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": outsider}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "assigné sans grant sur l'engagement -> 403");
        assert_eq!(assignee_of(&app, f1), None, "hors-grant ne mute rien");

        // assigné avec grant -> OK.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": insider}))).await;
        assert_eq!(r.status(), StatusCode::OK, "assigné avec grant sur l'engagement -> OK");
        assert_eq!(assignee_of(&app, f1), Some(insider));
        let _ = std::fs::remove_file(&led);
    }

    /// ENTERPRISE : un operator SANS grant sur l'engagement ne peut PAS assigner (can_operate_engagement
    /// fail-closed -> 403), même s'il est operator global.
    #[tokio::test]
    async fn assign_caller_without_engagement_grant_403() {
        let led = tmp_ledger("assign-nocaller");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
        }
        let (_v, otok) = seed_roles(&app); // operator global, MAIS aucun grant tenant/engagement
        let bob = seed_user(&app, "bob", "viewer");
        seed_tenant_grant(&app, bob, 1, "tenant_viewer");

        // sans grant, l'engagement #1 n'est même pas visible -> 404 (isolation) plutôt que d'exposer.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert!(
            r.status() == StatusCode::NOT_FOUND || r.status() == StatusCode::FORBIDDEN,
            "operator sans grant sur l'engagement ne peut pas assigner (404/403 fail-closed), got {}",
            r.status()
        );
        assert_eq!(assignee_of(&app, f1), None, "aucune mutation");
        let _ = std::fs::remove_file(&led);
    }

    /// M5 — SSE `finding_events` SCOPÉ PAR TENANT (fuite de métadonnées cross-tenant fermée). Le filtre
    /// `finding_event_visible_for` ne forwarde un event de triage que si son `engagement` est visible au
    /// caller. Community (tenancy off) => tout passe (no-op). Enterprise => un caller granté SEULEMENT sur le
    /// tenant A NE reçoit PAS les events du tenant B (from/to/by/finding_id d'un autre tenant jamais divulgués).
    #[tokio::test]
    async fn finding_events_scoped_per_tenant() {
        let led = tmp_ledger("sse-scope");
        let app = test_app(&led);
        // engagement 1 => tenant 1 (défaut) ; engagement 2 => tenant 2 (explicite).
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        {
            let db = app.db();
            db.execute("UPDATE engagement SET tenant_id=2 WHERE id=2", []).unwrap();
        }
        let (vtok, otok) = seed_roles(&app);
        let ho = bearer(&otok);
        // operator granté UNIQUEMENT sur le tenant 1.
        seed_tenant_grant(&app, uid_of(&app, "oo"), 1, "tenant_operator");

        let ev_a = json!({"finding_id": 10, "from": "new", "to": "triaging", "engagement": 1, "by": "oo"});
        let ev_b = json!({"finding_id": 20, "from": "new", "to": "confirmed", "engagement": 2, "by": "mallory"});

        // COMMUNITY (tenancy off) : les deux events passent (no-op, byte-identique single-tenant).
        assert!(finding_event_visible_for(&app, &ho, &ev_a), "community forwarde tenant 1");
        assert!(finding_event_visible_for(&app, &ho, &ev_b), "community forwarde tenant 2 (no-op)");

        // ENTERPRISE (tenancy on) : seul le tenant 1 (visible) passe ; le tenant 2 est DROPPÉ.
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
        }
        assert!(finding_event_visible_for(&app, &ho, &ev_a), "tenant granté (A) reçoit ses propres events");
        assert!(!finding_event_visible_for(&app, &ho, &ev_b), "tenant NON granté (B) ne fuit PAS cross-tenant");

        // Payload sans `engagement` => fail-closed (droppé).
        assert!(!finding_event_visible_for(&app, &ho, &json!({"finding_id": 30, "to": "triaging"})),
            "payload sans engagement -> droppé (fail-closed)");

        // Un caller SANS aucun grant (viewer vv) ne voit RIEN (deny-by-default).
        let hv = bearer(&vtok);
        assert!(!finding_event_visible_for(&app, &hv, &ev_a), "sans grant -> aucun event visible");
        assert!(!finding_event_visible_for(&app, &hv, &ev_b), "sans grant -> aucun event visible");
        let _ = std::fs::remove_file(&led);
    }

    /// ASSIGNABLE (community) : liste les users actifs assignables + NE DEADLOCK PAS (le handler calcule
    /// tenancy::enabled AVANT de tenir le guard `store`, sinon reprise réentrante du Mutex -> figé).
    #[tokio::test]
    async fn assignable_lists_users_no_deadlock() {
        let led = tmp_ledger("assignable");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_user(&app, "bob", "viewer");
        seed_user(&app, "carol", "viewer");
        let r = findings_assignable(State(app.clone()), HeaderMap::new(), q_eng("1")).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        let logins: Vec<String> = b["users"].as_array().unwrap().iter().map(|u| u["login"].as_str().unwrap().to_string()).collect();
        assert!(logins.contains(&"bob".to_string()) && logins.contains(&"carol".to_string()), "users assignables listés");
        let _ = std::fs::remove_file(&led);
    }

    // -------------------------------------------------------------------------------------------
    //  TRIAGE WORKFLOW — machine à états gouvernée : transition légale (persist + ledger + SSE),
    //  transition illégale (409, aucune écriture), isolation, write-failure, indépendance vs `status`.
    // -------------------------------------------------------------------------------------------

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

    /// PURE : la matrice fermée autorise EXACTEMENT les transitions spécifiées, rien d'autre (fail-closed).
    #[test]
    fn triage_matrix_is_closed() {
        assert!(triage_allows("new", "triaging"));
        assert!(triage_allows("new", "false_positive"));
        assert!(triage_allows("new", "duplicate"));
        assert!(triage_allows("triaging", "confirmed"));
        assert!(triage_allows("confirmed", "resolved"));
        assert!(triage_allows("confirmed", "false_positive"));
        assert!(triage_allows("false_positive", "triaging"));
        assert!(triage_allows("duplicate", "triaging"));
        assert!(triage_allows("resolved", "reopened"));
        assert!(triage_allows("reopened", "triaging"));
        assert!(triage_allows("reopened", "confirmed"));
        assert!(triage_allows("reopened", "resolved"));
        // Rejets représentatifs (fail-closed) :
        assert!(!triage_allows("new", "resolved"), "raccourci interdit");
        assert!(!triage_allows("new", "confirmed"), "saut d'étape interdit");
        assert!(!triage_allows("resolved", "confirmed"), "resolved -> confirmed interdit");
        assert!(!triage_allows("confirmed", "duplicate"), "confirmed -> duplicate interdit");
        assert!(!triage_allows("new", "new"), "self-transition interdite");
        assert!(!triage_allows("bogus", "triaging"), "état inconnu -> aucune transition");
    }

    /// LEGAL (community) : operator transitionne new -> triaging. Persistance colonne `triage`, `status` de
    /// PREUVE INCHANGÉ (indépendance), ledger `console.finding.triage` {from,to}, ET event SSE sur le bus.
    /// Viewer -> 403 (aucune mutation).
    #[tokio::test]
    async fn triage_legal_persists_ledgered_and_sse() {
        let led = tmp_ledger("triage-ok");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "triaged"); // status de PREUVE = "triaged"
        let (vtok, otok) = seed_roles(&app);

        // viewer -> 403, aucune mutation.
        let r = finding_triage(State(app.clone()), peer(), bearer(&vtok), Path(f1), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(triage_of(&app, f1), "new", "403 ne mute rien");

        // s'abonne au bus AVANT la transition (broadcast : seuls les messages postérieurs sont reçus).
        let mut rx = app.events.subscribe();

        // operator : new -> triaging.
        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        assert_eq!(b["from"], "new");
        assert_eq!(b["to"], "triaging");
        assert_eq!(triage_of(&app, f1), "triaging", "triage persisté");
        assert_eq!(status_of(&app, f1), "triaged", "le status de PREUVE est INDÉPENDANT — jamais touché");

        // ledger : console.finding.triage {from:new, to:triaging}.
        let last = read_ledger_lines(&led).pop().unwrap();
        assert_eq!(last["kind"], "console.finding.triage");
        assert_eq!(last["detail"]["from"], "new");
        assert_eq!(last["detail"]["to"], "triaging");
        assert_eq!(last["detail"]["finding_id"], f1);

        // event SSE émis sur le bus (topic FINDINGS_TOPIC, kind finding.triage).
        let ev = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await
            .expect("event SSE reçu avant timeout").expect("event SSE valide");
        assert_eq!(ev.run_id, FINDINGS_TOPIC);
        assert_eq!(ev.kind, "finding.triage");
        assert_eq!(ev.payload["to"], "triaging");
        assert_eq!(ev.payload["finding_id"], f1);

        // détail : triage exposé.
        let d = finding_detail(State(app.clone()), HeaderMap::new(), Path(f1), q_eng("1")).await.into_response();
        assert_eq!(to_json(d).await["triage"], "triaging");
        let _ = std::fs::remove_file(&led);
    }

    /// ILLEGAL : new -> resolved (hors matrice) -> 409, AUCUNE écriture, AUCUN ledger. La réponse rappelle
    /// l'état courant + les états atteignables (guidage). Le `status` de PREUVE reste intact.
    #[tokio::test]
    async fn triage_illegal_409_no_write_no_ledger() {
        let led = tmp_ledger("triage-illegal");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);
        let before = read_ledger_lines(&led).len();

        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "resolved"}))).await;
        assert_eq!(r.status(), StatusCode::CONFLICT, "transition illégale -> 409");
        let b = to_json(r).await;
        assert_eq!(b["error"], "illegal_transition");
        assert_eq!(b["current"], "new");
        let allowed: Vec<String> = b["allowed"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(allowed.contains(&"triaging".to_string()) && !allowed.contains(&"resolved".to_string()), "états atteignables rappelés");
        assert_eq!(triage_of(&app, f1), "new", "409 ne mute rien");
        assert_eq!(read_ledger_lines(&led).len(), before, "une transition illégale NE ledgerise PAS");
        let _ = std::fs::remove_file(&led);
    }

    /// BAD TARGET : `to` absent -> 400 ; `to` hors vocabulaire -> 400 (aucune mutation, aucun ledger).
    #[tokio::test]
    async fn triage_bad_target_400() {
        let led = tmp_ledger("triage-bad");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);

        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "'to' absent -> 400");
        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "bogus"}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "'to' hors vocabulaire -> 400");
        assert_eq!(triage_of(&app, f1), "new", "aucune mutation");
        let _ = std::fs::remove_file(&led);
    }

    /// ISOLATION : un finding d'un AUTRE engagement -> 404 (jamais transitionné, pas de cross-engagement).
    #[tokio::test]
    async fn triage_cross_engagement_404() {
        let led = tmp_ledger("triage-xeng");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let fx = seed_finding(&app, 2, "fx", "new"); // AUTRE engagement
        let (_v, otok) = seed_roles(&app);

        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(fx), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "id d'un AUTRE engagement -> 404");
        assert_eq!(triage_of(&app, fx), "new", "finding cross-engagement INTOUCHÉ");
        let _ = std::fs::remove_file(&led);
    }

    /// INJECTION D'ÉCHEC : trigger BEFORE UPDATE ABORT -> 500 `db_write_failed`, AUCUN ledger, triage intouché.
    #[tokio::test]
    async fn triage_db_failure_500_and_no_ledger() {
        let led = tmp_ledger("triage-fail");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);
        {
            let db = app.db();
            db.execute_batch("CREATE TRIGGER t_block_upd BEFORE UPDATE ON finding BEGIN SELECT RAISE(ABORT,'boom'); END;").unwrap();
        }
        let before = read_ledger_lines(&led).len();
        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(to_json(r).await["error"], "db_write_failed");
        assert_eq!(triage_of(&app, f1), "new", "aucune mutation");
        assert_eq!(read_ledger_lines(&led).len(), before, "un échec d'écriture NE ledgerise PAS");
        let _ = std::fs::remove_file(&led);
    }

    /// FILTER : `?triage=<state>` rend EXACTEMENT le sous-ensemble dans cet état. Valeur bornée en Param.
    #[tokio::test]
    async fn filter_by_triage() {
        let led = tmp_ledger("filter-triage");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let f2 = seed_finding(&app, 1, "f2", "new");
        let _f3 = seed_finding(&app, 1, "f3", "new"); // reste 'new'
        let (_v, otok) = seed_roles(&app);
        for f in [f1, f2] {
            let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f), q_eng("1"),
                Json(json!({"to": "triaging"}))).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        // filtre triaging -> f1,f2.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("triage".to_string(), "triaging".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(b["total"], 2);
        let ids: Vec<i64> = b["findings"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert!(ids.contains(&f1) && ids.contains(&f2) && !ids.contains(&_f3), "filtre triage exact");
        // filtre new -> seulement f3.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("triage".to_string(), "new".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(b["total"], 1);
        assert_eq!(b["findings"][0]["id"], _f3);
        // valeur hors vocabulaire -> filtre IGNORÉ (best-effort) : tous les findings.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("triage".to_string(), "bogus".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(b["total"], 3, "valeur invalide -> filtre ignoré (aucune injection, aucun 500)");
        let _ = std::fs::remove_file(&led);
    }

    /// MIGRATE additif + idempotent : les findings existants héritent de `triage='new'` (DEFAULT backfill) ;
    /// rejouer `migrate()` ne panique pas et la colonne reste présente/valide.
    #[test]
    fn triage_migrate_default_new_and_idempotent() {
        let led = tmp_ledger("triage-migrate");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new"); // inséré sans `triage` -> DEFAULT 'new'
        assert_eq!(triage_of(&app, f1), "new", "finding existant backfillé à 'new'");
        // rejouer migrate (idempotent : ADD COLUMN error-ignored) -> pas de panic, colonne toujours là.
        {
            let db = app.db();
            crate::migrate(&db);
            crate::migrate(&db);
        }
        assert_eq!(triage_of(&app, f1), "new", "triage préservé après re-migration");
        let _ = std::fs::remove_file(&led);
    }

    /// ENTERPRISE (tenancy ON) : un operator SANS grant sur l'engagement ne peut PAS transitionner (fail-closed
    /// : l'engagement n'est même pas visible -> 404/403), et le finding reste intouché.
    #[tokio::test]
    async fn triage_caller_without_engagement_grant_denied() {
        let led = tmp_ledger("triage-nocaller");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
        }
        let (_v, otok) = seed_roles(&app); // operator global, MAIS aucun grant tenant/engagement
        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert!(
            r.status() == StatusCode::NOT_FOUND || r.status() == StatusCode::FORBIDDEN,
            "operator sans grant sur l'engagement ne peut pas transitionner (404/403 fail-closed), got {}",
            r.status()
        );
        assert_eq!(triage_of(&app, f1), "new", "aucune mutation");
        let _ = std::fs::remove_file(&led);
    }
}

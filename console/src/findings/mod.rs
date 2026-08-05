// SPDX-License-Identifier: AGPL-3.0-or-later
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
mod tests;

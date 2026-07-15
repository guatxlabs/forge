// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — IN-APP NOTIFICATIONS (« triage enrichi ») : couche LÉGÈRE de collaboration sur les
//! findings, posée SUR l'ownership (assignee) + le cycle de triage existants. PAS un moteur SLA/email
//! (ceux-là exigent une config de canal — hors périmètre).
//!
//! MODÈLE : une `notification` = « quelque chose te concerne » adressé à UN destinataire (`user_id` =
//! users.id). Deux déclencheurs, branchés sur les hooks EXISTANTS de `findings.rs` :
//!   - `finding.assigned` — un finding t'a été ASSIGNÉ (single + bulk assign). JAMAIS pour une
//!     auto-assignation (si l'assigné == l'acteur, on saute).
//!   - `finding.triage`   — un finding DONT TU ES L'ASSIGNÉ a changé d'état de triage (from → to). Jamais
//!     si l'assigné == l'acteur (pas de notif pour sa propre action).
//!
//! GARANTIES (fail-closed, miroir de l'assignation) :
//!   - GRANT-SCOPED À L'ÉMISSION : une notif n'est créée QUE pour un destinataire qui a un GRANT sur
//!     l'engagement du finding (enterprise). En community (pas de tenancy) le contrôle est un NO-OP (single
//!     user) — l'assigné doit juste exister, comme le reste.
//!   - BEST-EFFORT : l'insert d'une notif est MATCHÉ mais son échec NE CASSE PAS ni ne fausse la mutation
//!     assign/triage (celle-ci a déjà réussi + ledgerisé). Les notifs NE SONT PAS des events d'audit -> on
//!     NE DOUBLE PAS le ledger.
//!   - AUCUN VERROU TENU À TRAVERS L'ENVOI SSE : le guard `store` est libéré avant `app.events.send`.
//!   - LECTURE/MARQUAGE fail-closed au `user_id` de l'appelant : `GET /api/notifications` et
//!     `POST /api/notifications/read` ne touchent QUE les lignes de l'appelant (jamais celles d'un autre).
//!
//! Transport LIVE : réutilise le bus `App.events` (broadcast) avec un TOPIC dédié `NOTIFICATIONS_TOPIC`
//! (disjoint des topics runs/présence/findings). Le flux SSE d'un utilisateur ne FORWARDE que les events
//! dont le payload `user_id` == le sien (isolation : le texte d'une notif d'autrui n'atteint jamais son
//! client). Ce module n'ajoute AUCUN champ à `App` ni aucune dépendance nouvelle.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::Stream;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::store::{Param, Row, StoreResult};
use crate::{attribution_login, tenancy, App, RunEvent};

/// `run_id` synthétique qui porte les events de NOTIFICATION sur le bus SSE partagé (`App.events`, typé
/// pour les runs). Hors de l'espace des vrais run_id (préfixe `__`, comme `presence::PRESENCE_TOPIC` /
/// `FINDINGS_TOPIC`) : `run_sse`/`presence_events`/`finding_events` filtrent sur LEUR topic et ne le
/// remonteront jamais. Réutilise le bus existant (pas de 2e canal).
pub(crate) const NOTIFICATIONS_TOPIC: &str = "__notifications__";

/// Cadence (s) du heartbeat/keep-alive du flux SSE de notifications (parité présence/triage).
const NOTIF_SSE_TICK_SECS: u64 = 20;

/// Plafond dur du nombre de notifications renvoyées en une page (anti-abus). `?limit` le borne.
const MAX_PAGE: i64 = 200;
/// Taille de page par défaut si `?limit` absent.
const DEFAULT_PAGE: i64 = 50;
/// Borne dure du nombre d'ids acceptés par `POST /read` (anti-abus).
const MAX_READ_IDS: usize = 1000;
/// Borne du texte d'une notification (anti-abus ; les résumés sont courts).
const MAX_TEXT: usize = 512;

/// Kinds de notification RECONNUS (jeu fermé — cohérent avec le schéma). PURE.
pub(crate) const KIND_ASSIGNED: &str = "finding.assigned";
pub(crate) const KIND_TRIAGE: &str = "finding.triage";

// =====================================================================================
//  ÉMISSION — appelée depuis les hooks assign/triage de findings.rs (best-effort, grant-scopée, no-self).
// =====================================================================================

/// Titre d'un finding CONFINÉ à l'engagement `eid` (pour composer le texte de la notif). Chaîne VIDE si
/// introuvable / NULL. Guard `store` scopé + libéré immédiatement (anti auto-deadlock). PURE lecture.
fn finding_title(app: &App, id: i64, eid: i64) -> String {
    let store = app.store();
    store
        .query_row(
            "SELECT title FROM finding WHERE id=? AND engagement_id=?",
            &crate::sql_params![id, eid],
            |r| Ok(r.get_opt_str(0)?.unwrap_or_default()),
        )
        .unwrap_or_default()
}

/// `assignee` (user_id) d'un finding CONFINÉ à l'engagement `eid`, ou `None` (non assigné / introuvable /
/// cross-engagement). Guard `store` scopé + libéré immédiatement. PURE lecture.
fn finding_assignee(app: &App, id: i64, eid: i64) -> Option<i64> {
    let store = app.store();
    store
        .query_row(
            "SELECT assignee FROM finding WHERE id=? AND engagement_id=?",
            &crate::sql_params![id, eid],
            |r| r.get_opt_i64(0),
        )
        .ok()
        .flatten()
}

/// CŒUR de l'émission (best-effort) — crée UNE notification pour `recipient` et diffuse l'event SSE.
/// FAIL-CLOSED / anti-spam :
///   - `actor_uid == Some(recipient)` -> NO-OP (pas d'auto-notification) ;
///   - tenancy ENGAGÉE et `recipient` SANS grant sur `engagement_id` -> NO-OP (grant-scopé, miroir de
///     l'assignation ; en community le contrôle est un NO-OP -> single user sain) ;
///   - insert MATCHÉ : un échec (lock/disque/pg) est LOGGÉ puis avalé — la mutation appelante (assign/
///     triage, déjà réussie + ledgerisée) N'EST NI CASSÉE NI FAUSSÉE, et on NE double PAS le ledger.
///
/// Le guard `store` est libéré AVANT `app.events.send` (aucun verrou tenu à travers l'envoi SSE).
fn emit(app: &App, recipient: i64, actor_uid: Option<i64>, engagement_id: i64, finding_id: i64, kind: &str, text: String) {
    // Anti auto-notification (pas de spam pour sa propre action).
    if actor_uid == Some(recipient) {
        return;
    }
    // GRANT-SCOPED (enterprise) : on ne notifie QUE quelqu'un réellement sur l'engagement. `tenancy::enabled`
    // + `user_has_engagement_grant` acquièrent+libèrent EUX-MÊMES le Mutex de connexion -> appelés AVANT de
    // tenir un guard `store`. Community => enabled=false => contrôle sauté (aucun grant n'existe, single user).
    if tenancy::enabled(app) && !tenancy::user_has_engagement_grant(app, recipient, engagement_id) {
        return;
    }
    // Texte borné (défense anti-abus ; le rendu client l'ÉCHAPPE — jamais interprété comme HTML).
    let text = if text.len() > MAX_TEXT { text.chars().take(MAX_TEXT).collect() } else { text };
    let id = {
        let store = app.store();
        match store.execute_returning_id(
            "INSERT INTO notification(user_id,kind,engagement_id,finding_id,text,read,created)
             VALUES(?,?,?,?,?,0,datetime('now'))",
            &crate::sql_params![recipient, kind, engagement_id, finding_id, text.clone()],
        ) {
            Ok(id) => id,
            Err(e) => {
                // BEST-EFFORT : la mutation assign/triage a déjà réussi. On lowarn et on abandonne la notif —
                // jamais de panique, jamais de faux échec propagé à l'appelant, jamais de ledger doublé.
                eprintln!("[notifications] insert best-effort échoué (mutation préservée): {e}");
                return;
            }
        }
    };
    // EVENT SSE (temps réel) — guard `store` DÉJÀ libéré (aucun verrou tenu à travers l'envoi). Le payload
    // porte `user_id` = destinataire : SEUL le flux de CE destinataire le forwarde (isolation, cf. events()).
    let _ = app.events.send(RunEvent {
        run_id: NOTIFICATIONS_TOPIC.to_string(),
        kind: "notification".to_string(),
        payload: json!({
            "id": id, "user_id": recipient, "kind": kind,
            "engagement_id": engagement_id, "finding_id": finding_id, "text": text, "read": 0,
        }),
    });
}

/// HOOK ASSIGN (single) — notifie le NOUVEL assigné qu'un finding lui a été attribué (best-effort). Résout
/// l'acteur (user_id + login) puis délègue à [`emit`] (qui saute l'auto-assignation + applique le grant-scope).
pub(crate) fn notify_assigned(app: &App, headers: &HeaderMap, eid: i64, finding_id: i64, assignee: i64) {
    let actor_uid = tenancy::caller_user_id(app, headers);
    let actor = attribution_login(app, headers);
    notify_assigned_by(app, actor_uid, &actor, eid, finding_id, assignee);
}

/// HOOK ASSIGN (bulk-friendly) — variante où l'acteur (user_id + login) est DÉJÀ résolu (évite N résolutions
/// de session dans une boucle de bulk-assign). Compose le texte + délègue à [`emit`].
pub(crate) fn notify_assigned_by(app: &App, actor_uid: Option<i64>, actor_login: &str, eid: i64, finding_id: i64, assignee: i64) {
    if actor_uid == Some(assignee) {
        return; // fast-path (emit re-garde de toute façon)
    }
    let title = finding_title(app, finding_id, eid);
    let text = format!("{actor_login} vous a assigné le finding #{finding_id} « {title} »");
    emit(app, assignee, actor_uid, eid, finding_id, KIND_ASSIGNED, text);
}

/// HOOK TRIAGE (single) — notifie l'ASSIGNÉ du finding qu'il a changé d'état de triage (from → to). No-op
/// si le finding n'a pas d'assigné, ou si l'assigné == l'acteur. Best-effort + grant-scopé (via [`emit`]).
pub(crate) fn notify_triage(app: &App, headers: &HeaderMap, eid: i64, finding_id: i64, from: &str, to: &str) {
    let actor_uid = tenancy::caller_user_id(app, headers);
    let actor = attribution_login(app, headers);
    notify_triage_by(app, actor_uid, &actor, eid, finding_id, from, to);
}

/// HOOK TRIAGE (bulk-friendly) — variante avec acteur DÉJÀ résolu. Récupère l'assigné du finding puis notifie.
pub(crate) fn notify_triage_by(app: &App, actor_uid: Option<i64>, actor_login: &str, eid: i64, finding_id: i64, from: &str, to: &str) {
    let assignee = match finding_assignee(app, finding_id, eid) {
        Some(a) => a,
        None => return, // non assigné -> personne à notifier
    };
    if actor_uid == Some(assignee) {
        return; // l'assigné a trié son propre finding -> pas de notif pour soi-même
    }
    let title = finding_title(app, finding_id, eid);
    let text = format!("{actor_login} a trié le finding #{finding_id} « {title} » : {from} → {to}");
    emit(app, assignee, actor_uid, eid, finding_id, KIND_TRIAGE, text);
}

// =====================================================================================
//  ROUTES + HANDLERS (grant-scopés / fail-closed au user_id de l'appelant).
// =====================================================================================

/// Sous-routeur NOTIFICATIONS — FUSIONNÉ dans le routeur protégé de `build_router` (hérite donc de
/// l'auth_guard/host_guard). Aucun `Extension` requis (état 100 % en base + bus `App.events`).
pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/notifications", get(list))
        .route("/api/notifications/read", post(mark_read))
        .route("/api/notifications/events", get(events))
}

/// Sérialise une ligne `notification` (colonnes = SELECT_COLS) en JSON d'API.
const SELECT_COLS: &str = "id,user_id,kind,engagement_id,finding_id,text,read,created";
fn row_to_json(r: &Row) -> StoreResult<Value> {
    Ok(json!({
        "id": r.get_i64(0)?,
        "user_id": r.get_i64(1)?,
        "kind": r.get_str(2)?,
        "engagement_id": r.get_opt_i64(3)?,
        "finding_id": r.get_opt_i64(4)?,
        "text": r.get_str(5)?,
        "read": r.get_i64(6)? != 0,
        "created": r.get_opt_str(7)?.unwrap_or_default(),
    }))
}

/// GET /api/notifications[?limit=&offset=] — les notifications DE L'APPELANT (fail-closed au `user_id` de
/// sa session). NON-LUES D'ABORD puis les plus récentes (`ORDER BY read ASC, id DESC`), plafonné/paginé.
/// Réponse `{notifications:[…], unread, count, user_id}`. Un appelant SANS identité individuelle (dev-open /
/// bootstrap env-hash, sans user_id) n'a PAS de boîte -> liste vide + unread 0 (jamais celle d'un autre).
async fn list(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let uid = match tenancy::caller_user_id(&app, &headers) {
        Some(u) => u,
        None => return Json(json!({"notifications": [], "unread": 0, "count": 0, "user_id": Value::Null})).into_response(),
    };
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let offset = q.get("offset").and_then(|s| s.parse::<i64>().ok()).filter(|&n| n >= 0).unwrap_or(0);
    let store = app.store();
    let sql = format!(
        "SELECT {SELECT_COLS} FROM notification WHERE user_id=? ORDER BY read ASC, id DESC LIMIT ? OFFSET ?"
    );
    let rows: Vec<Value> = match store.query_lax(&sql, &crate::sql_params![uid, limit, offset], row_to_json) {
        Ok(rows) => rows,
        Err(e) => {
            drop(store);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal", "why": e.to_string()}))).into_response();
        }
    };
    // Compteur non-lu (sert au badge) — même appelant, index (user_id, read).
    let unread: i64 = store
        .query_row("SELECT COUNT(*) FROM notification WHERE user_id=? AND read=0", &crate::sql_params![uid], |r| r.get_i64(0))
        .unwrap_or(0);
    drop(store);
    Json(json!({"notifications": rows, "unread": unread, "count": rows.len(), "user_id": uid})).into_response()
}

/// POST /api/notifications/read {ids?:[i64]} — marque LUES les notifications de l'appelant. `ids` fourni ->
/// ce sous-ensemble (borné à [`MAX_READ_IDS`]) ; absent/vide -> TOUTES les non-lues de l'appelant. ISOLATION
/// fail-closed : chaque UPDATE est confiné à `user_id=<appelant>` — un id d'un AUTRE utilisateur est SKIPPÉ
/// (0 ligne), jamais marqué (et jamais divulgué). Réponse `{ok, marked}`. Pas de ledger (les notifs ne sont
/// pas des events d'audit). Un appelant sans identité individuelle -> `{ok:true, marked:0}` (rien à marquer).
async fn mark_read(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let uid = match tenancy::caller_user_id(&app, &headers) {
        Some(u) => u,
        None => return Json(json!({"ok": true, "marked": 0})).into_response(),
    };
    // `ids` optionnel : absent/null -> TOUT marquer ; tableau -> sous-ensemble (entiers uniquement).
    let ids: Option<Vec<i64>> = match body.get("ids") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) => {
            if arr.len() > MAX_READ_IDS {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": format!("trop d'ids (max {MAX_READ_IDS})")}))).into_response();
            }
            let mut out: Vec<i64> = Vec::with_capacity(arr.len());
            for v in arr {
                match v.as_i64() {
                    Some(n) => { if !out.contains(&n) { out.push(n); } }
                    None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "'ids' doit ne contenir que des entiers"}))).into_response(),
                }
            }
            Some(out)
        }
        Some(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "'ids' attendu : tableau d'entiers (ou absent pour tout marquer)"}))).into_response(),
    };
    let marked: usize = {
        let store = app.store();
        let res = match &ids {
            // Sous-ensemble : IN (?,?,…) BORNÉ au user_id de l'appelant (fail-closed : jamais la notif d'un
            // autre). Les ids sont LIÉS en Param (aucune interpolation de valeur). `ids` vide -> 0 marqué.
            Some(v) if !v.is_empty() => {
                let placeholders = vec!["?"; v.len()].join(",");
                let mut params: Vec<Param> = Vec::with_capacity(v.len() + 1);
                params.push(Param::Int(uid));
                for &n in v {
                    params.push(Param::Int(n));
                }
                store.execute(&format!("UPDATE notification SET read=1 WHERE user_id=? AND read=0 AND id IN ({placeholders})"), &params)
            }
            Some(_) => Ok(0), // ids fourni mais vide -> rien à marquer (no-op)
            // Aucun id -> marquer TOUTES les non-lues de l'appelant.
            None => store.execute("UPDATE notification SET read=1 WHERE user_id=? AND read=0", &crate::sql_params![uid]),
        };
        match res {
            Ok(n) => n,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal", "why": e.to_string()}))).into_response(),
        }
    };
    Json(json!({"ok": true, "marked": marked})).into_response()
}

/// GET /api/notifications/events — flux SSE des NOUVELLES notifications de l'appelant (temps réel : le badge
/// s'incrémente sans polling). Réutilise le bus `App.events` (topic [`NOTIFICATIONS_TOPIC`]) — même patron
/// que `finding_events`/`presence_events`. ISOLATION : ne FORWARDE que les events dont le payload `user_id`
/// == le `user_id` de l'appelant (le texte d'une notif d'autrui n'atteint jamais ce client). Un appelant sans
/// identité individuelle reçoit le flux mais AUCUN event ne matche (`my_uid = None` -> rien forwardé).
async fn events(State(app): State<App>, headers: HeaderMap) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let my_uid = tenancy::caller_user_id(&app, &headers);
    let rx = app.events.subscribe();
    let mut ticker = tokio::time::interval(Duration::from_secs(NOTIF_SSE_TICK_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let stream = futures_util::stream::unfold(
        (rx, ticker, false),
        move |(mut rx, mut ticker, mut synced)| async move {
            if !synced {
                synced = true;
                let ev = Event::default()
                    .event("notification")
                    .json_data(json!({"event": "sync"}))
                    .unwrap_or_else(|_| Event::default().comment("sync"));
                return Some((Ok(ev), (rx, ticker, synced)));
            }
            loop {
                tokio::select! {
                    r = rx.recv() => match r {
                        // Notre topic ET destiné à CET appelant (isolation fail-closed sur user_id).
                        Ok(ev) if ev.run_id == NOTIFICATIONS_TOPIC
                            && my_uid.is_some()
                            && ev.payload.get("user_id").and_then(|v| v.as_i64()) == my_uid =>
                        {
                            let ev2 = Event::default()
                                .event("notification")
                                .json_data(&ev.payload)
                                .unwrap_or_else(|_| Event::default().comment("notification"));
                            return Some((Ok(ev2), (rx, ticker, synced)));
                        }
                        Ok(_) => continue, // autre topic, ou notif d'un AUTRE utilisateur -> jamais forwardée
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            let ev = Event::default()
                                .event("notification")
                                .json_data(json!({"event": "resync"}))
                                .unwrap_or_else(|_| Event::default().comment("resync"));
                            return Some((Ok(ev), (rx, ticker, synced)));
                        }
                        Err(broadcast::error::RecvError::Closed) => return None,
                    },
                    _ = ticker.tick() => {
                        return Some((Ok(Event::default().comment("hb")), (rx, ticker, synced)));
                    }
                }
            }
        },
    );
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(NOTIF_SSE_TICK_SECS)).text("keep-alive"))
}

// =====================================================================================
//  TESTS — émission grant-scopée / no-self, isolation par user_id (lecture + marquage), best-effort
//  (l'échec d'insert ne casse pas la mutation), SSE scopé, migration additive/idempotente.
//
//  Auto-portants : App de test (DB in-memory, SCHEMA + migrate comme au boot) + appel direct des handlers
//  (les HOOKS assign/triage passent par les VRAIS handlers `crate::finding_assign`/`crate::finding_triage`).
// =====================================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_session, hash_pw, upsert_user, LedgerHead, RunState};
    use axum::extract::{ConnectInfo, Path};
    use rusqlite::Connection;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    fn tmp_ledger(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "forge-notif-{}-{}-{}.jsonl",
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
    fn seed_user(app: &App, login: &str, role: &str) -> i64 {
        { let db = app.db(); upsert_user(&db, login, role, &hash_pw("pw")).unwrap(); }
        uid_of(app, login)
    }
    fn seed_op(app: &App, login: &str) -> (i64, String) {
        let uid = seed_user(app, login, "operator");
        let (tok, _) = create_session(app, uid);
        (uid, tok)
    }
    fn seed_tenant_grant(app: &App, uid: i64, tid: i64, role: &str) {
        let db = app.db();
        db.execute("INSERT INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,?,?,datetime('now'))", rusqlite::params![uid, tid, role]).unwrap();
    }
    fn uid_of(app: &App, login: &str) -> i64 {
        let db = app.db();
        db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
    }
    fn assignee_of(app: &App, id: i64) -> Option<i64> {
        let db = app.db();
        db.query_row("SELECT assignee FROM finding WHERE id=?", [id], |r| r.get(0)).ok().flatten()
    }
    fn notif_count(app: &App, uid: i64) -> i64 {
        let db = app.db();
        db.query_row("SELECT COUNT(*) FROM notification WHERE user_id=?", [uid], |r| r.get(0)).unwrap()
    }
    fn notif_rows(app: &App, uid: i64) -> Vec<(i64, String, i64, i64)> {
        let db = app.db();
        let mut st = db.prepare("SELECT id,kind,finding_id,read FROM notification WHERE user_id=? ORDER BY id").unwrap();
        let rows: Vec<(i64, String, i64, i64)> = st
            .query_map([uid], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)))
            .unwrap()
            .filter_map(|x| x.ok())
            .collect();
        drop(st);
        drop(db);
        rows
    }
    fn bearer(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {tok}").parse().unwrap());
        h
    }
    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:9".parse().unwrap())
    }
    fn q_eng(eid: &str) -> Query<HashMap<String, String>> {
        Query(HashMap::from([("engagement".to_string(), eid.to_string())]))
    }
    async fn to_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// ASSIGN : assigner à un AUTRE user crée une notif finding.assigned pour LUI ; s'auto-assigner n'en
    /// crée AUCUNE (pas de self-notify).
    #[tokio::test]
    async fn assign_notifies_new_assignee_not_self() {
        let led = tmp_ledger("assign");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (oo_uid, otok) = seed_op(&app, "oo");
        let bob = seed_user(&app, "bob", "viewer");

        // oo assigne f1 à bob -> 200 + 1 notif finding.assigned pour bob, 0 pour oo.
        let r = crate::finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"), Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let rows = notif_rows(&app, bob);
        assert_eq!(rows.len(), 1, "bob reçoit 1 notif");
        assert_eq!(rows[0].1, KIND_ASSIGNED);
        assert_eq!(rows[0].2, f1, "notif liée à f1");
        assert_eq!(rows[0].3, 0, "non-lue");
        assert_eq!(notif_count(&app, oo_uid), 0, "l'acteur ne se notifie pas");

        // oo s'auto-assigne f1 -> 200 mais AUCUNE notif (assignee == acteur).
        let r = crate::finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"), Json(json!({"assignee": oo_uid}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(notif_count(&app, oo_uid), 0, "pas de self-notify");
        let _ = std::fs::remove_file(&led);
    }

    /// TRIAGE : une transition notifie l'ASSIGNÉ du finding, PAS l'acteur.
    #[tokio::test]
    async fn triage_notifies_assignee_not_actor() {
        let led = tmp_ledger("triage");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (oo_uid, otok) = seed_op(&app, "oo");
        let bob = seed_user(&app, "bob", "viewer");
        // f1 assigné à bob (crée 1 notif assigned pour bob).
        crate::finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"), Json(json!({"assignee": bob}))).await;
        assert_eq!(notif_count(&app, bob), 1);

        // oo transitionne new -> triaging : bob (assigné, != acteur) reçoit une notif finding.triage.
        let r = crate::finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"), Json(json!({"to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let rows = notif_rows(&app, bob);
        assert_eq!(rows.len(), 2, "bob : assigned + triage");
        assert_eq!(rows[1].1, KIND_TRIAGE);
        assert_eq!(rows[1].2, f1);
        assert_eq!(notif_count(&app, oo_uid), 0, "l'acteur du triage ne reçoit rien");
        let _ = std::fs::remove_file(&led);
    }

    /// LECTURE isolée : GET /api/notifications ne renvoie QUE les lignes de l'appelant (A ne voit pas celles de B).
    #[tokio::test]
    async fn list_returns_only_callers_rows() {
        let led = tmp_ledger("list-iso");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let f2 = seed_finding(&app, 1, "f2", "new");
        let (o1_uid, o1) = seed_op(&app, "o1");
        let (o2_uid, o2) = seed_op(&app, "o2");
        // o2 assigne f1 à o1 -> notif pour o1 ; o1 assigne f2 à o2 -> notif pour o2.
        crate::finding_assign(State(app.clone()), peer(), bearer(&o2), Path(f1), q_eng("1"), Json(json!({"assignee": o1_uid}))).await;
        crate::finding_assign(State(app.clone()), peer(), bearer(&o1), Path(f2), q_eng("1"), Json(json!({"assignee": o2_uid}))).await;

        let b = to_json(list(State(app.clone()), bearer(&o1), Query(HashMap::new())).await).await;
        assert_eq!(b["count"], 1, "o1 ne voit que SA notif");
        assert_eq!(b["user_id"], o1_uid);
        assert_eq!(b["notifications"][0]["finding_id"], f1);
        let b = to_json(list(State(app.clone()), bearer(&o2), Query(HashMap::new())).await).await;
        assert_eq!(b["count"], 1, "o2 ne voit que SA notif");
        assert_eq!(b["notifications"][0]["finding_id"], f2);
        // sanity DB : chacun a bien exactement 1 ligne, jamais celle de l'autre.
        assert_eq!(notif_count(&app, o1_uid), 1);
        assert_eq!(notif_count(&app, o2_uid), 1);
        let _ = std::fs::remove_file(&led);
    }

    /// MARQUAGE isolé : POST /read ne marque QUE les lignes de l'appelant (B ne marque pas celle de A).
    #[tokio::test]
    async fn mark_read_only_marks_own() {
        let led = tmp_ledger("read-iso");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let f2 = seed_finding(&app, 1, "f2", "new");
        let (o1_uid, o1) = seed_op(&app, "o1");
        let (o2_uid, o2) = seed_op(&app, "o2");
        crate::finding_assign(State(app.clone()), peer(), bearer(&o2), Path(f1), q_eng("1"), Json(json!({"assignee": o1_uid}))).await;
        crate::finding_assign(State(app.clone()), peer(), bearer(&o1), Path(f2), q_eng("1"), Json(json!({"assignee": o2_uid}))).await;
        let o1_nid = notif_rows(&app, o1_uid)[0].0;

        // o2 tente de marquer la notif de o1 -> 0 marqué (fail-closed), la notif de o1 reste non-lue.
        let b = to_json(mark_read(State(app.clone()), bearer(&o2), Json(json!({"ids": [o1_nid]}))).await).await;
        assert_eq!(b["marked"], 0, "o2 ne marque pas la notif de o1");
        assert_eq!(notif_rows(&app, o1_uid)[0].3, 0, "notif de o1 encore non-lue");

        // o1 marque TOUT -> sa propre notif passe lue ; celle de o2 intouchée.
        let b = to_json(mark_read(State(app.clone()), bearer(&o1), Json(json!({}))).await).await;
        assert_eq!(b["marked"], 1);
        assert_eq!(notif_rows(&app, o1_uid)[0].3, 1, "notif de o1 lue");
        assert_eq!(notif_rows(&app, o2_uid)[0].3, 0, "notif de o2 toujours non-lue");
        let _ = std::fs::remove_file(&led);
    }

    /// SSE : `emit` diffuse un event NOTIFICATIONS_TOPIC portant le user_id du DESTINATAIRE (base de
    /// l'isolation du flux : seul le flux de ce user forwarde l'event).
    #[tokio::test]
    async fn emit_broadcasts_scoped_to_recipient() {
        let led = tmp_ledger("sse");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let bob = seed_user(&app, "bob", "viewer");
        let mut rx = app.events.subscribe();
        emit(&app, bob, Some(999), 1, f1, KIND_ASSIGNED, "test".into());
        let ev = rx.try_recv().expect("un event diffusé");
        assert_eq!(ev.run_id, NOTIFICATIONS_TOPIC);
        assert_eq!(ev.payload.get("user_id").and_then(|v| v.as_i64()), Some(bob));
        assert_eq!(notif_count(&app, bob), 1);
        let _ = std::fs::remove_file(&led);
    }

    /// GRANT-SCOPED (enterprise) : un destinataire SANS grant sur l'engagement ne reçoit JAMAIS de notif ;
    /// un destinataire AVEC grant en reçoit. Teste `emit` directement (tenancy ON).
    #[tokio::test]
    async fn emit_grant_scoped_enterprise() {
        let led = tmp_ledger("grant");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A"); // tenant_id défaut = 1
        let f1 = seed_finding(&app, 1, "f1", "new");
        { let db = app.db(); crate::settings_set(&db, "enterprise.tenancy", "on").unwrap(); }
        let insider = seed_user(&app, "insider", "viewer");
        seed_tenant_grant(&app, insider, 1, "tenant_viewer");
        let outsider = seed_user(&app, "outsider", "viewer");

        emit(&app, outsider, None, 1, f1, KIND_ASSIGNED, "x".into());
        assert_eq!(notif_count(&app, outsider), 0, "sans grant -> aucune notif (fail-closed)");
        emit(&app, insider, None, 1, f1, KIND_ASSIGNED, "x".into());
        assert_eq!(notif_count(&app, insider), 1, "avec grant -> notif créée");
        let _ = std::fs::remove_file(&led);
    }

    /// BEST-EFFORT : si l'insert de notif ÉCHOUE (table absente), la mutation assign RÉUSSIT quand même
    /// (200 + assignee posé) — pas de faux échec, pas de casse.
    #[tokio::test]
    async fn notif_insert_failure_preserves_assign() {
        let led = tmp_ledger("besteffort");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_oo, otok) = seed_op(&app, "oo");
        let bob = seed_user(&app, "bob", "viewer");
        // Simule une panne d'insert de notif : on supprime la table.
        { let db = app.db(); db.execute("DROP TABLE notification", []).unwrap(); }

        let r = crate::finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"), Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::OK, "l'assignation réussit malgré l'échec de notif");
        assert_eq!(assignee_of(&app, f1), Some(bob), "la mutation est bien durable");
        let _ = std::fs::remove_file(&led);
    }

    /// MIGRATION additive + idempotente : `migrate()` crée la table `notification` sur une base ANTÉRIEURE
    /// (sans la table) et re-passer migrate() ne casse rien ; la table est utilisable.
    #[test]
    fn migrate_additive_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        // Base ANTÉRIEURE : PAS de SCHEMA (table absente). migrate() doit la créer.
        crate::migrate(&conn);
        crate::migrate(&conn); // idempotent : 2e passe sans erreur.
        conn.execute("INSERT INTO notification(user_id,kind,finding_id,text,read,created) VALUES(1,'finding.assigned',7,'t',0,datetime('now'))", []).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM notification WHERE user_id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "table notification présente + insérable après migrate");
        // l'index (user_id, read) existe.
        let idx: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_notification_user_read'", [], |r| r.get(0)).unwrap();
        assert_eq!(idx, 1, "index (user_id, read) créé");
    }

    #[test]
    fn routes_build() {
        let _r: Router<App> = routes();
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — PRESENCE (#9) : roster multi-opérateur LIVE (qui est connecté/en train d'opérer).
//!
//! La console a un BUS d'événements SSE (`App.events`, cf. runs.rs) + l'attribution `started_by`. Ce
//! module ajoute la présence : qui d'autre est connecté/en train d'opérer. Le registre a DEUX backends,
//! choisis une fois à la construction (`PresenceRegistry::for_app`, dans `build_router`) :
//!   - MONO-INSTANCE / community (défaut) : entièrement EN MÉMOIRE (aucune table lue/écrite) ;
//!   - HA (opt-in `FORGE_HA` + Postgres, feature `store-postgres`) : backé par la table `presence`
//!     PARTAGÉE (cf. state.rs SCHEMA/PG_SCHEMA) -> `GET /api/presence` sur N'IMPORTE quel réplica agrège
//!     l'UNION des opérateurs de TOUS les réplicas (chaque ligne stampée de `FORGE_INSTANCE_ID`).
//! Les DEUX backends exposent les MÊMES méthodes et sont branchés sur le CYCLE DE VIE de la connexion SSE :
//!   - un client ouvre `GET /api/presence/events` -> on l'INSCRIT (join) + on diffuse un event `presence`
//!     sur le bus existant pour que les autres clients se rafraîchissent ;
//!   - tant que le flux vit, un tick interne rafraîchit le `last_seen` (heartbeat côté serveur) ;
//!   - à la déconnexion (drop du flux) un guard RAII le RETIRE (leave) + rediffuse `presence`.
//!   - `GET /api/presence[?engagement=<id>]` renvoie le roster courant (dédupliqué par login).
//!   - `POST /api/presence/heartbeat` (léger) rafraîchit le TTL de toutes les connexions de l'appelant.
//!
//! FAIL-CLOSED sur l'auth : SEULS les appelants avec une identité résolue (session ou bootstrap env-hash)
//! sont inscrits — un anonyme dev-open n'apparaît jamais. TENANCY (ENTERPRISE, flag-gated) : une entrée
//! rattachée à un engagement n'est visible que si le caller peut VOIR cet engagement
//! (`tenancy::engagement_visible`) — jamais de fuite de présence inter-tenant. Une entrée périmée (pas de
//! heartbeat depuis `PRESENCE_TTL_SECS`) expire (GC paresseux à la lecture) : une connexion tuée sans
//! `Drop` (crash réseau) finit par disparaître.
//!
//! BYTE-IDENTIQUE HORS-HA (garantie forte) : sans `FORGE_HA`, le backend PG n'est jamais attaché (`for_app`
//! renvoie le registre EN MÉMOIRE) ; le champ `backend` et CHAQUE branche PG sont `#[cfg(store-postgres)]`
//! -> dans le build community le code PG est littéralement absent (struct identique à avant, aucune dep PG
//! tirée), et dans un build `store-postgres` mono-instance `backend == None` court-circuite vers la map en
//! mémoire. Les lignes périmées d'un réplica mort expirent par TTL (`last_seen`, filtré à la lecture +
//! GC de fond leader-only `presence_gc_loop`) -> jamais de roster fantôme.
//!
//! Ce module réutilise `App` + le bus `App.events` + les helpers d'auth/tenancy. L'état vit dans un
//! `Extension<PresenceRegistry>` câblé une fois dans `build_router` (donc ZÉRO champ ajouté à `App` ->
//! aucun site de construction touché) ; la table `presence` partagée n'est touchée QUE sous HA.

use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json,
    },
    routing::{get, post},
    Router,
};
use futures_util::Stream;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

use crate::{gen_token, now_epoch, resolve_identity, tenancy, App, RunEvent};

/// `run_id` synthétique porté par les events de PRÉSENCE sur le bus SSE partagé (`App.events`, typé pour
/// les runs). Choisi hors de l'espace des vrais run_id (préfixe `__`) : `run_sse` filtre sur `run_id ==
/// id` et ne verra donc JAMAIS un event de présence, et réciproquement `presence_events` ne remonte que
/// les events dont `run_id == PRESENCE_TOPIC`. Réutiliser le bus existant évite un 2e canal broadcast.
pub(crate) const PRESENCE_TOPIC: &str = "__presence__";

/// TTL d'une entrée sans rafraîchissement : au-delà, elle est considérée PÉRIMÉE et GC-ée (lecture). Doit
/// rester > à l'intervalle de heartbeat (côté serveur ET client) pour ne pas faire clignoter un présent.
const PRESENCE_TTL_SECS: i64 = 45;

/// Cadence du heartbeat interne du flux SSE (rafraîchit `last_seen` + keep-alive). < TTL par sécurité.
const HEARTBEAT_TICK_SECS: u64 = 15;

/// Une connexion présente. Clé de la map = `conn_id` (token aléatoire par flux SSE) — un même login peut
/// donc avoir PLUSIEURS entrées (onglets/sessions multiples), dédupliquées à la lecture du roster.
#[derive(Clone)]
struct PresenceEntry {
    login: String,
    role: String,
    engagement_id: Option<i64>, // engagement où l'opérateur travaille (None = connecté sans engagement)
    since: i64,                 // epoch de la 1re connexion de CETTE entrée
    last_seen: i64,             // epoch du dernier heartbeat (sert au TTL)
}

/// Registre de présence PAR-INSTANCE. `Clone` = partage du même `Arc<Mutex<..>>` (câblé une fois dans
/// `build_router` via `Extension`, cloné par requête). Le Mutex n'est JAMAIS tenu à travers un `.await`
/// (chaque méthode lock -> mute -> release en synchrone) : conforme au lint `await_holding_lock`.
#[derive(Clone, Default)]
pub(crate) struct PresenceRegistry {
    inner: Arc<Mutex<HashMap<String, PresenceEntry>>>, // conn_id -> entrée (backend EN MÉMOIRE, !ha)
    // HA #10 Wave C — PRESENCE PG TABLE. `Some(app)` UNIQUEMENT quand HA est engagé : les mêmes méthodes
    // (join/touch/touch_login/leave/snapshot) écrivent alors la table `presence` PARTAGÉE (roster
    // cross-instance) au lieu de la map en mémoire. `None` (défaut, community/mono-instance) -> map en
    // mémoire, BYTE-IDENTIQUE. Feature-gated : le champ n'existe pas dans le build community (struct
    // identique à avant), et `derive(Default)` le laisse à `None`.
    #[cfg(feature = "store-postgres")]
    backend: Option<crate::App>,
}

impl PresenceRegistry {
    /// Construit le registre pour CET `app` : PG-backé (table `presence` partagée) quand HA est engagé,
    /// sinon EN MÉMOIRE (défaut, byte-identique). Câblé une fois dans `build_router`. En community/!store-
    /// postgres, TOUJOURS en mémoire.
    #[cfg(feature = "store-postgres")]
    pub(crate) fn for_app(app: &crate::App) -> Self {
        if crate::ha::ha_enabled(app) {
            PresenceRegistry { inner: Arc::default(), backend: Some(app.clone()) }
        } else {
            PresenceRegistry::default()
        }
    }
    #[cfg(not(feature = "store-postgres"))]
    pub(crate) fn for_app(_app: &crate::App) -> Self {
        PresenceRegistry::default()
    }

    /// Inscrit (ou remplace) la connexion `conn_id`. `since`/`last_seen` = maintenant. Sous HA -> upsert
    /// dans la table `presence` PARTAGÉE (stampée de l'`instance_id` hôte) ; sinon map en mémoire.
    fn join(&self, conn_id: &str, login: &str, role: &str, engagement_id: Option<i64>) {
        let now = now_epoch();
        #[cfg(feature = "store-postgres")]
        if let Some(app) = &self.backend {
            
            let _ = (app.store()).execute(
                "INSERT INTO presence(conn_id,login,role,engagement_id,instance_id,since,last_seen)
                 VALUES(?,?,?,?,?,?,?)
                 ON CONFLICT(conn_id) DO UPDATE SET login=excluded.login, role=excluded.role,
                   engagement_id=excluded.engagement_id, instance_id=excluded.instance_id,
                   since=excluded.since, last_seen=excluded.last_seen",
                &crate::sql_params![conn_id, login, role, engagement_id, app.instance_id.as_str(), now, now],
            );
            return;
        }
        let mut m = self.inner.lock().unwrap();
        m.insert(
            conn_id.to_string(),
            PresenceEntry { login: login.to_string(), role: role.to_string(), engagement_id, since: now, last_seen: now },
        );
    }

    /// Rafraîchit le `last_seen` d'UNE connexion (heartbeat interne du flux). No-op si déjà retirée.
    fn touch(&self, conn_id: &str) {
        let now = now_epoch();
        #[cfg(feature = "store-postgres")]
        if let Some(app) = &self.backend {
            
            let _ = (app.store()).execute("UPDATE presence SET last_seen=? WHERE conn_id=?", &crate::sql_params![now, conn_id]);
            return;
        }
        let mut m = self.inner.lock().unwrap();
        if let Some(e) = m.get_mut(conn_id) {
            e.last_seen = now;
        }
    }

    /// Rafraîchit TOUTES les connexions d'un login (heartbeat endpoint, sans conn_id). Renvoie le nombre
    /// rafraîchi. Permet à un client qui préfère le polling de maintenir sa présence sans flux SSE ouvert.
    fn touch_login(&self, login: &str) -> usize {
        let now = now_epoch();
        #[cfg(feature = "store-postgres")]
        if let Some(app) = &self.backend {
            let store = app.store();
            return store
                .execute("UPDATE presence SET last_seen=? WHERE login=?", &crate::sql_params![now, login])
                .unwrap_or(0);
        }
        let mut m = self.inner.lock().unwrap();
        let mut n = 0;
        for e in m.values_mut() {
            if e.login == login {
                e.last_seen = now;
                n += 1;
            }
        }
        drop(m);
        n
    }

    /// Retire la connexion `conn_id` (déconnexion). Renvoie l'entrée retirée (pour diffuser le leave).
    fn leave(&self, conn_id: &str) -> Option<PresenceEntry> {
        #[cfg(feature = "store-postgres")]
        if let Some(app) = &self.backend {
            let store = app.store();
            // lit l'entrée AVANT de la supprimer (pour diffuser le leave login/engagement). Best-effort.
            let entry = store
                .query_row(
                    "SELECT login, role, engagement_id, since, last_seen FROM presence WHERE conn_id=?",
                    &crate::sql_params![conn_id],
                    |r| {
                        Ok(PresenceEntry {
                            login: r.get_str(0)?,
                            role: r.get_str(1)?,
                            engagement_id: r.get_opt_i64(2)?,
                            since: r.get_i64(3)?,
                            last_seen: r.get_i64(4)?,
                        })
                    },
                )
                .ok();
            let _ = store.execute("DELETE FROM presence WHERE conn_id=?", &crate::sql_params![conn_id]);
            drop(store);
            return entry;
        }
        let mut m = self.inner.lock().unwrap();
        m.remove(conn_id)
    }

    /// Snapshot des entrées NON périmées. Le GC physique (DELETE des lignes dont `last_seen` dépasse le TTL)
    /// N'EST PLUS fait ici : sous HA il tournait sur CHAQUE lecture `/api/presence` (amplification d'écriture
    /// proportionnelle au trafic de lecture). Il est désormais PÉRIODIQUE (cf. `presence_gc_loop`, cadence du
    /// heartbeat) ; le snapshot est en LECTURE SEULE et filtre les lignes périmées SUR LA LECTURE
    /// (`WHERE last_seen >= cutoff`) -> sémantique de TTL IDENTIQUE (une entrée morte disparaît immédiatement
    /// du roster) mais AUCUNE écriture par lecture. Sous HA -> SELECT filtré de la table PARTAGÉE (le filtre
    /// tenancy reste dans `presence_roster`) -> le roster agrège les opérateurs de TOUS les réplicas.
    /// Community (!ha, en mémoire) : purge paresseuse `retain` inchangée (byte-identique).
    fn snapshot(&self) -> Vec<PresenceEntry> {
        let cutoff = now_epoch() - PRESENCE_TTL_SECS;
        #[cfg(feature = "store-postgres")]
        if let Some(app) = &self.backend {
            let store = app.store();
            // LECTURE SEULE : filtre les périmés sur la lecture (pas de DELETE ici). Le GC est périodique.
            return store
                .query(
                    "SELECT login, role, engagement_id, since, last_seen FROM presence WHERE last_seen >= ?",
                    &crate::sql_params![cutoff],
                    |r| {
                        Ok(PresenceEntry {
                            login: r.get_str(0)?,
                            role: r.get_str(1)?,
                            engagement_id: r.get_opt_i64(2)?,
                            since: r.get_i64(3)?,
                            last_seen: r.get_i64(4)?,
                        })
                    },
                )
                .unwrap_or_default();
        }
        let mut m = self.inner.lock().unwrap();
        m.retain(|_, e| e.last_seen >= cutoff);
        m.values().cloned().collect()
    }
}

/// GC PÉRIODIQUE de la table `presence` PARTAGÉE (HA #10, Fix write-amplification). Remplace le DELETE
/// qui tournait sur CHAQUE lecture `/api/presence` par un DELETE de fond à la cadence du heartbeat
/// ([`HEARTBEAT_TICK_SECS`]) : purge les lignes dont `last_seen` dépasse [`PRESENCE_TTL_SECS`] (connexions
/// mortes sans `Drop`). Le snapshot reste correct entre deux ticks car il FILTRE déjà les périmés sur la
/// lecture -> la sémantique de TTL est INCHANGÉE, seule l'écriture physique est amortie. LEADER-ONLY : un
/// seul writer cluster-wide (le DELETE est idempotent, mais gate sur `is_leader` évite N réplicas écrivant
/// la même purge). Spawné UNIQUEMENT sous HA (cf. `main.rs`) ; single-instance/community : la purge
/// paresseuse `retain` en mémoire du snapshot suffit, cette boucle n'existe pas.
#[cfg(feature = "store-postgres")]
pub(crate) async fn presence_gc_loop(app: App) {
    let mut ticker = tokio::time::interval(Duration::from_secs(HEARTBEAT_TICK_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if !crate::ha::is_leader(&app) {
            continue; // un seul réplica (le leader) fait la purge de fond.
        }
        let cutoff = now_epoch() - PRESENCE_TTL_SECS;
        // Le guard `Store` est `!Send` et scoppé à ce bloc sync (droppé avant le prochain `.await`) ->
        // le future reste `Send`/spawnable et ne tient aucun verrou DB à travers une suspension.
        let store = app.store();
        let _ = store.execute("DELETE FROM presence WHERE last_seen < ?", &crate::sql_params![cutoff]);
        drop(store);
    }
}

/// Guard RAII de présence : posé quand un flux SSE inscrit une connexion, DROPPÉ quand le flux meurt
/// (retour normal OU déconnexion/annulation du future côté client). Son `Drop` RETIRE la connexion et
/// rediffuse un `presence` (leave) — c'est LE mécanisme qui garantit qu'un onglet fermé disparaît du
/// roster des autres sans attendre le TTL.
struct PresenceGuard {
    app: App,
    reg: PresenceRegistry,
    conn_id: String,
    login: String,
    engagement_id: Option<i64>,
}

impl Drop for PresenceGuard {
    fn drop(&mut self) {
        self.reg.leave(&self.conn_id);
        broadcast_presence(&self.app, "leave", &self.login, self.engagement_id);
    }
}

/// Diffuse un changement de présence (join/leave/…) sur le bus SSE partagé. Le payload est VOLONTAIREMENT
/// minimal : les clients traitent tout event de présence comme « quelque chose a changé -> re-fetch
/// `/api/presence` » (pas de reconstruction incrémentale côté client -> pas de désync possible).
fn broadcast_presence(app: &App, event: &str, login: &str, engagement_id: Option<i64>) {
    let _ = app.events.send(RunEvent {
        run_id: PRESENCE_TOPIC.to_string(),
        kind: "presence".to_string(),
        payload: json!({"event": event, "login": login, "engagement": engagement_id}),
    });
}

/// Sous-routeur PRÉSENCE — fusionné dans le routeur protégé de `build_router` (hérite donc de
/// l'auth_guard/host_guard). L'`Extension<PresenceRegistry>` est câblée séparément dans `build_router`.
pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/presence", get(presence_roster))
        .route("/api/presence/events", get(presence_events))
        .route("/api/presence/heartbeat", post(presence_heartbeat))
}

/// GET /api/presence[?engagement=<id>] — roster courant, DÉDUPLIQUÉ par login (un opérateur multi-onglets
/// = 1 ligne, `connections` = nb de flux). FAIL-CLOSED tenancy :
///   - `?engagement=<id>` non visible au caller  => roster VIDE (jamais la présence d'un autre tenant) ;
///   - sinon on ne garde que les entrées rattachées à CET engagement ;
///   - sans `?engagement`, on garde les entrées dont l'engagement est visible au caller (les entrées
///     rattachées à un engagement NON visible sont écartées — anti-fuite inter-tenant).
///
/// `self:true` marque la propre ligne du caller (pour l'UI). Community (tenancy OFF) : `engagement_visible`
/// est un no-op -> visibilité universelle mono-tenant (comportement byte-identique).
async fn presence_roster(
    State(app): State<App>,
    Extension(reg): Extension<PresenceRegistry>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let me = resolve_identity(&app, &headers).map(|i| i.login);
    let want_eng: Option<i64> = q.get("engagement").and_then(|s| s.parse().ok());

    // Engagement explicite NON visible -> fail-closed (roster vide), sans divulguer qu'il existe.
    if let Some(eid) = want_eng {
        if !tenancy::engagement_visible(&app, &headers, eid) {
            return Json(json!({"engagement": eid, "count": 0, "operators": []}));
        }
    }

    // Agrégation par login : (role, engagement, since_min, last_seen_max, connections).
    let mut by_login: HashMap<String, (String, Option<i64>, i64, i64, i64)> = HashMap::new();
    for e in reg.snapshot() {
        // Visibilité par-entrée (une entrée rattachée à un engagement invisible est écartée).
        if let Some(eid) = e.engagement_id {
            if !tenancy::engagement_visible(&app, &headers, eid) {
                continue;
            }
        }
        // Filtre d'engagement explicite : ne garder que la présence DE cet engagement.
        if let Some(weid) = want_eng {
            if e.engagement_id != Some(weid) {
                continue;
            }
        }
        let ent = by_login
            .entry(e.login.clone())
            .or_insert((e.role.clone(), e.engagement_id, e.since, e.last_seen, 0));
        ent.4 += 1;
        if e.since < ent.2 {
            ent.2 = e.since;
        }
        if e.last_seen > ent.3 {
            ent.3 = e.last_seen;
        }
    }

    let mut operators: Vec<Value> = by_login
        .into_iter()
        .map(|(login, (role, eng, since, last_seen, conns))| {
            let is_self = me.as_deref() == Some(login.as_str());
            json!({
                "login": login,
                "role": role,
                "engagement_id": eng,
                "since": since,
                "last_seen": last_seen,
                "connections": conns,
                "self": is_self,
            })
        })
        .collect();
    // Ordre stable (tri par login) — sortie déterministe pour l'UI et les tests.
    operators.sort_by(|a, b| a["login"].as_str().unwrap_or("").cmp(b["login"].as_str().unwrap_or("")));

    let count = operators.len();
    Json(json!({"engagement": want_eng, "count": count, "operators": operators}))
}

/// GET /api/presence/events[?engagement=<id>] — flux SSE de PRÉSENCE. Inscrit la connexion au connect
/// (si le caller a une identité — FAIL-CLOSED, un anonyme n'est jamais inscrit), diffuse `join`, forwarde
/// les events `presence` du bus (chaque event = signal « re-fetch le roster »), rafraîchit `last_seen`
/// toutes les `HEARTBEAT_TICK_SECS`, et à la déconnexion (Drop du flux) le guard RETIRE la connexion +
/// diffuse `leave`. Un `sync` initial est émis pour que le client charge le roster immédiatement.
async fn presence_events(
    State(app): State<App>,
    Extension(reg): Extension<PresenceRegistry>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Engagement demandé, retenu SEULEMENT s'il est visible au caller (anti-fuite : une entrée n'est
    // jamais rattachée à un engagement que le caller ne peut pas voir).
    let want_eng: Option<i64> = q
        .get("engagement")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&eid| tenancy::engagement_visible(&app, &headers, eid));

    let conn_id = gen_token();
    // FAIL-CLOSED : on n'inscrit QUE si une identité est résolue (session ou bootstrap env-hash).
    let guard = resolve_identity(&app, &headers).map(|id| {
        reg.join(&conn_id, &id.login, &id.role, want_eng);
        broadcast_presence(&app, "join", &id.login, want_eng);
        PresenceGuard { app: app.clone(), reg: reg.clone(), conn_id: conn_id.clone(), login: id.login, engagement_id: want_eng }
    });

    let rx = app.events.subscribe();
    let mut ticker = tokio::time::interval(Duration::from_secs(HEARTBEAT_TICK_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // État de l'unfold : (récepteur bus, guard RAII, ticker heartbeat, sync_envoyé). Le guard vit DANS
    // l'état -> il est droppé quand le flux (donc l'état) est droppé = à la déconnexion client.
    let stream = futures_util::stream::unfold(
        (rx, guard, ticker, false),
        move |(mut rx, guard, mut ticker, mut synced)| async move {
            if !synced {
                synced = true;
                let ev = Event::default()
                    .event("presence")
                    .json_data(json!({"event": "sync"}))
                    .unwrap_or_else(|_| Event::default().comment("sync"));
                return Some((Ok(ev), (rx, guard, ticker, synced)));
            }
            loop {
                tokio::select! {
                    r = rx.recv() => match r {
                        Ok(ev) if ev.run_id == PRESENCE_TOPIC => {
                            let ev2 = Event::default()
                                .event("presence")
                                .json_data(&ev.payload)
                                .unwrap_or_else(|_| Event::default().comment("presence"));
                            return Some((Ok(ev2), (rx, guard, ticker, synced)));
                        }
                        Ok(_) => continue, // event d'un run — pas de la présence
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // Buffer débordé : on demande au client une resync complète (re-fetch roster).
                            let ev = Event::default()
                                .event("presence")
                                .json_data(json!({"event": "resync"}))
                                .unwrap_or_else(|_| Event::default().comment("resync"));
                            return Some((Ok(ev), (rx, guard, ticker, synced)));
                        }
                        Err(broadcast::error::RecvError::Closed) => return None,
                    },
                    _ = ticker.tick() => {
                        // Heartbeat côté serveur : tant que le flux vit, la connexion reste « fraîche ».
                        if let Some(g) = guard.as_ref() {
                            g.reg.touch(&g.conn_id);
                        }
                        return Some((Ok(Event::default().comment("hb")), (rx, guard, ticker, synced)));
                    }
                }
            }
        },
    );

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(HEARTBEAT_TICK_SECS)).text("keep-alive"))
}

/// POST /api/presence/heartbeat — rafraîchit le TTL de TOUTES les connexions de l'appelant (léger, sans
/// conn_id). FAIL-CLOSED : sans identité, no-op. Complément du heartbeat interne du flux SSE (utile si le
/// client préfère un heartbeat explicite / proxy bufferisant le SSE).
async fn presence_heartbeat(
    State(app): State<App>,
    Extension(reg): Extension<PresenceRegistry>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match resolve_identity(&app, &headers) {
        Some(id) => {
            let n = reg.touch_login(&id.login);
            Json(json!({"ok": true, "refreshed": n}))
        }
        None => Json(json!({"ok": false, "refreshed": 0})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// join -> snapshot voit l'entrée ; leave -> disparaît.
    #[test]
    fn join_and_leave_roundtrip() {
        let reg = PresenceRegistry::default();
        reg.join("c1", "alice", "operator", Some(2));
        assert_eq!(reg.snapshot().len(), 1);
        let e = &reg.snapshot()[0];
        assert_eq!(e.login, "alice");
        assert_eq!(e.engagement_id, Some(2));
        reg.leave("c1");
        assert!(reg.snapshot().is_empty(), "leave retire l'entrée");
    }

    /// Un même login sur 2 connexions -> 2 entrées (dédupliquées à la lecture du roster, pas ici).
    #[test]
    fn multi_connection_same_login() {
        let reg = PresenceRegistry::default();
        reg.join("c1", "alice", "operator", Some(1));
        reg.join("c2", "alice", "operator", Some(1));
        assert_eq!(reg.snapshot().len(), 2, "2 connexions du même login = 2 entrées");
        assert_eq!(reg.touch_login("alice"), 2, "heartbeat rafraîchit les 2");
        assert_eq!(reg.touch_login("bob"), 0, "aucun match -> 0");
    }

    /// Une entrée dont le `last_seen` dépasse le TTL est GC-ée au snapshot.
    #[test]
    fn stale_entry_expires() {
        let reg = PresenceRegistry::default();
        reg.join("c1", "alice", "operator", None);
        // Force le last_seen dans le passé au-delà du TTL.
        {
            let mut m = reg.inner.lock().unwrap();
            m.get_mut("c1").unwrap().last_seen = now_epoch() - PRESENCE_TTL_SECS - 5;
        }
        assert!(reg.snapshot().is_empty(), "entrée périmée -> GC au snapshot");
    }

    /// Le topic de présence est distinct de l'espace des run_id (filtrage sûr sur le bus partagé).
    #[test]
    fn presence_topic_is_namespaced() {
        assert!(PRESENCE_TOPIC.starts_with("__"), "topic hors espace des run_id réels");
    }
}

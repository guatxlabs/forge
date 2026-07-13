// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — HA / ORCHESTRATION LEADER du run-lifecycle (PURE MOVE extrait de `runs.rs`). Réconcilie
//! les runs orphelins (`reconcile_runs`/`ReconcileScope`/`reap_dead_leader_runs`), la réservation FIFO
//! cancellation-safe (`RunReservation` guard RAII CONC-1 + `reserve_engagement_slot`), le spec résolu
//! (dé)sérialisable (`RunSpawnSpec`), l'enqueue/claim cross-instance (`enqueue_pending`/`claim_run_running`/
//! `unclaim_running_on_failure`), le cancel routé HA (`run_cancel_ha`) et la boucle du tick leader
//! (`LEADER_TICK_SECS`/`leader_tick_loop`/`cancel_watch_tick`/`claim_pending_tick`).
//!
//! Structs d'ÉTAT (App/RunState/RunHandle) + helpers de process (`kill_group`/`purge_stale_run_dirs`/
//! `push_run_log`/`claim_and_spawn`) référencés via `crate::*` ; re-exporté `pub(crate)` à la racine —
//! appelants (`run_create`, `run_cancel`, main.rs boot/leader-tick) ET tests inline (`super::*`) INCHANGÉS.
use crate::*;

use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use serde_json::{json, Value};

/// OWNER-SCOPING du réconciliateur de boot (HA #10 Wave B). Décide QUELS runs 'running' un boot peut
/// réaper et pour LESQUELS un `kill_group` (killpg) est SÛR (= même hôte) :
///   - `All` : single-instance / non-HA. Réape TOUS les 'running' et killpg TOUS les pgid vivants —
///     comportement HISTORIQUE byte-identique (un seul hôte, tout pgid enregistré est local).
///   - `BootOwner{me}` : boot-reconcile d'un réplica HA, appelé par le LEADER-TICK la 1re fois que cette
///     instance détient le bail (le boot main.rs ne peut pas le faire : `is_leader` est faux au boot). Un
///     leader qui redémarre-après-crash avec un instance_id STABLE a laissé SES PROPRES lignes 'running'
///     (owner=me) sans superviseur vivant (ce process neuf a un run_state VIDE). Réape UNIQUEMENT SES
///     orphelins — `owner_instance = me` OU NULL legacy même-hôte — et killpg les pgid correspondants. Ne
///     touche JAMAIS le run d'un pair VIVANT (owner=autre) : appel SÛR sur un process vivant (contrairement
///     à `All` dont l'UPDATE flippe tous les 'running'). Les orphelins d'un leader MORT (owner=autre) sont
///     réapés séparément par `reap_dead_leader_runs` (garde de liveness).
#[cfg_attr(not(feature = "store-postgres"), allow(dead_code))]
pub(crate) enum ReconcileScope {
    All,
    #[cfg_attr(not(feature = "store-postgres"), allow(dead_code))]
    BootOwner { me: String },
}

/// Réconcilie les run_job 'running' au boot : un process spawné qui n'a pas survécu au reboot de la
/// console est orphelin -> 'failed' (jamais laissé 'running' à tort). Opère sur la table (source de
/// vérité) : il traite en une passe TOUS les runs orphelins, quel que soit leur engagement — la
/// concurrence inter-engagement (plusieurs runs 'running' simultanés au crash) est gérée nativement,
/// chacun restant rattaché à SON engagement_id en base. En PLUS :
///   - tue le GROUPE de process (killpg) de tout pgid enregistré et encore vivant (un moteur détaché
///     qui aurait survécu à un simple restart console deviendrait sinon incontrôlable -> on le coupe) —
///     UNIQUEMENT pour les runs de CET hôte (voir `ReconcileScope`) ; jamais un pgid cross-host ;
///   - purge les dirs temp `forge-run-*` (scope.json/targets.json) laissés par des runs interrompus.
///
/// `scope=All` (single-instance / non-HA) reproduit EXACTEMENT le comportement historique. `scope=
/// BootOwner{me}` (boot leader HA) réape tous les orphelins mais restreint le killpg à l'hôte courant.
pub(crate) fn reconcile_runs(store: &crate::store::Store, scope: ReconcileScope) {
    // 1) collecter les pgid des runs 'running' pour lesquels un killpg est SÛR (= même hôte). En `All`
    //    tout pgid vivant ; en `BootOwner` seulement owner_instance=me OU NULL (legacy même-hôte). Un
    //    pgid cross-host (autre owner) n'est JAMAIS signalé (killpg d'un pid d'un autre hôte = non-sens
    //    voire dangereux). query_lax = idiome lenient (lignes mal formées sautées) ; erreur PREPARE ->
    //    unwrap_or_default() -> vec![] (parité `Err(_) => vec![]`).
    let orphan_pgids: Vec<i32> = match &scope {
        ReconcileScope::All => store
            .query_lax(
                "SELECT pid FROM run_job WHERE status='running' AND pid>1",
                &crate::sql_params![],
                |r| r.get_i64(0).map(|p| p as i32),
            )
            .unwrap_or_default(),
        ReconcileScope::BootOwner { me } => store
            .query_lax(
                "SELECT pid FROM run_job WHERE status='running' AND pid>1
                   AND (owner_instance=? OR owner_instance IS NULL)",
                &crate::sql_params![me.as_str()],
                |r| r.get_i64(0).map(|p| p as i32),
            )
            .unwrap_or_default(),
    };
    // 2) couper tout groupe encore vivant (best-effort ; SIGTERM via killpg). kill_group ignore <=1.
    for pgid in &orphan_pgids {
        kill_group(*pgid);
    }
    // 3) marquer les runs orphelins comme 'failed'.
    //    - `All` (mono-instance, au BOOT) : TOUS les 'running' sont orphelins (aucun superviseur vivant dans
    //      ce process) -> tous flippés. Comportement HISTORIQUE byte-identique.
    //    - `BootOwner{me}` (boot-reconcile HA, appelé par le leader-tick sur un process VIVANT) : l'UPDATE est
    //      OWNER-SCOPÉ (owner=me OU NULL legacy) — on ne flippe QUE MES PROPRES orphelins (et le legacy
    //      NULL même-hôte), JAMAIS le run d'un pair VIVANT (owner=autre). C'est ce qui rend l'appel SÛR
    //      hors-boot : un leader qui redémarre réconcilie ses lignes 'running' bloquées sans toucher les runs
    //      vivants d'un autre réplica. Les orphelins d'un leader MORT (owner=autre) sont réapés séparément
    //      par `reap_dead_leader_runs` (garde de liveness), pas ici.
    let n = match &scope {
        ReconcileScope::All => store
            .execute(
                "UPDATE run_job SET status='failed', finished=datetime('now'), pid=-1,
                   detail=COALESCE(NULLIF(detail,''),'')||' [reconciled: orphelin au boot]'
                 WHERE status='running'",
                &crate::sql_params![],
            )
            .unwrap_or(0),
        ReconcileScope::BootOwner { me } => store
            .execute(
                "UPDATE run_job SET status='failed', finished=datetime('now'), pid=-1,
                   detail=COALESCE(NULLIF(detail,''),'')||' [reconciled: boot leader — orphelin owner-scopé]'
                 WHERE status='running' AND (owner_instance=? OR owner_instance IS NULL)",
                &crate::sql_params![me.as_str()],
            )
            .unwrap_or(0),
    };
    if n > 0 {
        println!(
            "[forge] reconcile: {n} run(s) orphelin(s) 'running' -> 'failed' ({} groupe(s) local/(aux) signalé(s))",
            orphan_pgids.len()
        );
    }
    // 4) purge des dirs temp de runs (forge-run-*) laissés derrière par des runs interrompus.
    purge_stale_run_dirs();
}

/// FAILOVER cleanup (HA #10 Wave B) — appelé PÉRIODIQUEMENT par le tick du leader VIVANT (jamais au
/// boot). Contrairement à `reconcile_runs` (boot : aucun superviseur vivant), le leader courant A ses
/// PROPRES runs vivants (owner=me, superviseurs actifs) qu'il ne doit JAMAIS toucher. Il réape donc
/// UNIQUEMENT les orphelins des LEADERS RÉELLEMENT MORTS.
///
/// CORRECTNESS DU FLAP (Fix #3) : on NE réape PAS en aveugle tout `owner<>me`. Un ancien leader peut être
/// simplement DEMOTED-MAIS-VIVANT (flap : partition/lenteur — son bail a expiré donc j'ai pu prendre le
/// relais, mais son PROCESS tourne encore et son superviseur pompe TOUJOURS son run). Le flipper 'failed'
/// dé-synchroniserait la base d'un moteur bien vivant. On consulte donc la LIVENESS PAR-INSTANCE
/// (`ha_instance.last_seen`, rafraîchie par le heartbeat de CHAQUE réplica) : un owner est MORT ssi il n'a
/// AUCUN heartbeat frais (`last_seen >= now-TTL`). On ne réape que les runs d'un owner MORT ; le run d'un
/// pair VIVANT (heartbeat frais) est laissé intact. Marqué 'failed' SANS killpg (les pgid sont sur l'hôte
/// mort, ininterprétables ici). Ne touche NI owner=me (vivants) NI owner NULL (legacy/pending). Renvoie le
/// nombre de runs réapés.
///
/// Compilé sous `store-postgres` (chemin runtime : appelé par le tick leader) OU `test` (exercé sur
/// SQLite par `cargo test` — la garde owner-scope + liveness est dialect-portable). La communauté NON-test
/// ne le compile pas (jamais appelé sans HA) -> aucun dead code.
#[cfg(any(feature = "store-postgres", test))]
pub(crate) fn reap_dead_leader_runs(store: &crate::store::Store, me: &str) -> usize {
    // cutoff = now - TTL : un owner sans ligne ha_instance OU dont le last_seen est < cutoff est MORT.
    let cutoff = crate::now_epoch() - crate::ha::LEASE_TTL_SECS;
    store
        .execute(
            "UPDATE run_job SET status='failed', finished=datetime('now'), pid=-1,
               detail=COALESCE(NULLIF(detail,''),'')||' [reconciled: leader mort — orphelin failover]'
             WHERE status='running' AND owner_instance IS NOT NULL AND owner_instance<>?
               AND owner_instance NOT IN (SELECT instance_id FROM ha_instance WHERE last_seen >= ?)",
            &crate::sql_params![me, cutoff],
        )
        .unwrap_or(0)
}

/// Guard RAII CANCELLATION-SAFE de la réservation de slot FIFO d'un engagement (CONC-1).
///
/// PROBLÈME résolu : `run_create` réserve le slot FIFO d'un engagement AVANT de faire le travail lourd
/// (écritures fs, INSERT DB, spawn, appends ledger) SANS tenir le verrou async `run_state` pendant tout
/// ce temps (deux engagements différents peuvent donc démarrer EN PARALLÈLE). La réservation vit dans
/// `App.run_reservations` (set std synchrone). Si le future du handler est DROPPÉ à un point d'`.await`
/// AVANT la promotion en run vivant (déconnexion client / annulation), une libération faite par une
/// re-lock AWAITÉE ne s'exécuterait JAMAIS -> le slot fuiterait définitivement (409 erroné à chaque
/// retry du même engagement). Ce guard corrige ça : son `Drop` est SYNCHRONE et s'exécute sur retour
/// normal, early-return, panic ET drop-du-future. Tant que `active`, il retire `eng_id` du set.
///
/// Sur SUCCÈS, l'appelant insère le `RunHandle` réel dans `run_state` puis met `active=false` : le Drop
/// devient un no-op (la réservation est PROMUE en run vivant, pas simplement libérée — pas de
/// double-libération, pas de fenêtre où ni la réservation ni le run vivant n'existeraient).
pub(crate) struct RunReservation<'a> {
    app: &'a App,
    eng_id: i64,
    pub(crate) active: bool,
}

impl Drop for RunReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            // Verrou std SYNCHRONE tenu quelques microsecondes (jamais à travers un `.await`).
            // Poison-safe (comme App::db) : un panic ailleurs ne doit pas empêcher la libération.
            let mut resv = self.app.run_reservations.lock().unwrap_or_else(|e| e.into_inner());
            resv.remove(&self.eng_id);
        }
    }
}

/// FIFO PAR ENGAGEMENT — réserve (cancellation-safe) le slot du run vivant de `eng_id`. Prend le verrou
/// async `run_state` (juste `contains_key`) ET le verrou std `run_reservations` (microsecondes), décide
/// ET pose la réservation, PUIS relâche les DEUX (le travail lourd se fait sans verrou). `Some(guard)` si
/// le slot était libre (réservation posée ; le guard RAII la libère sur tout chemin de sortie tant qu'il
/// est `active`), `None` si un run est déjà VIVANT ou RÉSERVÉ pour CET engagement (-> l'appelant renvoie
/// 409 / laisse pending). ISOLATION : clé = eng_id ; un autre engagement (autre clé) n'entrave rien.
/// Aucun verrou tenu à travers un `.await` (le std `run_reservations` en particulier ne l'est jamais).
// ALLOW significant_drop_tightening: the two guards form ONE atomic check-then-act (contains_key/
// contains -> insert). Both MUST span the check AND the insert; tightening either would open a TOCTOU
// window where a concurrent reservation could interleave between check and insert (double-spawn). The
// hold is the correctness guarantee, not incidental.
#[allow(clippy::significant_drop_tightening)]
pub(crate) async fn reserve_engagement_slot(app: &App, eng_id: i64) -> Option<RunReservation<'_>> {
    let state = app.run_state.lock().await;
    // std Mutex : jamais tenu à travers un `.await` ; poison-safe.
    let mut resv = app.run_reservations.lock().unwrap_or_else(|e| e.into_inner());
    if state.current.contains_key(&eng_id) || resv.contains(&eng_id) {
        return None;
    }
    resv.insert(eng_id);
    Some(RunReservation { app, eng_id, active: true })
    // les DEUX verrous sont relâchés à la sortie du bloc — le travail lourd de l'appelant n'en tient AUCUN.
}

/// RÉSOLU (validé) d'un run, capturé APRÈS toute la validation stateless de `run_create`. Source UNIQUE de
/// `claim_and_spawn` — le SPAWN DIRECT (leader / mono-instance) le passe par référence ; le chemin
/// ENQUEUE-PENDING (HA non-leader) le SÉRIALISE (`to_value`) dans `run_job.spawn_spec` et le leader le
/// RECONSTRUIT (`from_value`) au moment de claimer. Pas de `#[derive(Serialize)]` (le crate n'a que
/// `serde_json`) : (dé)sérialisation MANUELLE via `serde_json::Value`, portable sur les deux backends.
pub(crate) struct RunSpawnSpec {
    pub(crate) run_id: String,
    pub(crate) eng_id: i64,
    pub(crate) eng_mode: String,
    pub(crate) eng_scope_out: Vec<String>,
    pub(crate) eng_ledger_path: String,
    pub(crate) campaign: String,
    pub(crate) targets: Vec<String>,          // cibles VALIDÉES ⊆ scope de l'engagement
    pub(crate) requested_modules: Vec<String>,
    pub(crate) module_params: Value,          // objet {kind: {params}}
    pub(crate) mode: String,                  // "auto" | "propose"
    pub(crate) budget: Option<f64>,
    pub(crate) exhaustive: bool,
    pub(crate) auto_pentest: bool,
    pub(crate) reason: String,
    pub(crate) arm: bool,
    pub(crate) high_impact: bool,             // opt-in haut-impact DÉJÀ gaté (operator+arm+reason)
    pub(crate) started_by: String,
    pub(crate) actor: String,
    pub(crate) selection: Value,              // technique_selection résolue
    pub(crate) disabled_modules: Vec<String>,
    pub(crate) body_targets: Value,           // body["targets"] d'origine (colonne run_job.targets + ledger)
    pub(crate) rate: Option<i64>,             // débit req/s OPT-IN (override per-run) : None => défaut 5, byte-identique
}

impl RunSpawnSpec {
    /// Sérialise le spec en `Value` JSON (stocké dans run_job.spawn_spec sur le chemin pending).
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "run_id": self.run_id, "eng_id": self.eng_id, "eng_mode": self.eng_mode,
            "eng_scope_out": self.eng_scope_out, "eng_ledger_path": self.eng_ledger_path,
            "campaign": self.campaign, "targets": self.targets, "requested_modules": self.requested_modules,
            "module_params": self.module_params, "mode": self.mode, "budget": self.budget,
            "exhaustive": self.exhaustive, "auto_pentest": self.auto_pentest, "reason": self.reason,
            "arm": self.arm, "high_impact": self.high_impact, "started_by": self.started_by,
            "actor": self.actor, "selection": self.selection, "disabled_modules": self.disabled_modules,
            "body_targets": self.body_targets, "rate": self.rate,
        })
    }

    /// Reconstruit le spec depuis un `Value` (parsé de run_job.spawn_spec par le leader qui claime).
    /// `None` si le blob est corrompu (le leader marque alors le run failed et passe au suivant).
    /// Consommé UNIQUEMENT par le tick leader (`claim_pending_tick`, PG-only) — inerte en community.
    #[cfg_attr(not(feature = "store-postgres"), allow(dead_code))]
    pub(crate) fn from_value(v: &Value) -> Option<Self> {
        Some(RunSpawnSpec {
            run_id: v.get("run_id")?.as_str()?.to_string(),
            eng_id: v.get("eng_id")?.as_i64()?,
            eng_mode: v.get("eng_mode").and_then(|x| x.as_str()).unwrap_or("grey").to_string(),
            eng_scope_out: scope_json_list(v, "eng_scope_out"),
            eng_ledger_path: v.get("eng_ledger_path").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            campaign: v.get("campaign").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            targets: scope_json_list(v, "targets"),
            requested_modules: scope_json_list(v, "requested_modules"),
            module_params: v.get("module_params").cloned().unwrap_or_else(|| json!({})),
            mode: v.get("mode").and_then(|x| x.as_str()).unwrap_or("propose").to_string(),
            budget: v.get("budget").and_then(|x| x.as_f64()),
            exhaustive: v.get("exhaustive").and_then(|x| x.as_bool()).unwrap_or(false),
            auto_pentest: v.get("auto_pentest").and_then(|x| x.as_bool()).unwrap_or(false),
            reason: v.get("reason").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            arm: v.get("arm").and_then(|x| x.as_bool()).unwrap_or(false),
            high_impact: v.get("high_impact").and_then(|x| x.as_bool()).unwrap_or(false),
            started_by: v.get("started_by").and_then(|x| x.as_str()).unwrap_or("operator").to_string(),
            actor: v.get("actor").and_then(|x| x.as_str()).unwrap_or("operator").to_string(),
            selection: v.get("selection").cloned().unwrap_or_else(|| json!({})),
            disabled_modules: scope_json_list(v, "disabled_modules"),
            body_targets: v.get("body_targets").cloned().unwrap_or_else(|| json!([])),
            rate: v.get("rate").and_then(|x| x.as_i64()),
        })
    }
}

/// ENQUEUE d'un run 'pending' (HA, instance NON-leader). Persiste le run_job en `status='pending'`,
/// `owner_instance=NULL`, `spawn_spec=<blob JSON du spec>` — TOUT ce qu'il faut au leader pour reconstruire
/// et spawner. Renseigne aussi les colonnes standard (campaign/mode/reason/targets/modules/started_by/
/// engagement_id) pour que /api/runs affiche le pending. N'écrit AUCUN ledger console.run.start (écrivain
/// unique = le leader au moment du claim). Renvoie 202 {run_id, status:"pending"}.
pub(crate) fn enqueue_pending(app: &App, spec: &RunSpawnSpec) -> (StatusCode, Json<Value>) {
    let spec_json = spec.to_value().to_string();
    {
        let store = app.store();
        // FAIL-CLOSED : on MATCHE le Result de l'enqueue. `Ok(_)` (y compris ON CONFLICT DO NOTHING -> 0 ligne,
        // enqueue idempotent d'un run_id déjà en file) -> 202 pending BYTE-IDENTIQUE. `Err` (lock/disque/pg) ->
        // 500 : sans ça, on renverrait un faux 202 « pending » alors que RIEN n'a été mis en file (le leader
        // ne claimera jamais un run inexistant, et l'appelant croirait son run accepté).
        if let Err(e) = store.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,mode,pid,started_by,reason,targets,modules,started,engagement_id,owner_instance,spawn_spec)
             VALUES(?,?,datetime('now'),'pending',?,-1,?,?,?,?,'',?,NULL,?)
             ON CONFLICT(run_id) DO NOTHING",
            &crate::sql_params![
                spec.run_id.as_str(), spec.campaign.as_str(), spec.mode.as_str(), spec.started_by.as_str(), spec.reason.as_str(),
                serde_json::to_string(&spec.body_targets).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&spec.requested_modules).unwrap_or_else(|_| "[]".into()),
                spec.eng_id,
                spec_json.as_str()
            ],
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "enqueue_failed", "why": format!("mise en file du run échouée: {e}")})));
        }
    }
    (StatusCode::ACCEPTED, Json(json!({"run_id": spec.run_id, "status": "pending", "campaign": spec.campaign, "mode": spec.mode, "high_impact": spec.high_impact, "auto_pentest": spec.auto_pentest})))
}

/// GARDE AUTORITATIVE CROSS-INSTANCE (HA #10 Wave B, Fix #2) — transition ATOMIQUE d'un run vers 'running'
/// AVANT tout spawn. C'est LE point de fencing unique cross-réplica : l'INDEX UNIQUE PARTIEL
/// `run_job(engagement_id) WHERE status='running'` fait ÉCHOUER la transition si un AUTRE run 'running'
/// existe déjà pour le même engagement (double-spawn d'un leader périmé pendant un flap) -> on ne spawne
/// JAMAIS de 2e moteur pour un même engagement. UPSERT couvrant les DEUX chemins leader :
///   - DIRECT (ligne absente) : INSERT d'une ligne 'running' NEUVE (pid=-1 placeholder, owner=me + colonnes
///     standard du spec). L'index partiel la REFUSE (Err -> false) si l'engagement a déjà un run 'running'.
///   - CLAIM-PENDING (ligne 'pending' posée par enqueue_pending) : conflit run_id -> DO UPDATE gardé
///     `WHERE status='pending'` -> flip 'pending'->'running' + owner=me. Refusé de même par l'index partiel
///     si un autre run 'running' existe pour l'engagement (Err -> false) ; n=0 -> false si la ligne n'est
///     plus 'pending' (déjà claimée/annulée par un autre réplica dans la course).
///
/// Renvoie true SSI EXACTEMENT une ligne a été claimée. `pid`/`started` réels sont posés APRÈS le spawn
/// (claim_and_spawn). TOUJOURS compilé : référencé par claim_and_spawn dans une branche `if ha` que
/// l'optimiseur élague en community (HA off, const-fold) -> byte-identique ; exercé sur SQLite par cargo test.
pub(crate) fn claim_run_running(store: &crate::store::Store, spec: &RunSpawnSpec, owner: &str) -> bool {
    store
        .execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,mode,pid,started_by,reason,targets,modules,started,engagement_id,owner_instance)
             VALUES(?,?,datetime('now'),'running',?,-1,?,?,?,?,'',?,?)
             ON CONFLICT(run_id) DO UPDATE SET status='running', owner_instance=excluded.owner_instance
               WHERE run_job.status='pending'",
            &crate::sql_params![
                spec.run_id.as_str(), spec.campaign.as_str(), spec.mode.as_str(), spec.started_by.as_str(), spec.reason.as_str(),
                serde_json::to_string(&spec.body_targets).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&spec.requested_modules).unwrap_or_else(|_| "[]".into()),
                spec.eng_id,
                owner
            ],
        )
        .unwrap_or(0)
        == 1
}

/// UN-CLAIM (HA #10 Wave B, Fix #2) — quand le claim PRÉ-SPAWN a réussi (ligne 'running', pid=-1) mais que
/// l'écriture fs OU le spawn échoue ENSUITE, on ne doit pas laisser une ligne 'running' ORPHELINE (sans
/// process). On la marque 'failed'. No-op si `!ha` (le chemin mono-instance n'a jamais claimé pré-spawn ->
/// aucune ligne à nettoyer). TOUJOURS compilé (référencé par claim_and_spawn) ; élagué en community (ha=false).
pub(crate) fn unclaim_running_on_failure(app: &App, run_id: &str, ha: bool) {
    if ha {
        let store = app.store();
        let _ = store.execute(
            "UPDATE run_job SET status='failed', finished=datetime('now'), pid=-1,
               detail=COALESCE(NULLIF(detail,''),'')||' [claim: échec fs/spawn après claim pré-spawn]'
             WHERE run_id=? AND status='running'",
            &crate::sql_params![run_id],
        );
    }
}

/// HA (#10 Wave B) — CANCEL routé quand HA est engagé (appelé par `run_cancel`). Écrit l'intention
/// 'cancelled' DURABLE (conditionnel : n'ouvre pas un run déjà terminal) + le ledger console.run.cancel,
/// sur N'IMPORTE QUEL réplica. Si le run est LOCAL (dans MON run_state -> `my_pgid`>1, je suis le
/// propriétaire) je `kill_group` MAINTENANT ; sinon le PROPRIÉTAIRE (leader) l'observe via son cancel-watch
/// tick et coupe — JAMAIS un pgid cross-host. Annule aussi un run 'pending' (le leader ne le claimera pas).
/// 404 si inconnu, 409 si déjà terminal (parité avec le chemin mono-instance). Portable (compilé partout)
/// mais atteint UNIQUEMENT sous HA (`ha_enabled` gate l'appel).
pub(crate) async fn run_cancel_ha(app: &App, headers: &HeaderMap, id: &str, my_pgid: i32) -> (StatusCode, Json<Value>) {
    // statut courant — source de vérité = base PARTAGÉE (le run peut vivre sur un autre réplica).
    let status: Option<String> = {
        let store = app.store();
        store.query_opt("SELECT status FROM run_job WHERE run_id=?", &crate::sql_params![id], |r| r.get_str(0)).unwrap_or(None)
    };
    let status = match status {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"}))),
    };
    if status != "running" && status != "pending" {
        return (StatusCode::CONFLICT, Json(json!({"error": "not_running", "why": "le run n'est pas en cours"})));
    }
    // intention DURABLE : running|pending -> cancelled (conditionnel : ne ré-ouvre pas un terminal).
    {
        let store = app.store();
        let _ = store.execute("UPDATE run_job SET status='cancelled' WHERE run_id=? AND status IN ('running','pending')", &crate::sql_params![id]);
    }
    let actor = attribution_login(app, headers);
    let cancel_ledger = engagement_ledger_for_run(app, id);
    append_run_ledger_path(app, &cancel_ledger, "console.run.cancel", json!({"run_id": id, "actor": actor, "by": "operator"}));
    if my_pgid > 1 {
        // run LOCAL (je suis le propriétaire) -> kill immédiat, comme en mono-instance.
        push_run_log(app, id, "system", &format!("cancel demandé par '{actor}' — kill group (propriétaire local)"));
        kill_group(my_pgid);
    } else {
        // run distant (autre hôte) ou pending -> l'intention 'cancelled' suffit ; le propriétaire coupe via son tick.
        push_run_log(app, id, "system", &format!("cancel demandé par '{actor}' — intention 'cancelled' persistée ; coupé par le propriétaire (HA)"));
    }
    (StatusCode::OK, Json(json!({"run_id": id, "status": "cancelling"})))
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// LEADER TICK (HA #10 Wave B) — la boucle périodique du DÉTENTEUR DU BAIL. Spawné UNIQUEMENT quand HA est
// engagé (main.rs, `if app.ha`). PG-only (référence `app.instance_id`). À chaque tick, SI je suis le
// leader courant (`is_leader`), il fait TROIS choses, dans l'ordre :
//   1. FAILOVER — réape les runs 'running' des LEADERS MORTS (owner<>moi, bail expiré -> marqués failed,
//      SANS killpg cross-host) ;
//   2. CANCEL-WATCH — pour chacun de MES runs vivants (run_state), si la base dit 'cancelled', kill_group
//      local (c'est ainsi qu'un cancel arrivé sur un AUTRE réplica est exécuté par le propriétaire) ;
//   3. CLAIM — draine la file 'pending' (FIFO par engagement) : réserve le slot local, claim ATOMIQUE
//      (UPDATE … WHERE status='pending' -> race-safe entre flaps de leader), reconstruit le spec et spawn.
// Un non-leader (le tick tourne sur tous les réplicas HA) NE fait RIEN (court sous `is_leader`).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Cadence du tick leader (s). Court : les runs 'pending' sont claimés promptement, et un cancel arrivé
/// sur un autre réplica est exécuté par le propriétaire en ~quelques secondes.
#[cfg(feature = "store-postgres")]
pub(crate) const LEADER_TICK_SECS: u64 = 3;

/// Boucle du tick leader (voir l'en-tête de section). Spawné par main.rs quand `app.ha`. Ne fait le
/// travail QUE si `is_leader` (le bail est à moi) ; sinon tick à vide (défense : si je perds le bail je
/// cesse immédiatement de claimer/reaper). Le `Store` guard (`!Send`) est scoppé à des blocs synchrones,
/// DROPPÉ avant chaque `.await` -> le future reste `Send` (spawnable).
#[cfg(feature = "store-postgres")]
pub(crate) async fn leader_tick_loop(app: App) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(LEADER_TICK_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // (Fix #1) BOOT-RECONCILE DIFFÉRÉ : sous HA `is_leader` est FAUX au boot (le heartbeat le bascule
    // APRÈS main.rs), donc le boot-reconcile ne peut pas tourner dans main.rs. On l'exécute ICI, UNE SEULE
    // FOIS, la 1re fois que CETTE instance détient le bail. Un leader qui redémarre-après-crash avec un
    // instance_id STABLE a laissé SES PROPRES lignes 'running' (owner=me) sans superviseur vivant (ce
    // process neuf a un run_state VIDE) : le boot-reconcile OWNER-SCOPÉ (reconcile_runs(BootOwner{me})) les
    // réape une fois le leadership acquis. Ne touche JAMAIS le run d'un pair vivant (owner=autre).
    let mut boot_reconciled = false;
    loop {
        ticker.tick().await;
        if !crate::ha::is_leader(&app) {
            continue; // pas (ou plus) leader -> aucun claim/reap/kill (fail-closed sur le leadership)
        }
        let me = match crate::ha::my_instance_id(&app) {
            Some(m) => m,
            None => continue, // ha engagé mais pas d'identité (ne devrait pas arriver) -> ne rien faire
        };
        // 0) BOOT-RECONCILE (une seule fois, à la 1re prise de leadership) — mes propres orphelins (owner=me
        //    OU NULL legacy) d'un crash antérieur -> 'failed' + killpg local. Différé du boot (cf. supra).
        if !boot_reconciled {
            {
                let store = app.store();
                reconcile_runs(&store, ReconcileScope::BootOwner { me: me.clone() });
            }
            boot_reconciled = true;
        }
        // 1) FAILOVER — réape les orphelins des leaders MORTS (owner=autre + heartbeat périmé). Marqués
        //    'failed' ; jamais killpg cross-host ; JAMAIS le run d'un pair VIVANT (garde de liveness).
        {
            let store = app.store();
            let n = reap_dead_leader_runs(&store, &me);
            drop(store);
            if n > 0 {
                println!("[forge] leader-tick: {n} run(s) orphelin(s) d'un leader mort -> 'failed' (failover, sans killpg cross-host)");
            }
        }
        // 2) CANCEL-WATCH — coupe MES runs vivants dont l'intention DB est 'cancelled'.
        cancel_watch_tick(&app).await;
        // 3) CLAIM — draine la file 'pending' (FIFO par engagement ; claim atomique dans claim_and_spawn).
        claim_pending_tick(&app).await;
    }
}

/// CANCEL-WATCH (tick leader) — pour chacun de MES runs vivants (run_state), si la base partagée dit
/// 'cancelled', fait le `kill_group` local. C'est le maillon qui exécute un cancel arrivé sur un AUTRE
/// réplica : le réplica-récepteur a persisté 'cancelled' (run_cancel_ha), le PROPRIÉTAIRE (moi, leader)
/// l'observe ici et coupe. `kill_group` (SIGTERM) est idempotent -> re-signaler un groupe déjà mourant est
/// sans effet ; le superviseur finalise en 'cancelled' (préservé) et retire le run de run_state.
#[cfg(feature = "store-postgres")]
pub(crate) async fn cancel_watch_tick(app: &App) {
    // snapshot de MES runs vivants (verrou async relâché avant les lectures DB).
    let live: Vec<(String, i32)> = {
        let st = app.run_state.lock().await;
        st.current.values().map(|h| (h.run_id.clone(), h.pgid)).collect()
    };
    for (run_id, pgid) in live {
        if pgid <= 1 {
            continue;
        }
        let cancelled: bool = {
            let store = app.store();
            store
                .query_row("SELECT 1 FROM run_job WHERE run_id=? AND status='cancelled'", &crate::sql_params![run_id.as_str()], |_| Ok(()))
                .is_ok()
        };
        if cancelled {
            push_run_log(app, &run_id, "system", "cancel observé (HA) — kill group par le propriétaire");
            kill_group(pgid);
        }
    }
}

/// CLAIM (tick leader) — draine la file 'pending' en FIFO PAR ENGAGEMENT. Pour chaque run 'pending' (par
/// id croissant) : (a) RECONSTRUIT le spec depuis `spawn_spec` (blob corrompu -> marque 'failed' la ligne
/// ENCORE 'pending', passe) ; (b) RÉSERVE le slot local de son engagement (occupé -> laisse pending, FIFO) ;
/// (c) SPAWNE via `claim_and_spawn`, qui fait LUI-MÊME le CLAIM ATOMIQUE `pending -> running` (garde
/// autoritative + INDEX UNIQUE PARTIEL par engagement) AVANT le spawn : c'est le point de fencing unique
/// (Fix #2). Si le claim est perdu (flap : un autre réplica a gagné la ligne, ou un autre run 'running'
/// existe déjà pour l'engagement), `claim_and_spawn` renvoie 409 SANS spawner et libère la réservation
/// (Drop) — aucune ligne 'running' orpheline sans process. L'ordre réserve-PUIS-claim(dans claim_and_spawn)
/// garantit qu'on ne flippe JAMAIS pending->running sans tenir le slot.
#[cfg(feature = "store-postgres")]
pub(crate) async fn claim_pending_tick(app: &App) {
    // liste des runs pending (run_id, engagement_id, spawn_spec). Lecture lax (lignes mal formées sautées).
    let pendings: Vec<(String, i64, String)> = {
        let store = app.store();
        store
            .query_lax(
                "SELECT run_id, engagement_id, spawn_spec FROM run_job WHERE status='pending' ORDER BY id",
                &crate::sql_params![],
                |r| Ok((r.get_str(0)?, r.get_i64(1)?, r.get_opt_str(2)?.unwrap_or_default())),
            )
            .unwrap_or_default()
    };
    for (run_id, eng_id, spec_json) in pendings {
        // (a) RECONSTRUIT le spec AVANT de réserver/claimer (parse pur, sans effet). Blob corrompu -> marque
        //     'failed' la ligne ENCORE 'pending' (le claim ne l'a pas encore flippée), passe au suivant.
        let spec = serde_json::from_str::<Value>(&spec_json)
            .ok()
            .and_then(|v| RunSpawnSpec::from_value(&v));
        let spec = match spec {
            Some(s) => s,
            None => {
                
                let _ = (app.store()).execute(
                    "UPDATE run_job SET status='failed', finished=datetime('now'), pid=-1,
                       detail=COALESCE(NULLIF(detail,''),'')||' [claim: spawn_spec corrompu]'
                     WHERE run_id=? AND status='pending'",
                    &crate::sql_params![run_id.as_str()],
                );
                continue;
            }
        };
        // (b) RÉSERVE le slot local — occupé -> laisse pending (FIFO : ce run attend que le slot se libère).
        let reservation = match reserve_engagement_slot(app, eng_id).await {
            Some(r) => r,
            None => continue,
        };
        // (c) SPAWN : claim_and_spawn fait le claim atomique pending->running (garde autoritative) AVANT le
        //     spawn ; owner=me y est posé (my_instance_id). Retour HTTP ignoré (409 = claim perdu -> réservation
        //     déjà libérée par le Drop). Le run_id du spec est celui de la ligne pending (cohérence garantie).
        let _ = claim_and_spawn(app, &spec, reservation).await;
    }
}

#[cfg(test)]
mod wave_b_tests {
    use super::*;
    use crate::store::Store;

    /// Connexion SQLite en mémoire avec le SCHEMA de base + migrate (colonnes run_job étendues :
    /// pid/started/owner_instance/spawn_spec), enveloppée dans un Mutex (modèle de garde tenue par appel).
    fn mem() -> std::sync::Mutex<rusqlite::Connection> {
        let conn = rusqlite::Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        crate::migrate(&conn);
        std::sync::Mutex::new(conn)
    }

    // `eng_id` DISTINCT par run 'running' d'un même test : l'INDEX UNIQUE PARTIEL (Fix #2) interdit
    // désormais deux 'running' pour un même engagement (l'invariant qu'il garantit). Les tests de reap/
    // reconcile (owner-scopé, sans filtre d'engagement) modélisent des runs d'owners différents -> chacun
    // sur son engagement pour pouvoir coexister en 'running'.
    fn insert_run(m: &std::sync::Mutex<rusqlite::Connection>, run_id: &str, status: &str, pid: i64, owner: Option<&str>, eng_id: i64) {
        let s = Store::sqlite(m.lock().unwrap());
        s.execute(
            "INSERT INTO run_job(run_id,status,pid,owner_instance,engagement_id) VALUES(?,?,?,?,?)",
            &crate::sql_params![run_id, status, pid, owner.map(|x| x.to_string()), eng_id],
        )
        .expect("insert run");
    }

    fn status_of(m: &std::sync::Mutex<rusqlite::Connection>, run_id: &str) -> String {
        Store::sqlite(m.lock().unwrap())
            .query_row("SELECT status FROM run_job WHERE run_id=?", &crate::sql_params![run_id], |r| r.get_str(0))
            .unwrap()
    }

    /// Enregistre un heartbeat de liveness pour `instance_id` avec `last_seen` donné (frais = now_epoch()).
    fn set_heartbeat(m: &std::sync::Mutex<rusqlite::Connection>, instance_id: &str, last_seen: i64) {
        Store::sqlite(m.lock().unwrap())
            .execute(
                "INSERT INTO ha_instance(instance_id,last_seen) VALUES(?,?) ON CONFLICT(instance_id) DO UPDATE SET last_seen=?",
                &crate::sql_params![instance_id, last_seen, last_seen],
            )
            .expect("heartbeat");
    }

    /// Spec minimal pour un engagement donné (pour exercer `claim_run_running` sur SQLite).
    fn spec_for(run_id: &str, eng_id: i64) -> RunSpawnSpec {
        RunSpawnSpec {
            run_id: run_id.into(), eng_id, eng_mode: "grey".into(), eng_scope_out: vec![],
            eng_ledger_path: String::new(), campaign: "c".into(), targets: vec![], requested_modules: vec![],
            module_params: serde_json::json!({}), mode: "propose".into(), budget: None, exhaustive: false,
            auto_pentest: false, reason: String::new(), arm: false, high_impact: false,
            started_by: "op".into(), actor: "op".into(), selection: serde_json::json!({}),
            disabled_modules: vec![], body_targets: serde_json::json!([]), rate: None,
        }
    }

    /// Le spec RÉSOLU (RunSpawnSpec) survit à un aller-retour to_value/from_value SANS PERTE — c'est le
    /// contrat qui permet au leader de reconstruire scope.json/targets.json/argv à l'identique depuis
    /// run_job.spawn_spec sur le chemin claim-pending.
    #[test]
    fn run_spawn_spec_roundtrip_is_lossless() {
        let spec = RunSpawnSpec {
            run_id: "run-x-1".into(),
            eng_id: 7,
            eng_mode: "black".into(),
            eng_scope_out: vec!["out.example.com".into()],
            eng_ledger_path: "/tmp/eng7.jsonl".into(),
            campaign: "camp".into(),
            targets: vec!["a.example.com".into(), "b.example.com".into()],
            requested_modules: vec!["httpx".into(), "nuclei".into()],
            module_params: serde_json::json!({"nuclei": {"severity": "high"}}),
            mode: "auto".into(),
            budget: Some(12.5),
            exhaustive: true,
            auto_pentest: true,
            reason: "authorized test".into(),
            arm: true,
            high_impact: true,
            started_by: "alice+high_impact".into(),
            actor: "alice".into(),
            selection: serde_json::json!({"profile": "bug_bounty", "categories": {"idor": true}, "techniques": {}}),
            disabled_modules: vec!["sqlmap".into()],
            body_targets: serde_json::json!(["a.example.com", "b.example.com"]),
            rate: Some(25),
        };
        let round = RunSpawnSpec::from_value(&spec.to_value()).expect("reconstruct");
        assert_eq!(round.run_id, spec.run_id);
        assert_eq!(round.eng_id, spec.eng_id);
        assert_eq!(round.eng_mode, spec.eng_mode);
        assert_eq!(round.eng_scope_out, spec.eng_scope_out);
        assert_eq!(round.eng_ledger_path, spec.eng_ledger_path);
        assert_eq!(round.campaign, spec.campaign);
        assert_eq!(round.targets, spec.targets);
        assert_eq!(round.requested_modules, spec.requested_modules);
        assert_eq!(round.module_params, spec.module_params);
        assert_eq!(round.mode, spec.mode);
        assert_eq!(round.budget, spec.budget);
        assert_eq!(round.exhaustive, spec.exhaustive);
        assert_eq!(round.auto_pentest, spec.auto_pentest);
        assert_eq!(round.reason, spec.reason);
        assert_eq!(round.arm, spec.arm);
        assert_eq!(round.high_impact, spec.high_impact);
        assert_eq!(round.started_by, spec.started_by);
        assert_eq!(round.actor, spec.actor);
        assert_eq!(round.selection, spec.selection);
        assert_eq!(round.disabled_modules, spec.disabled_modules);
        assert_eq!(round.body_targets, spec.body_targets);
        assert_eq!(round.rate, spec.rate);
        // blob corrompu -> None (le leader marque failed et passe au suivant).
        assert!(RunSpawnSpec::from_value(&serde_json::json!({"garbage": 1})).is_none(), "spec sans run_id/eng_id => None");
    }

    /// FAILOVER : `reap_dead_leader_runs(me)` marque 'failed' UNIQUEMENT les 'running' d'un AUTRE owner
    /// MORT (aucun heartbeat frais dans ha_instance) ; il ne touche NI mes runs vivants (owner=me) NI les
    /// legacy (owner NULL) NI les runs déjà terminaux. Ici "old-leader" n'a AUCUN heartbeat -> mort -> réapé.
    #[test]
    fn reap_dead_leader_runs_owner_scoped() {
        let m = mem();
        insert_run(&m, "mine", "running", 100, Some("me"), 1);      // vivant chez moi -> préservé
        insert_run(&m, "dead", "running", 200, Some("old-leader"), 2); // orphelin leader mort (pas de heartbeat) -> failed
        insert_run(&m, "legacy", "running", 300, None, 3);          // legacy NULL -> préservé (jamais réapé à chaud)
        insert_run(&m, "done-other", "done", 400, Some("old-leader"), 4); // déjà terminal -> intouché

        let n = reap_dead_leader_runs(&Store::sqlite(m.lock().unwrap()), "me");
        assert_eq!(n, 1, "un seul run réapé (celui du leader mort, encore running)");
        assert_eq!(status_of(&m, "mine"), "running", "mon run vivant NE doit PAS être réapé");
        assert_eq!(status_of(&m, "dead"), "failed", "l'orphelin du leader mort est marqué failed");
        assert_eq!(status_of(&m, "legacy"), "running", "un run legacy (owner NULL) n'est pas réapé à chaud");
        assert_eq!(status_of(&m, "done-other"), "done", "un terminal d'un autre owner est intouché");
    }

    /// (Fix #3) LIVENESS DU FLAP : `reap_dead_leader_runs` NE réape QUE les runs d'un owner MORT (heartbeat
    /// absent OU périmé). Un pair VIVANT-MAIS-DEMOTED (flap : heartbeat FRAIS) garde son run 'running' — on
    /// ne dé-synchronise JAMAIS la base d'un moteur encore vivant.
    #[test]
    fn reap_spares_live_peer_reaps_dead_and_stale() {
        let m = mem();
        insert_run(&m, "mine", "running", 100, Some("me"), 1);                // moi -> jamais réapé (owner=me)
        insert_run(&m, "live-peer", "running", 200, Some("peer-live"), 2);    // pair VIVANT (flap) -> préservé
        insert_run(&m, "stale-peer", "running", 300, Some("peer-stale"), 3);  // heartbeat périmé -> mort -> failed
        insert_run(&m, "gone-peer", "running", 400, Some("peer-gone"), 4);    // aucun heartbeat -> mort -> failed
        let now = crate::now_epoch();
        set_heartbeat(&m, "peer-live", now);                                    // frais
        set_heartbeat(&m, "peer-stale", now - crate::ha::LEASE_TTL_SECS - 10);  // périmé (au-delà du TTL)

        let n = reap_dead_leader_runs(&Store::sqlite(m.lock().unwrap()), "me");
        assert_eq!(n, 2, "seuls les owners MORTS (stale + gone) sont réapés");
        assert_eq!(status_of(&m, "mine"), "running", "mon run intact");
        assert_eq!(status_of(&m, "live-peer"), "running", "le run d'un pair VIVANT (heartbeat frais) N'est PAS réapé");
        assert_eq!(status_of(&m, "stale-peer"), "failed", "owner à heartbeat périmé -> mort -> réapé");
        assert_eq!(status_of(&m, "gone-peer"), "failed", "owner sans heartbeat -> mort -> réapé");
    }

    /// (Fix #2) FENCING CROSS-INSTANCE : l'index unique partiel garantit AU PLUS UN run 'running' par
    /// engagement. `claim_run_running` (transition autoritative pré-spawn) réussit pour le 1er run d'un
    /// engagement, ÉCHOUE (Err -> false, aucune ligne insérée) pour un 2e run du MÊME engagement, et
    /// réussit pour un engagement DISTINCT.
    #[test]
    fn claim_run_running_enforces_one_running_per_engagement() {
        let m = mem();
        assert!(claim_run_running(&Store::sqlite(m.lock().unwrap()), &spec_for("run-a", 1), "inst-A"), "1er claim direct -> running");
        assert_eq!(status_of(&m, "run-a"), "running");
        // 2e claim direct, MÊME engagement, run_id différent -> refusé par l'index unique partiel.
        assert!(!claim_run_running(&Store::sqlite(m.lock().unwrap()), &spec_for("run-b", 1), "inst-B"), "2e claim même engagement -> refusé");
        let exists_b: bool = Store::sqlite(m.lock().unwrap())
            .query_row("SELECT 1 FROM run_job WHERE run_id=?", &crate::sql_params!["run-b"], |_| Ok(())).is_ok();
        assert!(!exists_b, "run-b n'a PAS été inséré (double-spawn empêché)");
        // engagement DISTINCT -> claim OK.
        assert!(claim_run_running(&Store::sqlite(m.lock().unwrap()), &spec_for("run-c", 2), "inst-B"), "engagement distinct -> claim OK");
        assert_eq!(status_of(&m, "run-c"), "running");
    }

    /// (Fix #2) SCÉNARIO DOUBLE-RUN DU FLAP : un leader périmé DIRECT-claime un run pour l'engagement E
    /// pendant que le nouveau leader tente de claimer un run 'pending' pour LE MÊME E. L'un gagne, l'autre
    /// est bloqué par l'index unique partiel — JAMAIS deux 'running' pour un engagement.
    #[test]
    fn claim_run_running_blocks_flap_double_run() {
        let m = mem();
        // enqueue_pending a posé une ligne 'pending' pour l'engagement 5 (nouveau leader la claimera).
        Store::sqlite(m.lock().unwrap())
            .execute("INSERT INTO run_job(run_id,status,engagement_id,owner_instance) VALUES('run-pending','pending',5,NULL)", &crate::sql_params![])
            .unwrap();
        // Leader PÉRIMÉ : direct-claim d'un AUTRE run pour le MÊME engagement 5 -> gagne (running).
        assert!(claim_run_running(&Store::sqlite(m.lock().unwrap()), &spec_for("run-direct", 5), "stale-leader"), "direct claim même engagement -> running");
        assert_eq!(status_of(&m, "run-direct"), "running");
        // Nouveau leader : claim du run 'pending' (flip pending->running) pour E=5 -> BLOQUÉ (index unique).
        assert!(!claim_run_running(&Store::sqlite(m.lock().unwrap()), &spec_for("run-pending", 5), "new-leader"), "flip pending -> refusé (un running existe déjà pour E)");
        assert_eq!(status_of(&m, "run-pending"), "pending", "le pending reste pending -> pas de 2e moteur");
    }

    /// (Fix #1) BOOT-RECONCILE OWNER-SCOPÉ : l'UPDATE de `reconcile_runs(BootOwner{me})` ne flippe 'failed'
    /// QUE mes propres orphelins (owner=me OU NULL legacy) — JAMAIS le run 'running' d'un pair VIVANT
    /// (owner=autre). C'est ce qui rend l'appel SÛR depuis le leader-tick (process vivant, pairs vivants).
    /// On exerce le WHERE EXACT de l'UPDATE (mirror ; on n'appelle pas reconcile_runs pour éviter killpg/purge).
    #[test]
    fn boot_owner_reconcile_update_is_owner_scoped() {
        let m = mem();
        insert_run(&m, "mine", "running", 1, Some("me"), 1);
        insert_run(&m, "legacy", "running", 1, None, 2);
        insert_run(&m, "peer", "running", 1, Some("other"), 3); // pair vivant -> NE doit PAS être flippé
        let n = Store::sqlite(m.lock().unwrap())
            .execute(
                "UPDATE run_job SET status='failed', finished=datetime('now'), pid=-1,
                   detail=COALESCE(NULLIF(detail,''),'')||' [reconciled: boot leader — orphelin owner-scopé]'
                 WHERE status='running' AND (owner_instance=? OR owner_instance IS NULL)",
                &crate::sql_params!["me"],
            )
            .unwrap();
        assert_eq!(n, 2, "mine + legacy flippés (owner=me OU NULL)");
        assert_eq!(status_of(&m, "mine"), "failed");
        assert_eq!(status_of(&m, "legacy"), "failed");
        assert_eq!(status_of(&m, "peer"), "running", "le run d'un pair (owner=autre) reste running");
    }

    /// BootOwner : le killpg du reconcile de boot ne SÉLECTIONNE que les pgid de MON hôte (owner=me OU
    /// NULL) — jamais un pgid cross-host (owner d'un autre leader mort), qui serait ininterprétable
    /// localement. On teste la requête de sélection exacte utilisée par `reconcile_runs(BootOwner)`.
    #[test]
    fn boot_owner_killpg_select_excludes_cross_host() {
        let m = mem();
        insert_run(&m, "mine", "running", 100, Some("me"), 1);
        insert_run(&m, "legacy", "running", 300, None, 2);
        insert_run(&m, "cross", "running", 200, Some("old-leader"), 3); // pgid cross-host -> JAMAIS killpg
        let pgids: Vec<i32> = Store::sqlite(m.lock().unwrap())
            .query_lax(
                "SELECT pid FROM run_job WHERE status='running' AND pid>1
                   AND (owner_instance=? OR owner_instance IS NULL)",
                &crate::sql_params!["me"],
                |r| r.get_i64(0).map(|p| p as i32),
            )
            .unwrap();
        assert!(pgids.contains(&100), "mon pgid est killable");
        assert!(pgids.contains(&300), "un pgid legacy (NULL, même hôte historiquement) est killable");
        assert!(!pgids.contains(&200), "un pgid cross-host (autre owner) n'est JAMAIS signalé au killpg");
    }
}

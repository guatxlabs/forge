// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SOUS-SYSTÈME RUN-LIFECYCLE / C2-light extrait de main.rs (PURE MOVE). Regroupe le
//! lancement GOUVERNÉ + AUDITÉ de campagnes depuis l'UI web et tout le cycle de vie d'un run :
//! `run_create` (POST /api/run), `run_cancel` (POST /api/runs/:id/cancel), `runs_list`/`run_detail`/
//! `run_logs`/`run_sse` (lecture + flux SSE), le superviseur détaché (`spawn_supervisor`), le
//! réconciliateur de boot (`reconcile_runs` + `purge_stale_run_dirs`), l'ingestion de scanners
//! existants (`import_scan`, POST /api/import), et la validation de params RUN-SPÉCIFIQUE
//! (`validate_module_params`/`validate_modules`/`high_impact_modules`/`high_impact_gate`) ainsi que les
//! helpers de process POSIX (`spawn_setsid`/`kill_group`), le pousseur de logs (`push_run_log`) et le
//! sérialiseur de run_job (`run_job_json`/`RUN_JOB_COLS`).
//!
//! Les structs d'ÉTAT (App / RunState / RunHandle / RunEvent / Engagement) RESTENT à la racine de crate
//! (stage `state`) et sont référencées via `crate::*`. Réutilise App + les helpers de la racine
//! (`check_operator`/`operator_denied`/`attribution_login`/`append_run_ledger_path`/`chrono_now_compact`/
//! `resolve_engagement`/`host_in_scope_list`/`filter_enabled_modules`/`operator_disabled_modules`/
//! `technique_selection_value_for`/`validate_campaign`/`validate_host`/`gen_token`/`gs`/`extract_cwe`/
//! `cvss_base_for_severity`/`sanitize_filename`/`valid_import_format`/`validate_param_value`/
//! `module_operator_disabled`/`append_console_ledger`/`paginate`/`resolve_view_engagement_id` …) via
//! `use crate::*`, et est re-exporté à la racine par `pub(crate) use crate::runs::*` — les routes de
//! build_router (`post(run_create)`, `post(import_scan)`, `post(run_cancel)`, `get(runs_list)`,
//! `get(run_detail)`, `get(run_logs)`, `get(run_sse)`) ET les tests inline de main.rs (`super::*`)
//! résolvent donc ces handlers/helpers INCHANGÉS. `RUN_JOB_COLS`/`run_job_json` restent consommés par
//! `run_report` (main.rs) via la ré-exportation racine.
use crate::error;
use crate::*;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::broadcast;

// ===========================================================================================
// C2-light — lancement GOUVERNÉ + AUDITÉ de campagnes Forge depuis l'UI web.
//
// Modèle de sûreté (non négociable) :
//   1. Rôle OPÉRATEUR fail-closed (check_operator) sur TOUTES les routes C2.
//   2. Validation stricte de l'entrée (campaign regex ; hosts hostname-ou-CIDR sans métacaractères ;
//      modules ⊆ kinds connus ET web_allowed=1).
//   3. PLANCHER EXPLOIT (défaut) : 400 si un module demandé est exploit=1 OU destructive=1. Levé
//      UNIQUEMENT par l'opt-in HAUT-IMPACT GOUVERNÉ : `allow_high_impact=true` honoré seulement si
//      operator authentifié (check_operator) + `arm=true` + `reason` non vide (sinon 400
//      'high_impact_requires_arm_and_reason'). Hors opt-in, le plancher tient comme avant.
//   4. Spawn SANS shell : argv fixe via tokio::process::Command ; scope & targets passés par FICHIERS
//      dans un dir temp par run ; le scope écrit force allow_exploit/allow_destructive = valeur de
//      l'opt-in honoré (false par défaut). L'opt-in ne touche QUE allow_exploit/destructive — JAMAIS
//      in_scope/out_scope : le scope-guard du moteur reste seul juge du périmètre (hors-scope = VETO).
//   5. setsid (process group) -> cancel/watchdog tuent le GROUPE ; watchdog timeout (FORGE_RUN_TIMEOUT).
//   6. FIFO : un seul run vivant à la fois (refus 409 sinon).
//   7. Reconciler au boot : tout run_job 'running' orphelin -> 'failed'.
// ===========================================================================================

/// pré-exec hook posix : place l'enfant dans un nouveau groupe de session (setsid) pour que
/// cancel/watchdog puissent tuer TOUT le sous-arbre via killpg, et pour qu'un Ctrl-C console
/// ne propage pas au moteur (et inversement). Sans shell — argv fixe.
#[cfg(unix)]
pub(crate) fn spawn_setsid(cmd: &mut tokio::process::Command) {
    // `pre_exec` est la méthode inhérente de tokio::process::Command (pas le trait std CommandExt).
    unsafe {
        cmd.pre_exec(|| {
            // nouveau groupe de session ; le PID enfant devient le PGID.
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Tue le groupe de process (SIGTERM puis on laisse le watchdog/await récupérer le code).
/// UNIX : `killpg` via `libc::kill(-pgid, SIGTERM)` — coupe tout le sous-arbre détaché par setsid.
#[cfg(unix)]
pub(crate) fn kill_group(pgid: i32) {
    if pgid > 1 {
        unsafe {
            // négatif => cible le GROUPE entier (cf. killpg).
            libc::kill(-pgid, libc::SIGTERM);
        }
    }
}

/// Repli non-Unix (Windows/…) : les groupes de process POSIX (setsid/killpg) n'existent pas, donc
/// il n'y a PAS de killpg du sous-arbre. Best-effort/no-op : le process enfant spawné reste
/// néanmoins terminé via `kill_on_drop(true)` quand son handle Tokio est libéré, et le run est
/// marqué terminal en base par le superviseur/reconciler. La sémantique « couper tout le
/// sous-arbre détaché » n'est pas disponible hors Unix (documenté).
#[cfg(not(unix))]
pub(crate) fn kill_group(pgid: i32) {
    let _ = pgid;
}

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
            "[forge-console] reconcile: {n} run(s) orphelin(s) 'running' -> 'failed' ({} groupe(s) local/(aux) signalé(s))",
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

/// Supprime les répertoires temporaires `forge-run-*` (scope.json/targets.json par run) restés dans
/// le tempdir après une interruption (crash/reboot console) — best-effort, jamais fatal.
pub(crate) fn purge_stale_run_dirs() {
    let tmp = std::env::temp_dir();
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        let mut purged = 0;
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("forge-run-") && e.path().is_dir() && std::fs::remove_dir_all(e.path()).is_ok() {
                purged += 1;
            }
        }
        if purged > 0 {
            println!("[forge-console] reconcile: {purged} dir(s) temp forge-run-* purgé(s)");
        }
    }
}

/// Écrit une ligne de log de run en base ET la diffuse aux abonnés SSE.
pub(crate) fn push_run_log(app: &App, run_id: &str, stream: &str, line: &str) {
    {
        let store = app.store();
        let _ = store.execute(
            "INSERT INTO run_log(run_id,ts,stream,line) VALUES(?,datetime('now'),?,?)",
            &crate::sql_params![run_id, stream, line],
        );
    }
    // bus SSE lock-free (best-effort : ignore l'absence d'abonné)
    let _ = app.events.send(RunEvent {
        run_id: run_id.to_string(),
        kind: "log".into(),
        payload: json!({"stream": stream, "line": line}),
    });
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
    active: bool,
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

/// POST /api/run — démarre une campagne. Corps JSON :
///   {campaign, targets:[host…], modules:[kind…]?, mode:"propose"|"auto"?, budget:num?,
///    exhaustive:bool?, reason:str?, arm:bool?, allow_high_impact:bool?}
/// Auth : X-Forge-Operator (FAIL-CLOSED). Renvoie 202 {run_id, status:"running", high_impact:bool}.
/// Opt-in haut-impact GOUVERNÉ : `allow_high_impact=true` n'est honoré qu'avec operator + `arm=true`
/// + `reason` non vide (sinon 400 'high_impact_requires_arm_and_reason'). Honoré => le plancher
///   exploit est levé (validate_modules) et le scope du run écrit allow_exploit/destructive=true ;
///   l'autorisation est journalisée au ledger. Hors opt-in : comportement actuel inchangé.
pub(crate) async fn run_create(State(app): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    // (1) rôle opérateur fail-closed (+ contrainte source-CIDR si configurée : cf. check_operator)
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j);
    }

    // (1b) ENGAGEMENT CIBLE — le run opère SUR un engagement (objet de 1re classe). `engagement_id`
    // (corps) sélectionne l'engagement ; absent => l'engagement actif le plus ancien (rétro-compat :
    // #1). C'est SON scope (in/out), SON mode et SON ledger qui gouvernent ce run — PAS les App globals
    // (qui ne restent que les défauts de l'engagement #1). Fail-closed : engagement inconnu => 400.
    let engagement_id = body.get("engagement_id").and_then(|v| v.as_i64());
    let eng = match resolve_engagement(&app, &headers, engagement_id) {
        Ok(e) => e,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_engagement", "why": why}))),
    };

    // (1c) ENTERPRISE PER-ENGAGEMENT RBAC (readiness #14) — the caller's EFFECTIVE role on THIS engagement
    // must allow OPERATE (tenant_admin|tenant_operator), most-specific-wins (engagement grant > tenant grant),
    // FAIL-CLOSED. A tenant_viewer (or a user with only a viewer override on this engagement) is DENIED here
    // even though the tenant is visible + they passed the console-global operator gate. Community (flag OFF)
    // => NO-OP (branch skipped, byte-identical). Cross-tenant is already refused by resolve_engagement above.
    if tenancy::enabled(&app) && !tenancy::can_operate_engagement(&app, &headers, eng.id) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "engagement_operator_required",
                        "why": format!("rôle operator requis sur l'engagement #{} (grant per-engagement/tenant insuffisant — fail-closed)", eng.id)})),
        );
    }

    // (2) validation stricte de l'entrée
    let campaign = match validate_campaign(body.get("campaign").and_then(|v| v.as_str()).unwrap_or("")) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_campaign", "why": e}))),
    };
    let targets_in = match body.get("targets").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_targets", "why": "targets[] requis (non vide)"}))),
    };
    let mut targets: Vec<String> = Vec::new();
    for t in &targets_in {
        let host = t.as_str().unwrap_or("");
        match validate_host(host) {
            Ok(h) => {
                // SCOPE-GUARD DE L'ENGAGEMENT (fail-closed) : le scope du run est restreint au scope
                // de CET engagement (in_scope) — une cible hors du périmètre de l'engagement est refusée
                // AVANT le spawn (le moteur la vétoerait, mais on ne dépense pas de process pour ça et on
                // n'élargit jamais le périmètre). ISOLATION : un run pour l'engagement A valide contre le
                // scope de A UNIQUEMENT — jamais les App globals ni le scope d'un autre engagement.
                if !host_in_scope_list(&eng.scope_in, &h) {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "out_of_scope", "why": format!("'{h}' hors du scope de l'engagement #{}", eng.id)})));
                }
                targets.push(h);
            }
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_target", "why": e}))),
        }
    }

    // Opt-in haut-impact GOUVERNÉ. Lu AVANT validate_modules car il décide si le plancher exploit
    // tient. `arm` et `reason` sont parsés ici (besoin du gate) — réutilisés tels quels plus bas.
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("").chars().take(200).collect::<String>();
    let arm = body.get("arm").and_then(|v| v.as_bool()).unwrap_or(false);
    let allow_high_impact = body.get("allow_high_impact").and_then(|v| v.as_bool()).unwrap_or(false);
    // GATE : honore l'opt-in seulement si operator (déjà vérifié ci-dessus) + arm=true + reason non
    // vide. Sinon 400 explicite. Ok(false) => plancher exploit inchangé (comportement actuel).
    let high_impact = match high_impact_gate(allow_high_impact, true, arm, &reason) {
        Ok(v) => v,
        Err(e) => return e.into_parts(),
    };

    // modules demandés : ⊆ kinds connus ET web_allowed=1 ; PLANCHER EXPLOIT (exploit|destructive => 400)
    // SAUF si l'opt-in haut-impact est honoré (high_impact=true) — alors exploit/destructif autorisés.
    let requested_modules: Vec<String> = body
        .get("modules")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if let Err(e) = validate_modules(&app, &requested_modules, high_impact) {
        return e.into_parts();
    }

    // params PAR-MODULE (passthrough) : validés (taille/profondeur/NUL/kind bien formé) puis
    // transportés tels quels jusqu'au moteur via scope.json + targets.json (cf. plus bas). Ne
    // touche AUCUN garde-fou : ce sont des paramètres d'exécution, pas des bascules de capacité —
    // allow_exploit/destructive restent forcés false plus bas, quel que soit le contenu des params.
    let module_params = match validate_module_params(&body, &requested_modules) {
        Ok(m) => m,
        Err(e) => return e.into_parts(),
    };

    let mode = match body.get("mode").and_then(|v| v.as_str()).unwrap_or("propose") {
        "auto" => "auto",
        "propose" => "propose",
        other => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_mode", "why": format!("mode '{other}' invalide (propose|auto)")}))),
    };
    let budget = body.get("budget").and_then(|v| v.as_f64());
    let exhaustive = body.get("exhaustive").and_then(|v| v.as_bool()).unwrap_or(false);
    // --auto-pentest : MODE PENTEST AUTOMATISÉ — balaie TOUTES les techniques ACTIVÉES du scope à
    // travers la surface découverte (recon -> chaînage -> oracles), gouverné À L'IDENTIQUE d'un run
    // normal (scope-guard, plancher exploit, ledger). Ne CHANGE aucun garde-fou : il ne fait qu'élargir
    // le PLAN à l'ensemble effectif du scope (le moteur le re-filtre et le ROE le gate). Défaut : false.
    let auto_pentest = body.get("auto_pentest").and_then(|v| v.as_bool()).unwrap_or(false);
    // `reason`, `arm` et `allow_high_impact`/`high_impact` ont été parsés/évalués plus haut (le gate
    // les exige avant validate_modules). `arm` reste journalisé ; sans opt-in haut-impact honoré il
    // est inerte côté capacité (le scope écrit ci-dessous force allow_*=false dans ce cas).

    // SÉLECTION DE TECHNIQUES PAR-SCOPE — l'intention persistée (profil + toggles catégorie/technique)
    // est injectée dans le scope.json du run. Le moteur en RÉSOUT l'ensemble effectif
    // (resolve_enabled_kinds) et l'ENFORCE : une technique hors-profil/désactivée n'est NI planifiée NI
    // tirée (fail-closed). Une entrée de run explicite `technique_selection` dans le corps override la
    // sélection persistée. ENGAGEMENT : à défaut, la sélection PERSISTÉE est celle de CET engagement.
    // Résolue ICI (stateless, sur n'importe quelle instance) pour figer le spec avant le branchement HA.
    let selection = match body.get("technique_selection") {
        Some(v) if v.is_object() => validate_technique_selection(v).unwrap_or_else(|_| technique_selection_value_for(&app, eng.id)),
        _ => technique_selection_value_for(&app, eng.id),
    };
    // GOUVERNANCE CONNECTEUR : connecteurs DÉSACTIVÉS par l'opérateur (injectés au scope.json + ledger).
    let disabled_modules = operator_disabled_modules(&app);
    // ATTRIBUTION : identité individuelle (session) sinon repli 'operator'. `started_by` encode le compte
    // (+high_impact pour un run armé) -> traçabilité au COMPTE, sans nouvelle colonne. Résolus ICI
    // (stateless) : figés dans le spec pour que le LEADER qui claime un run pending préserve l'attribution.
    let actor = attribution_login(&app, &headers);
    let started_by = if high_impact { format!("{actor}+high_impact") } else { actor.clone() };
    // run_id : horodaté + suffixe aléatoire (traçable, unique). Figé maintenant : le même id est renvoyé
    // au client (202) et réutilisé par le leader s'il claime le run depuis 'pending'.
    let run_id = format!("run-{}-{}", chrono_now_compact(), gen_token().chars().take(8).collect::<String>());

    // SPEC RÉSOLU — capture TOUTE l'entrée validée+résolue (scope de l'engagement, cibles, modules,
    // params, mode, opt-in haut-impact, sélection, attribution). C'est l'UNIQUE source pour `claim_and_spawn`
    // (chemin direct comme chemin claim-pending) : sur le chemin pending il est SÉRIALISÉ dans
    // run_job.spawn_spec pour que le LEADER reconstruise scope.json/targets.json + argv à l'identique.
    let spec = RunSpawnSpec {
        run_id: run_id.clone(),
        eng_id: eng.id,
        eng_mode: eng.mode.clone(),
        eng_scope_out: eng.scope_out.clone(),
        eng_ledger_path: eng.ledger_path.clone(),
        campaign: campaign.clone(),
        targets,
        requested_modules,
        module_params: Value::Object(module_params),
        mode: mode.to_string(),
        budget,
        exhaustive,
        auto_pentest,
        reason,
        arm,
        high_impact,
        started_by,
        actor,
        selection,
        disabled_modules,
        body_targets: body.get("targets").cloned().unwrap_or(json!([])),
    };

    // ─── BRANCHEMENT RUN-LEADER (HA #10 Wave B) ──────────────────────────────────────────────────────
    // Toute la VALIDATION ci-dessus est STATELESS et correcte sur N'IMPORTE QUELLE instance. L'EXÉCUTION,
    // elle, doit être leader-only sous HA (sinon deux réplicas spawneraient/reaperaient les runs l'un de
    // l'autre). Deux cas :
    //   - non-HA (mono-instance) OU je SUIS le leader : SPAWN DIRECT via claim_and_spawn. En mono-instance
    //     `is_leader` court-circuite à true -> comportement HISTORIQUE byte-identique.
    //   - HA + je ne suis PAS le leader : j'ENQUEUE le run 'pending' (spec sérialisé) et je réponds 202
    //     {status:"pending"} — le LEADER le claime et le spawne (il écrit alors console.run.start). Aucun
    //     ledger console.run.start ici (écrivain unique = le leader, cohérent avec Wave C).
    if !crate::ha::ha_enabled(&app) || crate::ha::is_leader(&app) {
        // FIFO PAR ENGAGEMENT : réserve le slot (cancellation-safe) ; 409 si déjà vivant/réservé pour CET
        // engagement (isolation : un AUTRE engagement n'entrave rien). Puis spawn direct.
        let reservation = match reserve_engagement_slot(&app, eng.id).await {
            Some(r) => r,
            None => return (StatusCode::CONFLICT, Json(json!({"error": "run_in_progress", "engagement_id": eng.id, "why": format!("un run est déjà en cours pour l'engagement #{} (FIFO par engagement : un seul à la fois par engagement)", eng.id)}))),
        };
        claim_and_spawn(&app, &spec, reservation).await
    } else {
        enqueue_pending(&app, &spec)
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
            "body_targets": self.body_targets,
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
fn unclaim_running_on_failure(app: &App, run_id: &str, ha: bool) {
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

/// CŒUR DU RUN-LEADER (HA #10 Wave B) — écrit scope.json/targets.json dans un dir temp, spawne
/// `python -m forge.cli campaign …` (setsid, sans shell), promeut le run_job en 'running'
/// (owner_instance = MOI si HA), journalise `console.run.start` (+ `console.run.high_impact_authorized`),
/// promeut la réservation en run vivant (run_state) et détache le superviseur. RÉUTILISÉ par les DEUX
/// chemins : SPAWN DIRECT (`run_create` sur le leader / mono-instance) ET CLAIM-PENDING (le leader claime
/// un run enqueué).
///
/// FENCING CROSS-INSTANCE (Fix #2) — SOUS HA, la transition -> 'running' est faite AVANT tout spawn via
/// `claim_run_running` (garde autoritative : l'index unique partiel refuse un 2e run 'running' par
/// engagement). Si le claim échoue (un autre réplica a déjà un run 'running' pour cet engagement, ou la
/// course de flap est perdue) -> 409, AUCUN spawn. Le `pid` réel est posé APRÈS le spawn. Un échec fs/spawn
/// après le claim marque la ligne 'failed' (un-claim). MONO-INSTANCE (!ha) : chemin INCHANGÉ — pas de claim
/// pré-spawn, INSERT post-spawn HISTORIQUE (`ON CONFLICT(run_id) DO UPDATE`), owner NULL — byte-identique
/// (le FIFO garantit déjà l'unicité, l'index ne se déclenche jamais). L'appelant DÉTIENT déjà la réservation
/// FIFO (passée ici, RAII). Renvoie la réponse HTTP (202 running ; 409 claim perdu ; 5xx échec fs/spawn — la
/// réservation est alors libérée par le Drop du guard).
// ALLOW significant_drop_tightening: the promotion critical section below holds run_state + run_reservations
// together across insert-then-remove (atomic hand-off from reservation to live run). Tightening either guard
// reopens a window where an observer sees NEITHER — a real race, so the hold is load-bearing.
#[allow(clippy::significant_drop_tightening)]
pub(crate) async fn claim_and_spawn(app: &App, spec: &RunSpawnSpec, mut reservation: RunReservation<'_>) -> (StatusCode, Json<Value>) {
    let run_id = spec.run_id.as_str();
    // owner (HA #10 Wave B) : MOI sous HA (Some), None sinon -> NULL (reconcile-all mono-instance préservé).
    let owner: Option<String> = crate::ha::my_instance_id(app);
    let ha = crate::ha::ha_enabled(app);
    // (Fix #2) GARDE AUTORITATIVE PRE-SPAWN — sous HA, transition -> 'running' AVANT tout spawn. L'index
    // unique partiel `run_job(engagement_id) WHERE status='running'` refuse un 2e run 'running' pour ce
    // même engagement (double-spawn d'un leader périmé pendant un flap). Échec -> 409, AUCUN spawn (le Drop
    // de la réservation libère le slot FIFO). Mono-instance (!ha) : sauté -> l'INSERT post-spawn reste
    // byte-identique. La branche entière est élaguée en community (ha const-fold = false).
    if ha && !claim_run_running(&app.store(), spec, owner.as_deref().unwrap_or("")) {
        return (StatusCode::CONFLICT, Json(json!({"error": "run_in_progress", "engagement_id": spec.eng_id, "why": format!("un run est déjà 'running' pour l'engagement #{} (garde d'unicité DB cross-instance — au plus un 'running' par engagement, tous réplicas confondus)", spec.eng_id)})));
    }
    // (4) dir temp par run : scope.json (allow_exploit/destructive suivent l'opt-in) + targets.json.
    let run_dir = std::env::temp_dir().join(format!("forge-run-{run_id}"));
    if let Err(e) = std::fs::create_dir_all(&run_dir) {
        unclaim_running_on_failure(app, run_id, ha); // HA : la ligne 'running' claimée pré-spawn -> 'failed'
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "mkdir_failed", "why": e.to_string()})));
    }
    // scope du run : RESTREINT aux cibles validées. allow_exploit/destructive = opt-in haut-impact GOUVERNÉ
    // (false par défaut). INVARIANT : on ne touche QUE allow_exploit/destructive — in_scope/out_scope (le
    // périmètre) restent dictés par le scope de l'engagement, le scope-guard du moteur reste seul juge.
    let scope_comment = if spec.high_impact {
        format!("scope généré par la console pour {run_id} — HAUT-IMPACT GOUVERNÉ (allow_exploit/destructive=true, autorisé par operator armé)")
    } else {
        format!("scope généré par la console pour {run_id} — exploit/destructif IMPOSSIBLES (forcés false)")
    };
    let scope_notes = if spec.high_impact {
        "lancé via console C2-light (gouverné/audité) — opt-in HAUT-IMPACT honoré (operator+arm+reason) ; scope-guard moteur inchangé (hors-scope = VETO)"
    } else {
        "lancé via console C2-light (gouverné/audité) — non-exploit, non-destructif forcés"
    };
    let sel_profile = spec.selection.get("profile").cloned().unwrap_or(json!("bug_bounty"));
    let sel_categories = spec.selection.get("categories").cloned().unwrap_or(json!({}));
    let sel_techniques = spec.selection.get("techniques").cloned().unwrap_or(json!({}));
    let scope_doc = json!({
        "_comment": scope_comment,
        // mode + out_scope viennent de L'ENGAGEMENT (figés dans le spec) : le scope-guard du moteur applique
        // le périmètre de CET engagement. in_scope = cibles validées ⊆ scope de l'engagement.
        "mode": spec.eng_mode,
        "in_scope": spec.targets,
        "out_scope": spec.eng_scope_out,
        "rate": 5,
        "allow_exploit": spec.high_impact,
        "allow_destructive": spec.high_impact,
        "known_creds": [],
        "idor_targets": [],
        "module_params": spec.module_params.clone(),
        "disabled_modules": spec.disabled_modules.clone(),
        "profile": sel_profile,
        "categories_enabled": sel_categories,
        "techniques_enabled": sel_techniques,
        "notes": scope_notes
    });
    // Chaque cible porte les params par-module dans `attrs.module_params` (passthrough sûr, doublon volontaire).
    let targets_doc: Vec<Value> = spec.targets.iter()
        .map(|h| json!({"host": h, "kind": "host", "attrs": {"module_params": spec.module_params.clone()}}))
        .collect();
    let scope_path = run_dir.join("scope.json");
    let targets_path = run_dir.join("targets.json");
    if std::fs::write(&scope_path, serde_json::to_vec(&scope_doc).unwrap()).is_err()
        || std::fs::write(&targets_path, serde_json::to_vec(&Value::Array(targets_doc)).unwrap()).is_err()
    {
        let _ = std::fs::remove_dir_all(&run_dir);
        unclaim_running_on_failure(app, run_id, ha); // HA : la ligne 'running' claimée pré-spawn -> 'failed'
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write_failed", "why": "écriture scope/targets impossible"})));
    }

    // (4) argv FIXE — aucun shell. Le token console (en clair) transite UNIQUEMENT par l'environnement.
    let token: Option<String> = if app.token_raw.is_empty() { None } else { Some(app.token_raw.as_str().to_string()) };
    let console_url = format!("http://{}", std::env::var("FORGE_CONSOLE_ADDR").unwrap_or_else(|_| "127.0.0.1:7100".to_string()));
    let mut argv: Vec<String> = vec![
        "-m".into(), "forge.cli".into(), "campaign".into(),
        "--scope".into(), scope_path.to_string_lossy().into_owned(),
        "--targets".into(), targets_path.to_string_lossy().into_owned(),
        "--campaign".into(), spec.campaign.clone(),
        "--mode".into(), spec.mode.clone(),
        "--run-id".into(), run_id.to_string(),
        // --ledger : le ledger DÉDIÉ de l'engagement (chaîne SHA-256 tamper-evident propre à SON engagement).
        "--ledger".into(), spec.eng_ledger_path.clone(),
        "--console".into(), console_url.clone(),
    ];
    if let Some(b) = spec.budget { argv.push("--budget".into()); argv.push(format!("{b}")); }
    if spec.exhaustive { argv.push("--exhaustive".into()); }
    if spec.auto_pentest { argv.push("--auto-pentest".into()); }
    // sélection de modules -> --modules : filtre au spawn (EXCLUT tout connecteur désactivé). Flag omis si vide.
    let spawn_modules = filter_enabled_modules(app, &spec.requested_modules);
    if !spawn_modules.is_empty() {
        argv.push("--modules".into());
        argv.push(spawn_modules.join(","));
    }
    if !spec.reason.is_empty() { argv.push("--reason".into()); argv.push(spec.reason.clone()); }
    if spec.arm { argv.push("--arm".into()); }

    let mut cmd = tokio::process::Command::new(app.python.as_str());
    cmd.args(&argv)
        .current_dir(app.pkg_dir.as_str())
        .env("FORGE_CONSOLE_URL", &console_url)
        // STREAMING LIVE : stdout Python NON bufferisé -> lignes d'avancement au fil de l'eau vers SSE.
        .env("PYTHONUNBUFFERED", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(t) = &token { cmd.env("FORGE_CONSOLE_TOKEN", t); }
    #[cfg(unix)]
    spawn_setsid(&mut cmd);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&run_dir);
            unclaim_running_on_failure(app, run_id, ha); // HA : la ligne 'running' claimée pré-spawn -> 'failed'
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "spawn_failed", "why": e.to_string()})));
        }
    };
    let pid = child.id().map(|p| p as i32).unwrap_or(-1);
    let pgid = pid; // setsid => le PID enfant EST le PGID.

    // AUDIT haut-impact : modules exploit/destructif effectivement débloqués (traçabilité ; vide sinon).
    let hi_modules: Vec<String> = if spec.high_impact { high_impact_modules(app, &spec.requested_modules) } else { vec![] };

    // ÉCRITURE DE LA LIGNE run_job APRÈS SPAWN — pose le pid réel du process.
    //   - HA (Fix #2) : la ligne est DÉJÀ 'running' (claim autoritative pré-spawn ci-dessus, owner=me déjà
    //     posé). On se contente d'UPDATE pid/started réels — PAS de nouvelle transition de status (le fencing
    //     a déjà eu lieu ; ré-INSÉRER 'running' post-spawn rejouerait la garde d'unicité pour rien).
    //   - MONO-INSTANCE (!ha) : chemin HISTORIQUE byte-identique — INSERT 'running' + pid, owner NULL,
    //     `ON CONFLICT(run_id) DO UPDATE` (la ligne n'existe jamais d'avance en mono-instance : INSERT neuf).
    if ha {
        let store = app.store();
        let _ = store.execute(
            "UPDATE run_job SET pid=?, started=datetime('now') WHERE run_id=?",
            &crate::sql_params![pgid, run_id],
        );
    } else {
        let store = app.store();
        let _ = store.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,mode,pid,started_by,reason,targets,modules,started,engagement_id,owner_instance)
             VALUES(?,?,datetime('now'),'running',?,?,?,?,?,?,datetime('now'),?,?)
             ON CONFLICT(run_id) DO UPDATE SET status='running', pid=excluded.pid, started=excluded.started, owner_instance=excluded.owner_instance",
            &crate::sql_params![
                run_id, spec.campaign.as_str(), spec.mode.as_str(), pgid, spec.started_by.as_str(), spec.reason.as_str(),
                serde_json::to_string(&spec.body_targets).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&spec.requested_modules).unwrap_or_else(|_| "[]".into()),
                spec.eng_id,
                owner.clone()
            ],
        );
    }
    // ledger : acte de lancement (qui/quoi/quand). L'opt-in haut-impact honoré est journalisé explicitement.
    if spec.high_impact {
        append_run_ledger_path(app, &spec.eng_ledger_path, "console.run.high_impact_authorized", json!({
            "run_id": run_id, "engagement_id": spec.eng_id, "campaign": spec.campaign, "actor": spec.actor, "by": "operator",
            "arm": spec.arm, "reason": spec.reason,
            "exploit_modules_authorized": hi_modules,
            "requested_modules": spec.requested_modules,
            "allow_exploit": true, "allow_destructive": true,
            "note": "opt-in haut-impact GOUVERNÉ honoré (operator+arm+reason) ; scope-guard moteur inchangé (hors-scope = VETO)"
        }));
    }
    append_run_ledger_path(app, &spec.eng_ledger_path, "console.run.start", json!({
        "run_id": run_id, "engagement_id": spec.eng_id, "campaign": spec.campaign, "mode": spec.mode, "actor": spec.actor, "by": "operator",
        "targets": spec.body_targets, "modules": spec.requested_modules,
        "module_params": spec.module_params,
        "disabled_modules": spec.disabled_modules,
        "technique_selection": spec.selection,
        "auto_pentest": spec.auto_pentest,
        "reason": spec.reason, "arm_requested": spec.arm,
        "high_impact": spec.high_impact,
        "exploit_floor": if spec.high_impact { "lifted via governed high-impact opt-in (allow_exploit=true allow_destructive=true)" } else { "forced allow_exploit=false allow_destructive=false" }
    }));

    // PROMOTION réservation -> run vivant. run_state publié AVANT de retirer la réservation (aucune fenêtre
    // où ni la réservation ni le run vivant ne seraient visibles). Aucun `.await` sous le verrou std.
    {
        // ATOMIC promotion (see the fn-level allow): both guards are held together across insert-then-
        // remove so no observer ever sees NEITHER the reservation NOR the live run; releasing either early
        // reopens that window. The hold is the correctness guarantee, not incidental.
        let mut state = app.run_state.lock().await;
        state.current.insert(spec.eng_id, RunHandle { run_id: run_id.to_string(), pgid });
        let mut resv = app.run_reservations.lock().unwrap_or_else(|e| e.into_inner());
        resv.remove(&spec.eng_id);
        reservation.active = false; // run promu -> Drop = no-op
    }
    let _ = app.events.send(RunEvent { run_id: run_id.to_string(), kind: "status".into(), payload: json!({"status": "running"}) });

    // superviseur détaché : pompe stdout/stderr -> run_log + SSE ; watchdog ; finalisation atomique + libération slot.
    spawn_supervisor(app.clone(), child, run_id.to_string(), spec.eng_id, pgid, run_dir, spec.eng_ledger_path.clone());

    (StatusCode::ACCEPTED, Json(json!({"run_id": run_id, "status": "running", "campaign": spec.campaign, "mode": spec.mode, "high_impact": spec.high_impact, "auto_pentest": spec.auto_pentest})))
}

/// POST /api/import — INGESTION de sorties de SCANNERS EXISTANTS (migration Faraday/Trickest/reNgine/
/// Osmedeus). OPÉRATEUR/ADMIN (check_operator, 403 sinon) + LEDGERISÉ (`console.import`). Corps :
///   {campaign, format:"auto"|<fmt>, content:<texte du fichier>, filename?, flag_out_of_scope?}
///
/// GOUVERNANCE — PUR DATA, ZÉRO exécution : le fichier est PARSÉ par le moteur Python (`forge import`,
/// SOURCE UNIQUE des parseurs — pas de re-implémentation Rust qui dériverait) sous le SCOPE SERVEUR
/// autoritatif (roe.Scope, LE scope-guard unique). Les findings d'assets HORS périmètre sont JETÉS
/// (défaut) ou MARQUÉS (`flag_out_of_scope` -> status=skipped). Les secrets du fichier sont RÉDIGÉS par
/// le moteur AVANT tout finding ; le fichier temp est supprimé aussitôt le parse fini (aucun secret ne
/// persiste). Le ledger n'enregistre QUE l'attribution + les COMPTEURS (jamais le contenu). Orienté
/// preuve : les findings importés sont tested/reported_by_tool (jamais `vulnerable`). no-shell (argv FIXE).
pub(crate) async fn import_scan(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // (1) gate opérateur fail-closed (comme /api/run — une ingestion mute l'engagement).
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    // (2) validation stricte de l'entrée
    let campaign = match validate_campaign(body.get("campaign").and_then(|v| v.as_str()).unwrap_or("default")) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_campaign", "why": e}))).into_response(),
    };
    let fmt_in = body.get("format").and_then(|v| v.as_str()).unwrap_or("auto").trim().to_string();
    if !valid_import_format(&fmt_in) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_format",
            "why": "format inconnu (nmap|nuclei|burp|httpx|ffuf|hosts|generic-json|generic-csv|auto)"}))).into_response();
    }
    let content = match body.get("content").and_then(|v| v.as_str()) {
        Some(c) if !c.trim().is_empty() => c.to_string(),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_content", "why": "content (texte du fichier de scan) requis"}))).into_response(),
    };
    if content.len() > 64 * 1024 * 1024 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "too_large", "why": "fichier trop volumineux (>64 MiB)"}))).into_response();
    }
    let filename = sanitize_filename(body.get("filename").and_then(|v| v.as_str()).unwrap_or(""));
    let flag_oos = body.get("flag_out_of_scope").and_then(|v| v.as_bool()).unwrap_or(false);

    // (3) écrit le fichier + le SCOPE SERVEUR (autoritatif) dans un dossier temp, PUIS parse via le
    //     moteur Python. Le scope-guard (roe.Scope) filtre les assets hors périmètre au parse.
    let import_dir = std::env::temp_dir().join(format!("forge-import-{}-{}", chrono_now_compact(),
        gen_token().chars().take(8).collect::<String>()));
    if std::fs::create_dir_all(&import_dir).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "mkdir_failed"}))).into_response();
    }
    let file_path = import_dir.join("scan.input");
    let scope_path = import_dir.join("scope.json");
    let scope_doc = json!({
        "_comment": "scope serveur autoritatif — filtre les findings importés hors périmètre (scope-guard fail-closed)",
        "mode": app.scope_mode.as_str(),
        "in_scope": app.scope_in.as_ref().clone(),
        "out_scope": [],
    });
    if std::fs::write(&file_path, content.as_bytes()).is_err()
        || std::fs::write(&scope_path, serde_json::to_vec(&scope_doc).unwrap()).is_err()
    {
        let _ = std::fs::remove_dir_all(&import_dir);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write_failed"}))).into_response();
    }
    // argv FIXE — aucune valeur concaténée à un shell ; le contenu ne transite QUE par un fichier.
    let mut argv: Vec<String> = vec![
        "-m".into(), "forge.cli".into(), "import".into(),
        "--format".into(), fmt_in.clone(),
        "--file".into(), file_path.to_string_lossy().into_owned(),
        "--scope".into(), scope_path.to_string_lossy().into_owned(),
        "--campaign".into(), campaign.clone(),
        "--json".into(),
    ];
    if flag_oos { argv.push("--flag-out-of-scope".into()); }
    let spawn = std::process::Command::new(app.python.as_str())
        .args(&argv)
        .current_dir(app.pkg_dir.as_str())
        .stdin(std::process::Stdio::null())
        .output();
    // nettoyage IMMÉDIAT — le contenu (secrets potentiels) ne persiste jamais sur disque au-delà du parse.
    let _ = std::fs::remove_dir_all(&import_dir);
    let out = match spawn {
        Ok(o) => o,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "spawn_failed", "why": e.to_string()}))).into_response(),
    };
    if !out.status.success() {
        // stderr rédigé/borné (le moteur n'imprime jamais le contenu ni un secret sur stderr).
        let why = String::from_utf8_lossy(&out.stderr).chars().take(300).collect::<String>();
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "parse_failed", "why": why}))).into_response();
    }
    let env: Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "bad_envelope", "why": e.to_string()}))).into_response(),
    };
    let fmt_detected = env.get("format").and_then(|v| v.as_str()).unwrap_or(fmt_in.as_str()).to_string();
    let counts = env.get("counts").cloned().unwrap_or_else(|| json!({}));

    // (4) INSÈRE les findings (déjà scope-filtrés par le moteur). MÊME dérivation CWE/CVSS que /api/ingest.
    let run_id = format!("import-{}-{}", chrono_now_compact(), gen_token().chars().take(6).collect::<String>());
    let mut ingested = 0i64;
    if let Some(arr) = env.get("findings").and_then(|v| v.as_array()) {
        let store = app.store();
        for f in arr {
            let cwe = { let c = gs(f, "cwe"); if c.is_empty() { extract_cwe(&gs(f, "category")) } else { c } };
            let (mut cvss_vec, mut cvss_score) = (gs(f, "cvss_vector"), f.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0));
            if cvss_vec.is_empty() && cvss_score == 0.0 {
                let (v, s) = cvss_base_for_severity(&gs(f, "severity"));
                cvss_vec = v.to_string();
                cvss_score = s;
            }
            if let Ok(n) = store.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                &crate::sql_params![gs(f,"ts"), &campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                    gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                    gs(f,"fix"), &run_id, cwe, cvss_vec, cvss_score],
            ) {
                ingested += n as i64;
            }
        }
    }

    // (5) LEDGER : attribution + COMPTEURS uniquement — JAMAIS le contenu du fichier ni un secret.
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.import", json!({
        "actor": actor, "by": "operator", "campaign": campaign,
        "format": fmt_detected, "requested_format": fmt_in, "filename": filename,
        "run_id": run_id, "flag_out_of_scope": flag_oos,
        "counts": {
            "parsed": counts.get("parsed").cloned().unwrap_or(json!(null)),
            "in_scope": counts.get("in_scope").cloned().unwrap_or(json!(null)),
            "out_of_scope": counts.get("out_of_scope").cloned().unwrap_or(json!(null)),
            "emitted": counts.get("emitted").cloned().unwrap_or(json!(null)),
            "ingested": ingested,
        },
        "note": "import PUR DATA (aucune exécution) ; scope-guard appliqué (hors périmètre jeté/marqué) ; secrets rédigés par le moteur"
    }));

    (StatusCode::OK, Json(json!({
        "ok": true, "format": fmt_detected, "campaign": campaign, "run_id": run_id,
        "counts": counts, "ingested": ingested
    }))).into_response()
}

/// Valide les params PAR-MODULE du corps /api/run. Forme attendue :
///   "module_params": { "<kind>": { ... }, ... }
/// Règles : chaque clé doit être un `kind` bien formé ([A-Za-z0-9._-], 1..64) ; si une allow-list de
/// modules est fournie (modules non vide), la clé DOIT y appartenir (on ne transporte pas de params
/// pour un module qui ne sera pas lancé) ; chaque valeur est un objet, validé récursivement (taille,
/// profondeur, NUL). Renvoie la map normalisée (kind -> objet params) ou 400. Absent/vide => map vide.
pub(crate) fn validate_module_params(
    body: &Value,
    modules: &[String],
) -> Result<serde_json::Map<String, Value>, error::ApiError> {
    let mut out = serde_json::Map::new();
    let raw = match body.get("module_params") {
        None | Some(Value::Null) => return Ok(out),
        Some(Value::Object(m)) => m,
        Some(_) => {
            return Err(error::ApiError::bad("bad_module_params", "module_params doit être un objet {kind: {params}}"));
        }
    };
    if raw.len() > 128 {
        return Err(error::ApiError::bad("bad_module_params", "trop de modules dans module_params (>128)"));
    }
    for (kind, params) in raw {
        // clé = kind bien formé (même grammaire que validate_campaign : pas de métacaractère/-en-tête).
        if let Err(e) = validate_campaign(kind) {
            return Err(error::ApiError::bad("bad_module_params", format!("clé module '{kind}' invalide: {e}")));
        }
        // si une allow-list explicite est fournie, on n'accepte de params QUE pour ces modules.
        if !modules.is_empty() && !modules.iter().any(|m| m == kind) {
            return Err(error::ApiError::bad("param_for_unrequested_module", format!("params fournis pour '{kind}' qui n'est pas dans modules[]")));
        }
        if !params.is_object() {
            return Err(error::ApiError::bad("bad_module_params", format!("params de '{kind}' doivent être un objet")));
        }
        if let Err(e) = validate_param_value(params, 0) {
            return Err(error::ApiError::bad("bad_module_params", format!("params de '{kind}': {e}")));
        }
        out.insert(kind.clone(), params.clone());
    }
    Ok(out)
}

/// Vérifie qu'un module demandé existe (kinds connus), est web_allowed=1, et N'EST NI exploit NI
/// destructive (PLANCHER EXPLOIT). 400 sinon. Liste vide => OK (le planner choisira tout seul, et le
/// scope force allow_*=false de toute façon).
///
/// `allow_high_impact` : quand l'opt-in haut-impact gouverné est HONORÉ (operator + arm + reason —
/// cf. `high_impact_gate`), le PLANCHER EXPLOIT est levé : les modules exploit/destructive sont
/// acceptés (et la dérivée `web_allowed=0` qui n'existe QUE parce que exploit/destructif/idor est
/// elle aussi tolérée). Le contrôle `unknown_module` reste TOUJOURS appliqué — on n'accepte jamais
/// un kind inconnu du registre, même armé. `false` (défaut) => comportement actuel inchangé.
pub(crate) fn validate_modules(app: &App, modules: &[String], allow_high_impact: bool) -> Result<(), error::ApiError> {
    if modules.is_empty() {
        return Ok(());
    }
    
    for m in modules {
        let row = app.store().query_row(
            "SELECT exploit,destructive,web_allowed,enabled,available_override FROM module WHERE kind=?",
            &crate::sql_params![m],
            |r| Ok((
                r.get_i64(0)?, r.get_i64(1)?, r.get_i64(2)?,
                r.get_i64(3)? != 0, r.get_opt_i64(4)?.map(|v| v != 0),
            )),
        );
        match row {
            Ok((exploit, destructive, web_allowed, enabled, available_override)) => {
                // GOUVERNANCE CONNECTEUR (fail-closed) : un module DÉSACTIVÉ par l'opérateur (enabled=0
                // ou available_override=0) n'est JAMAIS lançable depuis le web — MÊME sous opt-in
                // haut-impact. Désactiver un connecteur = le désinstaller opérationnellement, un cran
                // AU-DESSUS du plancher exploit : vérifié AVANT le bypass high-impact. (Un binaire
                // simplement absent, sans intention opérateur, reste accepté puis SKIP par le moteur.)
                if module_operator_disabled(enabled, available_override) {
                    return Err(error::ApiError::bad("module_disabled", format!("module '{m}' désactivé (gouvernance connecteur) — non lançable, même armé")));
                }
                // Opt-in haut-impact honoré : on NE rejette PAS exploit/destructif. Le scope-guard du
                // moteur reste seul juge des cibles (hors-scope = VETO), l'écriture allow_* ne touche
                // que la capacité, jamais le périmètre.
                if allow_high_impact {
                    continue;
                }
                if exploit != 0 || destructive != 0 {
                    return Err(error::ApiError::bad("exploit_floor", format!("module '{m}' est exploit/destructif — interdit depuis le web (sans opt-in haut-impact gouverné)")));
                }
                if web_allowed == 0 {
                    return Err(error::ApiError::bad("not_web_allowed", format!("module '{m}' n'est pas lançable depuis le web (web_allowed=0)")));
                }
            }
            Err(_) => {
                return Err(error::ApiError::bad("unknown_module", format!("module '{m}' inconnu du registre")));
            }
        }
    }
    Ok(())
}

/// Liste, parmi `modules`, ceux marqués exploit OU destructive dans le registre — c.-à-d. les
/// modules HAUT-IMPACT effectivement autorisés par un opt-in honoré. Sert UNIQUEMENT à l'audit
/// (ledger + run_job) : tracer précisément quelles capacités haut-impact ont été débloquées pour ce
/// run. N'altère aucun garde-fou. Liste vide => le planner choisit seul (rien d'explicitement listé).
pub(crate) fn high_impact_modules(app: &App, modules: &[String]) -> Vec<String> {
    let store = app.store();
    modules
        .iter()
        .filter(|m| {
            store.query_row(
                "SELECT exploit,destructive,enabled,available_override FROM module WHERE kind=?",
                &crate::sql_params![m.as_str()],
                |r| Ok((
                    r.get_i64(0)?, r.get_i64(1)?,
                    r.get_i64(2)? != 0, r.get_opt_i64(3)?.map(|v| v != 0),
                )),
            )
            // haut-impact ET effectivement activable : un connecteur exploit/destructif DÉSACTIVÉ par
            // l'opérateur ne sera pas tiré -> il ne doit pas figurer parmi les capacités « débloquées »
            // dans l'audit (ledger/run_job). Consulte `enabled`/`available_override`.
            .map(|(e, d, en, ov)| (e != 0 || d != 0) && !module_operator_disabled(en, ov))
            .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// GATE de gouvernance haut-impact — fonction PURE (testable, aucun effet de bord).
///
/// Décide si l'opt-in `allow_high_impact` du corps /api/run est HONORÉ. L'opt-in n'est honoré QUE si
/// les TROIS conditions de gouvernance sont réunies :
///   (1) requête authentifiée operator (vérifiée en amont par `check_operator`, fail-closed —
///       passée ici via `operator_ok` pour garder la fonction pure et testable) ;
///   (2) `arm == true` (armement explicite) ;
///   (3) `reason` non vide (raison obligatoire, déjà bornée à 200 car. par l'appelant).
///
/// Retour :
///   - `Ok(false)` : opt-in NON demandé (`allow_high_impact=false`) -> comportement ACTUEL inchangé
///     (plancher exploit tient, scope écrit allow_*=false) ;
///   - `Ok(true)`  : opt-in demandé ET les 3 conditions réunies -> capacité haut-impact autorisée ;
///   - `Err((code, json))` : opt-in demandé mais une condition manque -> 400 explicite.
pub(crate) fn high_impact_gate(
    allow_high_impact: bool,
    operator_ok: bool,
    arm: bool,
    reason: &str,
) -> Result<bool, error::ApiError> {
    if !allow_high_impact {
        return Ok(false); // défaut : aucune dérogation, plancher exploit inchangé
    }
    // operator_ok est en principe TOUJOURS vrai à ce stade (check_operator a déjà gaté l'endpoint) ;
    // on le revérifie ici par défense en profondeur — un opt-in haut-impact ne peut JAMAIS être
    // honoré sans preuve operator, quelle que soit l'ordre des futurs appelants (fail-closed).
    if !operator_ok || !arm || reason.trim().is_empty() {
        return Err(error::ApiError::bad("high_impact_requires_arm_and_reason", "allow_high_impact n'est honoré qu'avec operator authentifié + arm=true + reason non vide"));
    }
    Ok(true)
}

/// Détache le superviseur du run : pompe stdout/stderr ligne à ligne vers run_log+SSE, applique le
/// watchdog (FORGE_RUN_TIMEOUT) qui tue le GROUPE, puis finalise le run_job (status terminal) et
/// libère le slot FIFO DE CET engagement. Atomique : quel que soit le chemin de sortie, le run est
/// marqué terminal. `eid` = clé du slot à libérer (isolation : on ne touche QUE le slot de CET
/// engagement) ; `pgid` = groupe de process pour le kill du watchdog (connu au spawn, pas relu).
pub(crate) fn spawn_supervisor(app: App, mut child: tokio::process::Child, run_id: String, eid: i64, pgid: i32, run_dir: std::path::PathBuf, ledger_path: String) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    tokio::spawn(async move {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        // pompes stdout/stderr concurrentes
        let (app_o, rid_o) = (app.clone(), run_id.clone());
        let pump_out = tokio::spawn(async move {
            if let Some(out) = stdout {
                let mut lines = BufReader::new(out).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    push_run_log(&app_o, &rid_o, "stdout", &line);
                }
            }
        });
        let (app_e, rid_e) = (app.clone(), run_id.clone());
        let pump_err = tokio::spawn(async move {
            if let Some(err) = stderr {
                let mut lines = BufReader::new(err).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    push_run_log(&app_e, &rid_e, "stderr", &line);
                }
            }
        });

        // attente du process avec watchdog timeout -> kill group.
        let timeout = Duration::from_secs(app.run_timeout_secs);
        let (final_status, exit_code): (&str, Option<i64>) = match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => {
                let code = status.code().map(|c| c as i64);
                if status.success() { ("done", code) } else { ("failed", code) }
            }
            Ok(Err(_)) => ("failed", None),
            Err(_) => {
                // timeout : tuer le GROUPE de CE run (pgid connu au spawn), récupérer. On n'inspecte
                // pas le slot d'un autre engagement — le pgid ciblé est exclusivement celui de ce run.
                push_run_log(&app, &run_id, "system", &format!("watchdog: timeout {}s — kill group", app.run_timeout_secs));
                kill_group(pgid);
                let _ = child.wait().await;
                ("timeout", None)
            }
        };
        let _ = pump_out.await;
        let _ = pump_err.await;

        // finalisation : status terminal + exit_code + finished. Ne pas écraser un statut 'cancelled'
        // déjà posé par run_cancel (cancel l'emporte sur la cause secondaire SIGTERM).
        {
            let store = app.store();
            // UPDATE conditionnel : ne finalise QUE si le run est encore 'running' ou 'cancelled'
            // (course superviseur vs cancel). Un statut déjà terminal posé ailleurs n'est pas écrasé.
            // CASE préserve 'cancelled' (cancel l'emporte sur la cause secondaire SIGTERM/timeout).
            let _ = store.execute(
                "UPDATE run_job SET status=CASE WHEN status='cancelled' THEN 'cancelled' ELSE ? END,
                   finished=datetime('now'), pid=-1, exit_code=?
                 WHERE run_id=? AND status IN ('running','cancelled')",
                &crate::sql_params![final_status, exit_code, &run_id],
            );
        }
        let terminal: String = {
            let store = app.store();
            store.query_row("SELECT status FROM run_job WHERE run_id=?", &crate::sql_params![&run_id], |r| r.get_str(0))
                .unwrap_or_else(|_| final_status.to_string())
        };
        append_run_ledger_path(&app, &ledger_path, "console.run.end", json!({
            "run_id": run_id, "status": terminal, "exit_code": exit_code
        }));

        // libère le slot FIFO DE CET engagement + diffuse le statut terminal. ISOLATION + garde
        // anti-course : on ne retire QUE le slot de `eid`, et seulement s'il porte TOUJOURS CE run_id
        // (jamais celui d'un run/engagement voisin qui aurait pris la place entre-temps).
        {
            let mut st = app.run_state.lock().await;
            if st.current.get(&eid).map(|h| h.run_id == run_id).unwrap_or(false) {
                st.current.remove(&eid);
            }
        }
        let _ = app.events.send(RunEvent { run_id: run_id.clone(), kind: "status".into(), payload: json!({"status": terminal, "exit_code": exit_code}) });
        // nettoyage du dir temp (scope/targets) — best-effort.
        let _ = std::fs::remove_dir_all(&run_dir);
    });
}

/// POST /api/runs/:id/cancel — annule un run vivant (kill group). Opérateur fail-closed.
pub(crate) async fn run_cancel(State(app): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Path(id): Path<String>) -> impl IntoResponse {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j);
    }
    // Recherche du run vivant par run_id (GLOBAL-unique) parmi TOUS les engagements : `current` est
    // maintenant indexé par engagement_id, donc on balaie les valeurs. On ne cible que le pgid du run
    // demandé ; les slots des autres engagements ne sont ni lus ni modifiés (le kill ne vise que ce run).
    let pgid = {
        let st = app.run_state.lock().await;
        st.current.values().find(|h| h.run_id == id).map(|h| h.pgid).unwrap_or(-1)
    };
    // HA (#10 Wave B) — ROUTAGE DU CANCEL. Sous HA un cancel peut arriver sur N'IMPORTE QUEL réplica (LB)
    // alors que le run n'est trackée dans run_state (et killable) que sur son PROPRIÉTAIRE (le leader qui
    // l'a spawné). On route donc TOUT cancel HA par `run_cancel_ha` : il persiste l'intention 'cancelled'
    // (durable) + le ledger, puis killpg MAINTENANT si le run est LOCAL (pgid>1 dans mon run_state), sinon
    // laisse le propriétaire couper via son cancel-watch tick (JAMAIS de killpg cross-host). En mono-instance
    // `ha_enabled` est false -> ce bloc est inerte et le cancel reste LOCAL byte-identique (code ci-dessous).
    if crate::ha::ha_enabled(&app) {
        return run_cancel_ha(&app, &headers, &id, pgid).await;
    }
    if pgid <= 1 {
        // run inconnu ou déjà terminé.
        let exists: bool = {
            let store = app.store();
            store.query_row("SELECT 1 FROM run_job WHERE run_id=?", &crate::sql_params![&id], |_| Ok(())).is_ok()
        };
        return if exists {
            (StatusCode::CONFLICT, Json(json!({"error": "not_running", "why": "le run n'est pas en cours"})))
        } else {
            (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"})))
        };
    }
    // marque 'cancelled' AVANT le kill, mais SEULEMENT si le run est encore 'running' (UPDATE
    // conditionnel : course cancel vs finalisation superviseur — on ne ré-ouvre pas un run déjà
    // terminal en 'cancelled'). Le superviseur, lui, préserve 'cancelled' s'il le voit posé.
    {
        let store = app.store();
        let _ = store.execute("UPDATE run_job SET status='cancelled' WHERE run_id=? AND status='running'", &crate::sql_params![&id]);
    }
    let actor = attribution_login(&app, &headers);
    push_run_log(&app, &id, "system", &format!("cancel demandé par '{actor}' — kill group"));
    // ledger de L'ENGAGEMENT propriétaire du run (isolation) — pas systématiquement App.ledger_path.
    let cancel_ledger = engagement_ledger_for_run(&app, &id);
    append_run_ledger_path(&app, &cancel_ledger, "console.run.cancel", json!({"run_id": id, "actor": actor, "by": "operator"}));
    kill_group(pgid);
    (StatusCode::OK, Json(json!({"run_id": id, "status": "cancelling"})))
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
                println!("[forge-console] leader-tick: {n} run(s) orphelin(s) d'un leader mort -> 'failed' (failover, sans killpg cross-host)");
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

/// Sérialise un run_job en JSON (vue détaillée / liste).
pub(crate) fn run_job_json(r: &crate::store::Row) -> crate::store::StoreResult<Value> {
    Ok(json!({
        "run_id": r.get_str(0)?,
        "campaign": r.get_opt_str(1)?.unwrap_or_default(),
        "ts": r.get_opt_str(2)?.unwrap_or_default(),
        "status": r.get_opt_str(3)?.unwrap_or_default(),
        "mode": r.get_opt_str(4)?.unwrap_or_default(),
        "fired": r.get_opt_i64(5)?.unwrap_or(0),
        "dry_run": r.get_opt_i64(6)?.unwrap_or(0),
        "vetoed": r.get_opt_i64(7)?.unwrap_or(0),
        "errors": r.get_opt_i64(8)?.unwrap_or(0),
        "skipped_budget": serde_json::from_str::<Value>(&r.get_opt_str(9)?.unwrap_or_else(|| "[]".into())).unwrap_or(json!([])),
        "coverage_gaps": serde_json::from_str::<Value>(&r.get_opt_str(10)?.unwrap_or_else(|| "{}".into())).unwrap_or(json!({})),
        "started_by": r.get_opt_str(11)?.unwrap_or_default(),
        "reason": r.get_opt_str(12)?.unwrap_or_default(),
        "targets": serde_json::from_str::<Value>(&r.get_opt_str(13)?.unwrap_or_else(|| "[]".into())).unwrap_or(json!([])),
        "modules": serde_json::from_str::<Value>(&r.get_opt_str(14)?.unwrap_or_else(|| "[]".into())).unwrap_or(json!([])),
        "started": r.get_opt_str(15)?.unwrap_or_default(),
        "finished": r.get_opt_str(16)?.unwrap_or_default(),
        "exit_code": r.get_opt_i64(17)?,
    }))
}

pub(crate) const RUN_JOB_COLS: &str = "run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps,started_by,reason,targets,modules,started,finished,exit_code";

/// GET /api/runs — liste les runs (récents d'abord). Lecture (viewer) — pas besoin d'opérateur.
pub(crate) async fn runs_list(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : liste des runs de l'engagement actif UNIQUEMENT (isolation).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    
    // `engagement_id` (entier résolu) LIÉ en 1er Param ; RUN_JOB_COLS est une const de colonnes FIXES
    // (identifiants, non paramétrables). LIMIT/OFFSET (entiers clampés) LIÉS en derniers placeholders.
    let (mut conds, mut params): (Vec<String>, Vec<crate::store::Param>) =
        (vec!["engagement_id=?".into()], vec![crate::store::Param::Int(eid)]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?".into()); params.push(crate::store::Param::Text(c.clone())); }
    if let Some(s) = q.get("status") { conds.push("status=?".into()); params.push(crate::store::Param::Text(s.clone())); }
    let where_ = format!(" WHERE {}", conds.join(" AND "));
    let (limit, offset) = paginate(&q, 100, 1000);
    params.push(crate::store::Param::Int(limit));
    params.push(crate::store::Param::Int(offset));
    let sql = format!("SELECT {RUN_JOB_COLS} FROM run_job{where_} ORDER BY id DESC LIMIT ? OFFSET ?");
    // query_lax reproduit `query_map(..).filter_map(|r| r.ok())` (lignes malformées ignorées) ; une erreur
    // de prepare/bind PROPAGE (Err) -> unwrap_or_default() rend `[]`, identique à l'ancien `Err(_) => []`.
    let out: Vec<Value> = app.store().query_lax(&sql, &params, run_job_json).unwrap_or_default();
    Json(Value::Array(out))
}

/// GET /api/runs/:id — détail d'un run. Lecture (viewer).
pub(crate) async fn run_detail(State(app): State<App>, Path(id): Path<String>) -> impl IntoResponse {
    let store = app.store();
    let sql = format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?");
    // query_row rend Err(NoRows) sur résultat vide (miroir de QueryReturnedNoRows) -> branche 404 inchangée.
    match store.query_row(&sql, &crate::sql_params![&id], run_job_json) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"}))),
    }
}

/// GET /api/runs/:id/logs?after=ID — lignes de log d'un run (fallback polling de SSE).
/// `after` (id de ligne) permet l'incrémental ; renvoie {last_id, lines:[{id,ts,stream,line}]}.
pub(crate) async fn run_logs(State(app): State<App>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let after = q.get("after").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(2000).clamp(1, 5000);
    
    let mut last = after;
    let lines: Vec<Value> = app.store()
        .query_lax(
            "SELECT id,ts,stream,line FROM run_log WHERE run_id=? AND id>? ORDER BY id LIMIT ?",
            &crate::sql_params![&id, after, limit],
            |r| {
                let lid = r.get_i64(0)?;
                Ok((lid, json!({
                    "id": lid,
                    "ts": r.get_opt_str(1)?.unwrap_or_default(),
                    "stream": r.get_opt_str(2)?.unwrap_or_default(),
                    "line": r.get_opt_str(3)?.unwrap_or_default(),
                })))
            },
        )
        .unwrap_or_default()
        .into_iter()
        .map(|(lid, v)| { if lid > last { last = lid; } v })
        .collect();
    Json(json!({"last_id": last, "lines": lines}))
}

/// GET /api/runs/:id/events — flux SSE des lignes de log + transitions de statut d'un run.
/// Events : `log` ({stream,line}) et `status` ({status,exit_code?}). Fallback : /api/runs/:id/logs.
/// Diffuse les events broadcast filtrés sur run_id. Termine quand le statut devient terminal.
pub(crate) async fn run_sse(State(app): State<App>, Path(id): Path<String>) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let rx = app.events.subscribe();
    let stream = futures_util::stream::unfold((rx, id, false), |(mut rx, id, mut done)| async move {
        if done {
            return None;
        }
        loop {
            match rx.recv().await {
                Ok(ev) if ev.run_id == id => {
                    if ev.kind == "status" {
                        let s = ev.payload.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        if matches!(s, "done" | "failed" | "timeout" | "cancelled") {
                            done = true;
                        }
                    }
                    let event = Event::default().event(ev.kind.clone()).json_data(&ev.payload).unwrap_or_else(|_| Event::default().comment("bad"));
                    return Some((Ok(event), (rx, id, done)));
                }
                Ok(_) => continue, // évènement d'un autre run
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // le consommateur SSE a pris du retard et a PERDU `n` évènements (buffer broadcast
                    // débordé). On émet un event `lag` explicite -> le client sait qu'il a un trou et
                    // peut se resynchroniser via /api/runs/:id/logs?after=... (au lieu d'un silence).
                    let event = Event::default().event("lag")
                        .json_data(json!({"dropped": n}))
                        .unwrap_or_else(|_| Event::default().comment("lag"));
                    return Some((Ok(event), (rx, id, done)));
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("keep-alive"))
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
            disabled_modules: vec![], body_targets: serde_json::json!([]),
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

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

/// Réconcilie les run_job 'running' au boot : un process spawné qui n'a pas survécu au reboot de la
/// console est orphelin -> 'failed' (jamais laissé 'running' à tort). Opère sur la table (source de
/// vérité) : il traite en une passe TOUS les runs orphelins, quel que soit leur engagement — la
/// concurrence inter-engagement (plusieurs runs 'running' simultanés au crash) est gérée nativement,
/// chacun restant rattaché à SON engagement_id en base. En PLUS :
///   - tue le GROUPE de process (killpg) de tout pgid enregistré et encore vivant (un moteur détaché
///     qui aurait survécu à un simple restart console deviendrait sinon incontrôlable -> on le coupe) ;
///   - purge les dirs temp `forge-run-*` (scope.json/targets.json) laissés par des runs interrompus.
pub(crate) fn reconcile_runs(store: &crate::store::Store) {
    // 1) collecter les pgid des runs marqués 'running' (avant de les flipper). query_lax = idiome
    //    lenient (les lignes mal formées sont sautées, comme `query_map(..).filter_map(|r| r.ok())`) ;
    //    une erreur de PREPARE propage -> `unwrap_or_default()` rend `vec![]` (parité `Err(_) => vec![]`).
    let orphan_pgids: Vec<i32> = store
        .query_lax(
            "SELECT pid FROM run_job WHERE status='running' AND pid>1",
            &crate::sql_params![],
            |r| r.get_i64(0).map(|p| p as i32),
        )
        .unwrap_or_default();
    // 2) couper tout groupe encore vivant (best-effort ; SIGTERM via killpg). kill_group ignore <=1.
    for pgid in &orphan_pgids {
        kill_group(*pgid);
    }
    // 3) marquer les runs orphelins comme 'failed'.
    let n = store
        .execute(
            "UPDATE run_job SET status='failed', finished=datetime('now'), pid=-1,
               detail=COALESCE(NULLIF(detail,''),'')||' [reconciled: orphelin au boot]'
             WHERE status='running'",
            &crate::sql_params![],
        )
        .unwrap_or(0);
    if n > 0 {
        println!(
            "[forge-console] reconcile: {n} run(s) orphelin(s) 'running' -> 'failed' ({} groupe(s) signalé(s))",
            orphan_pgids.len()
        );
    }
    // 4) purge des dirs temp de runs (forge-run-*) laissés derrière par des runs interrompus.
    purge_stale_run_dirs();
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
struct RunReservation<'a> {
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

    // (6) FIFO PAR ENGAGEMENT : au plus UN run vivant par engagement. Le verrou async sérialise la
    // réservation (check -> insert) des /api/run concurrents ; si un run est déjà enregistré pour CET
    // engagement -> 409 (refus immédiat, pas de file d'attente). ISOLATION/CONCURRENCE : la présence
    // d'un run pour un AUTRE engagement (autre clé de la map) n'entrave PAS ce démarrage — deux
    // engagements peuvent tourner en parallèle sans 409 croisé. La clé est l'engagement_id résolu (eng.id)
    // : on ne consulte JAMAIS le slot d'un autre engagement.
    // RÉSERVATION CANCELLATION-SAFE (CONC-1) : on prend le verrou async `run_state` (bref : juste
    // `contains_key` + rien d'autre) ET le verrou std `run_reservations` (microsecondes) le temps de
    // décider ET de poser la réservation, PUIS on les relâche IMMÉDIATEMENT (fin de bloc) — le travail
    // lourd (fs/DB/spawn/ledger) se fait SANS aucun de ces verrous. 409 si un run est déjà VIVANT
    // (run_state) OU déjà RÉSERVÉ (run_reservations) pour CET engagement : la fenêtre entre réservation
    // et promotion est ainsi couverte (deux /api/run concurrents sur le même engagement -> le 2e voit
    // la réservation -> 409). ISOLATION : clé = eng.id ; un autre engagement (autre clé) n'entrave rien
    // -> deux engagements DIFFÉRENTS démarrent en parallèle (plus de sérialisation globale). Aucun
    // verrou tenu à travers un `.await` (le std `run_reservations` en particulier ne l'est jamais).
    {
        let state = app.run_state.lock().await;
        // std Mutex : jamais tenu à travers un `.await` ; poison-safe.
        let mut resv = app.run_reservations.lock().unwrap_or_else(|e| e.into_inner());
        if state.current.contains_key(&eng.id) || resv.contains(&eng.id) {
            return (StatusCode::CONFLICT, Json(json!({"error": "run_in_progress", "engagement_id": eng.id, "why": format!("un run est déjà en cours pour l'engagement #{} (FIFO par engagement : un seul à la fois par engagement)", eng.id)})));
        }
        resv.insert(eng.id);
    } // les DEUX verrous sont relâchés ici — le travail lourd ci-dessous n'en tient AUCUN.

    // À partir d'ici, TOUT chemin de sortie (return d'erreur, panic, drop-du-future/annulation) libère
    // la réservation via le `Drop` de ce guard. Sur SUCCÈS, on posera `active=false` après avoir promu
    // le run dans `run_state` (cf. plus bas), pour que le Drop soit un no-op.
    let mut reservation = RunReservation { app: &app, eng_id: eng.id, active: true };

    // run_id : horodaté + suffixe aléatoire (traçable, unique).
    let run_id = format!("run-{}-{}", chrono_now_compact(), gen_token().chars().take(8).collect::<String>());

    // (4) dir temp par run : scope.json (FORCÉ non-exploit/non-destructif) + targets.json.
    let run_dir = std::env::temp_dir().join(format!("forge-run-{run_id}"));
    if let Err(e) = std::fs::create_dir_all(&run_dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "mkdir_failed", "why": e.to_string()})));
    }
    // scope du run : RESTREINT aux cibles validées. allow_exploit/destructive suivent l'opt-in
    // haut-impact GOUVERNÉ (high_impact) : false par défaut (plancher), true UNIQUEMENT si l'opt-in
    // a été honoré (operator + arm + reason). INVARIANT : on ne touche QUE allow_exploit/destructive —
    // in_scope/out_scope (le périmètre) restent dictés par le scope serveur, le scope-guard du moteur
    // reste seul juge et VÉTOE toute cible hors-scope même avec l'opt-in.
    // `module_params` est transporté tel quel (clé additive ignorée par le ROE/Scope actuel —
    // forward-compat : le moteur la consommera sans changement de l'API de la console).
    let scope_comment = if high_impact {
        format!("scope généré par la console pour {run_id} — HAUT-IMPACT GOUVERNÉ (allow_exploit/destructive=true, autorisé par operator armé)")
    } else {
        format!("scope généré par la console pour {run_id} — exploit/destructif IMPOSSIBLES (forcés false)")
    };
    let scope_notes = if high_impact {
        "lancé via console C2-light (gouverné/audité) — opt-in HAUT-IMPACT honoré (operator+arm+reason) ; scope-guard moteur inchangé (hors-scope = VETO)"
    } else {
        "lancé via console C2-light (gouverné/audité) — non-exploit, non-destructif forcés"
    };
    // GOUVERNANCE CONNECTEUR — ENFORCEMENT AU TIR : la liste des connecteurs DÉSACTIVÉS par l'opérateur
    // (enabled=0 / available_override=0) est injectée dans le scope.json du run. Le moteur la lit
    // (roe.Scope.disabled_modules) et SKIP ces kinds EXACTEMENT comme un outil absent — y compris les
    // modules choisis par le PLANNER (au-delà de `--modules`). C'est le complément indispensable au filtre
    // `--modules` ci-dessous : ensemble, ils garantissent qu'un connecteur désactivé ne tire jamais.
    let disabled_modules = operator_disabled_modules(&app);
    // SÉLECTION DE TECHNIQUES PAR-SCOPE — l'intention persistée (profil + toggles catégorie/technique)
    // est injectée dans le scope.json du run. Le moteur en RÉSOUT l'ensemble effectif
    // (resolve_enabled_kinds) et l'ENFORCE : une technique hors-profil/désactivée n'est NI planifiée NI
    // tirée (fail-closed), en plus de la gouvernance connecteur et du scope-guard. Défaut : profil
    // bug_bounty (liste qualifiante). N'altère AUCUN garde-fou de capacité (allow_* restent dictés par
    // l'opt-in haut-impact ci-dessus). Une entrée de run explicite `profile`/`categories_enabled`/
    // `techniques_enabled` dans le corps override la sélection persistée (sinon : la persistée).
    // ENGAGEMENT : à défaut d'override explicite dans le corps, la sélection PERSISTÉE est celle de CET
    // engagement (technique_selection_value_for(eng.id)) — chaque engagement a SON profil/toggles.
    let selection = match body.get("technique_selection") {
        Some(v) if v.is_object() => validate_technique_selection(v).unwrap_or_else(|_| technique_selection_value_for(&app, eng.id)),
        _ => technique_selection_value_for(&app, eng.id),
    };
    let sel_profile = selection.get("profile").cloned().unwrap_or(json!("bug_bounty"));
    let sel_categories = selection.get("categories").cloned().unwrap_or(json!({}));
    let sel_techniques = selection.get("techniques").cloned().unwrap_or(json!({}));
    let scope_doc = json!({
        "_comment": scope_comment,
        // mode + out_scope viennent de L'ENGAGEMENT (pas des App globals) : le scope-guard du moteur
        // applique le périmètre de CET engagement. in_scope = cibles validées ⊆ scope de l'engagement.
        "mode": eng.mode,
        "in_scope": targets,
        "out_scope": eng.scope_out.clone(),
        "rate": 5,
        "allow_exploit": high_impact,
        "allow_destructive": high_impact,
        "known_creds": [],
        "idor_targets": [],
        "module_params": Value::Object(module_params.clone()),
        "disabled_modules": disabled_modules.clone(),
        // sélection de techniques par-scope (enforcée par le moteur : profil ∪ activations − désactivations).
        "profile": sel_profile.clone(),
        "categories_enabled": sel_categories.clone(),
        "techniques_enabled": sel_techniques.clone(),
        "notes": scope_notes
    });
    // Chaque cible porte les params par-module dans `attrs.module_params` (le moteur charge déjà
    // Target.attrs tel quel). Doublon volontaire avec le scope : selon que le module lit le scope
    // global ou les attrs de sa cible, les params sont disponibles des deux côtés (passthrough sûr).
    let module_params_val = Value::Object(module_params.clone());
    let targets_doc: Vec<Value> = targets.iter()
        .map(|h| json!({"host": h, "kind": "host", "attrs": {"module_params": module_params_val.clone()}}))
        .collect();
    let scope_path = run_dir.join("scope.json");
    let targets_path = run_dir.join("targets.json");
    if std::fs::write(&scope_path, serde_json::to_vec(&scope_doc).unwrap()).is_err()
        || std::fs::write(&targets_path, serde_json::to_vec(&Value::Array(targets_doc)).unwrap()).is_err()
    {
        let _ = std::fs::remove_dir_all(&run_dir);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write_failed", "why": "écriture scope/targets impossible"})));
    }

    // (4) argv FIXE — aucun shell. Les valeurs proviennent de fichiers (chemins) ou sont validées.
    // Le token de la console (en clair) est transmis au moteur UNIQUEMENT via l'environnement
    // (FORGE_CONSOLE_TOKEN), JAMAIS en argv : argv est visible de tout utilisateur local via
    // `ps`/proc/<pid>/cmdline -> y mettre le bearer fuiterait le secret. console_client.ingest lit
    // déjà FORGE_CONSOLE_TOKEN en repli quand --console-token est absent.
    let token: Option<String> = if app.token_raw.is_empty() { None } else { Some(app.token_raw.as_str().to_string()) };
    let console_url = format!("http://{}", std::env::var("FORGE_CONSOLE_ADDR").unwrap_or_else(|_| "127.0.0.1:7100".to_string()));
    let mut argv: Vec<String> = vec![
        "-m".into(), "forge.cli".into(), "campaign".into(),
        "--scope".into(), scope_path.to_string_lossy().into_owned(),
        "--targets".into(), targets_path.to_string_lossy().into_owned(),
        "--campaign".into(), campaign.clone(),
        "--mode".into(), mode.to_string(),
        "--run-id".into(), run_id.clone(),
        // --ledger : le ledger DÉDIÉ de l'engagement (chaîne SHA-256 tamper-evident propre à SON
        // engagement). Le moteur y écrit ses actes ; jamais le ledger d'un autre engagement.
        "--ledger".into(), eng.ledger_path.clone(),
        "--console".into(), console_url.clone(),
    ];
    if let Some(b) = budget { argv.push("--budget".into()); argv.push(format!("{b}")); }
    if exhaustive { argv.push("--exhaustive".into()); }
    // --auto-pentest : balaie l'ensemble EFFECTIF de techniques du scope (profil + toggles). Gouverné à
    // l'identique (le scope écrit force allow_* selon l'opt-in ; le ROE gate chaque action).
    if auto_pentest { argv.push("--auto-pentest".into()); }
    // sélection de modules de l'UI -> --modules kind1,kind2 : RESTREINT le plan du moteur aux
    // kinds demandés (déjà validés : ⊆ kinds connus, web_allowed=1, ni exploit ni destructif).
    // Vide -> flag omis -> le moteur garde le plan complet du cerveau (comportement inchangé).
    // Les kinds passent la grammaire validate_modules (kind bien formé) : pas d'injection d'argv
    // (argv FIXE, aucun shell), et la gate ROE reste seule juge des capacités.
    // GOUVERNANCE CONNECTEUR — filtre au spawn : la liste passée EXCLUT tout connecteur désactivé par
    // l'opérateur (défense en profondeur ; validate_modules l'a déjà refusé, mais un désactivé n'atteint
    // JAMAIS l'argv). NB : on ne passe le flag que si la liste DEMANDÉE était non vide — une liste vidée
    // par le filtre resterait vide et NE retombe PAS en « plan complet » (validate_modules ayant refusé
    // toute demande contenant un désactivé, ce cas ne se présente pas ; le scope.json disabled_modules
    // couvre de toute façon le plan complet du planner).
    let spawn_modules = filter_enabled_modules(&app, &requested_modules);
    if !spawn_modules.is_empty() {
        argv.push("--modules".into());
        argv.push(spawn_modules.join(","));
    }
    if !reason.is_empty() { argv.push("--reason".into()); argv.push(reason.clone()); }
    // --arm : armement explicite. Sans opt-in haut-impact honoré il reste inerte côté capacité (le
    // scope écrit force allow_*=false). Avec l'opt-in honoré (high_impact), le scope écrit
    // allow_exploit/destructive=true -> le moteur peut exécuter les modules haut-impact AUTORISÉS,
    // toujours sous le veto scope-guard pour le périmètre.
    if arm { argv.push("--arm".into()); }
    // NB: pas de `--console-token` en argv (fuite via ps/cmdline) — passé par env ci-dessous.

    let mut cmd = tokio::process::Command::new(app.python.as_str());
    cmd.args(&argv)
        .current_dir(app.pkg_dir.as_str())
        .env("FORGE_CONSOLE_URL", &console_url)
        // STREAMING LIVE : force le stdout Python en mode NON bufferisé pour que les lignes d'avancement
        // par action (verdict/SKIP) et les bannières de vague atteignent le superviseur -> run_log -> SSE
        // AU FIL DE L'EAU, au lieu d'arriver en bloc à la fin (stdout est block-buffered vers un pipe).
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
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "spawn_failed", "why": e.to_string()})));
        }
    };
    let pid = child.id().map(|p| p as i32).unwrap_or(-1);
    let pgid = pid; // setsid => le PID enfant EST le PGID.

    // AUDIT haut-impact : si l'opt-in a été honoré, lister précisément les modules exploit/destructif
    // explicitement demandés qui ont été DÉBLOQUÉS (pour la traçabilité ; vide si le planner choisit
    // seul). N'altère aucun garde-fou — lecture du registre uniquement.
    let hi_modules: Vec<String> = if high_impact { high_impact_modules(&app, &requested_modules) } else { vec![] };

    // run_job 'running' + provenance opérateur. ATTRIBUTION : on résout l'IDENTITÉ individuelle depuis
    // la session (login réel) si présente ; sinon repli rétro-compat sur 'operator' (compte bootstrap
    // env-hash ou dev-open). Le started_by encode `<login>` et, pour un run armé, `<login>+high_impact`
    // -> tout run haut-impact reste traçable au COMPTE qui l'a déclenché, sans nouvelle colonne.
    let actor = attribution_login(&app, &headers);
    let started_by = if high_impact { format!("{actor}+high_impact") } else { actor.clone() };
    {
        let store = app.store();
        let _ = store.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,mode,pid,started_by,reason,targets,modules,started,engagement_id)
             VALUES(?,?,datetime('now'),'running',?,?,?,?,?,?,datetime('now'),?)
             ON CONFLICT(run_id) DO UPDATE SET status='running', pid=excluded.pid, started=excluded.started",
            &crate::sql_params![
                &run_id, &campaign, mode, pgid, &started_by, &reason,
                serde_json::to_string(&body.get("targets").cloned().unwrap_or(json!([]))).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&requested_modules).unwrap_or_else(|_| "[]".into()),
                eng.id
            ],
        );
    }
    // ledger : trace l'acte de lancement (qui/quoi/quand) — preuve d'audit côté console. Quand
    // l'opt-in haut-impact est honoré, on JOURNALISE EXPLICITEMENT l'autorisation (operator + reason
    // + liste des modules exploit/destructif débloqués), de sorte que tout lancement haut-impact soit
    // traçable et non-répudiable dans la chaîne du ledger.
    if high_impact {
        append_run_ledger_path(&app, &eng.ledger_path, "console.run.high_impact_authorized", json!({
            "run_id": run_id, "engagement_id": eng.id, "campaign": campaign, "actor": actor, "by": "operator",
            "arm": arm, "reason": reason,
            "exploit_modules_authorized": hi_modules,
            "requested_modules": requested_modules,
            "allow_exploit": true, "allow_destructive": true,
            "note": "opt-in haut-impact GOUVERNÉ honoré (operator+arm+reason) ; scope-guard moteur inchangé (hors-scope = VETO)"
        }));
    }
    append_run_ledger_path(&app, &eng.ledger_path, "console.run.start", json!({
        "run_id": run_id, "engagement_id": eng.id, "campaign": campaign, "mode": mode, "actor": actor, "by": "operator",
        "targets": body.get("targets").cloned().unwrap_or(json!([])), "modules": requested_modules,
        "module_params": Value::Object(module_params.clone()),
        // gouvernance connecteur : connecteurs désactivés (skippés au tir, y compris plan planner).
        "disabled_modules": disabled_modules,
        // sélection de techniques par-scope enforcée par le moteur + mode pentest automatisé.
        "technique_selection": selection,
        "auto_pentest": auto_pentest,
        "reason": reason, "arm_requested": arm,
        "high_impact": high_impact,
        "exploit_floor": if high_impact { "lifted via governed high-impact opt-in (allow_exploit=true allow_destructive=true)" } else { "forced allow_exploit=false allow_destructive=false" }
    }));

    // PROMOTION réservation -> run vivant. On reprend le verrou async `run_state` BRIÈVEMENT (juste un
    // insert) pour enregistrer le RunHandle réel sous la clé engagement_id (ce run devient le run vivant
    // de CET engagement ; un autre engagement garde son propre slot — aucune interférence), PUIS on
    // retire la réservation du set std et on désarme le guard (active=false) pour que son Drop soit un
    // no-op. Ordre volontaire : le run vivant est publié dans `run_state` AVANT de retirer la
    // réservation, donc il n'existe aucune fenêtre où ni la réservation ni le run vivant ne seraient
    // visibles (un /api/run concurrent voit toujours l'un ou l'autre -> 409 maintenu). Aucun `.await`
    // n'est fait tant que le verrou std `run_reservations` est tenu.
    {
        let mut state = app.run_state.lock().await;
        state.current.insert(eng.id, RunHandle { run_id: run_id.clone(), pgid });
        let mut resv = app.run_reservations.lock().unwrap_or_else(|e| e.into_inner());
        resv.remove(&eng.id);
        reservation.active = false; // run promu et traqué dans run_state -> Drop = no-op (pas de double-libération)
    } // verrous run_state (async) + run_reservations (std) relâchés ici.
    let _ = app.events.send(RunEvent { run_id: run_id.clone(), kind: "status".into(), payload: json!({"status": "running"}) });

    // superviseur : pompe stdout/stderr -> run_log + SSE ; watchdog timeout ; finalisation atomique.
    // Reçoit l'engagement_id (clé du slot à libérer), le pgid (kill group du watchdog) et le ledger
    // DÉDIÉ de l'engagement pour y journaliser la fin de run (isolation par engagement).
    spawn_supervisor(app.clone(), child, run_id.clone(), eng.id, pgid, run_dir, eng.ledger_path.clone());

    (StatusCode::ACCEPTED, Json(json!({"run_id": run_id, "status": "running", "campaign": campaign, "mode": mode, "high_impact": high_impact, "auto_pentest": auto_pentest})))
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
    let store = app.store();
    for m in modules {
        let row = store.query_row(
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
    let store = app.store();
    let (mut conds, mut args): (Vec<String>, Vec<String>) = (vec![format!("engagement_id={eid}")], vec![]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?".into()); args.push(c.clone()); }
    if let Some(s) = q.get("status") { conds.push("status=?".into()); args.push(s.clone()); }
    let where_ = format!(" WHERE {}", conds.join(" AND "));
    let (limit, offset) = paginate(&q, 100, 1000);
    let sql = format!("SELECT {RUN_JOB_COLS} FROM run_job{where_} ORDER BY id DESC LIMIT {limit} OFFSET {offset}");
    // query_lax reproduit `query_map(..).filter_map(|r| r.ok())` (lignes malformées ignorées) ; une erreur
    // de prepare/bind PROPAGE (Err) -> unwrap_or_default() rend `[]`, identique à l'ancien `Err(_) => []`.
    let params: Vec<crate::store::Param> = args.iter().map(|s| crate::store::Param::from(s.as_str())).collect();
    let out: Vec<Value> = store.query_lax(&sql, &params, run_job_json).unwrap_or_default();
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
    let store = app.store();
    let mut last = after;
    let lines: Vec<Value> = store
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


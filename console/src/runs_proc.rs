// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SUPERVISION DE PROCESS OS du run-lifecycle (PURE MOVE extrait de `runs.rs`). Frontière
//! OS quasi sans couplage : helpers de process POSIX (`spawn_setsid`/`kill_group` + repli non-Unix), purge
//! des dirs temp (`purge_stale_run_dirs`), pousseur de logs run_log+SSE (`push_run_log`), le CŒUR du spawn
//! gouverné (`claim_and_spawn` : écrit scope/targets, spawne le moteur sans shell, promeut le run) et le
//! superviseur détaché (`spawn_supervisor` : pompes stdout/stderr, watchdog, finalisation).
//!
//! Structs d'ÉTAT (App/RunHandle/RunEvent/RunReservation/RunSpawnSpec) référencées via `crate::*` ; re-
//! exporté `pub(crate)` à la racine — appelants (`run_create`, `run_cancel`, le tick leader) INCHANGÉS.
use crate::*;

use axum::http::StatusCode;
use axum::response::Json;
use serde_json::{json, Value};
use std::time::Duration;

/// URL que le MOTEUR spawné utilise pour POST /api/ingest. `FORGE_CONSOLE_ADDR` est l'adresse de BIND
/// de la console (ex. `0.0.0.0:7100` en Docker) ; un host de bind wildcard/unspecified (`0.0.0.0`, `::`)
/// N'EST PAS un Host valide pour le garde anti-rebinding `host_guard` (allowlist =
/// localhost/127.0.0.1/::1) -> le moteur recevait `421 Misdirected Request` (B2). Le moteur tournant sur
/// le MÊME host que la console, on POST TOUJOURS en loopback `127.0.0.1:<port>` : ce Host est toujours
/// dans l'allowlist. On ne conserve du bind que le PORT (dernier segment `:`), défaut 7100.
pub(crate) fn engine_console_url(bind_addr: &str) -> String {
    let port = bind_addr
        .rsplit(':')
        .next()
        .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("7100");
    format!("http://127.0.0.1:{port}")
}

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

/// Grâce (s) laissée au GROUPE moteur entre le SIGTERM (cancel/watchdog -> D1 flushe le travail en
/// vol) et le SIGKILL de dernier ressort. Miroir du `_TERM_GRACE=5` de `forge/runner.py` : term
/// gracieux d'abord (persistance D1), kill ferme si le moteur ne sort pas.
pub(crate) const CANCEL_GRACE_SECS: u64 = 5;

/// Vrai si le GROUPE de process `pgid` a AU MOINS un membre VIVANT. `kill(-pgid, 0)` : signal 0 =
/// test d'existence pur (n'envoie rien), pid NÉGATIF = tout le groupe -> 0 si l'appelant peut
/// signaler ≥1 membre, ESRCH si le groupe est vide. Note : un leader ZOMBIE non encore récolté
/// répond « vivant » — le superviseur le récolte (`child.wait`) peu après sa mort.
#[cfg(unix)]
pub(crate) fn group_alive(pgid: i32) -> bool {
    if pgid <= 1 {
        return false;
    }
    unsafe { libc::kill(-pgid, 0) == 0 }
}

#[cfg(not(unix))]
pub(crate) fn group_alive(pgid: i32) -> bool {
    let _ = pgid;
    false
}

/// ESCALADE SIGKILL du GROUPE moteur (le SIGTERM a DÉJÀ été envoyé par `kill_group` juste avant).
/// Sonde le groupe pendant `grace` : s'il disparaît (sortie gracieuse D1) on s'arrête sans SIGKILL ;
/// sinon (moteur wedgé / handler qui ne sort pas dans les temps) on SIGKILL TOUT le groupe — signal
/// non-catchable, garantit la mort du moteur (fin du « cancel = no-op » : un moteur bloqué qui
/// continuait à lancer des outils est désormais coupé). Idempotent + fail-safe : `pgid<=1` ou groupe
/// déjà mort -> les signaux sont avalés par le noyau (ESRCH). Réutilise le killpg du watchdog.
#[cfg(unix)]
pub(crate) async fn escalate_kill_group(pgid: i32, grace: std::time::Duration) {
    if pgid <= 1 {
        return;
    }
    let step = std::time::Duration::from_millis(100);
    let mut waited = std::time::Duration::ZERO;
    while waited < grace {
        if !group_alive(pgid) {
            return; // sorti proprement dans la grâce (D1 a flushé) -> pas de SIGKILL.
        }
        tokio::time::sleep(step).await;
        waited += step;
    }
    // Toujours vivant après la grâce -> dernier ressort : SIGKILL de TOUT le groupe.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
pub(crate) async fn escalate_kill_group(pgid: i32, _grace: std::time::Duration) {
    let _ = pgid;
}

/// Reaping FAIL-SAFE d'un enfant moteur DÉJÀ spawné dont le bookkeeping post-spawn a ÉCHOUÉ — garantit
/// AUCUN orphelin ni faux-succès. `kill_on_drop(true)` ne SIGKILL que le PID direct (pas le GROUPE setsid,
/// donc pas les petits-enfants) et laisse scope.json/targets.json sur disque : on nettoie explicitement.
/// Ordre : (1) SIGTERM du GROUPE entier via `kill_group` TANT QU'on connaît le pgid, (2) SIGKILL du PID
/// direct + `wait().await` pour RÉCOLTER le zombie de façon DÉTERMINISTE (pas de zombie résiduel), (3)
/// suppression du dir temp du run. Async car `wait` est awaité — on tourne déjà dans le handler async.
async fn reap_orphaned_spawn(pgid: i32, mut child: tokio::process::Child, run_dir: &std::path::Path) {
    kill_group(pgid);
    let _ = child.start_kill();
    let _ = child.wait().await; // récolte l'enfant (plus d'orphelin NI de zombie)
    let _ = std::fs::remove_dir_all(run_dir);
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
            println!("[forge] reconcile: {purged} dir(s) temp forge-run-* purgé(s)");
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
/// Construit le `scope.json` du run (fonction PURE, testable). CONTRAT avec le moteur Python (roe.Scope) :
///   - `mode`/`in_scope`/`out_scope` = périmètre de L'ENGAGEMENT (le scope-guard reste seul juge) ;
///   - `allow_exploit`/`allow_destructive` = opt-in haut-impact GOUVERNÉ (false par défaut) ;
///   - `allow_private` = EFFECTIF (master global AND opt-in engagement, calculé server-side dans run_create) ;
///     le moteur le lit (défaut False si absent) et VÉTO toute cible privée/loopback OU qui RÉSOUT en privé.
/// INVARIANT : on ne touche JAMAIS in_scope/out_scope ici — uniquement les bascules de capacité/politique.
pub(crate) fn build_run_scope_doc(run_id: &str, spec: &RunSpawnSpec) -> Value {
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
    json!({
        "_comment": scope_comment,
        // mode + out_scope viennent de L'ENGAGEMENT (figés dans le spec) : le scope-guard du moteur applique
        // le périmètre de CET engagement. in_scope = cibles validées ⊆ scope de l'engagement.
        "mode": spec.eng_mode,
        "in_scope": spec.targets,
        "out_scope": spec.eng_scope_out,
        // DÉBIT : override per-run si fourni (throttle oracle + drapeaux de débit outils), sinon défaut 5.
        // `rate_explicit` gate l'ajout des drapeaux CLI aux sous-process (byte-identique sans override).
        "rate": spec.rate.unwrap_or(5),
        "rate_explicit": spec.rate.is_some(),
        "allow_exploit": spec.high_impact,
        "allow_destructive": spec.high_impact,
        // POLITIQUE RÉSEAU (privé/LAN/loopback) — CONTRAT avec le moteur (roe.Scope lit `allow_private`,
        // défaut False si absent). EFFECTIF = master global AND opt-in engagement (calculé dans run_create).
        // False => le moteur VÉTO toute cible privée OU qui RÉSOUT en privé (anti-rebinding, seul juge autoritatif).
        "allow_private": spec.allow_private,
        "known_creds": [],
        "idor_targets": [],
        "module_params": spec.module_params.clone(),
        "disabled_modules": spec.disabled_modules.clone(),
        "profile": sel_profile,
        "categories_enabled": sel_categories,
        "techniques_enabled": sel_techniques,
        "notes": scope_notes
    })
}

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
    // Construction EXTRAITE (fonction PURE, testable) : le CONTRAT scope.json est ainsi vérifiable en test.
    let scope_doc = build_run_scope_doc(run_id, spec);
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
    // B2 — le moteur POST /api/ingest en LOOPBACK (127.0.0.1:<port du bind>), JAMAIS sur l'host de bind
    // (0.0.0.0 en Docker) qui déclenchait un 421 host_guard. Même host que la console -> loopback toujours
    // joignable et son Host toujours dans l'allowlist. Cf. `engine_console_url`.
    let console_url = engine_console_url(
        &std::env::var("FORGE_CONSOLE_ADDR").unwrap_or_else(|_| "127.0.0.1:7100".to_string()),
    );
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
    let write_res = if ha {
        let store = app.store();
        store.execute(
            "UPDATE run_job SET pid=?, started=datetime('now') WHERE run_id=?",
            &crate::sql_params![pgid, run_id],
        )
    } else {
        let store = app.store();
        store.execute(
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
        )
    };
    // FAIL-SAFE (swallowed-write hardening) : l'écriture d'appartenance/de ligne post-spawn a échoué. Le
    // process moteur est DÉJÀ spawné et détaché (setsid) : un simple 500 ici ORPHELINERAIT l'enfant (et son
    // groupe) + laisserait scope.json/targets.json sur disque, tout en signalant faussement l'échec. On TUE
    // le groupe de process fraîchement spawné, on RÉCOLTE l'enfant et on nettoie le dir AVANT de renvoyer
    // l'erreur — puis on un-claime la ligne HA 'running'. Aucun orphelin, aucun faux-succès.
    if let Err(e) = write_res {
        reap_orphaned_spawn(pgid, child, &run_dir).await;
        unclaim_running_on_failure(app, run_id, ha); // HA : la ligne 'running' claimée pré-spawn -> 'failed'
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "ownership_write_failed", "why": e.to_string()})));
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

#[cfg(test)]
mod scope_doc_contract_tests {
    use super::*;

    /// Spec minimal paramétré uniquement par high_impact + allow_private (le reste inerte).
    fn spec(high_impact: bool, allow_private: bool) -> RunSpawnSpec {
        RunSpawnSpec {
            run_id: "run-x".into(), eng_id: 1, eng_mode: "white".into(),
            eng_scope_out: vec!["out.example".into()], eng_ledger_path: String::new(),
            campaign: "c".into(), targets: vec!["10.0.0.5".into()], requested_modules: vec![],
            module_params: json!({}), mode: "auto".into(), budget: None, exhaustive: false,
            auto_pentest: false, reason: String::new(), arm: false, high_impact,
            started_by: "op".into(), actor: "op".into(), selection: json!({}),
            disabled_modules: vec![], body_targets: json!(["10.0.0.5"]), rate: None,
            allow_private,
        }
    }

    /// CONTRAT scope.json (linchpin) : le writer Rust émet `allow_private` = valeur EFFECTIVE du spec, et
    /// n'y touche JAMAIS in_scope/out_scope (le périmètre reste dicté par l'engagement). Le reader Python
    /// (roe.Scope) lit exactement cette clé (défaut False si absente).
    #[test]
    fn scope_doc_carries_effective_allow_private_and_preserves_scope() {
        let on = build_run_scope_doc("run-x", &spec(false, true));
        assert_eq!(on["allow_private"], json!(true), "allow_private effectif=true écrit tel quel");
        let off = build_run_scope_doc("run-x", &spec(false, false));
        assert_eq!(off["allow_private"], json!(false), "allow_private effectif=false écrit tel quel (fail-closed)");
        // in_scope/out_scope INTOUCHÉS par la politique réseau (seul allow_private varie).
        assert_eq!(off["in_scope"], json!(["10.0.0.5"]));
        assert_eq!(off["out_scope"], json!(["out.example"]));
        // orthogonal au haut-impact : allow_private ne dépend pas de allow_exploit/destructive.
        let hi = build_run_scope_doc("run-x", &spec(true, false));
        assert_eq!(hi["allow_exploit"], json!(true));
        assert_eq!(hi["allow_private"], json!(false), "politique réseau indépendante du haut-impact");
    }
}

#[cfg(all(test, unix))]
mod reap_tests {
    use super::{escalate_kill_group, group_alive, kill_group, reap_orphaned_spawn, spawn_setsid};
    use std::time::Duration;

    /// `libc::kill(pid, 0)` == -1 avec ESRCH => le PID n'existe PLUS (ni vivant, ni zombie non récolté).
    fn process_gone(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == -1 && *libc::__errno_location() == libc::ESRCH }
    }

    /// Reproduit le chemin d'échec d'écriture post-spawn de `claim_and_spawn` : un enfant est spawné dans
    /// son PROPRE groupe de session (setsid, comme le moteur), puis `reap_orphaned_spawn` doit le TUER, le
    /// RÉCOLTER (pas d'orphelin/zombie) et SUPPRIMER son dir temp. Prouve qu'un 500 post-spawn ne laisse
    /// aucun process détaché ni fichier scope/targets derrière lui.
    #[tokio::test]
    async fn reap_kills_group_and_removes_dir() {
        let run_dir = std::env::temp_dir().join(format!("forge-run-test-reap-{}", std::process::id()));
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(run_dir.join("scope.json"), b"{}").unwrap();

        // enfant longue durée dans un nouveau groupe de session — mime le spawn moteur (sans shell).
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("60").kill_on_drop(true);
        spawn_setsid(&mut cmd);
        let child = cmd.spawn().expect("spawn sleep");
        let pid = child.id().expect("pid") as i32;
        let pgid = pid; // setsid => PID == PGID (cf. claim_and_spawn).
        assert!(!process_gone(pid), "l'enfant doit être vivant avant le reap");

        reap_orphaned_spawn(pgid, child, &run_dir).await;

        // Récolté de façon déterministe (wait().await) : le PID a disparu, pas d'orphelin ni de zombie.
        assert!(process_gone(pid), "l'enfant doit être tué ET récolté (aucun orphelin)");
        assert!(!run_dir.exists(), "le dir temp du run (scope/targets) doit être supprimé");
    }

    /// E4 — LE CANCEL COUPE VRAIMENT LE MOTEUR. Reproduit le symptôme (T29) : un moteur détaché qui
    /// IGNORE SIGTERM (wedgé) et un enfant dans son groupe — le cancel « gracieux » (SIGTERM seul) est
    /// un NO-OP, le moteur survivait et relançait des outils. On prouve la SÉQUENCE EXACTE du handler
    /// `run_cancel` — `kill_group` (SIGTERM) PUIS `escalate_kill_group` (SIGKILL après grâce) :
    ///   1. SIGTERM seul laisse le GROUPE VIVANT (le moteur ignore -> preuve que le cancel d'avant était un no-op) ;
    ///   2. l'escalade SIGKILL tue TOUT le groupe (leader + enfant) — aucun survivant, comme le hard-kill manuel ;
    ///   3. ré-escalader un groupe déjà mort est un no-op propre (idempotent / fail-safe).
    #[tokio::test]
    async fn cancel_escalates_sigterm_to_sigkill_and_leaves_no_survivor() {
        // Fichier où l'ENFANT (petit-enfant du test) publie son PID -> preuve directe qu'il meurt aussi.
        let pidfile = std::env::temp_dir().join(format!("forge-e4-child-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&pidfile);
        // Moteur bidon : IGNORE SIGTERM (comme un moteur wedgé), fork un enfant qui publie son pid et
        // ignore aussi SIGTERM, puis les deux dorment. Python3 = dépendance réelle du moteur Forge.
        // NB : script sur UNE ligne source (les `\n` sont littéraux). Pas de continuation `\`-retour :
        // en Rust elle SUPPRIME l'indentation de tête -> IndentationError côté Python.
        let script = "import os,signal,sys,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\npid=os.fork()\nif pid==0:\n    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n    open(sys.argv[1],'w').write(str(os.getpid()))\n    time.sleep(120)\nelse:\n    time.sleep(120)\n";
        let mut cmd = tokio::process::Command::new("python3");
        cmd.arg("-c").arg(script).arg(&pidfile).kill_on_drop(true);
        spawn_setsid(&mut cmd);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => {
                eprintln!("python3 indisponible — test E4 sauté");
                return;
            }
        };
        let pid = child.id().expect("pid") as i32;
        let pgid = pid; // setsid => PID == PGID.

        // attend que l'enfant ait publié son pid (le groupe est alors bien établi : leader + enfant).
        let mut grandchild = -1;
        for _ in 0..100 {
            if let Ok(s) = std::fs::read_to_string(&pidfile) {
                if let Ok(v) = s.trim().parse::<i32>() {
                    grandchild = v;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(grandchild > 1, "l'enfant du moteur doit avoir publié son PID");
        assert!(group_alive(pgid), "le groupe moteur doit être vivant avant le cancel");
        assert!(!process_gone(grandchild), "l'enfant doit être vivant avant le cancel");

        // (1) SIGTERM seul (ancien comportement du cancel) : le moteur l'IGNORE -> groupe TOUJOURS vivant.
        kill_group(pgid);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(group_alive(pgid), "SIGTERM seul est un NO-OP sur un moteur wedgé (le bug E4)");
        assert!(!process_gone(grandchild), "l'enfant survit au SIGTERM seul");

        // (2) ESCALADE SIGKILL (grâce courte) : tue TOUT le groupe.
        escalate_kill_group(pgid, Duration::from_millis(300)).await;
        let _ = child.wait().await; // récolte le leader (plus de zombie qui masquerait group_alive).

        // le leader ET l'enfant ont disparu — aucun survivant (l'enfant est récolté par init après SIGKILL).
        let mut child_gone = false;
        for _ in 0..100 {
            if process_gone(grandchild) {
                child_gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(process_gone(pid), "le leader moteur doit être tué par l'escalade SIGKILL");
        assert!(child_gone, "l'enfant du moteur doit être tué aussi — AUCUN survivant (comme le hard-kill manuel)");
        assert!(!group_alive(pgid), "le groupe moteur est entièrement éteint");

        // (3) IDEMPOTENT / FAIL-SAFE : ré-escalader un groupe déjà mort ne panique pas et reste un no-op.
        escalate_kill_group(pgid, Duration::from_millis(100)).await;
        assert!(!group_alive(pgid), "ré-escalade sur un groupe mort = no-op propre");
        let _ = std::fs::remove_file(&pidfile);
    }
}


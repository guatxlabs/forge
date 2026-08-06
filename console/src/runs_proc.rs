// SPDX-License-Identifier: AGPL-3.0-or-later
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

/// pré-exec du LEADER d'un spawn moteur BORNÉ : `setsid` (comme tout spawn moteur) PLUS
/// `PR_SET_CHILD_SUBREAPER` (Linux) — le leader devient le point de ré-attachement de ses propres
/// orphelins. Conséquence : un descendant qui double-forke pour se détacher est ré-attaché AU LEADER
/// (pas à `init`), donc il reste visible par la chaîne de parenté même s'il a remplacé son
/// environnement. L'attribut est préservé par `execve` et n'est PAS hérité par les enfants : seul le
/// leader de CE spawn adopte, jamais un process voisin. Réservé aux spawns BORNÉS (courts) : un run
/// C2 supervisé garde `spawn_setsid` seul, son cycle de vie et sa récolte étant ceux du superviseur.
#[cfg(unix)]
pub(crate) fn spawn_setsid_subreaper(cmd: &mut tokio::process::Command) {
    spawn_setsid(cmd);
    #[cfg(target_os = "linux")]
    unsafe {
        cmd.pre_exec(|| {
            // best-effort : un noyau sans PR_SET_CHILD_SUBREAPER (< 3.4) laisse la garde sur ses
            // deux autres appuis (groupe + marqueur d'environnement) au lieu d'échouer le spawn.
            libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1);
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

/// Préfixes des dirs temp éphémères : un par RUN (`runs_proc`) et un par DRY-PLAN (`planning`).
pub(crate) const RUN_DIR_PREFIXES: [&str; 2] = ["forge-run-", "forge-plan-"];

/// Âge à partir duquel un dir temp est réputé ABANDONNÉ. Doit dépasser la plus longue exécution
/// plausible, sinon on supprime sous les pieds d'un run vivant : le watchdog plafonne un run à
/// `FORGE_RUN_TIMEOUT` (défaut 3600 s), on prend le double.
const RUN_DIR_STALE_SECS: u64 = 2 * 3600;

/// Supprime les dirs temp de run/plan (`scope.json`/`targets.json`) restés dans le tempdir après une
/// interruption (crash/reboot console) — best-effort, jamais fatal.
///
/// SEUIL D'ÂGE (2026-08-05) : la version initiale supprimait TOUT `forge-run-*` sans condition. Deux
/// collisions réelles sur une SEULE instance, sans tempdir partagé :
///   - `planning.rs` nommait ses dirs de dry-plan avec le MÊME préfixe `forge-run-` — un plan en vol
///     perdait ses fichiers ; le préfixe est désormais distinct, et les deux sont couverts ici ;
///   - le boot-reconcile du leader-tick est un one-shot qui peut se déclencher APRÈS le bind HTTP,
///     donc après qu'un run local ait démarré.
/// Le seuil ne supprime jamais PLUS qu'avant : aucune régression possible sur le cas nominal.
pub(crate) fn purge_stale_run_dirs() {
    let tmp = std::env::temp_dir();
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        let mut purged = 0;
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if !RUN_DIR_PREFIXES.iter().any(|p| name.starts_with(p)) || !e.path().is_dir() {
                continue;
            }
            // Métadonnée illisible ou horloge incohérente => on NE supprime PAS (fail-closed : ne
            // jamais détruire sur une information qu'on n'a pas su lire).
            let stale = e
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| t.elapsed().map(|d| d.as_secs() > RUN_DIR_STALE_SECS).unwrap_or(false))
                .unwrap_or(false);
            if stale && std::fs::remove_dir_all(e.path()).is_ok() {
                purged += 1;
            }
        }
        if purged > 0 {
            println!("[forge] reconcile: {purged} dir(s) temp de run/plan abandonné(s) purgé(s)");
        }
    }
}

/// Crée le dir temp d'un run/plan en PRIVÉ (`0700` sur unix) — jamais `0755` par défaut d'umask.
///
/// SECRET (R5b) : depuis que le `scope.json` d'un run peut porter le CONTEXTE D'AUTHENTIFICATION de
/// l'engagement (bearer/cookies/en-têtes des comptes de test de l'opérateur), ce dir vit dans un tempdir
/// PARTAGÉ (`/tmp`) où tout compte local peut lister et lire ce qui est world-readable. Le mode est posé
/// À LA CRÉATION (pas par un `chmod` a posteriori) : aucune fenêtre pendant laquelle le dir serait
/// lisible par autrui. Non-unix : comportement inchangé (`create_dir_all`).
pub(crate) fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Écrit un fichier d'entrée du moteur en PRIVÉ (`0600` sur unix) — `scope.json` / `targets.json`.
///
/// SECRET (R5b) : `scope.json` porte le matériel d'auth de l'opérateur. Le mode est demandé À LA
/// CRÉATION (`OpenOptions::mode`) pour qu'il n'existe AUCUN instant où le fichier serait world-readable ;
/// `truncate` garantit qu'un chemin réutilisé ne conserve pas de queue d'un contenu précédent. Non-unix :
/// comportement inchangé (`fs::write`).
pub(crate) fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
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
///
/// `field_key` = passphrase de CHIFFREMENT DE CHAMP (cf. `field_crypto`). Le bloc `auth` porté par le
/// spec est SCELLÉ (il vient tel quel de `engagement.scope_json`, et transite scellé jusque dans le blob
/// `run_job.spawn_spec` du chemin HA pending) : c'est ICI, à l'unique point d'USAGE, qu'il est OUVERT —
/// pour être écrit dans le `scope.json` 0600 du run, lu par le moteur. FAIL-CLOSED : si le matériel est
/// scellé et que la clé manque ou ne correspond pas, on rend `Err` et le run NE DÉMARRE PAS. Partir avec
/// un bloc `auth` VIDE désarmerait les oracles de contrôle d'accès EN SILENCE — c'est exactement le mode
/// de panne qui a coûté une campagne, donc il n'existe aucun repli « au mieux » sur ce chemin.
pub(crate) fn build_run_scope_doc(run_id: &str, spec: &RunSpawnSpec, field_key: Option<&str>) -> Result<Value, String> {
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
    let mut doc = json!({
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
    });
    // CONTEXTE AUTH PAR-ENGAGEMENT (R5b) : le bloc `auth` {accounts, idor_targets} de l'engagement est
    // AJOUTÉ au scope.json UNIQUEMENT s'il existe -> le moteur (AuthContext.from_scope) alimente les
    // oracles IDOR/ATO en cross-compte. ABSENT (None) => AUCUN champ `auth` ajouté => scope.json
    // BYTE-IDENTIQUE à l'historique (no-op strict pour les engagements sans auth). SECRET : ce fichier
    // temp local du run porte le matériel d'auth ; il n'est jamais journalisé (le moteur rédige findings/ledger).
    if let Some(auth) = &spec.eng_auth {
        doc["auth"] = crate::field_crypto::unseal_auth_block(auth, field_key)?;
    }
    Ok(doc)
}

/// LABELS des comptes du bloc `auth` d'un engagement dont le matériel est PÉRIMÉ à `now`, ou vide.
///
/// PURE et SANS CLÉ (le lanceur n'a pas à déchiffrer pour avertir) : lit le tampon `exp` non secret
/// posé au scellement. Aucun bloc auth, ou aucune échéance connue => vecteur VIDE => le run part
/// EXACTEMENT comme avant (ni champ de ledger, ni `warnings` : payloads byte-identiques).
pub(crate) fn auth_expiry_warning(eng_auth: Option<&Value>, now: i64) -> Vec<String> {
    eng_auth.map(|a| crate::field_crypto::auth_expired_labels(a, now)).unwrap_or_default()
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
    // dir PRIVÉ (0700) : le scope.json peut porter le contexte d'auth de l'engagement (cf. create_private_dir).
    let run_dir = std::env::temp_dir().join(format!("forge-run-{run_id}"));
    if let Err(e) = create_private_dir(&run_dir) {
        unclaim_running_on_failure(app, run_id, ha); // HA : la ligne 'running' claimée pré-spawn -> 'failed'
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "mkdir_failed", "why": e.to_string()})));
    }
    // scope du run : RESTREINT aux cibles validées. allow_exploit/destructive = opt-in haut-impact GOUVERNÉ
    // (false par défaut). INVARIANT : on ne touche QUE allow_exploit/destructive — in_scope/out_scope (le
    // périmètre) restent dictés par le scope de l'engagement, le scope-guard du moteur reste seul juge.
    // Construction EXTRAITE (fonction PURE, testable) : le CONTRAT scope.json est ainsi vérifiable en test.
    // OUVERTURE DU MATÉRIEL D'AUTH (chiffré au repos) — unique point de déchiffrement du chemin de run.
    // FAIL-CLOSED LISIBLE : clé absente/mauvaise => on NETTOIE (dir temp + un-claim) et on rend une 5xx
    // NOMMÉE plutôt que de spawner un moteur avec un contexte d'authentification vide, qui aurait l'air
    // de tourner tout en ne testant plus RIEN en cross-compte.
    let scope_doc = match build_run_scope_doc(run_id, spec, crate::field_crypto::key_from_env().as_deref()) {
        Ok(d) => d,
        Err(why) => {
            let _ = std::fs::remove_dir_all(&run_dir);
            unclaim_running_on_failure(app, run_id, ha);
            let code = if crate::field_crypto::is_key_missing(&why) { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::INTERNAL_SERVER_ERROR };
            return (code, Json(json!({"error": "auth_context_sealed", "engagement_id": spec.eng_id, "why": why})));
        }
    };
    // Chaque cible porte les params par-module dans `attrs.module_params` (passthrough sûr, doublon volontaire).
    let targets_doc: Vec<Value> = spec.targets.iter()
        .map(|h| json!({"host": h, "kind": "host", "attrs": {"module_params": spec.module_params.clone()}}))
        .collect();
    let scope_path = run_dir.join("scope.json");
    let targets_path = run_dir.join("targets.json");
    // Fichiers PRIVÉS (0600) : scope.json porte le matériel d'auth quand l'engagement est armé (cf. write_private_file).
    if write_private_file(&scope_path, &serde_json::to_vec(&scope_doc).unwrap()).is_err()
        || write_private_file(&targets_path, &serde_json::to_vec(&Value::Array(targets_doc)).unwrap()).is_err()
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
    // R3 — RESSOURCES : threade le profil + les overrides par-levier via les env vars que le MOTEUR lit
    // DÉJÀ (FORGE_RESOURCE_PROFILE / FORGE_TOOLS_PROFILE + un `FORGE_*` par levier de l'ALLOWLIST
    // `RESOURCE_KNOBS` — cf. `forge/resource_profile.py::ENV_OVERRIDES`, la source de vérité).
    // PRÉCÉDENCE préservée : un champ non renseigné => AUCUNE variable posée => défaut du profil (ou
    // défaut-code). `balanced` sans override => vecteur VIDE => aucune variable => byte-identique.
    // CHOIX DE RESSOURCE PUR : aucune bascule de scope/ROE/exploit — voir ResourceOptions.
    for (k, v) in spec.resource.env_pairs() {
        cmd.env(k, v);
    }
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
    let mut start_detail = json!({
        "run_id": run_id, "engagement_id": spec.eng_id, "campaign": spec.campaign, "mode": spec.mode, "actor": spec.actor, "by": "operator",
        "targets": spec.body_targets, "modules": spec.requested_modules,
        "module_params": spec.module_params,
        "disabled_modules": spec.disabled_modules,
        "technique_selection": spec.selection,
        "auto_pentest": spec.auto_pentest,
        "reason": spec.reason, "arm_requested": spec.arm,
        "high_impact": spec.high_impact,
        "exploit_floor": if spec.high_impact { "lifted via governed high-impact opt-in (allow_exploit=true allow_destructive=true)" } else { "forced allow_exploit=false allow_destructive=false" }
    });
    // CONTEXTE AUTH (R5b) : atteste QUE le run est parti ARMÉ (labels des comptes + nombre de cibles) —
    // miroir de `AuthContext.ledger_summary()` moteur. JAMAIS un secret, JAMAIS une URL de cible. Champ
    // ABSENT quand l'engagement n'a pas de contexte => entrée byte-identique à l'historique.
    // MATÉRIEL PÉRIMÉ — le DIRE AU LANCEMENT. Un run parti avec des comptes expirés ne casse pas :
    // il désarme les oracles de contrôle d'accès et rend un rapport PROPRE et VIDE qui ressemble à
    // « cible saine » (le mode d'échec qui a coûté une campagne). Lu SANS la clé de champ, depuis le
    // tampon `exp` non secret posé au scellement. On N'EMPÊCHE PAS le run : une campagne fait aussi
    // du recon, du header, du SSRF — bloquer serait une sur-portée, et le moteur re-détecte de toute
    // façon au tir (`skipped` + `degraded`). On NOMME, à trois endroits : ledger (ci-dessous),
    // réponse de lancement (`warnings`) et éditeur d'engagement (`auth_summary_json`).
    let auth_expired = auth_expiry_warning(spec.eng_auth.as_ref(), crate::state::now_epoch());
    if let Some(a) = &spec.eng_auth {
        start_detail["auth_context"] = crate::auth_ledger_summary(a);
        // Champ ABSENT quand rien n'est périmé => entrée de ledger byte-identique à l'historique.
        // SÛR : des LABELS, jamais un jeton (même contrat que `auth_ledger_summary`).
        if !auth_expired.is_empty() {
            start_detail["auth_expired"] = json!(auth_expired);
        }
    }
    append_run_ledger_path(app, &spec.eng_ledger_path, "console.run.start", start_detail);

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

    let mut accepted = json!({"run_id": run_id, "status": "running", "campaign": spec.campaign, "mode": spec.mode, "high_impact": spec.high_impact, "auto_pentest": spec.auto_pentest});
    // AVERTISSEMENT DE LANCEMENT (champ ABSENT si rien n'est périmé => réponse byte-identique à
    // l'historique). C'est la seule surface que l'opérateur regarde à coup sûr au moment du clic.
    if !auth_expired.is_empty() {
        accepted["warnings"] = json!([{
            "code": "auth_context_expired",
            "accounts": auth_expired,
            "why": "le matériel d'authentification de ces comptes porte une date d'expiration DÉPASSÉE : les oracles de contrôle d'accès (IDOR/ATO/privesc) rendront 'skipped' (non testé) au lieu d'un verdict. Rafraîchir le matériel dans le bloc `auth` de l'engagement pour que ce run prouve quoi que ce soit en cross-compte."
        }]);
    }
    (StatusCode::ACCEPTED, Json(accepted))
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
            allow_private, resource: Default::default(), eng_auth: None,
        }
    }

    /// CONTRAT scope.json (linchpin) : le writer Rust émet `allow_private` = valeur EFFECTIVE du spec, et
    /// n'y touche JAMAIS in_scope/out_scope (le périmètre reste dicté par l'engagement). Le reader Python
    /// (roe.Scope) lit exactement cette clé (défaut False si absente).
    #[test]
    fn scope_doc_carries_effective_allow_private_and_preserves_scope() {
        // aucun bloc auth ici => aucune clé de champ requise (no-op strict, cf. field_crypto).
        let on = build_run_scope_doc("run-x", &spec(false, true), None).unwrap();
        assert_eq!(on["allow_private"], json!(true), "allow_private effectif=true écrit tel quel");
        let off = build_run_scope_doc("run-x", &spec(false, false), None).unwrap();
        assert_eq!(off["allow_private"], json!(false), "allow_private effectif=false écrit tel quel (fail-closed)");
        // in_scope/out_scope INTOUCHÉS par la politique réseau (seul allow_private varie).
        assert_eq!(off["in_scope"], json!(["10.0.0.5"]));
        assert_eq!(off["out_scope"], json!(["out.example"]));
        // orthogonal au haut-impact : allow_private ne dépend pas de allow_exploit/destructive.
        let hi = build_run_scope_doc("run-x", &spec(true, false), None).unwrap();
        assert_eq!(hi["allow_exploit"], json!(true));
        assert_eq!(hi["allow_private"], json!(false), "politique réseau indépendante du haut-impact");
    }

    /// CONTEXTE AUTH PAR-ENGAGEMENT (R5b) : le scope.json du run PORTE le bloc `auth` de l'engagement
    /// UNIQUEMENT s'il existe -> le moteur (AuthContext.from_scope) alimente les oracles IDOR/ATO. ABSENT
    /// (eng_auth=None) => AUCUN champ `auth` => scope.json byte-identique à l'historique (no-op strict).
    ///
    /// CHIFFREMENT AU REPOS : le bloc arrive SCELLÉ (il vient de `engagement.scope_json`) et c'est ce
    /// writer qui l'OUVRE, pour le seul fichier 0600 du run. Le clair n'existe qu'ici.
    #[test]
    fn scope_doc_emits_auth_block_only_when_present() {
        const KEY: &str = "cle-de-champ-du-test-scope-doc";
        // (1) sans auth (le défaut du helper) => aucun champ `auth` (no-op byte-identique), sans clé.
        let none = build_run_scope_doc("run-x", &spec(false, false), None).unwrap();
        assert!(none.get("auth").is_none(), "eng_auth=None => aucun champ auth dans le scope.json");

        // (2) avec auth SCELLÉ => le moteur reçoit le bloc EN CLAIR, valeurs verbatim.
        let mut s = spec(false, false);
        let auth = json!({
            "accounts": [{"label": "attacker", "bearer": "TOK"}, {"label": "victim", "cookies": {"sid": "v"}}],
            "idor_targets": [{"url": "https://app.test/api/me", "owner": "victim", "marker": "MK"}]
        });
        let sealed = crate::field_crypto::seal_auth_block(&auth, Some(KEY)).unwrap();
        assert_ne!(sealed, auth, "le spec transporte du CHIFFRÉ (pas le credential)");
        s.eng_auth = Some(sealed);
        let with = build_run_scope_doc("run-x", &s, Some(KEY)).unwrap();
        assert_eq!(with["auth"], auth, "le bloc auth est OUVERT pour le moteur (round-trip verbatim)");
    }

    /// [MATÉRIEL PÉRIMÉ — LE LANCEMENT LE DIT] Un run parti avec des comptes expirés ne casse pas : il
    /// DÉSARME les oracles de contrôle d'accès et rend un rapport propre et vide. Le lanceur le NOMME
    /// (ledger `console.run.start.auth_expired` + `warnings` de la réponse), SANS la clé de champ et
    /// SANS bloquer le run (une campagne fait aussi du recon : bloquer serait une sur-portée).
    /// MUTATION-PROVABLE : rendre `auth_expiry_warning` toujours vide -> ROUGE.
    #[test]
    fn auth_expiry_warning_names_dead_accounts_without_the_key() {
        use base64::Engine as _;
        let b = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes());
        let jwt = |exp: i64| format!("{}.{}.sig", b(r#"{"alg":"HS256"}"#), b(&format!(r#"{{"exp":{exp}}}"#)));
        let auth = json!({"accounts": [{"label": "attacker", "bearer": jwt(1_600_000_000)},
                                       {"label": "victim", "bearer": jwt(1_900_000_000)},
                                       {"label": "opaque", "cookies": "sid=rien-de-lisible"}]});
        // SCELLÉ (l'état réel en base) : l'avertissement se lit SANS jamais ouvrir le matériel.
        let sealed = crate::field_crypto::seal_auth_block(&auth, Some("cle-de-champ-warning")).unwrap();
        assert_eq!(auth_expiry_warning(Some(&sealed), 1_700_000_000), vec!["attacker".to_string()],
                   "seul le compte PROUVÉ périmé est nommé (ni le valide, ni l'opaque)");
        // Aucun bloc auth, ou rien de périmé => VIDE => run byte-identique à l'historique.
        assert!(auth_expiry_warning(None, 1_700_000_000).is_empty());
        assert!(auth_expiry_warning(Some(&sealed), 1_500_000_000).is_empty());
    }

    /// [FAIL-CLOSED — LE RUN NE PART PAS SANS SON CONTEXTE] Un bloc `auth` SCELLÉ que la console ne peut
    /// pas ouvrir (clé absente, ou mauvaise clé) fait ÉCHOUER la construction du scope.json — le run est
    /// refusé. Il ne part JAMAIS avec un `auth` vide/partiel : le moteur aurait alors l'air de tourner
    /// tout en ne testant plus rien en cross-compte (le mode de panne silencieux qu'on refuse).
    /// MUTATION-PROVABLE : remplacer le `?` de `unseal_auth_block` par un `unwrap_or_default()` ou par
    /// l'omission du champ `auth` fait passer ce test AU ROUGE.
    #[test]
    fn scope_doc_refuses_rather_than_running_with_an_empty_auth_context() {
        const KEY: &str = "cle-de-champ-du-test-refus";
        let mut s = spec(false, false);
        let auth = json!({"accounts": [{"label": "attacker", "bearer": "TOK-SECRET"}], "idor_targets": []});
        s.eng_auth = Some(crate::field_crypto::seal_auth_block(&auth, Some(KEY)).unwrap());

        let e = build_run_scope_doc("run-x", &s, None).expect_err("scellé + pas de clé => run REFUSÉ");
        assert!(crate::field_crypto::is_key_missing(&e), "refus typé -> 503 field_key_missing");
        let e = build_run_scope_doc("run-x", &s, Some("mauvaise-cle")).expect_err("mauvaise clé => run REFUSÉ");
        assert_eq!(e, crate::field_crypto::ERR_UNSEAL);

        // Le contre-exemple qui prouve que le refus vient bien du scellé : AVEC la bonne clé, ça passe.
        let ok = build_run_scope_doc("run-x", &s, Some(KEY)).expect("bonne clé => run construit");
        assert_eq!(ok["auth"]["accounts"][0]["bearer"], json!("TOK-SECRET"));
    }

    /// [SECRET — R5b] Le dir temp d'un run et les fichiers d'entrée du moteur sont PRIVÉS au propriétaire.
    /// `scope.json` peut porter le CONTEXTE D'AUTH de l'engagement (bearer/cookies/en-têtes des comptes de
    /// test de l'opérateur) et vit dans un tempdir PARTAGÉ : au mode par défaut d'umask (0755/0644), TOUT
    /// compte local du système pourrait le lire. La propriété gardée est « aucun bit groupe/autres » —
    /// vraie quel que soit l'umask du process. MUTATION-PROVABLE : revenir à `create_dir_all`/`fs::write`
    /// fait passer ce test AU ROUGE sur un umask usuel (0022).
    #[cfg(unix)]
    #[test]
    fn run_temp_dir_and_engine_input_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::path::PathBuf::from(crate::testutil::tmp_path("forge-test-private-run"));
        create_private_dir(&dir).expect("création du dir temp privé");
        let dmode = std::fs::metadata(&dir).expect("stat dir").permissions().mode();
        assert_eq!(dmode & 0o077, 0, "dir temp de run : aucun accès groupe/autres (0700)");
        assert_eq!(dmode & 0o700, 0o700, "…tout en restant utilisable par le propriétaire");

        let f = dir.join("scope.json");
        write_private_file(&f, br#"{"auth":{"accounts":[{"label":"attacker","bearer":"TOK"}]}}"#)
            .expect("écriture du fichier privé");
        let fmode = std::fs::metadata(&f).expect("stat scope.json").permissions().mode();
        assert_eq!(fmode & 0o077, 0, "scope.json : aucun accès groupe/autres (il porte le matériel d'auth)");
        assert_eq!(fmode & 0o600, 0o600, "…lisible/écrivable par le propriétaire (la console et le moteur)");

        // TRUNCATE : un chemin réutilisé ne conserve aucune queue d'un contenu précédent (pas de secret résiduel).
        write_private_file(&f, b"{}").expect("réécriture");
        assert_eq!(std::fs::read_to_string(&f).expect("relecture"), "{}");
        let _ = std::fs::remove_dir_all(&dir);
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

/// LE DESCENDANT QUI QUITTE LE GROUPE — les deux héritages, exercés SÉPARÉMENT puis de bout en bout.
///
/// Le symptôme fermé ici a été mesuré sur le binaire, gate de LECTURE à 4 : 40 requêtes abandonnées
/// laissaient 40 descendants `setsid` vivants et la borne n'avait JAMAIS refusé. Le kill de groupe ne
/// pouvait pas les voir : ils n'étaient plus dans le groupe. Ces tests portent sur ce que le descendant
/// NE CHOISIT PAS — l'environnement dont il hérite, et le parent auquel il est rattaché.
#[cfg(all(test, target_os = "linux"))]
mod escaped_descendant_tests {
    use super::*;

    fn process_gone(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == -1 && *libc::__errno_location() == libc::ESRCH }
    }

    /// Chemin temporaire SANS métacaractère shell (le bouchon « environ vide » l'écrit depuis `sh`).
    fn tmpfile(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("forge-esc-{tag}-{}-{}.pid", std::process::id(), crate::gen_token()))
    }

    /// Attend (borné) qu'un fichier contienne un PID, puis le rend. -1 si rien n'arrive.
    async fn wait_pid(path: &std::path::Path) -> i32 {
        for _ in 0..200 {
            if let Ok(s) = std::fs::read_to_string(path) {
                if let Ok(v) = s.trim().parse::<i32>() {
                    return v;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        -1
    }

    /// Moteur bouchon : DOUBLE-FORK + `setsid`. Le petit-fils quitte le groupe ET devient orphelin,
    /// publie son PID, puis pend. `scrub` => il se ré-exécute avec un environnement VIDE (il perd donc
    /// le marqueur hérité : c'est le cas-limite, pas le cas nominal). Le leader pend ensuite.
    fn escaping_engine(pidfile: &std::path::Path, scrub: bool) -> tokio::process::Command {
        let payload = if scrub {
            // `execve` avec un environ VIDE : le marqueur DISPARAÎT du /proc/<pid>/environ du descendant.
            "os.execve('/bin/sh', ['sh', '-c', 'echo $$ > ' + sys.argv[1] + '; exec sleep 120'], {})"
        } else {
            "open(sys.argv[1], 'w').write(str(os.getpid()));  time.sleep(120)"
        };
        let script = format!(
            "import os,sys,time\npid=os.fork()\nif pid==0:\n    os.setsid()\n    if os.fork()>0: os._exit(0)\n    {payload}\nelse:\n    time.sleep(60)\n"
        );
        let mut cmd = tokio::process::Command::new("python3");
        cmd.arg("-c").arg(script).arg(pidfile);
        cmd
    }

    /// CANAL 1 — LE MARQUEUR HÉRITÉ. Un process qui porte l'entrée d'environnement du spawn est
    /// retrouvé même s'il n'est PAS dans l'arbre de parenté du leader (leader inexistant ici : le canal
    /// « parenté » ne peut rien apporter). Et un token DIFFÉRENT ne le voit pas : pas de kill à
    /// l'aveugle d'un moteur voisin.
    #[tokio::test]
    async fn marker_channel_finds_a_process_outside_the_parent_chain() {
        let token = crate::gen_token();
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("30").env(ENGINE_SPAWN_MARKER_ENV, &token).kill_on_drop(true);
        spawn_setsid(&mut cmd); // hors du groupe de ce test, comme un évadé
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => return, // `sleep` absent : rien à prouver ici
        };
        let pid = child.id().expect("pid") as i32;
        // leader INEXISTANT (PID hors borne) => seul le canal MARQUEUR peut trouver quelque chose.
        let seen = spawn_descendants(i32::MAX, &token);
        assert!(seen.contains(&pid), "le marqueur hérité doit rendre le process visible hors chaîne de parenté (vu={seen:?})");
        // token étranger => invisible (aucun faux positif : un spawn voisin n'est jamais visé).
        let other = spawn_descendants(i32::MAX, &crate::gen_token());
        assert!(!other.contains(&pid), "un token différent ne doit JAMAIS voir ce process (vu={other:?})");
        let _ = child.start_kill();
        let _ = child.wait().await;
    }

    /// CANAL 2 — LA CHAÎNE DE PARENTÉ. Un descendant qui a REMPLACÉ son environnement (donc invisible
    /// au marqueur) reste rattaché au leader marqué `PR_SET_CHILD_SUBREAPER`, malgré `setsid` ET le
    /// double-fork. C'est une forme que le marqueur ne traite pas : elle doit quand même tomber du bon
    /// côté tant que le leader vit.
    #[tokio::test]
    async fn parent_chain_finds_a_descendant_that_replaced_its_environment() {
        let pidfile = tmpfile("scrub");
        let _ = std::fs::remove_file(&pidfile);
        let token = crate::gen_token();
        let mut cmd = escaping_engine(&pidfile, true);
        cmd.env(ENGINE_SPAWN_MARKER_ENV, &token).kill_on_drop(true);
        spawn_setsid_subreaper(&mut cmd);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => {
                eprintln!("python3 indisponible — test sauté");
                return;
            }
        };
        let leader = child.id().expect("pid") as i32;
        let escapee = wait_pid(&pidfile).await;
        assert!(escapee > 1, "le descendant à environnement vide doit avoir publié son PID");
        // marqueur SEUL (leader inexistant) : il ne le voit pas — l'environnement a été remplacé.
        assert!(
            !spawn_descendants(i32::MAX, &token).contains(&escapee),
            "environ remplacé : le canal marqueur ne peut pas le voir (c'est la limite documentée)"
        );
        // chaîne de parenté depuis le leader : il le voit — un process ne choisit pas son parent.
        let seen = spawn_descendants(leader, &token);
        assert!(seen.contains(&escapee), "le descendant réadopté par le leader doit être vu (vu={seen:?})");
        let _ = std::fs::remove_file(&pidfile);
        unsafe { libc::kill(escapee, libc::SIGKILL) };
        let _ = child.start_kill();
        let _ = child.wait().await;
    }

    /// DE BOUT EN BOUT, CHEMIN BUDGET — le symptôme d'origine : un descendant `setsid`+double-fork
    /// survivait au budget dépassé et le slot était rendu quand même. Ici : la borne rend `Timeout`,
    /// AUCUN descendant ne survit, et le slot est bien RENDU (une prise suivante réussit).
    #[tokio::test]
    async fn escaped_descendant_dies_on_budget_and_slot_comes_back() {
        static GATE: EngineGate = EngineGate::new("FORGE_TEST_ESCAPE_BUDGET_MAX", 1);
        let pidfile = tmpfile("budget");
        let _ = std::fs::remove_file(&pidfile);
        let cmd = escaping_engine(&pidfile, false);
        let waited = bounded_engine_output(&GATE, cmd, std::time::Duration::from_secs(3), 1 << 20, None).await;
        assert!(matches!(waited, Err(EngineBoundErr::Timeout(_))), "le leader pend -> budget dépassé");
        let escapee = std::fs::read_to_string(&pidfile).ok().and_then(|s| s.trim().parse::<i32>().ok()).unwrap_or(-1);
        if escapee < 0 {
            eprintln!("python3 indisponible ou fork impossible — test sauté");
            return;
        }
        assert!(process_gone(escapee), "le descendant détaché ({escapee}) doit être mort quand la borne rend la main");
        // le slot est RENDU : une prise suivante ne doit pas rendre `Busy` (plafond = 1).
        let mut ok = tokio::process::Command::new("sh");
        ok.arg("-c").arg("exit 0");
        let second = bounded_engine_output(&GATE, ok, std::time::Duration::from_secs(5), 1 << 20, None).await;
        assert!(!matches!(second, Err(EngineBoundErr::Busy { .. })), "slot non rendu après la mort du spawn");
        let _ = std::fs::remove_file(&pidfile);
    }

    /// DE BOUT EN BOUT, CHEMIN ABANDON — c'est CE chemin qui a été mesuré à 40 survivants. La tâche du
    /// handler est ABANDONNÉE (client déconnecté) : le superviseur détaché doit quand même tuer le
    /// descendant détaché AVANT de rendre le slot.
    #[tokio::test]
    async fn escaped_descendant_dies_when_the_request_is_abandoned() {
        static GATE: EngineGate = EngineGate::new("FORGE_TEST_ESCAPE_ABANDON_MAX", 1);
        let pidfile = tmpfile("abandon");
        let _ = std::fs::remove_file(&pidfile);
        let cmd = escaping_engine(&pidfile, false);
        let handle = tokio::spawn(async move {
            let _ = bounded_engine_output(&GATE, cmd, std::time::Duration::from_secs(60), 1 << 20, None).await;
        });
        let escapee = wait_pid(&pidfile).await;
        if escapee < 0 {
            handle.abort();
            eprintln!("python3 indisponible — test sauté");
            return;
        }
        handle.abort(); // ABANDON : exactement ce que fait un client qui coupe
        let mut gone = false;
        for _ in 0..200 {
            if process_gone(escapee) {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(gone, "abandon client : le descendant détaché ({escapee}) doit être tué, pas laissé vivant");
        // Le slot est rendu APRÈS la mort du spawn (c'est l'ordre voulu) : on sonde donc le compteur,
        // borné, au lieu de supposer qu'il est déjà à zéro à l'instant où le descendant meurt.
        let mut released = false;
        for _ in 0..200 {
            if GATE.in_flight.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                released = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(released, "slot non rendu après un abandon");
        let mut ok = tokio::process::Command::new("sh");
        ok.arg("-c").arg("exit 0");
        let second = bounded_engine_output(&GATE, ok, std::time::Duration::from_secs(5), 1 << 20, None).await;
        assert!(!matches!(second, Err(EngineBoundErr::Busy { .. })), "slot non repris après un abandon");
        let _ = std::fs::remove_file(&pidfile);
    }

    /// LE MARQUEUR EST POSÉ PAR LA BORNE, PAS PAR L'APPELANT — et il est UNIQUE par spawn. C'est ce qui
    /// rend la garde non-énumérée : un futur site d'appel n'a rien à écrire pour en bénéficier, et deux
    /// spawns simultanés ne peuvent pas se balayer l'un l'autre.
    #[tokio::test]
    async fn every_bounded_spawn_carries_its_own_marker_without_the_caller_asking() {
        static GATE: EngineGate = EngineGate::new("FORGE_TEST_MARKER_MAX", 4);
        let mut seen = Vec::new();
        for _ in 0..2 {
            let mut cmd = tokio::process::Command::new("sh");
            cmd.arg("-c").arg(format!("printf %s \"${ENGINE_SPAWN_MARKER_ENV}\""));
            let out = bounded_engine_output(&GATE, cmd, std::time::Duration::from_secs(10), 1 << 20, None)
                .await
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string());
            match out {
                Ok(v) => seen.push(v),
                Err(_) => return, // `sh` absent : rien à prouver
            }
        }
        assert!(!seen[0].is_empty(), "tout spawn borné doit porter le marqueur (aucun appelant ne l'écrit)");
        assert_ne!(seen[0], seen[1], "le marqueur doit être UNIQUE par spawn (sinon un spawn balaierait le voisin)");
    }
}


// =====================================================================================
// BORNE MACHINE DES SPAWNS MOTEUR (S5-bis) — un process moteur par requête est un COÛT MACHINE, pas
// une lecture. Trois bornes, une seule implémentation, partagée par TOUTES les routes qui spawnent :
// nombre de PROCESS vivants (`EngineGate`), budget de TEMPS et plafond d'OCTETS (`bounded_engine_output`).
//
// CE QUE LE SLOT MESURE (corrigé DEUX FOIS) : un slot est tenu par la VIE DU PROCESS ET DE SES
// DESCENDANTS, pas par la vie de la requête HTTP. (1) Avant, le permis appartenait au future du
// handler : abandonner la requête (client déconnecté) le rendait INSTANTANÉMENT alors que
// `kill_on_drop` ne tue que l'enfant DIRECT — un petit-enfant survivait et la borne ne comptait plus
// rien (mesuré : 20 requêtes abandonnées -> 20 process vivants avec un plafond de 4, sans un seul
// refus). Le permis est donc MOVÉ dans un superviseur DÉTACHÉ (`tokio::spawn`) que l'abandon ne peut
// pas annuler. (2) Mais tenir le slot « jusqu'à la mort du GROUPE » restait une FORME : un descendant
// qui QUITTE le groupe (`setsid`/double-fork) n'était ni tué ni compté (mesuré à nouveau : 40
// descendants vivants après 40 abandons, plafond 4, aucun refus). Le superviseur balaie désormais AUSSI
// les descendants détachés par deux HÉRITAGES qu'un détachement ne défait pas (marqueur d'environnement
// + chaîne de parenté fermée par subreaper — cf. `kill_and_reap_spawn`), PUIS rend le slot.
//
// PAR CONSTRUCTION (vérifié par le compilateur) : `EnginePermit` et `EngineGate::try_acquire` sont
// PRIVÉS À CE MODULE — aucun autre fichier ne peut nommer le type, donc aucun ne peut prendre, tenir ni
// rendre un slot. Dans ce module il y a exactement UNE prise (`bounded_engine_output`) et UN `drop`
// (le superviseur, après la mort du groupe). Le plafond franchi n'est plus un `Option::None` que
// l'appelant peut jeter, mais une VARIANTE D'ERREUR NOMMÉE (`EngineBoundErr::Busy`) qu'il doit traiter.
//
// CE QUI EST GARANTI, ET RIEN DE PLUS : (1) au-delà du plafond, la prise échoue -> `Busy` (jamais de
// file d'attente muette) ; (2) au-delà du budget, le groupe est SIGTERM puis SIGKILL ; (3) au-delà du
// plafond d'octets, la collecte s'arrête et le groupe est tué — aucune sortie partielle rendue comme
// complète ; (4) sur TOUS les chemins (succès, temps, octets, abandon client), le groupe est tué et
// RÉCOLTÉ avant que le slot ne soit rendu et avant que la réponse ne parte. Limite mesurable : si un
// membre du groupe survit à SIGKILL (état D), l'attente est bornée (cf. `kill_and_reap_group`), le slot
// est rendu et un log le dit — c'est une borne d'attente, pas une promesse d'omnipotence.
// =====================================================================================

/// Plafond de process moteur VIVANTS, relu dans l'ENV À CHAQUE PRISE (donc modifiable sans redémarrer,
/// contrairement à un `OnceLock` dimensionné au premier appel). Valeur d'env absente/invalide/0 => le
/// défaut du site d'appel. Compteur PROCESS-GLOBAL : la borne est celle de la MACHINE, pas d'une session.
pub(crate) struct EngineGate {
    in_flight: std::sync::atomic::AtomicUsize,
    env_var: &'static str,
    default_max: usize,
}

/// Réservation d'un slot. PRIVÉE AU MODULE (pas `pub(crate)`) : aucun autre module ne peut nommer ce
/// type, donc aucun ne peut détenir un slot ni décider quand il est rendu. Le seul détenteur possible
/// est le superviseur détaché de `bounded_engine_output`, qui le libère après la mort du groupe.
struct EnginePermit {
    gate: &'static EngineGate,
}

impl EngineGate {
    pub(crate) const fn new(env_var: &'static str, default_max: usize) -> Self {
        Self { in_flight: std::sync::atomic::AtomicUsize::new(0), env_var, default_max }
    }

    /// Plafond EFFECTIF au moment de l'appel (lecture d'env, jamais figée).
    fn max(&self) -> usize {
        std::env::var(self.env_var)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(self.default_max)
    }

    /// Prend un slot SANS ATTENDRE. `None` => plafond atteint. PRIVÉE : le seul appelant possible est
    /// `bounded_engine_output`, qui transforme le `None` en `EngineBoundErr::Busy` (erreur nommée).
    fn try_acquire(&'static self) -> Option<EnginePermit> {
        let max = self.max();
        self.in_flight
            .fetch_update(std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst, |n| {
                if n < max { Some(n + 1) } else { None }
            })
            .ok()?;
        Some(EnginePermit { gate: self })
    }

    /// Nom de la variable d'env qui règle ce plafond — pour que le refus la NOMME à l'exploitant.
    fn env_var(&self) -> &'static str {
        self.env_var
    }
}

impl Drop for EnginePermit {
    fn drop(&mut self) {
        self.gate.in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Slots des spawns moteur de LECTURE (catalogue de techniques, workflows intégrés, rendu du livrable
/// DOCX/PDF, collecteur de détections). Distinct des slots du dry-plan : une rafale de lectures ne doit
/// pas affamer l'opérateur, et réciproquement. Le total de process moteur vivants est donc la SOMME des
/// trois plafonds (lecture + opérateur + dry-plan), pas l'un d'eux.
pub(crate) static ENGINE_GATE: EngineGate = EngineGate::new("FORGE_ENGINE_MAX_CONCURRENT", 4);

/// Slots des spawns moteur déclenchés par un OPÉRATEUR authentifié (import de scan `POST /api/import`,
/// re-probe du registre `POST /api/modules/refresh` et son appel de BOOT). Gate SÉPARÉE de la lecture
/// pour deux raisons mesurées : une rafale de lectures viewer ne doit pas faire échouer un import
/// opérateur, et 40 refresh concurrents ne doivent pas rendre une lecture viewer 50× plus lente
/// (mesuré 0,21 s -> 11,4 s avant borne). Défaut 2.
pub(crate) static ENGINE_OPERATOR_GATE: EngineGate = EngineGate::new("FORGE_ENGINE_OPERATOR_MAX_CONCURRENT", 2);

/// Budget de temps par défaut d'un spawn moteur de lecture (`FORGE_ENGINE_TIMEOUT`).
pub(crate) const ENGINE_TIMEOUT_DEFAULT_SECS: u64 = 120;

/// Budget EFFECTIF, relu à l'appel.
pub(crate) fn engine_timeout_secs() -> u64 {
    std::env::var("FORGE_ENGINE_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(ENGINE_TIMEOUT_DEFAULT_SECS)
}

/// Plafond d'octets collectés en RAM pour une sortie TEXTE de moteur (catalogue JSON, sortie du
/// dry-plan). Constante : ce n'est pas un réglage d'exploitation mais une digue anti-OOM.
pub(crate) const ENGINE_TEXT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Idem pour une sortie BINAIRE (DOCX/PDF du livrable) — plus haut, un rapport est plus gros qu'un JSON.
pub(crate) const ENGINE_BINARY_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Sortie d'un spawn moteur BORNÉ.
pub(crate) struct EngineOutput {
    pub(crate) status: std::process::ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

/// Échec d'un spawn borné. Chaque variante est EXPLICITE côté appelant (jamais un silence). `Busy` est
/// une VARIANTE, pas un `None` : un appelant ne peut plus « perdre » le plafond franchi en le confondant
/// avec une absence de dépendance (c'est ce que faisait `try_acquire()?` sur le chemin DOCX/PDF).
pub(crate) enum EngineBoundErr {
    /// plafond de process VIVANTS atteint — AUCUN process n'a été spawné. Porte la variable et sa valeur.
    Busy { var: &'static str, max: usize },
    /// budget de temps dépassé (secondes) — le groupe a été tué.
    Timeout(u64),
    /// plafond d'octets dépassé (octets) — le groupe a été tué, rien n'est rendu.
    TooLarge(usize),
    /// requête abandonnée par le client — le groupe a été tué, personne n'attend la réponse.
    Abandoned,
    /// spawn/IO impossible (moteur absent, pipe cassé…).
    Io(String),
}

impl EngineBoundErr {
    /// Message destiné à l'exploitant : il NOMME la borne franchie et la variable qui la règle.
    pub(crate) fn why(&self) -> String {
        match self {
            EngineBoundErr::Busy { var, max } => format!("trop de spawns moteur en cours ({var}={max}) — réessayez dans un instant"),
            EngineBoundErr::Timeout(s) => format!("moteur interrompu au-delà de {s}s (FORGE_ENGINE_TIMEOUT) — process arrêté, aucune sortie partielle rendue"),
            EngineBoundErr::TooLarge(n) => format!("sortie moteur au-delà de {n} octets — process arrêté, aucune sortie partielle rendue"),
            EngineBoundErr::Abandoned => "requête abandonnée par le client — moteur arrêté".to_string(),
            EngineBoundErr::Io(e) => format!("spawn échoué: {e}"),
        }
    }
}

// -------------------------------------------------------------------------------------
// IDENTIFIER UN DESCENDANT QUI A QUITTÉ LE GROUPE — deux propriétés HÉRITÉES, pas une liste de formes
// -------------------------------------------------------------------------------------
// Le groupe de session (`setsid`+`killpg`) est le chemin RAPIDE, mais c'est une FORME : `setsid` /
// double-fork en sortent, donc un descendant détaché n'était ni compté ni tué (mesuré : 40 descendants
// vivants après 40 requêtes abandonnées, plafond 4, aucun refus). Ce que le descendant ne peut PAS
// éviter en se détachant, ce sont deux héritages posés AVANT son existence :
//
//   1. L'ENVIRONNEMENT. `FORGE_ENGINE_SPAWN=<token unique>` est posé par `bounded_engine_output`
//      lui-même (pas par l'appelant), et fork/exec recopient l'environnement — `setsid` et le
//      double-fork n'y changent rien. C'est EXACTEMENT le mécanisme que le moteur Python a dû
//      construire pour la même raison (`forge/modules/_daemon_reap.py` : « le daemon est souvent
//      DÉTACHÉ (setsid/double-fork) -> il ÉCHAPPE au reap par groupe de processus »).
//   2. LA CHAÎNE DE PARENTÉ. Le leader du spawn est marqué `PR_SET_CHILD_SUBREAPER` (Linux) : un
//      descendant orphelin (double-fork) est ré-attaché AU LEADER au lieu d'`init`. Un process ne
//      choisit pas son parent — cette propriété tient même si le descendant a REMPLACÉ son
//      environnement (`env -i`, re-exec avec un environ vide), tant que le leader vit.
//
// LIMITES MESURÉES (écrites, pas contournées) :
//   - hors Linux, `/proc` n'existe pas : les deux scans rendent une liste VIDE et la garde retombe sur
//     le kill de groupe seul (no-op sûr, jamais de kill à l'aveugle) — cf. docs/PLATFORMS.md ;
//   - un descendant qui remplace son environnement ET dont le leader est DÉJÀ mort (chemin nominal,
//     où le leader a rendu la main avant le balayage) n'est plus rattachable : il n'est ni tué ni
//     compté. Résidu MESURÉ et documenté (`docs/HTTP_API.md`), pas une promesse d'omnipotence.

/// Variable d'environnement portant le marqueur unique d'un spawn moteur borné. Miroir Rust de
/// `FORGE_RUN_MARKER` (`forge/modules/_daemon_reap.py`).
pub(crate) const ENGINE_SPAWN_MARKER_ENV: &str = "FORGE_ENGINE_SPAWN";

/// Descendants d'un spawn encore vivants, par les DEUX héritages ci-dessus, en UNE seule passe sur
/// `/proc` : (a) `environ` porte l'entrée NUL-délimitée COMPLÈTE `FORGE_ENGINE_SPAWN=<token>` (jamais
/// une sous-chaîne ; le token est unique donc aucun faux positif, et un moteur concurrent n'est jamais
/// touché) ; (b) le pid descend de `leader` par la chaîne `ppid` (fermée par le subreaper). Exclut
/// soi-même, `init` et le leader. Best-effort : un `/proc` illisible n'entraîne AUCUN kill.
#[cfg(target_os = "linux")]
fn spawn_descendants(leader: i32, token: &str) -> Vec<i32> {
    let me = std::process::id() as i32;
    let needle = format!("{ENGINE_SPAWN_MARKER_ENV}={token}").into_bytes();
    let mut marked: Vec<i32> = Vec::new();
    let mut parent: Vec<(i32, i32)> = Vec::new();
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return Vec::new(), // pas de /proc -> aucune victime (no-op sûr)
    };
    for e in entries.flatten() {
        let pid = match e.file_name().to_string_lossy().parse::<i32>() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid <= 1 || pid == me {
            continue;
        }
        if let Ok(st) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            // le champ `comm` peut contenir espaces ET parenthèses -> on coupe à la DERNIÈRE `)`.
            if let Some((_, tail)) = st.rsplit_once(')') {
                if let Some(ppid) = tail.split_whitespace().nth(1).and_then(|v| v.parse::<i32>().ok()) {
                    parent.push((pid, ppid));
                }
            }
        }
        if let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) {
            if env.split(|&b| b == 0).any(|entry| entry == needle) {
                marked.push(pid);
            }
        }
    }
    // fermeture transitive de la parenté depuis le leader (le leader lui-même est exclu du résultat).
    let mut tree: Vec<i32> = Vec::new();
    let mut frontier = vec![leader];
    while let Some(cur) = frontier.pop() {
        for &(pid, ppid) in &parent {
            if ppid == cur && pid != leader && !tree.contains(&pid) {
                tree.push(pid);
                frontier.push(pid);
            }
        }
    }
    for pid in tree {
        if !marked.contains(&pid) {
            marked.push(pid);
        }
    }
    marked.retain(|&p| p != leader);
    marked
}

#[cfg(not(target_os = "linux"))]
fn spawn_descendants(_leader: i32, _token: &str) -> Vec<i32> {
    Vec::new() // pas de /proc : aucun kill à l'aveugle (cf. docs/PLATFORMS.md)
}

/// Vrai si `pid` existe et n'est pas un zombie déjà récolté. `kill(pid,0)` : test d'existence pur.
#[cfg(unix)]
fn pid_alive(pid: i32) -> bool {
    pid > 1 && unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(unix)]
fn signal_all(pids: &[i32], sig: i32) {
    for &p in pids {
        if p > 1 {
            unsafe {
                libc::kill(p, sig);
            }
        }
    }
}

/// Tue le spawn ENTIER puis RÉCOLTE, avant que le slot ne soit rendu. Ordre (et raison de chaque étape) :
/// (0) INVENTAIRE des descendants AVANT tout kill — tant que le leader vit, la chaîne de parenté est
/// fermée (subreaper) et le marqueur hérité est lisible ; tuer d'abord perdrait l'attribution ;
/// (1) SIGTERM aux évadés inventoriés (PID exacts) ; (2) l'enfant DIRECT est SIGKILLé puis `wait()` —
/// un zombie non récolté ferait répondre « vivant » à `group_alive` (cf. son doc-comment) et le slot
/// serait tenu pour rien ; (3) SIGTERM au GROUPE, et SEULEMENT s'il a encore un membre (signaler un
/// pgid déjà libéré viserait un PID recyclé, donc étranger) ; (4) grâce PARTAGÉE
/// (`CANCEL_GRACE_SECS`) pendant laquelle on sonde groupe ET évadés ; (5) SIGKILL des deux, sur un
/// inventaire RAFRAÎCHI (un descendant peut naître pendant la grâce) ; (6) sonde bornée de la
/// disparition effective. Le budget d'attente est celui d'AVANT (grâce puis `GROUP_REAP_POLLS`
/// sondes) : fermer l'évasion n'allonge pas la fenêtre pendant laquelle le slot reste tenu.
#[cfg(unix)]
async fn kill_and_reap_spawn(child: &mut tokio::process::Child, pgid: i32, token: &str) {
    // (0) inventaire AVANT de tuer.
    let mut victims = spawn_descendants(pgid, token);
    // (1) SIGTERM aux évadés : des PID EXACTS, relevés à l'instant (jamais un pgid périmé).
    signal_all(&victims, libc::SIGTERM);
    // (2) récolte de l'enfant direct AVANT de tester le groupe : un zombie non récolté ferait
    //     répondre « vivant » à `group_alive` et on signalerait un groupe qui n'existe plus.
    let _ = child.start_kill();
    let _ = child.wait().await;
    // (3) le groupe n'est signalé QUE s'il a encore un membre. Signaler un pgid déjà libéré n'est pas
    //     un no-op inoffensif à terme : un PID recyclé rendrait le signal ÉTRANGER (le chemin nominal
    //     passe ici avec un leader déjà mort et récolté).
    let group_live = pgid > 1 && group_alive(pgid);
    if group_live {
        kill_group(pgid);
    }
    if !group_live && !victims.iter().any(|&p| pid_alive(p)) {
        return; // cas nominal : rien à attendre, on ne dort pas.
    }
    // (4) grâce PARTAGÉE groupe + évadés (même budget qu'avant l'ajout des évadés).
    let step = std::time::Duration::from_millis(100);
    let mut waited = std::time::Duration::ZERO;
    let grace = std::time::Duration::from_secs(CANCEL_GRACE_SECS);
    while waited < grace {
        if (pgid <= 1 || !group_alive(pgid)) && !victims.iter().any(|&p| pid_alive(p)) {
            return; // sorti proprement dans la grâce -> pas de SIGKILL
        }
        tokio::time::sleep(step).await;
        waited += step;
    }
    // (5) dernier ressort : SIGKILL. Inventaire RAFRAÎCHI — un descendant né pendant la grâce hérite
    // du même marqueur, donc il est vu ici même s'il n'existait pas à l'étape (0).
    for p in spawn_descendants(pgid, token) {
        if !victims.contains(&p) {
            victims.push(p);
        }
    }
    if pgid > 1 && group_alive(pgid) {
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    signal_all(&victims, libc::SIGKILL);
    // (6) sonde bornée de la disparition effective.
    for _ in 0..GROUP_REAP_POLLS {
        if (pgid <= 1 || !group_alive(pgid)) && !victims.iter().any(|&p| pid_alive(p)) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let survivors: Vec<i32> = victims.into_iter().filter(|&p| pid_alive(p)).collect();
    eprintln!(
        "[forge] moteur: spawn {pgid} encore vivant après SIGKILL (groupe={} évadés={survivors:?}) — slot rendu à la borne d'attente",
        group_alive(pgid)
    );
}

#[cfg(not(unix))]
async fn kill_and_reap_spawn(child: &mut tokio::process::Child, _pgid: i32, _token: &str) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Sondes de 50 ms après le SIGKILL avant d'abandonner (borne D'ATTENTE, pas une promesse) : 2,5 s.
const GROUP_REAP_POLLS: usize = 50;

/// Fenêtre de DRAINAGE des pipes APRÈS la mort du process moteur. Ce n'est PAS une attente de fermeture
/// du pipe : c'est le temps laissé aux lectures pour vider ce que le moteur a écrit AVANT de sortir.
///
/// POURQUOI ELLE EXISTE (mesuré). La collecte s'arrêtait quand les pipes atteignaient EOF. Or un
/// DESCENDANT qui hérite du pipe stdout — le comportement PAR DÉFAUT d'un `fork`/`Popen` SANS
/// redirection, et `forge/modules/_daemon_reap.py` prouve que des daemons détachés existent dans ce
/// produit — tient ce pipe ouvert après la sortie du moteur. Attendre EOF facturait alors à une requête
/// RÉUSSIE le BUDGET MOTEUR ENTIER, et jetait la sortie valide : mesuré sur le binaire, `GET
/// /api/techniques` avec un descendant qui hérite du pipe et MEURT pourtant au SIGTERM — 5,127–5,136 s
/// à `FORGE_ENGINE_TIMEOUT=5`, 9,130–9,140 s à 9 (donc indexé sur le BUDGET, pas sur `CANCEL_GRACE_SECS`),
/// et 120,061 s au DÉFAUT LIVRÉ, corps `{"error":"techniques_unavailable"}` alors que le moteur était
/// sorti en 0 avec une sortie valide. Le BOOT lui-même (sonde du registre) subissait la même attente :
/// 120,66 s entre le lancement et le `listen`, contre 1,31 s après ce correctif.
///
/// CE QU'ELLE COÛTE, ET CE QU'ELLE COUPE. Sur le chemin nominal (personne d'autre ne tient le pipe),
/// EOF arrive AVEC la mort du process : la fenêtre n'est jamais consommée (mesuré 0,030–0,040 s de
/// bout en bout). Quand un descendant tient le pipe, la lecture est COUPÉE au bout de cette fenêtre et
/// la sortie déjà collectée est rendue — ELLE N'EST PAS TRONQUÉE : contrôle mesuré avec 5 MiB de sortie
/// valide ET un descendant qui hérite du pipe, corps rendu 5 243 025 octets (`pad` = 5 242 880 exact),
/// JSON valide, 0,79 s ; le même contrôle AVANT rendait 351 octets d'erreur en 5,13 s, les 5 MiB jetés.
/// CE QUE ÇA NE CAPTURE PLUS, dit plutôt que tu : une sortie écrite par un DESCENDANT APRÈS la mort du
/// moteur n'est plus attendue (elle l'était, au prix ci-dessus).
const PIPE_DRAIN_AFTER_EXIT: std::time::Duration = std::time::Duration::from_millis(250);

/// Pompe un flux du moteur dans `sink` jusqu'à EOF ou dépassement de `cap` (+1 octet suffit à DÉTECTER
/// le dépassement sans collecter davantage). Le `sink` est PARTAGÉ avec le superviseur : si la lecture
/// est COUPÉE (descendant qui tient le pipe), ce qui a déjà été lu reste lisible — c'est ce qui permet
/// de RENDRE la sortie du moteur au lieu de la jeter. Celui qui atteint le plafond TUE le groupe : sans
/// ça, on cesse de lire un pipe que l'enfant continue de remplir -> il se bloque, et le dépassement
/// d'OCTETS dégénère en dépassement de TEMPS (mesuré).
async fn pump_into<R: tokio::io::AsyncRead + Unpin>(
    mut r: R,
    sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    cap: u64,
    pgid: i32,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 8192];
    let mut total: u64 = 0;
    loop {
        let n = r.read(&mut buf).await?;
        if n > 0 {
            total += n as u64;
            if let Ok(mut s) = sink.lock() {
                s.extend_from_slice(&buf[..n]);
            }
        }
        if total > cap {
            kill_group(pgid);
            return Ok(());
        }
        if n == 0 {
            return Ok(());
        }
    }
}

/// Spawne `cmd` et collecte sa sortie SOUS TROIS BORNES, ET C'EST LE SEUL ENDROIT DU BINAIRE OÙ UN SLOT
/// DE CONCURRENCE MOTEUR EST PRIS ET RENDU (`EnginePermit` est privé à ce module : le compilateur
/// interdit à tout autre fichier de nommer, détenir ou libérer un slot).
///
/// - `gate` : le plafond à appliquer (lecture/opérateur/dry-plan). Plafond atteint => `Busy`, AUCUN spawn.
/// - `budget` : temps de mur du travail moteur. Dépassé => `Timeout`, groupe tué.
/// - `max_bytes` : octets collectés PAR FLUX. Dépassé => `TooLarge`, groupe tué, rien n'est rendu.
/// - `stdin_data` : entrée optionnelle (délégation DOCX/PDF).
///
/// LE SLOT EST TENU PAR LA VIE DU PROCESS, PAS PAR CELLE DE LA REQUÊTE : la supervision tourne dans une
/// tâche DÉTACHÉE que l'abandon du handler (client déconnecté) ne peut pas annuler. Elle observe cet
/// abandon (`tx.closed()`), tue le spawn, attend sa mort, rend le slot, puis répond.
///
/// CE QUI EST TUÉ, ET COMMENT ON LE TROUVE (cf. `kill_and_reap_spawn`) : le GROUPE de session (chemin
/// rapide) PLUS tout descendant qui l'a QUITTÉ (`setsid`/double-fork), retrouvé par deux héritages
/// qu'un détachement ne défait pas — le marqueur d'environnement unique posé ici même, et la chaîne de
/// parenté fermée par `PR_SET_CHILD_SUBREAPER` sur le leader. Quand cette fonction rend la main, ni le
/// groupe ni ces descendants ne sont vivants.
///
/// RÉSIDU CONNU ET MESURÉ, à ne pas sur-promettre : un descendant qui SE PRIVE DU MARQUEUR et dont le
/// leader est DÉJÀ mort n'est rattachable par aucun des deux héritages — il survit, et le slot est rendu.
/// Ce n'est PAS cher pour lui : il n'a pas à jeter son environnement (`env -i`), il lui suffit d'en
/// retirer UNE variable, celle nommée juste en dessous (`env -u FORGE_ENGINE_SPAWN` -> 7 survivants,
/// identique à `env -i`, mesuré). L'héritage est PASSIF ; un acte délibéré le défait.
/// LIMITE DE MÊME CLASSE, non couverte : un travail DÉLÉGUÉ À UN NON-DESCENDANT (`systemd-run --user`)
/// sort du domaine de la propriété (il n'hérite ni du marqueur ni de la parenté) — mesuré : 4 requêtes
/// abandonnées laissent 5 process vivants et rendent leur slot aussitôt.
/// COÛT SUR LE CHEMIN NOMINAL — DEUX FORMES DE DESCENDANT, DEUX PRIX, MESURÉS SÉPARÉMENT (une seule
/// forme avait été mesurée, et son chiffre généralisé à tort ; cf. `PIPE_DRAIN_AFTER_EXIT`) :
///   - descendant qui REDIRIGE ses fd (`>/dev/null`) et MEURT au SIGTERM : 0,133–0,146 s ;
///   - descendant qui REDIRIGE ses fd et IGNORE SIGTERM : il tient le slot jusqu'au SIGKILL de
///     `CANCEL_GRACE_SECS` — 5,17–5,24 s (INCHANGÉ par ce correctif) ;
///   - descendant qui HÉRITE du pipe stdout (défaut d'un `fork`/`Popen` sans redirection) : 0,380–0,396 s
///     APRÈS ce correctif, contre le BUDGET MOTEUR ENTIER avant (5,13 s à `FORGE_ENGINE_TIMEOUT=5`,
///     9,13 s à 9, 120,061 s au défaut livré) — et la sortie valide était JETÉE ;
///   - aucun descendant : 0,030–0,040 s.
/// CE QUE CE CHOIX COÛTE AILLEURS, dit et mesuré : un moteur qui FERME ses deux pipes puis se BLOQUE
/// n'est plus borné par « EOF + `CANCEL_GRACE_SECS` » mais par `budget` — mesuré à
/// `FORGE_ENGINE_TIMEOUT=9` : 9,128–9,141 s contre 5,130–5,145 s avant. L'issue est la même (`Timeout`,
/// groupe tué, aucune sortie partielle rendue) ; seule l'attente change, et elle ne dépasse jamais le
/// budget annoncé.
/// Hors Linux, `/proc` n'existe pas : la garde retombe sur le kill de groupe seul. Toutes ces limites
/// sont écrites dans `docs/HTTP_API.md`.
pub(crate) async fn bounded_engine_output(
    gate: &'static EngineGate,
    mut cmd: tokio::process::Command,
    budget: std::time::Duration,
    max_bytes: usize,
    stdin_data: Option<Vec<u8>>,
) -> Result<EngineOutput, EngineBoundErr> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // (1) SLOT — pris ICI, avant tout spawn. Plafond atteint => erreur NOMMÉE, aucun process créé.
    let permit = match gate.try_acquire() {
        Some(p) => p,
        None => return Err(EngineBoundErr::Busy { var: gate.env_var(), max: gate.max() }),
    };
    // MARQUEUR HÉRITÉ — posé ICI, au seul endroit qui prend un slot, jamais par l'appelant : un site
    // d'appel ne peut donc pas l'oublier, et tout process issu de ce spawn le porte (fork/exec
    // recopient l'environnement, `setsid`/double-fork n'y changent rien). Token unique par spawn
    // (CSPRNG) -> le balayage ne peut viser qu'un descendant de CE spawn.
    let marker = crate::gen_token();
    cmd.env(ENGINE_SPAWN_MARKER_ENV, &marker);
    cmd.stdin(if stdin_data.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    spawn_setsid_subreaper(&mut cmd); // PGID = PID de l'enfant (kill du GROUPE) + adoption des orphelins
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        // AUCUN process n'existe : rendre le slot ici (drop de `permit`) ne peut rien laisser fuir.
        Err(e) => return Err(EngineBoundErr::Io(e.to_string())),
    };
    let pgid = child.id().map_or(0, |p| p as i32);
    let mut stdin = child.stdin.take();
    let out = child.stdout.take();
    let err = child.stderr.take();
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<EngineOutput, EngineBoundErr>>();
    // (2) SUPERVISEUR DÉTACHÉ — il possède le permis, l'enfant et le pgid. `tokio::spawn` : son cycle de
    // vie est celui du RUNTIME, pas celui du future du handler ; abandonner la requête ne l'annule pas.
    tokio::spawn(async move {
        let mut tx = tx;
        let cap = max_bytes as u64;
        let out_sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let err_sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let pipes = match (out, err) {
            (Some(o), Some(e)) => Some((o, e)),
            _ => None,
        };
        // lecture CONCURRENTE des deux flux (sinon un pipe plein bloque l'enfant), chacune plafonnée à
        // max_bytes+1 (cf. `pump_into`). Les tâches écrivent dans des tampons PARTAGÉS : ce qui a été lu
        // reste récupérable même si la lecture est coupée.
        let (mut o_task, mut e_task) = match pipes {
            Some((o, e)) => (
                Some(tokio::spawn(pump_into(o.take(cap + 1), out_sink.clone(), cap, pgid))),
                Some(tokio::spawn(pump_into(e.take(cap + 1), err_sink.clone(), cap, pgid))),
            ),
            None => (None, None),
        };
        // stdin écrit dans SA tâche : alimenter le moteur ne séquence plus la lecture de sa sortie.
        let w_task = tokio::spawn(async move {
            if let (Some(mut w), Some(data)) = (stdin.take(), stdin_data) {
                let _ = w.write_all(&data).await;
                drop(w); // EOF pour l'enfant
            }
        });
        let work = async {
            let (ot, et) = match (o_task.as_mut(), e_task.as_mut()) {
                (Some(o), Some(e)) => (o, e),
                _ => return Err(EngineBoundErr::Io("pipes stdout/stderr indisponibles".into())),
            };
            // (a) LE TRAVAIL DU MOTEUR SE TERMINE QUAND LE PROCESS MOTEUR SORT — pas quand le dernier
            //     détenteur du pipe le ferme. C'est la MÊME règle que celle déjà écrite au-dessus pour le
            //     slot (« tenu par la vie du PROCESS »), appliquée aussi à la COLLECTE.
            let status = child.wait().await.map_err(|e| EngineBoundErr::Io(e.to_string()))?;
            // (b) le moteur est SORTI : ce qu'il a écrit est déjà dans le pipe. On draine brièvement puis
            //     on COUPE — attendre la fermeture d'un pipe HÉRITÉ par un descendant facturerait le
            //     budget moteur entier à une requête réussie (cf. `PIPE_DRAIN_AFTER_EXIT`).
            let _ = tokio::time::timeout(PIPE_DRAIN_AFTER_EXIT, async {
                let _ = (&mut *ot).await;
                let _ = (&mut *et).await;
            })
            .await;
            ot.abort();
            et.abort();
            let ob = out_sink.lock().map(|g| g.clone()).unwrap_or_default();
            let eb = err_sink.lock().map(|g| g.clone()).unwrap_or_default();
            if ob.len() > max_bytes || eb.len() > max_bytes {
                return Err(EngineBoundErr::TooLarge(max_bytes));
            }
            Ok(EngineOutput { status, stdout: ob, stderr: eb })
        };
        // ABANDON CLIENT : `tx.closed()` se résout quand le récepteur est libéré, c.-à-d. quand le future
        // du handler est abandonné. On ne rend PAS le slot pour autant — on part tuer le groupe.
        let outcome = tokio::select! {
            r = tokio::time::timeout(budget, work) => match r {
                Ok(inner) => inner,
                Err(_) => Err(EngineBoundErr::Timeout(budget.as_secs())),
            },
            _ = tx.closed() => Err(EngineBoundErr::Abandoned),
        };
        // Plus personne n'écoute les pipes : les lectures et l'alimentation stdin sont coupées, quel que
        // soit le chemin de sortie (une tâche de lecture laissée vivante tiendrait le pipe d'un
        // descendant jusqu'à la fin des temps).
        w_task.abort();
        if let Some(t) = o_task.as_ref() {
            t.abort();
        }
        if let Some(t) = e_task.as_ref() {
            t.abort();
        }
        // (3) MORT DU SPAWN (groupe + descendants détachés) puis — et seulement ensuite — RESTITUTION
        // DU SLOT. Unique site de `drop`.
        kill_and_reap_spawn(&mut child, pgid, &marker).await;
        drop(permit);
        let _ = tx.send(outcome);
    });
    match rx.await {
        Ok(r) => r,
        // le superviseur ne peut disparaître qu'à l'arrêt du runtime ; on ne rend jamais un faux succès.
        Err(_) => Err(EngineBoundErr::Io("superviseur de spawn moteur perdu".into())),
    }
}

#[cfg(test)]
mod purge_tests {
    use super::*;

    /// `purge_stale_run_dirs` n'avait AUCUN test — et le test le plus proche l'ÉVITAIT explicitement
    /// (« on n'appelle pas reconcile_runs pour éviter killpg/purge »). La suite savait donc la fonction
    /// dangereuse à exécuter, et contournait au lieu de garder. Ce test la garde.
    ///
    /// La propriété qui compte n'est pas « ça supprime » mais **« ça ne supprime PAS ce qui est vivant »**.
    #[test]
    fn purge_epargne_les_dirs_recents_et_ramasse_les_abandonnes() {
        let tmp = std::env::temp_dir();
        let uniq = std::process::id();
        let vivants = [
            tmp.join(format!("forge-run-vivant-{uniq}")),
            tmp.join(format!("forge-plan-vivant-{uniq}")),
        ];
        let abandonnes = [
            tmp.join(format!("forge-run-abandonne-{uniq}")),
            tmp.join(format!("forge-plan-abandonne-{uniq}")),
        ];
        for d in vivants.iter().chain(abandonnes.iter()) {
            std::fs::create_dir_all(d).expect("mkdir fixture");
            std::fs::write(d.join("scope.json"), b"{}").expect("write fixture");
        }
        let vieux = std::time::SystemTime::now()
            - std::time::Duration::from_secs(RUN_DIR_STALE_SECS + 600);
        for d in &abandonnes {
            std::fs::File::open(d).expect("open dir").set_modified(vieux).expect("set mtime");
        }

        purge_stale_run_dirs();

        for d in &vivants {
            assert!(d.is_dir(), "un dir RÉCENT ne doit jamais être purgé : {}", d.display());
            let _ = std::fs::remove_dir_all(d);
        }
        for d in &abandonnes {
            assert!(!d.exists(), "un dir ABANDONNÉ doit être purgé : {}", d.display());
        }
    }

    /// Le préfixe des dry-plans doit rester DISTINCT de celui des runs (la collision d'origine), tout
    /// en restant couvert par la purge — sinon on échange une collision contre une fuite.
    #[test]
    fn les_deux_prefixes_sont_distincts_et_couverts() {
        assert_eq!(RUN_DIR_PREFIXES.len(), 2);
        assert!(!RUN_DIR_PREFIXES[1].starts_with(RUN_DIR_PREFIXES[0]),
                "le préfixe de plan ne doit pas être un sous-préfixe de celui des runs");
        for name in ["forge-run-42", "forge-plan-abc"] {
            assert!(RUN_DIR_PREFIXES.iter().any(|p| name.starts_with(p)),
                    "{name} doit rester couvert par la purge");
        }
    }
}

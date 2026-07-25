// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — SCHEDULER de sauvegarde + EXPÉDITION OFFSITE. Extrait de `backup.rs`
//! (PURE MOVE, behavior-neutral — corps bit-à-bit identiques) : runner périodique fail-open,
//! exécution d'une sauvegarde programmée, garde « due », expédition offsite (local_dir/exec/s3),
//! rétention. Réutilise le moteur backup (`run_backup_core`, `BackupOpts`, `backup_archive_name`,
//! `load_backup_policy*`, `read_passphrase_env`) via la racine de crate. Aucune logique modifiée.
use crate::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::time::Duration;

// --- Runner programmé (offsite) — tâche périodique fail-open, ne crashe JAMAIS la console. -----------

/// Expédie l'archive `archive_path` vers la destination offsite. `none` -> no-op. `local_dir` -> copie
/// dans `dir` (créé si besoin). `exec` -> lance un argv FIXE (aucun shell) avec timeout ; le token
/// littéral `{archive}` dans `program`/`args` est remplacé par le chemin de l'archive. Aucun secret n'est
/// journalisé (kind + statut seuls). Renvoie un rapport (jamais d'argv complet si secretish — l'admin
/// est responsable de ne pas mettre de secret inline ; préférer des creds via l'ENV du process/rclone.conf).
pub(crate) fn ship_offsite(offsite: &Value, archive_path: &str) -> Result<Value, String> {
    let kind = offsite.get("kind").and_then(|v| v.as_str()).unwrap_or("none");
    match kind {
        "none" => Ok(json!({"shipped": false, "kind": "none"})),
        "local_dir" => {
            let dir = offsite.get("dir").and_then(|v| v.as_str()).unwrap_or("");
            if dir.is_empty() {
                return Err("offsite local_dir : `dir` requis".to_string());
            }
            std::fs::create_dir_all(dir).map_err(|e| format!("création de '{dir}' échouée: {e}"))?;
            let base = std::path::Path::new(archive_path).file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(backup_archive_name);
            let dst = std::path::Path::new(dir).join(&base);
            std::fs::copy(archive_path, &dst).map_err(|e| format!("copie offsite échouée: {e}"))?;
            Ok(json!({"shipped": true, "kind": "local_dir", "dest": dst.to_string_lossy()}))
        }
        "exec" => {
            let program = offsite.get("program").and_then(|v| v.as_str()).unwrap_or("");
            if program.is_empty() {
                return Err("offsite exec : `program` requis".to_string());
            }
            let timeout = offsite.get("timeout_secs").and_then(|v| v.as_u64()).filter(|&n| n > 0).unwrap_or(120);
            let subst = |s: &str| s.replace("{archive}", archive_path);
            let program = subst(program);
            let args: Vec<String> = offsite.get("args").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).map(subst).collect())
                .unwrap_or_default();
            // AUCUN shell : argv fixe. status + timeout, jamais d'interprétation de métacaractères.
            run_offsite_exec(&program, &args, timeout)
        }
        // BLOBSTORE S3/MinIO (feature `object-store`) — PUT de l'archive CHIFFRÉE vers l'objet S3.
        // Config/credentials via l'ENV FORGE_BLOB_S3_* (jamais dans la politique). Rapport SANS secret
        // (bucket/clé/URL). En build community (feature OFF), cet arm n'existe pas : `s3` est déjà rejeté
        // en amont par `validate_backup_policy` (absent de OFFSITE_KINDS) et retomberait ici sur `other`.
        #[cfg(feature = "object-store")]
        "s3" => crate::blob::ship_offsite_s3(offsite, archive_path),
        other => Err(format!("offsite.kind inconnu: {other}")),
    }
}

/// Lance un binaire (chemin explicite) avec un argv FIXE (aucun shell) et un timeout dur. Tue le
/// process au dépassement. Renvoie {shipped, kind:"exec", code} (code de sortie) ; erreur si le spawn
/// échoue ou si le process sort en échec/timeout. Blocage borné -> appelé depuis spawn_blocking.
pub(crate) fn run_offsite_exec(program: &str, args: &[String], timeout_secs: u64) -> Result<Value, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("offsite exec: lancement de '{program}' impossible: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(json!({"shipped": true, "kind": "exec", "code": status.code()}));
                }
                return Err(format!("offsite exec: '{program}' a échoué (code={:?})", status.code()));
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("offsite exec: '{program}' dépassé le timeout ({timeout_secs}s) — process tué"));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => return Err(format!("offsite exec: attente de '{program}' échouée: {e}")),
        }
    }
}

/// Applique la rétention : conserve les `keep` archives `forge-backup-*.forge` les plus récentes de
/// `dir`, supprime le reste. `keep=0` -> aucune purge (rétention illimitée). Best-effort (erreurs ignorées).
pub(crate) fn apply_backup_retention(dir: &str, keep: usize) {
    if keep == 0 {
        return;
    }
    let mut archives: Vec<(std::time::SystemTime, std::path::PathBuf)> = std::fs::read_dir(dir)
        .map(|it| it.filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with("forge-backup-") && n.ends_with(".forge")
            })
            .filter_map(|e| e.metadata().and_then(|m| m.modified()).ok().map(|t| (t, e.path())))
            .collect())
        .unwrap_or_default();
    if archives.len() <= keep {
        return;
    }
    archives.sort_by_key(|b| std::cmp::Reverse(b.0)); // plus récent d'abord
    for (_, path) in archives.into_iter().skip(keep) {
        let _ = std::fs::remove_file(path);
    }
}

/// Exécute UNE sauvegarde programmée selon `settings.backup_policy` : lit la passphrase depuis la
/// variable d'ENV NOMMÉE par la politique (JAMAIS depuis settings en clair) ; crée une archive chiffrée
/// dans le staging ; applique la rétention ; expédie offsite ; trace chaque étape au ledger (métadonnées).
/// Fail-closed sur passphrase absente. Renvoie un rapport ou une erreur (l'appelant ledgerise l'échec).
/// Fonction BLOQUANTE (argon2 + I/O) -> à invoquer via spawn_blocking depuis le runner async.
pub(crate) fn run_scheduled_backup(app: &App) -> Result<Value, String> {
    let policy = { let store = app.store(); load_backup_policy_store(&store) };
    if !policy.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Ok(json!({"skipped": true, "reason": "policy_disabled"}));
    }
    let pass_env = policy.get("passphrase_env").and_then(|v| v.as_str()).unwrap_or("");
    if pass_env.is_empty() {
        return Err("passphrase_env absent de la politique (fail-closed)".to_string());
    }
    let passphrase = read_passphrase_env(pass_env)
        .ok_or_else(|| format!("passphrase absente — la variable d'ENV '{pass_env}' est vide/non définie (fail-closed)"))?;

    // staging : `staging_dir` de la politique, sinon un dossier `backups/` sibling de la base.
    let staging = policy.get("staging_dir").and_then(|v| v.as_str()).map(|s| s.to_string())
        .unwrap_or_else(|| {
            std::path::Path::new(app.db_path.as_str()).parent()
                .map(|p| p.join("backups").to_string_lossy().into_owned())
                .unwrap_or_else(|| "backups".to_string())
        });
    std::fs::create_dir_all(&staging).map_err(|e| format!("création du staging '{staging}' échouée: {e}"))?;
    let out = std::path::Path::new(&staging).join(backup_archive_name()).to_string_lossy().into_owned();

    let opts = BackupOpts {
        out: out.clone(),
        passphrase,
        db: (*app.db_path).clone(),
        ledger: Some((*app.ledger_path).clone()),
        ts: Some(format!("@{}", chrono_now_compact())),
        actor: "scheduler".to_string(),
    };
    let (report, _detail) = run_backup_core(&opts)?;
    let sealed_len = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    let archive_sha = std::fs::read(&out).map(|b| sha256_hex_bytes(&b)).unwrap_or_default();

    // AUDIT (métadonnées) — via append_console_ledger (verrou + cache head, pas de désync).
    append_console_ledger(app, "console.backup.scheduled", json!({
        "actor": "scheduler",
        "out": out,
        "archive_bytes": sealed_len,
        "archive_sha256": archive_sha,
        "db_sha256": report.get("db_sha256").cloned().unwrap_or(Value::Null),
        "encrypted": true,
    }));

    // rétention locale (conserve les N plus récentes).
    let keep = policy.get("retention").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    apply_backup_retention(&staging, keep);

    // offsite : expédie l'archive ; ledgerise le résultat (kind + statut, jamais de secret).
    let offsite = policy.get("offsite").cloned().unwrap_or_else(|| json!({"kind": "none"}));
    let offsite_kind = offsite.get("kind").and_then(|v| v.as_str()).unwrap_or("none").to_string();
    let offsite_res = ship_offsite(&offsite, &out);
    match &offsite_res {
        Ok(r) => append_console_ledger(app, "console.backup.offsite", json!({
            "actor": "scheduler", "kind": offsite_kind, "ok": true,
            "shipped": r.get("shipped").cloned().unwrap_or(json!(false)),
        })),
        Err(e) => append_console_ledger(app, "console.backup.offsite", json!({
            "actor": "scheduler", "kind": offsite_kind, "ok": false, "why": e,
        })),
    }

    Ok(json!({
        "ok": true,
        "out": out,
        "archive_bytes": sealed_len,
        "archive_sha256": archive_sha,
        "offsite": offsite_res.unwrap_or_else(|e| json!({"shipped": false, "error": e})),
    }))
}

/// Vrai si une sauvegarde programmée est DUE : politique activée + `interval_secs` écoulé depuis
/// `settings.backup_last_run` (0/absent -> due immédiatement). Lecture seule (aucun effet de bord).
#[allow(dead_code)] // conservé pour les tests (accès SQLite direct) — le runtime passe par _store.
pub(crate) fn scheduled_backup_due(db: &Connection) -> bool {
    let policy = load_backup_policy(db);
    if !policy.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
        return false;
    }
    let interval = policy.get("interval_secs").and_then(|v| v.as_u64()).unwrap_or(0);
    if interval == 0 {
        return false;
    }
    let now: u64 = chrono_now_compact().parse().unwrap_or(0);
    let last: u64 = settings_get(db, "backup_last_run").and_then(|s| s.parse().ok()).unwrap_or(0);
    now.saturating_sub(last) >= interval
}

/// PORTABLE SEAM analogue of [`scheduled_backup_due`] over `App::store()`. Byte-identical gate logic
/// (activée + `interval_secs` écoulé depuis `settings.backup_last_run`). Runtime scheduler uses this;
/// the `&Connection` version above stays for tests.
pub(crate) fn scheduled_backup_due_store(store: &crate::store::Store) -> bool {
    let policy = load_backup_policy_store(store);
    if !policy.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
        return false;
    }
    let interval = policy.get("interval_secs").and_then(|v| v.as_u64()).unwrap_or(0);
    if interval == 0 {
        return false;
    }
    let now: u64 = chrono_now_compact().parse().unwrap_or(0);
    let last: u64 = crate::settings_get_store(store, "backup_last_run").and_then(|s| s.parse().ok()).unwrap_or(0);
    now.saturating_sub(last) >= interval
}

/// Runner périodique EN CONSOLE : à chaque tick, si une politique est DUE, exécute une sauvegarde
/// programmée (via spawn_blocking — argon2 hors runtime async), met à jour `backup_last_run`, et
/// ledgerise. FAIL-OPEN : un échec de backup/offsite est loggé + ledgerisé (`console.backup.error`) mais
/// ne fait JAMAIS crasher la console (un panic de la tâche bloquante est capté par le JoinHandle). Sans
/// politique/activation, ne fait rien (aucune sauvegarde codée en dur). Tick réglable (FORGE_BACKUP_TICK_SECS).
pub(crate) async fn backup_scheduler_loop(app: App) {
    let tick = std::env::var("FORGE_BACKUP_TICK_SECS").ok()
        .and_then(|s| s.parse::<u64>().ok()).filter(|&n| n > 0).unwrap_or(60);
    loop {
        tokio::time::sleep(Duration::from_secs(tick)).await;
        let due = { let store = app.store(); scheduled_backup_due_store(&store) };
        if !due {
            continue;
        }
        let app2 = app.clone();
        let res = tokio::task::spawn_blocking(move || run_scheduled_backup(&app2)).await;
        // marque la tentative (succès OU échec) pour ne pas boucler serré ; prochaine tentative après interval.
        {
            let store = app.store();
            let _ = crate::settings_set_store(&store, "backup_last_run", &chrono_now_compact());
        }
        match res {
            Ok(Ok(v)) => {
                println!("[forge] backup programmé OK — {} octets (offsite: {})",
                    v.get("archive_bytes").and_then(|x| x.as_u64()).unwrap_or(0),
                    v.get("offsite").and_then(|o| o.get("kind")).and_then(|x| x.as_str())
                        .or_else(|| v.get("offsite").and_then(|o| o.get("shipped")).map(|_| "done")).unwrap_or("none"));
            }
            Ok(Err(e)) => {
                eprintln!("[forge] backup programmé ÉCHEC (fail-open, console intacte): {e}");
                append_console_ledger(&app, "console.backup.error", json!({"actor": "scheduler", "why": e}));
            }
            Err(join_err) => {
                eprintln!("[forge] backup programmé : tâche interrompue (fail-open): {join_err}");
                append_console_ledger(&app, "console.backup.error", json!({"actor": "scheduler", "why": "tâche de backup interrompue"}));
            }
        }
    }
}

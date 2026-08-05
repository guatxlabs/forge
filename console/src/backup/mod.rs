// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — SAUVEGARDE / RESTAURATION CHIFFRÉE + politique/scheduler offsite + API backup/restore.
//! Bloc déplacé depuis main.rs (PURE MOVE, Wave 2). Réutilise App + les helpers d'auth/ledger de la
//! racine de crate (re-exportés `pub(crate) use crate::backup::*`) et référence `crate::dbmigrate`
//! (helpers de copie/ledger partagés) — dépendance croisée volontaire (les deux sous-systèmes partagent
//! le même trio base+ledger+clé).
use crate::*;
// Sous-modules extraits de backup.rs (PURE MOVE, behavior-neutral) : primitives crypto/format
// (`backup_crypto`) et scheduler/offsite (`backup_sched`). Re-exportés `pub(crate)` ici pour que le
// glob `pub(crate) use crate::backup::*` (main.rs) les propage à la racine de crate — les appelants
// inter-modules (compliance: `crate::backup_encrypt`/`crate::sha256_hex_bytes`/`crate::backup_decrypt` ;
// main: `backup_scheduler_loop`) ET le module de tests (`super::*`) continuent de les résoudre INCHANGÉS.
pub(crate) use crate::backup_crypto::*;
pub(crate) use crate::backup_sched::*;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::Engine;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

/// Assemble le PLAINTEXT de l'archive (tar) : manifest.json (schéma+timestamp optionnel+sha256 par
/// fichier) EN PREMIER, puis db.sqlite (toujours), puis engagement.jsonl et signing.ed25519 s'ils
/// existent. `ts` = timestamp passé-en-argument ou OMIS (jamais inventé). Renvoie les octets tar.
pub(crate) fn backup_build_archive(
    db_snapshot: &[u8],
    ledger: Option<&[u8]>,
    key: Option<&[u8]>,
    ts: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut files_meta = serde_json::Map::new();
    // db toujours présent.
    files_meta.insert(
        BACKUP_ENTRY_DB.to_string(),
        json!({"sha256": sha256_hex_bytes(db_snapshot), "size": db_snapshot.len()}),
    );
    if let Some(l) = ledger {
        files_meta.insert(
            BACKUP_ENTRY_LEDGER.to_string(),
            json!({"sha256": sha256_hex_bytes(l), "size": l.len()}),
        );
    }
    if let Some(k) = key {
        files_meta.insert(
            BACKUP_ENTRY_KEY.to_string(),
            json!({"sha256": sha256_hex_bytes(k), "size": k.len()}),
        );
    }
    let mut manifest = json!({
        "kind": "forge-backup",
        "schema": BACKUP_SCHEMA_VERSION,
        "cipher": "xchacha20poly1305",
        "kdf": "argon2id",
        "files": Value::Object(files_meta),
    });
    if let Some(t) = ts {
        manifest["created_at"] = json!(t);
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("sérialisation du manifest échouée: {e}"))?;

    let mut entries: Vec<(&str, &[u8])> = vec![
        (BACKUP_ENTRY_MANIFEST, manifest_bytes.as_slice()),
        (BACKUP_ENTRY_DB, db_snapshot),
    ];
    if let Some(l) = ledger { entries.push((BACKUP_ENTRY_LEDGER, l)); }
    if let Some(k) = key { entries.push((BACKUP_ENTRY_KEY, k)); }
    backup_build_tar(&entries)
}

/// Écrit `data` à `path` de façon quasi-atomique : écrit un fichier temporaire sibling puis rename().
/// Crée le dossier parent si nécessaire. `mode` (unix) appliqué au fichier final (ex: 0600 pour la clé).
pub(crate) fn backup_write_atomic(path: &str, data: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("création du dossier de '{path}' échouée: {e}"))?;
        }
    }
    let tmp = format!("{path}.forge-tmp-{}", std::process::id());
    std::fs::write(&tmp, data).map_err(|e| format!("écriture de '{tmp}' échouée: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {mode:o} de '{tmp}' échoué: {e}"))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    // SYS-1 : fsync du CONTENU du fichier temporaire AVANT le rename — sinon un crash peut laisser une
    // entrée renommée mais vide/partielle (le rename est durable, pas les données qu'il pointe).
    {
        let f = std::fs::File::open(&tmp).map_err(|e| format!("réouverture de '{tmp}' pour sync échouée: {e}"))?;
        f.sync_all().map_err(|e| format!("sync de '{tmp}' échoué: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("renommage de '{tmp}' -> '{path}' échoué: {e}")
    })?;
    // SYS-1 : fsync du DOSSIER PARENT APRÈS le rename — rend l'entrée de répertoire (le nouveau nom)
    // durable. Best-effort (unix uniquement ; no-op ailleurs). Ne bloque pas la réussite du write.
    #[cfg(unix)]
    {
        let parent = std::path::Path::new(path).parent();
        let dir = match parent {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => std::path::Path::new("."),
        };
        if let Ok(dirf) = std::fs::File::open(dir) {
            let _ = dirf.sync_all();
        }
    }
    Ok(())
}

/// Vrai si un fichier existe ET est non vide (taille > 0). Sert la garde anti-écrasement du restore.
pub(crate) fn path_exists_nonempty(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_file() && m.len() > 0).unwrap_or(false)
}

/// Options d'une sauvegarde (partagées CLI/coeur).
pub(crate) struct BackupOpts {
    pub(crate) out: String,             // chemin de l'archive chiffrée à écrire
    pub(crate) passphrase: String,      // passphrase EN CLAIR (déjà lue depuis l'ENV — jamais depuis argv)
    pub(crate) db: String,              // base source
    pub(crate) ledger: Option<String>,  // ledger source (défaut : sibling engagement.jsonl de `db`)
    pub(crate) ts: Option<String>,      // timestamp du manifest (ou OMIS)
    pub(crate) actor: String,           // attribution ledger ("cli:backup")
}

/// CŒUR d'une sauvegarde, SANS la trace ledger finale. Étapes : (a) VÉRIFIE la chaîne du ledger —
/// ABORT sur rupture ; (b) snapshot COHÉRENT de la base (VACUUM INTO, source READ-ONLY) ; (c) archive
/// tar {manifest, db, ledger, clé} ; (d) CHIFFRE (argon2id + XChaCha20-Poly1305) -> écrit l'archive.
/// Renvoie `(rapport, detail_a_tracer)` : le `detail` est ce que l'appelant DOIT ledgeriser
/// (`console.backup`, métadonnées SEULES — JAMAIS la passphrase/clé). Séparer la trace permet à
/// l'appelant LIVE (serveur) de la router via `append_console_ledger` (verrou + cache du head) plutôt
/// que `ledger_append_standalone`, ce qui éviterait de DÉSYNCHRONISER le cache du head ledger de l'App.
/// La voie CLI (offline) réutilise `run_backup` (ci-dessous) qui trace en standalone.
pub(crate) fn run_backup_core(opts: &BackupOpts) -> Result<(Value, Value), String> {
    if opts.passphrase.is_empty() {
        return Err("passphrase absente — une passphrase est OBLIGATOIRE (fail-closed)".to_string());
    }
    if !std::path::Path::new(&opts.db).exists() {
        return Err(format!("base source introuvable: {}", opts.db));
    }
    let ledger_path = opts.ledger.clone().unwrap_or_else(|| default_sibling_ledger(&opts.db));

    // (a) VÉRIF chaîne ledger AVANT tout — un ledger présent mais rompu AVORTE (aucune archive écrite).
    // Un ledger ABSENT n'est pas une rupture (install neuf, rien à inclure) -> on continue.
    let v = verify_ledger_chain(&ledger_path);
    if v.exists && !v.ok {
        return Err(format!(
            "ledger rompu (seq={}) : {} — backup AVORTÉ (aucune archive écrite)",
            v.broken,
            v.why.clone().unwrap_or_default()
        ));
    }

    // (b) snapshot COHÉRENT de la base via VACUUM INTO (réutilise la primitive de migration) dans un
    // fichier temporaire sibling de l'archive, lu en mémoire puis supprimé.
    let snap = format!("{}.forge-snap-{}", opts.out, std::process::id());
    {
        let src = Connection::open_with_flags(
            &opts.db,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| format!("ouverture read-only de '{}' impossible: {e}", opts.db))?;
        let _ = src.busy_timeout(std::time::Duration::from_secs(5));
        migrate_copy_plaintext(&src, &snap)?; // VACUUM INTO (source jamais mutée)
    }
    let db_snapshot = std::fs::read(&snap).map_err(|e| format!("lecture du snapshot '{snap}' échouée: {e}"));
    // nettoyage du temporaire quel que soit le résultat de lecture.
    let _ = std::fs::remove_file(&snap);
    let _ = std::fs::remove_file(format!("{snap}-wal"));
    let _ = std::fs::remove_file(format!("{snap}-shm"));
    let db_snapshot = db_snapshot?;

    // (c) lit ledger + clé de signature (verbatim) s'ils existent.
    let ledger_bytes = if std::path::Path::new(&ledger_path).exists() {
        Some(std::fs::read(&ledger_path).map_err(|e| format!("lecture du ledger '{ledger_path}' échouée: {e}"))?)
    } else {
        None
    };
    let key_path = format!("{ledger_path}.ed25519");
    let key_bytes = if std::path::Path::new(&key_path).exists() {
        Some(std::fs::read(&key_path).map_err(|e| format!("lecture de la clé '{key_path}' échouée: {e}"))?)
    } else {
        None
    };

    let plaintext = backup_build_archive(
        &db_snapshot,
        ledger_bytes.as_deref(),
        key_bytes.as_deref(),
        opts.ts.as_deref(),
    )?;

    // (d) CHIFFREMENT OBLIGATOIRE (aucun chemin en clair) puis écriture atomique de l'archive.
    let sealed = backup_encrypt(&plaintext, &opts.passphrase)?;
    backup_write_atomic(&opts.out, &sealed, 0o600)?;

    // `detail` à TRACER par l'appelant (métadonnées SEULES — jamais passphrase/clé). L'archive reflète
    // l'état AVANT cette entrée (point-in-time propre : le fichier ledger est lu plus haut, avant tout
    // append). `archive_sha256` = empreinte de l'archive scellée (traçabilité offsite).
    let detail = json!({
        "actor": opts.actor,
        "db": opts.db,
        "ledger": ledger_path,
        "out": opts.out,
        "db_sha256": sha256_hex_bytes(&db_snapshot),
        "archive_bytes": sealed.len(),
        "archive_sha256": sha256_hex_bytes(&sealed),
        "included": {"db": true, "ledger": ledger_bytes.is_some(), "key": key_bytes.is_some()},
        "encrypted": true,
        "cipher": "xchacha20poly1305",
        "kdf": "argon2id",
    });

    let report = json!({
        "ok": true,
        "out": opts.out,
        "db": opts.db,
        "ledger": ledger_path,
        "archive_bytes": sealed.len(),
        "archive_sha256": sha256_hex_bytes(&sealed),
        "db_sha256": sha256_hex_bytes(&db_snapshot),
        "included_ledger": ledger_bytes.is_some(),
        "included_key": key_bytes.is_some(),
        "encrypted": true,
    });
    Ok((report, detail))
}

/// Sauvegarde CLI/offline : exécute `run_backup_core` PUIS trace `console.backup` au ledger via
/// `ledger_append_standalone` (relit le head à froid — pas d'App live à désynchroniser). Renvoie le
/// rapport enrichi de `backup_ledger_hash`. Comportement historique préservé (voie CLI de confiance).
pub(crate) fn run_backup(opts: &BackupOpts) -> Result<Value, String> {
    let (mut report, detail) = run_backup_core(opts)?;
    let ledger_path = report.get("ledger").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let backup_hash = if !ledger_path.is_empty() {
        ledger_append_standalone(&ledger_path, "console.backup", &detail).ok()
    } else {
        None
    };
    report["backup_ledger_hash"] = json!(backup_hash);
    Ok(report)
}

/// Options d'une restauration (partagées CLI/coeur).
pub(crate) struct RestoreOpts {
    pub(crate) input: String,           // archive chiffrée à lire
    pub(crate) passphrase: String,      // passphrase EN CLAIR (déjà lue depuis l'ENV)
    pub(crate) to: Option<String>,      // base cible (défaut : FORGE_CONSOLE_DB / forge.db)
    pub(crate) ledger: Option<String>,  // ledger cible (défaut : sibling engagement.jsonl de la base)
    pub(crate) force: bool,             // autorise l'écrasement d'un install existant NON VIDE
    pub(crate) actor: String,           // attribution ledger ("cli:restore")
}

/// Exécute une restauration. Étapes : (1) DÉCHIFFRE (mauvaise passphrase / archive altérée => Err propre,
/// RIEN écrit) ; (2) extrait le tar ; (3) VÉRIFIE le sha256 de chaque fichier du manifest ; (4) re-VÉRIFIE
/// la chaîne du ledger extrait ; (5) REFUSE d'écraser un install non vide sans `--force` ; (6) place
/// db/ledger/clé (clé en 0600) verbatim ; (7) re-vérifie la chaîne APRÈS placement ; trace `console.restore`
/// (métadonnées seules). La clé voyage TOUJOURS à côté du ledger.
pub(crate) fn run_restore(opts: &RestoreOpts) -> Result<Value, String> {
    if opts.passphrase.is_empty() {
        return Err("passphrase absente — une passphrase est OBLIGATOIRE (fail-closed)".to_string());
    }
    let archive = std::fs::read(&opts.input)
        .map_err(|e| format!("lecture de l'archive '{}' impossible: {e}", opts.input))?;

    // (1) DÉCHIFFREMENT — échec (passphrase/altération) AVANT toute écriture disque => rien n'est touché.
    let plaintext = backup_decrypt(&archive, &opts.passphrase)?;
    // (2) extraction en mémoire (aucune écriture cible pour l'instant).
    let entries = backup_extract_tar(&plaintext)?;
    let get = |name: &str| entries.iter().find(|(n, _)| n == name).map(|(_, b)| b.as_slice());

    // (3) manifest + vérif sha256 de CHAQUE fichier listé.
    let manifest_bytes = get(BACKUP_ENTRY_MANIFEST)
        .ok_or_else(|| "manifest.json absent de l'archive".to_string())?;
    let manifest: Value = serde_json::from_slice(manifest_bytes)
        .map_err(|e| format!("manifest.json illisible: {e}"))?;
    let files = manifest
        .get("files")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "manifest.json : section `files` absente ou invalide".to_string())?;
    for (fname, meta) in files {
        let expected = meta
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("manifest : sha256 manquant pour '{fname}'"))?;
        let data = get(fname)
            .ok_or_else(|| format!("fichier '{fname}' listé au manifest mais ABSENT de l'archive"))?;
        let actual = sha256_hex_bytes(data);
        if actual != expected {
            return Err(format!(
                "sha256 mismatch pour '{fname}' — archive altérée (attendu {expected}, calculé {actual})"
            ));
        }
    }

    let db_data = get(BACKUP_ENTRY_DB).ok_or_else(|| "db.sqlite absent de l'archive".to_string())?;
    let ledger_data = get(BACKUP_ENTRY_LEDGER);
    let key_data = get(BACKUP_ENTRY_KEY);

    // destinations.
    let db_dst = opts.to.clone().unwrap_or_else(cli_db_path);
    let ledger_dst = opts.ledger.clone().unwrap_or_else(|| default_sibling_ledger(&db_dst));
    let key_dst = format!("{ledger_dst}.ed25519");

    // (4) re-VÉRIF de la chaîne du ledger EXTRAIT (intégrité) — via un temporaire, AVANT tout placement.
    if let Some(l) = ledger_data {
        let tmpv = format!("{ledger_dst}.forge-verify-{}", std::process::id());
        std::fs::write(&tmpv, l).map_err(|e| format!("écriture temp de vérif ledger échouée: {e}"))?;
        let vext = verify_ledger_chain(&tmpv);
        let _ = std::fs::remove_file(&tmpv);
        if vext.exists && !vext.ok {
            return Err(format!(
                "ledger de l'archive rompu (seq={}) : {} — restore AVORTÉ (rien écrit)",
                vext.broken,
                vext.why.clone().unwrap_or_default()
            ));
        }
    }

    // (5) GARDE anti-écrasement : une base OU un ledger cible NON VIDE bloque sans `--force`.
    if !opts.force && (path_exists_nonempty(&db_dst) || path_exists_nonempty(&ledger_dst)) {
        return Err(format!(
            "install existant NON VIDE ({db_dst} / {ledger_dst}) — restore REFUSÉ sans --force (aucune écriture)"
        ));
    }

    // (6) placement verbatim. DB : purge des sidecars WAL/SHM potentiellement périmés avant d'écrire.
    let _ = std::fs::remove_file(format!("{db_dst}-wal"));
    let _ = std::fs::remove_file(format!("{db_dst}-shm"));
    backup_write_atomic(&db_dst, db_data, 0o600)?;
    if let Some(l) = ledger_data {
        backup_write_atomic(&ledger_dst, l, 0o644)?;
    }
    // la clé DOIT voyager avec le ledger — placée en 0600 (secret de signature).
    if let Some(k) = key_data {
        backup_write_atomic(&key_dst, k, 0o600)?;
    }

    // (7) re-VÉRIF de la chaîne APRÈS placement (intégrité restaurée), PUIS trace `console.restore`.
    let restore_hash = if ledger_data.is_some() {
        let vplaced = verify_ledger_chain(&ledger_dst);
        if vplaced.exists && !vplaced.ok {
            return Err(format!(
                "ledger restauré invérifiable après placement (seq={}) : {}",
                vplaced.broken,
                vplaced.why.clone().unwrap_or_default()
            ));
        }
        // TRACE (métadonnées SEULES — jamais passphrase/clé) : continue la chaîne du ledger restauré.
        let detail = json!({
            "actor": opts.actor,
            "input": opts.input,
            "db": db_dst,
            "ledger": ledger_dst,
            "forced": opts.force,
            "restored": {"db": true, "ledger": ledger_data.is_some(), "key": key_data.is_some()},
        });
        ledger_append_standalone(&ledger_dst, "console.restore", &detail).ok()
    } else {
        None
    };

    Ok(json!({
        "ok": true,
        "input": opts.input,
        "db": db_dst,
        "ledger": ledger_dst,
        "restored_ledger": ledger_data.is_some(),
        "restored_key": key_data.is_some(),
        "forced": opts.force,
        "restore_ledger_hash": restore_hash,
    }))
}

/// Lit une passphrase depuis la variable d'ENV nommée (JAMAIS depuis argv/STDIN echo), avec repli
/// `*_FILE` (secret Docker/k8s) : si `<VAR>` est vide/absente mais `<VAR>_FILE` pointe un fichier
/// lisible, la passphrase est LUE depuis ce fichier (newline de fin retiré). Vide/absente/illisible
/// => None (l'appelant échoue fail-closed). La valeur n'est jamais imprimée/loggée. Ce SEUL point de
/// résolution est partagé par le backup/restore CLI, le scheduler (`policy.passphrase_env`) et
/// `upgrade` (`--passphrase-env`) — tous héritent donc du repli `*_FILE`.
pub(crate) fn read_passphrase_env(var: &str) -> Option<String> {
    crate::secret_from_env(var)
}

/// `forge backup --out <archive> --passphrase-env <ENVVAR> [--db <path>] [--ledger <path>]`
/// Sauvegarde CHIFFRÉE (obligatoire) de la base + ledger + clé. Codes : 0 OK, 1 échec, 2 usage.
pub(crate) fn run_backup_cli(args: &[String]) -> i32 {
    let out = match cli_opt(args, "out") {
        Some(o) if !o.is_empty() => o,
        _ => {
            eprintln!("usage: forge backup --out <archive> --passphrase-env <ENVVAR> [--db <path>] [--ledger <path>]");
            return 2;
        }
    };
    let pass_env = match cli_opt(args, "passphrase-env") {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("[forge] backup: --passphrase-env <ENVVAR> requis (la passphrase est lue depuis cette variable d'ENV, jamais en argv)");
            return 2;
        }
    };
    let passphrase = match read_passphrase_env(&pass_env) {
        Some(p) => p,
        None => {
            eprintln!("[forge] backup: passphrase absente — la variable d'ENV '{pass_env}' est vide ou non définie (fail-closed)");
            return 2;
        }
    };
    let db = cli_opt(args, "db").filter(|s| !s.is_empty()).unwrap_or_else(cli_db_path);
    let opts = BackupOpts {
        out,
        passphrase,
        db,
        ledger: cli_opt(args, "ledger").filter(|s| !s.is_empty()),
        ts: Some(format!("@{}", chrono_now_compact())),
        actor: "cli:backup".to_string(),
    };
    match run_backup(&opts) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into()));
            println!(
                "[forge] backup: OK — archive chiffrée écrite ({} octets) : {}",
                report.get("archive_bytes").and_then(|x| x.as_u64()).unwrap_or(0),
                opts.out
            );
            0
        }
        Err(e) => {
            eprintln!("[forge] backup: {e}");
            1
        }
    }
}

/// `forge restore --in <archive> --passphrase-env <ENVVAR> [--to <db>] [--ledger <path>] [--force]`
/// Restauration CHIFFRÉE (déchiffre, vérifie sha256+ledger, place db/ledger/clé). Codes : 0 OK, 1 échec, 2 usage.
pub(crate) fn run_restore_cli(args: &[String]) -> i32 {
    let input = match cli_opt(args, "in") {
        Some(i) if !i.is_empty() => i,
        _ => {
            eprintln!("usage: forge restore --in <archive> --passphrase-env <ENVVAR> [--to <db>] [--ledger <path>] [--force]");
            return 2;
        }
    };
    let pass_env = match cli_opt(args, "passphrase-env") {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("[forge] restore: --passphrase-env <ENVVAR> requis (passphrase lue depuis l'ENV, jamais en argv)");
            return 2;
        }
    };
    let passphrase = match read_passphrase_env(&pass_env) {
        Some(p) => p,
        None => {
            eprintln!("[forge] restore: passphrase absente — la variable d'ENV '{pass_env}' est vide ou non définie (fail-closed)");
            return 2;
        }
    };
    let opts = RestoreOpts {
        input,
        passphrase,
        to: cli_opt(args, "to").filter(|s| !s.is_empty()),
        ledger: cli_opt(args, "ledger").filter(|s| !s.is_empty()),
        force: cli_flag(args, "force"),
        actor: "cli:restore".to_string(),
    };
    match run_restore(&opts) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into()));
            println!(
                "[forge] restore: OK — {} -> base {} (ledger {})",
                opts.input,
                report.get("db").and_then(|x| x.as_str()).unwrap_or(""),
                report.get("ledger").and_then(|x| x.as_str()).unwrap_or("")
            );
            0
        }
        Err(e) => {
            eprintln!("[forge] restore: {e}");
            1
        }
    }
}

// ===========================================================================================
// API SAUVEGARDE / RESTAURATION / POLITIQUE (admin-gated) — expose le moteur backup au-dessus de
// l'API + la programmation/offsite. Invariants PRÉSERVÉS : l'archive est TOUJOURS chiffrée (aucun
// chemin en clair) ; la passphrase est transitoire (JAMAIS stockée/loggée/ledgerisée) ; la chaîne du
// ledger est vérifiée AVANT backup / à la validation de restore ; le restore refuse d'écraser sans
// confirmation ; chaque action est réservée admin (check_admin, 403) et ledgerisée (métadonnées seules).
// ===========================================================================================

/// Nom canonique d'archive de backup (préfixe + epoch compact). Pas de secret, déterministe par instant.
pub(crate) fn backup_archive_name() -> String {
    format!("forge-backup-{}.forge", chrono_now_compact())
}

/// Suffixe unique pour un fichier TEMPORAIRE (pid + nanos) — évite toute collision entre deux backups /
/// restores concurrents la même seconde. Sans valeur sémantique (jamais persisté/ledgerisé).
pub(crate) fn tmp_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", std::process::id(), nanos)
}

/// Kinds d'offsite FERMÉS (fail-closed : tout autre kind est rejeté avant persistance). La liste par
/// DÉFAUT (community) reste `[none, local_dir, exec]` — VALEUR INCHANGÉE, donc le build par défaut est
/// byte-identique. Sous la feature `object-store`, `s3` (BlobStore S3/MinIO) s'ajoute — le seul chemin
/// qui expédie l'archive chiffrée vers un objet S3 (cf. `ship_offsite`).
#[cfg(not(feature = "object-store"))]
pub(crate) const OFFSITE_KINDS: [&str; 3] = ["none", "local_dir", "exec"];
#[cfg(feature = "object-store")]
pub(crate) const OFFSITE_KINDS: [&str; 4] = ["none", "local_dir", "exec", "s3"];

/// Rédige une politique de backup pour un GET : neutralise TOUTE valeur potentiellement secrète
/// (clé matchant pass/secret/token/password/cred/key) SAUF les noms de variables d'ENV (`*_env`, qui
/// ne sont que des NOMS, pas des secrets). Récursif (couvre `offsite`). Garantit qu'un GET ne renvoie
/// JAMAIS un secret même si un admin a collé par erreur un secret en clair dans la politique.
pub(crate) fn redact_backup_policy(v: &Value) -> Value {
    fn key_is_secretish(k: &str) -> bool {
        if k.ends_with("_env") { return false; } // NOM d'ENV -> jamais un secret
        let lk = k.to_ascii_lowercase();
        ["pass", "secret", "token", "password", "cred", "key"].iter().any(|n| lk.contains(n))
    }
    match v {
        Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, val) in m {
                if key_is_secretish(k) {
                    out.insert(k.clone(), json!("***REDACTED***"));
                } else {
                    out.insert(k.clone(), redact_backup_policy(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(redact_backup_policy).collect()),
        other => other.clone(),
    }
}

/// Politique par défaut quand `settings.backup_policy` est ABSENTE : rien de programmé, aucun offsite.
/// Rien de codé en dur ailleurs — sans politique, le runner ne fait AUCUNE sauvegarde.
pub(crate) fn backup_policy_default() -> Value {
    json!({"enabled": false, "offsite": {"kind": "none"}})
}

/// Lit `settings.backup_policy` (objet JSON) ; défaut si absente/illisible. Ne renvoie jamais d'erreur
/// (fail-soft en lecture — l'appelant obtient la politique par défaut, jamais une valeur inventée).
#[allow(dead_code)] // conservé pour les tests (accès SQLite direct) — le runtime passe par _store.
pub(crate) fn load_backup_policy(db: &Connection) -> Value {
    settings_get(db, "backup_policy")
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(backup_policy_default)
}

/// PORTABLE SEAM analogue of [`load_backup_policy`] over `App::store()`. Identical fail-soft read
/// (défaut si absente/illisible/non-objet). Runtime callers use this; the `&Connection` version above
/// stays for tests.
pub(crate) fn load_backup_policy_store(store: &crate::store::Store) -> Value {
    crate::settings_get_store(store, "backup_policy")
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(backup_policy_default)
}

/// Valide une politique entrante (fail-closed sur les champs structurants). Retourne la politique
/// NETTOYÉE à persister (tout `passphrase` en clair est RETIRÉ — on ne stocke JAMAIS le secret ; seul
/// `passphrase_env` (un NOM d'ENV) est conservé). Erreur -> l'appelant renvoie 400 sans rien écrire.
pub(crate) fn validate_backup_policy(incoming: &Value) -> Result<Value, String> {
    let obj = incoming.as_object().ok_or_else(|| "politique attendue : objet JSON".to_string())?;
    let mut clean = obj.clone();
    // JAMAIS de secret en clair persisté : on retire tout `passphrase` littéral (seul `passphrase_env` reste).
    clean.remove("passphrase");
    let enabled = clean.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    if enabled {
        let interval = clean.get("interval_secs").and_then(|v| v.as_u64()).unwrap_or(0);
        if interval == 0 {
            return Err("interval_secs > 0 requis quand enabled=true".to_string());
        }
        let pe = clean.get("passphrase_env").and_then(|v| v.as_str()).unwrap_or("");
        if pe.is_empty() {
            return Err("passphrase_env requis quand enabled=true (nom de la variable d'ENV portant la passphrase — jamais la passphrase elle-même)".to_string());
        }
    }
    // offsite (kind fermé + forme par kind).
    let offsite = clean.get("offsite").cloned().unwrap_or_else(|| json!({"kind": "none"}));
    let ok = offsite.as_object().ok_or_else(|| "offsite attendu : objet {kind,...}".to_string())?;
    let kind = ok.get("kind").and_then(|v| v.as_str()).unwrap_or("none");
    if !OFFSITE_KINDS.contains(&kind) {
        #[cfg(not(feature = "object-store"))]
        return Err(format!("offsite.kind inconnu: {kind} (attendu: none|local_dir|exec)"));
        #[cfg(feature = "object-store")]
        return Err(format!("offsite.kind inconnu: {kind} (attendu: none|local_dir|exec|s3)"));
    }
    if kind == "local_dir" {
        let dir = ok.get("dir").and_then(|v| v.as_str()).unwrap_or("");
        if dir.is_empty() {
            return Err("offsite local_dir : champ `dir` requis".to_string());
        }
    }
    if kind == "exec" {
        let program = ok.get("program").and_then(|v| v.as_str()).unwrap_or("");
        if program.is_empty() {
            return Err("offsite exec : champ `program` (chemin absolu) requis".to_string());
        }
        if !std::path::Path::new(program).is_absolute() {
            return Err("offsite exec : `program` doit être un chemin ABSOLU (pas de résolution PATH/shell)".to_string());
        }
        if let Some(a) = ok.get("args") {
            if !a.is_array() {
                return Err("offsite exec : `args` doit être un tableau d'arguments (argv fixe, aucun shell)".to_string());
            }
        }
    }
    // offsite s3 (feature `object-store` uniquement — sinon `s3` est déjà rejeté par le check OFFSITE_KINDS
    // ci-dessus). La config S3 (endpoint/bucket/credentials) vit dans l'ENV FORGE_BLOB_S3_* (jamais dans la
    // politique -> aucun secret persisté). Seul `key_prefix` (optionnel) est porté par la politique.
    #[cfg(feature = "object-store")]
    if kind == "s3" {
        if let Some(p) = ok.get("key_prefix") {
            if !p.is_string() {
                return Err("offsite s3 : `key_prefix` (optionnel) doit être une chaîne".to_string());
            }
        }
    }
    Ok(Value::Object(clean))
}

/// Inspecte une archive de backup SANS rien écrire sur une cible : (1) DÉCHIFFRE (mauvaise passphrase /
/// altération => Err propre, tag AEAD) ; (2) extrait le tar en mémoire ; (3) re-vérifie le sha256 de
/// chaque fichier du manifest ; (4) vérifie la chaîne du ledger extrait via un fichier TEMPORAIRE
/// (supprimé aussitôt). Renvoie un rapport de validation (aucun secret). Sert le chemin de restore
/// « valider + rapporter » (par défaut, non destructif).
pub(crate) fn backup_inspect(archive: &[u8], passphrase: &str) -> Result<Value, String> {
    if passphrase.is_empty() {
        return Err("passphrase absente — une passphrase est OBLIGATOIRE (fail-closed)".to_string());
    }
    let plaintext = backup_decrypt(archive, passphrase)?;
    let entries = backup_extract_tar(&plaintext)?;
    let get = |name: &str| entries.iter().find(|(n, _)| n == name).map(|(_, b)| b.as_slice());

    let manifest_bytes = get(BACKUP_ENTRY_MANIFEST)
        .ok_or_else(|| "manifest.json absent de l'archive".to_string())?;
    let manifest: Value = serde_json::from_slice(manifest_bytes)
        .map_err(|e| format!("manifest.json illisible: {e}"))?;
    let files = manifest
        .get("files")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "manifest.json : section `files` absente ou invalide".to_string())?;
    let mut files_report = Vec::new();
    for (fname, meta) in files {
        let expected = meta.get("sha256").and_then(|v| v.as_str())
            .ok_or_else(|| format!("manifest : sha256 manquant pour '{fname}'"))?;
        let data = get(fname)
            .ok_or_else(|| format!("fichier '{fname}' listé au manifest mais ABSENT de l'archive"))?;
        let actual = sha256_hex_bytes(data);
        if actual != expected {
            return Err(format!(
                "sha256 mismatch pour '{fname}' — archive altérée (attendu {expected}, calculé {actual})"
            ));
        }
        files_report.push(json!({"name": fname, "size": data.len(), "sha256": actual}));
    }

    // vérif de la chaîne du ledger extrait, sur un temporaire (aucune cible touchée).
    let mut ledger_ok = true;
    let mut ledger_entries = 0i64;
    if let Some(l) = get(BACKUP_ENTRY_LEDGER) {
        let tmpv = std::env::temp_dir()
            .join(format!("forge-inspect-{}.jsonl", tmp_nonce()))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&tmpv, l).map_err(|e| format!("écriture temp de vérif ledger échouée: {e}"))?;
        let v = verify_ledger_chain(&tmpv);
        ledger_entries = read_ledger_lines(&tmpv).len() as i64;
        let _ = std::fs::remove_file(&tmpv);
        if v.exists && !v.ok {
            return Err(format!(
                "ledger de l'archive rompu (seq={}) : {}",
                v.broken, v.why.clone().unwrap_or_default()
            ));
        }
        ledger_ok = v.ok || !v.exists;
    }

    Ok(json!({
        "ok": true,
        "manifest": {
            "schema": manifest.get("schema").cloned().unwrap_or(Value::Null),
            "created_at": manifest.get("created_at").cloned().unwrap_or(Value::Null),
            "cipher": manifest.get("cipher").cloned().unwrap_or(Value::Null),
            "kdf": manifest.get("kdf").cloned().unwrap_or(Value::Null),
        },
        "files": files_report,
        "has_db": get(BACKUP_ENTRY_DB).is_some(),
        "has_ledger": get(BACKUP_ENTRY_LEDGER).is_some(),
        "has_key": get(BACKUP_ENTRY_KEY).is_some(),
        "ledger_ok": ledger_ok,
        "ledger_entries": ledger_entries,
    }))
}

/// POST /api/backup — ADMIN (check_admin, 403 sinon), LEDGERISÉ. Corps `{passphrase}` : la passphrase
/// est utilisée UNE FOIS (dérivation argon2id) puis abandonnée — JAMAIS stockée/loggée/ledgerisée.
/// Exécute le moteur de backup (chaîne ledger vérifiée AVANT ; archive TOUJOURS chiffrée) et RENVOIE
/// l'archive chiffrée en téléchargement (Content-Disposition). La trace ledger `console.backup` ne
/// contient QUE : acteur + (ts implicite) + taille + sha256 de l'archive (+ sha db). Jamais la passphrase.
pub(crate) async fn api_backup(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let passphrase = body.get("passphrase").and_then(|v| v.as_str()).unwrap_or("");
    if passphrase.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "passphrase_required", "why": "une passphrase est OBLIGATOIRE (fail-closed) — l'archive est toujours chiffrée"})),
        ).into_response();
    }
    // archive écrite dans un temporaire (0600) puis relue et supprimée ; jamais persistée côté serveur.
    let out = std::env::temp_dir()
        .join(format!("{}.tmp-{}", backup_archive_name(), tmp_nonce()))
        .to_string_lossy()
        .into_owned();
    let opts = BackupOpts {
        out: out.clone(),
        passphrase: passphrase.to_string(),
        db: (*app.db_path).clone(),
        ledger: Some((*app.ledger_path).clone()),
        ts: Some(format!("@{}", chrono_now_compact())),
        actor: actor.clone(),
    };
    // run_backup_core NE trace PAS le ledger (on le fait ci-dessous via append_console_ledger, qui tient
    // le verrou + met à jour le cache du head -> aucune désynchronisation de la chaîne live).
    let (report, _cli_detail) = match run_backup_core(&opts) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&out);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "backup_failed", "why": e}))).into_response();
        }
    };
    let sealed = match std::fs::read(&out) {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_file(&out);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "backup_read_failed", "why": e.to_string()}))).into_response();
        }
    };
    let _ = std::fs::remove_file(&out); // le serveur ne conserve JAMAIS l'archive
    // AUDIT : métadonnées SEULES (acteur + taille + sha256), JAMAIS la passphrase ni la clé.
    append_console_ledger(&app, "console.backup", json!({
        "actor": actor,
        "archive_bytes": sealed.len(),
        "archive_sha256": sha256_hex_bytes(&sealed),
        "db_sha256": report.get("db_sha256").cloned().unwrap_or(Value::Null),
        "included": {
            "db": true,
            "ledger": report.get("included_ledger").cloned().unwrap_or(json!(false)),
            "key": report.get("included_key").cloned().unwrap_or(json!(false)),
        },
        "encrypted": true,
        "via": "api",
    }));
    let filename = backup_archive_name();
    (
        StatusCode::OK,
        [
            ("content-type", "application/octet-stream".to_string()),
            ("content-disposition", format!("attachment; filename=\"{filename}\"")),
            ("x-forge-archive-sha256", sha256_hex_bytes(&sealed)),
        ],
        sealed,
    ).into_response()
}

/// POST /api/restore — ADMIN (check_admin, 403 sinon), LEDGERISÉ. Corps JSON :
///   `{archive_b64, passphrase, apply?:bool, confirm?:bool}`.
/// La passphrase est transitoire (jamais stockée/loggée/ledgerisée). PAR DÉFAUT (apply absent/false) :
/// VALIDER + VÉRIFIER l'archive (déchiffrement AEAD, sha256 du manifest, chaîne ledger) et RAPPORTER —
/// AUCUNE écriture. Trace `console.restore.validate` (métadonnées). Un SWAP en place (apply=true) exige
/// une CONFIRMATION explicite (`confirm=true`) : il remplace db+ledger+clé (garde anti-écrasement via
/// --force implicite sous confirm) et REQUIERT UN REDÉMARRAGE de la console (la connexion SQLite vivante
/// tient encore l'ancien fichier). Mauvaise passphrase / archive altérée => échec propre, RIEN écrit.
pub(crate) async fn api_restore(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let passphrase = body.get("passphrase").and_then(|v| v.as_str()).unwrap_or("");
    if passphrase.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "passphrase_required", "why": "une passphrase est OBLIGATOIRE (fail-closed)"})),
        ).into_response();
    }
    let b64 = body.get("archive_b64").and_then(|v| v.as_str()).unwrap_or("");
    if b64.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "archive_required", "why": "champ `archive_b64` (archive chiffrée base64) requis"})),
        ).into_response();
    }
    let archive = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_base64", "why": "archive_b64 n'est pas du base64 valide"}))).into_response(),
    };

    // (1) VALIDATION non destructive systématique (déchiffre + vérifie sha256 + chaîne ledger).
    let inspect = match backup_inspect(&archive, passphrase) {
        Ok(v) => v,
        Err(e) => {
            // échec de validation (mauvaise passphrase / archive altérée) — trace SANS secret, 422.
            append_console_ledger(&app, "console.restore.validate", json!({
                "actor": actor, "archive_bytes": archive.len(), "ok": false, "via": "api",
            }));
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": "archive_invalid", "why": e}))).into_response();
        }
    };

    let apply = body.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
    if !apply {
        // chemin SÛR par défaut : rapporter la validation, ne RIEN écrire.
        append_console_ledger(&app, "console.restore.validate", json!({
            "actor": actor,
            "archive_bytes": archive.len(),
            "archive_sha256": sha256_hex_bytes(&archive),
            "ok": true,
            "via": "api",
        }));
        return (StatusCode::OK, Json(json!({
            "ok": true,
            "applied": false,
            "validated": inspect,
            "note": "archive VALIDÉE (déchiffrable, sha256 conformes, chaîne ledger intègre). Aucune écriture. Pour APPLIQUER le swap en place, relancez avec apply=true ET confirm=true — un REDÉMARRAGE de la console sera requis.",
        }))).into_response();
    }

    // (2) APPLY : swap en place — CONFIRMATION explicite OBLIGATOIRE.
    let confirm = body.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
    if !confirm {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "confirmation_required",
            "why": "apply=true exige confirm=true (confirmation explicite) — le swap remplace la base/ledger/clé en place et REQUIERT un redémarrage",
        }))).into_response();
    }
    // écrit l'archive dans un temporaire (run_restore lit un chemin), puis restaure vers la base/ledger LIVE.
    // `force=true` : la confirmation explicite vaut autorisation d'écraser l'install existant (non vide).
    let tmp = std::env::temp_dir()
        .join(format!("forge-restore-{}.forge", tmp_nonce()))
        .to_string_lossy()
        .into_owned();
    if let Err(e) = std::fs::write(&tmp, &archive) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "restore_stage_failed", "why": e.to_string()}))).into_response();
    }
    let ropts = RestoreOpts {
        input: tmp.clone(),
        passphrase: passphrase.to_string(),
        to: Some((*app.db_path).clone()),
        ledger: Some((*app.ledger_path).clone()),
        force: true,
        actor: actor.clone(),
    };
    let result = run_restore(&ropts);
    let _ = std::fs::remove_file(&tmp);
    match result {
        Ok(mut report) => {
            // run_restore a remplacé le fichier ledger LIVE par celui de l'archive (avec sa propre trace
            // `console.restore`). Le cache du head de l'App est désormais périmé -> on l'invalide pour que
            // tout append ultérieur (avant le redémarrage requis) relise le head à froid (chaîne intacte).
            app.invalidate_ledger_head();
            if let Some(o) = report.as_object_mut() {
                o.insert("applied".to_string(), json!(true));
                o.insert("restart_required".to_string(), json!(true));
                o.insert("maintenance".to_string(), json!("Base/ledger/clé restaurés SUR PLACE. La connexion SQLite vivante tient encore l'ancien fichier : REDÉMARREZ la console (docker restart / systemctl restart) pour charger l'état restauré."));
            }
            (StatusCode::OK, Json(report)).into_response()
        }
        Err(e) => {
            // ex. install non vide sans force (ne devrait pas arriver ici, force=true) OU intégrité.
            let code = if e.contains("REFUSÉ") { StatusCode::CONFLICT } else { StatusCode::UNPROCESSABLE_ENTITY };
            (code, Json(json!({"error": "restore_failed", "why": e}))).into_response()
        }
    }
}

/// GET /api/backup/policy — ADMIN (403 sinon). Renvoie la politique de sauvegarde RÉDIGÉE (aucun secret ;
/// `passphrase_env` = NOM d'ENV, conservé), la liste FERMÉE des kinds d'offsite, et l'horodatage de la
/// dernière exécution programmée (`last_run`, métadonnée). Sans politique -> défaut (rien de programmé).
pub(crate) async fn api_backup_policy_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let (policy, last_run) = {
        let store = app.store();
        (load_backup_policy_store(&store), crate::settings_get_store(&store, "backup_last_run"))
    };
    (StatusCode::OK, Json(json!({
        "policy": redact_backup_policy(&policy),
        "offsite_kinds": OFFSITE_KINDS,
        "last_run": last_run,
        "configured": crate::settings_get_store(&app.store(), "backup_policy").is_some(),
    }))).into_response()
}

/// POST /api/backup/policy — ADMIN (403 sinon), LEDGERISÉ. Corps : la politique (à plat) OU `{policy:{...}}`.
/// Valide (kinds fermés, interval/passphrase_env requis si enabled), RETIRE tout `passphrase` en clair
/// (jamais de secret persisté), persiste `settings.backup_policy`, trace `console.backup.policy.set`
/// (métadonnées : enabled/interval/offsite_kind/passphrase_env — jamais un secret). Renvoie la politique rédigée.
pub(crate) async fn api_backup_policy_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let incoming = if let Some(p) = body.get("policy").filter(|v| v.is_object()) {
        p.clone()
    } else if body.is_object() {
        body.clone()
    } else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "corps attendu : {policy:{...}} ou l'objet politique à plat"}))).into_response();
    };
    let clean = match validate_backup_policy(&incoming) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_policy", "why": e}))).into_response(),
    };
    {
        let store = app.store();
        if let Err(e) = crate::settings_set_store(&store, "backup_policy", &clean.to_string()) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "settings_write_failed", "why": e}))).into_response();
        }
    }
    let offsite_kind = clean.get("offsite").and_then(|o| o.get("kind")).and_then(|v| v.as_str()).unwrap_or("none").to_string();
    append_console_ledger(&app, "console.backup.policy.set", json!({
        "actor": actor,
        "enabled": clean.get("enabled").cloned().unwrap_or(json!(false)),
        "interval_secs": clean.get("interval_secs").cloned().unwrap_or(Value::Null),
        "retention": clean.get("retention").cloned().unwrap_or(Value::Null),
        "offsite_kind": offsite_kind,
        "passphrase_env": clean.get("passphrase_env").cloned().unwrap_or(Value::Null),
    }));
    (StatusCode::OK, Json(json!({"ok": true, "saved": true, "policy": redact_backup_policy(&clean)}))).into_response()
}




#[cfg(test)]
mod tests;

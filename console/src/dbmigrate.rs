// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — MIGRATION DE DONNÉES + CHIFFREMENT AU REPOS (import d'un install existant, clé
//! SQLCipher au boot). Bloc déplacé depuis main.rs (PURE MOVE, Wave 2). `copy_ledger_and_key` route
//! l'écriture atomique de la clé via `crate::backup::backup_write_atomic` (re-exporté pub(crate)).
//! Réutilise App + les helpers de la racine de crate (re-exportés `pub(crate) use crate::dbmigrate::*`).
use crate::backup::backup_write_atomic;
use crate::*;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

// ===========================================================================================
// MIGRATION DE DONNÉES — importe un install Forge EXISTANT (non-Docker) vers un install
// Docker/autre. Trois volets couplés qui doivent voyager ENSEMBLE pour rester audités :
//   1) la base SQLite (findings/runs/roe/users/settings) — copie COHÉRENTE via VACUUM INTO
//      (source ouverte READ-ONLY, jamais mutée) ou export CHIFFRÉ (SQLCipher, feature opt-in) ;
//   2) le ledger JSONL d'engagement (chaîne SHA-256 tamper-evident) ;
//   3) la clé de signature sibling `.ed25519` (0600) — SANS elle, les entrées signées du ledger
//      deviennent invérifiables (la chaîne perd sa non-répudiation). La clé DOIT suivre le ledger.
// La cible reçoit ensuite SCHEMA + migrate() : une base plus ANCIENNE est upgradée EN PLACE.
// ZÉRO défaut caché : chaque chemin est explicite (pas d'IP/host/clé codés en dur). La migration
// est elle-même TRACÉE au ledger cible (kind `console.migrate`, chaîne SHA-256 continue).
// ===========================================================================================

/// Options d'une migration (partagées par la sous-commande CLI et POST /api/setup/migrate).
pub(crate) struct MigrateOpts {
    pub(crate) from: String,            // source : un DOSSIER (install) ou un FICHIER .db
    pub(crate) to: String,              // base cible
    pub(crate) ledger: Option<String>,  // ledger cible (défaut : sibling engagement.jsonl de `to`)
    pub(crate) verify: bool,            // recompute la chaîne SHA-256 du ledger source, ABORT sur rupture
    pub(crate) encrypt: bool,           // cible chiffrée SQLCipher (exige la feature `encryption`)
    pub(crate) key_env: Option<String>, // nom de la variable d'ENV portant la clé (JAMAIS la clé en argv)
    pub(crate) actor: String,           // attribution ledger ("cli:migrate" | "api:setup/migrate")
}

/// Résout (source_db, source_ledger) depuis `--from`. Un DOSSIER -> {dir}/forge-console.db +
/// {dir}/engagement.jsonl (convention d'install). Un FICHIER -> le fichier .db + son sibling
/// engagement.jsonl (même dossier). Aucune invention : si le ledger n'existe pas, la copie le note.
pub(crate) fn resolve_migrate_source(from: &str) -> (String, String) {
    let p = std::path::Path::new(from);
    if p.is_dir() {
        let db = p.join("forge-console.db");
        let led = p.join("engagement.jsonl");
        (db.to_string_lossy().into_owned(), led.to_string_lossy().into_owned())
    } else {
        let led = p.parent().unwrap_or_else(|| std::path::Path::new("."))
            .join("engagement.jsonl");
        (from.to_string(), led.to_string_lossy().into_owned())
    }
}

/// Chemin ledger par défaut à côté d'une base : {dir(to)}/engagement.jsonl.
pub(crate) fn default_sibling_ledger(to: &str) -> String {
    std::path::Path::new(to)
        .parent()
        .map(|p| p.join("engagement.jsonl"))
        .unwrap_or_else(|| std::path::PathBuf::from("engagement.jsonl"))
        .to_string_lossy()
        .into_owned()
}

// ===========================================================================================
// GARDE-FOU MIGRATION VIA API (POST /api/setup/migrate) — cet endpoint est joignable NON-AUTHENTIFIÉ
// pendant la fenêtre de setup (avant le 1er provisioning). Sans garde, `from`/`to`/`ledger` sont des
// chemins serveur ARBITRAIRES -> primitive d'écriture/suppression de fichier non-auth (traversal `..`,
// chemins absolus). DEUX couches défendent cette frontière API (la voie CLI, invocation locale de
// confiance, reste INCHANGÉE et non restreinte) :
//   COUCHE 1 — opt-in `FORGE_ALLOW_API_MIGRATE` (défaut OFF = CLI-seule) : sans le flag, l'endpoint
//              REFUSE avant toute I/O -> la primitive disparaît du déploiement par défaut.
//   COUCHE 2 — quand le flag est actif, confinement anti-traversal des chemins sous une racine
//              allowlistée (racine de données console), avec refus d'écraser une cible hors racine.
// ===========================================================================================

/// Lit un flag booléen d'ENV : `1`/`true`/`yes`/`on` (insensible à la casse) => true ; absent, vide,
/// ou toute autre valeur => false. FAIL-CLOSED : un flag mal orthographié n'active RIEN.
pub(crate) fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false)
}

/// Racine autorisée pour l'import/export via API (allowlist anti-traversal). Par défaut : le DOSSIER
/// parent de la base console ($FORGE_CONSOLE_DB — la racine de données), surchargeable explicitement
/// par $FORGE_CONSOLE_IMPORT_DIR (dossier de staging dédié). Un chemin de base relatif sans parent
/// (défaut `forge-console.db`) => `.` (cwd de la console). N'affecte QUE la frontière API.
pub(crate) fn api_migrate_base_dir() -> std::path::PathBuf {
    if let Some(d) = std::env::var("FORGE_CONSOLE_IMPORT_DIR").ok().filter(|s| !s.is_empty()) {
        return std::path::PathBuf::from(d);
    }
    let db = std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge-console.db".to_string());
    std::path::Path::new(&db)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Confine UN chemin d'import/export (frontière API) sous `base_canon` (déjà canonicalisé). Étapes :
///   1) rejet de tout composant `..` (traversal explicite) AVANT toute résolution ;
///   2) résolution : si la cible existe, canonicalise le chemin COMPLET ; sinon (to/ledger neufs)
///      canonicalise le DOSSIER PARENT (qui doit exister) puis rejoint le nom de fichier ;
///   3) confinement : le chemin résolu DOIT être SOUS `base_canon` (comparaison par composants).
///
/// `must_exist` : la source (`from`) doit exister ; une cible préexistante HORS base est REFUSÉE
/// (jamais d'écrasement/suppression hors racine). N'est appelée QUE sur la voie API (jamais la CLI).
pub(crate) fn validate_api_migrate_path(
    base_canon: &std::path::Path,
    raw: &str,
    label: &str,
    must_exist: bool,
) -> Result<(), String> {
    if raw.is_empty() {
        return Err(format!("chemin `{label}` vide"));
    }
    let p = std::path::Path::new(raw);
    // 1) refus de tout composant `..` (traversal) — avant même de toucher le disque.
    if p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(format!("chemin `{label}` refusé : composant `..` interdit ({raw})"));
    }
    // 2) résolution en chemin absolu réel.
    let resolved = if p.exists() {
        // existe (source, OU cible préexistante) : canonicalise le chemin complet.
        p.canonicalize()
            .map_err(|e| format!("canonicalisation de `{label}` ({raw}) impossible: {e}"))?
    } else {
        if must_exist {
            return Err(format!("source `{label}` introuvable: {raw}"));
        }
        // cible neuve : le PARENT doit exister et être sous la base ; on rejoint ensuite le nom.
        let parent = p
            .parent()
            .filter(|pp| !pp.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let parent_canon = parent
            .canonicalize()
            .map_err(|e| format!("dossier parent de `{label}` ({raw}) inexistant/illisible: {e}"))?;
        let name = p
            .file_name()
            .ok_or_else(|| format!("chemin `{label}` sans nom de fichier: {raw}"))?;
        parent_canon.join(name)
    };
    // 3) confinement sous la racine allowlistée (starts_with = comparaison PAR COMPOSANTS, pas de
    //    faux-positif "/a/bc".starts_with("/a/b")). Une cible préexistante hors base tombe ici => refus.
    if !resolved.starts_with(base_canon) {
        return Err(format!(
            "chemin `{label}` hors de la racine autorisée : {} n'est pas sous {}",
            resolved.display(),
            base_canon.display()
        ));
    }
    Ok(())
}

/// Valide `from`/`to`/`ledger` de la migration API contre la racine allowlistée ($FORGE_CONSOLE_IMPORT_DIR
/// ou la racine de données console). Résout+canonicalise la base UNE fois, puis délègue par chemin.
/// N'est appelée QUE depuis `setup_migrate` (jamais la CLI). Err(why) => la requête est refusée (403).
pub(crate) fn validate_api_migrate_paths(from: &str, to: &str, ledger: Option<&str>) -> Result<(), String> {
    let base = api_migrate_base_dir();
    let base_canon = base.canonicalize().map_err(|e| {
        format!(
            "racine d'import autorisée introuvable/illisible ({}): {e} — créer le dossier ou poser FORGE_CONSOLE_IMPORT_DIR",
            base.display()
        )
    })?;
    validate_api_migrate_path(&base_canon, from, "from", true)?;
    validate_api_migrate_path(&base_canon, to, "to", false)?;
    if let Some(l) = ledger {
        validate_api_migrate_path(&base_canon, l, "ledger", false)?;
    }
    Ok(())
}

/// Append UNE entrée au ledger JSONL à `path`, en (re)lisant le head depuis le disque (chaîne
/// SHA-256, alg "sha256-console", sig ""). AUTONOME (pas d'App/cache) — pour la migration one-shot :
/// une seule entrée, pas de contention. Miroir strict de append_console_ledger côté pré-image, donc
/// /api/ledger/verify recompute la chaîne SANS rupture. Renvoie le hash de la nouvelle entrée.
pub(crate) fn ledger_append_standalone(path: &str, kind: &str, detail: &Value) -> Result<String, String> {
    let mut prev = "0".repeat(64);
    let mut seq = 0i64;
    if let Ok(s) = std::fs::read_to_string(path) {
        for line in s.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(rec) = serde_json::from_str::<Value>(line) {
                if let Some(h) = rec.get("hash").and_then(|v| v.as_str()) { prev = h.to_string(); }
                if let Some(q) = rec.get("seq").and_then(|v| v.as_i64()) { seq = q; }
            }
        }
    }
    let seq = seq + 1;
    let ts = format!("@{}", chrono_now_compact());
    let preimage = format!("{prev}|{seq}|{ts}|{kind}|{}", canon_json(detail));
    let hash = sha_hex(&preimage);
    let rec = json!({
        "seq": seq, "ts": ts, "kind": kind, "detail": detail,
        "prev": prev, "hash": hash, "alg": "sha256-console", "sig": ""
    });
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() { let _ = std::fs::create_dir_all(parent); }
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)
        .map_err(|e| format!("ouverture ledger cible '{path}' impossible: {e}"))?;
    writeln!(f, "{}", canon_json(&rec)).map_err(|e| format!("écriture ledger cible échouée: {e}"))?;
    // SYS-2 : fsync -> l'entrée du ledger dédié est DURABLE avant de retourner (comme append_console_ledger).
    f.sync_all().map_err(|e| format!("sync ledger cible échoué: {e}"))?;
    Ok(hash)
}

/// plaintext -> plaintext : `VACUUM INTO` (copie COHÉRENTE, fonctionne sur une source READ-ONLY).
/// La cible NE DOIT PAS préexister (VACUUM INTO refuse d'écraser) -> on retire cible + sidecars WAL/SHM
/// d'abord. Renvoie `encrypted=false`.
pub(crate) fn migrate_copy_plaintext(src: &Connection, target: &str) -> Result<bool, String> {
    if std::path::Path::new(target).exists() {
        std::fs::remove_file(target)
            .map_err(|e| format!("cible '{target}' déjà présente et non supprimable: {e}"))?;
    }
    let _ = std::fs::remove_file(format!("{target}-wal"));
    let _ = std::fs::remove_file(format!("{target}-shm"));
    if let Some(parent) = std::path::Path::new(target).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("création du dossier cible échouée: {e}"))?;
        }
    }
    // paramètre lié (le chemin cible n'est pas inliné dans le SQL).
    src.execute("VACUUM INTO ?1", [target])
        .map_err(|e| format!("VACUUM INTO '{target}' échoué: {e}"))?;
    Ok(false)
}

/// Résout la clé de chiffrement depuis la variable d'ENV nommée par `--key-env`. JAMAIS la clé en argv
/// (fuite via ps/historique). None si le nom est absent ou la variable vide. Gated : n'existe que dans
/// le build chiffré (dans le build par défaut, aucun code ne la référence).
#[cfg(feature = "encryption")]
pub(crate) fn resolve_key(key_env: Option<&str>) -> Option<String> {
    let name = key_env?;
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// plaintext -> CHIFFRÉ : attache une base cible chiffrée (PRAGMA KEY) et exporte via
/// sqlcipher_export(). Compilé UNIQUEMENT avec la feature `encryption`.
#[cfg(feature = "encryption")]
pub(crate) fn migrate_copy_encrypted(src: &Connection, target: &str, key_env: Option<&str>) -> Result<bool, String> {
    let key = resolve_key(key_env)
        .ok_or_else(|| "clé de chiffrement absente (--key-env non résolu / variable d'ENV vide)".to_string())?;
    if std::path::Path::new(target).exists() {
        std::fs::remove_file(target).map_err(|e| format!("cible '{target}' non supprimable: {e}"))?;
    }
    let _ = std::fs::remove_file(format!("{target}-wal"));
    let _ = std::fs::remove_file(format!("{target}-shm"));
    if let Some(parent) = std::path::Path::new(target).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("création du dossier cible échouée: {e}"))?;
        }
    }
    src.execute("ATTACH DATABASE ?1 AS encrypted KEY ?2", rusqlite::params![target, key])
        .map_err(|e| format!("ATTACH de la cible chiffrée échoué: {e}"))?;
    let export = src.query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()));
    let _ = src.execute("DETACH DATABASE encrypted", []);
    export.map_err(|e| format!("sqlcipher_export('encrypted') échoué: {e}"))?;
    Ok(true)
}

/// Build PAR DÉFAUT (sans `encryption`) : le chiffrement au repos n'est PAS compilé -> erreur CLAIRE
/// (recompiler avec `--features encryption`). Aucune dépendance SQLCipher n'est tirée par ce chemin.
#[cfg(not(feature = "encryption"))]
pub(crate) fn migrate_copy_encrypted(_src: &Connection, _target: &str, _key_env: Option<&str>) -> Result<bool, String> {
    Err("chiffrement au repos NON compilé dans ce build — recompiler avec `--features encryption` (SQLCipher)".to_string())
}

/// Copie le ledger JSONL source + sa clé de signature sibling `.ed25519` (et le repli HMAC `.key`)
/// dans le dossier ledger CIBLE, en PRÉSERVANT le mode 0600 de la ou des clés (la clé DOIT voyager
/// avec le ledger, sinon la chaîne signée devient invérifiable). Renvoie (ledger_copié, ed25519_copiée).
/// Ledger source absent -> ne copie rien (Ok(false,false)) : un install neuf n'a pas d'engagement.
pub(crate) fn copy_ledger_and_key(src_ledger: &str, target_ledger: &str) -> Result<(bool, bool), String> {
    if !std::path::Path::new(src_ledger).exists() {
        return Ok((false, false));
    }
    if std::path::Path::new(src_ledger) == std::path::Path::new(target_ledger) {
        // source == cible (upgrade en place du même dossier) : rien à copier, la clé est déjà là.
        let has_key = std::path::Path::new(&format!("{src_ledger}.ed25519")).exists();
        return Ok((true, has_key));
    }
    if let Some(parent) = std::path::Path::new(target_ledger).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("création du dossier ledger cible échouée: {e}"))?;
        }
    }
    std::fs::copy(src_ledger, target_ledger)
        .map_err(|e| format!("copie du ledger '{src_ledger}' -> '{target_ledger}' échouée: {e}"))?;
    let mut ed_copied = false;
    // clé(s) de signature sibling : <ledger>.ed25519 (Ed25519, non-répudiation) + <ledger>.key (repli HMAC).
    for ext in [".ed25519", ".key"] {
        let src_key = format!("{src_ledger}{ext}");
        if std::path::Path::new(&src_key).exists() {
            let dst_key = format!("{target_ledger}{ext}");
            // SYS-3 : la clé destination NAÎT en 0600 (backup_write_atomic écrit un temp 0600 puis rename)
            // -> plus de fenêtre 0644 sur le fichier final. L'ancien std::fs::copy créait dst en 0644 PUIS
            // chmod 0600 (bref instant lisible par autrui). Contenu + perms finales identiques (0600).
            let bytes = std::fs::read(&src_key)
                .map_err(|e| format!("lecture de la clé '{src_key}' échouée: {e}"))?;
            backup_write_atomic(&dst_key, &bytes, 0o600)
                .map_err(|e| format!("copie de la clé '{src_key}' -> '{dst_key}' échouée: {e}"))?;
            if ext == ".ed25519" { ed_copied = true; }
        }
    }
    Ok((true, ed_copied))
}

/// Exécute une migration complète. Étapes : (1) ouvre la source READ-ONLY (jamais mutée) ; (2) si
/// `verify`, recompute la chaîne SHA-256 du ledger source et ABORT sur une rupture réelle ; (3) copie
/// la base (VACUUM INTO plaintext | sqlcipher_export chiffré) ; (4) SCHEMA + migrate() sur la cible
/// (upgrade en place) ; (5) copie ledger + clé `.ed25519` (0600) dans le dossier ledger cible ;
/// (6) trace `console.migrate` au ledger cible (chaîne SHA-256 continue). Renvoie un rapport JSON.
pub(crate) fn run_migration(opts: &MigrateOpts) -> Result<Value, String> {
    let (src_db, src_ledger) = resolve_migrate_source(&opts.from);
    if !std::path::Path::new(&src_db).exists() {
        return Err(format!("base source introuvable: {src_db}"));
    }
    // (1) source en LECTURE SEULE — l'install existant n'est JAMAIS modifié par la migration.
    let src = Connection::open_with_flags(
        &src_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("ouverture read-only de '{src_db}' impossible: {e}"))?;
    let _ = src.busy_timeout(std::time::Duration::from_secs(5));

    // (2) --verify : recompute la chaîne du ledger source. ABORT AVANT toute écriture cible si une
    // rupture RÉELLE est détectée (le fichier existe mais la chaîne est cassée). Un ledger ABSENT
    // n'est pas une rupture (install neuf) -> on continue (rien à copier).
    let verify_report = if opts.verify {
        let v = verify_ledger_chain(&src_ledger);
        if v.exists && !v.ok {
            return Err(format!(
                "ledger source rompu (seq={}) : {} — migration AVORTÉE (aucune écriture)",
                v.broken, v.why.clone().unwrap_or_default()
            ));
        }
        Some(ledger_verify_api_json(&v, &src_ledger))
    } else {
        None
    };

    // (3) copie de la base.
    let encrypted = if opts.encrypt {
        migrate_copy_encrypted(&src, &opts.to, opts.key_env.as_deref())?
    } else {
        migrate_copy_plaintext(&src, &opts.to)?
    };
    drop(src); // libère la connexion read-only avant d'ouvrir la cible en écriture.

    // (4) SCHEMA + migrate() sur la cible : une base plus ANCIENNE est upgradée EN PLACE.
    {
        let dst = Connection::open(&opts.to)
            .map_err(|e| format!("ouverture de la cible '{}' impossible: {e}", opts.to))?;
        // cible chiffrée : PRAGMA key AVANT tout statement (sinon SQLCipher lit une base illisible).
        #[cfg(feature = "encryption")]
        if opts.encrypt {
            if let Some(k) = resolve_key(opts.key_env.as_deref()) {
                let _ = dst.pragma_update(None, "key", &k);
            }
        }
        let _ = dst.busy_timeout(std::time::Duration::from_secs(5));
        dst.execute_batch(SCHEMA).map_err(|e| format!("SCHEMA sur la cible échoué: {e}"))?;
        migrate(&dst);
    }

    // (5) copie du ledger + de la clé de signature .ed25519 (0600) dans le dossier ledger cible.
    let target_ledger = opts.ledger.clone().unwrap_or_else(|| default_sibling_ledger(&opts.to));
    let (ledger_copied, key_copied) = copy_ledger_and_key(&src_ledger, &target_ledger)?;

    // (6) trace la migration au ledger CIBLE (mutation ledgerisée, chaîne SHA-256 continue). JAMAIS
    // la clé/le secret — seulement les chemins + booléens. Best-effort : une erreur d'écriture du
    // ledger ne défait pas la copie DB déjà réalisée (la migration reste utilisable).
    let detail = json!({
        "actor": opts.actor, "from": opts.from, "source_db": src_db, "target_db": opts.to,
        "encrypted": encrypted, "verified": opts.verify,
        "ledger_copied": ledger_copied, "key_copied": key_copied,
    });
    let migrate_hash = ledger_append_standalone(&target_ledger, "console.migrate", &detail).ok();

    Ok(json!({
        "ok": true,
        "source_db": src_db,
        "target_db": opts.to,
        "target_ledger": target_ledger,
        "encrypted": encrypted,
        "ledger_copied": ledger_copied,
        "key_copied": key_copied,
        "migrate_ledger_hash": migrate_hash,
        "verify": verify_report,
    }))
}

/// Applique la clé SQLCipher AU REPOS au BOOT si `FORGE_DB_KEY` est posé. `PRAGMA key` DOIT précéder
/// toute autre requête sur la connexion (contrat SQLCipher). Compilé UNIQUEMENT avec `encryption` :
/// dans le build par défaut, ce hook n'existe pas et la base reste en clair (inchangé).
#[cfg(feature = "encryption")]
pub(crate) fn apply_db_key_on_boot(conn: &Connection) {
    if let Ok(key) = std::env::var("FORGE_DB_KEY") {
        if !key.is_empty() {
            // la clé est passée telle quelle -> SQLCipher en dérive la clé de chiffrement (KDF).
            let _ = conn.pragma_update(None, "key", &key);
        }
    }
}

/// `forge-console migrate --from <dir|db> --to <db> [--ledger <path>] [--verify]
///                        [--encrypt --key-env <ENVVAR>]`
/// Migre un install Forge existant vers une base cible. UX PRIMAIRE (documentée) : lancée dans un
/// conteneur one-shot au 1er déploiement Docker. Codes : 0 OK, 1 échec migration/vérif, 2 usage.
pub(crate) fn run_migrate_cli(args: &[String]) -> i32 {
    let from = match cli_opt(args, "from") {
        Some(f) if !f.is_empty() => f,
        _ => {
            eprintln!("usage: forge-console migrate --from <dir|db> --to <db> [--ledger <path>] [--verify] [--encrypt --key-env <ENVVAR>]");
            return 2;
        }
    };
    let to = match cli_opt(args, "to") {
        Some(t) if !t.is_empty() => t,
        _ => {
            eprintln!("[forge-console] migrate: --to <db> requis");
            return 2;
        }
    };
    let encrypt = cli_flag(args, "encrypt");
    let key_env = cli_opt(args, "key-env");
    if encrypt && !cfg!(feature = "encryption") {
        eprintln!("[forge-console] migrate: --encrypt demandé mais ce build n'inclut PAS le chiffrement au repos (recompiler avec `--features encryption`)");
        return 2;
    }
    if encrypt && key_env.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
        eprintln!("[forge-console] migrate: --encrypt exige --key-env <ENVVAR> (nom de la variable d'ENV portant la clé)");
        return 2;
    }
    let opts = MigrateOpts {
        from,
        to,
        ledger: cli_opt(args, "ledger"),
        verify: cli_flag(args, "verify"),
        encrypt,
        key_env,
        actor: "cli:migrate".to_string(),
    };
    match run_migration(&opts) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into()));
            if let Some(v) = report.get("verify").filter(|v| !v.is_null()) {
                println!(
                    "[forge-console] migrate: ledger source vérifié — ok={}, entries={}",
                    v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
                    v.get("entries").and_then(|x| x.as_u64()).unwrap_or(0)
                );
            }
            println!(
                "[forge-console] migrate: OK — {} -> {} (ledger cible: {})",
                report.get("source_db").and_then(|x| x.as_str()).unwrap_or(""),
                opts.to,
                report.get("target_ledger").and_then(|x| x.as_str()).unwrap_or("")
            );
            0
        }
        Err(e) => {
            eprintln!("[forge-console] migrate: {e}");
            1
        }
    }
}

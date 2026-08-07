// SPDX-License-Identifier: AGPL-3.0-or-later
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

/// Résout (source_db, source_ledger) depuis `--from`. Un DOSSIER -> {dir}/forge.db +
/// {dir}/engagement.jsonl (convention d'install). Un FICHIER -> le fichier .db + son sibling
/// engagement.jsonl (même dossier). Aucune invention : si le ledger n'existe pas, la copie le note.
pub(crate) fn resolve_migrate_source(from: &str) -> (String, String) {
    let p = std::path::Path::new(from);
    if p.is_dir() {
        let db = p.join("forge.db");
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
/// (défaut `forge.db`) => `.` (cwd de la console). N'affecte QUE la frontière API.
pub(crate) fn api_migrate_base_dir() -> std::path::PathBuf {
    if let Some(d) = std::env::var("FORGE_CONSOLE_IMPORT_DIR").ok().filter(|s| !s.is_empty()) {
        return std::path::PathBuf::from(d);
    }
    let db = std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge.db".to_string());
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
/// SHA-256, alg "sha256-console", sig ""). AUTONOME (pas d'App/cache). Miroir strict de
/// append_console_ledger côté pré-image, donc /api/ledger/verify recompute la chaîne SANS rupture.
/// Renvoie le hash de la nouvelle entrée. B1 — DÉLÈGUE à `append_sha256_console_locked` : la relecture
/// de la queue ET l'écriture se font SOUS un `fcntl.flock` cross-processus (le MÊME verrou que
/// forge/ledger.py), si bien qu'un ledger dédié écrit CONCURREMMENT par le moteur Python (spawné avec
/// `--ledger <ce fichier>`) ne peut plus forker la chaîne (la queue est relue sous le verrou, pas via
/// un état pré-verrou -> plus de TOCTOU lecture-queue/écriture).
pub(crate) fn ledger_append_standalone(path: &str, kind: &str, detail: &Value) -> Result<String, String> {
    let (_prev, _seq, hash) = crate::append_sha256_console_locked(path, kind, detail)?;
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

/// Encode un chemin de fichier en URI SQLite LECTURE SEULE (`file:…?mode=ro`). Le chemin est d'abord
/// canonicalisé (absolu, sans `..` ni double slash de tête qui serait lu comme une AUTORITÉ d'URI),
/// puis les trois caractères réservés de la syntaxe URI SQLite sont percent-encodés : `%` (l'échappement
/// lui-même), `?` (début de query) et `#` (début de fragment) — sans quoi un chemin contenant `?`
/// verrait sa fin interprétée comme des paramètres. Compilé UNIQUEMENT avec `encryption`.
#[cfg(feature = "encryption")]
pub(crate) fn sqlite_uri_ro(path: &str) -> String {
    let abs = std::path::Path::new(path)
        .canonicalize()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string());
    let mut out = String::with_capacity(abs.len() + 16);
    out.push_str("file:");
    for ch in abs.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '?' => out.push_str("%3f"),
            '#' => out.push_str("%23"),
            c => out.push(c),
        }
    }
    out.push_str("?mode=ro");
    out
}

/// plaintext -> CHIFFRÉ : exporte la base source vers une cible SQLCipher via sqlcipher_export().
/// Compilé UNIQUEMENT avec la feature `encryption`.
///
/// ⚠️ SENS DE L'EXPORT — la CIBLE CHIFFRÉE est `main` (ouverte RW+CREATE, `PRAGMA key` en premier),
/// et la source plaintext est ATTACHÉE en lecture seule. L'inverse (attacher la cible depuis la
/// connexion source, ce que faisait la version initiale) est IMPOSSIBLE PAR CONSTRUCTION : `run_migration`
/// ouvre la source avec SQLITE_OPEN_READ_ONLY et SQLite propage `db->openFlags` aux bases ATTACHÉES
/// (attach.c : `flags = db->openFlags`). La cible héritait donc de READONLY *sans* CREATE ->
/// `unable to open database` sur un fichier neuf, et « attempt to write a readonly database » même sur
/// un fichier pré-créé. L'URI `?mode=rwc` ne rattrape rien : SQLite REFUSE toute remontée de privilège
/// d'une base attachée (`access mode not allowed: rwc`, SQLITE_PERM). Ce chemin `--encrypt` n'a donc
/// JAMAIS pu produire de cible, sur AUCUN hôte, SQLCipher présent ou non.
///
/// L'invariant « la source n'est jamais mutée » est PRÉSERVÉ : elle est attachée via `file:…?mode=ro`
/// (SQLite n'autorise que la RÉTROGRADATION d'accès, jamais l'inverse) — la migration fonctionne même
/// si le dossier de l'install source est en 0500. `KEY ''` est OBLIGATOIRE sur cet ATTACH : sans lui,
/// SQLCipher appliquerait la clé de `main` à la source et la lirait comme une base chiffrée.
#[cfg(feature = "encryption")]
pub(crate) fn migrate_copy_encrypted(src_db: &str, target: &str, key_env: Option<&str>) -> Result<bool, String> {
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
    let dst = Connection::open_with_flags(
        target,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("ouverture de la cible chiffrée '{target}' impossible: {e}"))?;
    // PRAGMA key AVANT tout autre statement (contrat SQLCipher).
    dst.pragma_update(None, "key", &key)
        .map_err(|e| format!("PRAGMA key sur la cible chiffrée échoué: {e}"))?;
    dst.execute("ATTACH DATABASE ?1 AS plaintext KEY ''", rusqlite::params![sqlite_uri_ro(src_db)])
        .map_err(|e| format!("ATTACH read-only de la source plaintext échoué: {e}"))?;
    // sqlcipher_export(cible, source) : copie LOGIQUE intégrale plaintext -> chiffré.
    let export = dst.query_row("SELECT sqlcipher_export('main', 'plaintext')", [], |_| Ok(()));
    let _ = dst.execute("DETACH DATABASE plaintext", []);
    export.map_err(|e| format!("sqlcipher_export('main', 'plaintext') échoué: {e}"))?;
    Ok(true)
}

/// Build PAR DÉFAUT (sans `encryption`) : le chiffrement au repos n'est PAS compilé -> erreur CLAIRE
/// (recompiler avec `--features encryption`). Aucune dépendance SQLCipher n'est tirée par ce chemin.
#[cfg(not(feature = "encryption"))]
pub(crate) fn migrate_copy_encrypted(_src_db: &str, _target: &str, _key_env: Option<&str>) -> Result<bool, String> {
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

    // (3) copie de la base. Chemin CHIFFRÉ : la cible est `main` et la source est ATTACHÉE en
    // lecture seule (cf. migrate_copy_encrypted) — on lui passe donc le CHEMIN source, pas la
    // connexion read-only : une base attachée hérite des openFlags de `main` et serait, depuis
    // `src`, en READONLY sans CREATE (impossible à créer/écrire).
    let encrypted = if opts.encrypt {
        migrate_copy_encrypted(&src_db, &opts.to, opts.key_env.as_deref())?
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
    // FORGE_DB_KEY with a `*_FILE` fallback (Docker/k8s secret): the key can live in a mounted,
    // root-owned file instead of a plaintext env beside the app. Absent/empty => base stays clear
    // (unchanged). `secret_from_env` never returns an empty string, but keep the guard for clarity.
    if let Some(key) = crate::secret_from_env("FORGE_DB_KEY") {
        if !key.is_empty() {
            // la clé est passée telle quelle -> SQLCipher en dérive la clé de chiffrement (KDF).
            let _ = conn.pragma_update(None, "key", &key);
        }
    }
}

/// `forge migrate --from <dir|db> --to <db> [--ledger <path>] [--verify]
///                        [--encrypt --key-env <ENVVAR>]`
/// Migre un install Forge existant vers une base cible. UX PRIMAIRE (documentée) : lancée dans un
/// conteneur one-shot au 1er déploiement Docker. Codes : 0 OK, 1 échec migration/vérif, 2 usage.
pub(crate) fn run_migrate_cli(args: &[String]) -> i32 {
    let from = match cli_opt(args, "from") {
        Some(f) if !f.is_empty() => f,
        _ => {
            eprintln!("usage: forge migrate --from <dir|db> --to <db> [--ledger <path>] [--verify] [--encrypt --key-env <ENVVAR>]");
            return 2;
        }
    };
    let to = match cli_opt(args, "to") {
        Some(t) if !t.is_empty() => t,
        _ => {
            eprintln!("[forge] migrate: --to <db> requis");
            return 2;
        }
    };
    let encrypt = cli_flag(args, "encrypt");
    let key_env = cli_opt(args, "key-env");
    if encrypt && !cfg!(feature = "encryption") {
        eprintln!("[forge] migrate: --encrypt demandé mais ce build n'inclut PAS le chiffrement au repos (recompiler avec `--features encryption`)");
        return 2;
    }
    if encrypt && key_env.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
        eprintln!("[forge] migrate: --encrypt exige --key-env <ENVVAR> (nom de la variable d'ENV portant la clé)");
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
                    "[forge] migrate: ledger source vérifié — ok={}, entries={}",
                    v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
                    v.get("entries").and_then(|x| x.as_u64()).unwrap_or(0)
                );
            }
            println!(
                "[forge] migrate: OK — {} -> {} (ledger cible: {})",
                report.get("source_db").and_then(|x| x.as_str()).unwrap_or(""),
                opts.to,
                report.get("target_ledger").and_then(|x| x.as_str()).unwrap_or("")
            );
            0
        }
        Err(e) => {
            eprintln!("[forge] migrate: {e}");
            1
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    /// [MIGRATION plaintext] copie COHÉRENTE (VACUUM INTO) + upgrade EN PLACE : la cible reçoit les
    /// colonnes additives (cwe) et les tables neuves (settings) via SCHEMA+migrate(), la donnée
    /// source survit, le ledger + la clé voyagent, et le ledger cible reste VÉRIFIABLE (chaîne
    /// SHA-256 continue avec l'entrée `console.migrate`).
    #[test]
    fn migrate_plaintext_copies_and_upgrades_schema() {
        let src_dir = tmp_dir("forge-mig-src");
        let src_db = format!("{src_dir}/forge.db");
        seed_old_source_db(&src_db);
        // ledger source (2 entrées chaînées) + clé de signature .ed25519.
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        ledger_append_standalone(&src_ledger, "engagement.start", &json!({"a": 1})).unwrap();
        ledger_append_standalone(&src_ledger, "action.recon", &json!({"a": 2})).unwrap();
        std::fs::write(format!("{src_ledger}.ed25519"), b"fake-ed25519-key-32-bytes-xxxxxx").unwrap();

        let to = tmp_path("forge-mig-to.db");
        let target_ledger = tmp_path("forge-mig-to.jsonl");
        let opts = MigrateOpts {
            from: src_dir.clone(),
            to: to.clone(),
            ledger: Some(target_ledger.clone()),
            verify: true,
            encrypt: false,
            key_env: None,
            actor: "test".to_string(),
        };
        let report = run_migration(&opts).expect("migration doit réussir");
        assert_eq!(report["ok"], true);
        assert_eq!(report["encrypted"], false, "build par défaut -> copie en clair");
        assert_eq!(report["verify"]["ok"], true, "ledger source intact -> verify ok");

        // 1) schéma UPGRADÉ en place : colonne additive `cwe` présente, donnée source préservée.
        let dst = Connection::open(&to).expect("open target");
        let cwe: String = dst
            .query_row("SELECT cwe FROM finding WHERE id=1", [], |r| r.get(0))
            .expect("colonne cwe ajoutée par migrate()");
        assert_eq!(cwe, "", "cwe = DEFAULT '' sur une ligne migrée");
        let title: String = dst.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding", "la donnée source survit à la copie");
        // 2) table neuve `settings` créée par SCHEMA sur la cible ET TAMPONNÉE par migrate() : la source
        //    ancienne n'avait ni la table ni de réglage, donc la cible contient UNIQUEMENT le stamp
        //    `schema_version` (== SCHEMA_VERSION) posé par migrate() après les ALTER additifs.
        let n: i64 = dst.query_row("SELECT count(*) FROM settings", [], |r| r.get(0)).expect("table settings créée");
        assert_eq!(n, 1, "seul le stamp schema_version est présent après migrate()");
        let sv: String = dst
            .query_row("SELECT value FROM settings WHERE key='schema_version'", [], |r| r.get(0))
            .expect("schema_version tamponnée par migrate()");
        assert_eq!(sv, crate::schema::SCHEMA_VERSION.to_string(), "stamp == SCHEMA_VERSION");

        // 3) ledger + clé copiés ; ledger cible VÉRIFIABLE (2 source + 1 console.migrate = 3, intègre).
        assert_eq!(report["ledger_copied"], true);
        assert_eq!(report["key_copied"], true);
        assert!(std::path::Path::new(&format!("{target_ledger}.ed25519")).exists(), "clé .ed25519 copiée");
        let v = verify_ledger_chain(&target_ledger);
        assert!(v.ok, "ledger cible doit rester intègre après l'append console.migrate");
        assert_eq!(v.entries, 3, "2 entrées source + 1 entrée de migration");
        let last = read_ledger_lines(&target_ledger).pop().unwrap();
        assert_eq!(last["kind"], "console.migrate", "la migration est tracée au ledger cible");
        assert_eq!(last["detail"]["encrypted"], false);

        drop(dst);
        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::remove_file(&target_ledger);
        let _ = std::fs::remove_file(format!("{target_ledger}.ed25519"));
    }

    /// [MIGRATION --verify] passe sur un ledger INTACT et ABORTE (aucune écriture cible) sur un ledger
    /// ALTÉRÉ (une entrée tamperée casse le recompute de hash).
    #[test]
    fn migrate_verify_passes_intact_aborts_on_tamper() {
        // --- cas INTACT : verify ok, migration réussit. ---
        let src_dir = tmp_dir("forge-mig-verify-ok");
        let src_db = format!("{src_dir}/forge.db");
        seed_old_source_db(&src_db);
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        for i in 0..4 {
            ledger_append_standalone(&src_ledger, "console.test", &json!({"i": i, "msg": "événement"})).unwrap();
        }
        let to_ok = tmp_path("forge-mig-verify-ok-to.db");
        let led_ok = tmp_path("forge-mig-verify-ok-to.jsonl");
        let ok_opts = MigrateOpts {
            from: src_dir.clone(), to: to_ok.clone(), ledger: Some(led_ok.clone()),
            verify: true, encrypt: false, key_env: None, actor: "test".to_string(),
        };
        let r = run_migration(&ok_opts).expect("ledger intact -> migration réussit");
        assert_eq!(r["verify"]["ok"], true);
        assert!(std::path::Path::new(&to_ok).exists(), "cible écrite quand le ledger est intact");

        // --- cas ALTÉRÉ : on tampere une entrée -> verify échoue -> ABORT avant toute écriture. ---
        let src_dir2 = tmp_dir("forge-mig-verify-tamper");
        let src_db2 = format!("{src_dir2}/forge.db");
        seed_old_source_db(&src_db2);
        let src_ledger2 = format!("{src_dir2}/engagement.jsonl");
        for i in 0..4 {
            ledger_append_standalone(&src_ledger2, "console.test", &json!({"i": i, "msg": "événement"})).unwrap();
        }
        // altère le CONTENU d'une entrée sans recalculer son hash -> "hash recalculé != stocké".
        let tampered = std::fs::read_to_string(&src_ledger2).unwrap().replacen("événement", "ALTÉRÉ", 1);
        std::fs::write(&src_ledger2, tampered).unwrap();
        // pré-condition : la vérif détecte bien la rupture.
        let vchk = verify_ledger_chain(&src_ledger2);
        assert!(!vchk.ok && vchk.exists, "le ledger tamperé doit être détecté comme rompu");

        let to_bad = tmp_path("forge-mig-verify-tamper-to.db");
        let bad_opts = MigrateOpts {
            from: src_dir2.clone(), to: to_bad.clone(), ledger: Some(tmp_path("forge-mig-tamper-to.jsonl")),
            verify: true, encrypt: false, key_env: None, actor: "test".to_string(),
        };
        let err = run_migration(&bad_opts).expect_err("ledger rompu -> migration AVORTÉE");
        assert!(err.contains("AVORTÉE"), "message d'abort explicite: {err}");
        assert!(!std::path::Path::new(&to_bad).exists(), "AUCUNE écriture cible sur abort (verify avant copie)");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&src_dir2);
        let _ = std::fs::remove_file(&to_ok);
        let _ = std::fs::remove_file(&led_ok);
        let _ = std::fs::remove_file(format!("{led_ok}.ed25519"));
    }

    /// [MIGRATION clé] la clé de signature `.ed25519` voyage AVEC le ledger, en mode 0600 FORCÉ
    /// (même si la source est plus permissive) — sinon la chaîne signée devient invérifiable.
    #[cfg(unix)]
    #[test]
    fn migrate_copies_ed25519_key_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let src_dir = tmp_dir("forge-mig-key");
        let src_db = format!("{src_dir}/forge.db");
        seed_old_source_db(&src_db);
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        ledger_append_standalone(&src_ledger, "engagement.start", &json!({"a": 1})).unwrap();
        // clé source DÉLIBÉRÉMENT en 0644 -> prouve que la copie FORCE 0600 (pas un simple héritage).
        let src_key = format!("{src_ledger}.ed25519");
        std::fs::write(&src_key, b"raw-ed25519-private-key-32-bytes").unwrap();
        std::fs::set_permissions(&src_key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let to = tmp_path("forge-mig-key-to.db");
        let target_ledger = tmp_path("forge-mig-key-to.jsonl");
        let opts = MigrateOpts {
            from: src_dir.clone(), to: to.clone(), ledger: Some(target_ledger.clone()),
            verify: false, encrypt: false, key_env: None, actor: "test".to_string(),
        };
        run_migration(&opts).expect("migration ok");

        let dst_key = format!("{target_ledger}.ed25519");
        assert!(std::path::Path::new(&dst_key).exists(), "clé .ed25519 copiée dans le dossier ledger cible");
        let mode = std::fs::metadata(&dst_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "la clé doit être 0600 (secret de signature)");
        // contenu identique (la clé est le même secret).
        assert_eq!(std::fs::read(&dst_key).unwrap(), b"raw-ed25519-private-key-32-bytes");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::remove_file(&target_ledger);
        let _ = std::fs::remove_file(&dst_key);
    }

    /// [MIGRATION chiffrement — build par défaut] `--encrypt` sans la feature `encryption` renvoie une
    /// ERREUR CLAIRE (jamais un faux succès en clair). Ce test n'existe QUE dans le build par défaut.
    #[cfg(not(feature = "encryption"))]
    #[test]
    fn migrate_encrypt_without_feature_errors_clearly() {
        let src_dir = tmp_dir("forge-mig-noenc");
        let src_db = format!("{src_dir}/forge.db");
        seed_old_source_db(&src_db);
        let opts = MigrateOpts {
            from: src_dir.clone(), to: tmp_path("forge-mig-noenc-to.db"), ledger: None,
            verify: false, encrypt: true, key_env: Some("FORGE_TEST_KEY".to_string()), actor: "test".to_string(),
        };
        let err = run_migration(&opts).expect_err("encrypt sans feature -> erreur");
        assert!(err.contains("NON compilé") || err.contains("features encryption"),
            "message doit dire que le chiffrement n'est pas compilé: {err}");
        let _ = std::fs::remove_dir_all(&src_dir);
    }

    /// Écrit un message VISIBLE dans la sortie de `cargo test` MÊME SANS `--nocapture` : libtest
    /// n'intercepte que les macros `print!`/`eprint!` (via `io::set_output_capture`), jamais les
    /// écritures DIRECTES sur le handle global. Un test sauté DOIT se voir : un saut silencieux fait
    /// croire à une couverture qui n'existe pas — c'est pire qu'un rouge.
    #[cfg(feature = "encryption")]
    fn announce(msg: &str) {
        use std::io::Write;
        let mut err = std::io::stderr();
        let _ = writeln!(err, "{msg}");
        let _ = err.flush();
    }

    /// CAPACITÉ RÉELLE de chiffrement au repos DU BINAIRE COURANT — pas la présence d'un fichier ni
    /// d'une variable d'ENV : on ouvre une base, on pose une clé, on écrit, et on VÉRIFIE qu'elle est
    /// illisible sans la clé et lisible avec. Seule la capacité observée prédit l'échec.
    ///
    /// (`ldconfig | grep sqlcipher` ne prédit RIEN : `rusqlite/bundled-sqlcipher` COMPILE l'amalgame
    /// SQLCipher DANS le binaire — il n'existe aucun `libsqlcipher.so` à trouver. Le cas que cette
    /// sonde couvre réellement est l'inverse : un build qui compile sous la feature mais que
    /// `SQLITE3_LIB_DIR`/pkg-config ont lié à un SQLite système SANS codec.)
    ///
    /// `Ok(version)` si la capacité est là ; `Err(pourquoi)` sinon.
    #[cfg(feature = "encryption")]
    fn sqlcipher_capability() -> Result<String, String> {
        let dir = tmp_dir("forge-sqlcipher-capability");
        let probe = format!("{dir}/capability.db");
        let verdict = (|| -> Result<String, String> {
            let c = Connection::open(&probe).map_err(|e| format!("ouverture de la sonde impossible: {e}"))?;
            let version: String = c.query_row("PRAGMA cipher_version", [], |r| r.get(0)).map_err(|e| {
                format!("`PRAGMA cipher_version` ne rend rien ({e}) — ce binaire n'embarque aucun codec SQLCipher")
            })?;
            c.pragma_update(None, "key", "capability-probe-key")
                .map_err(|e| format!("`PRAGMA key` refusé: {e}"))?;
            c.execute_batch("CREATE TABLE t(a); INSERT INTO t VALUES(1);")
                .map_err(|e| format!("écriture dans une base chiffrée impossible: {e}"))?;
            drop(c);
            let plain = Connection::open(&probe).map_err(|e| format!("réouverture impossible: {e}"))?;
            if plain.query_row("SELECT count(*) FROM t", [], |r| r.get::<_, i64>(0)).is_ok() {
                return Err("la base sonde reste lisible SANS clé — le codec ne chiffre rien".to_string());
            }
            drop(plain);
            let keyed = Connection::open(&probe).map_err(|e| format!("réouverture impossible: {e}"))?;
            keyed.pragma_update(None, "key", "capability-probe-key")
                .map_err(|e| format!("`PRAGMA key` refusé à la relecture: {e}"))?;
            keyed.query_row("SELECT count(*) FROM t", [], |r| r.get::<_, i64>(0))
                .map_err(|e| format!("relecture AVEC la clé impossible: {e}"))?;
            Ok(version)
        })();
        let _ = std::fs::remove_dir_all(&dir);
        verdict
    }

    /// [MIGRATION chiffrement — build chiffré] plaintext -> SQLCipher -> relecture avec la clé. GARDÉ
    /// derrière `#[cfg(feature="encryption")]` : SKIP (non compilé) dans la suite par défaut, pour ne
    /// PAS faire dépendre celle-ci de SQLCipher/openssl. Exécuté seulement via `--features encryption`.
    ///
    /// GARDE D'HÔTE : sous la feature, on sonde la CAPACITÉ RÉELLE (`sqlcipher_capability`) avant de
    /// tester. Capacité absente -> le test s'ANNONCE sauté, avec la raison, sur la sortie non capturée
    /// (jamais un vert silencieux). Capacité présente -> il s'exécute INTÉGRALEMENT, l'annonce le dit,
    /// et aucune défaillance n'est avalée.
    #[cfg(feature = "encryption")]
    #[test]
    fn migrate_encrypted_roundtrip_reads_back_with_key() {
        match sqlcipher_capability() {
            Ok(v) => announce(&format!(
                "[dbmigrate] SQLCipher DISPONIBLE ({v}) — migrate_encrypted_roundtrip_reads_back_with_key EXÉCUTÉ intégralement"
            )),
            Err(why) => {
                announce(&format!(
                    "[dbmigrate] SKIP migrate_encrypted_roundtrip_reads_back_with_key — SQLCipher indisponible sur cet hôte : {why}"
                ));
                return;
            }
        }
        let src_dir = tmp_dir("forge-mig-enc");
        let src_db = format!("{src_dir}/forge.db");
        seed_old_source_db(&src_db);
        let to = tmp_path("forge-mig-enc-to.db");
        std::env::set_var("FORGE_TEST_ENC_KEY", "correct horse battery staple");
        let opts = MigrateOpts {
            from: src_dir.clone(), to: to.clone(), ledger: Some(tmp_path("forge-mig-enc-to.jsonl")),
            verify: false, encrypt: true, key_env: Some("FORGE_TEST_ENC_KEY".to_string()), actor: "test".to_string(),
        };
        let report = run_migration(&opts).expect("migration chiffrée doit réussir");
        assert_eq!(report["encrypted"], true);

        // relecture AVEC la bonne clé -> lisible ; la donnée source a survécu.
        let dst = Connection::open(&to).unwrap();
        dst.pragma_update(None, "key", "correct horse battery staple").unwrap();
        let title: String = dst.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding");

        // relecture SANS clé -> illisible (preuve que la base est bien chiffrée au repos).
        let bad = Connection::open(&to).unwrap();
        assert!(bad.query_row("SELECT count(*) FROM finding", [], |r| r.get::<_, i64>(0)).is_err(),
            "sans PRAGMA key, une base chiffrée est illisible");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&to);
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! `forge-console upgrade` — flux d'UPGRADE SÛR EN UNE COMMANDE, fail-closed avec rollback.
// ===========================================================================================
// `forge-console upgrade --passphrase-env <ENV> [--db <path>] [--ledger <path>] [--backup-dir <dir>]
//   [--to <postgres-url>] [--force] [--dry-run]`
//
// SÉQUENCE FAIL-CLOSED (jamais de base à moitié migrée) :
//   a. SNAPSHOT PRÉ-UPGRADE CHIFFRÉ (réutilise le moteur backup audité : argon2id + XChaCha20-Poly1305,
//      chaîne ledger vérifiée, fsync'd) taggé `pre-upgrade-<schema_version>-<epoch>.forge`. ABORT si le
//      backup OU sa re-vérification (déchiffrement + sha256 + hash-chain via backup_inspect) échoue :
//      on NE MIGRE JAMAIS sans un instantané bon (fail-closed).
//   b. MIGRATE additif (SCHEMA + migrate() -> tamponne schema_version) ; si `--to` est fourni, MIGRATION
//      DE STORE gouvernée SQLite -> Postgres (migrate-store : ordre FK, vérif des comptes, checkpoint signé).
//   c. VÉRIF : self-check de schéma (colonnes attendues présentes + schema_version == cible) + `ledger
//      verify` (hash-chain) + (store) la vérif des comptes de migrate-store.
//   d. SELF-CHECK SANTÉ : la base répond (SELECT 1) + tête de ledger cohérente (comme /health).
//   e. Sur TOUT échec en b–d : RESTORE depuis le snapshot pré-upgrade (retour à l'état EXACT d'avant) +
//      exit NON-ZÉRO avec message clair. Sur succès : schema_version tamponnée + ledger `console.upgrade`.
//
//   IDEMPOTENT : re-lancer alors que la base est DÉJÀ à la version cible = no-op succès (on saute le
//   migrate additif mais on VÉRIFIE quand même). `--dry-run` : montre le plan (backup + migration prévue)
//   sans RIEN muter.
//
// SECRETS : passphrase (backup) via ENV, URL Postgres via seam RÉDIGÉ — jamais en argv/log/ledger.
// ===========================================================================================
use crate::*;
use rusqlite::Connection;
use serde_json::{json, Value};

/// Options du flux d'upgrade (partagées CLI/cœur — le cœur est testable sans process réel).
pub(crate) struct UpgradeOpts {
    pub(crate) db: String,                  // base SQLite source/cible
    pub(crate) ledger: String,              // ledger source/cible
    pub(crate) passphrase: String,          // passphrase du snapshot (déjà lue depuis l'ENV — jamais argv)
    pub(crate) backup_dir: String,          // dossier où écrire le snapshot pré-upgrade
    pub(crate) to: Option<String>,          // URL Postgres cible (migration de store — feature-gated)
    pub(crate) force: bool,                 // --force propagé à migrate-store (écrase une cible non vide)
    pub(crate) dry_run: bool,               // n'écrit RIEN — montre seulement le plan
    pub(crate) actor: String,               // attribution ledger
    // HOOK TEST/CHAOS : force l'ÉTAPE DE VÉRIF (après migrate) à échouer, pour exercer le rollback.
    // Toujours `None` depuis le CLI réel ; seul un test/chaos-drill le pose. Modélise « une vérif a échoué ».
    pub(crate) simulate_failure: Option<String>,
}

/// Colonnes attendues par table APRÈS `migrate()` (self-check de schéma). Si une seule manque, l'upgrade
/// est considéré ÉCHOUÉ (et rollback). Sous-ensemble REPRÉSENTATIF des ALTER additifs de `migrate()`.
const EXPECTED_COLUMNS: &[(&str, &[&str])] = &[
    ("finding", &["run_id", "fix", "cwe", "cvss_vector", "cvss_score", "classification", "assignee", "triage", "engagement_id"]),
    ("runrecord", &["run_id", "engagement_id"]),
    ("run_job", &["pid", "started_by", "reason", "targets", "modules", "started", "finished", "exit_code", "engagement_id", "owner_instance", "spawn_spec"]),
    ("panel", &["descr", "col_span", "updated", "dashboard_id"]),
    ("module", &["enabled", "available_override"]),
    ("engagement", &["tenant_id"]),
];

/// Tables attendues APRÈS `migrate()` (créées par SCHEMA et/ou les CREATE IF NOT EXISTS de migrate()).
const EXPECTED_TABLES: &[&str] = &[
    "settings", "engagement", "finding_template", "tenant", "tenant_grant",
    "engagement_grant", "saved_view", "leader_lease", "ha_instance", "presence",
];

/// Self-check de schéma sur une connexion SQLite : chaque colonne de `EXPECTED_COLUMNS` et chaque table de
/// `EXPECTED_TABLES` DOIT exister, ET `schema_version` doit valoir la cible. Renvoie la liste des manques
/// (Err) ou `Ok(())`. Lecture seule (PRAGMA table_info + sqlite_master).
fn schema_self_check(conn: &Connection) -> Result<(), String> {
    let mut missing: Vec<String> = Vec::new();
    // tables
    for t in EXPECTED_TABLES {
        let n: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", [t], |r| r.get(0))
            .unwrap_or(0);
        if n == 0 {
            missing.push(format!("table:{t}"));
        }
    }
    // colonnes
    for (table, cols) in EXPECTED_COLUMNS {
        let present: std::collections::HashSet<String> = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .and_then(|mut s| {
                s.query_map([], |r| r.get::<_, String>(1)).map(|rows| rows.filter_map(|x| x.ok()).collect())
            })
            .unwrap_or_default();
        for c in *cols {
            if !present.contains(*c) {
                missing.push(format!("{table}.{c}"));
            }
        }
    }
    // version
    match read_schema_version_conn(conn) {
        Some(v) if v == crate::schema::SCHEMA_VERSION => {}
        Some(v) => missing.push(format!("schema_version={v} (attendu {})", crate::schema::SCHEMA_VERSION)),
        None => missing.push("schema_version=absente".to_string()),
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("self-check de schéma : {} élément(s) manquant(s)/incohérent(s) : {}", missing.len(), missing.join(", ")))
    }
}

/// Self-check de SANTÉ (comme /health) : la base répond `SELECT 1` ET la tête du ledger est cohérente
/// (chaîne intègre OU ledger absent/vide — jamais une chaîne rompue). Err lisible sinon.
fn health_self_check(db: &str, ledger: &str) -> Result<(), String> {
    let conn = Connection::open_with_flags(
        db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("santé : ouverture read-only de '{db}' impossible: {e}"))?;
    let one: i64 = conn
        .query_row("SELECT 1", [], |r| r.get(0))
        .map_err(|e| format!("santé : SELECT 1 a échoué: {e}"))?;
    if one != 1 {
        return Err("santé : SELECT 1 n'a pas renvoyé 1".to_string());
    }
    let lv = verify_ledger_chain(ledger);
    if lv.exists && !lv.ok {
        return Err(format!("santé : chaîne ledger rompue (seq={}) : {}", lv.broken, lv.why.unwrap_or_default()));
    }
    Ok(())
}

/// Applique la migration additive SQLite EN PLACE : SCHEMA (idempotent) + migrate() (ALTER additifs +
/// stamp schema_version). Ouvre sa PROPRE connexion RW et la DROP en sortie (le fichier peut ensuite être
/// écrasé par un rollback). Ne touche JAMAIS le ledger. Err si l'ouverture/DDL échoue.
fn apply_sqlite_migrate(db: &str) -> Result<(), String> {
    let conn = Connection::open(db).map_err(|e| format!("ouverture RW de '{db}' impossible: {e}"))?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    conn.execute_batch(crate::SCHEMA).map_err(|e| format!("application de SCHEMA échouée: {e}"))?;
    crate::migrate(&conn); // ALTER additifs error-ignored + stamp schema_version
    Ok(())
}

/// Migration de STORE gouvernée SQLite -> Postgres via `migrate-store` (feature `store-postgres`). Renvoie
/// Err si le migrateur sort non-zéro (refus de gouvernance, comptes discordants -> rollback, connexion…).
/// Le migrateur émet son PROPRE checkpoint signé `console.store.migrate` (audit). Hors feature : Err claire.
fn apply_store_migration(db: &str, ledger: &str, to_url: &str, force: bool) -> Result<(), String> {
    #[cfg(feature = "store-postgres")]
    {
        let mut sargs: Vec<String> = vec![
            "--to".into(), to_url.to_string(),
            "--from".into(), db.to_string(),
            "--ledger".into(), ledger.to_string(),
        ];
        if force {
            sargs.push("--force".into());
        }
        let code = crate::cli::run_migrate_store_cli(&sargs);
        if code == 0 {
            Ok(())
        } else {
            Err(format!("migrate-store a échoué (exit {code}) — voir la sortie ci-dessus"))
        }
    }
    #[cfg(not(feature = "store-postgres"))]
    {
        let _ = (db, ledger, to_url, force);
        Err("migration de store demandée (--to) mais ce binaire n'est pas compilé avec la feature `store-postgres`".to_string())
    }
}

/// CŒUR de l'upgrade (testable sans process réel). Voir l'en-tête du module pour la séquence fail-closed.
/// `Ok(report)` : dry-run OU upgrade réussi (report inclut le plan/les étapes). `Err(msg)` : échec — si un
/// snapshot pré-upgrade avait été pris, la base a été RESTAURÉE à son état d'avant (le message le précise).
pub(crate) fn run_upgrade_core(opts: &UpgradeOpts) -> Result<Value, String> {
    // Version AVANT (base courante) vs cible (compilée dans ce binaire).
    let current_version: Option<i64> = {
        match Connection::open_with_flags(
            &opts.db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        ) {
            Ok(c) => read_schema_version_conn(&c),
            Err(_) => None, // base neuve/absente -> None (le migrate la créera)
        }
    };
    let target = crate::schema::SCHEMA_VERSION;
    let same_version = current_version == Some(target);

    // --- DRY-RUN : montre le plan, ne mute RIEN (pas de backup écrit, pas de migrate) ---
    if opts.dry_run {
        return Ok(json!({
            "ok": true,
            "dry_run": true,
            "from": current_version,
            "to": target,
            "already_current": same_version,
            "would_backup_to": format!("{}/pre-upgrade-{}-<epoch>.forge", opts.backup_dir.trim_end_matches('/'), current_version.map(|v| v.to_string()).unwrap_or_else(|| "none".into())),
            "would_migrate": !same_version,
            "would_migrate_store": opts.to.as_ref().map(|u| redact_target(u)),
            "note": "DRY-RUN — aucune écriture. Relancez sans --dry-run pour exécuter (snapshot chiffré -> migrate -> vérif -> rollback si échec).",
        }));
    }

    // --- (a) SNAPSHOT PRÉ-UPGRADE CHIFFRÉ (fail-closed : jamais de migrate sans un bon snapshot) ---
    if opts.passphrase.is_empty() {
        return Err("passphrase absente — le snapshot pré-upgrade est OBLIGATOIRE (fail-closed)".to_string());
    }
    let tag = current_version.map(|v| v.to_string()).unwrap_or_else(|| "none".into());
    let backup_out = format!(
        "{}/pre-upgrade-{}-{}.forge",
        opts.backup_dir.trim_end_matches('/'),
        tag,
        chrono_now_compact()
    );
    let bopts = BackupOpts {
        out: backup_out.clone(),
        passphrase: opts.passphrase.clone(),
        db: opts.db.clone(),
        ledger: Some(opts.ledger.clone()),
        ts: Some(format!("@{}", chrono_now_compact())),
        actor: format!("{}:pre-upgrade", opts.actor),
    };
    // run_backup vérifie DÉJÀ la chaîne ledger AVANT d'écrire (abort si rompue) + fsync l'archive.
    run_backup(&bopts).map_err(|e| format!("snapshot pré-upgrade échoué (AUCUNE migration tentée) : {e}"))?;
    // Re-VÉRIFICATION du snapshot : déchiffrable + sha256 conformes + hash-chain intègre (backup_inspect).
    // Un snapshot invérifiable = on n'a PAS de filet -> ABORT avant toute mutation.
    let sealed = std::fs::read(&backup_out)
        .map_err(|e| format!("relecture du snapshot '{backup_out}' impossible (AUCUNE migration tentée) : {e}"))?;
    let inspect = backup_inspect(&sealed, &opts.passphrase)
        .map_err(|e| format!("snapshot pré-upgrade INVÉRIFIABLE (AUCUNE migration tentée) : {e}"))?;
    let backup_id = sha256_hex_bytes(&sealed);

    // ============ ÉTAPES MUTANTES (b–d) — sur ÉCHEC : RESTORE depuis le snapshot ============
    let mutate = || -> Result<(), String> {
        // (b) MIGRATE additif SQLite (sauf si déjà à la cible : idempotent -> skip mais on vérifie quand même).
        if !same_version {
            apply_sqlite_migrate(&opts.db)?;
        }
        // (b') MIGRATION DE STORE gouvernée si --to (indépendante du bump de version — c'est une copie de données).
        if let Some(url) = &opts.to {
            apply_store_migration(&opts.db, &opts.ledger, url, opts.force)?;
        }
        // HOOK TEST/CHAOS : simule une vérif échouée APRÈS migrate -> exerce le rollback (jamais posé par le CLI).
        if let Some(reason) = &opts.simulate_failure {
            return Err(format!("échec de vérif SIMULÉ (chaos-drill) : {reason}"));
        }
        // (c) VÉRIF de schéma (colonnes + version) + (d) santé (SELECT 1 + tête ledger cohérente).
        {
            let conn = Connection::open_with_flags(
                &opts.db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
            )
            .map_err(|e| format!("vérif : ouverture read-only de '{}' impossible: {e}", opts.db))?;
            schema_self_check(&conn)?;
        }
        health_self_check(&opts.db, &opts.ledger)?;
        // (c') VÉRIF ledger explicite (hash-chain) — redondant avec health mais nommé pour la clarté du rapport.
        let lv = verify_ledger_chain(&opts.ledger);
        if lv.exists && !lv.ok {
            return Err(format!("vérif : chaîne ledger rompue (seq={}) après migration", lv.broken));
        }
        Ok(())
    };

    match mutate() {
        Ok(()) => {
            // SUCCÈS : schema_version déjà tamponnée par migrate() (ou déjà à la cible). Trace `console.upgrade`
            // (métadonnées SEULES — jamais la passphrase/l'URL en clair). backup_id = sha256 du snapshot.
            let detail = json!({
                "actor": opts.actor,
                "from": current_version,
                "to": target,
                "already_current": same_version,
                "backup_id": backup_id,
                "backup": backup_out,
                "store_migration": opts.to.as_ref().map(|u| redact_target(u)),
            });
            let upgrade_hash = ledger_append_standalone(&opts.ledger, "console.upgrade", &detail).ok();
            Ok(json!({
                "ok": true,
                "applied": !same_version || opts.to.is_some(),
                "already_current": same_version,
                "from": current_version,
                "to": target,
                "backup": backup_out,
                "backup_id": backup_id,
                "backup_verified": inspect.get("ok").cloned().unwrap_or(json!(true)),
                "store_migration": opts.to.as_ref().map(|u| redact_target(u)),
                "upgrade_ledger_hash": upgrade_hash,
            }))
        }
        Err(e) => {
            // ÉCHEC en b–d : ROLLBACK depuis le snapshot pré-upgrade -> état EXACT d'avant. `force=true` :
            // le snapshot fait AUTORITÉ (on écrase la base à moitié migrée). run_restore re-vérifie sha256 +
            // hash-chain à la restauration (fail-closed) et trace `console.restore`.
            let ropts = RestoreOpts {
                input: backup_out.clone(),
                passphrase: opts.passphrase.clone(),
                to: Some(opts.db.clone()),
                ledger: Some(opts.ledger.clone()),
                force: true,
                actor: format!("{}:rollback", opts.actor),
            };
            match run_restore(&ropts) {
                Ok(_) => Err(format!(
                    "UPGRADE ÉCHOUÉ : {e}. ROLLBACK EFFECTUÉ — base/ledger restaurés à l'état pré-upgrade depuis '{backup_out}' (snapshot vérifié). Aucune base à moitié migrée."
                )),
                Err(re) => Err(format!(
                    "UPGRADE ÉCHOUÉ : {e}. ⚠️ ROLLBACK AUSSI ÉCHOUÉ : {re}. Le snapshot pré-upgrade chiffré est à '{backup_out}' — restaurez manuellement : `forge-console restore --in '{backup_out}' --passphrase-env <ENV> --to '{}' --ledger '{}' --force`.",
                    opts.db, opts.ledger
                )),
            }
        }
    }
}

/// Rédige une cible de migration de store pour l'audit/rapport (Postgres -> sans credentials ; autre -> tel quel).
fn redact_target(url: &str) -> String {
    #[cfg(feature = "store-postgres")]
    let out = redact_pg_url(url);
    // sans le seam PG, on ne devrait pas recevoir d'URL ; par prudence on ne renvoie que le schéma+hôte.
    #[cfg(not(feature = "store-postgres"))]
    let out = url
        .split_once("://")
        .map(|(s, _)| format!("{s}://<redacted>"))
        .unwrap_or_else(|| "<redacted>".to_string());
    out
}

/// `forge-console upgrade --passphrase-env <ENV> [--db <path>] [--ledger <path>] [--backup-dir <dir>]
///   [--to <postgres-url>] [--force] [--dry-run]`. Codes : 0 = OK (ou dry-run), 1 = échec (rollback effectué
///   si applicable), 2 = usage (passphrase/args).
pub(crate) fn run_upgrade_cli(args: &[String]) -> i32 {
    let dry_run = cli_flag(args, "dry-run");
    let db = cli_opt(args, "db").filter(|s| !s.is_empty()).unwrap_or_else(cli_db_path);
    let ledger = cli_opt(args, "ledger")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("FORGE_CONSOLE_LEDGER").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| default_sibling_ledger(&db));
    // dossier du snapshot : --backup-dir sinon le dossier de la base (sibling), sinon "." .
    let backup_dir = cli_opt(args, "backup-dir").filter(|s| !s.is_empty()).unwrap_or_else(|| {
        std::path::Path::new(&db)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string())
    });

    // passphrase (backup) : lue depuis l'ENV, jamais argv. REQUISE hors dry-run (le snapshot en dépend).
    let passphrase = if dry_run {
        String::new()
    } else {
        let pass_env = match cli_opt(args, "passphrase-env").filter(|s| !s.is_empty()) {
            Some(e) => e,
            None => {
                eprintln!("usage: forge-console upgrade --passphrase-env <ENVVAR> [--db <path>] [--ledger <path>] [--backup-dir <dir>] [--to <postgres-url>] [--force] [--dry-run]");
                eprintln!("  --passphrase-env est REQUIS (hors --dry-run) : le snapshot pré-upgrade chiffré en dépend (passphrase lue depuis cette ENV, jamais en argv).");
                return 2;
            }
        };
        match read_passphrase_env(&pass_env) {
            Some(p) => p,
            None => {
                eprintln!("[forge-console] upgrade: passphrase absente — la variable d'ENV '{pass_env}' est vide ou non définie (fail-closed)");
                return 2;
            }
        }
    };

    let opts = UpgradeOpts {
        db,
        ledger,
        passphrase,
        backup_dir,
        to: cli_opt(args, "to").filter(|s| !s.is_empty()),
        force: cli_flag(args, "force"),
        dry_run,
        actor: "cli:upgrade".to_string(),
        simulate_failure: None,
    };

    match run_upgrade_core(&opts) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into()));
            if opts.dry_run {
                println!("[forge-console] upgrade [DRY-RUN] : plan affiché — aucune écriture.");
            } else if report.get("already_current").and_then(|v| v.as_bool()).unwrap_or(false)
                && opts.to.is_none()
            {
                println!("[forge-console] upgrade : DÉJÀ à la version cible (schema_version={}) — no-op vérifié, aucun changement.", crate::schema::SCHEMA_VERSION);
            } else {
                println!("[forge-console] upgrade : OK — base à schema_version={}, snapshot pré-upgrade conservé, ledger tracé.", crate::schema::SCHEMA_VERSION);
            }
            0
        }
        Err(e) => {
            eprintln!("[forge-console] upgrade: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    /// Base au schéma ANCIEN (finding sans colonnes additives, pas de settings) + une ligne. Réutilise le
    /// helper de test partagé pour rester cohérent avec la suite de migration.
    fn seed_old(db: &str) {
        seed_old_source_db(db);
    }

    fn opts_for(db: &str, ledger: &str, backup_dir: &str) -> UpgradeOpts {
        UpgradeOpts {
            db: db.to_string(),
            ledger: ledger.to_string(),
            passphrase: "test-pass-123".to_string(),
            backup_dir: backup_dir.to_string(),
            to: None,
            force: false,
            dry_run: false,
            actor: "test:upgrade".to_string(),
            simulate_failure: None,
        }
    }

    /// [upgrade happy-path] Sur une base ANCIENNE : snapshot -> migrate -> vérif -> succès. La version est
    /// bumpée (schema_version == cible), les colonnes additives existent, la ligne d'origine est préservée,
    /// un snapshot chiffré est écrit, et le ledger porte une entrée `console.upgrade`.
    #[test]
    fn upgrade_happy_path_bumps_version_and_ledgers() {
        let dir = tmp_dir("forge-upgrade-happy");
        let db = format!("{dir}/console.db");
        let ledger = format!("{dir}/engagement.jsonl");
        let bdir = format!("{dir}/backups");
        std::fs::create_dir_all(&bdir).unwrap();
        seed_old(&db);
        // un ledger valide pré-existant (pour prouver qu'il reste intègre + reçoit console.upgrade).
        ledger_append_standalone(&ledger, "engagement.start", &json!({"a": 1})).unwrap();

        let rep = run_upgrade_core(&opts_for(&db, &ledger, &bdir)).expect("upgrade ok");
        assert_eq!(rep["ok"], json!(true));
        assert_eq!(rep["to"], json!(crate::schema::SCHEMA_VERSION));

        // version tamponnée + colonnes additives + ligne préservée.
        let c = Connection::open(&db).unwrap();
        assert_eq!(read_schema_version_conn(&c), Some(crate::schema::SCHEMA_VERSION));
        let has_triage: i64 = c
            .prepare("PRAGMA table_info(finding)").unwrap()
            .query_map([], |r| r.get::<_, String>(1)).unwrap()
            .filter_map(|x| x.ok()).filter(|n| n == "triage").count() as i64;
        assert_eq!(has_triage, 1, "colonne additive `triage` présente après upgrade");
        let title: String = c.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding", "ligne d'origine préservée");

        // snapshot écrit + entrée console.upgrade au ledger.
        let backups: Vec<_> = std::fs::read_dir(&bdir).unwrap().filter_map(|e| e.ok()).collect();
        assert!(!backups.is_empty(), "au moins un snapshot pré-upgrade écrit");
        let led = std::fs::read_to_string(&ledger).unwrap();
        assert!(led.contains("console.upgrade"), "ledger porte une entrée console.upgrade");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [upgrade FAILURE -> rollback] Une vérif échouée (injectée) APRÈS migrate déclenche le RESTORE : la
    /// base revient à l'état EXACT d'avant (colonnes additives ABSENTES à nouveau), l'appel renvoie Err
    /// (exit non-zéro côté CLI), et AUCUNE entrée console.upgrade n'est écrite (jamais de succès trahi).
    #[test]
    fn upgrade_failure_rolls_back_to_prior_state() {
        let dir = tmp_dir("forge-upgrade-fail");
        let db = format!("{dir}/console.db");
        let ledger = format!("{dir}/engagement.jsonl");
        let bdir = format!("{dir}/backups");
        std::fs::create_dir_all(&bdir).unwrap();
        seed_old(&db);

        let mut o = opts_for(&db, &ledger, &bdir);
        o.simulate_failure = Some("boom".to_string());
        let res = run_upgrade_core(&o);
        assert!(res.is_err(), "vérif échouée -> Err");
        let msg = res.unwrap_err();
        assert!(msg.contains("ROLLBACK EFFECTUÉ"), "rollback effectué : {msg}");

        // la base est RESTAURÉE : la colonne additive `triage` NE doit PAS exister (état pré-migrate).
        let c = Connection::open(&db).unwrap();
        let has_triage = c
            .prepare("PRAGMA table_info(finding)").unwrap()
            .query_map([], |r| r.get::<_, String>(1)).unwrap()
            .filter_map(|x| x.ok()).any(|n| n == "triage");
        assert!(!has_triage, "rollback : colonne `triage` absente (état pré-upgrade restauré)");
        // la ligne d'origine est toujours là (snapshot fidèle).
        let title: String = c.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding");

        // aucune entrée console.upgrade (le succès n'est jamais trahi ; le seed n'avait pas de ledger,
        // et le rollback d'un backup sans ledger n'en crée pas).
        if let Ok(led) = std::fs::read_to_string(&ledger) {
            assert!(!led.contains("console.upgrade"), "aucune entrée console.upgrade sur échec");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [upgrade idempotent] Un 2e upgrade alors que la base est DÉJÀ à la cible = no-op succès : Err jamais,
    /// version inchangée, `already_current=true`.
    #[test]
    fn upgrade_idempotent_second_run_is_noop_success() {
        let dir = tmp_dir("forge-upgrade-idem");
        let db = format!("{dir}/console.db");
        let ledger = format!("{dir}/engagement.jsonl");
        let bdir = format!("{dir}/backups");
        std::fs::create_dir_all(&bdir).unwrap();
        seed_old(&db);

        let _ = run_upgrade_core(&opts_for(&db, &ledger, &bdir)).expect("1er upgrade ok");
        let rep2 = run_upgrade_core(&opts_for(&db, &ledger, &bdir)).expect("2e upgrade (idempotent) ok");
        assert_eq!(rep2["already_current"], json!(true), "2e run : déjà à la cible");
        let c = Connection::open(&db).unwrap();
        assert_eq!(read_schema_version_conn(&c), Some(crate::schema::SCHEMA_VERSION));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [upgrade dry-run] `--dry-run` ne mute RIEN : aucune migration, aucun snapshot écrit, base inchangée.
    #[test]
    fn upgrade_dry_run_mutates_nothing() {
        let dir = tmp_dir("forge-upgrade-dry");
        let db = format!("{dir}/console.db");
        let ledger = format!("{dir}/engagement.jsonl");
        let bdir = format!("{dir}/backups");
        std::fs::create_dir_all(&bdir).unwrap();
        seed_old(&db);
        let before = std::fs::read(&db).unwrap();

        let mut o = opts_for(&db, &ledger, &bdir);
        o.dry_run = true;
        o.passphrase = String::new(); // dry-run n'exige pas de passphrase
        let rep = run_upgrade_core(&o).expect("dry-run ok");
        assert_eq!(rep["dry_run"], json!(true));
        assert_eq!(rep["would_migrate"], json!(true), "base ancienne -> migration prévue");

        // fichier base INCHANGÉ octet pour octet + aucun snapshot écrit.
        let after = std::fs::read(&db).unwrap();
        assert_eq!(before, after, "dry-run : base non mutée");
        let backups: Vec<_> = std::fs::read_dir(&bdir).unwrap().filter_map(|e| e.ok()).collect();
        assert!(backups.is_empty(), "dry-run : aucun snapshot écrit");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Witnesses of the ADDITIVE settings-key migration `enterprise.<x>` -> `advanced.<x>`: a database that
//! carried the old keys keeps every advanced module engaged — and its super-administrator — after the first
//! start of the new binary, while the old rows stay readable by an older replica; two diverging values are
//! refused at migration time with an exact message that names keys, never values; once stamped, leftovers
//! never block a start and the new value is the one that counts; the pass is idempotent; and each path
//! that can bring an old key in (restore, import, upgrade, the Postgres boot, `migrate-store`) migrates it
//! or refuses it. Each witness builds its OWN database with generic accounts (alice, bob, operateur).
use super::*;
use crate::testutil::*;
use rusqlite::Connection;
use serde_json::json;

/// Exact refusal text, written out here (not rebuilt from the code under test) so that a change of
/// wording shows up as a red witness.
pub(crate) fn expected_refusal(gaps: &str, clause: &str) -> String {
    format!(
        "settings keys out of step: {gaps}. The enterprise.* settings keys were renamed advanced.* (no alias); \
         until the enterprise.* leftovers are removed, both names must hold the same value. Give BOTH names the \
         same intended value; never delete an advanced.* key to get past this; if the enterprise.* rows were \
         removed on purpose, run the complete removal of docs/UPGRADE.md §8. {clause}"
    )
}
pub(crate) const BOOT: &str = "Refusing to start rather than pick one.";
pub(crate) const MIGRATE_STORE: &str = "migrate-store refused: its transaction is rolled back, the target holds no copied row.";
const IMPORT: &str = "Import refused: the target database was copied but not migrated; correct the source, then import again.";
const UPGRADE: &str = "Upgrade refused: the database goes back to its pre-upgrade snapshot.";

fn superadmin_conflict(clause: &str) -> String {
    expected_refusal("enterprise.superadmin present, advanced.superadmin differs", clause)
}

/// The five old keys as a pre-rename installation stored them, and the values the witnesses expect back.
fn old_rows() -> Vec<(&'static str, &'static str)> {
    vec![
        ("enterprise.tenancy", "on"),
        ("enterprise.sso", "on"),
        ("enterprise.scim", "on"),
        ("enterprise.compliance", "on"),
        ("enterprise.superadmin", "alice, operateur"),
    ]
}

fn put(db: &Connection, key: &str, value: &str) {
    crate::settings_set(db, key, value).expect("settings_set");
}

/// `(key, value)` of every row of `settings`, sorted — `updated` left out (the stamp rewrites it).
fn dump(db: &Connection) -> Vec<(String, String)> {
    let mut stmt = db.prepare("SELECT key, value FROM settings ORDER BY key").unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(|r| r.unwrap()).collect()
}

fn get(db: &Connection, key: &str) -> Option<String> {
    crate::settings_get(db, key)
}

/// Puts a database back in its PRE-UPGRADE state: the five old keys (plus `extra`), the stamp of the
/// previous schema version, 2, and NO migration record (the test app's fresh database already wrote one)
/// — the state a database is in when the new binary starts on it for the first time.
fn seed_pre_upgrade(db: &Connection, extra: &[(&str, &str)]) {
    db.execute("DELETE FROM settings WHERE key=?", [MIGRATION_RECORD_KEY]).expect("record removed");
    for (k, v) in old_rows().into_iter().chain(extra.iter().copied()) {
        put(db, k, v);
    }
    put(db, crate::schema::SCHEMA_VERSION_KEY, "2");
}

/// A pre-rename SQLite file on disk: the base schema, the five old keys, schema_version 2 and a ledger.
fn pre_rename_db(dir: &str, extra: &[(&str, &str)]) -> (String, String) {
    let db = format!("{dir}/forge.db");
    let ledger = format!("{dir}/engagement.jsonl");
    let c = Connection::open(&db).expect("open");
    c.execute_batch(crate::SCHEMA).expect("schema");
    seed_pre_upgrade(&c, extra);
    drop(c);
    crate::ledger_append_standalone(&ledger, "engagement.start", &json!({"by": "alice"})).expect("ledger");
    (db, ledger)
}

/// Each new key holds its old key's value, AND the old row is still there, unchanged (additive).
fn assert_copied(db: &Connection) {
    for (old, value) in old_rows() {
        let new = old.replacen(RETIRED_SETTING_PREFIX, ADVANCED_SETTING_PREFIX, 1);
        assert_eq!(get(db, &new).as_deref(), Some(value), "{new} porte la valeur de {old}");
        assert_eq!(get(db, old).as_deref(), Some(value), "{old} reste intacte pour un réplica antérieur");
    }
}

// ------------------------------------------------------------------ planner contract

#[test]
fn plan_contract_copy_record_compare_refuse() {
    use MigrationStep::*;
    let rows = |v: &[(&str, &str)]| v.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect::<Vec<_>>();
    let plan = |v: &[(&str, &str)]| plan_settings_copy(&rows(v), RefusalContext::Boot);
    let rec = |l: &str| Record { suffixes: l.to_string() };
    // Première migration : le témoin est écrit même quand rien n'est copié (liste vide).
    assert_eq!(plan(&[]), Ok(vec![rec("")]), "aucune clé : témoin à liste vide");
    assert_eq!(
        plan(&[("enterprise.sso", "on")]),
        Ok(vec![Copy { from: "enterprise.sso".into(), to: "advanced.sso".into() }, rec("sso")])
    );
    assert_eq!(plan(&[("enterprise.sso", "on"), ("advanced.sso", "on")]), Ok(vec![rec("sso")]), "égales : rien à copier");
    assert_eq!(plan(&[("advanced.sso", "on")]), Ok(vec![rec("")]), "seule la neuve : rien sous l'ancien nom");
    assert_eq!(
        plan(&[("enterprise.superadmin", "alice"), ("advanced.superadmin", "bob"), ("schema_version", "2")]),
        Err(superadmin_conflict(BOOT))
    );
    // Tampon >= 3 : rien, même en écart.
    for v in ["3", "4"] {
        assert_eq!(plan(&[("enterprise.superadmin", "alice"), ("schema_version", v)]), Ok(vec![]), "tampon {v}");
    }
    // AVEC témoin (un binaire antérieur a retamponné 2) : AUCUNE copie, jamais ; comparaison seule.
    let r = "migration.renamed_settings";
    assert_eq!(plan(&[(r, "superadmin"), ("enterprise.superadmin", "a"), ("advanced.superadmin", "a")]), Ok(vec![]));
    let gap = |v: &[(&str, &str)]| plan(v).expect_err("écart");
    assert_eq!(gap(&[(r, "superadmin"), ("enterprise.superadmin", "a")]),
        expected_refusal("enterprise.superadmin present, advanced.superadmin absent", BOOT), "neuve supprimée");
    assert_eq!(gap(&[(r, "superadmin"), ("enterprise.superadmin", "a"), ("advanced.superadmin", "b")]),
        expected_refusal("enterprise.superadmin present, advanced.superadmin differs", BOOT), "neuve ou ancienne changée");
    assert_eq!(gap(&[(r, "superadmin"), ("advanced.superadmin", "a")]),
        expected_refusal("enterprise.superadmin absent, advanced.superadmin present", BOOT), "ancienne supprimée");
    assert_eq!(gap(&[(r, "superadmin")]),
        expected_refusal("enterprise.superadmin absent, advanced.superadmin absent", BOOT), "les deux supprimées");
    // Hors liste : ancienne absente => rien ; ancienne présente (écrite sous l'ancien binaire) => neuve égale.
    assert_eq!(plan(&[(r, ""), ("advanced.tenancy", "on")]), Ok(vec![]));
    assert_eq!(gap(&[(r, ""), ("enterprise.scim", "on")]),
        expected_refusal("enterprise.scim present, advanced.scim absent", BOOT));
    // Plusieurs écarts : le refus les nomme TOUS, dans l'ordre, séparés par « ; », et une copie qui serait à
    // faire ne sort pas — rien n'est à moitié appliqué.
    assert_eq!(
        plan(&[("enterprise.tenancy", "on"), ("enterprise.sso", "on"), ("advanced.sso", "off"),
            ("enterprise.scim", "1"), ("advanced.scim", "yes")]),
        Err(expected_refusal("enterprise.sso present, advanced.sso differs; enterprise.scim present, advanced.scim differs", BOOT)),
        "deux écarts et une copie à faire : refus complet, aucune étape"
    );
    // Lecture FERMÉE du témoin : un élément hors des cinq noms fait refuser et il est nommé, borné et imprimable.
    assert_eq!(gap(&[(r, "sso,scim,"), ("enterprise.sso", "on"), ("advanced.sso", "on"), ("enterprise.scim", "1"), ("advanced.scim", "1")]),
        expected_refusal("migration.renamed_settings lists unknown name \"\"", BOOT), "élément vide en fin de liste");
    assert_eq!(gap(&[(r, format!("{}\u{7}\n", "x".repeat(60)).as_str())]),
        expected_refusal(&format!("migration.renamed_settings lists unknown name \"{}...\"", "x".repeat(32)), BOOT),
        "élément long tronqué");
    assert_eq!(gap(&[(r, "bad\u{1b}[2Jname")]),
        expected_refusal("migration.renamed_settings lists unknown name \"bad?[2Jname\"", BOOT), "caractère non imprimable remplacé");
    assert_eq!(gap(&[(r, "Sso,uknown")]),
        expected_refusal("migration.renamed_settings lists unknown name \"Sso\"; migration.renamed_settings lists unknown name \"uknown\"", BOOT),
        "chaque élément fautif est nommé");
    // Le contexte décide la dernière phrase ; aucune valeur n'est recopiée.
    let e = plan_settings_copy(&rows(&[(r, "sso"), ("enterprise.sso", "secret-1"), ("advanced.sso", "secret-2")]), RefusalContext::MigrateStore)
        .expect_err("écart");
    assert_eq!(e, expected_refusal("enterprise.sso present, advanced.sso differs", MIGRATE_STORE));
    assert!(!e.contains("secret"), "aucune valeur dans le refus : {e}");
}

// ------------------------------------------------------------------ A + B + F on SQLite (the boot step)

/// A + B — SQLite. Base portant les anciennes clés -> après la passe de démarrage (`migrate`, celle de
/// `boot::serve`) chaque module est TOUJOURS engagé, la super-administration aussi, et les nouvelles clés
/// portent la même valeur.
#[test]
fn sqlite_boot_pass_keeps_every_module_engaged_under_the_new_names() {
    let app = test_app(&tmp_path("rename-boot-ledger"));
    {
        let db = app.db();
        seed_pre_upgrade(&db, &[]);
        crate::migrate(&db).expect("migration sans conflit");
        assert_copied(&db);
        assert_eq!(get(&db, crate::schema::SCHEMA_VERSION_KEY), Some(crate::schema::SCHEMA_VERSION.to_string()));
    }
    assert!(crate::tenancy::enabled(&app), "cloisonnement toujours engagé");
    assert!(crate::sso::enabled(&app), "SSO toujours engagé");
    assert!(crate::scim::enabled(&app), "SCIM toujours engagé");
    assert!(crate::compliance::enabled(&app), "conformité toujours engagée");
    assert!(crate::tenancy::is_superadmin_login(&app, "alice"), "super-administratrice conservée");
    assert!(crate::tenancy::is_superadmin_login(&app, "operateur"), "second super-administrateur conservé");
    assert!(!crate::tenancy::is_superadmin_login(&app, "bob"), "aucun super-administrateur inventé");
}

/// F.6 — COHABITATION : après la migration, une lecture « à l'ancienne » de `enterprise.tenancy` (ce
/// que fait un réplica pas encore monté, ou l'image précédente après un retour arrière) rend toujours la
/// valeur d'avant, et le binaire neuf, lui, lit la nouvelle clé.
#[test]
fn sqlite_older_replica_still_reads_its_key_after_the_migration() {
    let app = test_app(&tmp_path("rename-cohab-ledger"));
    let db = app.db();
    seed_pre_upgrade(&db, &[]);
    crate::migrate(&db).expect("migration");
    let old_replica_read: Option<String> =
        db.query_row("SELECT value FROM settings WHERE key='enterprise.tenancy'", [], |r| r.get(0)).ok();
    assert_eq!(old_replica_read.as_deref(), Some("on"), "un réplica antérieur garde son cloisonnement");
    assert_eq!(get(&db, "advanced.tenancy").as_deref(), Some("on"));
    drop(db);
}

/// F.2 — une fois la base tamponnée, les restes ne font JAMAIS refuser un démarrage : migration, puis
/// changement des réglages neufs (dont `advanced.tenancy`), puis redémarrage -> démarre, et c'est la valeur
/// neuve qui vaut dans CHAQUE module. Les anciennes lignes gardant l'ancienne valeur, ce témoin est aussi
/// celui qui rougit si un module relit l'ancienne clé (aucun alias de lecture).
#[test]
fn sqlite_changing_a_new_key_after_the_migration_never_blocks_the_next_start() {
    let app = test_app(&tmp_path("rename-change-ledger"));
    {
        let db = app.db();
        seed_pre_upgrade(&db, &[]);
        crate::migrate(&db).expect("migration");
        for k in ["advanced.tenancy", "advanced.sso", "advanced.scim", "advanced.compliance"] {
            put(&db, k, "off");
        }
        put(&db, "advanced.superadmin", "bob");
        crate::migrate(&db).expect("redémarrage : la base est tamponnée, le reste ancien n'est pas contrôlé");
        assert_eq!(get(&db, "enterprise.tenancy").as_deref(), Some("on"), "le reste ancien n'est pas touché");
        assert_eq!(get(&db, "advanced.tenancy").as_deref(), Some("off"), "la valeur neuve n'est pas écrasée");
    }
    assert!(!crate::tenancy::enabled(&app), "cloisonnement : la valeur neuve vaut, pas le reste ancien");
    assert!(!crate::sso::enabled(&app), "SSO : la valeur neuve vaut");
    assert!(!crate::scim::enabled(&app), "SCIM : la valeur neuve vaut");
    assert!(!crate::compliance::enabled(&app), "conformité : la valeur neuve vaut");
    assert!(crate::tenancy::is_superadmin_login(&app, "bob"), "super-administration : la valeur neuve vaut");
    assert!(!crate::tenancy::is_superadmin_login(&app, "alice"), "le reste ancien ne désigne personne");
}

/// B — valeurs DIFFÉRENTES sous l'ancien et le nouveau nom au moment de la migration : refus au message
/// exact, RIEN n'est écrit (ni la copie des autres clés, ni le tampon), aucune valeur n'est recopiée.
#[test]
fn sqlite_conflict_is_refused_names_both_keys_and_writes_nothing() {
    let app = test_app(&tmp_path("rename-conflict-ledger"));
    let db = app.db();
    seed_pre_upgrade(&db, &[("advanced.superadmin", "bob")]);
    let before = dump(&db);
    let e = crate::migrate(&db).expect_err("deux valeurs divergentes => refus");
    assert_eq!(e, superadmin_conflict(BOOT));
    assert!(!e.contains("alice") && !e.contains("bob") && !e.contains("operateur"), "aucune valeur dans le refus : {e}");
    assert_eq!(dump(&db), before, "la transaction est annulée : aucune clé copiée, aucun tampon");
    drop(db);
}

/// B — valeurs ÉGALES : rien à écrire, les deux lignes restent.
#[test]
fn sqlite_equal_values_write_nothing() {
    let app = test_app(&tmp_path("rename-equal-ledger"));
    let db = app.db();
    seed_pre_upgrade(&db, &[("advanced.tenancy", "on")]);
    crate::migrate(&db).expect("valeurs égales : pas de refus");
    assert_eq!(get(&db, "enterprise.tenancy").as_deref(), Some("on"));
    assert_eq!(get(&db, "advanced.tenancy").as_deref(), Some("on"));
    drop(db);
}

/// A — rejouer la migration deux fois -> même état.
#[test]
fn sqlite_pass_replayed_twice_gives_the_same_state() {
    let app = test_app(&tmp_path("rename-twice-ledger"));
    let db = app.db();
    seed_pre_upgrade(&db, &[]);
    crate::migrate(&db).expect("1re passe");
    let once = dump(&db);
    crate::migrate(&db).expect("2e passe");
    assert_eq!(dump(&db), once, "la 2e passe ne change rien");
    assert_copied(&db);
    drop(db);
}

// ------------------------------------------------------------------ C — entry paths of old data (SQLite)

/// C — RESTAURATION d'une sauvegarde antérieure : `run_restore` replace la base TELLE QUELLE (l'archive
/// est vérifiée par sha256, elle n'est pas réécrite) et exige un redémarrage ; c'est la passe du
/// démarrage suivant qui migre. Témoin : la base restaurée porte encore l'ancienne clé, puis la passe
/// du boot la copie sous le nouveau nom (l'ancienne ligne reste) ; et une base restaurée en conflit fait refuser ce démarrage.
#[test]
fn restore_of_a_pre_rename_backup_is_migrated_by_the_next_start() {
    for conflict in [false, true] {
        let dir = tmp_dir("rename-restore-src");
        let extra: &[(&str, &str)] = if conflict { &[("advanced.superadmin", "bob")] } else { &[] };
        let (db, ledger) = pre_rename_db(&dir, extra);
        let archive = format!("{dir}/backup.forge");
        crate::run_backup(&crate::BackupOpts {
            out: archive.clone(),
            passphrase: "phrase-de-test".into(),
            db,
            ledger: Some(ledger),
            ts: None,
            actor: "test".into(),
        })
        .expect("sauvegarde");
        let dst = tmp_dir("rename-restore-dst");
        let to = format!("{dst}/forge.db");
        crate::run_restore(&crate::RestoreOpts {
            input: archive,
            passphrase: "phrase-de-test".into(),
            to: Some(to.clone()),
            ledger: Some(format!("{dst}/engagement.jsonl")),
            force: false,
            actor: "test".into(),
        })
        .expect("restauration");
        let c = Connection::open(&to).unwrap();
        assert_eq!(get(&c, "enterprise.tenancy").as_deref(), Some("on"), "placement verbatim de l'archive");
        // La passe du démarrage suivant (boot::serve : SCHEMA puis migrate).
        c.execute_batch(crate::SCHEMA).unwrap();
        let r = crate::migrate(&c);
        if conflict {
            assert_eq!(r, Err(superadmin_conflict(BOOT)), "base restaurée en conflit => démarrage refusé");
            assert_eq!(get(&c, "enterprise.tenancy").as_deref(), Some("on"), "rien n'est écrit sur refus");
        } else {
            r.expect("migration au démarrage");
            assert_copied(&c);
        }
        drop(c);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dst);
    }
}

/// C — IMPORT d'un install existant (`forge migrate` et `POST /api/setup/migrate`, même cœur
/// `run_migration`) : la cible reçoit les nouvelles clés (anciennes lignes laissées) ; un conflit fait échouer l'import au message exact.
#[test]
fn import_of_an_existing_install_migrates_or_refuses() {
    for conflict in [false, true] {
        let dir = tmp_dir("rename-import-src");
        let extra: &[(&str, &str)] = if conflict { &[("advanced.superadmin", "bob")] } else { &[] };
        pre_rename_db(&dir, extra);
        let to = tmp_path("rename-import-to.db");
        let opts = crate::MigrateOpts {
            from: dir.clone(),
            to: to.clone(),
            ledger: Some(tmp_path("rename-import-to.jsonl")),
            verify: true,
            encrypt: false,
            key_env: None,
            actor: "test".into(),
        };
        let r = crate::run_migration(&opts);
        if conflict {
            let e = r.expect_err("conflit => import refusé");
            assert_eq!(e, format!("migration de schéma de la cible refusée : {}", superadmin_conflict(IMPORT)));
        } else {
            r.expect("import");
            assert_copied(&Connection::open(&to).unwrap());
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&to);
    }
}

/// C — `forge upgrade` : une base en version 2 est migrée (clés copiées sous le nouveau nom, version 3) ; en conflit,
/// l'upgrade échoue et la base est RESTAURÉE depuis son instantané (anciennes clés intactes).
#[test]
fn upgrade_migrates_or_refuses_and_rolls_back() {
    for conflict in [false, true] {
        let dir = tmp_dir("rename-upgrade");
        let extra: &[(&str, &str)] = if conflict { &[("advanced.superadmin", "bob")] } else { &[] };
        let (db, ledger) = pre_rename_db(&dir, extra);
        let opts = crate::UpgradeOpts {
            db: db.clone(),
            ledger,
            passphrase: "phrase-de-test".into(),
            backup_dir: dir.clone(),
            to: None,
            force: false,
            dry_run: false,
            actor: "test".into(),
            simulate_failure: None,
        };
        let r = crate::run_upgrade_core(&opts);
        let c = Connection::open(&db).unwrap();
        if conflict {
            let e = r.expect_err("conflit => upgrade refusé");
            assert!(e.contains(&superadmin_conflict(UPGRADE)), "le refus est rapporté tel quel : {e}");
            assert!(e.contains("pre-upgrade snapshot. ROLLBACK EFFECTUÉ"), "un seul point après le refus : {e}");
            assert!(!e.contains(".."), "aucun point doublé : {e}");
            assert_eq!(get(&c, "enterprise.superadmin").as_deref(), Some("alice, operateur"), "base restaurée");
            assert_eq!(get(&c, "advanced.superadmin").as_deref(), Some("bob"), "base restaurée");
            assert_eq!(get(&c, crate::schema::SCHEMA_VERSION_KEY).as_deref(), Some("2"), "version inchangée");
        } else {
            r.expect("upgrade");
            assert_copied(&c);
            assert_eq!(get(&c, crate::schema::SCHEMA_VERSION_KEY), Some(crate::schema::SCHEMA_VERSION.to_string()));
        }
        drop(c);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ------------------------------------------------------------------ wire names (whoami, compliance)

/// FIL — `/api/whoami` sert le champ `advanced` (le SPA le lit) ; l'ancien nom n'est plus servi.
#[tokio::test]
async fn whoami_serves_the_advanced_field() {
    use axum::response::IntoResponse;
    let app = test_app(&tmp_path("rename-whoami-ledger"));
    enable_advanced_tenancy(&app);
    let resp = crate::auth::whoami(axum::extract::State(app.clone()), axum::http::HeaderMap::new()).await.into_response();
    let body = resp_json(resp).await;
    assert_eq!(body["advanced"]["tenancy"], json!(true), "{body}");
    assert_eq!(body["advanced"]["sso"], json!(false), "{body}");
    let keys: Vec<&String> = body.as_object().expect("objet").keys().collect();
    assert!(keys.iter().all(|k| !k.contains(RETIRED_SETTING_PREFIX.trim_end_matches('.'))), "ancien champ servi : {keys:?}");
}

// ------------------------------------------------------------------ A + B + C on Postgres

/// A connected `Store` on its OWN schema of the `TEST_PG_URL` database (parallel tests never share
/// tables), dropped at the end. `None` (and a note) when `TEST_PG_URL` is unset.
#[cfg(feature = "store-postgres")]
pub(crate) fn with_isolated_pg_schema(tag: &str, f: impl FnOnce(&crate::store::Store)) {
    let Ok(url) = std::env::var("TEST_PG_URL") else {
        eprintln!("[{tag}] TEST_PG_URL unset — skipping (set it to run against a real Postgres)");
        return;
    };
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let schema = format!("{tag}_{}_{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
    let m = std::sync::Mutex::new(crate::store::connect_postgres(&url).expect("connect TEST_PG_URL"));
    let store = crate::store::Store::postgres(m.lock().unwrap());
    store.execute_batch(&format!("CREATE SCHEMA {schema}; SET search_path TO {schema}")).expect("schéma isolé");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&store)));
    let _ = store.execute_batch(&format!("SET search_path TO public; DROP SCHEMA {schema} CASCADE"));
    drop(store);
    if let Err(p) = outcome {
        std::panic::resume_unwind(p);
    }
}

#[cfg(feature = "store-postgres")]
fn pg_get(store: &crate::store::Store, key: &str) -> Option<String> {
    crate::settings_get_store(store, key)
}

#[cfg(feature = "store-postgres")]
fn pg_dump(store: &crate::store::Store) -> Vec<(String, String)> {
    store
        .query("SELECT key, value FROM settings ORDER BY key", &crate::sql_params![], |r| Ok((r.get_str(0)?, r.get_str(1)?)))
        .unwrap()
}

/// A + B + F — Postgres, la transaction de boot elle-même (`schema::pg_boot_schema_and_seed`) : anciennes
/// clés copiées (anciennes lignes laissées) et tamponnées ensemble ; deux fois -> même état ; base
/// tamponnée : un reste ancien divergent et un réglage neuf modifié ne bloquent pas le redémarrage ;
/// base revenue à un ancien tampon (sauvegarde restaurée) en conflit -> refus exact, rien écrit.
#[cfg(feature = "store-postgres")]
#[test]
fn pg_boot_transaction_migrates_replays_and_refuses() {
    with_isolated_pg_schema("rename_pg_boot", |store| {
        store.execute_batch(crate::schema::PG_SCHEMA).expect("PG_SCHEMA");
        for (k, v) in old_rows() {
            crate::settings_set_store(store, k, v).unwrap();
        }
        crate::settings_set_store(store, crate::schema::SCHEMA_VERSION_KEY, "2").unwrap();
        crate::schema::pg_boot_schema_and_seed(store, &[], "grey", "").expect("boot PG");
        for (old, value) in old_rows() {
            let new = old.replacen(RETIRED_SETTING_PREFIX, ADVANCED_SETTING_PREFIX, 1);
            assert_eq!(pg_get(store, old).as_deref(), Some(value), "{old} reste pour un réplica antérieur");
            assert_eq!(pg_get(store, &new).as_deref(), Some(value), "{new} porte la valeur");
        }
        assert_eq!(pg_get(store, crate::schema::SCHEMA_VERSION_KEY), Some(crate::schema::SCHEMA_VERSION.to_string()));
        let once = pg_dump(store);
        crate::schema::pg_boot_schema_and_seed(store, &[], "grey", "").expect("boot PG rejoué");
        assert_eq!(pg_dump(store), once, "la 2e passe ne change rien");

        // Base tamponnée : réglage neuf modifié + reste ancien divergent -> le redémarrage passe, la valeur
        // neuve vaut et n'est pas écrasée.
        crate::settings_set_store(store, "advanced.tenancy", "off").unwrap();
        crate::settings_set_store(store, "enterprise.superadmin", "bob").unwrap();
        crate::schema::pg_boot_schema_and_seed(store, &[], "grey", "").expect("base tamponnée : restes inertes");
        assert_eq!(pg_get(store, "advanced.tenancy").as_deref(), Some("off"));
        assert_eq!(pg_get(store, "advanced.superadmin").as_deref(), Some("alice, operateur"));

        // Conflit : la base revient à un ancien tampon (sauvegarde antérieure) avec UNE valeur divergente
        // (le cloisonnement est remis d'accord, seul `superadmin` diverge).
        crate::settings_set_store(store, "advanced.tenancy", "on").unwrap();
        crate::settings_set_store(store, crate::schema::SCHEMA_VERSION_KEY, "2").unwrap();
        let before = pg_dump(store);
        let e = crate::schema::pg_boot_schema_and_seed(store, &[], "grey", "").expect_err("conflit => refus");
        assert_eq!(e.to_string(), superadmin_conflict(BOOT));
        assert_eq!(pg_dump(store), before, "ROLLBACK : ni copie, ni tampon");
    });
}

// ------------------------------------------------------------------ an OLDER binary ran since: no rebirth

/// State of a database right after the FIRST migration: the five old rows, their five copies, the record
/// listing all five suffixes, stamp 3. Plain SQL, run as is on SQLite and on Postgres.
pub(crate) const MIGRATED_STATE: &str = "DELETE FROM settings;
INSERT INTO settings(key, value, updated) VALUES
 ('enterprise.tenancy','on',''), ('enterprise.sso','on',''), ('enterprise.scim','on',''),
 ('enterprise.compliance','on',''), ('enterprise.superadmin','alice, operateur',''),
 ('advanced.tenancy','on',''), ('advanced.sso','on',''), ('advanced.scim','on',''),
 ('advanced.compliance','on',''), ('advanced.superadmin','alice, operateur',''),
 ('migration.renamed_settings','tenancy,sso,scim,compliance,superadmin',''), ('schema_version','3','');";

/// The removal of the leftovers, EXACTLY as docs/UPGRADE.md §8 prints it (`removal_sql_is_the_documented_one`
/// holds the two together): one transaction, delete the five old keys AND empty the record's list.
pub(crate) const LEFTOVER_REMOVAL: &str = "BEGIN;
DELETE FROM settings WHERE key IN ('enterprise.tenancy','enterprise.sso','enterprise.scim','enterprise.compliance','enterprise.superadmin');
UPDATE settings SET value='' WHERE key='migration.renamed_settings';
COMMIT;";

/// What the operator (or an older binary) did since the first migration, then the older binary's start:
/// the stamp goes back to 2. `gaps` = expected refusal, or `None` = the start goes through.
pub(crate) struct OlderBinaryCase {
    pub(crate) name: &'static str,
    pub(crate) then: &'static str,
    pub(crate) gaps: Option<&'static str>,
}

pub(crate) fn older_binary_cases() -> Vec<OlderBinaryCase> {
    vec![
        OlderBinaryCase { name: "neuve supprimée (super-administratrice révoquée)",
            then: "DELETE FROM settings WHERE key='advanced.superadmin';",
            gaps: Some("enterprise.superadmin present, advanced.superadmin absent") },
        OlderBinaryCase { name: "neuve changée",
            then: "UPDATE settings SET value='bob' WHERE key='advanced.superadmin';",
            gaps: Some("enterprise.superadmin present, advanced.superadmin differs") },
        OlderBinaryCase { name: "ancienne supprimée",
            then: "DELETE FROM settings WHERE key='enterprise.tenancy';",
            gaps: Some("enterprise.tenancy absent, advanced.tenancy present") },
        OlderBinaryCase { name: "ancienne changée (sous l'ancien binaire)",
            then: "UPDATE settings SET value='off' WHERE key='enterprise.tenancy';",
            gaps: Some("enterprise.tenancy present, advanced.tenancy differs") },
        OlderBinaryCase { name: "tout égal", then: "", gaps: None },
        OlderBinaryCase { name: "retrait complet du §8", then: LEFTOVER_REMOVAL, gaps: None },
        OlderBinaryCase { name: "après retrait, l'ancien binaire écrit l'ancien nom seul",
            then: "BEGIN;
DELETE FROM settings WHERE key IN ('enterprise.tenancy','enterprise.sso','enterprise.scim','enterprise.compliance','enterprise.superadmin');
UPDATE settings SET value='' WHERE key='migration.renamed_settings';
COMMIT;
INSERT INTO settings(key, value, updated) VALUES ('enterprise.superadmin','alice','');",
            gaps: Some("enterprise.superadmin present, advanced.superadmin differs") },
        // Lecture FERMÉE du témoin : un élément hors des cinq noms fait refuser, même quand les clés sont
        // d'accord — sinon un nom effacé de la liste laisserait passer une ancienne clé supprimée.
        OlderBinaryCase { name: "témoin : casse différente",
            then: "UPDATE settings SET value='tenancy,SSO,scim,compliance,superadmin' WHERE key='migration.renamed_settings';",
            gaps: Some("migration.renamed_settings lists unknown name \"SSO\"") },
        OlderBinaryCase { name: "témoin : espace autour d'un nom",
            then: "UPDATE settings SET value='tenancy, sso,scim,compliance,superadmin' WHERE key='migration.renamed_settings';",
            gaps: Some("migration.renamed_settings lists unknown name \" sso\"") },
        OlderBinaryCase { name: "témoin : mot inconnu, ancienne clé supprimée",
            then: "UPDATE settings SET value='tenancy,sso,scim,compliance,superuser' WHERE key='migration.renamed_settings';
DELETE FROM settings WHERE key='enterprise.superadmin';",
            gaps: Some("migration.renamed_settings lists unknown name \"superuser\"") },
        OlderBinaryCase { name: "témoin : élément vide au milieu",
            then: "UPDATE settings SET value='tenancy,,sso,scim,compliance,superadmin' WHERE key='migration.renamed_settings';",
            gaps: Some("migration.renamed_settings lists unknown name \"\"") },
    ]
}

/// `before` with only the stamp moved to the current version — what a start that goes through leaves.
pub(crate) fn restamped(before: &[(String, String)]) -> Vec<(String, String)> {
    before
        .iter()
        .map(|(k, v)| {
            let v = if k == crate::schema::SCHEMA_VERSION_KEY { crate::schema::SCHEMA_VERSION.to_string() } else { v.clone() };
            (k.clone(), v)
        })
        .collect()
}

/// SQLite boot pass. A refusal writes NOTHING (a deleted key stays deleted); a start that goes through
/// changes nothing but the stamp — nothing is reborn.
#[test]
fn sqlite_boot_after_an_older_binary_compares_and_never_copies_again() {
    for case in older_binary_cases() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::SCHEMA).unwrap();
        c.execute_batch(MIGRATED_STATE).unwrap();
        c.execute_batch(case.then).unwrap();
        c.execute("UPDATE settings SET value='2' WHERE key='schema_version'", []).unwrap();
        let before = dump(&c);
        let r = crate::migrate(&c);
        match case.gaps {
            Some(g) => {
                assert_eq!(r, Err(expected_refusal(g, BOOT)), "{}", case.name);
                assert_eq!(dump(&c), before, "{} : rien n'est écrit, la clé supprimée le reste", case.name);
            }
            None => {
                r.unwrap_or_else(|e| panic!("{} : {e}", case.name));
                assert_eq!(dump(&c), restamped(&before), "{} : retamponné 3, rien ne renaît", case.name);
            }
        }
    }
}

/// Première migration sans aucune clé : le témoin est écrit, liste vide (base neuve comprise).
#[test]
fn first_migration_without_any_key_writes_an_empty_record() {
    let app = test_app(&tmp_path("rename-fresh-ledger"));
    let db = app.db();
    assert_eq!(get(&db, MIGRATION_RECORD_KEY).as_deref(), Some(""), "base neuve : témoin à liste vide");
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(crate::SCHEMA).unwrap();
    put(&c, crate::schema::SCHEMA_VERSION_KEY, "2");
    crate::migrate(&c).expect("migration");
    assert_eq!(get(&c, MIGRATION_RECORD_KEY).as_deref(), Some(""));
    drop(db);
}

/// Le retrait que les témoins jouent est mot pour mot celui que la note de migration imprime, dans les
/// deux langues.
#[test]
fn removal_sql_is_the_documented_one() {
    for doc in ["UPGRADE.md", "UPGRADE.fr.md"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("docs").join(doc);
        let text = std::fs::read_to_string(&path).expect("note de migration");
        assert!(text.contains(LEFTOVER_REMOVAL), "{doc} n'imprime pas la transaction de retrait jouée par les témoins");
    }
}

/// BRANCHEMENT du refus au démarrage réel : un ENFANT de ce binaire de test (comme
/// `flags::tests::real_entry_point_refuses_a_retired_name`) appelle `serve()`, le boot du serveur, sur une
/// base dont la super-administratrice a été révoquée puis le tampon remis à 2 par un binaire antérieur. Il
/// doit sortir en code 2 sur le FATAL exact, sans rien écrire. L'adresse d'écoute est invalide : si le
/// refus ne mordait pas, l'enfant échouerait au bind au lieu de servir indéfiniment.
const BOOT_CHILD: &str = "FORGE_TEST_SETTINGS_BOOT_CHILD";
const BOOT_TEST: &str = "settings_rename::tests::real_boot_refuses_keys_out_of_step";

#[test]
fn real_boot_refuses_keys_out_of_step() {
    if std::env::var_os(BOOT_CHILD).is_some() {
        tokio::runtime::Runtime::new().expect("runtime").block_on(crate::serve());
        return;
    }
    let dir = tmp_dir("rename-real-boot");
    let db = format!("{dir}/forge.db");
    {
        let c = Connection::open(&db).unwrap();
        c.execute_batch(crate::SCHEMA).unwrap();
        c.execute_batch(MIGRATED_STATE).unwrap();
        c.execute_batch("DELETE FROM settings WHERE key='advanced.superadmin'; UPDATE settings SET value='2' WHERE key='schema_version';").unwrap();
    }
    let before = dump(&Connection::open(&db).unwrap());
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("test binary"));
    cmd.args([BOOT_TEST, "--exact", "--test-threads=1", "--nocapture"]);
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().into_owned();
        if k.starts_with("FORGE_") {
            cmd.env_remove(k);
        }
    }
    cmd.env(BOOT_CHILD, "1")
        .env("FORGE_CONSOLE_DB", &db)
        .env("FORGE_CONSOLE_LEDGER", format!("{dir}/engagement.jsonl"))
        .env("FORGE_PKG_DIR", &dir)
        .env("FORGE_PYTHON", format!("{dir}/no-python"))
        .env("FORGE_CONSOLE_ADDR", "not-an-address")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn child");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while child.try_wait().expect("try_wait").is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("l'enfant ne s'est pas arrêté : le refus n'a pas mordu");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let out = child.wait_with_output().expect("output");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let fatal = format!(
        "[forge] FATAL {}",
        expected_refusal("enterprise.superadmin present, advanced.superadmin absent", BOOT)
    );
    assert_eq!(out.status.code(), Some(2), "code de sortie du boot:\n{stderr}");
    assert!(stderr.contains(&fatal), "le FATAL exact attendu:\n{stderr}");
    assert!(!stderr.contains("alice"), "aucune valeur dans la sortie:\n{stderr}");
    assert_eq!(dump(&Connection::open(&db).unwrap()), before, "base inchangée après le refus");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Même chose sur Postgres, par la transaction de boot elle-même.
#[cfg(feature = "store-postgres")]
#[test]
fn pg_boot_after_an_older_binary_compares_and_never_copies_again() {
    for case in older_binary_cases() {
        with_isolated_pg_schema("rename_pg_older", |store| {
            store.execute_batch(crate::schema::PG_SCHEMA).expect("PG_SCHEMA");
            store.execute_batch(MIGRATED_STATE).unwrap();
            if !case.then.is_empty() {
                store.execute_batch(case.then).unwrap();
            }
            store.execute_batch("UPDATE settings SET value='2' WHERE key='schema_version'").unwrap();
            let before = pg_dump(store);
            let r = crate::schema::pg_boot_schema_and_seed(store, &[], "grey", "");
            match case.gaps {
                Some(g) => {
                    assert_eq!(r.map_err(|e| e.to_string()), Err(expected_refusal(g, BOOT)), "{}", case.name);
                    assert_eq!(pg_dump(store), before, "{} : rien n'est écrit", case.name);
                }
                None => {
                    r.unwrap_or_else(|e| panic!("{} : {e}", case.name));
                    assert_eq!(pg_dump(store), restamped(&before), "{} : retamponné 3, rien ne renaît", case.name);
                }
            }
        });
    }
}

/// Postgres neuf : le boot écrit le témoin à liste vide.
#[cfg(feature = "store-postgres")]
#[test]
fn pg_first_boot_without_any_key_writes_an_empty_record() {
    with_isolated_pg_schema("rename_pg_fresh", |store| {
        crate::schema::pg_boot_schema_and_seed(store, &[], "grey", "").expect("boot PG");
        assert_eq!(pg_get(store, MIGRATION_RECORD_KEY).as_deref(), Some(""));
    });
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! `backup` — module de test EXTRAIT (PURE MOVE depuis `console/src/backup.rs`).
//! Corps IDENTIQUE ; ENFANT de `backup`, il voit donc toujours ses items privés.
use super::*;

    use super::*;
    use crate::testutil::*;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::AtomicBool;
    use std::collections::HashMap;
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    /// Sème une source d'engagement complète : base (schéma ancien, 1 finding), ledger chaîné à
    /// `entries` entrées, et une clé de signature `.ed25519`. Renvoie (db, ledger, key).
    fn seed_backup_source(dir: &str, entries: usize) -> (String, String, String) {
        let db = format!("{dir}/forge.db");
        seed_old_source_db(&db);
        let ledger = format!("{dir}/engagement.jsonl");
        for i in 0..entries {
            ledger_append_standalone(&ledger, "engagement.step", &json!({"i": i, "msg": "événement"})).unwrap();
        }
        let key = format!("{ledger}.ed25519");
        std::fs::write(&key, b"raw-ed25519-signing-key-32-bytes").unwrap();
        (db, ledger, key)
    }

    /// App de test dont `db_path`/`ledger_path` pointent sur des fichiers RÉELS (le moteur backup ouvre
    /// la base sur disque en read-only + VACUUM INTO). Sème un admin, une base au SCHEMA courant, un
    /// ledger chaîné (1 entrée) et une clé .ed25519. Renvoie (app, db_path, ledger_path, admin_token).
    fn test_app_disk(dir: &str) -> (App, String, String, String) {
        let db_path = format!("{dir}/forge.db");
        let ledger = format!("{dir}/engagement.jsonl");
        let conn = Connection::open(&db_path).expect("open disk db");
        conn.execute_batch(SCHEMA).expect("schema");
        migrate(&conn);
        upsert_user(&conn, "adm", "admin", &hash_pw("pw")).unwrap();
        upsert_user(&conn, "viw", "viewer", &hash_pw("pw")).unwrap();
        upsert_user(&conn, "opr", "operator", &hash_pw("pw")).unwrap();
        ledger_append_standalone(&ledger, "engagement.start", &json!({"a": 1})).unwrap();
        std::fs::write(format!("{ledger}.ed25519"), b"raw-ed25519-signing-key-32-bytes!").unwrap();
        let (events, _) = broadcast::channel::<RunEvent>(64);
        let app = App {
            db: Arc::new(Mutex::new(conn)),
            #[cfg(feature = "store-postgres")]
            pg: None,
            #[cfg(feature = "store-postgres")]
            ha: false,
            #[cfg(feature = "store-postgres")]
            instance_id: Arc::new("test-instance".into()),
            #[cfg(feature = "store-postgres")]
            is_leader: Arc::new(AtomicBool::new(true)),
            db_path: Arc::new(db_path.clone()),
            token_sha: Arc::new(sha_hex("t")),
            token_raw: Arc::new("t".into()),
            user: Arc::new("forge".into()),
            pass_hash: Arc::new(String::new()),
            auth_required: Arc::new(AtomicBool::new(true)),
            operator_hash: Arc::new(String::new()),
            allowed_hosts: Arc::new(vec!["localhost".into()]),
            ledger_path: Arc::new(ledger.clone()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(RunState { current: HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        };
        let (atok, _) = create_session(&app, uid_of(&app, "adm"));
        (app, db_path, ledger, atok)
    }

    /// [BACKUP crypto] round-trip byte-for-byte : la base (snapshot), le ledger et la clé sortent de
    /// l'archive IDENTIQUES à ce qui y est entré. Le restore place la DB et la clé VERBATIM, et
    /// reproduit le ledger d'origine à l'octet près (puis y ajoute une entrée `console.restore` de
    /// traçabilité). La donnée SQLite survit (contenu relisible).
    #[test]
    fn backup_restore_roundtrips_db_ledger_key_byte_for_byte() {
        let src_dir = tmp_dir("forge-bk-rt-src");
        let (src_db, src_ledger, src_key) = seed_backup_source(&src_dir, 2);
        // capture l'état AVANT le backup (le backup appendra `console.backup` à la SOURCE après coup).
        let orig_ledger = std::fs::read(&src_ledger).unwrap();
        let orig_key = std::fs::read(&src_key).unwrap();

        let out = tmp_path("forge-bk-rt.age");
        let pass = "correct horse battery staple";
        let bopts = BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db.clone(),
            ledger: Some(src_ledger.clone()), ts: Some("@1234".to_string()), actor: "test".to_string(),
        };
        let brep = run_backup(&bopts).expect("backup doit réussir");
        assert_eq!(brep["encrypted"], true, "l'archive est TOUJOURS chiffrée");
        assert_eq!(brep["included_ledger"], true);
        assert_eq!(brep["included_key"], true);
        assert!(std::path::Path::new(&out).exists(), "archive écrite");

        // l'archive ne commence PAS par les octets d'un tar en clair (magic FORGE + chiffré).
        let raw = std::fs::read(&out).unwrap();
        assert_eq!(&raw[0..8], BACKUP_MAGIC, "en-tête FORGEBK1");
        // fidélité au niveau ARCHIVE : déchiffre + extrait -> db/ledger/clé égaux aux sources (octet-près).
        let pt = backup_decrypt(&raw, pass).expect("déchiffrement ok");
        let entries = backup_extract_tar(&pt).unwrap();
        let ar_get = |n: &str| entries.iter().find(|(x, _)| x == n).map(|(_, b)| b.clone()).unwrap();
        let ar_db = ar_get(BACKUP_ENTRY_DB);
        let ar_ledger = ar_get(BACKUP_ENTRY_LEDGER);
        let ar_key = ar_get(BACKUP_ENTRY_KEY);
        assert_eq!(ar_ledger, orig_ledger, "ledger archivé == ledger source (byte-for-byte)");
        assert_eq!(ar_key, orig_key, "clé archivée == clé source (byte-for-byte)");
        // manifest présent, sha256 par fichier cohérents.
        let manifest: Value = serde_json::from_slice(&ar_get(BACKUP_ENTRY_MANIFEST)).unwrap();
        assert_eq!(manifest["schema"], BACKUP_SCHEMA_VERSION);
        assert_eq!(manifest["created_at"], "@1234", "timestamp passé-en-argument conservé");
        assert_eq!(manifest["files"]["db.sqlite"]["sha256"], sha256_hex_bytes(&ar_db));

        // restore dans un dossier NEUF (aucun écrasement).
        let to_dir = tmp_dir("forge-bk-rt-to");
        let to_db = format!("{to_dir}/forge.db");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        let ropts = RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: false, actor: "test".to_string(),
        };
        let rrep = run_restore(&ropts).expect("restore doit réussir");
        assert_eq!(rrep["restored_key"], true);

        // DB placée VERBATIM == db archivée (byte-for-byte) + contenu SQLite relisible.
        assert_eq!(std::fs::read(&to_db).unwrap(), ar_db, "DB restaurée == snapshot archivé (byte-for-byte)");
        let dst = Connection::open(&to_db).unwrap();
        let title: String = dst.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding", "la donnée SQLite survit au round-trip");
        drop(dst);

        // clé restaurée == clé source (byte-for-byte). La clé voyage AVEC le ledger.
        let to_key = format!("{to_ledger}.ed25519");
        assert!(std::path::Path::new(&to_key).exists(), "clé .ed25519 restaurée à côté du ledger");
        assert_eq!(std::fs::read(&to_key).unwrap(), orig_key, "clé restaurée == source (byte-for-byte)");

        // ledger : les 2 entrées d'origine sont reproduites À L'OCTET PRÈS en préfixe ; une entrée
        // `console.restore` de traçabilité est ajoutée ; la chaîne reste intègre.
        let restored_ledger = std::fs::read(&to_ledger).unwrap();
        assert!(restored_ledger.starts_with(&orig_ledger), "préfixe ledger == source (byte-for-byte)");
        let lines = read_ledger_lines(&to_ledger);
        assert_eq!(lines.len(), 3, "2 entrées source + 1 console.restore");
        assert_eq!(lines[2]["kind"], "console.restore", "restore tracé au ledger (métadonnées)");
        let vfin = verify_ledger_chain(&to_ledger);
        assert!(vfin.ok, "chaîne du ledger restauré + trace reste vérifiable");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP crypto] une MAUVAISE passphrase échoue proprement (tag AEAD) et n'écrit RIEN sur disque.
    #[test]
    /// UNE SAUVEGARDE NON CHIFFRÉE NE DOIT PAS POUVOIR EXISTER — au niveau du CŒUR, pas seulement de
    /// l'API HTTP.
    ///
    /// Une archive contient la base ENTIÈRE, donc tout matériel d'authentification stocké (bearers,
    /// cookies, en-têtes des comptes de test par engagement). C'est INHÉRENT : une sauvegarde doit
    /// restaurer fidèlement, la rédiger ferait perdre le contexte à la restauration. La garantie n'est
    /// donc pas « pas de secret dans l'archive » mais « **aucune archive en clair ne peut exister** ».
    ///
    /// Le fail-closed était bien codé, mais RIEN NE L'ÉPINGLAIT : le test existant vérifie la couche
    /// HTTP (400 sur passphrase absente), pas `run_backup_core` — qu'empruntent la CLI hors-ligne ET le
    /// planificateur. Neutraliser la garde laissait les 17 tests de sauvegarde verts (mesuré le
    /// 2026-08-06). Ce test ferme ce trou pour les trois chemins.
    #[test]
    fn backup_core_refuses_to_write_anything_without_a_passphrase() {
        let src_dir = tmp_dir("forge-bk-nopass-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-nopass.age");
        let err = run_backup_core(&BackupOpts {
            out: out.clone(), passphrase: String::new(), db: src_db.clone(),
            ledger: Some(src_ledger.clone()), ts: None, actor: "test".to_string(),
        })
        .expect_err("passphrase vide -> la sauvegarde DOIT échouer (fail-closed)");
        assert!(err.contains("passphrase"), "l'erreur doit nommer la cause : {err}");
        assert!(!std::path::Path::new(&out).exists(),
                "AUCUN fichier ne doit être écrit — pas même un plaintext temporaire : {out}");

        // Contrôle POSITIF : la même sauvegarde AVEC passphrase réussit et produit une archive
        // qui n'est PAS lisible en clair (sinon ce test passerait sur un chiffrement inopérant).
        run_backup_core(&BackupOpts {
            out: out.clone(), passphrase: "p".repeat(24), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        })
        .expect("avec passphrase -> ok");
        let raw = std::fs::read(&out).expect("archive écrite");
        assert!(!raw.windows(6).any(|w| w == b"SQLite"),
                "l'archive ne doit pas contenir l'en-tête SQLite en clair");
        let _ = std::fs::remove_file(&out);
    }

    fn backup_wrong_passphrase_fails_and_writes_nothing() {
        let src_dir = tmp_dir("forge-bk-wp-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-wp.age");
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: "the-right-one".to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");

        // déchiffrement direct avec la mauvaise passphrase -> Err (jamais de plaintext).
        let raw = std::fs::read(&out).unwrap();
        assert!(backup_decrypt(&raw, "the-WRONG-one").is_err(), "mauvaise passphrase -> tag AEAD invalide");
        assert!(backup_decrypt(&raw, "the-right-one").is_ok(), "bonne passphrase -> ok (sanity)");

        // restore complet avec mauvaise passphrase : Err ET aucune écriture cible.
        let to_dir = tmp_dir("forge-bk-wp-to");
        let to_db = format!("{to_dir}/db.sqlite");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        let err = run_restore(&RestoreOpts {
            input: out.clone(), passphrase: "the-WRONG-one".to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: true, actor: "test".to_string(),
        }).expect_err("mauvaise passphrase -> restore échoue");
        assert!(err.contains("AEAD") || err.contains("passphrase"), "erreur claire: {err}");
        assert!(!std::path::Path::new(&to_db).exists(), "RIEN écrit (db) sur mauvaise passphrase");
        assert!(!std::path::Path::new(&to_ledger).exists(), "RIEN écrit (ledger) sur mauvaise passphrase");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP crypto] un octet retourné dans l'archive (corps OU en-tête lié en AAD) casse le tag
    /// Poly1305 -> déchiffrement refusé, restore échoue et n'écrit rien.
    #[test]
    fn backup_flipped_byte_fails_aead_tag() {
        let src_dir = tmp_dir("forge-bk-flip-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-flip.age");
        let pass = "passphrase-forte-123";
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");
        let raw = std::fs::read(&out).unwrap();
        let hdr = backup_parse_header(&raw).unwrap();

        // 1) octet retourné dans le CIPHERTEXT.
        let mut t1 = raw.clone();
        let idx = hdr.header_len + 4; // dans le corps chiffré
        t1[idx] ^= 0xFF;
        assert!(backup_decrypt(&t1, pass).is_err(), "corps altéré -> tag AEAD invalide");

        // 2) octet retourné dans le SEL (en-tête, lié en AAD) : la clé dérivée diffère ET l'AAD change
        //    -> le tag AEAD échoue. Le sel occupe les octets 22..38 (après magic|ver|m|t|p|salt_len).
        let mut t2 = raw.clone();
        t2[25] ^= 0xFF; // à l'intérieur de la zone sel
        assert!(backup_decrypt(&t2, pass).is_err(), "sel altéré -> clé/AAD différents -> tag AEAD invalide");

        // 2b) octet retourné dans les PARAMS argon2 (en-tête, malléable AVANT authentification) : rejet
        //     PROPRE (Err, jamais de panic/DoS) grâce à la validation des bornes de la KDF.
        let mut t2b = raw.clone();
        t2b[12] ^= 0xFF; // octet de poids fort de m_cost -> valeur absurde
        assert!(backup_decrypt(&t2b, pass).is_err(), "params argon2 corrompus -> Err propre (pas de panic)");

        // 3) restore sur archive altérée : Err + aucune écriture.
        let tampered = tmp_path("forge-bk-flip-tampered.age");
        std::fs::write(&tampered, &t1).unwrap();
        let to_dir = tmp_dir("forge-bk-flip-to");
        let to_db = format!("{to_dir}/db.sqlite");
        let err = run_restore(&RestoreOpts {
            input: tampered.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(format!("{to_dir}/engagement.jsonl")), force: true, actor: "test".to_string(),
        }).expect_err("archive altérée -> restore échoue");
        assert!(err.contains("AEAD") || err.contains("altérée"), "erreur claire: {err}");
        assert!(!std::path::Path::new(&to_db).exists(), "RIEN écrit sur archive altérée");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
        let _ = std::fs::remove_file(&tampered);
    }

    /// [BACKUP intégrité] le manifest re-vérifie le sha256 de chaque fichier : un sha falsifié (même
    /// dans un plaintext par ailleurs bien chiffré) fait ÉCHOUER le restore sans rien placer.
    #[test]
    fn restore_rejects_manifest_sha_mismatch() {
        let db = b"fausse-base-sqlite-pour-le-test".to_vec();
        // manifest annonçant un sha256 VOLONTAIREMENT faux pour db.sqlite.
        let bad_manifest = json!({
            "kind": "forge-backup", "schema": BACKUP_SCHEMA_VERSION,
            "files": {"db.sqlite": {"sha256": "0".repeat(64), "size": db.len()}}
        });
        let mb = serde_json::to_vec_pretty(&bad_manifest).unwrap();
        let tar = backup_build_tar(&[(BACKUP_ENTRY_MANIFEST, &mb), (BACKUP_ENTRY_DB, &db)]).unwrap();
        let sealed = backup_encrypt(&tar, "pw").unwrap(); // bien chiffré : l'AEAD passera.
        let arch = tmp_path("forge-bk-shamism.age");
        std::fs::write(&arch, &sealed).unwrap();

        let to_dir = tmp_dir("forge-bk-shamism-to");
        let to_db = format!("{to_dir}/db.sqlite");
        let err = run_restore(&RestoreOpts {
            input: arch.clone(), passphrase: "pw".to_string(), to: Some(to_db.clone()),
            ledger: Some(format!("{to_dir}/engagement.jsonl")), force: true, actor: "test".to_string(),
        }).expect_err("sha256 falsifié -> restore refusé");
        assert!(err.contains("sha256 mismatch"), "erreur d'intégrité manifest: {err}");
        assert!(!std::path::Path::new(&to_db).exists(), "aucun placement quand le manifest est incohérent");

        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&arch);
    }

    /// [BACKUP garde] le restore REFUSE d'écraser un install existant NON VIDE sans `--force`, puis
    /// l'écrase quand `--force` est fourni.
    #[test]
    fn restore_without_force_refuses_to_clobber() {
        let src_dir = tmp_dir("forge-bk-clob-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-clob.age");
        let pass = "pw-clobber";
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");

        // install cible PRÉ-EXISTANT et NON VIDE.
        let to_dir = tmp_dir("forge-bk-clob-to");
        let to_db = format!("{to_dir}/forge.db");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        let sentinel = b"NE-PAS-ECRASER-existant".to_vec();
        std::fs::write(&to_db, &sentinel).unwrap();

        // sans --force -> REFUS, et la donnée existante est INTACTE.
        let err = run_restore(&RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: false, actor: "test".to_string(),
        }).expect_err("clobber refusé sans --force");
        assert!(err.contains("force") || err.contains("REFUSÉ"), "message anti-clobber: {err}");
        assert_eq!(std::fs::read(&to_db).unwrap(), sentinel, "install existant NON écrasé");

        // avec --force -> écrase.
        run_restore(&RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: true, actor: "test".to_string(),
        }).expect("--force autorise l'écrasement");
        assert_ne!(std::fs::read(&to_db).unwrap(), sentinel, "install écrasé avec --force");
        let dst = Connection::open(&to_db).unwrap();
        let n: i64 = dst.query_row("SELECT count(*) FROM finding", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "la base restaurée contient le finding source");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP perms] la clé `.ed25519` restaurée est en 0600 — MÊME si la clé source est plus
    /// permissive (0644). La clé de signature reste un secret non-lisible par autrui.
    #[cfg(unix)]
    #[test]
    fn restored_ed25519_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let src_dir = tmp_dir("forge-bk-perm-src");
        let (src_db, src_ledger, src_key) = seed_backup_source(&src_dir, 2);
        // clé source DÉLIBÉRÉMENT 0644 -> prouve que le restore FORCE 0600.
        std::fs::set_permissions(&src_key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let out = tmp_path("forge-bk-perm.age");
        let pass = "pw-perm";
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");

        let to_dir = tmp_dir("forge-bk-perm-to");
        let to_db = format!("{to_dir}/forge.db");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        run_restore(&RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db),
            ledger: Some(to_ledger.clone()), force: false, actor: "test".to_string(),
        }).expect("restore ok");
        let to_key = format!("{to_ledger}.ed25519");
        let mode = std::fs::metadata(&to_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "clé de signature restaurée en 0600");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP intégrité] un ledger source à la chaîne ROMPUE fait AVORTER le backup AVANT toute
    /// écriture d'archive.
    #[test]
    fn backup_aborts_on_tampered_ledger_chain() {
        let src_dir = tmp_dir("forge-bk-tamper-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 4);
        // altère le CONTENU d'une entrée sans recalculer son hash -> "hash recalculé != stocké".
        let tampered = std::fs::read_to_string(&src_ledger).unwrap().replacen("événement", "ALTÉRÉ", 1);
        std::fs::write(&src_ledger, tampered).unwrap();
        assert!(!verify_ledger_chain(&src_ledger).ok, "pré-condition : ledger détecté rompu");

        let out = tmp_path("forge-bk-tamper.age");
        let err = run_backup(&BackupOpts {
            out: out.clone(), passphrase: "pw".to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect_err("ledger rompu -> backup AVORTÉ");
        assert!(err.contains("AVORTÉ"), "message d'abort explicite: {err}");
        assert!(!std::path::Path::new(&out).exists(), "AUCUNE archive écrite sur abort");

        let _ = std::fs::remove_dir_all(&src_dir);
    }

    /// [BACKUP API gate] /api/backup, /api/restore, /api/backup/policy sont ADMIN-ONLY : viewer,
    /// operator et l'anonyme reçoivent 403 ; l'admin passe. Vérifie les handlers HTTP réels (check_admin).
    #[tokio::test]
    async fn backup_restore_policy_routes_are_admin_only_403() {
        let dir = tmp_dir("forge-bkapi-403");
        let (app, _db, _led, atok) = test_app_disk(&dir);
        let (vtok, _) = create_session(&app, uid_of(&app, "viw"));
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));
        let pbody = || Json(json!({"passphrase": "correct horse battery staple"}));

        // POST /api/backup : viewer/operator/anonyme -> 403.
        assert_eq!(api_backup(State(app.clone()), bearer_headers(&vtok), pbody()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup(State(app.clone()), bearer_headers(&otok), pbody()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup(State(app.clone()), HeaderMap::new(), pbody()).await.status(), StatusCode::FORBIDDEN);
        // admin -> 200 (téléchargement de l'archive chiffrée).
        assert_eq!(api_backup(State(app.clone()), bearer_headers(&atok), pbody()).await.status(), StatusCode::OK);

        // POST /api/restore : viewer/operator -> 403.
        let rbody = || Json(json!({"archive_b64": "AA==", "passphrase": "x"}));
        assert_eq!(api_restore(State(app.clone()), bearer_headers(&vtok), rbody()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_restore(State(app.clone()), bearer_headers(&otok), rbody()).await.status(), StatusCode::FORBIDDEN);

        // GET/POST /api/backup/policy : viewer/operator -> 403 ; admin -> 200.
        assert_eq!(api_backup_policy_get(State(app.clone()), bearer_headers(&vtok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup_policy_get(State(app.clone()), bearer_headers(&otok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup_policy_get(State(app.clone()), bearer_headers(&atok)).await.status(), StatusCode::OK);
        assert_eq!(
            api_backup_policy_set(State(app.clone()), bearer_headers(&vtok), Json(json!({"enabled": false}))).await.status(),
            StatusCode::FORBIDDEN
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [BACKUP API] POST /api/backup : passphrase manquante -> 400 (fail-closed) ; avec passphrase ->
    /// 200 + corps = archive CHIFFRÉE (magic FORGEBK1, déchiffrable) ; l'entrée ledger `console.backup`
    /// est écrite MAIS la passphrase n'apparaît JAMAIS dans le fichier ledger.
    #[tokio::test]
    async fn api_backup_downloads_encrypted_archive_and_never_ledgers_passphrase() {
        let dir = tmp_dir("forge-bkapi-dl");
        let (app, _db, ledger, atok) = test_app_disk(&dir);
        let secret_pass = "s3cr3t-passphrase-do-not-log-42";

        // passphrase absente -> 400.
        let r = api_backup(State(app.clone()), bearer_headers(&atok), Json(json!({}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "passphrase absente -> 400 fail-closed");

        // avec passphrase -> 200 + archive chiffrée téléchargeable.
        let r = api_backup(State(app.clone()), bearer_headers(&atok), Json(json!({"passphrase": secret_pass}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let disp = r.headers().get("content-disposition").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(disp.contains("attachment") && disp.contains("forge-backup-"), "Content-Disposition de téléchargement: {disp}");
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[0..8], BACKUP_MAGIC, "corps = archive chiffrée (magic FORGEBK1)");
        assert!(backup_decrypt(&body, secret_pass).is_ok(), "archive déchiffrable avec la bonne passphrase");
        assert!(backup_decrypt(&body, "mauvaise").is_err(), "mauvaise passphrase -> tag AEAD invalide");

        // le ledger contient `console.backup` MAIS jamais la passphrase.
        let ledger_txt = std::fs::read_to_string(&ledger).unwrap();
        assert!(ledger_txt.contains("console.backup"), "l'action backup est ledgerisée");
        assert!(!ledger_txt.contains(secret_pass), "la passphrase n'apparaît JAMAIS dans le ledger");
        assert!(verify_ledger_chain(&ledger).ok, "chaîne du ledger intacte après backup via API");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [RESTORE API] chemins de sûreté : (a) validation par défaut (apply absent) NE réécrit RIEN et
    /// répond applied:false ; (b) apply=true SANS confirm -> 400 (confirmation requise), rien écrit ;
    /// (c) mauvaise passphrase -> 422 propre + ledger `console.restore.validate` ok:false SANS la
    /// passphrase ; (d) apply=true+confirm=true -> swap effectué, restart_required:true.
    #[tokio::test]
    async fn api_restore_validate_default_confirm_required_and_apply() {
        let src_dir = tmp_dir("forge-rsapi-src");
        let (app, db_path, ledger, atok) = test_app_disk(&src_dir);
        let secret_pass = "restore-pass-never-logged-99";

        // fabrique une VRAIE archive chiffrée à partir de la source disque.
        let arch = tmp_path("forge-rsapi.forge");
        run_backup(&BackupOpts {
            out: arch.clone(), passphrase: secret_pass.to_string(), db: db_path.clone(),
            ledger: Some(ledger.clone()), ts: Some("@1000".into()), actor: "test".into(),
        }).expect("backup source");
        let archive_b64 = base64::engine::general_purpose::STANDARD.encode(std::fs::read(&arch).unwrap());

        // (a) validation par défaut : 200 applied:false, aucune écriture destructive.
        let db_before = std::fs::read(&db_path).unwrap();
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": secret_pass}))).await;
        assert_eq!(r.status(), StatusCode::OK, "validation par défaut -> 200");
        let j = resp_json(r).await;
        assert_eq!(j["applied"], false, "validation par défaut n'applique RIEN");
        assert_eq!(j["validated"]["ok"], true, "archive validée");
        assert_eq!(std::fs::read(&db_path).unwrap(), db_before, "base LIVE inchangée par la validation");

        // (b) apply sans confirm -> 400.
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": secret_pass, "apply": true}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "apply sans confirm -> 400");
        assert_eq!(std::fs::read(&db_path).unwrap(), db_before, "base LIVE inchangée sans confirm");

        // (c) mauvaise passphrase -> 422 + trace validate ok:false, jamais la passphrase.
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": "WRONG"}))).await;
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY, "mauvaise passphrase -> 422");
        let ledger_txt = std::fs::read_to_string(&ledger).unwrap();
        assert!(ledger_txt.contains("console.restore.validate"), "tentative de restore ledgerisée");
        assert!(!ledger_txt.contains(secret_pass), "la passphrase n'apparaît JAMAIS dans le ledger");
        assert!(!ledger_txt.contains("WRONG"), "la passphrase (même erronée) n'est jamais ledgerisée");

        // (d) apply=true+confirm=true -> swap effectué, redémarrage requis annoncé.
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": secret_pass, "apply": true, "confirm": true}))).await;
        assert_eq!(r.status(), StatusCode::OK, "apply+confirm -> 200");
        let j = resp_json(r).await;
        assert_eq!(j["applied"], true, "swap appliqué");
        assert_eq!(j["restart_required"], true, "redémarrage requis annoncé (base live tenue par la connexion)");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&arch);
    }

    /// [POLICY API] round-trip d'une politique (schedule/rétention/offsite) + RÉDACTION : un GET ne
    /// renvoie JAMAIS un secret (champ secretish rédigé), mais conserve `passphrase_env` (un NOM d'ENV).
    #[tokio::test]
    async fn backup_policy_round_trips_and_get_redacts_secrets() {
        let dir = tmp_dir("forge-pol-rt");
        let (app, _db, _led, atok) = test_app_disk(&dir);

        // POST : politique complète, avec un secret inline dans offsite exec (doit être rédigé au GET).
        let policy = json!({
            "enabled": true,
            "interval_secs": 3600,
            "retention": 7,
            "passphrase_env": "FORGE_BACKUP_PASSPHRASE",
            "staging_dir": format!("{dir}/staging"),
            "offsite": {"kind": "exec", "program": "/usr/bin/rclone",
                        "args": ["copy", "{archive}", "remote:forge/"], "token": "SUPER-SECRET-TOKEN"}
        });
        let r = api_backup_policy_set(State(app.clone()), bearer_headers(&atok), Json(policy)).await;
        assert_eq!(r.status(), StatusCode::OK, "politique valide enregistrée");

        // GET : round-trip des champs non-secrets + rédaction du secret.
        let r = api_backup_policy_get(State(app.clone()), bearer_headers(&atok)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let j = resp_json(r).await;
        let p = &j["policy"];
        assert_eq!(p["enabled"], true);
        assert_eq!(p["interval_secs"], 3600);
        assert_eq!(p["retention"], 7);
        assert_eq!(p["passphrase_env"], "FORGE_BACKUP_PASSPHRASE", "le NOM d'ENV n'est PAS un secret -> conservé");
        assert_eq!(p["offsite"]["kind"], "exec");
        assert_eq!(p["offsite"]["program"], "/usr/bin/rclone");
        assert_eq!(p["offsite"]["token"], "***REDACTED***", "tout champ secretish est RÉDIGÉ au GET");
        assert_eq!(j["configured"], true);

        // la valeur PERSISTÉE ne contient jamais de `passphrase` en clair (seul passphrase_env).
        let stored = { let db = app.db(); settings_get(&db, "backup_policy").unwrap() };
        assert!(!stored.contains("\"passphrase\""), "aucun `passphrase` en clair persisté");
        assert!(stored.contains("FORGE_BACKUP_PASSPHRASE"), "passphrase_env persisté");

        // politique invalide : enabled sans interval -> 400, rien n'est écrasé.
        let r = api_backup_policy_set(State(app.clone()), bearer_headers(&atok),
            Json(json!({"enabled": true, "passphrase_env": "X"}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "enabled sans interval -> 400");
        // offsite kind inconnu -> 400.
        let r = api_backup_policy_set(State(app.clone()), bearer_headers(&atok),
            Json(json!({"enabled": false, "offsite": {"kind": "ftp"}}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "offsite kind hors none/local_dir/exec -> 400");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [POLICY] validate_backup_policy : fail-closed (interval/passphrase_env requis si enabled ;
    /// exec program absolu). redact_backup_policy : rédige un secret, conserve `*_env`.
    #[test]
    fn backup_policy_validation_and_redaction_units() {
        // enabled sans interval -> Err.
        assert!(validate_backup_policy(&json!({"enabled": true, "passphrase_env": "P"})).is_err());
        // enabled sans passphrase_env -> Err.
        assert!(validate_backup_policy(&json!({"enabled": true, "interval_secs": 60})).is_err());
        // exec program relatif -> Err (pas de résolution PATH).
        assert!(validate_backup_policy(&json!({"enabled": false, "offsite": {"kind": "exec", "program": "rclone"}})).is_err());
        // valide : disabled + offsite none.
        assert!(validate_backup_policy(&json!({"enabled": false, "offsite": {"kind": "none"}})).is_ok());
        // le `passphrase` en clair est RETIRÉ à la persistance.
        let clean = validate_backup_policy(&json!({"enabled": false, "passphrase": "LEAK"})).unwrap();
        assert!(clean.get("passphrase").is_none(), "passphrase en clair jamais persistée");
        // rédaction.
        let red = redact_backup_policy(&json!({"passphrase_env": "P", "secret": "S", "offsite": {"token": "T", "kind": "exec"}}));
        assert_eq!(red["passphrase_env"], "P", "NOM d'ENV conservé");
        assert_eq!(red["secret"], "***REDACTED***");
        assert_eq!(red["offsite"]["token"], "***REDACTED***", "rédaction récursive");
        assert_eq!(red["offsite"]["kind"], "exec", "champ non-secret conservé");
    }

    /// [SCHEDULER] run_scheduled_backup : avec une politique activée + une passphrase via ENV + un offsite
    /// local_dir, crée une archive CHIFFRÉE dans le staging, la copie offsite, ledgerise (scheduled +
    /// offsite) et NE FUITE JAMAIS la passphrase. Passphrase ENV absente -> Err (fail-closed, pas de
    /// crash). Politique désactivée -> skip.
    #[test]
    fn scheduled_backup_encrypts_ships_local_dir_and_never_leaks_passphrase() {
        let _g = env_lock(); // ENV process-global
        let dir = tmp_dir("forge-sched");
        let (app, _db, ledger, _atok) = test_app_disk(&dir);
        let staging = format!("{dir}/staging");
        let offsite_dir = format!("{dir}/offsite");
        let pass_env = "FORGE_TEST_SCHED_PASS";
        let secret_pass = "scheduled-pass-shh-77";

        {
            let db = app.db();
            settings_set(&db, "backup_policy", &json!({
                "enabled": true, "interval_secs": 1, "retention": 2,
                "passphrase_env": pass_env, "staging_dir": staging,
                "offsite": {"kind": "local_dir", "dir": offsite_dir}
            }).to_string()).unwrap();
        }

        // (a) passphrase ENV absente -> Err (fail-closed), aucune archive, pas de crash.
        std::env::remove_var(pass_env);
        assert!(run_scheduled_backup(&app).is_err(), "passphrase ENV absente -> fail-closed");

        // (b) passphrase ENV posée -> backup + offsite.
        std::env::set_var(pass_env, secret_pass);
        let rep = run_scheduled_backup(&app).expect("backup programmé réussit");
        std::env::remove_var(pass_env);
        assert_eq!(rep["ok"], true);

        // une archive chiffrée dans le staging (magic + déchiffrable).
        let staged: Vec<_> = std::fs::read_dir(&staging).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".forge")).collect();
        assert_eq!(staged.len(), 1, "une archive dans le staging");
        let raw = std::fs::read(staged[0].path()).unwrap();
        assert_eq!(&raw[0..8], BACKUP_MAGIC, "archive chiffrée");
        assert!(backup_decrypt(&raw, secret_pass).is_ok(), "déchiffrable avec la passphrase ENV");

        // l'archive a été copiée offsite (local_dir).
        let shipped: Vec<_> = std::fs::read_dir(&offsite_dir).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".forge")).collect();
        assert_eq!(shipped.len(), 1, "archive expédiée dans l'offsite local_dir");

        // ledger : entrées scheduled + offsite, jamais la passphrase.
        let ltxt = std::fs::read_to_string(&ledger).unwrap();
        assert!(ltxt.contains("console.backup.scheduled"), "backup programmé ledgerisé");
        assert!(ltxt.contains("console.backup.offsite"), "expédition offsite ledgerisée");
        assert!(!ltxt.contains(secret_pass), "la passphrase n'apparaît JAMAIS dans le ledger");
        assert!(verify_ledger_chain(&ledger).ok, "chaîne du ledger intacte");

        // (c) politique désactivée -> skip (aucune erreur).
        { let db = app.db(); settings_set(&db, "backup_policy", &json!({"enabled": false}).to_string()).unwrap(); }
        let rep = run_scheduled_backup(&app).expect("désactivée -> Ok");
        assert_eq!(rep["skipped"], true, "politique désactivée -> skip");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [SCHEDULER] scheduled_backup_due : dû si activé + interval écoulé depuis backup_last_run ;
    /// jamais dû si désactivé ou interval=0. Rétention : conserve les N plus récentes.
    #[test]
    fn scheduled_due_gate_and_retention() {
        let dir = tmp_dir("forge-sched-due");
        let (app, _db, _led, _atok) = test_app_disk(&dir);
        {
            let db = app.db();
            assert!(!scheduled_backup_due(&db), "aucune politique -> pas dû");
            settings_set(&db, "backup_policy", &json!({"enabled": true, "interval_secs": 3600, "passphrase_env": "P"}).to_string()).unwrap();
            settings_set(&db, "backup_last_run", &chrono_now_compact()).unwrap();
            assert!(!scheduled_backup_due(&db), "dernière exécution à l'instant -> pas encore dû");
            settings_set(&db, "backup_last_run", "0").unwrap();
            assert!(scheduled_backup_due(&db), "last_run très ancien -> dû");
            settings_set(&db, "backup_policy", &json!({"enabled": false}).to_string()).unwrap();
            assert!(!scheduled_backup_due(&db), "désactivé -> jamais dû");
        }
        // rétention : 4 archives, keep=2 -> 2 restent.
        let ret = format!("{dir}/ret");
        std::fs::create_dir_all(&ret).unwrap();
        for i in 0..4 {
            std::fs::write(format!("{ret}/forge-backup-{i}.forge"), format!("a{i}")).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(15)); // mtimes distinctes
        }
        apply_backup_retention(&ret, 2);
        let left = std::fs::read_dir(&ret).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".forge")).count();
        assert_eq!(left, 2, "rétention conserve exactement les 2 plus récentes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [OFFSITE exec] ship_offsite exec : argv fixe (aucun shell), token `{archive}` substitué ; un
    /// programme qui sort en échec -> Err ; un timeout tue le process (Err). Le succès renvoie shipped:true.
    #[test]
    fn offsite_exec_no_shell_success_failure_and_timeout() {
        let dir = tmp_dir("forge-offx");
        let arch = format!("{dir}/a.forge");
        std::fs::write(&arch, b"payload").unwrap();
        // succès : /bin/cp {archive} -> {dir}/copied.forge (argv fixe, aucun shell).
        let dst = format!("{dir}/copied.forge");
        let r = ship_offsite(&json!({"kind": "exec", "program": "/bin/cp", "args": ["{archive}", dst]}), &arch);
        assert!(r.is_ok(), "cp argv fixe -> succès: {r:?}");
        assert!(std::path::Path::new(&dst).exists(), "token archive substitué -> fichier copié");
        // échec : /bin/false -> code != 0 -> Err.
        assert!(ship_offsite(&json!({"kind": "exec", "program": "/bin/false", "args": []}), &arch).is_err(),
            "exit code != 0 -> Err");
        // timeout : /bin/sleep 5 avec timeout_secs=1 -> Err (process tué).
        let r = ship_offsite(&json!({"kind": "exec", "program": "/bin/sleep", "args": ["5"], "timeout_secs": 1}), &arch);
        assert!(r.is_err() && r.unwrap_err().contains("timeout"), "dépassement -> tué + Err");
        // none -> no-op.
        assert_eq!(ship_offsite(&json!({"kind": "none"}), &arch).unwrap()["shipped"], false);
        let _ = std::fs::remove_dir_all(&dir);
    }

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — tests d'intégration du CHIFFREMENT DE CHAMP AU REPOS (`field_crypto`), au niveau où
//! il compte : le FICHIER SQLITE SUR DISQUE, la MIGRATION d'une base héritée, et le ROUND-TRIP de
//! SAUVEGARDE par-dessus.
//!
//! POURQUOI CES TESTS ET PAS UN SIMPLE ALLER-RETOUR D'API : un test qui chiffre puis déchiffre par
//! l'API prouverait seulement que le chiffrement est symétrique — pas que le disque est illisible. La
//! seule preuve qui vaille est d'écrire un CANARI par le chemin de production, puis de relire le
//! FICHIER EN OCTETS et de constater que le canari n'y est pas. Chaque test ci-dessous porte donc son
//! CONTRE-EXEMPLE : la même sonde, sur la même base, DÉTECTE le clair quand il y en a — sans quoi une
//! assertion « le canari est absent » pourrait passer au vert pour de mauvaises raisons.
use super::*;
use crate::testutil::*;

/// Ouvre une base SQLite SUR FICHIER au schéma de PRODUCTION (SCHEMA + migrate, comme le boot).
fn file_db(path: &str) -> Connection {
    let conn = Connection::open(path).expect("open file db");
    conn.execute_batch(SCHEMA).expect("schema");
    migrate(&conn);
    conn
}

/// Concatène TOUS les artefacts sur disque de la base (fichier principal + `-wal` + `-shm`). Le WAL
/// compte : une valeur peut n'exister que là. Ne rien en lire donnerait une preuve d'illisibilité
/// FAUSSEMENT rassurante.
fn on_disk_bytes(path: &str) -> Vec<u8> {
    let mut all = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        if let Ok(b) = std::fs::read(format!("{path}{suffix}")) {
            all.extend_from_slice(&b);
        }
    }
    all
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Scope armé de référence : trois canaris, un par forme de matériel (bearer, valeur d'en-tête,
/// cookies), plus de la config non secrète qui, elle, DOIT rester lisible.
fn armed_scope(bearer: &str, hdr: &str, cookie: &str) -> Value {
    json!({
        "mode": "grey", "in_scope": ["app.test"], "out_scope": [],
        "auth": {
            "accounts": [
                {"label": "attacker", "bearer": bearer, "headers": {"X-CSRF": hdr}},
                {"label": "victim", "cookies": format!("sid={cookie}")}
            ],
            "idor_targets": [{"url": "https://app.test/api/orders/1", "owner": "victim", "marker": "MK-1"}]
        }
    })
}

/// [PREUVE D'ILLISIBILITÉ SUR DISQUE] Le matériel d'authentification écrit par le CHEMIN DE PRODUCTION
/// (`validate_engagement_scope` -> INSERT) n'apparaît NULLE PART dans les octets du fichier SQLite.
///
/// CONTRE-EXEMPLE INTÉGRÉ (ce qui rend le test non vacuous) : la MÊME sonde, sur la MÊME base, TROUVE
/// les canaris quand la même valeur est écrite SANS scellement. Si un jour le scellement disparaît, ce
/// test rougit ; si la sonde cesse de fonctionner, le contre-exemple rougit.
/// MUTATION-PROVABLE : retirer `seal_auth_block` de `validate_engagement_scope` -> ROUGE immédiat.
#[test]
fn auth_material_is_absent_from_the_sqlite_file_on_disk() {
    const KEY: &str = "cle-de-champ-preuve-disque";
    const BEARER: &str = "DISK-CANARY-BEARER-a1b2";
    const HDR: &str = "DISK-CANARY-HEADER-c3d4";
    const COOKIE: &str = "DISK-CANARY-COOKIE-e5f6";
    let path = tmp_path("forge-fieldcrypto-disk.db");

    {
        let conn = file_db(&path);
        // (1) CHEMIN DE PRODUCTION — le scope est canonicalisé (donc SCELLÉ) puis persisté.
        let (canon, mode) = validate_engagement_scope(&armed_scope(BEARER, HDR, COOKIE), Some(KEY))
            .expect("scope armé valide");
        conn.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(70,'arme','active',?,?,'',datetime('now'),datetime('now'))",
            rusqlite::params![mode, canon],
        )
        .unwrap();
    } // fermeture = tout est poussé sur le disque

    let bytes = on_disk_bytes(&path);
    assert!(!bytes.is_empty(), "le fichier de base doit exister et être non vide");
    for canary in [BEARER, HDR, COOKIE] {
        assert!(
            !contains(&bytes, canary),
            "MATÉRIEL D'AUTHENTIFICATION LISIBLE SUR DISQUE : '{canary}' trouvé dans {path}"
        );
    }
    // La structure NON secrète, elle, reste lisible sur disque (l'éditeur doit pouvoir la ré-afficher
    // sans la clé) — c'est le périmètre MESURÉ du chiffrement, pas un chiffrement « de tout ».
    assert!(contains(&bytes, "attacker"), "les LABELS restent en clair (l'éditeur en a besoin)");
    assert!(contains(&bytes, "X-CSRF"), "les NOMS d'en-têtes restent en clair (non secrets)");
    assert!(contains(&bytes, "MK-1"), "les cibles idor restent en clair (config déjà re-servie par l'API)");

    // (2) CONTRE-EXEMPLE — la sonde DÉTECTE bien le clair quand il y en a. Sans ceci, l'assertion
    //     ci-dessus pourrait passer au vert parce que la sonde ne sait rien lire du tout.
    {
        let conn = Connection::open(&path).expect("réouverture");
        conn.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(71,'en-clair','active','grey',?,'',datetime('now'),datetime('now'))",
            rusqlite::params![armed_scope(BEARER, HDR, COOKIE).to_string()],
        )
        .unwrap();
    }
    let bytes = on_disk_bytes(&path);
    for canary in [BEARER, HDR, COOKIE] {
        assert!(
            contains(&bytes, canary),
            "CONTRE-EXEMPLE EN ÉCHEC : la sonde disque ne détecte pas '{canary}' pourtant écrit en clair — \
             l'assertion d'illisibilité ci-dessus ne prouverait alors RIEN"
        );
    }
    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{s}"));
    }
}

/// [MIGRATION D'UNE BASE HÉRITÉE] Une base écrite AVANT cette version porte le matériel EN CLAIR. La
/// passe de boot le SCELLE EN PLACE, idempotemment, et le canari disparaît DU FICHIER. Sans clé, rien
/// n'est converti mais l'état est COMPTÉ et ANNONCÉ — jamais tu, jamais maquillé en « chiffré ».
/// MUTATION-PROVABLE : neutraliser l'UPDATE de `migrate_seal_engagement_auth` -> le canari reste sur
/// disque -> ROUGE.
#[test]
fn legacy_plaintext_rows_are_sealed_in_place_at_boot() {
    const KEY: &str = "cle-de-champ-migration";
    const BEARER: &str = "LEGACY-CANARY-BEARER-9z";
    const HDR: &str = "LEGACY-CANARY-HEADER-8y";
    const COOKIE: &str = "LEGACY-CANARY-COOKIE-7x";
    let path = tmp_path("forge-fieldcrypto-migrate.db");
    let app = test_app_on_file(&path);

    // Base « héritée » : le scope_json est écrit EN CLAIR, comme le faisait la version précédente.
    app.db()
        .execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(80,'legacy','active','grey',?,'',datetime('now'),datetime('now'))",
            rusqlite::params![armed_scope(BEARER, HDR, COOKIE).to_string()],
        )
        .unwrap();
    // ... et un engagement SANS matériel : il ne doit JAMAIS être compté ni touché.
    app.db()
        .execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(81,'nu','active','grey','{\"mode\":\"grey\",\"in_scope\":[],\"out_scope\":[]}','',datetime('now'),datetime('now'))",
            [],
        )
        .unwrap();

    // (a) SANS CLÉ : rien n'est converti, mais le clair est COMPTÉ et l'annonce de boot le CRIE.
    let rep = crate::field_crypto::migrate_seal_engagement_auth(&app.store(), None);
    assert_eq!(rep.with_material, 1, "seul l'engagement armé est compté");
    assert_eq!(rep.sealed_now, 0);
    assert_eq!(rep.still_plaintext, 1, "le clair restant est COMPTÉ, jamais tu");
    let line = crate::field_crypto::boot_status_line(&rep, false).expect("annonce de boot obligatoire");
    assert!(line.contains("EN CLAIR"), "l'annonce nomme le problème: {line}");
    assert!(line.contains(crate::field_crypto::KEY_VAR), "l'annonce nomme la variable à poser: {line}");

    // (b) AVEC CLÉ : conversion en place, et le canari QUITTE le fichier.
    let rep = crate::field_crypto::migrate_seal_engagement_auth(&app.store(), Some(KEY));
    assert_eq!((rep.with_material, rep.sealed_now, rep.still_plaintext), (1, 1, 0));
    let stored: String = app
        .db()
        .query_row("SELECT scope_json FROM engagement WHERE id=80", [], |r| r.get(0))
        .unwrap();
    for canary in [BEARER, HDR, COOKIE] {
        assert!(!stored.contains(canary), "'{canary}' encore en clair après migration");
    }
    // le matériel reste EXPLOITABLE (la migration ne détruit rien — elle chiffre)
    let auth: Value = serde_json::from_str::<Value>(&stored).unwrap()["auth"].clone();
    let open = crate::field_crypto::unseal_auth_block(&auth, Some(KEY)).expect("ouverture post-migration");
    assert_eq!(open["accounts"][0]["bearer"], json!(BEARER), "valeur intacte après migration");
    assert_eq!(open["accounts"][1]["cookies"], json!(format!("sid={COOKIE}")));

    // (c) IDEMPOTENCE : rejouée (chaque boot), la passe ne re-chiffre RIEN et ne compte plus de clair.
    let before = stored.clone();
    let rep = crate::field_crypto::migrate_seal_engagement_auth(&app.store(), Some(KEY));
    assert_eq!((rep.with_material, rep.sealed_now, rep.still_plaintext), (1, 0, 0), "2e passe = no-op");
    let after: String = app
        .db()
        .query_row("SELECT scope_json FROM engagement WHERE id=80", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after, "aucun ré-chiffrement (donc aucun churn d'écriture à chaque boot)");
    // l'engagement NU n'a jamais été touché ni compté
    assert_eq!(crate::field_crypto::at_rest_label(&json!({"accounts": [], "idor_targets": []})), "none");

    drop(app);
    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{s}"));
    }
}

/// [SAUVEGARDE — les deux couches composent] Une base à CHAMPS CHIFFRÉS doit rester RESTAURABLE. On
/// fait le round-trip complet de l'archive (tar -> chiffrement d'archive -> déchiffrement -> extraction)
/// et on vérifie qu'après restauration le matériel s'ouvre TOUJOURS avec la clé de champ.
///
/// Les deux secrets sont INDÉPENDANTS : la passphrase d'archive protège le transport/l'entreposage,
/// la clé de champ protège le contenu. Restaurer avec la bonne passphrase mais SANS la clé de champ
/// rend une base intacte dont le matériel reste scellé — ce qui est exactement le comportement voulu
/// (et documenté en garde de custody : les DEUX secrets doivent être conservés).
#[test]
fn field_sealed_database_survives_the_encrypted_backup_round_trip() {
    const FIELD_KEY: &str = "cle-de-champ-backup";
    const ARCHIVE_PW: &str = "passphrase-archive-backup";
    const BEARER: &str = "BACKUP-CANARY-BEARER-4k";
    let src = tmp_path("forge-fieldcrypto-backup-src.db");
    let dst = tmp_path("forge-fieldcrypto-backup-dst.db");

    {
        let conn = file_db(&src);
        let (canon, mode) = validate_engagement_scope(&armed_scope(BEARER, "H", "C"), Some(FIELD_KEY)).unwrap();
        conn.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(90,'arme','active',?,?,'',datetime('now'),datetime('now'))",
            rusqlite::params![mode, canon],
        )
        .unwrap();
    }

    // ARCHIVE : tar (pur Rust) -> XChaCha20-Poly1305 + argon2id. Une archive n'existe JAMAIS en clair.
    let db_bytes = std::fs::read(&src).expect("lecture de la base source");
    let tar = crate::backup_build_tar(&[(crate::backup_crypto::BACKUP_ENTRY_DB, &db_bytes)]).expect("tar");
    let archive = crate::backup_encrypt(&tar, ARCHIVE_PW).expect("chiffrement d'archive");
    assert!(
        !contains(&archive, BEARER),
        "l'archive elle-même ne porte évidemment aucun clair (double couche)"
    );

    // RESTAURATION
    let plain_tar = crate::backup_decrypt(&archive, ARCHIVE_PW).expect("déchiffrement d'archive");
    let entries = crate::backup_extract_tar(&plain_tar).expect("extraction");
    let (_, restored) = entries
        .into_iter()
        .find(|(n, _)| n == crate::backup_crypto::BACKUP_ENTRY_DB)
        .expect("entrée db.sqlite");
    std::fs::write(&dst, &restored).expect("écriture de la base restaurée");

    // La base restaurée est fonctionnelle ET son matériel s'ouvre encore avec la clé de CHAMP.
    let conn = Connection::open(&dst).expect("ouverture de la base restaurée");
    let scope: String = conn
        .query_row("SELECT scope_json FROM engagement WHERE id=90", [], |r| r.get(0))
        .expect("engagement restauré");
    assert!(!scope.contains(BEARER), "le champ reste scellé APRÈS restauration");
    let auth: Value = serde_json::from_str::<Value>(&scope).unwrap()["auth"].clone();
    let open = crate::field_crypto::unseal_auth_block(&auth, Some(FIELD_KEY)).expect("ouverture post-restore");
    assert_eq!(open["accounts"][0]["bearer"], json!(BEARER), "round-trip complet: sauvegarde + champ");
    // ... et SANS la clé de champ, la base est intacte mais le matériel reste FERMÉ (fail-closed).
    assert!(crate::field_crypto::unseal_auth_block(&auth, None).is_err(), "les DEUX secrets sont requis");

    drop(conn);
    for p in [&src, &dst] {
        for s in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{p}{s}"));
        }
    }
}

// =================================================================================================
//  SECRETS D'INTÉGRATION (source de détection / canal de notification / client_secret SSO)
//
//  Ces trois-là étaient les DERNIERS credentials vivants encore EN CLAIR au repos. Ils avaient été
//  écartés du premier lot pour une raison technique réelle : les sceller EXIGEAIT de rendre leurs
//  chemins de lecture FAILLIBLES — `sso::load_config` rendait un `Option`, où un déchiffrement échoué
//  se serait présenté comme « SSO non configuré ». L'ordre suivi a donc été : d'abord la faillibilité
//  avec un échec LISIBLE, ensuite le scellement. Les tests ci-dessous mesurent les DEUX moitiés.
// =================================================================================================

/// Les trois configs d'intégration, chacune avec son canari, telles qu'un admin les pose.
fn integration_configs(ds: &str, ch: &str, sso: &str) -> Vec<(&'static str, &'static [&'static str], Value)> {
    vec![
        (
            "detection_source",
            crate::field_crypto::DS_SECRET_PATH,
            json!({"kind": "generic_http", "endpoint": "https://siem.example/api/alerts",
                   "auth": {"type": "bearer", "secret": ds}}),
        ),
        (
            "notify_channel",
            crate::field_crypto::CH_SECRET_PATH,
            json!({"kind": "webhook", "enabled": true, "endpoint": "https://hooks.example/x",
                   "auth": {"type": "bearer", "secret": ch}}),
        ),
        (
            "sso.config",
            crate::field_crypto::SSO_SECRET_PATH,
            json!({"issuer": "https://idp.example", "client_id": "forge-console",
                   "client_secret": sso, "redirect_uri": "https://console.example/api/sso/callback"}),
        ),
    ]
}

/// [PREUVE D'ILLISIBILITÉ SUR DISQUE] Aucun des trois secrets d'intégration n'apparaît dans les octets
/// du fichier SQLite quand il est écrit par le chemin de production (scellement AVANT persistance).
///
/// CONTRE-EXEMPLE INTÉGRÉ (ce qui rend le test non vacuous) : la MÊME sonde, sur la MÊME base, TROUVE
/// les canaris quand les mêmes valeurs sont écrites SANS scellement. Si le scellement disparaît, ce test
/// rougit ; si la sonde cesse de fonctionner, le contre-exemple rougit.
/// MUTATION-PROVABLE : retirer `seal_config_secret` du chemin d'écriture -> ROUGE immédiat.
#[test]
fn integration_secrets_are_absent_from_the_sqlite_file_on_disk() {
    const KEY: &str = "cle-de-champ-integrations-disque";
    const DS: &str = "DISK-CANARY-DS-SECRET-q1w2";
    const CH: &str = "DISK-CANARY-CH-SECRET-e3r4";
    const SSO: &str = "DISK-CANARY-SSO-SECRET-t5y6";
    let path = tmp_path("forge-fieldcrypto-settings-disk.db");

    {
        let app = test_app_on_file(&path);
        for (skey, field, cfg) in integration_configs(DS, CH, SSO) {
            // CHEMIN DE PRODUCTION : la config est SCELLÉE puis persistée (exactement ce que font
            // `detection_source_set`, `channel_set` et `sso::config_set`).
            let sealed = crate::field_crypto::seal_config_secret(&cfg, field, Some(KEY)).expect("scellement");
            crate::settings_set_store(&app.store(), skey, &sealed.to_string()).expect("persistance");
        }
        drop(app); // fermeture = tout est poussé sur le disque
    }

    let bytes = on_disk_bytes(&path);
    assert!(!bytes.is_empty(), "le fichier de base doit exister et être non vide");
    for canary in [DS, CH, SSO] {
        assert!(!contains(&bytes, canary), "SECRET D'INTÉGRATION LISIBLE SUR DISQUE : '{canary}' dans {path}");
    }
    // Le NON-SECRET reste lisible : l'admin doit pouvoir ré-éditer sa config sans la clé. C'est le
    // périmètre MESURÉ du chiffrement, pas un chiffrement « de tout ».
    assert!(contains(&bytes, "siem.example"), "l'endpoint (non secret) reste lisible");
    assert!(contains(&bytes, "forge-console"), "le client_id (non secret) reste lisible");
    assert!(contains(&bytes, "bearer"), "le TYPE d'auth (non secret) reste lisible");

    // CONTRE-EXEMPLE — la sonde DÉTECTE bien le clair quand il y en a.
    {
        let app = test_app_on_file(&path);
        for (skey, _, cfg) in integration_configs(DS, CH, SSO) {
            crate::settings_set_store(&app.store(), &format!("{skey}.enclair"), &cfg.to_string()).unwrap();
        }
        drop(app);
    }
    let bytes = on_disk_bytes(&path);
    for canary in [DS, CH, SSO] {
        assert!(
            contains(&bytes, canary),
            "CONTRE-EXEMPLE EN ÉCHEC : la sonde disque ne détecte pas '{canary}' pourtant écrit en clair — \
             l'assertion d'illisibilité ci-dessus ne prouverait alors RIEN"
        );
    }
    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{s}"));
    }
}

/// [MIGRATION D'UNE BASE HÉRITÉE] Les configs d'intégration écrites AVANT cette version portent leur
/// secret EN CLAIR. La passe de boot les SCELLE EN PLACE, idempotemment. Sans clé, rien n'est converti
/// mais l'état est COMPTÉ et ANNONCÉ — jamais tu, jamais maquillé en « chiffré ».
///
/// MUTATION-PROVABLE : neutraliser l'écriture de `migrate_seal_settings_secrets` -> le canari reste en
/// clair dans la colonne -> ROUGE.
#[test]
fn legacy_integration_secrets_are_sealed_in_place_at_boot() {
    const KEY: &str = "cle-de-champ-migration-integrations";
    const DS: &str = "LEGACY-DS-CANARY-a1";
    const CH: &str = "LEGACY-CH-CANARY-b2";
    const SSO: &str = "LEGACY-SSO-CANARY-c3";
    let path = tmp_path("forge-fieldcrypto-settings-migrate.db");
    let app = test_app_on_file(&path);

    // Base « héritée » : les trois configs sont écrites EN CLAIR, comme le faisait la version d'avant.
    for (skey, _, cfg) in integration_configs(DS, CH, SSO) {
        crate::settings_set_store(&app.store(), skey, &cfg.to_string()).unwrap();
    }
    // ... plus une config SANS secret : elle ne doit JAMAIS être comptée ni touchée.
    crate::settings_set_store(&app.store(), "notify_channel.vide", &json!({"kind": "none"}).to_string()).unwrap();

    // (a) SANS CLÉ : rien n'est converti, mais le clair est COMPTÉ et l'annonce de boot le CRIE.
    let rep = crate::field_crypto::migrate_seal_settings_secrets(&app.store(), None);
    assert_eq!(rep.with_material, 3, "les trois configs à secret sont comptées");
    assert_eq!((rep.sealed_now, rep.still_plaintext), (0, 3), "le clair restant est COMPTÉ, jamais tu");
    let line = crate::field_crypto::settings_boot_status_line(&rep, false).expect("annonce de boot obligatoire");
    assert!(line.contains("EN CLAIR"), "l'annonce nomme le problème: {line}");
    assert!(line.contains(crate::field_crypto::KEY_VAR), "l'annonce nomme la variable à poser: {line}");

    // (b) AVEC CLÉ : conversion en place, le canari QUITTE la colonne, la valeur reste EXPLOITABLE.
    let rep = crate::field_crypto::migrate_seal_settings_secrets(&app.store(), Some(KEY));
    assert_eq!((rep.with_material, rep.sealed_now, rep.still_plaintext), (3, 3, 0));
    for ((skey, field, _), canary) in integration_configs(DS, CH, SSO).into_iter().zip([DS, CH, SSO]) {
        let stored = crate::settings_get_store(&app.store(), skey).expect("ligne présente");
        assert!(!stored.contains(canary), "'{canary}' encore en clair après migration : {stored}");
        let v: Value = serde_json::from_str(&stored).unwrap();
        assert!(crate::field_crypto::is_sealed(&crate::field_crypto::config_field_raw(&v, field)), "enveloppe attendue");
        let opened = crate::field_crypto::open_config_secret(&v, field, Some(KEY)).expect("ouverture post-migration");
        assert_eq!(crate::field_crypto::config_field_raw(&opened, field), canary, "valeur intacte après migration");
    }

    // (c) IDEMPOTENCE : rejouée à chaque boot, la passe ne re-chiffre RIEN (aucun churn d'écriture).
    let before = crate::settings_get_store(&app.store(), "detection_source").unwrap();
    let rep = crate::field_crypto::migrate_seal_settings_secrets(&app.store(), Some(KEY));
    assert_eq!((rep.with_material, rep.sealed_now, rep.still_plaintext), (3, 0, 0), "2e passe = no-op");
    assert_eq!(before, crate::settings_get_store(&app.store(), "detection_source").unwrap(), "aucun ré-chiffrement");

    drop(app);
    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{s}"));
    }
}

/// [FAILLIBILITÉ — LA MOITIÉ QUI DEVAIT VENIR EN PREMIER] Un secret d'intégration scellé qui n'ouvre
/// PAS produit une erreur NOMMÉE, jamais un secret vide ni une config « absente ».
///
/// C'est la raison technique qui avait fait écarter ces trois champs du premier lot : un déchiffrement
/// échoué qui se présente comme « non configuré » est indistinguable d'une console jamais configurée —
/// l'admin part chercher chez son IdP au lieu de regarder sa clé de champ.
///
/// MUTATION : faire rendre `Ok(String::new())` à `open_config_secret` quand la clé manque -> ce test
/// rougit sur les deux premières assertions.
#[test]
fn an_unopenable_integration_secret_is_a_named_error_never_an_empty_one() {
    const KEY: &str = "la-bonne-cle-de-champ";
    const OTHER: &str = "une-autre-cle-de-champ";
    let (_, field, cfg) = integration_configs("s-ds", "s-ch", "s-sso").remove(0);
    let sealed = crate::field_crypto::seal_config_secret(&cfg, field, Some(KEY)).expect("scellement");

    // 1) CLÉ ABSENTE -> refus NOMMÉ (et reconnaissable par `is_key_missing`, ce qui donne un 503 dédié).
    let e = crate::field_crypto::open_config_secret(&sealed, field, None).expect_err("clé absente => Err");
    assert!(crate::field_crypto::is_key_missing(&e), "refus « clé absente » reconnaissable: {e}");
    // 2) MAUVAISE CLÉ -> refus NOMMÉ, distinct du précédent.
    let e = crate::field_crypto::open_config_secret(&sealed, field, Some(OTHER)).expect_err("mauvaise clé => Err");
    assert_eq!(e, crate::field_crypto::ERR_UNSEAL, "refus « illisible » attendu: {e}");
    // 3) BONNE CLÉ -> aller-retour exact (CONTRE-EXEMPLE : sans lui, « Err » pourrait venir de partout).
    let opened = crate::field_crypto::open_config_secret(&sealed, field, Some(KEY)).expect("bonne clé");
    assert_eq!(crate::field_crypto::config_field_raw(&opened, field), "s-ds");

    // 4) PASS-THROUGH — une config PAS ENCORE MIGRÉE (secret en clair) s'ouvre SANS clé : un upgrade en
    //    place continue de fonctionner jusqu'à la passe de boot.
    let plain = crate::field_crypto::open_config_secret(&cfg, field, None).expect("clair => pass-through");
    assert_eq!(crate::field_crypto::config_field_raw(&plain, field), "s-ds");
    // 5) SANS SECRET — aucune clé n'est jamais exigée d'une console qui n'a pas d'intégration authentifiée.
    let bare = json!({"kind": "generic_http", "endpoint": "https://siem.example/x"});
    assert!(crate::field_crypto::seal_config_secret(&bare, field, None).is_ok(), "no-op strict, sans clé");
    assert!(crate::field_crypto::open_config_secret(&bare, field, None).is_ok(), "no-op strict, sans clé");
    // 6) IDEMPOTENCE du scellement (chemin `keep_secret` : l'enveloppe est recopiée, jamais re-scellée).
    let twice = crate::field_crypto::seal_config_secret(&sealed, field, Some(KEY)).expect("re-scellement");
    assert_eq!(twice, sealed, "une valeur déjà scellée est laissée telle quelle");
}

/// [INVENTAIRE COMPLET] La liste FERMÉE `SETTINGS_SECRETS` doit couvrir les clés `settings` réellement
/// utilisées par les modules. Renommer `notify_channels::SETTINGS_KEY` ou `sso::CFG_KEY` sans mettre
/// l'inventaire à jour laisserait ce secret EN CLAIR au repos, en silence — ce test l'en empêche.
#[test]
fn settings_secrets_inventory_covers_every_module_key() {
    let keys: Vec<&str> = crate::field_crypto::SETTINGS_SECRETS.iter().map(|(k, _)| *k).collect();
    for expected in ["detection_source", crate::notify_channels::SETTINGS_KEY, crate::sso::CFG_KEY] {
        assert!(keys.contains(&expected), "clé settings porteuse de secret hors inventaire : {expected}");
    }
    assert_eq!(keys.len(), 3, "inventaire figé — ajouter une intégration à secret impose de l'inscrire ici");
}

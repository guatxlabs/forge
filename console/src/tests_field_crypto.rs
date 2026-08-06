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

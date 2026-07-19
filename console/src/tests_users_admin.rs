// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — tests d'intégration : panel-write auth, admin user CRUD, users routes 403, settings round-trip.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

    /// [C6] Écriture UI (panneaux/dashboards) autorisée par la SESSION (admin|operator), PAS par le token
    /// d'ingest machine. Un admin CONNECTÉ crée un panneau SANS coller aucun token ; un viewer connecté est
    /// refusé (403 writer_required) ; le token d'ingest ("t") ne satisfait PLUS l'écriture UI (check_writer)
    /// mais reste la porte de l'ingest MACHINE (check_token) — les deux gates restent bien distinctes.
    #[tokio::test]
    async fn panel_write_authorized_by_session_not_ingest_token() {
        let path = tmp_path("forge-test-panel-session");
        let app = test_app(&path);
        { let db = app.db(); migrate(&db); } // colonnes additives panel (descr/col_span/updated/dashboard_id)
        ensure_default_dashboard(&app.store()); // dashboard #1 (panel_create refuse un dashboard inexistant)
        {
            let db = app.db();
            upsert_user(&db, "adm", "admin", &hash_pw("pw")).unwrap();
            upsert_user(&db, "viw", "viewer", &hash_pw("pw")).unwrap();
        }
        let (atok, _) = create_session(&app, uid_of(&app, "adm"));
        let (vtok, _) = create_session(&app, uid_of(&app, "viw"));

        // check_writer : session admin OK, viewer NON, anonyme NON.
        assert!(check_writer(&app, &bearer_headers(&atok)), "session admin autorise l'écriture UI");
        assert!(!check_writer(&app, &bearer_headers(&vtok)), "session viewer refusée (fail-closed)");
        assert!(!check_writer(&app, &HeaderMap::new()), "anonyme refusé (fail-closed)");

        // Séparation des gates : le token d'ingest machine ("t") NE vaut PAS une session (écriture UI),
        // et une session admin N'EST PAS le token d'ingest. check_token reste la porte de l'ingest machine.
        assert!(!check_writer(&app, &bearer_headers("t")), "token d'ingest ≠ session (pas d'écriture UI)");
        assert!(check_token(&app, &bearer_headers("t")), "token d'ingest reste valide pour l'ingest machine");
        assert!(!check_token(&app, &bearer_headers(&atok)), "session admin n'est pas le token d'ingest");

        // BOUT-EN-BOUT : admin connecté -> crée un panneau SANS token d'ingest -> 200.
        let ok = panel_create(
            State(app.clone()),
            bearer_headers(&atok),
            Json(json!({"name": "P1", "query": "search severity=HIGH | stats count by mitre"})),
        ).await.into_response();
        assert_eq!(ok.status(), StatusCode::OK, "admin connecté crée un panneau sans token d'ingest");

        // Viewer connecté -> refusé (403), aucun token à coller.
        let denied = panel_create(
            State(app.clone()),
            bearer_headers(&vtok),
            Json(json!({"name": "P2", "query": "search severity=LOW | stats count by mitre"})),
        ).await.into_response();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "viewer refusé (403 writer_required)");

        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] admin_create_user + admin_list_users : création, vue publique SANS pass_hash, ledger
    /// de création SANS mot de passe/hash, attribution à l'acteur, doublon de login -> 409.
    #[test]
    fn admin_create_lists_and_never_leaks_pass_hash() {
        let path = tmp_path("forge-test-admin-create");
        let app = test_app(&path);
        let out = admin_create_user(&app, "aa", &json!({"login": "newbie", "role": "viewer", "password": "s3cretPW"}))
            .expect("création OK");
        assert_eq!(out["login"], "newbie");
        assert_eq!(out["role"], "viewer");
        assert_eq!(out["disabled"], false);
        assert!(out.get("pass_hash").is_none(), "la réponse de création ne contient jamais pass_hash");
        // liste : champs attendus, pass_hash structurellement absent.
        let users = admin_list_users(&app);
        let u = users.iter().find(|u| u["login"] == "newbie").expect("compte listé");
        assert!(u.get("pass_hash").is_none(), "la liste ne renvoie JAMAIS pass_hash");
        assert_eq!(u["role"], "viewer");
        assert_eq!(u["disabled"], false);
        // ledger : entrée create, attribuée, SANS le mot de passe ni le hash argon2.
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.admin.user.create");
        assert_eq!(last["detail"]["actor"], "aa");
        assert_eq!(last["detail"]["login"], "newbie");
        let ser = canon_json(last).to_lowercase();
        assert!(!ser.contains("s3cretpw"), "le mot de passe ne DOIT jamais entrer dans le ledger");
        assert!(!ser.contains("argon2"), "le hash ne DOIT jamais entrer dans le ledger");
        // le compte est réellement provisionné avec un hash vérifiable (mais jamais exposé).
        let ph: String = { let db = app.db(); db.query_row("SELECT pass_hash FROM users WHERE login='newbie'", [], |r| r.get(0)).unwrap() };
        assert!(verify_pw("s3cretPW", &ph), "mot de passe créé vérifiable côté DB");
        // doublon de login -> 409 (l'édition sert à modifier).
        let dup = admin_create_user(&app, "aa", &json!({"login": "newbie", "role": "admin", "password": "x"}));
        assert_eq!(dup.unwrap_err().0, StatusCode::CONFLICT, "login déjà pris -> 409");
        // login/rôle invalides -> 400.
        assert_eq!(admin_create_user(&app, "aa", &json!({"login": "-bad", "role": "viewer", "password": "x"})).unwrap_err().0, StatusCode::BAD_REQUEST);
        assert_eq!(admin_create_user(&app, "aa", &json!({"login": "ok", "role": "root", "password": "x"})).unwrap_err().0, StatusCode::BAD_REQUEST);
        assert_eq!(admin_create_user(&app, "aa", &json!({"login": "ok", "role": "viewer", "password": ""})).unwrap_err().0, StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] admin_update_user : la DÉSACTIVATION purge les sessions du compte + ledgerise (actor,
    /// sessions_purged). La RÉTROGRADATION purge aussi. Le RESET de mot de passe purge et n'expose rien.
    #[test]
    fn admin_update_disable_downgrade_reset_purge_sessions_and_ledger() {
        let path = tmp_path("forge-test-admin-update");
        let app = test_app(&path);
        admin_create_user(&app, "boot", &json!({"login": "root", "role": "admin", "password": "pw"})).unwrap();
        admin_create_user(&app, "root", &json!({"login": "bob", "role": "operator", "password": "pw"})).unwrap();
        let bob = uid_of(&app, "bob");
        let (btok, _) = create_session(&app, bob);
        assert!(resolve_session_identity(&app, &bearer_headers(&btok)).is_some(), "session bob valide au départ");
        // DÉSACTIVATION -> purge des sessions + ledger.
        let out = admin_update_user(&app, "root", "bob", &json!({"disabled": true})).unwrap();
        assert_eq!(out["disabled"], true);
        assert_eq!(out["sessions_purged"], true);
        assert_eq!(session_count(&app, bob), 0, "les sessions du compte désactivé sont purgées");
        assert!(resolve_session_identity(&app, &bearer_headers(&btok)).is_none(), "session révoquée");
        let last = read_ledger_lines(&path).pop().unwrap();
        assert_eq!(last["kind"], "console.admin.user.update");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["sessions_purged"], true);
        // RÉTROGRADATION admin->viewer purge (créer un 2e admin d'abord pour ne pas heurter le garde-fou).
        admin_create_user(&app, "root", &json!({"login": "admin2", "role": "admin", "password": "pw"})).unwrap();
        let a2 = uid_of(&app, "admin2");
        let (a2tok, _) = create_session(&app, a2);
        let out = admin_update_user(&app, "root", "admin2", &json!({"role": "viewer"})).unwrap();
        assert_eq!(out["role"], "viewer");
        assert_eq!(out["sessions_purged"], true, "la rétrogradation purge les sessions");
        assert!(resolve_session_identity(&app, &bearer_headers(&a2tok)).is_none(), "session purgée après rétrogradation");
        // RESET de mot de passe : purge + nouveau mot de passe effectif + rien de sensible au ledger.
        let root_id = uid_of(&app, "root");
        let (rtok, _) = create_session(&app, root_id);
        let out = admin_update_user(&app, "root", "root", &json!({"password": "brandNEW"})).unwrap();
        assert_eq!(out["password_reset"], true);
        assert_eq!(out["sessions_purged"], true, "un reset de mot de passe purge les sessions");
        assert!(resolve_session_identity(&app, &bearer_headers(&rtok)).is_none(), "ancienne session invalidée par le reset");
        let ph: String = { let db = app.db(); db.query_row("SELECT pass_hash FROM users WHERE login='root'", [], |r| r.get(0)).unwrap() };
        assert!(verify_pw("brandNEW", &ph) && !verify_pw("pw", &ph), "nouveau mot de passe effectif, ancien invalidé");
        let ser = canon_json(&read_ledger_lines(&path).pop().unwrap()).to_lowercase();
        assert!(!ser.contains("brandnew"), "aucun mot de passe dans le ledger (reset)");
        // corps vide -> 400 (aucun changement).
        assert_eq!(admin_update_user(&app, "root", "root", &json!({})).unwrap_err().0, StatusCode::BAD_REQUEST);
        // cible inexistante -> 404.
        assert_eq!(admin_update_user(&app, "root", "ghost", &json!({"role": "viewer"})).unwrap_err().0, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] garde-fou DERNIER ADMIN (fail-closed 409) : impossible de désactiver, rétrograder ou
    /// supprimer le seul admin activé ; possible dès qu'il en existe un second. Un refus 409 NE
    /// ledgerise PAS. La suppression réussie purge les sessions et ledgerise (actor).
    #[test]
    fn admin_last_admin_is_protected_on_disable_downgrade_delete() {
        let path = tmp_path("forge-test-admin-last");
        let app = test_app(&path);
        admin_create_user(&app, "boot", &json!({"login": "root", "role": "admin", "password": "pw"})).unwrap();
        let root_id = uid_of(&app, "root");
        let (rtok, _) = create_session(&app, root_id);
        // seul admin activé : désactivation / rétrogradation / suppression -> 409, SANS ledgeriser.
        let before = read_ledger_lines(&path).len();
        assert_eq!(admin_update_user(&app, "root", "root", &json!({"disabled": true})).unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(admin_update_user(&app, "root", "root", &json!({"role": "viewer"})).unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(admin_delete_user(&app, "root", "root").unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(read_ledger_lines(&path).len(), before, "un refus 409 ne ledgerise pas");
        assert!(resolve_session_identity(&app, &bearer_headers(&rtok)).is_some(), "root intact -> sa session survit");
        // 2e admin -> la suppression du 1er devient possible (purge ses sessions + ledger delete).
        admin_create_user(&app, "root", &json!({"login": "root2", "role": "admin", "password": "pw"})).unwrap();
        let del = admin_delete_user(&app, "root2", "root").expect("avec 2 admins, suppression permise");
        assert_eq!(del["deleted"], "root");
        assert_eq!(session_count(&app, root_id), 0, "sessions du compte supprimé purgées");
        let last = read_ledger_lines(&path).pop().unwrap();
        assert_eq!(last["kind"], "console.admin.user.delete");
        assert_eq!(last["detail"]["actor"], "root2");
        assert_eq!(last["detail"]["login"], "root");
        // il ne reste que root2 (seul admin) -> re-bloqué.
        assert_eq!(admin_delete_user(&app, "root2", "root2").unwrap_err().0, StatusCode::CONFLICT);
        // un NON-admin peut être supprimé même seul de son rôle ; inexistant -> 404.
        admin_create_user(&app, "root2", &json!({"login": "viewy", "role": "viewer", "password": "pw"})).unwrap();
        assert!(admin_delete_user(&app, "root2", "viewy").is_ok());
        assert_eq!(admin_delete_user(&app, "root2", "ghost").unwrap_err().0, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] gate des ROUTES : viewer et operator (et l'anonyme) reçoivent 403 sur /api/users
    /// (list/create/update/delete) ; l'admin passe. Vérifie les handlers HTTP réels (check_admin).
    #[tokio::test]
    async fn users_routes_are_admin_only_403() {
        let path = tmp_path("forge-test-users-403");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        app.recompute_auth_required();
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));
        let (atok, _) = create_session(&app, uid_of(&app, "aa"));
        // GET : viewer/operator/anonyme -> 403 ; admin -> 200.
        assert_eq!(users_list(State(app.clone()), bearer_headers(&vtok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(users_list(State(app.clone()), bearer_headers(&otok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(users_list(State(app.clone()), HeaderMap::new()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(users_list(State(app.clone()), bearer_headers(&atok)).await.status(), StatusCode::OK);
        // POST create : operator -> 403 (et le compte n'est PAS créé) ; admin -> 200.
        let body = || Json(json!({"login": "mallory", "role": "viewer", "password": "pw"}));
        assert_eq!(users_create(State(app.clone()), bearer_headers(&otok), body()).await.status(), StatusCode::FORBIDDEN);
        assert!(!admin_list_users(&app).iter().any(|u| u["login"] == "mallory"), "un create refusé (403) ne provisionne rien");
        assert_eq!(users_create(State(app.clone()), bearer_headers(&atok), body()).await.status(), StatusCode::OK);
        // POST update + DELETE : viewer -> 403.
        assert_eq!(
            users_update(State(app.clone()), bearer_headers(&vtok), Path("mallory".into()), Json(json!({"role": "operator"}))).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            users_delete(State(app.clone()), bearer_headers(&vtok), Path("mallory".into())).await.status(),
            StatusCode::FORBIDDEN
        );
        let _ = std::fs::remove_file(&path);
    }

    /// [SUBSTRAT settings] settings_get/settings_set : round-trip d'une clé, upsert (pas de doublon),
    /// horodatage `updated` renseigné, clé absente -> None.
    #[test]
    fn settings_get_set_round_trip() {
        let path = tmp_path("forge-test-settings");
        let app = test_app(&path);
        let db = app.db();
        assert!(settings_get(&db, "operator_policy").is_none(), "clé absente -> None (aucune valeur inventée)");
        settings_set(&db, "operator_policy", "{\"arm_required\":true}").unwrap();
        assert_eq!(settings_get(&db, "operator_policy").as_deref(), Some("{\"arm_required\":true}"),
            "la valeur écrite est relue à l'identique (round-trip)");
        let updated: String = db.query_row("SELECT updated FROM settings WHERE key='operator_policy'", [], |r| r.get(0)).unwrap();
        assert!(!updated.is_empty(), "horodatage `updated` renseigné à l'écriture");
        // upsert : re-écrire la MÊME clé remplace la valeur sans créer de doublon (PRIMARY KEY).
        settings_set(&db, "operator_policy", "{\"arm_required\":false}").unwrap();
        assert_eq!(settings_get(&db, "operator_policy").as_deref(), Some("{\"arm_required\":false}"), "valeur mise à jour");
        let count: i64 = db.query_row("SELECT COUNT(*) FROM settings WHERE key='operator_policy'", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "PRIMARY KEY -> une seule ligne par clé (upsert, pas d'insertion doublon)");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------------------------------------
    // WIZARD 1er DÉPLOIEMENT + politique opérateur source-CIDR
    // ---------------------------------------------------------------------------------------------


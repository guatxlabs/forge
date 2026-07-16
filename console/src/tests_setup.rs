// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — tests d'intégration : 1er-déploiement wizard, migrate/provision self-disabling, path-confinement.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

    /// [SETUP wizard] Flux END-TO-END sur le VRAI routeur (build_router) : fresh -> needs_setup ;
    /// POST /api/setup crée l'admin, pose le cookie, bascule provisioned ; 2e POST -> 409 ;
    /// detection_source + operator_policy atterrissent dans settings ; /api/setup* restent joignables
    /// SANS auth tandis qu'une route protégée (/api/whoami) passe à 401 une fois la gate engagée.
    #[tokio::test]
    async fn setup_wizard_live_end_to_end() {
        let ledger = tmp_path("forge-test-setup-ledger");
        let app = test_app(&ledger);
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // 1) fresh install -> needs_setup:true, sqlcipher:false (build par défaut), joignable SANS auth.
        let r = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert_eq!(parse_status(&r), 200, "setup/state public: {r}");
        assert!(body_of(&r).contains("\"needs_setup\":true"), "fresh -> needs_setup:true : {}", body_of(&r));
        assert!(body_of(&r).contains("\"provisioned\":false"));
        assert!(body_of(&r).contains("\"sqlcipher\":false"), "build par défaut -> sqlcipher:false");

        // 2) POST /api/setup SANS auth -> 200 + cookie posé + settings persistés.
        let setup_body = json!({
            "admin_login": "root",
            "admin_password": "hunter2pw",
            "session_ttl": 1800,
            "operator_policy": {"require_reason": true, "source_cidrs": ["10.0.0.0/24"], "high_impact_approval": false},
            "detection_source": {"kind": "plume", "endpoint": "http://soc.local:8080", "auth_type": "basic"}
        })
        .to_string();
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 200, "provision -> 200 : {r}");
        assert!(body_of(&r).contains("\"provisioned\":true"));
        let tok = cookie_token(&r).expect("cookie forge_session posé par le provisioning");
        assert!(!tok.is_empty());

        // 3) l'état bascule : provisioned:true / needs_setup:false.
        let r = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert!(body_of(&r).contains("\"needs_setup\":false"), "après provision -> needs_setup:false");
        assert!(body_of(&r).contains("\"provisioned\":true"));

        // 4) SECONDE provision -> 409 (route auto-désactivante).
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 409, "2e provision -> 409 : {r}");

        // 5) detection_source + operator_policy (+ session_ttl) atterrissent VERBATIM dans settings.
        {
            let db = app.db();
            assert!(settings_get(&db, "operator_policy").unwrap().contains("10.0.0.0/24"), "operator_policy stocké");
            assert!(settings_get(&db, "detection_source").unwrap().contains("plume"), "detection_source stocké");
            assert_eq!(settings_get(&db, "session_ttl").as_deref(), Some("1800"), "session_ttl stocké");
        }
        assert!(app.any_enabled_admin(), "un admin activé existe après provision");

        // 6) la gate d'auth est désormais engagée : /api/whoami SANS auth -> 401 ; AVEC session -> 200.
        let r = http_raw(addr, &get_req("/api/whoami", "")).await;
        assert_eq!(parse_status(&r), 401, "route protégée sans auth, gate engagée -> 401 : {r}");
        let r = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "route protégée avec session -> 200 : {r}");
        assert!(body_of(&r).contains("\"login\":\"root\""), "session = nouvel admin root : {}", body_of(&r));

        // 7) /api/setup/state RESTE joignable sans auth même gate engagée (hors auth_guard).
        let r = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert_eq!(parse_status(&r), 200, "setup/state toujours public une fois provisionné");

        // ledger : entrée de provision attribuée à root, JAMAIS le mot de passe/hash.
        let last = read_ledger_lines(&ledger).pop().expect("ledger provision");
        assert_eq!(last["kind"], "console.setup.provision");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["operator_policy_set"], true);
        assert_eq!(last["detail"]["detection_source_set"], true);
        let ser = canon_json(&last).to_lowercase();
        assert!(!ser.contains("hunter2pw"), "le mot de passe ne DOIT jamais entrer dans le ledger");
        assert!(!ser.contains("argon2"), "le hash ne DOIT jamais entrer dans le ledger");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [SETUP migrate] POST /api/setup/migrate : PUBLIC en pré-provision (exécute la migration + rend
    /// le rapport verify), puis AUTO-DÉSACTIVANTE (409) dès qu'un admin activé existe. Chemin plaintext
    /// (aucun sqlcipher requis).
    // env_lock() sérialise l'ENV process-global entre threads de test ; le garder à travers l'await
    // de setup_migrate est VOULU (l'ENV doit rester stable pendant l'appel awaité). Runtime de test
    // current_thread => aucun risque de blocage de l'exécuteur.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn setup_migrate_public_pre_provision_then_409_once_provisioned() {
        // COUCHE 1+2 activées : flag opt-in ON + racine d'import = temp_dir (où vivent from/to/ledger)
        // -> l'endpoint accepte l'import pré-provision. (Le verrou sérialise vs le test flag-OFF.)
        let _g = env_lock();
        std::env::set_var("FORGE_ALLOW_API_MIGRATE", "1");
        std::env::set_var("FORGE_CONSOLE_IMPORT_DIR", std::env::temp_dir().to_string_lossy().to_string());

        // source sur disque : base ANCIENNE + ledger intact.
        let src_dir = tmp_dir("forge-mig-http-src");
        let src_db = format!("{src_dir}/forge.db");
        seed_old_source_db(&src_db);
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        ledger_append_standalone(&src_ledger, "engagement.start", &json!({"a": 1})).unwrap();

        let led = tmp_path("forge-test-setup-migrate-ledger");
        let app = test_app(&led);
        let to = tmp_path("forge-mig-http-to.db");
        let target_ledger = tmp_path("forge-mig-http-to.jsonl");
        let body = json!({"from": src_dir, "to": to, "ledger": target_ledger, "verify": true});

        // 1) PRÉ-PROVISION : route publique -> exécute la migration -> 200 + cible écrite.
        let r = setup_migrate(State(app.clone()), Json(body.clone())).await;
        assert_eq!(r.status(), StatusCode::OK, "pré-provision -> 200");
        assert!(std::path::Path::new(&to).exists(), "migration exécutée (cible écrite)");

        // 2) provisionne un admin -> la route se ferme (409), sans relancer de migration.
        {
            let db = app.db();
            upsert_user(&db, "root", "admin", &hash_pw("pw123456")).unwrap();
        }
        app.recompute_auth_required();
        assert!(app.provisioned(), "un admin activé -> provisionné");
        let r = setup_migrate(State(app.clone()), Json(body)).await;
        assert_eq!(r.status(), StatusCode::CONFLICT, "une fois provisionné -> 409");

        std::env::remove_var("FORGE_ALLOW_API_MIGRATE");
        std::env::remove_var("FORGE_CONSOLE_IMPORT_DIR");
        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&led);
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::remove_file(&target_ledger);
        let _ = std::fs::remove_file(format!("{target_ledger}.ed25519"));
    }

    /// [SETUP migrate — COUCHE 1] Défaut OFF : sans FORGE_ALLOW_API_MIGRATE, l'endpoint REFUSE (403)
    /// AVANT toute I/O — la primitive d'écriture/suppression de fichier non-auth n'existe pas dans le
    /// déploiement par défaut. Preuve : la cible n'est JAMAIS écrite malgré une source valide.
    // env_lock() sérialise l'ENV process-global entre threads de test ; le garder à travers l'await
    // de setup_migrate est VOULU (l'ENV doit rester stable pendant l'appel awaité). Runtime de test
    // current_thread => aucun risque de blocage de l'exécuteur.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn setup_migrate_api_disabled_by_default_no_file_op() {
        let _g = env_lock();
        std::env::remove_var("FORGE_ALLOW_API_MIGRATE");

        let src_dir = tmp_dir("forge-mig-flagoff-src");
        seed_old_source_db(&format!("{src_dir}/forge.db"));
        let led = tmp_path("forge-mig-flagoff-led");
        let app = test_app(&led); // non provisionnée -> la fenêtre de setup est ouverte.
        assert!(!app.provisioned(), "console non provisionnée (fenêtre setup ouverte)");
        let to = tmp_path("forge-mig-flagoff-to.db");
        let body = json!({"from": src_dir, "to": to});

        let r = setup_migrate(State(app.clone()), Json(body)).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "flag OFF -> 403 (migration API désactivée)");
        assert!(!std::path::Path::new(&to).exists(), "AUCUN fichier écrit quand la migration API est OFF");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&led);
    }

    /// [SETUP migrate — COUCHE 2] Validation de chemin (flag ON) : (c) cible/ source SOUS la base
    /// acceptées ; (b) traversal `..` + absolu hors base rejetés ; (d) cible PRÉEXISTANTE hors base
    /// refusée SANS y toucher. Teste le helper directement (base injectée) -> aucune course d'ENV.
    #[test]
    fn api_migrate_path_validation_confines_to_base() {
        let base = tmp_dir("forge-mig-base");
        let base_canon = std::path::Path::new(&base).canonicalize().expect("canon base");

        // (c) cible neuve VALIDE sous la base (parent = base existe, fichier absent) -> acceptée.
        let ok_to = format!("{base}/staging.db");
        assert!(validate_api_migrate_path(&base_canon, &ok_to, "to", false).is_ok(),
            "cible neuve sous la base -> acceptée");
        // source existante VALIDE sous la base -> acceptée (must_exist).
        let src = format!("{base}/src.db");
        std::fs::write(&src, b"x").unwrap();
        assert!(validate_api_migrate_path(&base_canon, &src, "from", true).is_ok(),
            "source existante sous la base -> acceptée");

        // (b) traversal `..` -> rejeté AVANT toute résolution.
        let trav = format!("{base}/../etc/evil");
        assert!(validate_api_migrate_path(&base_canon, &trav, "to", false).is_err(),
            "composant `..` -> rejeté");
        // (b bis) chemin ABSOLU hors base -> rejeté.
        assert!(validate_api_migrate_path(&base_canon, "/etc/passwd", "from", true).is_err(),
            "absolu hors base -> rejeté");
        // source inexistante -> rejetée (introuvable), jamais silencieusement acceptée.
        assert!(validate_api_migrate_path(&base_canon, &format!("{base}/nope.db"), "from", true).is_err(),
            "source introuvable -> rejetée");

        // (d) cible PRÉEXISTANTE hors base -> refus d'écrasement, fichier intact.
        let outside_dir = tmp_dir("forge-mig-outside");
        let victim = format!("{outside_dir}/victim.db");
        std::fs::write(&victim, b"precious").unwrap();
        assert!(validate_api_migrate_path(&base_canon, &victim, "to", false).is_err(),
            "cible préexistante HORS base -> refusée (pas d'écrasement)");
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious", "la cible hors base reste intacte");

        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside_dir);
    }

    /// [SETUP wizard] Validation d'entrée + auto-désactivation par HASH ENV : login invalide -> 400,
    /// mot de passe vide -> 400 ; une install avec un hash d'amorçage env est déjà provisionnée -> 409
    /// (pas de nouvelle provision anonyme), même sans compte en base.
    #[tokio::test]
    async fn setup_provision_validates_and_self_disables_on_env_hash() {
        let path = tmp_path("forge-test-setup-validate");
        // login invalide -> 400
        {
            let app = test_app(&path);
            let r = setup_provision(State(app.clone()), HeaderMap::new(), Json(json!({"admin_login": "-bad", "admin_password": "x"}))).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "login invalide -> 400");
            // mot de passe vide -> 400
            let r = setup_provision(State(app.clone()), HeaderMap::new(), Json(json!({"admin_login": "ok", "admin_password": ""}))).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "mot de passe vide -> 400");
            assert!(!app.any_enabled_admin(), "aucun refus 400 ne provisionne quoi que ce soit");
        }
        // hash env d'amorçage posé -> provisioned d'emblée -> 409.
        {
            let mut app = test_app(&path);
            app.pass_hash = Arc::new(hash_pw("bootstrap"));
            app.recompute_auth_required();
            assert!(app.provisioned(), "hash env -> déjà provisionné");
            let r = setup_provision(State(app.clone()), HeaderMap::new(), Json(json!({"admin_login": "root", "admin_password": "x"}))).await;
            assert_eq!(r.status(), StatusCode::CONFLICT, "hash env d'amorçage -> /api/setup fermée (409)");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// [WIZARD ROE] setup_provision accepte un `scope_json` OPTIONNEL et l'écrit dans l'engagement #1 via le
    /// MÊME chemin de mise à jour validé que l'éditeur d'engagement. Trois cas : (a) scope valide -> 200,
    /// l'engagement #1 porte le scope (un run l'appliquerait — host_in_scope_list le confirme) ; (b) scope
    /// invalide -> 400 et RIEN n'est provisionné (fail-closed) ; (c) aucun scope -> 200, engagement #1 en
    /// scope VIDE (fail-closed) et la route s'auto-désactive (2e appel -> 409).
    #[tokio::test]
    async fn setup_provision_wizard_scope_optional_validated_and_self_disabling() {
        // (b) ROE invalide -> 400, aucun provisioning (validé AVANT toute écriture).
        {
            let path = tmp_path("forge-test-setup-scope-bad");
            let app = test_app(&path);
            insert_test_engagement(&app, 1, &[], "grey", &path);
            let bad = json!({"admin_login": "root", "admin_password": "pw",
                "scope_json": {"mode": "grey", "in_scope": ["bad host with spaces"]}});
            let r = setup_provision(State(app.clone()), HeaderMap::new(), Json(bad)).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "ROE invalide -> 400");
            assert!(!app.any_enabled_admin(), "un 400 ROE ne provisionne AUCUN admin (fail-closed)");
            let eng = load_engagement(&app.store(), 1).expect("engagement #1");
            assert!(eng.scope_in.is_empty(), "engagement #1 inchangé (scope resté vide)");
            let _ = std::fs::remove_file(&path);
        }
        // (a) ROE valide -> 200, engagement #1 porte le scope (enforcement prouvé via host_in_scope_list).
        {
            let path = tmp_path("forge-test-setup-scope-ok");
            let app = test_app(&path);
            insert_test_engagement(&app, 1, &[], "grey", &path);
            let ok = json!({"admin_login": "root", "admin_password": "pw",
                "scope_json": {"mode": "white", "in_scope": ["app.example.com", "*.lab.test"], "out_scope": ["admin.example.com"]}});
            let r = setup_provision(State(app.clone()), HeaderMap::new(), Json(ok)).await;
            assert_eq!(r.status(), StatusCode::OK, "ROE valide -> 200");
            assert!(app.provisioned(), "admin provisionné");
            let eng = load_engagement(&app.store(), 1).expect("engagement #1");
            assert_eq!(eng.mode, "white", "mode de l'engagement #1 = mode du ROE du wizard");
            assert_eq!(eng.scope_in, vec!["app.example.com".to_string(), "*.lab.test".to_string()],
                "in-scope de l'engagement #1 = ROE du wizard");
            assert_eq!(eng.scope_out, vec!["admin.example.com".to_string()], "out-scope écrit");
            // un run appliquerait CE scope : une cible in-scope passe, une hors-scope est refusée.
            assert!(host_in_scope_list(&eng.scope_in, "app.example.com"), "cible in-scope acceptée");
            assert!(host_in_scope_list(&eng.scope_in, "x.lab.test"), "wildcard in-scope accepté");
            assert!(!host_in_scope_list(&eng.scope_in, "evil.example.org"), "cible hors-scope refusée");
            let _ = std::fs::remove_file(&path);
        }
        // (c) aucun ROE -> 200, engagement #1 en scope VIDE (fail-closed), route auto-désactivée (2e -> 409).
        {
            let path = tmp_path("forge-test-setup-scope-none");
            let app = test_app(&path);
            insert_test_engagement(&app, 1, &[], "grey", &path);
            let r = setup_provision(State(app.clone()), HeaderMap::new(), Json(json!({"admin_login": "root", "admin_password": "pw"}))).await;
            assert_eq!(r.status(), StatusCode::OK, "sans ROE -> 200 (provisioning ok)");
            let eng = load_engagement(&app.store(), 1).expect("engagement #1");
            assert!(eng.scope_in.is_empty(), "sans ROE -> engagement #1 en scope VIDE (fail-closed)");
            let r2 = setup_provision(State(app.clone()), HeaderMap::new(), Json(json!({"admin_login": "root2", "admin_password": "pw2"}))).await;
            assert_eq!(r2.status(), StatusCode::CONFLICT, "route auto-désactivée après provisioning (409)");
            let _ = std::fs::remove_file(&path);
        }
    }


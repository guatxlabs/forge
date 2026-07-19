// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — tests d'intégration : run scope/ledger isolation, per-engagement slot, migrate-backfill, private-target gates.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

    /// [ENGAGEMENT #1 — migration ZÉRO-PERTE] `migrate()` ajoute engagement_id NOT NULL DEFAULT 1 :
    /// une ligne finding PRÉ-EXISTANTE (schéma ancien, sans la colonne) est rétro-rattachée à
    /// l'engagement #1. `ensure_default_engagement` crée l'engagement #1 depuis le scope serveur COURANT
    /// (in_scope + mode) + le ledger courant, et est IDEMPOTENT (n'écrase jamais un engagement existant).
    #[test]
    fn migrate_creates_engagement_one_and_backfills_engagement_id() {
        // `conn()` rend une garde fraîche sur la MÊME connexion (le seeder prend désormais un `&Store` ;
        // les ops rusqlite directes + migrate/load_engagement gardent leur `&Connection` via le deref).
        let dbm = Mutex::new(Connection::open_in_memory().expect("mem db"));
        let conn = || dbm.lock().unwrap_or_else(|e| e.into_inner());
        conn().execute_batch(SCHEMA).expect("schema"); // `finding` n'a PAS encore engagement_id
        // ligne « ancienne » insérée AVANT l'ajout de la colonne (simule une base antérieure).
        conn().execute(
            "INSERT INTO finding(id,title,target,campaign) VALUES(1,'old-finding','h.example','c1')",
            [],
        )
        .unwrap();
        migrate(&conn()); // ALTER ... ADD COLUMN engagement_id NOT NULL DEFAULT 1 -> backfill à 1
        let eid: i64 = conn()
            .query_row("SELECT engagement_id FROM finding WHERE id=1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(eid, 1, "ligne existante rétro-rattachée à l'engagement #1 (DEFAULT)");

        // table engagement vide -> ensure_default_engagement crée #1 depuis le scope/ledger COURANTS.
        let n0: i64 = conn().query_row("SELECT COUNT(*) FROM engagement", [], |r| r.get(0)).unwrap();
        assert_eq!(n0, 0, "aucun engagement avant l'amorçage");
        ensure_default_engagement(
            &crate::store::Store::sqlite(conn()),
            &["a.example.com".to_string(), "*.b.example.com".to_string()],
            "grey",
            "/tmp/eng1.jsonl",
        );
        let eng = load_engagement(&crate::store::Store::sqlite(conn()), 1).expect("engagement #1 créé");
        assert_eq!(eng.id, 1);
        assert_eq!(eng.mode, "grey");
        assert_eq!(eng.scope_in, vec!["a.example.com".to_string(), "*.b.example.com".to_string()],
            "scope de l'engagement #1 = scope serveur courant");
        assert_eq!(eng.ledger_path, "/tmp/eng1.jsonl", "ledger de l'engagement #1 = ledger courant");

        // idempotent : un 2e appel (scope/ledger DIFFÉRENTS) ne réécrit PAS l'engagement #1.
        ensure_default_engagement(&crate::store::Store::sqlite(conn()), &["changed.example".to_string()], "black", "/tmp/other.jsonl");
        let eng2 = load_engagement(&crate::store::Store::sqlite(conn()), 1).unwrap();
        assert_eq!(eng2.scope_in, vec!["a.example.com".to_string(), "*.b.example.com".to_string()],
            "idempotent : scope inchangé");
        assert_eq!(eng2.ledger_path, "/tmp/eng1.jsonl", "idempotent : ledger inchangé");
        let cnt: i64 = conn().query_row("SELECT COUNT(*) FROM engagement", [], |r| r.get(0)).unwrap();
        assert_eq!(cnt, 1, "idempotent : pas de doublon d'engagement");
    }

    /// [RUN FLOW — scope + ledger de L'ENGAGEMENT, pas les App globals] Un run créé pour l'engagement #2
    /// est validé contre le scope de #2 (pas les App globals) et journalisé dans le ledger DÉDIÉ de #2 ;
    /// le run_job porte engagement_id=2. Une cible qui n'est DANS les globals mais PAS dans #2 est
    /// refusée (preuve que ce sont bien les données de l'engagement qui gouvernent, jamais les globals).
    #[tokio::test]
    async fn run_uses_engagement_scope_and_ledger_not_app_globals() {
        let globals_ledger = tmp_path("forge-test-eng-globals");
        // App globals : scope = global.example.com, ledger = globals_ledger. (défauts de l'engagement #1)
        let mut app = test_app_scoped(&globals_ledger, vec!["global.example.com".into()]);
        app.python = Arc::new("true".into()); // spawn no-op : prouve qu'on a PASSÉ la validation sans lancer le moteur
        let eng2_ledger = tmp_path("forge-test-eng2-ledger");
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
        }
        // engagement #1 (globals) + #2 (scope + ledger DISTINCTS des globals).
        insert_test_engagement(&app, 1, &["global.example.com"], "grey", &globals_ledger);
        insert_test_engagement(&app, 2, &["eng2.example.com"], "grey", &eng2_ledger);
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // (a) cible DANS les globals mais HORS du scope de #2 -> refusée (on n'utilise PAS les globals).
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("c2", Some(2), &["global.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "cible du scope GLOBAL refusée pour l'engagement #2");
        let j = resp_json(resp).await;
        assert_eq!(j["error"], "out_of_scope");

        // (b) cible DANS le scope de #2 (mais PAS dans les globals) -> ACCEPTÉE (scope de l'engagement).
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("c2", Some(2), &["eng2.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED,
            "cible du scope de l'engagement #2 acceptée (le run utilise le scope de #2, pas les globals)");

        // run_job estampillé engagement_id=2.
        let run_eid: i64 = {
            let db = app.db();
            db.query_row("SELECT engagement_id FROM run_job WHERE campaign='c2'", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(run_eid, 2, "run_job porte l'engagement #2");

        // ledger : console.run.start est dans le ledger DÉDIÉ de #2, JAMAIS dans les globals.
        let eng2_entries = read_ledger_lines(&eng2_ledger);
        assert!(eng2_entries.iter().any(|e| e["kind"] == "console.run.start"
            && e["detail"]["engagement_id"] == 2),
            "run.start journalisé dans le ledger de l'engagement #2");
        let globals_entries = read_ledger_lines(&globals_ledger);
        assert!(!globals_entries.iter().any(|e| e["kind"] == "console.run.start"),
            "le ledger GLOBAL ne reçoit PAS le run d'un autre engagement (isolation)");

        let _ = std::fs::remove_file(&globals_ledger);
        let _ = std::fs::remove_file(&eng2_ledger);
    }

    /// [RUN FLOW — CHEMIN FORT-IMPACT HONORÉ + auto + arm] RÉGRESSION C16 (« Failed to fetch » au
    /// lancement). Le corps EXACT que l'UI live envoie quand l'opt-in fort-impact est PLEINEMENT honoré —
    /// `mode:"auto"`, `arm:true`, `allow_high_impact:true`, `reason` non vide, `modules:[]` (le planner
    /// choisit) — DOIT renvoyer une réponse GOUVERNÉE PROPRE (202 ACCEPTED, `high_impact:true`), JAMAIS un
    /// 500/panic ni une connexion coupée. Ce chemin exerce toutes les branches spécifiques au fort-impact
    /// (scope écrit allow_exploit/destructive=true, ledger `console.run.high_impact_authorized`,
    /// `high_impact_modules`) que les tests de run antérieurs (mode `propose`, non armés) n'atteignaient
    /// pas. `python="true"` : spawn no-op — on prouve la réponse HTTP propre sans lancer le moteur réel.
    #[tokio::test]
    async fn honored_high_impact_auto_arm_run_is_clean_202_not_panic() {
        let ledger = tmp_path("forge-test-c16-hi-ledger");
        let mut app = test_app_scoped(&ledger, vec!["127.0.0.1".into()]);
        app.python = Arc::new("true".into()); // spawn no-op : réponse HTTP propre sans moteur réel
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
        }
        // engagement #1 en mode white, 127.0.0.1 in-scope (réplique la config live de l'utilisateur).
        insert_test_engagement(&app, 1, &["127.0.0.1"], "white", &ledger);
        // POLITIQUE RÉSEAU : 127.0.0.1 est loopback -> les DEUX portes (master global + opt-in engagement)
        // doivent être ouvertes pour le scanner (sinon private_target_blocked). On les ouvre ici pour
        // exercer le chemin fort-impact — l'intention de CE test (le gate réseau a ses propres tests dédiés).
        {
            let db = app.db();
            crate::settings_set(&db, "network.allow_private", "on").unwrap();
            db.execute("UPDATE engagement SET allow_private=1 WHERE id=1", []).unwrap();
        }
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // corps EXACT honoré : auto + arm + allow_high_impact + reason + modules vides + engagement #1.
        let body = json!({
            "campaign": "testLoc", "targets": ["127.0.0.1"], "mode": "auto",
            "arm": true, "allow_high_impact": true, "reason": "test", "modules": [],
            "engagement_id": 1
        });
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok), Json(body)).await.into_response();
        // GOUVERNÉ PROPRE : 202 ACCEPTED (jamais 500/panic — le filet CatchPanic n'a rien à rattraper ici).
        assert_eq!(resp.status(), StatusCode::ACCEPTED,
            "le chemin fort-impact honoré + auto/arm renvoie 202 (réponse gouvernée propre, pas un panic)");
        let j = resp_json(resp).await;
        assert_eq!(j["status"], "running");
        assert_eq!(j["high_impact"], true, "opt-in fort-impact effectivement honoré");
        assert_eq!(j["mode"], "auto");
        // le ledger de l'engagement reçoit l'acte d'autorisation fort-impact (audit non régressé).
        let entries = read_ledger_lines(&ledger);
        assert!(entries.iter().any(|e| e["kind"] == "console.run.high_impact_authorized"),
            "l'autorisation fort-impact est journalisée (ledger intact)");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [POLITIQUE RÉSEAU — FAIL-CLOSED PAR DÉFAUT] Instance fraîche (master global OFF + opt-in engagement
    /// OFF) : un run visant un LITTÉRAL privé/LAN/loopback est REFUSÉ (private_target_blocked) AVANT tout
    /// spawn, pour CHAQUE famille d'IP privée. Une cible PUBLIQUE n'est JAMAIS bloquée par cette politique.
    #[tokio::test]
    async fn private_target_blocked_when_policy_off_by_default() {
        let ledger = tmp_path("forge-test-netpol-off");
        let mut app = test_app_scoped(&ledger, vec!["127.0.0.1".into()]);
        app.python = Arc::new("true".into()); // spawn no-op (la publique atteint 202 sans moteur réel)
        { let db = app.db(); upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap(); }
        insert_test_engagement(&app, 1, &["127.0.0.1", "10.0.0.5", "192.168.1.1", "93.184.216.34"], "white", &ledger);
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1"] {
            let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
                Json(run_body("c", Some(1), &[ip]))).await.into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{ip} doit être bloqué (politique OFF)");
            assert_eq!(resp_json(resp).await["error"], "private_target_blocked", "{ip}");
        }
        // cible PUBLIQUE : jamais bloquée par la politique réseau (202).
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("c", Some(1), &["93.184.216.34"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "cible publique non bloquée par la politique réseau");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [POLITIQUE RÉSEAU — DEUX PORTES CUMULATIVES] Master global ON mais opt-in engagement OFF => TOUJOURS
    /// bloqué (il faut les DEUX). Prouve que le master seul n'ouvre rien (isolation par engagement).
    #[tokio::test]
    async fn private_blocked_when_global_on_but_engagement_off() {
        let ledger = tmp_path("forge-test-netpol-global-only");
        let mut app = test_app_scoped(&ledger, vec!["10.0.0.5".into()]);
        app.python = Arc::new("true".into());
        { let db = app.db();
          upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
          crate::settings_set(&db, "network.allow_private", "on").unwrap(); } // master ON
        insert_test_engagement(&app, 1, &["10.0.0.5"], "white", &ledger);       // opt-in OFF (défaut 0)
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("c", Some(1), &["10.0.0.5"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "global ON + engagement OFF -> bloqué (2 portes)");
        assert_eq!(resp_json(resp).await["error"], "private_target_blocked");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [POLITIQUE RÉSEAU — DÉVERROUILLAGE] Les DEUX portes ouvertes (master global ON + opt-in engagement
    /// ON) => la cible privée in-scope passe le gate pré-spawn (202 ACCEPTED). C'est l'unlock end-to-end.
    #[tokio::test]
    async fn private_allowed_when_both_gates_on() {
        let ledger = tmp_path("forge-test-netpol-both-on");
        let mut app = test_app_scoped(&ledger, vec!["10.0.0.5".into()]);
        app.python = Arc::new("true".into()); // spawn no-op : prouve qu'on PASSE le gate sans moteur réel
        { let db = app.db();
          upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
          crate::settings_set(&db, "network.allow_private", "on").unwrap(); }   // porte 1
        insert_test_engagement(&app, 1, &["10.0.0.5"], "white", &ledger);
        { let db = app.db(); db.execute("UPDATE engagement SET allow_private=1 WHERE id=1", []).unwrap(); } // porte 2
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("c", Some(1), &["10.0.0.5"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "les DEUX portes ouvertes -> scan privé autorisé");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [POLITIQUE RÉSEAU — API MASTER GLOBAL] GET/POST /api/network-policy : ADMIN uniquement (operator ->
    /// 403), défaut fail-closed (false), persistance + ledger `console.settings.network_policy` (old->new).
    #[tokio::test]
    async fn network_policy_api_admin_gated_persists_and_ledgers() {
        let ledger = tmp_path("forge-test-netpol-api");
        let app = test_app_scoped(&ledger, vec!["x.example".into()]);
        { let db = app.db();
          upsert_user(&db, "adm", "admin", &hash_pw("pw")).unwrap();
          upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap(); }
        let (atok, _) = create_session(&app, uid_of(&app, "adm"));
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // défaut : GET (admin) -> allow_private false (fail-closed).
        let r = network_policy_get(State(app.clone()), bearer_headers(&atok)).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(resp_json(r).await["allow_private"], false, "défaut master = OFF (fail-closed)");

        // operator (non-admin) -> 403 sur GET et POST.
        let r = network_policy_get(State(app.clone()), bearer_headers(&otok)).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "GET réservé admin");
        let r = network_policy_set(State(app.clone()), bearer_headers(&otok), Json(json!({"allow_private": true}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "POST réservé admin");
        assert!(!crate::network_allow_private(&app.store()), "le POST refusé n'a rien persisté");

        // admin POST true -> persiste + ledger console.settings.network_policy (old=false, new=true).
        let r = network_policy_set(State(app.clone()), bearer_headers(&atok), Json(json!({"allow_private": true}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(crate::network_allow_private(&app.store()), "master persistant ON");
        let r = network_policy_get(State(app.clone()), bearer_headers(&atok)).await;
        assert_eq!(resp_json(r).await["allow_private"], true, "relecture ON");
        let entries = read_ledger_lines(&ledger);
        assert!(entries.iter().any(|e| e["kind"] == "console.settings.network_policy"
            && e["detail"]["old"] == false && e["detail"]["new"] == true),
            "bascule ledgerisée avec old->new");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [POLITIQUE RÉSEAU — OPT-IN ENGAGEMENT] Le champ `allow_private` d'un engagement fait l'aller-retour
    /// via l'API : create (true) -> GET /api/engagements l'expose -> update (false) -> relecture (false).
    #[tokio::test]
    async fn engagement_allow_private_round_trips_through_api() {
        let ledger = tmp_path("forge-test-eng-allowpriv");
        let app = test_app_scoped(&ledger, vec!["x.example".into()]);
        { let db = app.db(); upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap(); }
        insert_test_engagement(&app, 1, &["x.example"], "grey", &ledger); // ancre #1 (jamais le dernier actif)
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // create avec allow_private=true.
        let body = json!({"name": "neteng", "scope_json": {"mode": "grey", "in_scope": ["y.example"]}, "allow_private": true});
        let r = engagements_create(State(app.clone()), conn_info(), bearer_headers(&otok), Json(body)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let created = resp_json(r).await;
        assert_eq!(created["engagement"]["allow_private"], true, "create renvoie allow_private");
        let new_id = created["engagement"]["id"].as_i64().unwrap();

        // GET liste -> l'entrée porte allow_private=true.
        let r = engagements_list(State(app.clone()), bearer_headers(&otok)).await.into_response();
        let list = resp_json(r).await;
        let found = list["engagements"].as_array().unwrap().iter()
            .find(|e| e["id"].as_i64() == Some(new_id)).cloned().expect("engagement listé");
        assert_eq!(found["allow_private"], true, "la liste expose allow_private");

        // update -> allow_private=false.
        let r = engagements_update(State(app.clone()), conn_info(), bearer_headers(&otok),
            Path(new_id), Json(json!({"allow_private": false}))).await;
        assert_eq!(r.status(), StatusCode::OK, "update accepté");
        let r = engagements_list(State(app.clone()), bearer_headers(&otok)).await.into_response();
        let list = resp_json(r).await;
        let found = list["engagements"].as_array().unwrap().iter()
            .find(|e| e["id"].as_i64() == Some(new_id)).cloned().unwrap();
        assert_eq!(found["allow_private"], false, "update a basculé allow_private à false");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [M1 — suppression d'engagement vs run VIVANT] `engagement_do_delete` REFUSE (409) tant qu'un run de
    /// l'engagement est encore `status='running'` : supprimer sa ligne `run_job` pendant que le moteur
    /// détaché tourne laisserait ses POSTs `/api/ingest` tardifs résoudre l'engagement via une ligne
    /// DISPARUE -> `unwrap_or(1)` -> findings estampillés à l'engagement #1 (contamination cross-engagement).
    /// Une fois le run terminal (`done`/`cancelled`), la suppression passe.
    #[tokio::test]
    async fn m1_delete_engagement_refused_while_run_live() {
        let ledger = tmp_path("forge-test-m1-live");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger); // ancre #1 (jamais supprimable)
        insert_test_engagement(&app, 2, &["a.example.com"], "grey", &ledger); // cible
        { let db = app.db(); db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('rlive','c','running','propose',2)", []).unwrap(); }

        // (a) REFUS 409 tant que le run est vivant ; l'engagement ET sa ligne run_job survivent (pas de contamination).
        let e = engagement_do_delete(&app, 2, "adm").unwrap_err();
        assert_eq!(e.0, StatusCode::CONFLICT, "delete refusé (409) tant qu'un run est vivant");
        assert!(e.1.contains("en cours"), "message explicite: {}", e.1);
        { let n: i64 = app.db().query_row("SELECT COUNT(*) FROM engagement WHERE id=2", [], |r| r.get(0)).unwrap();
          assert_eq!(n, 1, "l'engagement #2 N'A PAS été supprimé"); }
        { let s: String = app.db().query_row("SELECT status FROM run_job WHERE run_id='rlive'", [], |r| r.get(0)).unwrap();
          assert_eq!(s, "running", "la ligne run_job survit (aucune résolution vers #1 possible)"); }

        // (b) run devenu terminal ('cancelled') -> la suppression PASSE.
        { let db = app.db(); db.execute("UPDATE run_job SET status='cancelled' WHERE run_id='rlive'", []).unwrap(); }
        let ok = engagement_do_delete(&app, 2, "adm").expect("delete OK une fois le run terminal");
        assert_eq!(ok["ok"], true, "suppression réussie");
        { let n: i64 = app.db().query_row("SELECT COUNT(*) FROM engagement WHERE id=2", [], |r| r.get(0)).unwrap();
          assert_eq!(n, 0, "l'engagement #2 est supprimé une fois le run terminal"); }
        let _ = std::fs::remove_file(&ledger);
    }

    /// [M1 — le RE-CHECK EN-TX est autoritaire ET la cascade est ATOMIQUE] Prouve que le garde « run vivant »
    /// vit désormais À L'INTÉRIEUR de la tx de suppression, avant les DELETE : quand un run `running` existe,
    /// la closure renvoie une erreur SENTINELLE -> ROLLBACK -> AUCUNE ligne possédée n'est supprimée (ni la
    /// ligne engagement, NI ses findings, NI son run_job). C'est ce qui ferme le TOCTOU : check + delete
    /// sérialisent sous le même verrou d'écriture, il n'existe plus de fenêtre où un run bascule à `running`
    /// entre un pré-check et une tx séparée qui détruirait sa ligne run_job (résolution `/api/ingest` -> #1).
    #[tokio::test]
    async fn m1_intx_recheck_rolls_back_whole_cascade() {
        let ledger = tmp_path("forge-test-m1-atomic");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger); // ancre #1
        insert_test_engagement(&app, 2, &["a.example.com"], "grey", &ledger); // cible
        {
            let db = app.db();
            // un run VIVANT + une donnée POSSÉDÉE (finding) rattachés à l'engagement #2.
            db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('rlive2','c','running','propose',2)", []).unwrap();
            db.execute("INSERT INTO finding(title,target,campaign,engagement_id) VALUES('owned','h.example','c',2)", []).unwrap();
        }
        // Refus 409 (run vivant vu SOUS le verrou de la tx) + message explicite.
        let e = engagement_do_delete(&app, 2, "adm").unwrap_err();
        assert_eq!(e.0, StatusCode::CONFLICT, "run vivant re-vérifié en-tx -> 409");
        assert!(e.1.contains("en cours"), "message explicite: {}", e.1);
        // ROLLBACK TOTAL : engagement, finding ET run_job survivent tous (la cascade n'a rien supprimé).
        { let n: i64 = app.db().query_row("SELECT COUNT(*) FROM engagement WHERE id=2", [], |r| r.get(0)).unwrap();
          assert_eq!(n, 1, "engagement #2 intact (rollback)"); }
        { let n: i64 = app.db().query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=2", [], |r| r.get(0)).unwrap();
          assert_eq!(n, 1, "le finding possédé survit -> cascade atomique rollback (pas de suppression partielle)"); }
        { let s: String = app.db().query_row("SELECT status FROM run_job WHERE run_id='rlive2'", [], |r| r.get(0)).unwrap();
          assert_eq!(s, "running", "la ligne run_job survit -> aucune résolution /api/ingest vers #1"); }
        let _ = std::fs::remove_file(&ledger);
    }

    /// [ISOLATION] Deux engagements aux scopes DISJOINTS restent isolés : un run pour A valide contre le
    /// scope de A UNIQUEMENT (la cible de B est refusée), et réciproquement. Un run pour B accepte sa
    /// propre cible et journalise dans SON ledger — jamais celui de A.
    #[tokio::test]
    async fn two_engagements_stay_isolated_run_validates_own_scope() {
        let ledger_a = tmp_path("forge-test-engA-ledger");
        let ledger_b = tmp_path("forge-test-engB-ledger");
        // App globals volontairement PERMISSIFS (les 2 hosts) : prouve que la validation vient bien du
        // scope de l'engagement (disjoint), pas des globals (qui accepteraient tout).
        let mut app = test_app_scoped(&ledger_a, vec!["a.example.com".into(), "b.example.com".into()]);
        app.python = Arc::new("true".into());
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
        }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger_a); // A
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger_b); // B
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // A ne valide QUE le scope de A : la cible de B est refusée pour l'engagement A.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cA", Some(1), &["b.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "A refuse la cible de B (isolation)");
        // B ne valide QUE le scope de B : la cible de A est refusée pour l'engagement B.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cB", Some(2), &["a.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "B refuse la cible de A (isolation)");

        // B accepte SA propre cible et journalise dans le ledger de B (jamais celui de A).
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cB", Some(2), &["b.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "B accepte sa propre cible");
        let entries_b = read_ledger_lines(&ledger_b);
        assert!(entries_b.iter().any(|e| e["kind"] == "console.run.start" && e["detail"]["engagement_id"] == 2),
            "run de B journalisé dans le ledger de B");
        let entries_a = read_ledger_lines(&ledger_a);
        assert!(!entries_a.iter().any(|e| e["kind"] == "console.run.start"),
            "le ledger de A ne reçoit JAMAIS le run de B (isolation ledger)");

        let _ = std::fs::remove_file(&ledger_a);
        let _ = std::fs::remove_file(&ledger_b);
    }

    /// [CONCURRENCE INTER-ENGAGEMENT + FIFO PAR ENGAGEMENT] Le slot de run n'est PLUS un FIFO
    /// console-global : c'est une map `engagement_id -> RunHandle`. Ce test prouve, de façon
    /// déterministe (slots posés à la main, sans dépendre de la durée d'un process), que :
    ///   (1) DEUX engagements peuvent avoir un run vivant EN MÊME TEMPS (la map porte 2 clés) ;
    ///   (2) un 2e /api/run sur un engagement DÉJÀ vivant -> 409 (FIFO PAR engagement), et le 409 porte
    ///       le bon engagement_id ;
    ///   (3) démarrer un run pour un TROISIÈME engagement pendant que #1 et #2 sont vivants -> 202
    ///       (aucun 409 croisé — la concurrence inter-engagement est réelle) ;
    ///   (4) le run de #3 est journalisé dans le ledger de #3 UNIQUEMENT (jamais ceux de #1/#2).
    // ALLOW significant_drop_tightening: the fixture below holds the run_state guard across two inserts +
    // an invariant assertion so the two simultaneous live runs are published as one atomic unit (mirrors
    // the production promotion). Nursery-lint FP on a deliberately-atomic block.
    #[allow(clippy::significant_drop_tightening)]
    #[tokio::test]
    async fn run_slot_is_per_engagement_not_global_fifo() {
        let ledger_a = tmp_path("forge-test-conc-A");
        let ledger_b = tmp_path("forge-test-conc-B");
        let ledger_c = tmp_path("forge-test-conc-C");
        // Globals volontairement PERMISSIFS (les 3 hosts) : la validation vient du scope de l'engagement.
        let mut app = test_app_scoped(&ledger_a,
            vec!["a.example.com".into(), "b.example.com".into(), "c.example.com".into()]);
        app.python = Arc::new("true".into()); // spawn no-op : le run #3 aboutit sans lancer le moteur
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
        }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger_a); // A
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger_b); // B
        insert_test_engagement(&app, 3, &["c.example.com"], "grey", &ledger_c); // C
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // (1) On pose À LA MAIN deux runs vivants simultanés (A sous la clé 1, B sous la clé 2). pgid=-1
        // => kill_group ignore (aucun process réel visé). Deux engagements vivants EN MÊME TEMPS.
        {
            let mut st = app.run_state.lock().await;
            st.current.insert(1, RunHandle { run_id: "run-held-A".into(), pgid: -1 });
            st.current.insert(2, RunHandle { run_id: "run-held-B".into(), pgid: -1 });
            assert_eq!(st.current.len(), 2, "deux engagements ont un run vivant EN MÊME TEMPS (map à 2 clés)");
        }

        // (2) 2e run sur un engagement DÉJÀ vivant -> 409, avec l'engagement_id fautif dans le corps.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cA2", Some(1), &["a.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "2e run sur #1 (déjà vivant) -> 409 (FIFO par engagement)");
        let j = resp_json(resp).await;
        assert_eq!(j["error"], "run_in_progress");
        assert_eq!(j["engagement_id"], 1, "le 409 identifie l'engagement occupé (#1)");
        // idem pour #2 (l'autre engagement vivant) -> 409, jamais un faux 202.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cB2", Some(2), &["b.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "2e run sur #2 (déjà vivant) -> 409");
        assert_eq!(resp_json(resp).await["engagement_id"], 2);

        // (3) un run pour un TROISIÈME engagement pendant que #1 ET #2 sont vivants -> 202 (aucun 409
        // croisé : la présence de runs pour #1/#2 n'entrave pas #3). C'est LA preuve de la concurrence.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cC", Some(3), &["c.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED,
            "run pour #3 pendant que #1 et #2 sont vivants -> 202 (concurrence inter-engagement, pas de 409 croisé)");
        // run_job de #3 estampillé engagement_id=3.
        let eid3: i64 = { let db = app.db(); db.query_row("SELECT engagement_id FROM run_job WHERE campaign='cC'", [], |r| r.get(0)).unwrap() };
        assert_eq!(eid3, 3, "le run concurrent porte l'engagement #3");

        // (4) isolation ledger : run.start de #3 dans SON ledger, JAMAIS dans ceux de #1/#2.
        assert!(read_ledger_lines(&ledger_c).iter().any(|e| e["kind"] == "console.run.start" && e["detail"]["engagement_id"] == 3),
            "run.start de #3 journalisé dans le ledger de #3");
        assert!(!read_ledger_lines(&ledger_a).iter().any(|e| e["kind"] == "console.run.start"),
            "le ledger de #1 ne reçoit PAS le run de #3 (isolation)");
        assert!(!read_ledger_lines(&ledger_b).iter().any(|e| e["kind"] == "console.run.start"),
            "le ledger de #2 ne reçoit PAS le run de #3 (isolation)");

        let _ = std::fs::remove_file(&ledger_a);
        let _ = std::fs::remove_file(&ledger_b);
        let _ = std::fs::remove_file(&ledger_c);
    }

    /// [ISOLATION VERROUILLÉE] Un run pour A écrit UNIQUEMENT le ledger de A et n'altère RIEN de B :
    ///   - PROBE (fail-closed) : un run de A contre une cible qui n'est QUE dans le scope de B est
    ///     refusé (400 out_of_scope) — A ne peut PAS tirer sur le périmètre de B (isolation par scope) ;
    ///   - le run de A (sur sa propre cible) est ACCEPTÉ et journalisé dans le ledger de A ;
    ///   - le ledger de B est INCHANGÉ (aucune ligne ajoutée, aucun run.start de A) ;
    ///   - les findings de B (engagement_id=2) sont INTACTS (nombre + contenu).
    #[tokio::test]
    async fn run_for_a_writes_only_a_ledger_and_leaves_b_untouched() {
        let ledger_a = tmp_path("forge-test-lock-A");
        let ledger_b = tmp_path("forge-test-lock-B");
        // Globals permissifs (a+b) : la validation doit venir du scope de l'engagement, pas des globals.
        let mut app = test_app_scoped(&ledger_a, vec!["a.example.com".into(), "b.example.com".into()]);
        app.python = Arc::new("true".into());
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
            // Sème l'état de B : un finding (engagement_id=2) + une entrée de ledger propre à B.
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('finding-de-B','b.example.com','cB','HIGH',2)", []).unwrap();
        }
        ledger_append_standalone(&ledger_b, "engagement.seed", &json!({"note": "état initial de B"})).unwrap();
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger_a); // A
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger_b); // B
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // Instantané de l'état de B AVANT tout run de A.
        let b_ledger_before = read_ledger_lines(&ledger_b).len();
        let b_findings_before: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=2", [], |r| r.get(0)).unwrap() };
        assert_eq!(b_findings_before, 1, "B a bien 1 finding au départ");

        // PROBE : A ne peut PAS tirer contre une cible qui n'est QUE dans le scope de B -> 400 out_of_scope.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cA-probe", Some(1), &["b.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "A refuse une cible du scope de B (probe d'isolation)");
        assert_eq!(resp_json(resp).await["error"], "out_of_scope");

        // Run LÉGITIME de A sur sa propre cible -> 202, journalisé dans le ledger de A.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cA", Some(1), &["a.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "A accepte SA propre cible");
        assert!(read_ledger_lines(&ledger_a).iter().any(|e| e["kind"] == "console.run.start" && e["detail"]["engagement_id"] == 1),
            "run.start de A journalisé dans le ledger de A");

        // VERROU : B est resté totalement intact — ledger et findings.
        let b_ledger_after = read_ledger_lines(&ledger_b);
        assert_eq!(b_ledger_after.len(), b_ledger_before, "le ledger de B n'a reçu AUCUNE ligne d'un run de A");
        assert!(!b_ledger_after.iter().any(|e| e["kind"] == "console.run.start"),
            "aucun run.start (a fortiori de A) n'apparaît dans le ledger de B");
        let b_findings_after: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=2", [], |r| r.get(0)).unwrap() };
        assert_eq!(b_findings_after, b_findings_before, "les findings de B sont intacts (nombre inchangé)");
        let b_title: String = { let db = app.db(); db.query_row("SELECT title FROM finding WHERE engagement_id=2 LIMIT 1", [], |r| r.get(0)).unwrap() };
        assert_eq!(b_title, "finding-de-B", "le finding de B est intact (contenu inchangé)");

        let _ = std::fs::remove_file(&ledger_a);
        let _ = std::fs::remove_file(&ledger_b);
    }

    /// [ENGAGEMENT — vues filtrées] Les endpoints de LISTE ne renvoient QUE les données de l'engagement
    /// ciblé par `?engagement=<id>` : les findings/runrecords/roe/runs/campagnes/couverture de A ne sont
    /// JAMAIS visibles sous B, et réciproquement (isolation stricte des vues, fail-closed).
    #[tokio::test]
    async fn list_endpoints_filter_by_engagement() {
        let ledger = tmp_path("forge-test-eng-list");
        let ledger2 = tmp_path("forge-test-eng-list2");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger);
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger2);
        {
            let db = app.db();
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('fa','a.example.com','cA','HIGH',1)", []).unwrap();
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('fb','b.example.com','cB','LOW',2)", []).unwrap();
            db.execute("INSERT INTO runrecord(campaign,target,kind,mitre,fired,engagement_id) VALUES('cA','a.example.com','recon.http','T1190',1,1)", []).unwrap();
            db.execute("INSERT INTO runrecord(campaign,target,kind,mitre,fired,engagement_id) VALUES('cB','b.example.com','recon.http','T1046',1,2)", []).unwrap();
            db.execute("INSERT INTO roe_decision(campaign,run_id,action_id,target,kind,verdict,engagement_id) VALUES('cA','r1','a1','a.example.com','recon.http','FIRE',1)", []).unwrap();
            db.execute("INSERT INTO roe_decision(campaign,run_id,action_id,target,kind,verdict,engagement_id) VALUES('cB','r2','a2','b.example.com','recon.http','VETO',2)", []).unwrap();
            db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('r1','cA','done','propose',1)", []).unwrap();
            db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('r2','cB','done','propose',2)", []).unwrap();
        }

        // findings : #1 ne voit que fa, #2 que fb.
        let j = resp_json(findings(State(app.clone()), HeaderMap::new(), eng_query(1)).await.into_response()).await;
        let t1: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(t1.contains(&"fa".to_string()) && !t1.contains(&"fb".to_string()), "engagement #1 ne voit que SES findings");
        let j = resp_json(findings(State(app.clone()), HeaderMap::new(), eng_query(2)).await.into_response()).await;
        let t2: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(t2.contains(&"fb".to_string()) && !t2.contains(&"fa".to_string()), "engagement #2 ne voit que SES findings");

        // runrecords : isolés par engagement.
        let j = resp_json(runrecords(State(app.clone()), HeaderMap::new(), eng_query(1)).await.into_response()).await;
        assert!(j.as_array().unwrap().iter().all(|x| x["campaign"] == "cA"), "runrecords #1 isolés");
        assert!(!j.as_array().unwrap().is_empty(), "runrecords #1 non vides");

        // roe : isolés par engagement.
        let j = resp_json(roe(State(app.clone()), HeaderMap::new(), eng_query(2)).await.into_response()).await;
        assert!(j.as_array().unwrap().iter().all(|x| x["campaign"] == "cB"), "roe #2 isolés");

        // runs : isolés par engagement.
        let j = resp_json(runs_list(State(app.clone()), HeaderMap::new(), eng_query(1)).await.into_response()).await;
        assert!(j.as_array().unwrap().iter().all(|x| x["campaign"] == "cA"), "runs #1 isolés");

        // campagnes (dérivées des findings) : isolées par engagement.
        let j = resp_json(campaigns(State(app.clone()), HeaderMap::new(), eng_query(2)).await.into_response()).await;
        let camps: Vec<String> = j.as_array().unwrap().iter().map(|c| c["campaign"].as_str().unwrap().to_string()).collect();
        assert!(camps.contains(&"cB".to_string()) && !camps.contains(&"cA".to_string()), "campagnes #2 isolées");

        // couverture ATT&CK : isolée par engagement (T1190 chez #1, T1046 chez #2).
        let j = resp_json(coverage(State(app.clone()), HeaderMap::new(), eng_query(1)).await.into_response()).await;
        let mitres: Vec<String> = j.as_array().unwrap().iter().map(|c| c["mitre"].as_str().unwrap().to_string()).collect();
        assert!(mitres.contains(&"T1190".to_string()) && !mitres.contains(&"T1046".to_string()), "couverture #1 isolée");

        // finding_detail : un id de #2 n'est PAS servi sous #1 (404, isolation).
        let fid_b: i64 = { let db = app.db(); db.query_row("SELECT id FROM finding WHERE title='fb'", [], |r| r.get(0)).unwrap() };
        let resp = finding_detail(State(app.clone()), HeaderMap::new(), Path(fid_b), eng_query(1)).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "détail d'un finding d'un AUTRE engagement -> 404");
        let resp = finding_detail(State(app.clone()), HeaderMap::new(), Path(fid_b), eng_query(2)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "détail servi dans SON engagement");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    // =====================================================================================
    // ENTERPRISE — ROW-LEVEL MULTI-TENANCY (tenancy.rs), flag-gated. Fail-closed tenant isolation +
    // community no-op (byte-identical). Ces tests sont MUTATION-PROVABLES : affaiblir le filtre central
    // (tenancy::engagement_visible / engagement_in / granted_tenants) fait passer un test AU ROUGE.
    // =====================================================================================


    // =====================================================================================
    // R5b — CONTEXTE D'AUTHENTIFICATION PAR-ENGAGEMENT : éditeur structuré (validate_engagement_scope
    // PRÉSERVE le bloc `auth`), round-trip store/load lossless, résumé RÉDIGÉ pour l'UI, et no-op strict
    // (aucun bloc auth => scope_json byte-identique, aucun champ `auth`). MUTATION-PROVABLE : retirer la
    // préservation de `auth` dans validate_engagement_scope fait passer ces tests AU ROUGE.
    // =====================================================================================

    /// validate_engagement_scope PRÉSERVE le bloc `auth` (round-trip lossless des valeurs) ET l'omet
    /// quand il est vide/absent (byte-identique à l'historique => no-op strict).
    #[test]
    fn engagement_scope_preserves_auth_block_or_omits_it() {
        // (a) NO-OP : sans bloc auth, la sortie est EXACTEMENT la chaîne historique (aucun champ `auth`).
        let plain = json!({"mode": "grey", "in_scope": ["app.test"], "out_scope": []});
        let (canon_plain, _m) = validate_engagement_scope(&plain).expect("scope plain valide");
        let expect_plain = json!({"mode": "grey", "in_scope": ["app.test"], "out_scope": []}).to_string();
        assert_eq!(canon_plain, expect_plain, "sans auth => scope_json byte-identique (no-op)");
        assert!(!canon_plain.contains("auth"), "aucun champ auth injecté sur un scope sans auth");

        // (b) avec un bloc auth non trivial => PRÉSERVÉ (labels, matériel, cibles) VERBATIM.
        let with_auth = json!({
            "mode": "grey", "in_scope": ["app.test"], "out_scope": [],
            "auth": {
                "accounts": [
                    {"label": "attacker", "bearer": "S3CR3T-tok"},
                    {"label": "victim", "cookies": {"sid": "V1CT1M"}, "headers": {"X-CSRF": "abc"}}
                ],
                "idor_targets": [{"url": "https://app.test/api/me", "owner": "victim", "marker": "MK-9z"}]
            }
        });
        let (canon, _m) = validate_engagement_scope(&with_auth).expect("scope+auth valide");
        let v: Value = serde_json::from_str(&canon).unwrap();
        let a = v.get("auth").expect("bloc auth préservé");
        assert_eq!(a["accounts"][0]["label"], json!("attacker"));
        assert_eq!(a["accounts"][0]["bearer"], json!("S3CR3T-tok"), "bearer préservé VERBATIM");
        assert_eq!(a["accounts"][1]["cookies"]["sid"], json!("V1CT1M"), "cookie préservé VERBATIM");
        assert_eq!(a["accounts"][1]["headers"]["X-CSRF"], json!("abc"), "header préservé VERBATIM");
        assert_eq!(a["idor_targets"][0]["url"], json!("https://app.test/api/me"));
        assert_eq!(a["idor_targets"][0]["marker"], json!("MK-9z"));

        // (c) un compte SANS matériel d'auth est DROPPÉ ; un bloc totalement vide => OMIS (no-op).
        let empty_material = json!({
            "mode": "grey", "in_scope": ["app.test"], "out_scope": [],
            "auth": {"accounts": [{"label": "ghost"}], "idor_targets": []}
        });
        let (canon_e, _m) = validate_engagement_scope(&empty_material).expect("valide");
        assert!(!canon_e.contains("auth"), "compte sans matériel + aucune cible => bloc auth OMIS (no-op)");

        // (d) forme invalide => Err (400 en amont).
        let bad = json!({"mode": "grey", "in_scope": ["app.test"], "auth": {"accounts": "not-an-array"}});
        assert!(validate_engagement_scope(&bad).is_err(), "accounts non-tableau => refus");
    }

    /// ROUND-TRIP STORE/LOAD : un engagement dont le scope_json PORTE un bloc auth le rend via
    /// load_engagement (eng.auth = Some, valeurs intactes) ; un engagement SANS auth => eng.auth = None.
    #[test]
    fn engagement_auth_survives_store_and_load() {
        let app = test_app("");
        // scope_json canonicalisé PAR le validateur (chemin de production exact) puis stocké.
        let with_auth = json!({
            "mode": "grey", "in_scope": ["app.test"], "out_scope": [],
            "auth": {
                "accounts": [{"label": "attacker", "bearer": "S3CR3T-tok"}],
                "idor_targets": [{"url": "https://app.test/api/me", "owner": "victim", "marker": "MK"}]
            }
        });
        let (canon, mode) = validate_engagement_scope(&with_auth).expect("valide");
        app.db().execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(41,'eng-auth','active',?,?, '', datetime('now'),datetime('now'))",
            rusqlite::params![mode, canon],
        ).unwrap();
        let eng = load_engagement(&app.store(), 41).expect("engagement chargé");
        let a = eng.auth.expect("eng.auth = Some (bloc préservé au chargement)");
        assert_eq!(a["accounts"][0]["bearer"], json!("S3CR3T-tok"), "bearer intact après store/load");
        assert_eq!(a["idor_targets"][0]["marker"], json!("MK"));

        // engagement SANS auth => eng.auth = None (=> le run flow n'émet aucun champ auth => no-op).
        insert_test_engagement(&app, 42, &["app.test"], "grey", "");
        let eng2 = load_engagement(&app.store(), 42).expect("engagement 2 chargé");
        assert!(eng2.auth.is_none(), "aucun bloc auth => eng.auth = None (no-op)");
    }

    /// auth_summary_json (exposé à l'éditeur) ne renvoie AUCUN secret : les valeurs bearer/cookies/headers
    /// n'apparaissent jamais ; seuls des booléens de présence + les NOMS d'en-têtes (non secrets) + les
    /// url/owner/marker (config) sont exposés.
    #[test]
    fn auth_summary_is_redacted_for_the_editor() {
        let scope_v = json!({
            "mode": "grey", "in_scope": ["app.test"],
            "auth": {
                "accounts": [{"label": "attacker", "bearer": "S3CR3T-tok", "headers": {"X-CSRF": "hidden-val"}},
                             {"label": "victim", "cookies": {"sid": "V1CT1M"}}],
                "idor_targets": [{"url": "https://app.test/api/me", "owner": "victim", "marker": "MK"}]
            }
        });
        let s = auth_summary_json(&scope_v).expect("résumé présent");
        let blob = s.to_string();
        assert!(!blob.contains("S3CR3T-tok"), "bearer JAMAIS exposé");
        assert!(!blob.contains("hidden-val"), "valeur d'en-tête JAMAIS exposée");
        assert!(!blob.contains("V1CT1M"), "valeur de cookie JAMAIS exposée");
        // structure ré-affichable : labels + présence + noms d'en-têtes + cibles (non secrets).
        assert_eq!(s["accounts"][0]["label"], json!("attacker"));
        assert_eq!(s["accounts"][0]["has_bearer"], json!(true));
        assert_eq!(s["accounts"][0]["header_keys"], json!(["X-CSRF"]), "noms d'en-têtes (non secrets) exposés");
        assert_eq!(s["accounts"][1]["has_cookies"], json!(true));
        assert_eq!(s["idor_targets"][0]["url"], json!("https://app.test/api/me"));
        assert_eq!(s["idor_targets"][0]["marker"], json!("MK"));
        // aucun bloc auth => None (=> champ absent du payload liste => byte-identique).
        assert!(auth_summary_json(&json!({"mode": "grey", "in_scope": ["app.test"]})).is_none());
    }

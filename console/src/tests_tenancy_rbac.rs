// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — tests d'intégration : tenancy isolation, per-engagement RBAC, superadmin, tenant + engagement CRUD.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

    /// [TENANCY — community no-op] Flag OFF (défaut) : le filtre tenant est INERTE. Un user SANS aucun
    /// grant voit TOUS les engagements et TOUTES leurs données (comportement mono-tenant historique,
    /// byte-identique). C'est la garantie « default build = single implicit tenant ».
    #[tokio::test]
    async fn tenancy_disabled_is_community_noop() {
        let ledger = tmp_path("forge-test-tnc-noop");
        let ledger2 = tmp_path("forge-test-tnc-noop2");
        // seed_two_tenants ENGAGE le flag ; on le DÉSACTIVE pour ce test (config community).
        let (app, alice, _bob, _fa, fid_b) = seed_two_tenants(&ledger, &ledger2);
        { let db = app.db(); db.execute("DELETE FROM settings WHERE key='enterprise.tenancy'", []).unwrap(); }
        assert!(!tenancy::enabled(&app), "flag OFF => community");

        // alice n'a de grant QUE sur tenant 1, mais en community elle voit AUSSI le tenant 2 (no-op).
        assert!(tenancy::engagement_visible(&app, &alice, 2), "community : visibilité universelle (no-op)");
        let engs = engagement_list_json(&app, &alice);
        assert_eq!(engs.len(), 2, "community : la liste montre les DEUX engagements (no filtre)");
        // findings de l'engagement #2 servis à alice malgré l'absence de grant (mono-tenant).
        let j = resp_json(findings(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await;
        let titles: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(titles.contains(&"fb".to_string()), "community : findings de #2 visibles (no-op)");
        // finding_detail d'un id de #2 servi sous #2 (200) même sans grant.
        let resp = finding_detail(State(app.clone()), alice.clone(), Path(fid_b), eng_query(2)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "community : détail servi (no-op)");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY — fail-closed cross-tenant] ENTERPRISE ON. alice (tenant A) ne peut NI LISTER, NI LIRE,
    /// NI AGIR sur les engagements/findings/runs/roe/ledger/couverture/rapport de bob (tenant B), et
    /// réciproquement. Aucun grant => zéro ligne / 403 (deny-by-default, comme le ROE).
    ///
    /// ⚠️ MUTATION-PROOF : si l'on affaiblit le filtre central (ex. `engagement_in`/`engagement_visible`
    /// renvoient `true`), `view_engagement_id(alice, Some(2))` cesserait de renvoyer NO_ENGAGEMENT et les
    /// findings/runs de B DÉBORDERAIENT chez alice -> les asserts « n'est PAS visible » passent AU ROUGE.
    #[tokio::test]
    async fn enterprise_tenant_isolation_is_fail_closed() {
        let ledger = tmp_path("forge-test-tnc-iso");
        let ledger2 = tmp_path("forge-test-tnc-iso2");
        let (app, alice, bob, _fa, fid_b) = seed_two_tenants(&ledger, &ledger2);
        assert!(tenancy::enabled(&app), "flag ON => enterprise");

        // (a) LISTE : alice ne voit QUE l'engagement de son tenant (A), bob QUE le sien (B).
        let ea: Vec<i64> = engagement_list_json(&app, &alice).iter().map(|e| e["id"].as_i64().unwrap()).collect();
        assert_eq!(ea, vec![1], "alice ne liste QUE l'engagement de son tenant");
        let eb: Vec<i64> = engagement_list_json(&app, &bob).iter().map(|e| e["id"].as_i64().unwrap()).collect();
        assert_eq!(eb, vec![2], "bob ne liste QUE l'engagement de son tenant");

        // (b) FINDINGS : alice voit fa (A), JAMAIS fb (B) — même en ciblant explicitement ?engagement=2.
        let j = resp_json(findings(State(app.clone()), alice.clone(), eng_query(1)).await.into_response()).await;
        let ta: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(ta.contains(&"fa".to_string()), "alice voit SES findings");
        let j = resp_json(findings(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await;
        assert!(j["findings"].as_array().unwrap().is_empty(), "alice ne voit AUCUN finding de B (fail-closed)");

        // (c) FINDING_DETAIL : un id de B n'est PAS servi à alice, même sous ?engagement=2 -> 404.
        let resp = finding_detail(State(app.clone()), alice.clone(), Path(fid_b), eng_query(2)).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "détail d'un finding de B refusé à alice (404)");

        // (d) RUNRECORDS / ROE / RUNS / COVERAGE de B invisibles à alice.
        assert!(resp_json(runrecords(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await.as_array().unwrap().is_empty(), "runrecords de B invisibles");
        assert!(resp_json(roe(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await.as_array().unwrap().is_empty(), "roe de B invisibles");
        assert!(resp_json(runs_list(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await.as_array().unwrap().is_empty(), "runs de B invisibles");
        assert!(resp_json(coverage(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await.as_array().unwrap().is_empty(), "couverture de B invisible");

        // (e) LEDGER : alice n'obtient PAS le ledger de B — ni entrées, ni chemin (aucun repli/leak).
        let jl = resp_json(super::ledger(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await;
        assert!(jl["entries"].as_array().unwrap().is_empty(), "ledger de B : aucune entrée servie à alice");
        assert_eq!(jl["path"].as_str().unwrap(), "", "ledger de B : aucun chemin divulgué (pas de repli sur le ledger par défaut)");

        // (f) RAPPORT / ÉDITION / RUN : le prédicat de garde (engagement_visible) refuse tout acte de A sur B.
        assert!(!tenancy::engagement_visible(&app, &alice, 2), "alice ne voit pas l'engagement de B (gate rapport/CRUD)");
        assert!(tenancy::engagement_visible(&app, &bob, 2), "bob voit SON engagement");
        // run_create : alice ne peut cibler l'engagement de B (resolve -> Err, run refusé AVANT tout spawn).
        assert!(resolve_engagement(&app, &alice, Some(2)).is_err(), "alice ne peut lancer un run sur l'engagement de B");
        assert!(resolve_engagement(&app, &bob, Some(2)).is_ok(), "bob peut lancer un run sur SON engagement");
        // technique-selection / workflows (mutation par-engagement) : refus cross-tenant.
        let q2 = HashMap::from([("engagement".to_string(), "2".to_string())]);
        assert!(resolve_mutation_engagement_id(&app, &alice, &q2, &json!({})).is_err(), "alice ne peut poser une config par-engagement sur B");
        assert!(resolve_mutation_engagement_id(&app, &bob, &q2, &json!({})).is_ok(), "bob peut poser une config sur SON engagement");

        // (g) ÉDITION/ARCHIVE/SUPPRESSION cross-tenant via le handler -> 404 (jamais divulgué ni muté).
        let resp = engagements_update(State(app.clone()), conn_info(), alice.clone(), Path(2i64),
            Json(json!({"name": "pwned-by-A"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "alice ne peut PAS éditer l'engagement de B (404)");
        {  let n: String = app.db().query_row("SELECT name FROM engagement WHERE id=2", [], |r| r.get(0)).unwrap();
          assert_ne!(n, "pwned-by-A", "l'engagement de B N'A PAS été muté par A"); }

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [H1 — surface SoQL brute tenant-scopée fail-closed] La surface `/api/query` (GET+POST) et
    /// `/api/panels/:id/data` compile une SoQL ARBITRAIRE sur TOUTE la table `finding`/`runrecord` SANS
    /// prédicat d'engagement (sa projection n'expose pas `engagement_id`), ce qui, en mode enterprise,
    /// laissait n'importe quelle session (même tenant_viewer) lire les findings de TOUS les tenants.
    /// Correctif fail-closed : la surface brute est REFUSÉE (403) dès que la tenancy est engagée — bob
    /// (tenant B) ne peut donc PAS lire les findings du tenant A via /api/query. Community (flag OFF) =>
    /// comportement INCHANGÉ (la SoQL renvoie les lignes ; l'engagement n'est pas une frontière de sécurité).
    ///
    /// ⚠️ MUTATION-PROOF : si `soql_tenancy_denied` cessait de refuser sous tenancy, la 1re assertion
    /// (403 pour bob) ET l'absence de "fa"/"fb" dans une réponse serviraient AU ROUGE.
    #[tokio::test]
    async fn h1_raw_soql_surface_tenant_scoped_fail_closed() {
        let ledger = tmp_path("forge-test-h1-soql");
        let ledger2 = tmp_path("forge-test-h1-soql2");
        let (app, alice, bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        assert!(tenancy::enabled(&app), "flag ON => enterprise");

        // (a) ENTERPRISE : /api/query (GET) refusé (403) — bob NE PEUT PAS lire les findings du tenant A.
        let q = Query(HashMap::from([("q".to_string(), "search".to_string())]));
        let resp = query(State(app.clone()), q).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "enterprise : /api/query brut refusé (fail-closed)");
        let jb = resp_json(resp).await;
        assert_eq!(jb["error"].as_str(), Some("tenant_scoped_surface_required"), "erreur explicite");

        // (b) ENTERPRISE : POST /api/query (search) — même refus (aucune donnée cross-tenant servie).
        let resp = query_post(State(app.clone()), Json(json!({"soql": "search"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "enterprise : POST /api/query brut refusé");

        // (c) ENTERPRISE : panel_data (exécute la SoQL d'un panel) — refusé aussi.
        {   // un panel existe (semé au boot #1) ou on en crée un via SQL direct.
            let db = app.db();
            db.execute("INSERT OR IGNORE INTO panel(id,name,query,viz,position,dashboard_id,updated) VALUES(999,'p','search','table',0,1,datetime('now'))", []).unwrap();
        }
        let resp = panel_data(State(app.clone()), Path(999i64), Query(HashMap::new())).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "enterprise : /api/panels/:id/data brut refusé");

        // (d) ENTERPRISE : panels_list gaté — bob (granté sur tenant B) VOIT les définitions (il a un
        // engagement visible) ; un compte SANS grant obtient une liste VIDE (fail-closed).
        let _ = bob; // bob est granté ; le cas grantless est couvert par carol ci-dessous.
        { let db = app.db(); upsert_user(&db, "nogrant", "viewer", &hash_pw("pw")).unwrap(); }
        let (ntok, _) = create_session(&app, uid_of(&app, "nogrant"));
        let ng = bearer_headers(&ntok);
        let jl = resp_json(panels_list(State(app.clone()), ng, Query(HashMap::new())).await.into_response()).await;
        assert!(jl.as_array().unwrap().is_empty(), "panels_list : appelant sans grant -> liste VIDE (fail-closed)");

        // (e) COMMUNITY (flag OFF) : le gate enterprise est LEVÉ -> comportement INCHANGÉ (plus de 403). On
        // désengage le flag. NB : en test in-memory (db_path=':memory:') la connexion read-only SÉPARÉE
        // qu'ouvre le moteur SoQL est vide -> 400 (artefact de harness), mais JAMAIS 403 : la preuve = le
        // gate est disengagé. Le service RÉEL de données (via le store partagé) est prouvé par panels_list.
        { let db = app.db(); db.execute("DELETE FROM settings WHERE key='enterprise.tenancy'", []).unwrap(); }
        assert!(!tenancy::enabled(&app), "flag OFF => community");
        let q = Query(HashMap::from([("q".to_string(), "search".to_string())]));
        let resp = query(State(app.clone()), q).await.into_response();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN, "community : /api/query n'est PLUS refusé (gate levé, inchangé)");
        // panels_list (lecture via le store PARTAGÉ) : non gaté en community -> la définition de panel semée
        // est servie normalement (preuve que le gate panels_list est bien un no-op community).
        let jl = resp_json(panels_list(State(app.clone()), alice.clone(), Query(HashMap::new())).await.into_response()).await;
        assert!(jl.as_array().unwrap().iter().any(|p| p["id"].as_i64() == Some(999)),
            "community : panels_list sert les définitions de panels (non gaté)");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY — sans grant = rien] ENTERPRISE ON. Un compte SANS aucun tenant_grant (carol) n'accède à
    /// RIEN : liste vide, résolution vers NO_ENGAGEMENT (zéro ligne), aucun engagement visible. Fail-closed
    /// deny-by-default (miroir du ROE). Le repli bootstrap (hash env) n'a pas non plus de grant.
    #[tokio::test]
    async fn enterprise_no_grant_sees_nothing() {
        let ledger = tmp_path("forge-test-tnc-nogrant");
        let ledger2 = tmp_path("forge-test-tnc-nogrant2");
        let (app, _alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // carol : compte activé mais AUCUN grant.
        { let db = app.db(); upsert_user(&db, "carol", "operator", &hash_pw("pw")).unwrap(); }
        let (ctok, _) = create_session(&app, uid_of(&app, "carol"));
        let carol = bearer_headers(&ctok);

        assert!(engagement_list_json(&app, &carol).is_empty(), "sans grant : aucune liste");
        assert_eq!(tenancy::view_engagement_id(&app, &carol, None), tenancy::NO_ENGAGEMENT, "sans grant : NO_ENGAGEMENT");
        assert_eq!(tenancy::view_engagement_id(&app, &carol, Some(1)), tenancy::NO_ENGAGEMENT, "sans grant : #1 non résolu");
        assert!(!tenancy::engagement_visible(&app, &carol, 1), "sans grant : #1 invisible");
        assert!(!tenancy::engagement_visible(&app, &carol, 2), "sans grant : #2 invisible");
        // requête anonyme (aucune session) : jamais aucun tenant accordé.
        assert!(tenancy::granted_tenants(&app, &HeaderMap::new()).is_empty(), "anonyme : aucun tenant accordé");
        let j = resp_json(findings(State(app.clone()), carol.clone(), eng_query(1)).await.into_response()).await;
        assert!(j["findings"].as_array().unwrap().is_empty(), "sans grant : aucun finding servi");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY — filtre central, unité] Sémantique exacte de tenancy::view_engagement_id / engagement_visible
    /// (l'ancre mutation-proof la plus directe : ces fonctions sont LE filtre). Enterprise ON.
    #[tokio::test]
    async fn tenancy_central_filter_semantics() {
        let ledger = tmp_path("forge-test-tnc-central");
        let ledger2 = tmp_path("forge-test-tnc-central2");
        let (app, alice, bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // visibilité stricte par appartenance tenant.
        assert!(tenancy::engagement_visible(&app, &alice, 1) && !tenancy::engagement_visible(&app, &alice, 2), "alice: A oui, B non");
        assert!(tenancy::engagement_visible(&app, &bob, 2) && !tenancy::engagement_visible(&app, &bob, 1), "bob: B oui, A non");
        // resolution explicite : id du tenant accordé -> id ; sinon NO_ENGAGEMENT.
        assert_eq!(tenancy::view_engagement_id(&app, &alice, Some(1)), 1);
        assert_eq!(tenancy::view_engagement_id(&app, &alice, Some(2)), tenancy::NO_ENGAGEMENT);
        // resolution par défaut (sans id) -> un engagement du tenant du caller (jamais NO_ENGAGEMENT s'il a un grant).
        assert_eq!(tenancy::view_engagement_id(&app, &alice, None), 1, "défaut alice -> son engagement");
        assert_eq!(tenancy::view_engagement_id(&app, &bob, None), 2, "défaut bob -> son engagement");
        // granted_tenants reflète les grants.
        assert!(tenancy::granted_tenants(&app, &alice).contains(&tenancy::DEFAULT_TENANT), "alice accède au tenant #1 (défaut)");
        assert!(tenancy::granted_tenants(&app, &bob).contains(&2) && !tenancy::granted_tenants(&app, &bob).contains(&1), "bob accède UNIQUEMENT à tenant 2");
        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [PER-ENGAGEMENT RBAC #14 — effective role, most-specific-wins, fail-closed] ENTERPRISE ON. Deux
    /// engagements (#1, #3) DANS LE MÊME tenant (1). alice est tenant_operator sur le tenant => operator sur
    /// LES DEUX par héritage. Un engagement_grant tenant_viewer sur #1 RÉTROGRADE alice à viewer sur #1
    /// SEULEMENT (most-specific-wins) : elle reste operator sur #3. Fail-closed : carol (aucun grant) n'a
    /// AUCUN rôle effectif. ⚠️ MUTATION-PROOF : si effective_engagement_role cessait de préférer l'override
    /// engagement, alice pourrait opérer sur #1 -> l'assert « viewer sur #1 » passe AU ROUGE.
    #[tokio::test]
    async fn per_engagement_rbac_effective_role_most_specific_wins() {
        let ledger = tmp_path("forge-test-eg-rbac");
        let ledger2 = tmp_path("forge-test-eg-rbac2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // 3e engagement DANS le tenant 1 (même tenant qu'alice).
        insert_test_engagement(&app, 3, &["a.example.com"], "grey", &ledger);
        set_engagement_tenant(&app, 3, 1);
        let uid_a = uid_of(&app, "alice");

        // (a) héritage tenant : alice (tenant_operator sur tenant 1) opère sur #1 ET #3.
        assert_eq!(tenancy::effective_engagement_role(&app, &alice, 1).as_deref(), Some("tenant_operator"), "alice hérite operator sur #1");
        assert_eq!(tenancy::effective_engagement_role(&app, &alice, 3).as_deref(), Some("tenant_operator"), "alice hérite operator sur #3");
        assert!(tenancy::can_operate_engagement(&app, &alice, 1) && tenancy::can_operate_engagement(&app, &alice, 3), "operator sur les deux (hérité)");
        assert!(!tenancy::can_admin_engagement(&app, &alice, 1), "tenant_operator n'est PAS admin engagement");

        // (b) override MOST-SPECIFIC : viewer sur #1 SEULEMENT.
        grant_engagement(&app, uid_a, 1, "tenant_viewer");
        assert_eq!(tenancy::effective_engagement_role(&app, &alice, 1).as_deref(), Some("tenant_viewer"), "override viewer sur #1 gagne");
        assert!(!tenancy::can_operate_engagement(&app, &alice, 1), "viewer-on-#1 : operate DENIED (fail-closed)");
        // #3 INCHANGÉ (toujours operator hérité) — la composition est par-engagement.
        assert_eq!(tenancy::effective_engagement_role(&app, &alice, 3).as_deref(), Some("tenant_operator"), "#3 reste operator");
        assert!(tenancy::can_operate_engagement(&app, &alice, 3), "operator-on-#3 : operate OK (operator sur A / viewer sur B)");

        // (c) override ADMIN sur #3 : alice devient tenant_admin sur #3 uniquement.
        grant_engagement(&app, uid_a, 3, "tenant_admin");
        assert!(tenancy::can_admin_engagement(&app, &alice, 3), "override admin sur #3");
        assert!(!tenancy::can_admin_engagement(&app, &alice, 1), "toujours pas admin sur #1");

        // (d) FAIL-CLOSED : carol (compte activé, AUCUN grant) n'a aucun rôle effectif -> ni operate ni admin.
        { let db = app.db(); upsert_user(&db, "carol", "operator", &hash_pw("pw")).unwrap(); }
        let (ctok, _) = create_session(&app, uid_of(&app, "carol"));
        let carol = bearer_headers(&ctok);
        assert!(tenancy::effective_engagement_role(&app, &carol, 1).is_none(), "carol : aucun rôle effectif (fail-closed)");
        assert!(!tenancy::can_operate_engagement(&app, &carol, 1) && !tenancy::can_operate_engagement(&app, &carol, 3), "carol : operate refusé partout");
        // requête anonyme (aucune session) : jamais aucun rôle effectif.
        assert!(tenancy::effective_engagement_role(&app, &HeaderMap::new(), 1).is_none(), "anonyme : aucun rôle effectif");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [PER-ENGAGEMENT RBAC #14 — handler wiring] ENTERPRISE ON. La mutation d'engagement (POST
    /// /api/engagements/:id, chemin edit=operator) est GATÉE par le rôle effectif par-engagement. alice
    /// (operator hérité) édite #1 -> OK ; après rétrogradation viewer sur #1 -> 403 engagement_operator_required,
    /// bien qu'elle VOIE toujours #1. Preuve du câblage fail-closed (pas seulement le helper).
    #[tokio::test]
    async fn per_engagement_rbac_edit_handler_gate() {
        let ledger = tmp_path("forge-test-eg-gate");
        let ledger2 = tmp_path("forge-test-eg-gate2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        let uid_a = uid_of(&app, "alice");

        // operator hérité : édition autorisée.
        let resp = engagements_update(State(app.clone()), conn_info(), alice.clone(), Path(1i64),
            Json(json!({"name": "renamed-by-operator"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "operator hérité : édition OK");

        // rétrogradation viewer sur #1 -> édition REFUSÉE (403), engagement toujours VISIBLE.
        grant_engagement(&app, uid_a, 1, "tenant_viewer");
        assert!(tenancy::engagement_visible(&app, &alice, 1), "viewer voit toujours #1");
        let resp = engagements_update(State(app.clone()), conn_info(), alice.clone(), Path(1i64),
            Json(json!({"name": "renamed-by-viewer"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer-on-#1 : édition refusée (403, fail-closed)");
        {  let n: String = app.db().query_row("SELECT name FROM engagement WHERE id=1", [], |r| r.get(0)).unwrap();
          assert_ne!(n, "renamed-by-viewer", "l'engagement n'a PAS été muté par le viewer"); }

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY — migration zéro-perte] ensure_default_tenant sur une base au SCHEMA courant : crée le
    /// tenant #1, rattache TOUS les engagements existants au tenant #1, et sème un grant tenant #1 pour
    /// CHAQUE utilisateur existant (rôle dérivé du RBAC). Idempotent (ne réécrit pas si un tenant existe).
    #[test]
    fn ensure_default_tenant_seeds_and_backfills() {
        // `conn()` rend une garde fraîche sur la MÊME connexion (le seeder prend désormais un `&Store` ;
        // les ops rusqlite directes + migrate gardent leur `&Connection` via le deref de la garde).
        let dbm = Mutex::new(Connection::open_in_memory().expect("mem db"));
        let conn = || dbm.lock().unwrap_or_else(|e| e.into_inner());
        conn().execute_batch(SCHEMA).expect("schema");
        migrate(&conn());
        // deux engagements + deux users AVANT toute provision tenant.
        conn().execute("INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path) VALUES(1,'e1','active','grey','{}','')", []).unwrap();
        conn().execute("INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path) VALUES(7,'e7','active','grey','{}','')", []).unwrap();
        conn().execute("INSERT INTO users(login,role,pass_hash,disabled,created) VALUES('root','admin','h',0,'')", []).unwrap();
        conn().execute("INSERT INTO users(login,role,pass_hash,disabled,created) VALUES('joe','viewer','h',0,'')", []).unwrap();

        ensure_default_tenant(&crate::store::Store::sqlite(conn()));
        // tenant #1 créé.
        let tcount: i64 = conn().query_row("SELECT COUNT(*) FROM tenant WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(tcount, 1, "tenant #1 (défaut) créé");
        // TOUS les engagements rattachés au tenant #1.
        let bad: i64 = conn().query_row("SELECT COUNT(*) FROM engagement WHERE tenant_id<>1", [], |r| r.get(0)).unwrap();
        assert_eq!(bad, 0, "tous les engagements existants -> tenant #1");
        // grants rétro-compat : chaque user existant accède au tenant #1, rôle dérivé du RBAC.
        let root_role: String = conn().query_row("SELECT g.role FROM tenant_grant g JOIN users u ON u.id=g.user_id WHERE u.login='root' AND g.tenant_id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(root_role, "tenant_admin", "admin -> tenant_admin");
        let joe_role: String = conn().query_row("SELECT g.role FROM tenant_grant g JOIN users u ON u.id=g.user_id WHERE u.login='joe' AND g.tenant_id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(joe_role, "tenant_viewer", "viewer -> tenant_viewer");

        // IDEMPOTENT : un 2e appel ne recrée rien ni n'écrase (renomme le tenant #1 -> doit rester).
        conn().execute("UPDATE tenant SET name='custom' WHERE id=1", []).unwrap();
        ensure_default_tenant(&crate::store::Store::sqlite(conn()));
        let n: String = conn().query_row("SELECT name FROM tenant WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(n, "custom", "ensure_default_tenant idempotent (n'écrase pas un provisioning existant)");
    }

    // =====================================================================================
    // ENTERPRISE — SUPER-ADMIN + TENANT CRUD + PER-TENANT LEDGER (tenancy.rs). Fail-closed, audited,
    // separable. Non-disablable super-admin (mirror Plume), audited cross-tenant READ, platform-admin
    // gated tenant CRUD, last-tenant/last-admin guards, tenant-scoped ledger paths.
    // =====================================================================================

    /// [SUPER-ADMIN — désignation fail-closed, provisioning-only] Sans désignation, PERSONNE n'est
    /// super-admin (même une session admin valide). La désignation (clé de provisioning) fait d'un admin
    /// un super-admin ; un login non désigné, un opérateur désigné, ou un anonyme ne le sont JAMAIS.
    #[test]
    fn superadmin_designation_is_fail_closed() {
        let ledger = tmp_path("forge-test-sa-desig");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        let root = admin_session(&app, "root");
        // aucune désignation => fail-closed (personne).
        assert!(!tenancy::is_superadmin(&app, &root), "aucune désignation => personne n'est super-admin");
        assert!(!tenancy::is_superadmin_login(&app, "root"), "root non désigné");
        // désignation via la clé de provisioning.
        designate_superadmin(&app, "root");
        assert!(tenancy::is_superadmin_login(&app, "root"), "root désigné");
        assert!(tenancy::is_superadmin(&app, &root), "root (session admin) est super-admin");
        // un AUTRE admin non désigné n'est pas super-admin.
        let mallory = admin_session(&app, "mallory");
        assert!(!tenancy::is_superadmin(&app, &mallory), "mallory non désignée => pas super-admin");
        // un login désigné mais NON admin (operator) n'est pas super-admin (session admin obligatoire).
        { let db = app.db(); upsert_user(&db, "opsa", "operator", &hash_pw("pw")).unwrap(); }
        designate_superadmin(&app, "root, opsa");
        let (otok, _) = create_session(&app, uid_of(&app, "opsa"));
        assert!(!tenancy::is_superadmin(&app, &bearer_headers(&otok)), "opérateur désigné => PAS super-admin (admin requis)");
        // anonyme (aucune session) jamais super-admin.
        assert!(!tenancy::is_superadmin(&app, &HeaderMap::new()), "anonyme jamais super-admin");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [SUPER-ADMIN — cross-tenant READ audité] Un super-admin (sans grant natif) LIT les données d'un
    /// autre tenant ; chaque accès émet `console.superadmin.access` (tenant + quoi). Un admin NON super
    /// (grant natif ailleurs) ne traverse PAS. ⚠️ MUTATION-PROOF : retirer le bypass super-admin de
    /// view_engagement_id fait échouer la lecture cross-tenant ; retirer l'audit fait échouer l'assert ledger.
    #[tokio::test]
    async fn superadmin_cross_tenant_read_is_ledgered() {
        let ledger = tmp_path("forge-test-sa-read");
        let ledger2 = tmp_path("forge-test-sa-read2");
        let (app, _alice, _bob, _fa, fid_b) = seed_two_tenants(&ledger, &ledger2);
        // root : admin, AUCUN grant natif, super-admin désigné.
        let root = admin_session(&app, "root");
        designate_superadmin(&app, "root");
        assert!(tenancy::is_superadmin(&app, &root), "root super-admin");
        // résolution cross-tenant explicite (tenant B) + lecture des findings de B.
        assert_eq!(tenancy::view_engagement_id(&app, &root, Some(2)), 2, "super-admin traverse vers l'engagement de B");
        let j = resp_json(findings(State(app.clone()), root.clone(), eng_query(2)).await.into_response()).await;
        let titles: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(titles.contains(&"fb".to_string()), "super-admin voit les findings du tenant B");
        let resp = finding_detail(State(app.clone()), root.clone(), Path(fid_b), eng_query(2)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "détail cross-tenant servi au super-admin");
        // AUDIT : au moins une entrée console.superadmin.access (tenant=2, actor=root).
        let hit = read_ledger_lines(&ledger).iter().any(|e| e["kind"] == "console.superadmin.access"
            && e["detail"]["tenant"] == json!(2) && e["detail"]["actor"] == json!("root"));
        assert!(hit, "cross-tenant read super-admin ledgerisé (console.superadmin.access, tenant=2)");

        // CONTRÔLE : un admin NON super-admin (grant natif tenant 1) ne traverse PAS vers B.
        let admin2 = admin_session(&app, "admin2");
        grant_tenant(&app, uid_of(&app, "admin2"), 1, "tenant_admin");
        assert!(!tenancy::is_superadmin(&app, &admin2), "admin2 non désigné => pas super-admin");
        assert_eq!(tenancy::view_engagement_id(&app, &admin2, Some(2)), tenancy::NO_ENGAGEMENT, "admin non-super ne traverse pas vers B");
        let j = resp_json(findings(State(app.clone()), admin2.clone(), eng_query(2)).await.into_response()).await;
        assert!(j["findings"].as_array().unwrap().is_empty(), "admin non-super ne voit AUCUN finding de B");
        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY CONTEXT — flag OFF = single implicit tenant, byte-identique] Le probe SPA GET /api/tenancy
    /// renvoie EXACTEMENT `{"enabled": false}` en community : c'est CE signal qui fait que le SPA ne rend
    /// AUCUNE surface tenant (ni sélecteur, ni vue #tenants, ni lien nav). La liste d'engagements n'expose
    /// alors PAS `tenant_id` (payload historique) et un user sans grant voit TOUS les engagements
    /// (mono-tenant, no-op) — un flux représentatif reste servi sans aucun filtrage tenant visible.
    #[tokio::test]
    async fn tenancy_context_flag_off_is_single_tenant() {
        let ledger = tmp_path("forge-test-tnc-ctx-off");
        let ledger2 = tmp_path("forge-test-tnc-ctx-off2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // community : on retire le flag semé par seed_two_tenants.
        { let db = app.db(); db.execute("DELETE FROM settings WHERE key='enterprise.tenancy'", []).unwrap(); }
        assert!(!tenancy::enabled(&app), "flag OFF => community");

        // /api/tenancy => {"enabled": false} STRICT — rien d'autre (pas de tenants, pas de super-admin).
        let ctx = resp_json(tenancy::tenancy_context(State(app.clone()), alice.clone()).await).await;
        assert_eq!(ctx, json!({"enabled": false}), "community : contexte tenant fermé (le SPA ne montre rien)");

        // Flux représentatif : liste d'engagements servie SANS `tenant_id` (byte-identique), un user sans
        // grant voit les DEUX engagements (visibilité universelle, no-op).
        let engs = engagement_list_json(&app, &alice);
        assert_eq!(engs.len(), 2, "community : les deux engagements listés (no filtre)");
        assert!(engs.iter().all(|e| e.get("tenant_id").is_none()), "community : aucun `tenant_id` exposé (byte-identique)");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY CONTEXT — flag ON = enforcement actif] Le probe SPA reflète le modèle multi-tenant : un
    /// user normal (alice, grant tenant 1) reçoit `enabled=true`, `is_platform_admin=false` et UNIQUEMENT
    /// son tenant ; un SUPER-ADMIN reçoit `is_platform_admin=true` et TOUS les tenants. La liste
    /// d'engagements expose alors `tenant_id` (hiérarchie tenant→engagement) et le filtre de grant reste
    /// fail-closed (alice ne liste QUE son engagement).
    /// ⚠️ MUTATION-PROOF : élargir `accessible_tenants` (renvoyer TOUS les tenants à un non-super-admin)
    /// fait passer l'assert « alice ne voit QUE le tenant 1 » AU ROUGE.
    #[tokio::test]
    async fn tenancy_context_flag_on_scopes_tenants_and_superadmin() {
        let ledger = tmp_path("forge-test-tnc-ctx-on");
        let ledger2 = tmp_path("forge-test-tnc-ctx-on2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        assert!(tenancy::enabled(&app), "flag ON => enterprise");

        // (a) user normal : enabled=true, PAS platform-admin, tenants = [1] uniquement (fail-closed).
        let ctx = resp_json(tenancy::tenancy_context(State(app.clone()), alice.clone()).await).await;
        assert_eq!(ctx["enabled"], json!(true), "flag ON => enabled");
        assert_eq!(ctx["is_platform_admin"], json!(false), "alice (operator) n'est pas platform-admin");
        assert_eq!(ctx["is_superadmin"], json!(false), "alice n'est pas super-admin");
        let tids: Vec<i64> = ctx["tenants"].as_array().unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect();
        assert_eq!(tids, vec![1], "alice ne voit QUE le tenant de son grant (fail-closed)");

        // (b) grant filter actif : liste d'engagements restreinte + `tenant_id` exposé (hiérarchie).
        let engs = engagement_list_json(&app, &alice);
        let ids: Vec<i64> = engs.iter().map(|e| e["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, vec![1], "alice ne liste QUE l'engagement de son tenant");
        assert_eq!(engs[0]["tenant_id"], json!(1), "flag ON => `tenant_id` exposé");

        // (c) SUPER-ADMIN : platform-admin + TOUS les tenants dans le contexte (surface #tenants + switch).
        let root = admin_session(&app, "root");
        designate_superadmin(&app, "root");
        let ctx = resp_json(tenancy::tenancy_context(State(app.clone()), root.clone()).await).await;
        assert_eq!(ctx["is_superadmin"], json!(true), "root désigné => super-admin");
        assert_eq!(ctx["is_platform_admin"], json!(true), "super-admin => platform-admin");
        let mut tids: Vec<i64> = ctx["tenants"].as_array().unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect();
        tids.sort_unstable();
        assert_eq!(tids, vec![1, 2], "super-admin voit TOUS les tenants");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANT_ADMIN de A -> 403 sur B] Un tenant_admin (rôle de GRANT) de A, non-admin console, ne voit
    /// RIEN de B (data) et ne peut PAS administrer les tenants (403) — ni B, ni le sien. « A normal
    /// tenant_admin can NEVER cross tenants. »
    #[tokio::test]
    async fn tenant_admin_of_a_cannot_cross_to_b() {
        let ledger = tmp_path("forge-test-ta-cross");
        let ledger2 = tmp_path("forge-test-ta-cross2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // alice : grant tenant_admin sur A, mais RBAC operator (pas admin console). uid_of AVANT le guard
        // DB (uid_of reverrouille le mutex — jamais en tenant `app.db()`).
        let ua = uid_of(&app, "alice");
        { let db = app.db(); db.execute("UPDATE tenant_grant SET role='tenant_admin' WHERE user_id=? AND tenant_id=1", [ua]).unwrap(); }
        // DATA : rien de B.
        assert_eq!(tenancy::view_engagement_id(&app, &alice, Some(2)), tenancy::NO_ENGAGEMENT, "tenant_admin de A ne traverse pas vers B");
        let j = resp_json(findings(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await;
        assert!(j["findings"].as_array().unwrap().is_empty(), "aucun finding de B");
        // MANAGEMENT : pas platform-admin => 403 sur le tenant B ET à la création.
        let resp = tenancy::tenant_grant_add(State(app.clone()), alice.clone(), Path(2i64), Json(json!({"login":"alice","role":"tenant_admin"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "tenant_admin (grant) de A -> 403 sur la gestion de B");
        let resp = tenancy::tenants_create(State(app.clone()), alice.clone(), Json(json!({"name":"AlicesTenant"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "un non-admin console ne crée pas de tenant (403)");
        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [SUPER-ADMIN — NON-DISABLABLE] Un super-admin désigné ne peut être désactivé / supprimé / rétrogradé
    /// sous admin (guard + handlers CRUD câblés). Deux admins présents => ce n'est PAS le garde-fou
    /// « dernier admin » qui joue, mais bien le marqueur super-admin (fail-closed).
    #[tokio::test]
    async fn superadmin_account_is_non_disablable() {
        let ledger = tmp_path("forge-test-sa-nondis");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        let _root = admin_session(&app, "root");
        let _backup = admin_session(&app, "backup"); // 2e admin => le garde-fou dernier-admin ne joue pas
        designate_superadmin(&app, "root");
        // guard unitaire.
        assert!(tenancy::guard_superadmin_user_mutation(&app, "root", true, None, false).is_err(), "désactivation refusée");
        assert!(tenancy::guard_superadmin_user_mutation(&app, "root", false, None, true).is_err(), "suppression refusée");
        assert!(tenancy::guard_superadmin_user_mutation(&app, "root", false, Some("viewer"), false).is_err(), "rétrogradation refusée");
        assert!(tenancy::guard_superadmin_user_mutation(&app, "root", false, Some("admin"), false).is_ok(), "rester admin OK");
        assert!(tenancy::guard_superadmin_user_mutation(&app, "backup", true, None, true).is_ok(), "login ordinaire : guard no-op");
        // via les handlers CRUD réels (câblés) -> 409 avec un message super-admin.
        let e = admin_update_user(&app, "backup", "root", &json!({"disabled": true})).unwrap_err();
        assert_eq!(e.0, StatusCode::CONFLICT); assert!(e.1.contains("super-admin"), "message super-admin: {}", e.1);
        let e = admin_delete_user(&app, "backup", "root").unwrap_err();
        assert_eq!(e.0, StatusCode::CONFLICT); assert!(e.1.contains("super-admin"), "message super-admin: {}", e.1);
        // root reste admin activé (non muté).
        {  let (role, dis): (String, i64) = app.db().query_row("SELECT role, disabled FROM users WHERE login='root'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
          assert_eq!(role, "admin", "root reste admin"); assert_eq!(dis, 0, "root reste activé"); }
        let _ = std::fs::remove_file(&ledger);
    }

    /// [TENANT CRUD — gated + ledgerisé] Community (flag OFF) : la surface tenant est FERMÉE (403
    /// enterprise_disabled) => byte-identique. Enterprise ON : create/rename/grant/revoke réservés à un
    /// platform-admin (operator -> 403), chacun ledgerisé `console.tenant.*`.
    #[tokio::test]
    async fn tenant_crud_gated_and_ledgered() {
        let ledger = tmp_path("forge-test-tenant-crud");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let store = app.store(); ensure_default_tenant(&store); }
        let admin = admin_session(&app, "adm");
        let opr = { { let db = app.db(); upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap(); } let (t,_) = create_session(&app, uid_of(&app, "opr")); bearer_headers(&t) };
        // community : flag OFF => 403 enterprise_disabled (aucune surface tenant).
        let resp = tenancy::tenants_create(State(app.clone()), admin.clone(), Json(json!({"name":"Acme"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "flag OFF => 403 enterprise_disabled");
        enable_enterprise_tenancy(&app);
        // operator => 403 ; admin => 200.
        let resp = tenancy::tenants_create(State(app.clone()), opr.clone(), Json(json!({"name":"Acme"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "operator (non platform-admin) refusé");
        let resp = tenancy::tenants_create(State(app.clone()), admin.clone(), Json(json!({"name":"Acme Corp"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "admin crée un tenant");
        let tid = resp_json(resp).await["tenant"]["id"].as_i64().unwrap();
        let resp = tenancy::tenants_update(State(app.clone()), admin.clone(), Path(tid), Json(json!({"name":"Acme Renamed"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "rename ok");
        { let db = app.db(); upsert_user(&db, "carol", "viewer", &hash_pw("pw")).unwrap(); }
        let resp = tenancy::tenant_grant_add(State(app.clone()), admin.clone(), Path(tid), Json(json!({"login":"carol","role":"tenant_viewer"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "grant add ok");
        let resp = tenancy::tenant_grant_add(State(app.clone()), opr.clone(), Path(tid), Json(json!({"login":"carol","role":"tenant_admin"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "grant add par operator refusé");
        let resp = tenancy::tenant_grant_remove(State(app.clone()), admin.clone(), Path((tid, "carol".to_string()))).await;
        assert_eq!(resp.status(), StatusCode::OK, "grant remove ok");
        // LEDGER : chaque mutation console.tenant.*.
        let kinds: Vec<String> = read_ledger_lines(&ledger).iter().filter_map(|e| e["kind"].as_str().map(String::from)).collect();
        for k in ["console.tenant.create", "console.tenant.rename", "console.tenant.grant", "console.tenant.revoke"] {
            assert!(kinds.iter().any(|x| x == k), "{k} ledgerisé");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    /// [TENANT — garde-fous fail-closed] Impossible d'archiver le DERNIER tenant actif ; impossible de
    /// retirer le DERNIER grant tenant_admin d'un tenant (son dernier admin).
    #[tokio::test]
    async fn tenant_last_active_and_last_admin_protections() {
        let ledger = tmp_path("forge-test-tenant-guards");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let store = app.store(); ensure_default_tenant(&store); }
        enable_enterprise_tenancy(&app);
        let admin = admin_session(&app, "adm");
        let tid2 = resp_json(tenancy::tenants_create(State(app.clone()), admin.clone(), Json(json!({"name":"Second"}))).await).await["tenant"]["id"].as_i64().unwrap();
        // archive #1 (reste #2 actif) => OK.
        let resp = tenancy::tenants_update(State(app.clone()), admin.clone(), Path(1i64), Json(json!({"status":"archived"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "archivage OK tant qu'un tenant reste actif");
        // #2 seul actif : archivage REFUSÉ.
        let resp = tenancy::tenants_update(State(app.clone()), admin.clone(), Path(tid2), Json(json!({"status":"archived"}))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "dernier tenant actif : archivage refusé");
        // dernier tenant_admin de #2 (adm, auto-grant à la création) : retrait REFUSÉ.
        let resp = tenancy::tenant_grant_remove(State(app.clone()), admin.clone(), Path((tid2, "adm".to_string()))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "dernier admin du tenant : retrait refusé");
        // ajouter un 2e tenant_admin -> le retrait du 1er devient OK.
        { let db = app.db(); upsert_user(&db, "dave", "operator", &hash_pw("pw")).unwrap(); }
        let resp = tenancy::tenant_grant_add(State(app.clone()), admin.clone(), Path(tid2), Json(json!({"login":"dave","role":"tenant_admin"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "2e admin ajouté");
        let resp = tenancy::tenant_grant_remove(State(app.clone()), admin.clone(), Path((tid2, "adm".to_string()))).await;
        assert_eq!(resp.status(), StatusCode::OK, "retrait OK dès qu'un 2e admin existe");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [PER-TENANT LEDGER — unité] Community (flag OFF) => None (chemin plat, byte-identique). Enterprise
    /// ON => `tenant-<tid>/engagement-<eid>.jsonl` (groupé par tenant, cross-platform via PathBuf). Deux
    /// tenants distincts => sous-dossiers distincts (isolation). La signature Ed25519 par-ledger est inchangée.
    #[test]
    fn per_tenant_ledger_path_is_scoped_and_community_flat() {
        let ledger = tmp_path("forge-test-ledger-scope");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        let base = std::path::Path::new(&std::env::temp_dir()).join("forge").join("engagement.jsonl").to_string_lossy().into_owned();
        // community => None.
        assert!(tenancy::scoped_engagement_ledger_path(&app, &base, 7, 3).is_none(), "community => pas de scoping (chemin plat)");
        enable_enterprise_tenancy(&app);
        let p = tenancy::scoped_engagement_ledger_path(&app, &base, 7, 3).expect("scoped");
        let expect = std::path::Path::new(&base).parent().unwrap().join("tenant-3").join("engagement-7.jsonl").to_string_lossy().into_owned();
        assert_eq!(p, expect, "ledger groupé par tenant (tenant-3/engagement-7.jsonl)");
        // même tenant => même sous-dossier ; tenant différent => dossier différent.
        assert!(tenancy::scoped_engagement_ledger_path(&app, &base, 8, 3).unwrap().contains("tenant-3"), "même tenant, même sous-dossier");
        let p3 = tenancy::scoped_engagement_ledger_path(&app, &base, 9, 4).unwrap();
        assert!(p3.contains("tenant-4") && !p3.contains("tenant-3"), "tenant différent => dossier différent");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [PER-TENANT LEDGER — bout-en-bout] Un engagement créé en mode enterprise dans le tenant 5 reçoit un
    /// ledger DÉDIÉ groupé sous `tenant-5/`, et sa genèse `console.engagement.create` y est écrite (le
    /// fichier existe réellement). Prouve le câblage derive_engagement_ledger_path -> tenancy.
    #[tokio::test]
    async fn engagement_create_writes_tenant_scoped_ledger() {
        let dir = tmp_path("forge-test-eng-tenant-ledger");
        std::fs::create_dir_all(&dir).unwrap();
        let ledger = format!("{dir}/engagement.jsonl");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let store = app.store(); ensure_default_tenant(&store); }
        // opérateur granté sur un tenant 5. upsert PUIS (guard relâché) uid_of PUIS insert grant — uid_of
        // reverrouille le mutex DB, ne jamais l'appeler en tenant `app.db()`.
        { let db = app.db();
          upsert_user(&db, "op5", "operator", &hash_pw("pw")).unwrap();
          db.execute("INSERT INTO tenant(id,name,status,created,updated) VALUES(5,'T5','active',datetime('now'),datetime('now'))", []).unwrap();
        }
        let uid5 = uid_of(&app, "op5");
        { let db = app.db(); db.execute("INSERT INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,5,'tenant_operator',datetime('now'))", [uid5]).unwrap(); }
        enable_enterprise_tenancy(&app);
        let (t,_) = create_session(&app, uid_of(&app, "op5"));
        let opr = bearer_headers(&t);
        let resp = engagements_create(State(app.clone()), conn_info(), opr.clone(),
            Json(json!({"name":"Eng T5","scope_json":{"in_scope":["a.example.com"]},"tenant_id":5}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "création engagement dans tenant 5");
        let id = resp_json(resp).await["engagement"]["id"].as_i64().unwrap();
        let lp: String = { let db = app.db(); db.query_row("SELECT ledger_path FROM engagement WHERE id=?", [id], |r| r.get(0)).unwrap() };
        let want = std::path::Path::new(&dir).join("tenant-5").join(format!("engagement-{id}.jsonl")).to_string_lossy().into_owned();
        assert_eq!(lp, want, "ledger scoppé tenant-5");
        assert!(std::path::Path::new(&lp).exists(), "fichier ledger tenant-scopé créé sur disque");
        assert!(read_ledger_lines(&lp).iter().any(|e| e["kind"] == "console.engagement.create"), "genèse écrite dans le ledger du tenant");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [ENGAGEMENT — CRUD gouverné + ledgerisé] Création/édition = OPÉRATEUR (viewer -> 403) ; archive/
    /// suppression = ADMIN (opérateur -> 403). Chaque mutation est journalisée `console.engagement.*`.
    #[tokio::test]
    async fn engagement_crud_role_gated_and_ledgered() {
        let ledger = tmp_path("forge-test-eng-crud");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "adm", "admin", &hash_pw("pw")).unwrap();
        }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger); // défaut #1 actif
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));
        let (atok, _) = create_session(&app, uid_of(&app, "adm"));

        // création sans session opérateur -> 403 (fail-closed).
        let resp = engagements_create(State(app.clone()), conn_info(), HeaderMap::new(),
            Json(json!({"name": "X", "scope_json": {"in_scope": ["x.example.com"]}}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "création sans opérateur refusée");

        // création par un OPÉRATEUR -> 200 + nouvel engagement (id >= 2) + ledger create.
        let resp = engagements_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(json!({"name": "Client Q3", "mode": "grey", "scope_json": {"in_scope": ["c.example.com"], "out_scope": []}}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "opérateur autorisé à créer");
        let j = resp_json(resp).await;
        let new_id = j["engagement"]["id"].as_i64().unwrap();
        assert!(new_id >= 2, "nouvel engagement id >= 2");
        assert!(read_ledger_lines(&ledger).iter().any(|e| e["kind"] == "console.engagement.create" && e["detail"]["engagement_id"] == new_id),
            "création ledgerisée dans le ledger console");

        // édition (rename) par un OPÉRATEUR -> 200.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&otok), Path(new_id),
            Json(json!({"name": "Renamed"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "opérateur autorisé à éditer");

        // archive par un OPÉRATEUR -> 403 (réservé admin).
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&otok), Path(new_id),
            Json(json!({"status": "archived"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "archive réservée admin");

        // archive par un ADMIN -> 200 (il reste #1 actif, donc pas le dernier) + ledger archive.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&atok), Path(new_id),
            Json(json!({"status": "archived"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "admin autorisé à archiver");
        assert!(read_ledger_lines(&ledger).iter().any(|e| e["kind"] == "console.engagement.archive"), "archive ledgerisée");

        // suppression par un OPÉRATEUR -> 403 (réservé admin).
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&otok), Path(new_id),
            Json(json!({"delete": true}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "suppression réservée admin");

        // suppression par un ADMIN (engagement #new_id, archivé, pas #1, pas le dernier actif) -> 200 + ledger.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&atok), Path(new_id),
            Json(json!({"delete": true}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "admin autorisé à supprimer");
        assert!(read_ledger_lines(&ledger).iter().any(|e| e["kind"] == "console.engagement.delete"), "suppression ledgerisée");
        assert!(app.db().query_row("SELECT 1 FROM engagement WHERE id=?", [new_id], |_| Ok(())).is_err(), "engagement supprimé de la base");

        let _ = std::fs::remove_file(&ledger);
    }

    /// [ENGAGEMENT — dernier actif protégé] On ne peut NI archiver NI supprimer le DERNIER engagement
    /// actif (fail-closed : il faut toujours un espace de travail actif). #1 (défaut) n'est jamais
    /// supprimable non plus.
    #[tokio::test]
    async fn last_active_engagement_archive_blocked() {
        let ledger = tmp_path("forge-test-eng-last");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let db = app.db(); upsert_user(&db, "adm", "admin", &hash_pw("pw")).unwrap(); }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger); // UNIQUE engagement actif
        let (atok, _) = create_session(&app, uid_of(&app, "adm"));

        // archiver le dernier engagement actif -> 409.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&atok), Path(1i64),
            Json(json!({"status": "archived"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "dernier engagement actif : archivage bloqué");
        {  let st: String = app.db().query_row("SELECT status FROM engagement WHERE id=1", [], |r| r.get(0)).unwrap();
          assert_eq!(st, "active", "l'engagement reste actif (mutation refusée)"); }

        // supprimer #1 (défaut + dernier actif) -> 409.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&atok), Path(1i64),
            Json(json!({"delete": true}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "#1 par défaut non supprimable");

        let _ = std::fs::remove_file(&ledger);
    }


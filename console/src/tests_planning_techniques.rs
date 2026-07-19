// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — tests d'intégration : technique selection/profiles, plan threading, workflows, techniques catalog, import.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

    /// [ENGAGEMENT — sélection de techniques PAR-ENGAGEMENT] La sélection (profil + toggles) posée pour
    /// l'engagement A n'affecte PAS B : chaque engagement round-trip sa propre sélection isolée.
    /// L'engagement #1 utilise la clé LEGACY `technique_selection` (rétro-compat), les autres la clé
    /// suffixée `technique_selection:<id>`.
    #[tokio::test]
    async fn per_engagement_technique_selection_round_trips() {
        let ledger = tmp_path("forge-test-eng-tech");
        let ledger2 = tmp_path("forge-test-eng-tech2");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let db = app.db(); upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap(); }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger);
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger2);
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // #1 -> profil pentest (+ toggle SQLi=false) ; #2 -> profil custom (+ rce.probe=true).
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(1), bearer_headers(&otok),
            Json(json!({"profile": "pentest", "categories": {"SQLi": false}, "techniques": {}}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "sélection #1 posée");
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(2), bearer_headers(&otok),
            Json(json!({"profile": "custom", "categories": {}, "techniques": {"rce.probe": true}}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "sélection #2 posée");

        // round-trip : chaque engagement relit SA sélection (isolation).
        assert_eq!(technique_selection_value_for(&app, 1)["profile"], "pentest", "#1 -> pentest");
        assert_eq!(technique_selection_value_for(&app, 2)["profile"], "custom", "#2 -> custom");
        assert_eq!(technique_selection_value_for(&app, 1)["categories"]["SQLi"], json!(false), "toggle #1 isolé");
        assert_eq!(technique_selection_value_for(&app, 2)["techniques"]["rce.probe"], json!(true), "toggle #2 isolé");

        // clés de stockage : legacy pour #1, suffixée pour #2.
        {
            let db = app.db();
            assert!(settings_get(&db, "technique_selection").is_some(), "engagement #1 -> clé legacy");
            assert!(settings_get(&db, "technique_selection:2").is_some(), "engagement #2 -> clé suffixée");
        }

        // un id EXPLICITE inexistant est refusé (fail-closed : pas d'écriture pour un engagement fantôme).
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(99), bearer_headers(&otok),
            Json(json!({"profile": "pentest"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "engagement inexistant -> 400");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [C5 — profils nommés] « Enregistrer comme profil… » crée un profil NOMMÉ (pas « custom ») dont les
    /// techniques ÉGALENT la sélection active persistée — c'est l'invariant sur lequel s'appuie le
    /// reconcile client (detectActiveProfile) pour re-sélectionner le profil au reload (et NON « custom »).
    /// Un nom de base réservé (bug_bounty/pentest/custom) est refusé.
    #[tokio::test]
    async fn save_as_creates_named_profile_matching_active_selection() {
        let ledger = tmp_path("forge-test-saveas");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let db = app.db(); upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap(); }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger);
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // save_as "web_bb" avec une sélection custom + toggles explicites.
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(1), bearer_headers(&otok),
            Json(json!({"profile": "custom", "techniques": {"sqli.error": true, "xss.reflected": false}, "save_as": "web_bb"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "save_as accepté");

        // le profil NOMMÉ existe (pas « custom ») ET ÉGALE la sélection active persistée (reconcile => actif au reload).
        let map = technique_profiles_map(&app);
        assert!(map.contains_key("web_bb"), "profil nommé 'web_bb' créé (pas 'custom')");
        let active = technique_selection_value_for(&app, 1);
        assert_eq!(map["web_bb"]["techniques"], active["techniques"], "profil nommé == sélection active persistée");
        assert_eq!(map["web_bb"]["techniques"]["sqli.error"], json!(true), "toggle capturé dans le profil");

        // un nom de base réservé ne peut pas masquer un profil de base.
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(1), bearer_headers(&otok),
            Json(json!({"profile": "custom", "save_as": "custom"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "nom de base réservé refusé");

        let _ = std::fs::remove_file(&ledger);
    }

    /// [C5 — profils nommés] Renommer = « Enregistrer comme profil… » sous un NOUVEAU nom (les deux
    /// coexistent, l'ancien peut ensuite être supprimé). Supprimer retire le profil NOMMÉ (global) sans
    /// toucher la sélection active ; supprimer un profil inconnu -> 404.
    #[tokio::test]
    async fn technique_profile_rename_then_delete() {
        let ledger = tmp_path("forge-test-profren");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let db = app.db(); upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap(); }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger);
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // crée "old", puis "renomme" en enregistrant SOUS "new" (la sélection active demeure).
        for name in ["old", "new"] {
            let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(1), bearer_headers(&otok),
                Json(json!({"profile": "custom", "techniques": {"idor.horizontal": true}, "save_as": name}))).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK, "save_as '{name}' accepté");
        }
        let map = technique_profiles_map(&app);
        assert!(map.contains_key("old") && map.contains_key("new"), "les deux profils coexistent");

        // supprime "old" -> 200, "new" conservé, sélection active intacte.
        let active_before = technique_selection_value_for(&app, 1);
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(1), bearer_headers(&otok),
            Json(json!({"delete_profile": "old"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "suppression 'old' acceptée");
        let map = technique_profiles_map(&app);
        assert!(!map.contains_key("old") && map.contains_key("new"), "'old' supprimé, 'new' conservé");
        assert_eq!(technique_selection_value_for(&app, 1)["techniques"], active_before["techniques"], "sélection active non touchée par la suppression");

        // supprimer un profil inconnu -> 404.
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(1), bearer_headers(&otok),
            Json(json!({"delete_profile": "ghost"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "profil inconnu -> 404");

        let _ = std::fs::remove_file(&ledger);
    }

    /// [C9 — params par-module dans le dry-plan] /api/plan THREADE désormais `module_params` : un
    /// `extra_args` avec un drapeau HORS allowlist est refusé FAIL-CLOSED (400) AVANT tout spawn moteur —
    /// preuve que les arguments de l'opérateur sont bien traités (parité run/plan), pas ignorés.
    #[tokio::test]
    async fn plan_threads_and_validates_module_params_extra_args() {
        let ledger = tmp_path("forge-test-planparams");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger);

        // extra_args non-allowlisté (module sans allowlist -> ensemble vide -> tout drapeau refusé).
        let resp = plan(State(app.clone()), HeaderMap::new(), eng_query(1),
            Json(json!({"targets": ["a.example.com"], "module_params": {"recon.http": {"extra_args": ["--evil-flag"]}}}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "extra_args hors allowlist refusé par /api/plan (fail-closed)");

        // params par-module MAL FORMÉS (pas un objet) -> 400 avant spawn (traités par /api/plan).
        let resp = plan(State(app.clone()), HeaderMap::new(), eng_query(1),
            Json(json!({"targets": ["a.example.com"], "module_params": "pas-un-objet"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "module_params non-objet refusé par /api/plan");

        let _ = std::fs::remove_file(&ledger);
    }

    /// [parité lecture] parse_plan_verdicts : extrait verdict + kind→target des lignes du moteur
    /// (mode propose), ignore les lignes sans verdict, tolère `->` et `→`. Couvre le format inline
    /// (CLI `forge plan` : `[VERDICT] kind → target`).
    #[test]
    fn plan_verdicts_extracted_from_engine_output() {
        let stdout = "\
[plan] access_control.idor -> api.example.com : DRY_RUN (non armé)
[plan] exploit.rce -> api.example.com : VETO (capacité non autorisée)
ligne sans verdict ignorée
[plan] recon.http → web.example.com : FIRE
";
        let v = parse_plan_verdicts(stdout);
        assert_eq!(v.len(), 3, "3 lignes avec verdict reconnu (la 3e ignorée)");
        assert_eq!(v[0]["verdict"], "DRY_RUN");
        assert_eq!(v[0]["kind"], "access_control.idor");
        assert_eq!(v[0]["target"], "api.example.com");
        assert_eq!(v[1]["verdict"], "VETO");
        assert_eq!(v[2]["verdict"], "FIRE");
        assert_eq!(v[2]["kind"], "recon.http", "séparateur unicode → géré");
    }

    /// [parité lecture] parse_plan_verdicts sur la sortie RÉELLE du moteur (`report.py`) : les
    /// lignes d'action vivent sous un en-tête de section et ne portent PAS le mot-clé du verdict ;
    /// les compteurs de synthèse en gras (`- **Tirées (FIRE)** : 0`) ne doivent JAMAIS produire de
    /// faux verdicts. Régression du dry-plan console (gouvernance : 1 action réelle, pas 3 fantômes).
    #[test]
    fn plan_verdicts_from_real_report_section_aware() {
        let stdout = "\
Tirées=0  Simulées=1  Refusées=0  Erreurs=0  Findings=0
## Couverture & transparence (ROE / anti-masquage)

- **Tirées (FIRE)** : 0
- **Simulées (DRY_RUN)** : 1
- **Refusées (VETO — hors scope / capacité non autorisée)** : 0
- **Erreurs / skips** : 0

**Simulées (non armé/approuvé)**
- `recon.httpx` → `guatx.com` : engagement non armé (dry-run)

**Refusées (VETO)**
- `exploit.rce` → `evil.example` : capacité non autorisée

**Classes jamais tentées**
- `guatx.com` : access_control, auth, ato
";
        let v = parse_plan_verdicts(stdout);
        assert_eq!(v.len(), 2, "2 actions réelles (les compteurs en gras et la ligne 'classes' ignorés)");
        assert_eq!(v[0]["verdict"], "DRY_RUN", "verdict tiré de la section, pas du compteur");
        assert_eq!(v[0]["kind"], "recon.httpx", "backticks retirés");
        assert_eq!(v[0]["target"], "guatx.com", "raisons `: …` coupées de la cible");
        assert_eq!(v[1]["verdict"], "VETO");
        assert_eq!(v[1]["kind"], "exploit.rce");
        assert_eq!(v[1]["target"], "evil.example");
    }

    /// [sélection pure] validate_technique_selection : profils fermés, toggles typés bool + clés bien
    /// formées, défauts, clés INCONNUES tolérées (le résolveur moteur les ignore — pas de capacité forgée).
    #[test]
    fn validate_technique_selection_grammar_and_defaults() {
        // corps vide -> défaut profil bug_bounty + toggles vides.
        let v = validate_technique_selection(&json!({})).unwrap();
        assert_eq!(v["profile"], "bug_bounty");
        assert_eq!(v["categories"], json!({}));
        assert_eq!(v["techniques"], json!({}));
        // profils FERMÉS.
        for p in ["bug_bounty", "pentest", "custom"] {
            assert_eq!(validate_technique_selection(&json!({"profile": p})).unwrap()["profile"], p);
        }
        assert!(validate_technique_selection(&json!({"profile": "root"})).is_err(), "profil inconnu refusé");
        // toggles : bool requis, clé bien formée ; clé inconnue TOLÉRÉE (résolveur moteur l'ignore).
        let v = validate_technique_selection(&json!({"categories": {"SQLi": false}, "techniques": {"rce.probe": true}})).unwrap();
        assert_eq!(v["categories"]["SQLi"], false);
        assert_eq!(v["techniques"]["rce.probe"], true);
        assert!(validate_technique_selection(&json!({"categories": {"SQLi": "no"}})).is_err(), "valeur non-bool refusée");
        assert!(validate_technique_selection(&json!({"categories": {"bad key": true}})).is_err(), "clé mal formée refusée");
        assert!(validate_technique_selection(&json!({"techniques": []})).is_err(), "techniques doit être un objet");
    }

    /// [sélection persistance] technique_selection_value : défaut bug_bounty si absent ; round-trip après
    /// settings_set ; valeur illisible -> défaut (fail-soft, jamais de valeur inventée).
    #[test]
    fn technique_selection_value_default_and_round_trip() {
        let path = tmp_path("forge-test-techsel");
        let app = test_app(&path);
        assert_eq!(technique_selection_value(&app)["profile"], "bug_bounty", "absent -> défaut bug_bounty");
        {
            let db = app.db();
            settings_set(&db, "technique_selection",
                &json!({"profile":"pentest","categories":{"SQLi":false},"techniques":{}}).to_string()).unwrap();
        }
        let v = technique_selection_value(&app);
        assert_eq!(v["profile"], "pentest");
        assert_eq!(v["categories"]["SQLi"], false);
        { let db = app.db(); settings_set(&db, "technique_selection", "pas du json").unwrap(); }
        assert_eq!(technique_selection_value(&app)["profile"], "bug_bounty", "illisible -> défaut (fail-soft)");
        let _ = std::fs::remove_file(&path);
    }

    /// [sélection endpoint] POST /api/techniques/selection : OPÉRATEUR/ADMIN-gated (viewer -> 403 SANS
    /// mutation) + LEDGERISÉ (`console.techniques.selection.set` attribuée à l'acteur) + persisté.
    #[tokio::test]
    async fn technique_selection_endpoint_operator_gated_and_ledgered() {
        let path = tmp_path("forge-test-techsel-ep");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));

        // viewer -> 403 (fail-closed) ET aucune persistance.
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&vtok),
            Json(json!({"profile": "pentest"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer refusé (fail-closed)");
        { let db = app.db(); assert!(settings_get(&db, "technique_selection").is_none(), "un refus ne persiste rien"); }

        // operator -> 200 + persistance + ledger attribué.
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"profile": "pentest", "categories": {"SQLi": false}}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "operator autorisé");
        let stored = { let db = app.db(); settings_get(&db, "technique_selection").unwrap() };
        let sv: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(sv["profile"], "pentest");
        assert_eq!(sv["categories"]["SQLi"], false);
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.techniques.selection.set", "mutation ledgerisée");
        assert_eq!(last["detail"]["actor"], "oo", "attribuée à l'acteur opérateur");
        assert_eq!(last["detail"]["selection"]["profile"], "pentest");

        // profil invalide -> 400.
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"profile": "root"}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "profil invalide -> 400");
        let _ = std::fs::remove_file(&path);
    }

    /// [B4 — édition du scope d'engagement PERSISTE + AFFICHÉE + scope-check ENGAGEMENT-AWARE] Un in-scope
    /// NON VIDE posé via engagement_do_update écrit scope_json.in_scope ; la liste le RE-EXPOSE (l'éditeur
    /// « reload shows it ») ; le scope-check résout la cible IN scope contre l'ENGAGEMENT (jamais les App
    /// globals figés). Une zone scope VIDE laisse le scope INCHANGÉ (sémantique documentée conservée).
    #[tokio::test]
    async fn engagement_scope_edit_persists_and_scope_check_is_engagement_aware() {
        let ledger = tmp_path("forge-test-b4-scope");
        // App globals VIDES : prouve que le scope-check lit l'ENGAGEMENT, pas les globals disque figés.
        let app = test_app(&ledger);
        { let db = app.db(); migrate(&db); }
        insert_test_engagement(&app, 1, &[], "grey", &ledger);

        // AVANT : scope vide -> HORS scope (fail-closed).
        let before = resp_json(scope_check(State(app.clone()), HeaderMap::new(), eng_query(1),
            Json(json!({"target": "example.com"}))).await.into_response()).await;
        assert_eq!(before["in_scope"], json!(false), "scope vide -> HORS scope");

        // ÉDITE : in-scope NON VIDE (example.com) + mode black.
        let v = engagement_do_update(&app, 1, "opr", &json!({
            "scope_json": {"mode": "black", "in_scope": ["example.com"], "out_scope": []}
        })).expect("edit ok");
        assert_eq!(v["action"], "edit");

        // PERSISTÉ : load_engagement + la liste RE-EXPOSENT le scope (« reload shows it ») + mode effectif.
        let eng = load_engagement(&app.store(), 1).unwrap();
        assert_eq!(eng.scope_in, vec!["example.com".to_string()], "in_scope persisté");
        assert_eq!(eng.mode, "black", "mode effectif persisté");
        let engs = engagement_list_json(&app, &HeaderMap::new());
        let e1 = engs.iter().find(|e| e["id"] == json!(1)).unwrap();
        assert_eq!(e1["in_scope"], json!(["example.com"]), "liste ré-expose le scope (éditeur l'affiche)");
        assert_eq!(e1["mode"], json!("black"), "liste expose le mode EFFECTIF (scope_json.mode)");

        // scope-check ENGAGEMENT-AWARE : la cible est désormais IN scope + le mode reflète l'engagement.
        let after = resp_json(scope_check(State(app.clone()), HeaderMap::new(), eng_query(1),
            Json(json!({"target": "example.com"}))).await.into_response()).await;
        assert_eq!(after["in_scope"], json!(true), "après édition -> IN scope (engagement-aware)");
        assert_eq!(after["mode"], json!("black"), "scope-check reflète le mode de l'engagement");
        assert_eq!(after["engagement_id"], json!(1));

        // ZONE VIDE = INCHANGÉ : un update sans scope_json (rename seul) ne touche pas le scope.
        engagement_do_update(&app, 1, "opr", &json!({"name": "renamed"})).expect("rename ok");
        let eng2 = load_engagement(&app.store(), 1).unwrap();
        assert_eq!(eng2.scope_in, vec!["example.com".to_string()], "scope inchangé quand scope_json absent");

        let _ = std::fs::remove_file(&ledger);
    }

    /// [B5 — bascule d'engagement = re-ciblage effectif] Le scope-check (comme le run flow) résout contre
    /// l'engagement DEMANDÉ (`?engagement=`) : basculer l'actif de A vers B change la cible évaluée. Prouve
    /// que « rendre B actif » (côté client : ajoute ?engagement=B) fait bien opérer sur le scope de B.
    #[tokio::test]
    async fn scope_check_targets_the_selected_engagement() {
        let ledger = tmp_path("forge-test-b5-switch");
        let ledger2 = tmp_path("forge-test-b5-switch2");
        let app = test_app(&ledger);
        { let db = app.db(); migrate(&db); }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger);
        insert_test_engagement(&app, 2, &["b.example.com"], "black", &ledger2);

        // Actif = #1 : b.example.com HORS scope, a.example.com IN.
        let r1 = resp_json(scope_check(State(app.clone()), HeaderMap::new(), eng_query(1),
            Json(json!({"target": "b.example.com"}))).await.into_response()).await;
        assert_eq!(r1["in_scope"], json!(false), "#1 : b.example.com hors scope");
        // Bascule sur #2 : b.example.com IN scope, mode = celui de #2.
        let r2 = resp_json(scope_check(State(app.clone()), HeaderMap::new(), eng_query(2),
            Json(json!({"target": "b.example.com"}))).await.into_response()).await;
        assert_eq!(r2["in_scope"], json!(true), "#2 : b.example.com in scope (re-ciblage)");
        assert_eq!(r2["mode"], json!("black"), "#2 : mode de l'engagement basculé");
        assert_eq!(r2["engagement_id"], json!(2));

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [B6 — profils de techniques NOMMÉS] « Enregistrer comme profil » (save_as) persiste la sélection
    /// courante sous un nom RÉUTILISABLE (map globale) EN PLUS de la poser comme sélection active ; la
    /// sélection est rechargeable à l'entrée (PAS reset « custom ») ; delete_profile la retire ; une
    /// technique DÉSACTIVÉE reste exclue (fail-closed intact) ; la mutation reste operator-gated (403 viewer).
    #[tokio::test]
    async fn technique_named_profiles_save_reload_delete_and_fail_closed() {
        let path = tmp_path("forge-test-b6-profiles");
        let app = test_app(&path);
        { let db = app.db(); upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap(); }
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));

        // SAVE-AS : sélection (rce.probe ON, sqli.err OFF) enregistrée sous « bug_bounty_web ».
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"profile": "custom", "save_as": "bug_bounty_web",
                        "techniques": {"rce.probe": true, "sqli.err": false}}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "save_as -> 200");

        // PERSISTÉ (map globale) + fail-closed (OFF reste OFF).
        let profiles = technique_profiles_map(&app);
        assert!(profiles.contains_key("bug_bounty_web"), "profil nommé persisté");
        assert_eq!(profiles["bug_bounty_web"]["techniques"]["rce.probe"], json!(true));
        assert_eq!(profiles["bug_bounty_web"]["techniques"]["sqli.err"], json!(false), "technique désactivée reste exclue (fail-closed)");
        // sélection ACTIVE de l'engagement #1 = la même (rechargée à l'entrée, PAS reset custom).
        let active = technique_selection_value_for(&app, 1);
        assert_eq!(active["techniques"]["rce.probe"], json!(true), "sélection active persistée (reload la retrouve)");
        assert_eq!(active["techniques"]["sqli.err"], json!(false), "OFF reste OFF au reload (fail-closed)");
        // ledger : la sauvegarde de profil est journalisée (governance ledgerisée).
        let entries = read_ledger_lines(&path);
        assert!(entries.iter().any(|e| e["kind"] == "console.techniques.profile.save"), "save profil ledgerisé");

        // nom RÉSERVÉ (base) refusé (400) — pas de masquage base vs nommé.
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"profile": "custom", "save_as": "bug_bounty", "techniques": {}}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "nom de base réservé refusé");

        // DELETE : retire le profil nommé.
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"delete_profile": "bug_bounty_web"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "delete -> 200");
        assert!(!technique_profiles_map(&app).contains_key("bug_bounty_web"), "profil supprimé");
        // delete inconnu -> 404 ; delete d'un nom de base -> 400.
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"delete_profile": "ghost"}))).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "profil inconnu -> 404");
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"delete_profile": "pentest"}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "delete d'un nom de base -> 400");

        // GOVERNANCE : un viewer NE PEUT PAS créer de profil (fail-closed, aucun profil écrit).
        { let db = app.db(); upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap(); }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&vtok),
            Json(json!({"profile": "custom", "save_as": "sneaky", "techniques": {}}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer -> 403 (governance operator/admin)");
        assert!(!technique_profiles_map(&app).contains_key("sneaky"), "aucun profil créé par un refus");

        let _ = std::fs::remove_file(&path);
    }

    // =============================================================================================
    // WORKFLOWS ÉDITABLES & SAUVEGARDÉS — validation pure, routes non-conflictuelles, CRUD gouverné
    // (opérateur/admin) + ledgerisé + persisté, builtins protégés (fail-closed).
    // =============================================================================================

    /// [workflows routes] les 2 routes workflows coexistent (segment statique vs `:name`, matchit).
    #[test]
    fn workflow_routes_do_not_conflict() {
        let _r: Router<App> = Router::new()
            .route("/api/workflows", get(workflows_list).post(workflow_create))
            .route("/api/workflows/:name", post(workflow_edit));
    }

    /// [workflows pur] validate_workflow_body : grammaire nom/kind, steps typées, défauts, name_override,
    /// kinds inconnus TOLÉRÉS (l'engine les LARGUE via ∩ enabled — pas de capacité forgée).
    #[test]
    fn validate_workflow_grammar_and_defaults() {
        // minimal -> défauts (description "", builtin false, steps normalisées {kind, params}).
        let v = validate_workflow_body(&json!({"name": "wf1", "steps": [{"kind": "recon.httpx"}]}), None).unwrap();
        assert_eq!(v["name"], "wf1");
        assert_eq!(v["description"], "");
        assert_eq!(v["builtin"], false);
        assert_eq!(v["steps"][0]["kind"], "recon.httpx");
        assert_eq!(v["steps"][0]["params"], json!({}));
        // name_override (segment d'URL) prime sur le corps.
        let v = validate_workflow_body(&json!({"name": "ignored", "steps": []}), Some("from-url")).unwrap();
        assert_eq!(v["name"], "from-url");
        // noms mal formés refusés.
        for bad in ["", "-x", "a b", "a/b"] {
            assert!(validate_workflow_body(&json!({"name": bad, "steps": []}), None).is_err(), "nom '{bad}' refusé");
        }
        // kind mal formé refusé ; params non-objet refusé ; steps non-liste refusé.
        assert!(validate_workflow_body(&json!({"name": "w", "steps": [{"kind": "bad kind"}]}), None).is_err());
        assert!(validate_workflow_body(&json!({"name": "w", "steps": [{"kind": "recon.httpx", "params": []}]}), None).is_err());
        assert!(validate_workflow_body(&json!({"name": "w", "steps": "nope"}), None).is_err());
        // kind INCONNU du registre : toléré (résolveur moteur/engine le LARGUE).
        let v = validate_workflow_body(&json!({"name": "w", "steps": [{"kind": "not.a.real.kind"}]}), None).unwrap();
        assert_eq!(v["steps"][0]["kind"], "not.a.real.kind");
        // trop d'étapes -> refus.
        let many: Vec<Value> = (0..129).map(|_| json!({"kind": "recon.httpx"})).collect();
        assert!(validate_workflow_body(&json!({"name": "w", "steps": many}), None).is_err(), "> 128 étapes refusé");
    }

    /// [workflows builtins protégés] validate + noms réservés (miroir local, sans spawn moteur).
    #[test]
    fn workflow_builtin_names_reserved() {
        for n in WORKFLOW_BUILTIN_NAMES {
            assert!(workflow_name_is_builtin(n), "'{n}' est un builtin réservé");
        }
        assert!(!workflow_name_is_builtin("my-custom"), "un nom utilisateur n'est pas réservé");
    }

    /// [workflows endpoint] CRUD GOUVERNÉ : viewer -> 403 SANS mutation ; operator -> create/edit
    /// persistés (`settings.workflows`) + ledgerisés (`console.workflows.save/delete` attribués) ;
    /// suppression d'un builtin -> 409 (protégé, fail-closed) ; suppression d'un inconnu -> 404 ;
    /// création avec nom réservé -> 409. Appelle les handlers HTTP réels (check_operator).
    #[tokio::test]
    async fn workflow_endpoints_operator_gated_and_ledgered() {
        let path = tmp_path("forge-test-wf-ep");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));

        // viewer -> 403 (fail-closed) ET aucune persistance.
        let resp = workflow_create(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&vtok),
            Json(json!({"name": "my-wf", "steps": [{"kind": "recon.httpx"}]}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer refusé (fail-closed)");
        { let db = app.db(); assert!(settings_get(&db, "workflows").is_none(), "un refus ne persiste rien"); }

        // operator create -> 200 + persistance + ledger attribué.
        let resp = workflow_create(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"name": "my-wf", "description": "d", "steps": [{"kind": "recon.httpx"}, {"kind": "sqli.probe", "params": {"param": "q"}}]}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "operator autorisé");
        let stored = { let db = app.db(); settings_get(&db, "workflows").unwrap() };
        let sv: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(sv["my-wf"]["steps"][1]["kind"], "sqli.probe");
        assert_eq!(sv["my-wf"]["steps"][1]["params"]["param"], "q");
        let last = read_ledger_lines(&path).into_iter().last().unwrap();
        assert_eq!(last["kind"], "console.workflows.save", "création ledgerisée");
        assert_eq!(last["detail"]["actor"], "oo", "attribuée à l'acteur opérateur");
        assert_eq!(last["detail"]["name"], "my-wf");

        // operator edit via :name -> 200 (remplace les étapes).
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("my-wf".into()), Json(json!({"steps": [{"kind": "web.nuclei"}]}))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let sv: Value = { let db = app.db(); serde_json::from_str(&settings_get(&db, "workflows").unwrap()).unwrap() };
        assert_eq!(sv["my-wf"]["steps"].as_array().unwrap().len(), 1);
        assert_eq!(sv["my-wf"]["steps"][0]["kind"], "web.nuclei");

        // création/édition avec un nom RÉSERVÉ (builtin) -> 409, aucune persistance du builtin.
        let resp = workflow_create(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"name": "full-pentest", "steps": []}))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "nom réservé refusé");
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("bug-bounty-web".into()), Json(json!({"steps": []}))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "édition d'un builtin refusée");

        // suppression d'un BUILTIN -> 409 (protégé), même par operator.
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("recon-surface".into()), Json(json!({"delete": true}))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "builtin non supprimable (fail-closed)");

        // suppression d'un INCONNU -> 404.
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("ghost".into()), Json(json!({"delete": true}))).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // viewer ne peut pas supprimer -> 403 (my-wf reste).
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&vtok),
            Path("my-wf".into()), Json(json!({"delete": true}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        {  let sv: Value = serde_json::from_str(&settings_get(&app.db(), "workflows").unwrap()).unwrap();
          assert!(sv.get("my-wf").is_some(), "un delete refusé ne supprime rien"); }

        // operator supprime son workflow -> 200 + ledger `console.workflows.delete`.
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("my-wf".into()), Json(json!({"delete": true}))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let sv: Value = { let db = app.db(); serde_json::from_str(&settings_get(&db, "workflows").unwrap()).unwrap() };
        assert!(sv.get("my-wf").is_none(), "supprimé de la map");
        let last = read_ledger_lines(&path).into_iter().last().unwrap();
        assert_eq!(last["kind"], "console.workflows.delete", "suppression ledgerisée");
        let _ = std::fs::remove_file(&path);
    }

    /// [workflows GET] GET /api/workflows — LISTE (viewer) : workflows UTILISATEUR (settings) +
    /// INTÉGRÉS dérivés du registre via le moteur (`forge workflows --json`). Nécessite python3 + forge
    /// (..) comme le test du catalogue de techniques (SOURCE UNIQUE moteur). Chaque entrée porte
    /// `step_kinds` + `step_count` ; les builtins portent `builtin:true` ; le user workflow apparaît.
    #[tokio::test]
    async fn workflows_list_returns_builtins_and_user() {
        let path = tmp_path("forge-test-wf-list");
        let app = test_app(&path);
        {
            let db = app.db();
            settings_set(&db, "workflows",
                &json!({"my-wf": {"name": "my-wf", "description": "d", "builtin": false,
                                   "steps": [{"kind": "recon.httpx", "params": {}}, {"kind": "sqli.probe", "params": {}}]}}).to_string()).unwrap();
        }
        let resp = workflows_list(State(app.clone()), HeaderMap::new(), Query(HashMap::new())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = resp_json(resp).await;
        // builtins dérivés du moteur : recon-surface / bug-bounty-web / full-pentest, builtin:true.
        let builtins = j["builtins"].as_array().expect("builtins array");
        assert!(builtins.len() >= 3, "au moins 3 workflows intégrés (dérivés du registre)");
        let bnames: Vec<&str> = builtins.iter().filter_map(|b| b["name"].as_str()).collect();
        for n in WORKFLOW_BUILTIN_NAMES {
            assert!(bnames.contains(n), "workflow intégré '{n}' présent");
        }
        assert!(builtins.iter().all(|b| b["builtin"] == true), "les intégrés portent builtin:true");
        assert!(builtins.iter().all(|b| b["step_count"].as_u64().unwrap_or(0) > 0), "chaque intégré a des étapes");
        // le workflow utilisateur apparaît avec ses step_kinds dédupliqués/ordonnés.
        let user = j["workflows"].as_array().expect("workflows array");
        let mine = user.iter().find(|w| w["name"] == "my-wf").expect("user workflow listé");
        assert_eq!(mine["builtin"], false);
        assert_eq!(mine["step_count"], 2);
        assert_eq!(mine["step_kinds"], json!(["recon.httpx", "sqli.probe"]));
        let _ = std::fs::remove_file(&path);
    }

    /// [MIGRATION] POST /api/import — ingestion de scans EXISTANTS, OPÉRATEUR-gaté + LEDGERISÉ +
    /// SCOPE-GUARDÉ. Viewer -> 403 (rien ingéré/ledgerisé). Operator -> 200 : findings insérés
    /// (ORIENTÉS PREUVE : jamais `vulnerable`), ledger `console.import` attribué + compteurs, et le
    /// CONTENU du fichier n'apparaît JAMAIS dans le ledger (filename assaini au basename). Un asset
    /// HORS scope serveur est JETÉ. Un format inconnu -> 400. Nécessite python3 + forge (..), comme
    /// le test du catalogue de techniques (le parse partage la SOURCE UNIQUE des parseurs du moteur).
    #[tokio::test]
    async fn import_endpoint_operator_gated_ledgered_and_scope_guarded() {
        let path = tmp_path("forge-test-import-ep");
        let app = test_app_scoped(&path, vec!["example.com".into(), "*.example.com".into()]);
        // Le boot serveur seede TOUJOURS l'engagement #1 depuis le scope serveur (ensure_default_engagement).
        // import_scan résout désormais l'engagement cible (L9) : on reflète donc le boot de PROD. Le scope
        // ainsi dérivé (mode/in_scope/out_scope=[]) est IDENTIQUE aux globals utilisés auparavant.
        ensure_default_engagement(&app.store(), &app.scope_in, &app.scope_mode, &app.ledger_path);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));

        let nmap = "<?xml version=\"1.0\"?><!DOCTYPE nmaprun><nmaprun><host>\
            <address addr=\"1.1.1.1\" addrtype=\"ipv4\"/><hostnames><hostname name=\"example.com\"/></hostnames>\
            <ports><port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><service name=\"https\"/></port></ports>\
            </host></nmaprun>";
        let body = json!({"campaign": "imp", "format": "auto", "filename": "../etc/scan.xml", "content": nmap});

        // viewer -> 403 (fail-closed), rien ingéré.
        let resp = import_scan(State(app.clone()), conn_info(), bearer_headers(&vtok), Json(body.clone())).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer refusé (fail-closed)");
        {  let n: i64 = app.db().query_row("SELECT COUNT(*) FROM finding", [], |r| r.get(0)).unwrap(); assert_eq!(n, 0, "un refus n'ingère rien"); }

        // operator -> 200 : findings insérés, orientés preuve, ledgerisés.
        let resp = import_scan(State(app.clone()), conn_info(), bearer_headers(&otok), Json(body.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK, "operator autorisé (nécessite python3+forge dans ..)");
        let jr = resp_json(resp).await;
        assert_eq!(jr["format"], "nmap", "format auto-détecté");
        assert!(jr["ingested"].as_i64().unwrap() >= 1, "au moins un finding ingéré");
        {
            let db = app.db();
            let n: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE campaign='imp'", [], |r| r.get(0)).unwrap();
            assert!(n >= 1, "findings insérés pour la campagne");
            let vuln: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE status='vulnerable'", [], |r| r.get(0)).unwrap();
            assert_eq!(vuln, 0, "un import ne CONFIRME jamais (orienté preuve : jamais vulnerable)");
            let tested: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE status='tested' AND tool='nmap'", [], |r| r.get(0)).unwrap();
            drop(db);
            assert!(tested >= 1, "nmap -> recon tested");
        }
        // ledger : console.import attribué + compteurs ; JAMAIS le contenu (filename assaini au basename).
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.import", "mutation ledgerisée");
        assert_eq!(last["detail"]["actor"], "oo", "attribuée à l'acteur opérateur");
        assert!(last["detail"]["counts"]["ingested"].as_i64().unwrap() >= 1);
        assert_eq!(last["detail"]["filename"], "scan.xml", "filename assaini (basename, pas de ../)");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("nmaprun"), "le contenu du fichier ne fuit JAMAIS dans le ledger");

        // out-of-scope : un asset hors scope serveur est JETÉ (compté out_of_scope, 0 ingéré).
        let oos = "<?xml version=\"1.0\"?><!DOCTYPE nmaprun><nmaprun><host>\
            <address addr=\"9.9.9.9\" addrtype=\"ipv4\"/><hostnames><hostname name=\"evil.attacker.test\"/></hostnames>\
            <ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/><service name=\"ssh\"/></port></ports>\
            </host></nmaprun>";
        let resp = import_scan(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(json!({"campaign": "imp2", "format": "nmap", "content": oos}))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let jr = resp_json(resp).await;
        assert_eq!(jr["counts"]["out_of_scope"], 1, "asset hors scope compté");
        assert_eq!(jr["ingested"].as_i64().unwrap(), 0, "asset hors scope JETÉ (rien ingéré)");
        {  let n: i64 = app.db().query_row("SELECT COUNT(*) FROM finding WHERE campaign='imp2'", [], |r| r.get(0)).unwrap(); assert_eq!(n, 0, "aucun finding hors scope inséré"); }

        // format inconnu -> 400 (grammaire fermée, fail-closed).
        let resp = import_scan(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(json!({"campaign": "imp", "format": "nessus-xml", "content": nmap}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "format inconnu refusé");

        let _ = std::fs::remove_file(&path);
    }

    /// [catalogue] GET /api/techniques : spawne le moteur, GROUPE par catégorie et reflète l'état activé
    /// du scope. Défaut (bug_bounty) : rce.probe désactivé, sqli.probe activé. Une sélection persistée
    /// (pentest) réactive rce.probe. DÉRIVÉ du registre (SOURCE UNIQUE) — nécessite python3 + forge (..).
    #[tokio::test]
    async fn techniques_catalog_groups_by_category_and_reflects_scope() {
        let path = tmp_path("forge-test-techcat");
        let app = test_app(&path);
        // défaut (aucune sélection persistée -> bug_bounty).
        let resp = techniques_catalog(State(app.clone()), HeaderMap::new(), Query(HashMap::new())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp_json(resp).await;
        assert!(body.get("error").is_none(), "catalogue indisponible (spawn moteur): {body:?}");
        assert_eq!(body["profile"], "bug_bounty");
        let groups = body["groups"].as_object().expect("groups objet");
        assert!(groups.contains_key("SQLi") && groups.contains_key("IDOR"), "groupé par catégorie (SQLi/IDOR)");
        let state = flatten_enabled(&body);
        assert_eq!(state.get("rce.probe"), Some(&false), "rce.probe pentest-only -> désactivé en bug_bounty");
        assert_eq!(state.get("sqli.probe"), Some(&true), "sqli.probe bug_bounty -> activé");
        // chaque ligne porte tools + éligibilité.
        let sqli = groups["SQLi"].as_array().unwrap().iter().find(|r| r["kind"] == "sqli.probe").unwrap();
        assert!(sqli.get("tools").is_some() && sqli.get("bug_bounty_eligible").is_some(),
            "chaque technique porte tools + éligibilité BB");

        // sélection persistée pentest -> rce.probe activé (reflète le scope courant).
        {
            let db = app.db();
            settings_set(&db, "technique_selection",
                &json!({"profile":"pentest","categories":{},"techniques":{}}).to_string()).unwrap();
        }
        let resp = techniques_catalog(State(app.clone()), HeaderMap::new(), Query(HashMap::new())).await;
        let body = resp_json(resp).await;
        assert_eq!(body["profile"], "pentest");
        assert_eq!(flatten_enabled(&body).get("rce.probe"), Some(&true), "pentest -> rce.probe activé");
        let _ = std::fs::remove_file(&path);
    }

    // =============================================================================================
    // AUTONOMIE (STANDALONE) — Forge ne DÉPEND JAMAIS de Plume / d'une source de détection.
    // Plume (et tout SIEM/IDS) n'est qu'un enrichissement OPTIONNEL de la boucle purple.
    // =============================================================================================


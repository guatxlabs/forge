// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — tests d'intégration : high-impact gate, validate_modules, extra_args allowlist, toolspec, tools CRUD.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

    /// [parité lecture] validate_host : /api/scope-check rejette les cibles malformées (métacaractères,
    /// `-` en tête) avant même la décision de scope — pas d'injection possible via le champ target.
    #[test]
    fn scope_check_rejects_malformed_target() {
        assert!(validate_host("api.example.com").is_ok());
        assert!(validate_host("10.0.0.0/8").is_ok());
        assert!(validate_host("-evil").is_err(), "tête '-' refusée (anti flag CLI)");
        assert!(validate_host("a;rm -rf").is_err(), "métacaractère shell refusé");
        assert!(validate_host("").is_err(), "vide refusé");
    }

    /// [MED resource] db() récupère une connexion empoisonnée (un panic en section critique ne gèle
    /// plus l'API). On empoisonne volontairement le Mutex puis on vérifie que db() fonctionne encore.
    #[test]
    fn db_recovers_from_poison() {
        let path = tmp_path("forge-test-poison-ledger");
        let app = test_app(&path);
        let app2 = app.clone();
        // empoisonne : un thread panique en tenant le verrou DB.
        let h = std::thread::spawn(move || {
            let _g = app2.db.lock().unwrap();
            panic!("poison volontaire");
        });
        let _ = h.join(); // le panic empoisonne le Mutex
        assert!(app.db.lock().is_err(), "le Mutex doit être empoisonné");
        // db() doit malgré tout rendre une garde utilisable (into_inner).
        
        let n: i64 = app.db().query_row("SELECT 1", [], |r| r.get(0)).expect("requête OK après poison");
        assert_eq!(n, 1, "la connexion reste exploitable après récupération du poison");
        let _ = std::fs::remove_file(&path);
    }

    /// [HIGH gouvernance] high_impact_gate (fonction pure) : honore l'opt-in UNIQUEMENT avec
    /// operator + arm + reason non vide ; défaut (opt-in absent) => Ok(false) inchangé ; toute
    /// condition manquante => Err 'high_impact_requires_arm_and_reason'.
    #[test]
    fn high_impact_gate_requires_all_conditions() {
        // défaut : opt-in non demandé -> Ok(false), comportement actuel (plancher tient).
        assert!(!high_impact_gate(false, true, true, "raison").unwrap());
        assert!(!high_impact_gate(false, false, false, "").unwrap(),
            "opt-in absent prime : aucune erreur même sans arm/reason");
        // opt-in demandé + 3 conditions réunies -> Ok(true).
        assert!(high_impact_gate(true, true, true, "test autorisé par l'opérateur").unwrap());
        // opt-in demandé mais une condition manque -> Err 400 explicite.
        for (op, arm, reason) in [
            (false, true, "r"),   // pas operator
            (true, false, "r"),   // pas arm
            (true, true, ""),     // reason vide
            (true, true, "   "),  // reason blanche (trim)
        ] {
            let err = high_impact_gate(true, op, arm, reason).unwrap_err();
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
            assert_eq!(err.code, "high_impact_requires_arm_and_reason",
                "condition manquante (op={op}, arm={arm}, reason={reason:?}) doit 400");
        }
    }

    /// [HIGH gouvernance] validate_modules : SANS opt-in (allow_high_impact=false) le plancher tient
    /// (exploit.rce -> 400 exploit_floor) ; AVEC opt-in honoré, exploit.rce passe ; un kind inconnu
    /// est TOUJOURS refusé, même armé (le contrôle unknown_module ne s'affaiblit jamais).
    #[test]
    fn validate_modules_high_impact_lifts_floor_only() {
        let path = tmp_path("forge-test-vmods");
        let app = test_app(&path);
        seed_modules(&app);
        // sans opt-in : recon OK, exploit refusé (plancher).
        assert!(validate_modules(&app, &["recon.httpx".into()], false).is_ok());
        let err = validate_modules(&app, &["exploit.rce".into()], false).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "exploit_floor", "plancher exploit tient sans opt-in");
        // avec opt-in honoré : exploit accepté.
        assert!(validate_modules(&app, &["exploit.rce".into()], true).is_ok(),
            "opt-in honoré -> exploit/destructif acceptés");
        // INVARIANT : kind inconnu refusé même avec opt-in (anti-injection d'argv préservé).
        let err = validate_modules(&app, &["forge.injected".into()], true).unwrap_err();
        assert_eq!(err.code, "unknown_module", "kind inconnu refusé même armé");
        let _ = std::fs::remove_file(&path);
    }

    /// [HIGH gouvernance] high_impact_modules : liste UNIQUEMENT les modules exploit/destructif parmi
    /// les demandés (pour l'audit ledger/run_job). Ignore les modules recon et les kinds inconnus.
    #[test]
    fn high_impact_modules_lists_only_high_impact() {
        let path = tmp_path("forge-test-himods");
        let app = test_app(&path);
        seed_modules(&app);
        let hi = high_impact_modules(&app, &["recon.httpx".into(), "exploit.rce".into(), "inconnu".into()]);
        assert_eq!(hi, vec!["exploit.rce".to_string()], "seul l'exploit listé pour l'audit");
        let _ = std::fs::remove_file(&path);
    }

    // =================================================================================================
    // GOUVERNANCE CONNECTEUR (#4) — enabled / available_override : intention opérateur + enforcement.
    // =================================================================================================

    /// [connecteur] module_operator_disabled / module_effectively_available (fonctions PURES) :
    /// désactivé ssi enabled=0 OU override=Some(false) ; un binaire simplement absent (probed=0, sans
    /// override) N'EST PAS une désactivation opérateur. effective = enabled AND (override ?? probed).
    #[test]
    fn module_governance_pure_predicates() {
        // enabled + rien -> suit la sonde.
        assert!(!module_operator_disabled(true, None), "enabled sans override -> pas désactivé opérateur");
        assert!(module_effectively_available(true, None, true), "enabled + sonde OK -> effectif");
        assert!(!module_effectively_available(true, None, false), "enabled + sonde KO -> non effectif (sonde)");
        // enabled=0 -> désactivé opérateur, jamais effectif (même sonde OK).
        assert!(module_operator_disabled(false, None), "enabled=0 -> désactivé");
        assert!(!module_effectively_available(false, None, true), "enabled=0 prime sur une sonde positive");
        // override=Some(false) -> désactivé opérateur MÊME si la sonde est positive (binaire présent).
        assert!(module_operator_disabled(true, Some(false)), "override=false -> désactivé opérateur");
        assert!(!module_effectively_available(true, Some(false), true), "override=false masque un binaire présent");
        // override=Some(true) -> PAS une désactivation ; effectif même sonde négative.
        assert!(!module_operator_disabled(true, Some(true)), "override=true -> pas désactivé");
        assert!(module_effectively_available(true, Some(true), false), "override=true force la disponibilité");
    }

    /// [connecteur --modules filter] filter_enabled_modules + operator_disabled_modules : un connecteur
    /// DÉSACTIVÉ (enabled=0) OU masqué par override=0 est RETIRÉ de la liste `--modules` passée au moteur
    /// au spawn, ET figure dans l'ensemble injecté au scope.json. Un binaire absent (probed=0, sans
    /// override) N'est PAS considéré « désactivé opérateur » (le moteur le SKIP via sa propre sonde).
    #[test]
    fn module_governance_filter_and_disabled_set() {
        let path = tmp_path("forge-test-modfilter");
        let app = test_app(&path);
        seed_modules(&app); // recon.httpx (enabled=1, dispo), exploit.rce (enabled=1, dispo)
        {
            let db = app.db();
            // recon.disabled : présent (available=1) mais DÉSACTIVÉ par l'opérateur (enabled=0).
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled) \
                        VALUES('recon.disabled',0,0,1,'','recon',1,0)", []).unwrap();
            // recon.masked : ENABLED mais override=0 -> masqué malgré un binaire présent.
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled,available_override) \
                        VALUES('recon.masked',0,0,1,'','recon',1,1,0)", []).unwrap();
            // recon.absent : ENABLED, pas d'override, binaire ABSENT (available=0) -> PAS désactivé opérateur.
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled) \
                        VALUES('recon.absent',0,0,0,'','recon',1,1)", []).unwrap();
        }
        let disabled = operator_disabled_modules(&app);
        assert!(disabled.contains(&"recon.disabled".to_string()), "enabled=0 -> dans le set désactivé");
        assert!(disabled.contains(&"recon.masked".to_string()), "override=0 -> dans le set désactivé");
        assert!(!disabled.contains(&"recon.absent".to_string()), "binaire absent (sans override) -> PAS désactivé opérateur");
        assert!(!disabled.contains(&"recon.httpx".to_string()), "connecteur actif -> hors set");
        // filtre --modules : les désactivés SONT retirés, les actifs et l'absent (géré par la sonde) restent.
        let filtered = filter_enabled_modules(&app,
            &["recon.httpx".into(), "recon.disabled".into(), "recon.masked".into(), "recon.absent".into()]);
        assert_eq!(filtered, vec!["recon.httpx".to_string(), "recon.absent".to_string()],
            "le filtre spawn retire recon.disabled + recon.masked, conserve httpx + absent");
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur validate] validate_modules CONSULTE enabled/override : un connecteur désactivé est
    /// refusé (400 module_disabled) — MÊME sous opt-in haut-impact (désinstaller un connecteur est au
    /// -dessus du plancher exploit). Un module actif reste accepté. Un binaire absent (sans override)
    /// N'est PAS refusé (comportement inchangé : accepté puis SKIP par le moteur).
    #[test]
    fn validate_modules_rejects_operator_disabled() {
        let path = tmp_path("forge-test-vmods-disabled");
        let app = test_app(&path);
        seed_modules(&app);
        {
            let db = app.db();
            db.execute("UPDATE module SET enabled=0 WHERE kind='recon.httpx'", []).unwrap(); // désactive
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled) \
                        VALUES('recon.absent',0,0,0,'','recon',1,1)", []).unwrap();           // absent mais actif
        }
        // désactivé -> 400 module_disabled (sans opt-in).
        let err = validate_modules(&app, &["recon.httpx".into()], false).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "module_disabled", "connecteur désactivé refusé");
        // désactivé -> 400 module_disabled MÊME sous opt-in haut-impact (au-dessus du plancher exploit).
        let err = validate_modules(&app, &["recon.httpx".into()], true).unwrap_err();
        assert_eq!(err.code, "module_disabled", "désactivé refusé même armé (gouvernance > plancher)");
        // réactive -> OK ; binaire absent (actif) -> accepté (skip côté moteur, pas un refus web).
        { let db = app.db(); db.execute("UPDATE module SET enabled=1 WHERE kind='recon.httpx'", []).unwrap(); }
        assert!(validate_modules(&app, &["recon.httpx".into()], false).is_ok(), "réactivé -> accepté");
        assert!(validate_modules(&app, &["recon.absent".into()], false).is_ok(),
            "binaire absent sans intention opérateur -> accepté (SKIP moteur), pas 400");
        let _ = std::fs::remove_file(&path);
    }

    /// [FEATURE A — extra_args echo] validate_extra_args ENFORCE l'allowlist de drapeaux server-side
    /// (défense en profondeur) : un flag hors liste -> 400 extra_arg_not_allowlisted ; un token-valeur
    /// (ne commençant pas par '-') passe ; extra_args non-liste -> 400 bad_extra_args ; absent -> OK.
    #[test]
    fn validate_extra_args_enforces_allowlist() {
        let path = tmp_path("forge-test-extra-args");
        let app = test_app(&path);
        {
            let store = app.store();
            // module nmap-like avec allowlist {-p, --max-rate}.
            upsert_probed_module(&store, "recon.nmap", false, false, true, "T1046", "nmap",
                                 "[]", "[\"-p\",\"--max-rate\"]");
        }
        let mk = |v: serde_json::Value| -> serde_json::Map<String, serde_json::Value> {
            let mut m = serde_json::Map::new();
            m.insert("recon.nmap".into(), v);
            m
        };
        // flag autorisé + valeur -> OK.
        assert!(validate_extra_args(&app, &mk(json!({"extra_args": ["--max-rate", "50"]}))).is_ok());
        // flag hors allowlist -> 400 extra_arg_not_allowlisted.
        let err = validate_extra_args(&app, &mk(json!({"extra_args": ["-oN", "/tmp/x"]}))).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "extra_arg_not_allowlisted");
        // la forme --flag=val n'est jamais dans l'allowlist -> refusée.
        let err = validate_extra_args(&app, &mk(json!({"extra_args": ["--max-rate=50"]}))).unwrap_err();
        assert_eq!(err.code, "extra_arg_not_allowlisted");
        // extra_args non-liste -> 400 bad_extra_args.
        let err = validate_extra_args(&app, &mk(json!({"extra_args": "-p 80"}))).unwrap_err();
        assert_eq!(err.code, "bad_extra_args");
        // token non-string -> 400.
        let err = validate_extra_args(&app, &mk(json!({"extra_args": [123]}))).unwrap_err();
        assert_eq!(err.code, "bad_extra_args");
        // pas d'extra_args -> OK (no-op).
        assert!(validate_extra_args(&app, &mk(json!({"ports": "80"}))).is_ok());
        // module inconnu -> allowlist vide -> tout flag refusé (fail-closed).
        let mut unk = serde_json::Map::new();
        unk.insert("recon.unknown".into(), json!({"extra_args": ["-p"]}));
        assert_eq!(validate_extra_args(&app, &unk).unwrap_err().code, "extra_arg_not_allowlisted");
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur no-clobber] upsert_probed_module (chemin populate_modules) : un DISABLE manuel
    /// (enabled=0 + available_override=0 + web_allowed=0) SURVIT à un re-probe qui met à jour les
    /// champs sondés (exploit/available/mitre/descr). Régression : le refresh ne doit JAMAIS écraser
    /// l'intention opérateur.
    #[test]
    fn refresh_does_not_clobber_manual_disable() {
        let path = tmp_path("forge-test-noclobber");
        let app = test_app(&path);
        {
            let store = app.store();
            // 1er probe : module recon dispo.
            upsert_probed_module(&store, "recon.httpx", false, false, true, "", "recon httpx", "[]", "[]");
            // l'admin DÉSACTIVE le connecteur + masque + retire du web (intention opérateur).
            store.execute("UPDATE module SET enabled=0, available_override=0, web_allowed=0 WHERE kind='recon.httpx'", &crate::sql_params![]).unwrap();
            // re-probe (nouvelle version : gagne une capacité exploit, sonde toujours dispo, descr changée).
            upsert_probed_module(&store, "recon.httpx", true, false, true, "T1190", "recon httpx v2", "[]", "[]");
            let (enabled, ov, web, exploit, descr): (i64, Option<i64>, i64, i64, String) = store.query_row(
                "SELECT enabled, available_override, web_allowed, exploit, descr FROM module WHERE kind='recon.httpx'",
                &crate::sql_params![], |r| Ok((r.get_i64(0)?, r.get_opt_i64(1)?, r.get_i64(2)?, r.get_i64(3)?, r.get_str(4)?))).unwrap();
            drop(store);
            // INTENTION OPÉRATEUR préservée :
            assert_eq!(enabled, 0, "enabled=0 préservé au re-probe (no-clobber)");
            assert_eq!(ov, Some(0), "available_override=0 préservé au re-probe");
            assert_eq!(web, 0, "web_allowed préservé au re-probe (intention opérateur)");
            // champs SONDÉS mis à jour :
            assert_eq!(exploit, 1, "champ sondé exploit MIS À JOUR par le re-probe");
            assert_eq!(descr, "recon httpx v2", "champ sondé descr MIS À JOUR par le re-probe");
        }
        // un NOUVEAU module hérite des DEFAULT enabled=1 / override=NULL.
        {
            let store = app.store();
            upsert_probed_module(&store, "recon.new", false, false, true, "", "neuf", "[]", "[]");
            let (enabled, ov): (i64, Option<i64>) = store.query_row(
                "SELECT enabled, available_override FROM module WHERE kind='recon.new'", &crate::sql_params![],
                |r| Ok((r.get_i64(0)?, r.get_opt_i64(1)?))).unwrap();
            drop(store); // release before the assertions below (no DB access there)
            assert_eq!(enabled, 1, "nouveau module -> enabled par défaut");
            assert_eq!(ov, None, "nouveau module -> pas d'override par défaut (suit la sonde)");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur endpoint] module_governance : ADMIN-GATED (viewer -> 403 sans aucune mutation) +
    /// LEDGERISÉ (une mutation admin écrit `console.admin.module.set` attribuée à l'acteur). Preuve que
    /// l'endpoint est la contrepartie écriture gouvernée de GET /api/modules.
    #[tokio::test]
    async fn module_governance_endpoint_admin_gated_and_ledgered() {
        let path = tmp_path("forge-test-modgov");
        let app = test_app(&path);
        seed_modules(&app);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (atok, _) = create_session(&app, uid_of(&app, "aa"));

        // viewer -> 403 (fail-closed) ET aucune mutation (le connecteur reste enabled=1).
        let resp = module_governance(
            State(app.clone()), bearer_headers(&vtok), Path("recon.httpx".into()),
            Json(json!({"enabled": false}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "non-admin refusé (fail-closed)");
        let en: i64 = { let db = app.db(); db.query_row("SELECT enabled FROM module WHERE kind='recon.httpx'", [], |r| r.get(0)).unwrap() };
        assert_eq!(en, 1, "un refus 403 ne DOIT rien muter");

        // admin -> 200 + mutation persistée + entrée ledger attribuée.
        let resp = module_governance(
            State(app.clone()), bearer_headers(&atok), Path("recon.httpx".into()),
            Json(json!({"enabled": false, "available_override": true}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "admin autorisé");
        let (en, ov): (i64, Option<i64>) = { let db = app.db(); db.query_row(
            "SELECT enabled, available_override FROM module WHERE kind='recon.httpx'", [],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!(en, 0, "admin a désactivé le connecteur");
        assert_eq!(ov, Some(1), "admin a posé available_override=true");
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.admin.module.set", "mutation ledgerisée");
        assert_eq!(last["detail"]["actor"], "aa", "attribuée à l'admin acteur");
        assert_eq!(last["detail"]["kind"], "recon.httpx");
        assert_eq!(last["detail"]["enabled"], false);

        // kind inconnu -> 404 (pas de module fantôme créé depuis l'admin).
        let resp = module_governance(
            State(app.clone()), bearer_headers(&atok), Path("recon.ghost".into()),
            Json(json!({"enabled": false}))).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "connecteur inconnu -> 404");
        // corps sans aucun champ -> 400 (aucun changement).
        let resp = module_governance(
            State(app.clone()), bearer_headers(&atok), Path("recon.httpx".into()),
            Json(json!({}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "aucun changement -> 400");
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur routeur] le param `/api/modules/:kind` coexiste avec le statique
    /// `/api/modules/refresh` (matchit : le statique prime). Construire ce sous-routeur ne doit PAS
    /// paniquer — garde-fou contre un conflit de routes introduit par la gouvernance connecteur.
    #[test]
    fn module_routes_do_not_conflict() {
        let _r: Router<App> = Router::new()
            .route("/api/modules", get(modules))
            .route("/api/modules/refresh", post(modules_refresh))
            .route("/api/modules/:kind", post(module_governance));
    }

    // =============================================================================================
    // OUTILS AJOUTÉS PAR L'UI (« add a tool from the web UI ») — validation fail-closed + endpoints.
    // =============================================================================================

    /// [tools validation] validate_toolspec REJETTE fail-closed : argv non-liste (chaîne shell), token
    /// `{evil}`, binaire interpréteur, drapeau d'exfil, `{args}` sans allowlist, kind hors `custom.*`
    /// (collision natif), et traversée de kind. Un spec propre PASSE et se canonicalise.
    #[test]
    fn validate_toolspec_fail_closed() {
        // spec propre -> OK, kind normalisé.
        let (k, canon) = crate::tools::validate_toolspec(&simple_toolspec()).expect("spec propre accepté");
        assert_eq!(k, "custom.echotool");
        assert_eq!(canon["binary"], "echo");
        // argv = chaîne shell (pas une liste) -> 400 (jamais de shell).
        let mut s = simple_toolspec(); s["argv_template"] = json!("echo {target}; rm -rf /");
        assert_eq!(crate::tools::validate_toolspec(&s).unwrap_err().0, StatusCode::BAD_REQUEST, "argv chaîne refusée");
        // token placeholder inconnu {evil} -> 400.
        let mut s = simple_toolspec(); s["argv_template"] = json!(["-u", "{evil}"]);
        assert_eq!(crate::tools::validate_toolspec(&s).unwrap_err().0, StatusCode::BAD_REQUEST, "{{evil}} refusé");
        // métacaractère shell dans un token littéral -> 400.
        let mut s = simple_toolspec(); s["argv_template"] = json!(["{target}", "; id"]);
        assert!(crate::tools::validate_toolspec(&s).is_err(), "métacaractère shell refusé");
        // binaire interpréteur (bash) -> 400 (réintroduirait le shell).
        let mut s = simple_toolspec(); s["binary"] = json!("bash"); s["argv_template"] = json!(["-c", "id"]);
        assert!(crate::tools::validate_toolspec(&s).is_err(), "bash refusé");
        // drapeau d'exfil dans argv (-o output) -> 400.
        let mut s = simple_toolspec(); s["argv_template"] = json!(["-o", "out.txt", "{target}"]);
        assert!(crate::tools::validate_toolspec(&s).is_err(), "-o (output-file) refusé");
        // {args} sans flag_allowlist -> 400.
        let mut s = simple_toolspec(); s["argv_template"] = json!(["{target}", "{args}"]);
        assert!(crate::tools::validate_toolspec(&s).is_err(), "{{args}} sans allowlist refusé");
        // {args} AVEC allowlist non dangereuse -> OK.
        let mut s = simple_toolspec(); s["argv_template"] = json!(["{target}", "{args}"]);
        s["flag_allowlist"] = json!(["-t", "--rate"]);
        assert!(crate::tools::validate_toolspec(&s).is_ok(), "{{args}} + allowlist accepté");
        // allowlist avec drapeau d'exfil -> 400.
        let mut s = simple_toolspec(); s["argv_template"] = json!(["{target}", "{args}"]);
        s["flag_allowlist"] = json!(["--proxy"]);
        assert!(crate::tools::validate_toolspec(&s).is_err(), "allowlist --proxy refusée");
        // drapeaux courts curl d'exfil/upload/config -T/-K/-F et --upload-file -> 400 (soit en argv, soit
        // en flag_allowlist). CASE-SENSITIVE : les minuscules -t/-k/-f (threads/insecure/fail) restent OK.
        for bad_flag in ["-T", "-K", "-F", "--upload-file"] {
            let mut s = simple_toolspec(); s["argv_template"] = json!([bad_flag, "{target}"]);
            assert!(crate::tools::validate_toolspec(&s).is_err(), "argv '{bad_flag}' (exfil curl) refusé");
            let mut s = simple_toolspec(); s["argv_template"] = json!(["{target}", "{args}"]);
            s["flag_allowlist"] = json!([bad_flag]);
            assert!(crate::tools::validate_toolspec(&s).is_err(), "flag_allowlist '{bad_flag}' refusée");
        }
        // garde anti-sur-blocage : les drapeaux MINUSCULES homologues restent autorisés (threads/insecure/fail).
        for ok_flag in ["-t", "-k", "-f"] {
            let mut s = simple_toolspec(); s["argv_template"] = json!(["{target}", "{args}"]);
            s["flag_allowlist"] = json!([ok_flag]);
            assert!(crate::tools::validate_toolspec(&s).is_ok(), "flag_allowlist '{ok_flag}' (légitime) acceptée");
        }
        // M2 — le SEGMENT DEFAULT d'un placeholder {param:NAME:DEFAULT} subit la MÊME curation
        // d'option-injection que les tokens littéraux : un défaut '-'-leading est REFUSÉ (il smugglerait un
        // drapeau d'écriture-fichier/exfil que le scan des seuls tokens littéraux + nom de param ne voit pas).
        for evil in ["{param:mode:-oN/tmp/pwned}", "{param:out:--output=/tmp/x}", "{param:p:-x}"] {
            let mut s = simple_toolspec(); s["argv_template"] = json!(["{target}", evil]);
            assert!(crate::tools::validate_toolspec(&s).is_err(), "défaut de param '-'-leading refusé: {evil}");
        }
        // garde anti-sur-blocage : un défaut de param NON-drapeau (valeur positionnelle) reste accepté.
        let mut s = simple_toolspec(); s["argv_template"] = json!(["{target}", "{param:port:443}", "{param:mode:fast}"]);
        assert!(crate::tools::validate_toolspec(&s).is_ok(), "défauts de param non-drapeau acceptés");

        // kind hors namespace custom.* (surcharge natif) -> 400.
        let mut s = simple_toolspec(); s["kind"] = json!("recon.httpx");
        assert!(crate::tools::validate_toolspec(&s).is_err(), "kind non-custom refusé");
        // kind avec traversée -> validate_kind refuse.
        assert!(crate::tools::validate_kind("custom../etc/passwd").is_err(), "traversée de kind refusée");
        assert!(crate::tools::validate_kind("custom.").is_err(), "kind sans nom refusé");
        assert!(crate::tools::validate_kind("x").is_err(), "kind trop court refusé");
        assert!(crate::tools::validate_kind("recon.httpx").is_err(), "kind natif (hors custom.) refusé");
        // hit_status='vulnerable' interdit (proof-oriented).
        let mut s = simple_toolspec(); s["hit_status"] = json!("vulnerable");
        assert!(crate::tools::validate_toolspec(&s).is_err(), "hit_status vulnerable refusé");
        // champ inconnu -> 400 (aucune capacité surprise, ex bug_bounty_eligible).
        let mut s = simple_toolspec(); s["bug_bounty_eligible"] = json!(true);
        assert!(crate::tools::validate_toolspec(&s).is_err(), "champ inconnu refusé");
    }

    /// [tools path] spec_file_path reste SOUS le dir managé et refuse toute traversée dérivée du kind.
    #[test]
    fn tool_spec_path_is_traversal_safe() {
        let _g = env_lock();
        let dir = tmp_dir("forge-test-tsdir");
        std::env::set_var("FORGE_TOOLSPECS_DIR", &dir);
        let p = crate::tools::spec_file_path("custom.echotool").unwrap();
        assert!(p.starts_with(&dir), "le fichier de spec reste sous le dir managé");
        assert_eq!(p.file_name().unwrap().to_string_lossy(), "custom.echotool.json");
        assert!(crate::tools::spec_file_path("custom./../evil").is_err(), "traversée refusée");
        std::env::remove_var("FORGE_TOOLSPECS_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [tools endpoint] POST /api/tools admin -> persiste 0600 + HOT-RELOAD (apparaît dans /api/modules) +
    /// ledger `console.tool.add` ; GET /api/tools le liste ; non-admin -> 403 ; DELETE admin le retire mais
    /// REFUSE un built-in (recon.httpx). Spawn le vrai probe python (registre in-tree, dir managé injecté).
    #[tokio::test]
    async fn tools_add_list_delete_admin_gated_and_hot_reload() {
        let _g = env_lock();
        let dir = tmp_dir("forge-test-tools-managed");
        std::env::set_var("FORGE_TOOLSPECS_DIR", &dir);
        std::env::remove_var("FORGE_TOOLSPECS");
        let path = tmp_path("forge-test-tools-ledger");
        let app = test_app(&path);
        seed_modules(&app); // recon.httpx (built-in, user_added=0)
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (atok, _) = create_session(&app, uid_of(&app, "aa"));

        // non-admin -> 403, ET rien de persisté.
        let r = tools_add(State(app.clone()), bearer_headers(&vtok), Json(simple_toolspec())).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "non-admin refusé (fail-closed)");
        assert!(!dir_has_spec(&dir, "custom.echotool"), "aucun fichier écrit sur refus 403");

        // admin -> 200. (le probe python peut être indisponible dans certains environnements : on tolère,
        // mais le fichier DOIT être écrit 0600 et le ledger DOIT porter l'entrée d'ajout.)
        let r = tools_add(State(app.clone()), bearer_headers(&atok), Json(simple_toolspec())).await;
        assert_eq!(r.status(), StatusCode::OK, "admin autorisé");
        assert!(dir_has_spec(&dir, "custom.echotool"), "spec persisté");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(dir_spec(&dir, "custom.echotool")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "spec écrit 0600");
        }
        let entries = read_ledger_lines(&path);
        let add = entries.iter().rev().find(|e| e["kind"] == "console.tool.add").expect("ledger add");
        assert_eq!(add["detail"]["actor"], "aa", "ajout attribué à l'admin");
        assert_eq!(add["detail"]["kind"], "custom.echotool");

        // le module doit apparaître dans le catalogue (hot-reload via re-probe) + marqué user_added.
        let present = { let s = app.store(); modules_catalog(&s).into_iter()
            .any(|m| m.get("kind").and_then(|v| v.as_str()) == Some("custom.echotool")) };
        assert!(present, "l'outil ajouté apparaît dans /api/modules (hot-reload)");
        let ua: i64 = { let db = app.db(); db.query_row("SELECT user_added FROM module WHERE kind='custom.echotool'", [], |r| r.get(0)).unwrap() };
        assert_eq!(ua, 1, "outil marqué user_added");

        // GET /api/tools (admin) le liste ; viewer -> 403.
        let r = tools_list(State(app.clone()), bearer_headers(&atok)).await;
        assert_eq!(r.status(), StatusCode::OK, "GET /api/tools admin");
        let body = resp_json(r).await;
        assert!(body["tools"].as_array().map(|a| a.iter().any(|t| t["kind"] == "custom.echotool")).unwrap_or(false),
            "l'outil UI est listé");
        assert_eq!(tools_list(State(app.clone()), bearer_headers(&vtok)).await.status(), StatusCode::FORBIDDEN);

        // DELETE d'un BUILT-IN -> 403 (jamais supprimable).
        let r = tools_delete(State(app.clone()), bearer_headers(&atok), Path("recon.httpx".into())).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "un built-in n'est pas supprimable");
        // DELETE non-admin -> 403.
        assert_eq!(tools_delete(State(app.clone()), bearer_headers(&vtok), Path("custom.echotool".into())).await.status(),
            StatusCode::FORBIDDEN, "delete non-admin refusé");
        // DELETE admin de l'outil UI -> 200 + fichier + ligne retirés + ledger remove.
        let r = tools_delete(State(app.clone()), bearer_headers(&atok), Path("custom.echotool".into())).await;
        assert_eq!(r.status(), StatusCode::OK, "suppression admin de l'outil UI");
        assert!(!dir_has_spec(&dir, "custom.echotool"), "fichier de spec supprimé");
        let gone = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM module WHERE kind='custom.echotool'", [], |r| r.get::<_, i64>(0)).unwrap() };
        assert_eq!(gone, 0, "ligne module retirée");
        let entries = read_ledger_lines(&path);
        assert!(entries.iter().any(|e| e["kind"] == "console.tool.remove"), "suppression ledgerisée");

        std::env::remove_var("FORGE_TOOLSPECS_DIR");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&path);
    }


// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — tests d'intégration : ip-in-cidr, operator-source-cidr, trusted-proxy, ct_eq, host_guard, network-policy.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

    /// [ENGAGEMENT #1] `ensure_default_engagement` avec un scope serveur VIDE/absent (aucun scope.json monté,
    /// cas ZÉRO-PRÉ-ÉTAPE du `docker compose up`) amorce PROPREMENT l'engagement #1 en scope VIDE
    /// (fail-closed) — pas de panique, rien lançable tant que l'opérateur ne renseigne pas le périmètre.
    #[test]
    fn ensure_default_engagement_empty_server_scope_boots_clean() {
        let dbm = Mutex::new(Connection::open_in_memory().expect("mem db"));
        let conn = || dbm.lock().unwrap_or_else(|e| e.into_inner());
        conn().execute_batch(SCHEMA).expect("schema");
        migrate(&conn()); // production enchaîne SCHEMA puis migrate (ajoute engagement.allow_private, etc.)
        // scope serveur ABSENT -> load_server_scope renvoie (vec![], "grey"). Amorçage avec ces valeurs.
        ensure_default_engagement(&crate::store::Store::sqlite(conn()), &[], "grey", "/tmp/eng1-empty.jsonl");
        let eng = load_engagement(&crate::store::Store::sqlite(conn()), 1).expect("engagement #1 amorcé");
        assert_eq!(eng.mode, "grey");
        assert!(eng.scope_in.is_empty(), "scope VIDE -> fail-closed (rien lançable)");
        assert!(!host_in_scope_list(&eng.scope_in, "anything.example.com"), "scope vide -> tout refusé");
    }

    /// [OPÉRATEUR source-CIDR] ip_in_cidr : appartenance v4/v6, IP exacte, /0, familles hétérogènes,
    /// et rejet fail-closed des entrées malformées (préfixe non numérique / hors borne, réseau invalide).
    #[test]
    fn ip_in_cidr_membership_and_fail_closed() {
        let v4 = "10.0.0.5".parse::<IpAddr>().unwrap();
        assert!(ip_in_cidr(&v4, "10.0.0.0/24"));
        assert!(ip_in_cidr(&v4, "10.0.0.0/8"));
        assert!(!ip_in_cidr(&v4, "10.0.1.0/24"));
        assert!(ip_in_cidr(&v4, "10.0.0.5"), "sans '/' -> comparaison exacte");
        assert!(!ip_in_cidr(&v4, "10.0.0.6"));
        assert!(ip_in_cidr(&v4, "0.0.0.0/0"), "/0 -> tout l'espace v4");
        assert!(!ip_in_cidr(&v4, "garbage"), "réseau invalide -> false");
        assert!(!ip_in_cidr(&v4, "10.0.0.0/33"), "préfixe hors borne -> false");
        assert!(!ip_in_cidr(&v4, "10.0.0.0/x"), "préfixe non numérique -> false");
        let v6 = "2001:db8::5".parse::<IpAddr>().unwrap();
        assert!(ip_in_cidr(&v6, "2001:db8::/32"));
        assert!(!ip_in_cidr(&v6, "2001:dead::/32"));
        assert!(!ip_in_cidr(&v4, "2001:db8::/32"), "v4 vs réseau v6 -> false");
        assert!(!ip_in_cidr(&v6, "10.0.0.0/8"), "v6 vs réseau v4 -> false");
    }

    /// [OPÉRATEUR source-CIDR] check_operator : la contrainte source ne s'applique QUE si configurée.
    /// Non configurée -> toute IP passe (défaut = none). Configurée -> hors-allowlist REFUSÉ, dans
    /// l'allowlist AUTORISÉ, IP indéterminée REFUSÉE (fail-closed). trusted_proxy (CIDR du proxy) ->
    /// honore le dernier hop XFF UNIQUEMENT si le pair TCP EST ce proxy ; un client direct (pair hors
    /// CIDR) qui forge un XFF est IGNORÉ (repli sur le pair) ; valeur héritée "1" -> aucun proxy de
    /// confiance. Un viewer ne passe jamais.
    #[tokio::test]
    async fn operator_source_cidr_enforced_only_when_configured() {
        let path = tmp_path("forge-test-op-cidr");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "op", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
        }
        let (otok, _) = create_session(&app, uid_of(&app, "op"));
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let h = bearer_headers(&otok);
        let ip_ok = "10.0.0.5".parse::<IpAddr>().unwrap();
        let ip_bad = "192.168.1.9".parse::<IpAddr>().unwrap();

        // (a) AUCUNE politique -> toute IP passe (défaut = none), y compris IP indéterminée.
        assert!(check_operator(&app, &h, Some(ip_ok)));
        assert!(check_operator(&app, &h, Some(ip_bad)), "sans politique, IP hors 'futur allowlist' passe");
        assert!(check_operator(&app, &h, None), "sans politique, IP indéterminée passe");

        // (b) politique source_cidrs configurée -> restriction fail-closed.
        {
            let db = app.db();
            settings_set(&db, "operator_policy", "{\"source_cidrs\":[\"10.0.0.0/24\"]}").unwrap();
        }
        assert!(check_operator(&app, &h, Some(ip_ok)), "IP dans le CIDR -> autorisée");
        assert!(!check_operator(&app, &h, Some(ip_bad)), "IP hors CIDR -> refusée (fail-closed)");
        assert!(!check_operator(&app, &h, None), "politique active + IP indéterminée -> refus");

        // (c) AUCUN trusted_proxy configuré -> X-Forwarded-For IGNORÉ (on prend le pair). Pair hors
        //     CIDR -> refus, même si le XFF prétend une IP autorisée.
        let mut hx = bearer_headers(&otok);
        hx.insert("x-forwarded-for", "10.0.0.5".parse().unwrap());
        assert!(!check_operator(&app, &hx, Some(ip_bad)), "sans trusted_proxy -> XFF ignoré, pair hors CIDR -> refus");

        // (d) [RÉTRO-COMPAT] valeur héritée "1" (truthy non-CIDR) -> traitée comme AUCUN proxy de
        //     confiance -> XFF ignoré, repli fail-closed sur le pair. Ne vaut JAMAIS « fais confiance à
        //     tout XFF » (ce qui rouvrirait le contournement).
        {
            let db = app.db();
            settings_set(&db, "trusted_proxy", "1").unwrap();
        }
        let mut hlegacy = bearer_headers(&otok);
        hlegacy.insert("x-forwarded-for", "203.0.113.7, 10.0.0.5".parse().unwrap());
        assert!(!check_operator(&app, &hlegacy, Some(ip_bad)),
            "trusted_proxy='1' (héritée) -> aucun proxy de confiance -> XFF ignoré, pair hors CIDR -> refus");

        // On configure désormais trusted_proxy = le CIDR RÉEL du proxy amont.
        {
            let db = app.db();
            settings_set(&db, "trusted_proxy", "172.16.0.0/12").unwrap();
        }
        let proxy_ip = "172.16.0.9".parse::<IpAddr>().unwrap(); // pair ∈ trusted_proxy CIDR

        // (e) [RÉGRESSION anti-contournement] client DIRECT (pair hors trusted_proxy CIDR) qui FORGE un
        //     X-Forwarded-For revendiquant une IP de l'allowlist -> XFF IGNORÉ (le pair n'est pas le
        //     proxy) -> repli sur le pair (ip_bad) -> REFUSÉ. Fermeture du bypass XFF spoofé.
        let mut hspoof = bearer_headers(&otok);
        hspoof.insert("x-forwarded-for", "10.0.0.5".parse().unwrap());
        assert!(!check_operator(&app, &hspoof, Some(ip_bad)),
            "client direct + XFF spoofé prétendant une IP autorisée -> XFF ignoré, repli sur pair -> REFUSÉ (bypass fermé)");

        // (f) requête RÉELLEMENT relayée : le pair TCP EST le proxy de confiance (∈ CIDR) et le dernier
        //     hop XFF est dans l'allowlist opérateur -> honoré -> AUTORISÉ (le pair-proxy n'est PAS dans
        //     l'allowlist, ce qui prouve que c'est bien le XFF qui décide).
        let mut hp = bearer_headers(&otok);
        hp.insert("x-forwarded-for", "203.0.113.7, 10.0.0.5".parse().unwrap());
        assert!(check_operator(&app, &hp, Some(proxy_ip)),
            "pair = proxy de confiance + dernier hop XFF dans le CIDR -> autorisé");

        // (f-bis) même proxy de confiance mais dernier hop XFF hors allowlist -> refusé (fail-closed sur
        //     l'IP réelle du client telle que déclarée par le proxy).
        let mut hp2 = bearer_headers(&otok);
        hp2.insert("x-forwarded-for", "203.0.113.7, 192.168.1.9".parse().unwrap());
        assert!(!check_operator(&app, &hp2, Some(proxy_ip)),
            "pair = proxy de confiance mais dernier hop XFF hors CIDR -> refusé");

        // (g) un viewer ne passe JAMAIS, quelle que soit l'IP/politique.
        assert!(!check_operator(&app, &bearer_headers(&vtok), Some(ip_ok)), "viewer refusé indépendamment de la politique source");
        let _ = std::fs::remove_file(&path);
    }

    /// [SÉCURITÉ XFF] parse_trusted_proxy_cidrs : tableau JSON / CSV / CIDR unique -> liste ; valeurs
    /// héritées truthy non-CIDR ("1"/"true"), vide, ou déchet -> liste VIDE (aucun proxy de confiance).
    /// effective_client_ip : XFF honoré SEULEMENT si le pair ∈ un trusted_proxy CIDR ; sinon IGNORÉ
    /// (repli fail-closed sur le pair, ou None si pair inconnu).
    #[test]
    fn trusted_proxy_cidr_parse_and_effective_ip_fail_closed() {
        // parse : formats acceptés
        assert_eq!(parse_trusted_proxy_cidrs("10.0.0.0/24"), vec!["10.0.0.0/24".to_string()]);
        assert_eq!(parse_trusted_proxy_cidrs("[\"10.0.0.0/24\",\"172.16.0.0/12\"]"),
                   vec!["10.0.0.0/24".to_string(), "172.16.0.0/12".to_string()]);
        assert_eq!(parse_trusted_proxy_cidrs("10.0.0.0/24, 172.16.0.0/12"),
                   vec!["10.0.0.0/24".to_string(), "172.16.0.0/12".to_string()]);
        assert_eq!(parse_trusted_proxy_cidrs("203.0.113.4"), vec!["203.0.113.4".to_string()], "IP nue -> match exact");
        // parse : héritées / invalides -> vide (fail-closed, jamais « trust all »)
        assert!(parse_trusted_proxy_cidrs("1").is_empty(), "'1' hérité -> aucun proxy de confiance");
        assert!(parse_trusted_proxy_cidrs("true").is_empty(), "'true' hérité -> aucun proxy de confiance");
        assert!(parse_trusted_proxy_cidrs("").is_empty());
        assert!(parse_trusted_proxy_cidrs("garbage").is_empty());
        assert!(parse_trusted_proxy_cidrs("10.0.0.0/33").is_empty(), "préfixe hors borne -> écarté");

        let cidrs = vec!["172.16.0.0/12".to_string()];
        let proxy = "172.16.0.9".parse::<IpAddr>().unwrap();
        let direct = "192.168.1.9".parse::<IpAddr>().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.5".parse().unwrap());

        // pair = proxy de confiance -> dernier hop XFF honoré
        assert_eq!(effective_client_ip(Some(proxy), &h, &cidrs), Some("10.0.0.5".parse().unwrap()));
        // pair = client direct (hors CIDR) -> XFF IGNORÉ, repli sur le pair
        assert_eq!(effective_client_ip(Some(direct), &h, &cidrs), Some(direct));
        // aucun trusted_proxy -> XFF ignoré, repli sur le pair
        assert_eq!(effective_client_ip(Some(proxy), &h, &[]), Some(proxy));
        // pair inconnu -> None (fail-closed), jamais l'XFF
        assert_eq!(effective_client_ip(None, &h, &cidrs), None);
    }

    /// [LOW sec] ct_eq_str : égalité correcte, inégalité correcte (la propriété temps-constant n'est
    /// pas mesurable en test unitaire, mais on garantit la correction fonctionnelle).
    #[test]
    fn ct_eq_str_correctness() {
        assert!(ct_eq_str("deadbeef", "deadbeef"));
        assert!(!ct_eq_str("deadbeef", "deadbee0"));
        assert!(!ct_eq_str("deadbeef", "deadbeeff")); // longueurs différentes
        assert!(!ct_eq_str("", "x"));
    }

    /// [WebUI] L'aide in-app est présente et accessible : bouton « ? » persistant (annoncé comme
    /// dialog) + indices de champ inline sur le wizard config-heavy dans l'index compilé, et le front
    /// définit le centre d'aide (openHelp + registre HELP_TOPICS + rubrique gouvernance/modèle de
    /// sûreté) avec la modale role=dialog/aria-modal et les indices des formulaires config-heavy.
    /// Garde-fou anti-régression : ces marqueurs ne doivent pas disparaître silencieusement.
    #[test]
    fn webui_help_affordance_and_registry_present() {
        let index = include_str!("../web/index.html");
        assert!(index.contains("id=\"help\""), "bouton d'aide manquant dans l'en-tête");
        assert!(index.contains("aria-haspopup=\"dialog\""), "affordance d'aide non annoncée comme dialog");
        assert!(index.contains("class=\"fhint\""), "indices de champ (.fhint) absents du wizard de 1er déploiement");

        // Le front est désormais découpé en modules ES (app.js = entrée ; le code vit sous web/js/**).
        // On agrège les modules porteurs de ces marqueurs et on cherche dans l'ensemble : le centre
        // d'aide (help.js), la modale accessible (ui.js) et les indices de source de détection (admin.js).
        let app = [
            include_str!("../web/app.js"),
            include_str!("../web/js/core/help.js"),
            include_str!("../web/js/core/ui.js"),
            include_str!("../web/js/views/admin.js"),
            include_str!("../web/js/components/detection-source-form.js"),
        ]
        .concat();
        assert!(app.contains("function openHelp("), "openHelp() absent du front");
        assert!(app.contains("HELP_TOPICS"), "registre d'aide HELP_TOPICS absent");
        assert!(app.contains("'governance'"), "rubrique « Comment Forge fonctionne » (gouvernance) absente");
        assert!(app.contains("'aria-modal'"), "la modale d'aide n'est pas marquée aria-modal");
        assert!(app.contains("'dialog'"), "la modale d'aide n'a pas role=dialog");
        assert!(app.contains("modal-fhint"), "indices de champ des modales (users/backup) absents");
        assert!(app.contains("det-fhint"), "indices de champ de la source de détection absents");
    }

    /// [LOW sec] host_guard fail-closed : Host vide/absent REFUSÉ ; hors allowlist refusé ; in-allowlist
    /// accepté (port ignoré).
    #[test]
    fn host_guard_rejects_empty_and_unknown() {
        let allow = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        assert!(!host_allowed("", &allow), "Host vide doit être refusé (fail-closed)");
        assert!(!host_allowed(":7100", &allow), "Host vide avec port doit être refusé");
        assert!(!host_allowed("evil.example", &allow), "Host hors allowlist refusé");
        assert!(host_allowed("localhost", &allow));
        assert!(host_allowed("localhost:7100", &allow), "port ignoré");
        assert!(host_allowed("127.0.0.1:8080", &allow));
    }


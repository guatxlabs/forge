// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — tests d'intégration : sessions, login-lockout, tokens, cookie/bearer, attribution, auth-gate, https-detect.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

    /// [2b] try_create_session PROPAGE l'échec d'écriture au lieu de l'avaler : si la table `session` est
    /// absente, l'INSERT échoue -> `Err` (aucun token non persisté rendu). Le handler /api/login le remonte
    /// en 500 (plus de faux-200 avec un token mort qui serait rejeté au 1er usage).
    #[tokio::test]
    async fn create_session_write_failure_propagates() {
        let path = tmp_path("forge-test-session-propagate");
        let app = test_app(&path);
        { let db = app.db(); upsert_user(&db, "sessu", "operator", &hash_pw("pw")).unwrap(); }
        let uid = uid_of(&app, "sessu");
        assert!(try_create_session(&app, uid).is_ok(), "nominal -> session persistée (Ok)");
        // casse l'écriture : sans table `session`, l'INSERT échoue -> Err doit remonter.
        { let db = app.db(); db.execute_batch("DROP TABLE session").unwrap(); }
        assert!(try_create_session(&app, uid).is_err(), "INSERT échoué -> Err (pas de faux-succès)");
        // bout-en-bout : login avec de BONS identifiants mais persistance impossible -> 500, pas 200.
        let r = login(State(app.clone()), HeaderMap::new(), Json(json!({"login": "sessu", "password": "pw"}))).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR, "login -> 500 sur échec de persistance de session");
        let b = resp_json(r).await;
        assert_eq!(b["error"], "session_persist_failed");
        let _ = std::fs::remove_file(&path);
    }

    /// [3] Lockout du login local après N échecs, SANS fuite d'existence de compte. (a) N échecs sur un
    /// compte EXISTANT -> 401 ; (b) seuil franchi -> verrou : MÊME le BON mot de passe est refusé ; (c)
    /// ANTI-ÉNUMÉRATION : un login INEXISTANT verrouillé par le même martelage renvoie un 401 BYTE-IDENTIQUE
    /// au compte existant verrouillé (indistinguables) ; (d) un compte sain non martelé se connecte (200).
    #[tokio::test]
    async fn login_lockout_triggers_without_user_enumeration() {
        async fn attempt(app: &App, login_name: &str, pw: &str) -> (StatusCode, Value) {
            let r = login(State(app.clone()), HeaderMap::new(), Json(json!({"login": login_name, "password": pw}))).await;
            let st = r.status();
            (st, resp_json(r).await)
        }
        let path = tmp_path("forge-test-login-lockout");
        let app = test_app(&path);
        { let db = app.db(); upsert_user(&db, "lockknownx", "operator", &hash_pw("goodpw")).unwrap(); }

        // (a) N échecs sur un compte existant -> chacun 401 invalid_credentials.
        for _ in 0..LOGIN_MAX_FAILS {
            let (st, b) = attempt(&app, "lockknownx", "wrong").await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
            assert_eq!(b["error"], "invalid_credentials");
        }
        // (b) seuil franchi -> verrou : le BON mot de passe est désormais refusé (le lockout mord).
        let (st_known, b_known) = attempt(&app, "lockknownx", "goodpw").await;
        assert_eq!(st_known, StatusCode::UNAUTHORIZED, "compte verrouillé : bon mdp refusé");
        assert_eq!(b_known["error"], "invalid_credentials");

        // (c) verrouiller un login INEXISTANT par le même martelage -> réponse IDENTIQUE (pas d'oracle).
        for _ in 0..LOGIN_MAX_FAILS {
            let _ = attempt(&app, "lockunknownx", "wrong").await;
        }
        let (st_unknown, b_unknown) = attempt(&app, "lockunknownx", "whatever").await;
        assert_eq!(st_unknown, st_known, "verrouillé inconnu == verrouillé connu (statut)");
        assert_eq!(b_unknown, b_known, "verrouillé inconnu == verrouillé connu (corps) — indistinguable");

        // (d) un AUTRE compte, non martelé, se connecte normalement (pas de lock-out collatéral).
        { let db = app.db(); upsert_user(&db, "freshuserx", "viewer", &hash_pw("okpw")).unwrap(); }
        let (st_ok, b_ok) = attempt(&app, "freshuserx", "okpw").await;
        assert_eq!(st_ok, StatusCode::OK, "compte sain -> login 200");
        assert!(b_ok.get("token").is_some(), "token émis pour le compte sain");
        let _ = std::fs::remove_file(&path);
    }

    /// [HIGH] gen_token : entropie CSPRNG -> non tous-zeros, longueur fixe, valeurs distinctes.
    #[test]
    fn gen_token_is_random_not_zero() {
        let a = gen_token();
        let b = gen_token();
        assert_eq!(a.len(), 32, "16 octets -> 32 hex");
        assert_ne!(a, "0".repeat(32), "token tous-zeros = entropie ignorée (régression)");
        assert_ne!(a, b, "deux tokens consécutifs doivent différer");
    }

    /// [HIGH] hash_pw : sel CSPRNG -> deux hash du MÊME mot de passe diffèrent (sel non constant),
    /// et la vérification réussit (format argon2id valide).
    #[test]
    fn hash_pw_salt_is_random_and_verifies() {
        let h1 = hash_pw("hunter2");
        let h2 = hash_pw("hunter2");
        assert_ne!(h1, h2, "même mdp -> hash identiques = sel constant/tous-zeros (régression)");
        assert!(verify_pw("hunter2", &h1), "hash doit se vérifier");
        assert!(!verify_pw("wrong", &h1), "mauvais mdp doit échouer");
    }


    /// [#6 comptes] validate_login / validate_role : grammaire stricte, rôles fermés (fail-closed).
    #[test]
    fn user_login_and_role_validation() {
        assert!(validate_login("alice").is_ok());
        assert!(validate_login("a.b_c-1").is_ok());
        assert!(validate_login("").is_err(), "login vide refusé");
        assert!(validate_login("-x").is_err(), "login débutant par '-' refusé (anti-flag)");
        assert!(validate_login("a b").is_err(), "espace refusé");
        assert!(validate_login("évil").is_err(), "non-ASCII refusé");
        assert!(validate_role("viewer").is_ok());
        assert!(validate_role("operator").is_ok());
        assert!(validate_role("admin").is_ok());
        assert!(validate_role("root").is_err(), "rôle inconnu refusé");
        assert!(validate_role("").is_err());
    }

    /// [#6 comptes] upsert_user -> session -> resolve_session_identity : un compte individuel en
    /// session est résolu (login/rôle réels), is_operator suit le rôle.
    #[test]
    fn session_resolves_individual_identity() {
        let path = tmp_path("forge-test-users-resolve");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "carol", "operator", &hash_pw("pw")).unwrap();
        }
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='carol'", [], |r| r.get(0)).unwrap() };
        let (tok, _exp) = create_session(&app, uid);
        let id = resolve_session_identity(&app, &bearer_headers(&tok)).expect("session valide -> identité");
        assert_eq!(id.login, "carol");
        assert_eq!(id.role, "operator");
        assert!(id.is_operator, "operator -> is_operator");
        assert!(id.via_session, "via_session=true pour un compte individuel");
        // token inconnu -> pas d'identité.
        assert!(resolve_session_identity(&app, &bearer_headers("deadbeef")).is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 comptes] disabled / expiration : un compte désactivé et une session expirée sont refusés
    /// (fail-closed), et la session expirée est purgée.
    #[test]
    fn session_disabled_and_expired_are_rejected() {
        let path = tmp_path("forge-test-users-disabled");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "dave", "viewer", &hash_pw("pw")).unwrap();
        }
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='dave'", [], |r| r.get(0)).unwrap() };
        let (tok, _) = create_session(&app, uid);
        // désactivation -> refus immédiat même session valide.
        { let db = app.db(); db.execute("UPDATE users SET disabled=1 WHERE id=?", [uid]).unwrap(); }
        assert!(resolve_session_identity(&app, &bearer_headers(&tok)).is_none(), "compte désactivé refusé");
        // réactive + force une session expirée -> refus + purge.
        { let db = app.db(); db.execute("UPDATE users SET disabled=0 WHERE id=?", [uid]).unwrap(); }
        let token_sha = sha_hex(&tok);
        { let db = app.db(); db.execute("UPDATE session SET expires=1 WHERE token_sha=?", [&token_sha]).unwrap(); }
        assert!(resolve_session_identity(&app, &bearer_headers(&tok)).is_none(), "session expirée refusée");
        let purged: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM session WHERE token_sha=?", [&token_sha], |r| r.get(0)).unwrap() };
        assert_eq!(purged, 0, "session expirée purgée");
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 RÉTRO-COMPAT] check_operator : repli bootstrap par hash env quand AUCUNE session n'est
    /// présentée — la console live (hash via env) continue de fonctionner.
    #[test]
    fn check_operator_falls_back_to_env_hash() {
        let path = tmp_path("forge-test-op-env");
        let mut app = test_app(&path);
        app.operator_hash = Arc::new(hash_pw("s3cr3t"));
        assert!(check_operator(&app, &operator_headers("s3cr3t"), None), "bonne preuve env -> opérateur");
        assert!(!check_operator(&app, &operator_headers("wrong"), None), "mauvaise preuve env -> refus");
        assert!(!check_operator(&app, &HeaderMap::new(), None), "aucune preuve -> refus (fail-closed)");
        // attribution sans session -> 'bootstrap' (compte env-hash).
        assert_eq!(attribution_login(&app, &operator_headers("s3cr3t")), "bootstrap");
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 sécurité] check_operator : une session VIEWER ne passe JAMAIS le C2, même si un hash env
    /// opérateur est présent (un viewer authentifié ne doit pas escalader via le secret partagé).
    /// Une session OPERATOR passe, et l'attribution porte le login individuel.
    #[test]
    fn session_viewer_cannot_arm_operator_can() {
        let path = tmp_path("forge-test-op-session");
        let mut app = test_app(&path);
        app.operator_hash = Arc::new(hash_pw("s3cr3t")); // hash env présent (ne doit pas sauver le viewer)
        {
            let db = app.db();
            upsert_user(&db, "viewy", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oppy", "operator", &hash_pw("pw")).unwrap();
        }
        let (vid, oid): (i64, i64) = {
            let db = app.db();
            (db.query_row("SELECT id FROM users WHERE login='viewy'", [], |r| r.get(0)).unwrap(),
             db.query_row("SELECT id FROM users WHERE login='oppy'", [], |r| r.get(0)).unwrap())
        };
        let (vtok, _) = create_session(&app, vid);
        let (otok, _) = create_session(&app, oid);
        assert!(!check_operator(&app, &bearer_headers(&vtok), None), "session viewer NE PASSE PAS le C2");
        assert!(check_operator(&app, &bearer_headers(&otok), None), "session operator passe le C2");
        assert_eq!(attribution_login(&app, &bearer_headers(&otok)), "oppy", "attribution = login individuel");
        let _ = std::fs::remove_file(&path);
    }

    /// [C14 — 401 création engagement] resolve_session_identity essaie Bearer PUIS cookie : un cookie
    /// de session VALIDE authentifie MÊME quand un Bearer PÉRIMÉ/ÉTRANGER (résidu d'un ancien build)
    /// l'accompagne — c'est la régression exacte du « Échec : 401 » sur POST /api/engagements. Prouve
    /// aussi : (a) cookie seul OK, (c) Bearer valide seul OK, (d) Bearer bidon SANS cookie -> None
    /// (fail-closed, aucune élévation). Assert check_operator=true sur le cas régressif (b).
    #[test]
    fn valid_cookie_authenticates_despite_stale_bearer() {
        // Construit un HeaderMap avec un cookie forge_session=<tok> (+ éventuellement un Bearer).
        fn cookie_headers(tok: &str) -> HeaderMap {
            let mut h = HeaderMap::new();
            h.insert("cookie", format!("forge_session={tok}").parse().unwrap());
            h
        }
        fn cookie_and_bearer(cookie_tok: &str, bearer_tok: &str) -> HeaderMap {
            let mut h = HeaderMap::new();
            h.insert("cookie", format!("forge_session={cookie_tok}").parse().unwrap());
            h.insert("authorization", format!("Bearer {bearer_tok}").parse().unwrap());
            h
        }

        let path = tmp_path("forge-test-cookie-vs-bearer");
        let app = test_app(&path);
        { let db = app.db(); upsert_user(&db, "adm", "admin", &hash_pw("pw")).unwrap(); }
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='adm'", [], |r| r.get(0)).unwrap() };
        let (atok, _) = create_session(&app, uid);
        let bogus = "stale-bogus-token-from-old-build";

        // (a) cookie SEUL -> identité admin résolue, opérateur autorisé.
        let id = resolve_session_identity(&app, &cookie_headers(&atok)).expect("cookie seul -> session résolue");
        assert_eq!(id.login, "adm");
        assert_eq!(id.role, "admin");
        assert!(check_operator(&app, &cookie_headers(&atok), None), "cookie admin seul -> C2 autorisé");

        // (b) RÉGRESSION : cookie VALIDE + Bearer PÉRIMÉ -> le Bearer ne masque plus le cookie.
        let hdrs = cookie_and_bearer(&atok, bogus);
        let id_b = resolve_session_identity(&app, &hdrs).expect("cookie valide doit gagner malgré Bearer périmé");
        assert_eq!(id_b.login, "adm", "authentifie comme le user DU COOKIE (pas d'élévation)");
        assert_eq!(id_b.role, "admin");
        assert!(check_operator(&app, &hdrs, None), "[C14] cookie admin + Bearer périmé -> C2 autorisé (était 401)");

        // (M3) TENANCY converge avec l'AUTH : `caller_user_id` (chemin tenancy) résout le MÊME user que
        // l'auth malgré le Bearer périmé — plus de single-candidat Bearer-first qui rendait l'utilisateur
        // grantless en mode entreprise. Cookie valide + Bearer bidon -> uid du COOKIE (pas None).
        assert_eq!(
            tenancy::caller_user_id(&app, &hdrs),
            Some(uid),
            "[M3] tenancy résout l'user DU COOKIE malgré le Bearer périmé (auth/tenancy ne divergent plus)"
        );
        assert_eq!(tenancy::caller_user_id(&app, &cookie_headers(&atok)), Some(uid), "[M3] cookie seul -> uid résolu");
        assert_eq!(id_b.user_id, uid, "[M3] resolve_session_identity expose le user_id réel de la session");

        // (c) Bearer VALIDE seul -> résolu (priorité Bearer, chemin inchangé).
        let id_c = resolve_session_identity(&app, &bearer_headers(&atok)).expect("Bearer valide seul -> résolu");
        assert_eq!(id_c.login, "adm");

        // (d) Bearer BIDON seul (aucun cookie) -> None (fail-closed, aucune élévation).
        assert!(resolve_session_identity(&app, &bearer_headers(bogus)).is_none(), "Bearer bidon sans cookie -> None");
        assert!(!check_operator(&app, &bearer_headers(bogus), None), "Bearer bidon seul -> C2 refusé");
        assert_eq!(tenancy::caller_user_id(&app, &bearer_headers(bogus)), None, "[M3] Bearer bidon seul -> aucun user (fail-closed)");
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 RÉTRO-COMPAT] attribution_login : sans aucune identité (dev-open, ni session ni hash env),
    /// retombe sur le littéral historique 'operator' (comportement existant préservé).
    #[test]
    fn attribution_defaults_to_operator_when_no_identity() {
        let path = tmp_path("forge-test-attr-default");
        let app = test_app(&path); // operator_hash vide
        assert_eq!(attribution_login(&app, &HeaderMap::new()), "operator");
        let _ = std::fs::remove_file(&path);
    }

    /// [SEC gate DB-state] auth_guard s'engage sur l'ÉTAT DB, pas seulement sur le hash env. Fresh
    /// install : hash env VIDE (pass_hash="") mais un compte ACTIVÉ présent -> gate engagée -> une
    /// requête sans preuve est REFUSÉE (le middleware répond alors 401, le SPA montre le login).
    /// Une session valide de ce compte passe. Ferme le trou dev-open « comptes en base, env vide ».
    #[test]
    fn auth_gate_engages_on_enabled_user_without_env_hash() {
        let path = tmp_path("forge-test-auth-gate");
        let app = test_app(&path); // pass_hash vide (dev), aucun compte au départ
        // 1) sans hash env ni compte -> dev-open : la gate est désengagée, tout passe.
        app.recompute_auth_required();
        assert!(!app.auth_required(), "sans hash env ni compte activé -> dev-open (gate désengagée)");
        assert!(auth_guard_allows(&app, &HeaderMap::new()), "dev-open : requête anonyme passe");
        // 2) un compte ACTIVÉ est provisionné en base -> après recompute, la gate DOIT s'engager,
        //    MÊME si le hash env reste vide (c'est exactement le trou historique qu'on ferme).
        {
            let db = app.db();
            upsert_user(&db, "erin", "viewer", &hash_pw("pw")).unwrap();
        }
        app.recompute_auth_required();
        assert!(app.auth_required(), "un compte activé engage la gate même sans hash env");
        assert!(!auth_guard_allows(&app, &HeaderMap::new()),
            "gate engagée : requête anonyme REFUSÉE -> le middleware renvoie 401");
        // 3) une session valide de ce compte passe la gate ; un token inconnu ne passe pas.
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='erin'", [], |r| r.get(0)).unwrap() };
        let (tok, _) = create_session(&app, uid);
        assert!(auth_guard_allows(&app, &bearer_headers(&tok)), "session individuelle valide passe la gate");
        assert!(!auth_guard_allows(&app, &bearer_headers("deadbeef")), "session inconnue -> refus (401)");
        // 4) contrapositive de la règle : désactiver l'UNIQUE compte, hash env toujours vide -> plus
        //    aucun compte activé -> la gate se désengage (règle « engage si hash OU compte activé »).
        { let db = app.db(); db.execute("UPDATE users SET disabled=1 WHERE id=?", [uid]).unwrap(); }
        app.recompute_auth_required();
        assert!(!app.auth_required(), "dernier compte activé désactivé + hash env vide -> gate désengagée");
        let _ = std::fs::remove_file(&path);
    }

    /// [SEC gate DB-state] un hash env posé engage la gate à lui seul (rétro-compat) : même sans aucun
    /// compte en base, auth_required=true et une requête anonyme est refusée.
    #[test]
    fn auth_gate_engages_on_env_hash_alone() {
        let path = tmp_path("forge-test-auth-gate-env");
        let mut app = test_app(&path);
        app.pass_hash = Arc::new(hash_pw("viewerpw")); // hash env posé, aucun compte en base
        app.recompute_auth_required();
        assert!(app.auth_required(), "hash env posé -> gate engagée même sans compte");
        assert!(!auth_guard_allows(&app, &HeaderMap::new()), "gate engagée : anonyme refusé (401)");
        // Basic viewer avec le bon mdp passe (rétro-compat viewer par hash env).
        let mut h = HeaderMap::new();
        let b64 = base64::engine::general_purpose::STANDARD.encode("forge:viewerpw");
        h.insert("authorization", format!("Basic {b64}").parse().unwrap());
        assert!(auth_guard_allows(&app, &h), "Basic viewer (hash env) passe la gate");
        let _ = std::fs::remove_file(&path);
    }

    /// [SEC admin] check_admin : FAIL-CLOSED, session ADMIN uniquement. Un viewer et un operator sont
    /// REFUSÉS ; un admin est autorisé. PAS de repli hash env (contrairement à operator) : une preuve
    /// X-Forge-Operator seule ne confère JAMAIS l'admin (attribution individuelle obligatoire).
    #[test]
    fn check_admin_requires_admin_session_no_env_fallback() {
        let path = tmp_path("forge-test-admin");
        let mut app = test_app(&path);
        app.operator_hash = Arc::new(hash_pw("s3cr3t")); // hash env opérateur présent -> ne doit PAS conférer l'admin
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let sid = |login: &str, app: &App| -> i64 {
            let db = app.db();
            db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
        };
        let (vtok, _) = create_session(&app, sid("vv", &app));
        let (otok, _) = create_session(&app, sid("oo", &app));
        let (atok, _) = create_session(&app, sid("aa", &app));
        assert!(!check_admin(&app, &bearer_headers(&vtok)), "viewer refusé (fail-closed)");
        assert!(!check_admin(&app, &bearer_headers(&otok)), "operator refusé (admin != operator)");
        assert!(check_admin(&app, &bearer_headers(&atok)), "admin autorisé");
        assert!(!check_admin(&app, &operator_headers("s3cr3t")), "hash env opérateur NE confère PAS l'admin (pas de repli)");
        assert!(!check_admin(&app, &HeaderMap::new()), "aucune preuve -> refus (fail-closed)");
        let _ = std::fs::remove_file(&path);
    }

    /// [C1] session_cookie : drapeau `Secure` SCHEME-AWARE (posé UNIQUEMENT en HTTPS), jamais par défaut.
    /// `HttpOnly` + `SameSite=Strict` + `Path=/` TOUJOURS. En http clair (is_https=false) -> pas de Secure
    /// (sinon le navigateur DROPPE un cookie Secure servi en http -> session jamais persistée = LE bug
    /// corrigé). En https (is_https=true) -> Secure posé. HttpOnly/SameSite jamais affaiblis.
    #[test]
    fn session_cookie_secure_is_scheme_aware() {
        let c_http = session_cookie("tok", 3600, false);
        assert!(c_http.contains("HttpOnly") && c_http.contains("SameSite=Strict") && c_http.contains("Path=/"),
            "attributs durcis toujours posés: {c_http}");
        assert!(!c_http.contains("Secure"), "http clair -> pas de Secure (sinon cookie droppé): {c_http}");
        let c_https = session_cookie("tok", 3600, true);
        assert!(c_https.contains("; Secure"), "https -> Secure posé: {c_https}");
        assert!(c_https.contains("HttpOnly") && c_https.contains("SameSite=Strict"),
            "https garde HttpOnly+SameSite: {c_https}");
    }

    /// [C1] request_is_https : true SEULEMENT si `X-Forwarded-Proto: https` (1er hop du proxy TLS) OU
    /// l'override `FORGE_FORCE_SECURE_COOKIE`. Sans en-tête (http direct loopback) OU XFP=http -> false.
    /// XFP n'est utilisé QUE pour le flag Secure, jamais pour l'auth (cf. doc). (L'override env n'est pas
    /// testé ici pour éviter la mutation d'env process-globale sous exécution parallèle.)
    #[test]
    fn request_is_https_detects_forwarded_proto() {
        assert!(!request_is_https(&HeaderMap::new()), "pas d'en-tête -> http direct -> false");
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(request_is_https(&h), "XFP=https -> true (reverse-proxy TLS)");
        let mut hc = HeaderMap::new();
        hc.insert("x-forwarded-proto", "https, http".parse().unwrap());
        assert!(request_is_https(&hc), "XFP chaîné 'https, http' -> 1er hop https -> true");
        let mut hh = HeaderMap::new();
        hh.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!request_is_https(&hh), "XFP=http -> false");
    }


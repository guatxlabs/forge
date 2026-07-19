// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — tests d'intégration : panic-responder, security-headers, store-gate, engine/console boot, standalone boot + health.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

    /// FILET ANTI-PANIC (C15) — le responder `catch_panic_response` renvoie un 500 STABLE et
    /// NON-FUYANT : status 500, `content-type: application/json`, corps générique figé, et AUCUNE
    /// fuite du message de panique (le `Box<dyn Any>` passé n'apparaît jamais dans le corps).
    #[tokio::test]
    async fn catch_panic_response_is_stable_and_non_leaking() {
        // On passe une charge de panique DISTINCTIVE : elle ne DOIT jamais transparaître dans le corps.
        let resp = catch_panic_response(Box::new("SECRET_PANIC_PAYLOAD_xyz".to_string()));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR, "500");
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_TYPE).map(|v| v.to_str().unwrap()),
            Some("application/json"),
            "content-type application/json"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let txt = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(txt, r#"{"error":"internal","why":"une erreur interne est survenue"}"#, "corps stable");
        assert!(!txt.contains("SECRET_PANIC_PAYLOAD_xyz"), "le message de panique ne fuit JAMAIS");
    }

    /// FILET ANTI-PANIC (C15) — END-TO-END : une route qui PANIQUE, enveloppée par LE MÊME
    /// `CatchPanicLayer::custom(catch_panic_response)` que `build_router`, renvoie une réponse HTTP
    /// `500` JSON PROPRE au client — PAS une connexion resetée (« Failed to fetch »). On sert la couche
    /// sur un port éphémère et on frappe avec un client TCP brut (std, zéro nouvelle dépendance) : la
    /// preuve est que le client REÇOIT une réponse complète (jamais un RST/EOF prématuré).
    #[tokio::test]
    async fn catch_panic_layer_converts_handler_panic_into_clean_500() {
        use std::io::{Read, Write};
        // Return type explicite (`Response`) : évite le never-type fallback du `panic!` divergent.
        async fn boom() -> Response {
            panic!("boom-should-be-caught-not-leaked")
        }
        let router = Router::new()
            .route("/boom", get(boom))
            .layer(tower_http::catch_panic::CatchPanicLayer::custom(catch_panic_response));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });
        let raw = tokio::task::spawn_blocking(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /boom HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
            let mut buf = String::new();
            s.read_to_string(&mut buf).unwrap(); // Connection: close -> lit jusqu'à EOF (réponse complète)
            buf
        })
        .await
        .unwrap();
        server.abort();
        assert!(raw.starts_with("HTTP/1.1 500"), "panique -> 500 propre (jamais un drop), got: {raw}");
        assert!(
            raw.to_ascii_lowercase().contains("content-type: application/json"),
            "corps JSON, got: {raw}"
        );
        assert!(
            raw.contains(r#"{"error":"internal","why":"une erreur interne est survenue"}"#),
            "corps stable, got: {raw}"
        );
        assert!(!raw.contains("boom-should-be-caught-not-leaked"), "message de panique jamais exposé, got: {raw}");
    }

    /// EN-TÊTES DE SÉCURITÉ (F1) — END-TO-END sur le VRAI `build_router` : on sert le routeur complet sur
    /// un port éphémère et on frappe avec un client TCP brut (std, zéro nouvelle dépendance). On vérifie
    /// que TOUTES les réponses (shell `/` public + une route `/api/*`) portent X-Frame-Options/nosniff/
    /// Referrer-Policy/CSP, et que HSTS est ABSENT en http clair mais PRÉSENT quand
    /// `X-Forwarded-Proto: https` est présenté (scheme-aware, même gate que le drapeau Secure du cookie).
    #[tokio::test]
    async fn security_headers_present_on_all_responses_and_hsts_is_scheme_aware() {
        use std::io::{Read, Write};
        // Un install non provisionné (auth_required=false via test_app) : `/` et `/api/whoami` répondent
        // sans credentials — ce qui nous suffit pour observer les EN-TÊTES (posés AVANT tout gating).
        let path = tmp_path("sechdr-ledger");
        let app = test_app(&path);
        let router = build_router(app, "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });
        // Helper : envoie une requête brute, lit la réponse complète (Connection: close -> EOF).
        fn hit(addr: std::net::SocketAddr, req: &str) -> String {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(req.as_bytes()).unwrap();
            let mut buf = String::new();
            s.read_to_string(&mut buf).unwrap();
            buf
        }
        let req_root = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_string();
        let req_api = "GET /api/whoami HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_string();
        let req_https = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n".to_string();
        let (root, api, https) = tokio::task::spawn_blocking(move || {
            (hit(addr, &req_root), hit(addr, &req_api), hit(addr, &req_https))
        })
        .await
        .unwrap();
        server.abort();

        // Les 4 en-têtes non-HSTS présents sur le shell ET sur l'API (comparaison insensible à la casse).
        for (label, raw) in [("/", &root), ("/api/whoami", &api)] {
            let lc = raw.to_ascii_lowercase();
            assert!(lc.contains("x-frame-options: deny"), "{label}: X-Frame-Options manquant\n{raw}");
            assert!(lc.contains("x-content-type-options: nosniff"), "{label}: nosniff manquant\n{raw}");
            assert!(lc.contains("referrer-policy: no-referrer"), "{label}: Referrer-Policy manquant\n{raw}");
            assert!(lc.contains("content-security-policy:"), "{label}: CSP manquante\n{raw}");
            assert!(lc.contains("frame-ancestors 'none'"), "{label}: frame-ancestors 'none' manquant\n{raw}");
        }
        // HSTS scheme-aware : ABSENT en http clair, PRÉSENT derrière X-Forwarded-Proto: https.
        assert!(
            !root.to_ascii_lowercase().contains("strict-transport-security"),
            "HSTS ne doit PAS être posé en http loopback clair\n{root}"
        );
        assert!(
            https.to_ascii_lowercase().contains("strict-transport-security: max-age=63072000; includesubdomains"),
            "HSTS DOIT être posé quand X-Forwarded-Proto: https\n{https}"
        );
    }

    /// GATE CONTRACT (Stage 2b batch 5) : la sélection du backend enterprise est FAIL-CLOSED.
    ///   - Toute valeur non-postgres (`None`/`"sqlite"`/`""`) -> `Sqlite`, dans LES DEUX builds.
    ///   - `postgres` SANS la feature -> refus clair « rebuild with --features store-postgres ».
    ///   - `postgres` AVEC la feature -> `Postgres(url)` SSI FORGE_DB_URL non vide ; sinon refus
    ///     nommant FORGE_DB_URL. (Bloc feature-gated ci-dessous.)
    #[test]
    fn enterprise_store_gate_contract() {
        // Non-postgres selections always boot on SQLite, in both builds.
        assert!(matches!(enterprise_store_gate(None, None), Ok(StoreSelection::Sqlite)),
                "default (unset) starts on SQLite");
        assert!(matches!(enterprise_store_gate(Some("sqlite"), None), Ok(StoreSelection::Sqlite)),
                "explicit sqlite starts on SQLite");
        assert!(matches!(enterprise_store_gate(Some(""), None), Ok(StoreSelection::Sqlite)),
                "empty value starts on SQLite");
        // A stray FORGE_DB_URL is IGNORED unless postgres is explicitly requested.
        assert!(matches!(enterprise_store_gate(None, Some("postgres://x")), Ok(StoreSelection::Sqlite)),
                "db_url alone does not select postgres");

        #[cfg(not(feature = "store-postgres"))]
        {
            // Without the feature compiled, postgres is refused with a rebuild message, whatever the url.
            let e = enterprise_store_gate(Some("postgres"), None)
                .expect_err("postgres refused without the feature");
            assert!(e.contains("store-postgres"), "names the feature to rebuild with: {e}");
            let e2 = enterprise_store_gate(Some("postgres"), Some("postgres://x"))
                .expect_err("still refused even with a url");
            assert!(e2.contains("store-postgres"), "names the feature: {e2}");
        }
        #[cfg(feature = "store-postgres")]
        {
            // With the feature, postgres is ACCEPTED iff FORGE_DB_URL is a non-empty DSN.
            match enterprise_store_gate(Some("postgres"), Some("postgres://u@h/db")) {
                Ok(StoreSelection::Postgres(u)) => assert_eq!(u, "postgres://u@h/db", "carries the DSN"),
                other => panic!("expected Postgres selection, got {other:?}"),
            }
            let e = enterprise_store_gate(Some("postgres"), None)
                .expect_err("postgres refused without FORGE_DB_URL");
            assert!(e.contains("FORGE_DB_URL"), "names the missing var: {e}");
            assert!(enterprise_store_gate(Some("postgres"), Some("")).is_err(),
                    "empty FORGE_DB_URL refused");
        }
    }


    /// B1 (CRITIQUE — anti-fourche) — MODÈLE DE LA COURSE DE PROD : la console (append_console_ledger) et
    /// le moteur Python écrivent le MÊME ledger. On simule un append MOTEUR (ligne écrite DIRECTEMENT sur
    /// disque, chaînée sur la queue) INTERCALÉ entre deux appends console. AVANT le fix, la console
    /// réutilisait son head EN CACHE (prev/seq périmés) -> deux entrées de même seq/prev -> fourche
    /// (« chaînage rompu (prev) », exactement le symptôme observé seq=8 après 23 entrées valides). APRÈS le
    /// fix, chaque append console RELIT la queue disque sous le flock -> l'entrée console chaîne SUR la
    /// queue du moteur (prev = hash moteur, seq = seq_moteur+1) et verify reste OK.
    #[test]
    fn console_engine_ledger_interleave_no_fork() {
        let path = tmp_path("forge-test-ledger-interleave");
        let app = test_app(&path);

        // (1) append CONSOLE #1 (seq 1).
        append_console_ledger(&app, "console.run.start", json!({"run": "r1"}));

        // (2) append MOTEUR interlacé : écrit une ligne DIRECTEMENT (comme forge/ledger.py le ferait sous
        //     SON flock), chaînée sur la queue actuelle. Alg hmac-sha256 (moteur), sig non vérifiée par
        //     verify_ledger_chain (hash-chain uniquement). C'est CE writer concurrent qui périmait le cache.
        let (tail_prev, tail_seq) = {
            let lines = read_ledger_lines(&path);
            let last = lines.last().cloned().unwrap();
            (last["hash"].as_str().unwrap().to_string(), last["seq"].as_i64().unwrap())
        };
        let eng_seq = tail_seq + 1;
        let eng_ts = "2026-07-15T15:20:30+00:00";
        let eng_kind = "roe.decision";
        let eng_detail = json!({"verdict": "DRY_RUN", "target": "example.com"});
        let eng_preimage = format!("{tail_prev}|{eng_seq}|{eng_ts}|{eng_kind}|{}", canon_json(&eng_detail));
        let eng_hash = sha_hex(&eng_preimage);
        let eng_rec = json!({
            "seq": eng_seq, "ts": eng_ts, "kind": eng_kind, "detail": eng_detail,
            "prev": tail_prev, "hash": eng_hash, "alg": "hmac-sha256", "sig": "deadbeef"
        });
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "{}", canon_json(&eng_rec)).unwrap();
        }

        // (3) append CONSOLE #2 : DOIT chaîner sur la queue du MOTEUR (pas sur le cache périmé).
        append_console_ledger(&app, "console.run.end", json!({"run": "r1", "status": "done"}));

        // La chaîne complète (console#1 -> moteur -> console#2) doit être INTÈGRE : aucune fourche.
        let v = verify_ledger_chain(&path);
        assert!(v.ok, "chaîne intègre attendue (pas de fourche) ; broken={:?} why={:?}", v.broken, v.why);
        assert_eq!(v.entries, 3, "3 entrées chaînées (console, moteur, console)");

        // L'entrée console #2 chaîne bien SUR le hash du moteur, seq = seq_moteur+1 (pas une réutilisation).
        let lines = read_ledger_lines(&path);
        let last = lines.last().unwrap();
        assert_eq!(last["prev"].as_str().unwrap(), eng_hash, "console#2.prev == hash moteur");
        assert_eq!(last["seq"].as_i64().unwrap(), eng_seq + 1, "console#2.seq == seq_moteur+1");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.hwm"));
    }

    /// B2 — l'URL d'ingest du moteur spawné est TOUJOURS un loopback (Host accepté par host_guard),
    /// jamais l'host de bind wildcard (`0.0.0.0`) qui provoquait le 421 Misdirected Request.
    #[test]
    fn engine_console_url_is_loopback_host_accepted() {
        // bind wildcard Docker -> loopback (le bug B2).
        assert_eq!(engine_console_url("0.0.0.0:7100"), "http://127.0.0.1:7100");
        assert_eq!(engine_console_url("[::]:7100"), "http://127.0.0.1:7100");
        assert_eq!(engine_console_url("127.0.0.1:9000"), "http://127.0.0.1:9000");
        assert_eq!(engine_console_url("garbage"), "http://127.0.0.1:7100"); // pas de port -> défaut
        // le Host résultant (127.0.0.1) est dans l'allowlist par défaut -> host_guard PASSE (pas de 421).
        let allowed = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
        assert!(host_allowed("127.0.0.1:7100", &allowed), "loopback accepté");
        assert!(!host_allowed("0.0.0.0:7100", &allowed), "wildcard bind refusé (aurait donné 421)");
    }

    /// [STANDALONE] Sans réglage `settings.detection_source` NI env PLUME_URL/PLUME_TOKEN, la source
    /// résolue au boot est `{kind:none}` : la console démarre en AUTONOME, aucune dépendance Plume.
    /// (Défense en profondeur : on RETIRE explicitement l'env legacy pour prouver l'absence de repli.)
    #[test]
    fn standalone_default_detection_source_is_none_without_plume_env() {
        let _g = env_lock();
        std::env::remove_var("PLUME_URL");
        std::env::remove_var("PLUME_TOKEN");
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let v = resolve_detection_source(&conn);
        assert_eq!(ds_kind(&v), "none", "aucune source ni env -> kind none (Forge autonome, pas de Plume requis)");
        assert!(ds_endpoint(&v).is_empty(), "aucun endpoint inventé en autonome");
        assert!(ds_secret(&v).is_empty(), "aucun secret en autonome");
    }

    /// [STANDALONE] fetch_purple_coverage sans source configurée (kind=none) : FAIL-OPEN LISIBLE et
    /// EXPLICITEMENT AUTONOME — `source_reachable:false`, `source_configured:false`, `source_kind:"none"`,
    /// AUCUNE métrique fabriquée (detected/missed vides, taux/MTTD nuls), et `techniques_fired` reste
    /// informatif. C'est un état NORMAL (pas une erreur) : la boucle purple est simplement OFF.
    #[tokio::test]
    async fn fetch_purple_coverage_standalone_invents_nothing() {
        let app = test_app(&tmp_path("standalone-cov-ledger"));
        // cache par défaut = {kind:none} (test_app). On l'affirme pour la lisibilité du test.
        set_detection_source(&app, json!({"kind": "none"}));
        let fired = vec![
            ("T1110".to_string(), Some(1000)),
            ("T1110".to_string(), Some(1100)),
            ("T1046".to_string(), Some(2000)),
            ("".to_string(), None),
        ];
        let cov = fetch_purple_coverage(&app, fired).await;
        assert_eq!(cov["source_reachable"], json!(false), "autonome -> non joignable (fail-open)");
        assert_eq!(cov["plume_reachable"], json!(false), "miroir rétro-compat");
        assert_eq!(cov["source_configured"], json!(false), "AUCUNE source configurée -> standalone");
        assert_eq!(cov["source_kind"], json!("none"));
        assert_eq!(cov["techniques_detected"], json!(0), "rien de détecté fabriqué");
        assert_eq!(cov["techniques_missed"], json!(0), "rien classé raté quand la mesure est impossible");
        assert_eq!(cov["detection_rate"], json!(0.0));
        assert_eq!(cov["mttd_avg_secs"], Value::Null);
        assert_eq!(cov["mttd_max_secs"], Value::Null);
        assert!(cov["detected"].as_array().unwrap().is_empty());
        assert!(cov["missed"].as_array().unwrap().is_empty());
        assert_eq!(cov["techniques_fired"], json!(2), "info offensive conservée (T1110+T1046 distinctes)");
        assert!(cov["error"].as_str().unwrap_or("").contains("non configurée"), "raison lisible");
    }

    /// [STANDALONE] Une source POSÉE mais INJOIGNABLE se distingue de l'autonome : `source_configured:true`
    /// + `source_reachable:false`. Le SPA peut ainsi afficher une ANOMALIE (source injoignable) là, et un
    /// état NEUTRE (autonome) quand aucune source n'est configurée — sans jamais bloquer l'UI.
    #[tokio::test]
    async fn fetch_purple_coverage_configured_but_unreachable_is_distinct() {
        let app = test_app(&tmp_path("unreachable-cov-ledger"));
        // endpoint bidon fermé -> injoignable, mais une source EST bien configurée.
        set_detection_source(&app, json!({
            "kind": "plume", "endpoint": "http://127.0.0.1:1", "auth": {"type": "basic", "secret": "dXNlcjpwYXNz"}
        }));
        let cov = fetch_purple_coverage(&app, vec![("T1110".to_string(), Some(1))]).await;
        assert_eq!(cov["source_reachable"], json!(false), "endpoint fermé -> injoignable");
        assert_eq!(cov["source_configured"], json!(true), "une source EST configurée (pas autonome)");
        assert_eq!(cov["source_kind"], json!("plume"));
        assert!(cov["detected"].as_array().unwrap().is_empty(), "aucune couverture inventée même configurée");
    }

    /// [STANDALONE bout-en-bout] Sur le VRAI routeur (build_router), SANS aucune source de détection :
    /// /health répond 200 et /api/purple/coverage (+ alias /api/detection/coverage) répond 200 en état
    /// AUTONOME (source_reachable:false, source_configured:false) — l'endpoint ne renvoie JAMAIS d'erreur
    /// qui bloquerait l'UI. Prouve que la console BOOTE et sert la vue purple sans Plume.
    #[tokio::test]
    async fn standalone_boot_serves_health_and_coverage_without_plume() {
        let app = test_app(&tmp_path("standalone-boot-ledger")); // détection par défaut = {kind:none}
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // /health : la console est up (aucun PLUME_URL requis pour démarrer).
        let r = http_raw(addr, &get_req("/health", "")).await;
        assert_eq!(parse_status(&r), 200, "/health up en autonome : {r}");
        assert!(body_of(&r).contains("\"status\":\"ok\""));

        // /api/purple/coverage : 200 + état AUTONOME lisible (jamais une 5xx/erreur bloquante).
        let r = http_raw(addr, &get_req("/api/purple/coverage", "")).await;
        assert_eq!(parse_status(&r), 200, "coverage 200 en autonome (pas d'erreur bloquante) : {r}");
        let b = body_of(&r);
        assert!(b.contains("\"source_reachable\":false"), "autonome -> source_reachable:false : {b}");
        assert!(b.contains("\"source_configured\":false"), "autonome -> source_configured:false : {b}");
        assert!(!b.contains("\"techniques_detected\":1"), "aucune détection fabriquée en autonome");

        // alias canonique /api/detection/coverage : même contrat 200 autonome.
        let r2 = http_raw(addr, &get_req("/api/detection/coverage", "")).await;
        assert_eq!(parse_status(&r2), 200, "alias /api/detection/coverage 200 en autonome : {r2}");
    }

    /// [/health SCHEMA VERSION] Après `migrate()` (qui TAMPONNE `settings.schema_version`), le handler
    /// /health SURFACE `schema_version == SCHEMA_VERSION` (en plus de status/version/db). ADDITIF : la
    /// forme historique {status, version, db} est préservée ; on ajoute seulement le champ tamponné.
    #[tokio::test]
    async fn health_surfaces_stamped_schema_version() {
        let app = test_app(&tmp_path("health-schema-version-ledger"));
        { let db = app.db(); migrate(&db); } // tamponne settings.schema_version
        let Json(body) = health(axum::extract::State(app)).await;
        assert_eq!(body["status"], json!("ok"), "forme historique préservée");
        assert_eq!(body["schema_version"], json!(crate::schema::SCHEMA_VERSION), "/health surface la version tamponnée");
    }

    // =============================================================================================
    // LEDGER VERIFY CLI — lecture seule, NON INTERACTIVE, RAPIDE (ne démarre PAS le serveur).
    // Régression : `forge ledger verify` retombait sur le boot serveur et PENDAIT.
    // =============================================================================================



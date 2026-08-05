// SPDX-License-Identifier: AGPL-3.0-or-later
//! `runs` — module de test EXTRAIT (PURE MOVE depuis `console/src/runs.rs`).
//! Corps IDENTIQUE ; ENFANT de `runs`, il voit donc toujours ses items privés.
//! Renommé `idor_tenancy_tests` -> `tests_idor_tenancy` : `tests/test_portability_guard.py` n'exclut
//! que les fichiers `tests.rs` / `tests_*` et scannerait l'autre nom (garde au ROUGE).
use super::*;

    use super::*;
    use crate::testutil::{bearer_headers, resp_json, uid_of};
    use rusqlite::Connection;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::Mutex as AsyncMutex;

    fn test_app() -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        crate::migrate(&conn);
        let (events, _) = broadcast::channel::<crate::RunEvent>(64);
        App {
            db: Arc::new(Mutex::new(conn)),
            #[cfg(feature = "store-postgres")]
            pg: None,
            #[cfg(feature = "store-postgres")]
            ha: false,
            #[cfg(feature = "store-postgres")]
            instance_id: Arc::new("test-instance".into()),
            #[cfg(feature = "store-postgres")]
            is_leader: Arc::new(AtomicBool::new(true)),
            db_path: Arc::new(":memory:".into()),
            token_sha: Arc::new(crate::sha_hex("t")),
            token_raw: Arc::new("t".into()),
            user: Arc::new("forge".into()),
            pass_hash: Arc::new(String::new()),
            auth_required: Arc::new(AtomicBool::new(false)),
            operator_hash: Arc::new(String::new()),
            allowed_hosts: Arc::new(vec!["localhost".into()]),
            ledger_path: Arc::new(String::new()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(RunState { current: HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(crate::LedgerHead::default())),
        }
    }

    /// Engagement `id` appartenant au tenant `tid`, actif. Sème aussi la ligne `tenant` correspondante.
    fn seed_engagement(app: &App, id: i64, tid: i64) {
        let db = app.db();
        db.execute(
            "INSERT INTO tenant(id,name,status,created,updated) VALUES(?,?, 'active',datetime('now'),datetime('now'))
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![tid, format!("tenant-{tid}")],
        )
        .unwrap();
        db.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,tenant_id,created,updated)
             VALUES(?,?, 'active','grey','{\"in_scope\":[\"a.example.com\"]}','',?,datetime('now'),datetime('now'))",
            rusqlite::params![id, format!("eng-{id}"), tid],
        )
        .unwrap();
        drop(db); // relâche le guard DB tôt (clippy::significant_drop_tightening)
    }

    /// run_job `run_id` appartenant à l'engagement `eid`, statut `status`. Sème une ligne de log associée.
    fn seed_run(app: &App, run_id: &str, eid: i64, status: &str) {
        let db = app.db();
        db.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,engagement_id) VALUES(?,?,datetime('now'),?,?)",
            rusqlite::params![run_id, "camp", status, eid],
        )
        .unwrap();
        db.execute(
            "INSERT INTO run_log(run_id,ts,stream,line) VALUES(?,datetime('now'),'stdout','SECRET-B-LOG-LINE')",
            rusqlite::params![run_id],
        )
        .unwrap();
        drop(db); // relâche le guard DB tôt (clippy::significant_drop_tightening)
    }

    /// Crée un compte + session ; accorde `role` sur le tenant `tid`. Renvoie le token de session.
    fn user_with_tenant_grant(app: &App, login: &str, console_role: &str, tid: i64, tenant_role: &str) -> String {
        {
            let db = app.db();
            crate::upsert_user(&db, login, console_role, &crate::hash_pw("pw")).unwrap();
            db.execute(
                "INSERT INTO tenant_grant(user_id,tenant_id,role,created)
                 SELECT id,?,?,datetime('now') FROM users WHERE login=?",
                rusqlite::params![tid, tenant_role, login],
            )
            .unwrap();
        }
        let (tok, _) = create_session(app, uid_of(app, login));
        tok
    }

    fn enable_tenancy(app: &App) {
        let db = app.db();
        crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
    }
    fn disable_tenancy(app: &App) {
        let db = app.db();
        db.execute("DELETE FROM settings WHERE key='enterprise.tenancy'", []).unwrap();
    }

    fn q_fmt(fmt: &str) -> Query<HashMap<String, String>> {
        let mut m = HashMap::new();
        m.insert("format".to_string(), fmt.to_string());
        Query(m)
    }

    /// (a) ENTERPRISE ON — un caller accordé UNIQUEMENT sur A obtient 404 sur detail/report/logs d'un run de B,
    /// et 403 sur cancel de B ; AUCUNE donnée de B (log brut, run_id) ne fuit dans le corps.
    #[tokio::test]
    async fn cross_tenant_run_reads_are_404_and_cancel_is_403() {
        let app = test_app();
        seed_engagement(&app, 1, 1); // engagement A -> tenant 1
        seed_engagement(&app, 2, 2); // engagement B -> tenant 2
        seed_run(&app, "run-B", 2, "running");
        enable_tenancy(&app);
        // alice : operator console + grant tenant_operator sur le tenant 1 UNIQUEMENT (rien sur le tenant 2).
        let atok = user_with_tenant_grant(&app, "alice", "operator", 1, "tenant_operator");
        let h = bearer_headers(&atok);

        // detail -> 404 (indistinguable d'un run inconnu).
        let r = run_detail(State(app.clone()), h.clone(), Path("run-B".into())).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "detail cross-tenant -> 404");
        let body = resp_json(r).await;
        assert_eq!(body["error"], "unknown_run", "aucune existence divulguée");

        // report -> 404, aucune donnée de B.
        let r = run_report(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("md")).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "report cross-tenant -> 404");

        // logs -> 404, la ligne brute SECRET-B-LOG-LINE ne fuit jamais.
        let r = run_logs(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("")).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "logs cross-tenant -> 404");
        let txt = serde_json::to_string(&resp_json(r).await).unwrap();
        assert!(!txt.contains("SECRET-B-LOG-LINE"), "stdout brut de B ne fuit pas");

        // sse -> 404 (garde AVANT ouverture du flux).
        let r = run_sse(State(app.clone()), h.clone(), Path("run-B".into())).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "sse cross-tenant -> 404");

        // cancel (ÉCRITURE) -> 403 (autorisation par-engagement refusée).
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = run_cancel(State(app.clone()), axum::extract::ConnectInfo(peer), h.clone(), Path("run-B".into())).await;
        let resp = r.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "cancel cross-tenant -> 403");
        let body = resp_json(resp).await;
        assert_eq!(body["error"], "engagement_operator_required");
    }

    /// (b) ENTERPRISE ON — le PROPRIÉTAIRE (accordé sur B) passe la garde : 200 en lecture ; cancel non-403.
    #[tokio::test]
    async fn owner_of_run_still_authorized() {
        let app = test_app();
        seed_engagement(&app, 2, 2);
        seed_run(&app, "run-B", 2, "running");
        enable_tenancy(&app);
        let btok = user_with_tenant_grant(&app, "bob", "operator", 2, "tenant_operator");
        let h = bearer_headers(&btok);

        let r = run_detail(State(app.clone()), h.clone(), Path("run-B".into())).await;
        assert_eq!(r.status(), StatusCode::OK, "detail par le propriétaire -> 200");

        let r = run_report(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("md")).await;
        assert_eq!(r.status(), StatusCode::OK, "report par le propriétaire -> 200");

        let r = run_logs(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("")).await;
        assert_eq!(r.status(), StatusCode::OK, "logs par le propriétaire -> 200");
        let txt = serde_json::to_string(&resp_json(r).await).unwrap();
        assert!(txt.contains("SECRET-B-LOG-LINE"), "le propriétaire voit bien ses logs");

        // cancel : la garde per-engagement PASSE (non-403). Sans process vivant -> 409 not_running (preuve
        // que l'autorisation a été accordée et que le flux a atteint la logique de cancel).
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = run_cancel(State(app.clone()), axum::extract::ConnectInfo(peer), h.clone(), Path("run-B".into())).await;
        let resp = r.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "cancel autorisé -> pas de run vivant -> 409");
        let body = resp_json(resp).await;
        assert_eq!(body["error"], "not_running", "authz passée : on atteint la logique cancel");
    }

    /// (c) COMMUNITY (flag OFF) — le MÊME caller « étranger » accède à TOUT (aucune régression) : la garde est
    /// un NO-OP byte-identique. detail/report/logs -> 200 ; cancel -> 409 not_running (jamais 403).
    #[tokio::test]
    async fn community_flag_off_no_regression() {
        let app = test_app();
        seed_engagement(&app, 1, 1);
        seed_engagement(&app, 2, 2);
        seed_run(&app, "run-B", 2, "running");
        // tenancy VOLONTAIREMENT non activée (community). alice n'a AUCUN grant — sans effet en community.
        let atok = user_with_tenant_grant(&app, "alice", "operator", 1, "tenant_operator");
        disable_tenancy(&app); // s'assure que le flag est OFF
        let h = bearer_headers(&atok);

        let r = run_detail(State(app.clone()), h.clone(), Path("run-B".into())).await;
        assert_eq!(r.status(), StatusCode::OK, "community: detail servi (no-op)");
        let r = run_report(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("md")).await;
        assert_eq!(r.status(), StatusCode::OK, "community: report servi (no-op)");
        let r = run_logs(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("")).await;
        assert_eq!(r.status(), StatusCode::OK, "community: logs servis (no-op)");
        let r = run_sse(State(app.clone()), h.clone(), Path("run-B".into())).await;
        // SSE community : la garde ne court-circuite pas -> flux ouvert (200 OK, content-type event-stream).
        assert_eq!(r.status(), StatusCode::OK, "community: sse ouvert (no-op)");

        // cancel en community : gouverné par check_operator SEUL -> pas de 403 per-engagement -> 409 not_running.
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = run_cancel(State(app.clone()), axum::extract::ConnectInfo(peer), h.clone(), Path("run-B".into())).await;
        let resp = r.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "community: cancel -> 409 not_running (jamais 403)");
    }

    /// L9 — ENTERPRISE ON : un import CIBLANT l'engagement d'un AUTRE tenant est REFUSÉ (résolution tenant-
    /// aware fail-closed, comme run_create) AVANT tout spawn/insertion. Aucun finding n'atterrit dans
    /// l'engagement de B (le défaut historique faisait tomber les findings importés sur l'engagement #1).
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn cross_tenant_import_is_refused() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let app = test_app();
        seed_engagement(&app, 1, 1); // engagement A -> tenant 1
        seed_engagement(&app, 2, 2); // engagement B -> tenant 2
        enable_tenancy(&app);
        // alice : operator console + tenant_operator sur le tenant 1 UNIQUEMENT (rien sur le tenant 2).
        let atok = user_with_tenant_grant(&app, "alice", "operator", 1, "tenant_operator");
        let h = bearer_headers(&atok);

        let body = json!({"engagement_id": 2, "campaign": "camp", "format": "auto", "content": "1.2.3.4"});
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = import_scan(State(app.clone()), axum::extract::ConnectInfo(peer), h.clone(), Json(body)).await;
        let resp = r.into_response();
        // REFUS : la résolution tenant-aware rejette l'engagement cross-tenant AVANT le spawn (400 bad_engagement).
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "import cross-tenant -> refusé (jamais 200)");
        let jb = resp_json(resp).await;
        assert_eq!(jb["error"], "bad_engagement", "refus au stade résolution d'engagement (fail-closed)");

        // AUCUN finding n'a été inséré dans l'engagement de B (ni ailleurs) — l'import n'a rien muté.
        let n_b: i64 = { let s = app.store(); s.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=2", &[], |r| r.get_i64(0)).unwrap_or(-1) };
        assert_eq!(n_b, 0, "aucun finding importé dans l'engagement de B");
    }

    /// L8 — DELETE-THEN-ATTEST : si la cascade de suppression ÉCHOUE (rollback), AUCUNE attestation n'est
    /// écrite dans le ledger DÉDIÉ (le défaut précédent appendait `console.engagement.delete` AVANT la
    /// transaction, attestant un delete qui n'a jamais eu lieu). On force l'échec en supprimant `run_job`
    /// (une des cibles du DELETE) : la tx part en erreur -> 500 -> le ledger reste vierge et la ligne survit.
    #[tokio::test]
    async fn delete_rollback_writes_no_attestation() {
        let app = test_app();
        // Ledger DÉDIÉ sur disque (fichier temp), pré-ensemencé d'une ligne quelconque (il EXISTE déjà).
        let led = std::env::temp_dir().join(format!("forge-l8-ledger-{}.jsonl", std::process::id()));
        let led_s = led.to_string_lossy().to_string();
        std::fs::write(&led, b"{\"kind\":\"engagement.start\"}\n").unwrap();
        // Engagement #2 ARCHIVÉ (esquive la garde « dernier actif ») avec SON ledger dédié.
        {
            let db = app.db();
            db.execute(
                "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
                 VALUES(2,'eng-2','archived','grey','{\"in_scope\":[\"a.example.com\"]}',?,datetime('now'),datetime('now'))",
                rusqlite::params![led_s],
            ).unwrap();
            // Supprime la table `run_job` : la cascade `DELETE FROM run_job` échouera -> with_tx ROLLBACK.
            db.execute("DROP TABLE run_job", []).unwrap();
        }

        let res = engagement_do_delete(&app, 2, "tester");
        // La suppression a ÉCHOUÉ (rollback) -> 500.
        assert!(res.is_err(), "la cascade doit échouer (run_job absente)");
        assert_eq!(res.err().unwrap().0, StatusCode::INTERNAL_SERVER_ERROR, "-> 500 sur échec cascade");

        // Le ledger dédié NE contient PAS d'attestation de delete (delete-then-attest : jamais atteint).
        let content = std::fs::read_to_string(&led).unwrap();
        assert!(!content.contains("console.engagement.delete"),
            "aucune attestation de delete ne doit être écrite quand la cascade rollback");

        // La ligne engagement #2 a SURVÉCU (rollback) — l'état est cohérent.
        let still: i64 = { let s = app.store(); s.query_row("SELECT COUNT(*) FROM engagement WHERE id=2", &[], |r| r.get_i64(0)).unwrap_or(-1) };
        assert_eq!(still, 1, "l'engagement doit survivre au rollback");
        let _ = std::fs::remove_file(&led);
    }

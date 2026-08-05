// SPDX-License-Identifier: AGPL-3.0-or-later
//! `scim` — module de test EXTRAIT (PURE MOVE depuis `console/src/scim.rs`).
//! Corps IDENTIQUE ; ENFANT de `scim`, il voit donc toujours ses items privés.
use super::*;

    use super::*;
    use crate::testutil::tmp_path;
    use crate::App;
    use rusqlite::Connection;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    // ---- minimal HTTP helpers (self-contained; mirror sso.rs's test harness) ----
    async fn http_raw(addr: SocketAddr, req: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        s.write_all(req.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.expect("read");
        String::from_utf8_lossy(&buf).into_owned()
    }
    fn get_req(path: &str, extra: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\r\n")
    }
    fn body_req(method: &str, path: &str, body: &str, extra: &str) -> String {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/scim+json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
    }
    fn parse_status(resp: &str) -> u16 {
        resp.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).unwrap_or(0)
    }
    fn body_of(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }
    fn json_of(resp: &str) -> Value {
        serde_json::from_str(body_of(resp)).unwrap_or(json!({}))
    }
    fn bearer_hdr(tok: &str) -> String {
        format!("Authorization: Bearer {tok}\r\n")
    }

    /// App backed by an in-memory DB (mirrors sso::tests::sso_test_app).
    fn scim_test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
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
            ledger_path: Arc::new(ledger_path.to_string()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(crate::RunState { current: HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(crate::LedgerHead::default())),
        }
    }

    /// Engage the enterprise SCIM flag on THIS db (per-DB, isolated — no env mutation).
    fn engage_flag(app: &App) {
        let db = app.db();
        crate::settings_set(&db, "enterprise.scim", "on").unwrap();
    }

    /// Set a SCIM bearer token directly (store its SHA). Returns the raw token.
    fn set_token(app: &App, raw: &str) {
        let db = app.db();
        crate::settings_set(&db, TOKEN_KEY, &crate::sha_hex(raw)).unwrap();
    }

    /// Provision a local admin + open an admin session; returns the session token.
    fn admin_session(app: &App) -> String {
        let hash = crate::hash_pw("adminpw");
        let db = app.db();
        crate::upsert_user(&db, "root", "admin", &hash).unwrap();
        let id: i64 = db.query_row("SELECT id FROM users WHERE login=?", ["root"], |r| r.get(0)).unwrap();
        drop(db);
        app.recompute_auth_required();
        crate::create_session(app, id).0
    }

    async fn serve(app: App) -> SocketAddr {
        let router = crate::build_router(app, "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;
        addr
    }

    fn scim_user_body(user_name: &str, active: bool, external_id: &str) -> String {
        json!({
            "schemas": [SCHEMA_USER],
            "userName": user_name,
            "externalId": external_id,
            "active": active,
            "name": { "givenName": "Alice", "familyName": "Example" },
            "emails": [{ "value": user_name, "primary": true }],
        })
        .to_string()
    }

    // ------------------------------------------------------------------------------------------------
    // 1) HAPPY PATH — POST /scim/v2/Users with a valid token creates a Forge user; it is ledgered.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn valid_token_creates_forge_user_and_ledgers() {
        let ledger = tmp_path("scim-create-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "scim-secret-token-value");
        let addr = serve(app.clone()).await;

        let body = scim_user_body("Alice@Corp.com", true, "okta-0001");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("scim-secret-token-value"))).await;
        assert_eq!(parse_status(&r), 201, "valid SCIM create should 201: {r}");
        let v = json_of(&r);
        assert_eq!(v["userName"], "alice.corp.com", "userName→login mapping: {v}");
        assert_eq!(v["active"], true, "created active: {v}");
        assert_eq!(v["externalId"], "okta-0001");
        // Content type is SCIM.
        assert!(r.to_ascii_lowercase().contains("application/scim+json"), "scim content type: {r}");

        // Forge user really exists, ENABLED, with the SCOPED default role (viewer — never admin).
        {
            
            let (role, disabled): (String, i64) = app.db()
                .query_row("SELECT role, disabled FROM users WHERE login=?", ["alice.corp.com"], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("forge user created");
            assert_eq!(role, "viewer", "scoped default role, never admin");
            assert_eq!(disabled, 0, "created enabled");
        }

        // Ledgered console.scim.user.create — token NEVER present.
        let lines = crate::read_ledger_lines(&ledger);
        let last = lines.last().expect("ledger entry");
        assert_eq!(last["kind"], "console.scim.user.create");
        assert_eq!(last["detail"]["login"], "alice.corp.com");
        assert_eq!(last["detail"]["active"], true);
        let ser = serde_json::to_string(&lines).unwrap();
        assert!(!ser.contains("scim-secret-token-value"), "SCIM token must never be ledgered");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 2) FAIL-CLOSED — no token / wrong token ⇒ 401 (no user created).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn missing_or_wrong_token_is_401() {
        let ledger = tmp_path("scim-401-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "the-real-token");
        let addr = serve(app.clone()).await;
        let body = scim_user_body("bob@corp.com", true, "ext-2");

        // No Authorization header.
        let r0 = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, "")).await;
        assert_eq!(parse_status(&r0), 401, "missing token → 401: {r0}");
        // Wrong token.
        let r1 = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("not-the-token"))).await;
        assert_eq!(parse_status(&r1), 401, "wrong token → 401: {r1}");
        // A GET is equally fail-closed.
        let r2 = http_raw(addr, &get_req("/scim/v2/Users", &bearer_hdr("nope"))).await;
        assert_eq!(parse_status(&r2), 401, "wrong token on GET → 401: {r2}");

        // No user was created by any of the rejected requests.
        {
            
            let n: i64 = app.db().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "no user created under failed auth");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 3) FAIL-CLOSED (unconfigured) — flag ON but NO token set ⇒ 401 even with an Authorization header.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn no_token_configured_is_401() {
        let ledger = tmp_path("scim-noconf-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app); // flag ON but token NOT provisioned
        let addr = serve(app).await;
        let r = http_raw(addr, &get_req("/scim/v2/Users", &bearer_hdr("anything"))).await;
        assert_eq!(parse_status(&r), 401, "no token configured → 401: {r}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 4) DE-PROVISION — active=false (PATCH) disables the user AND purges its sessions (immediate).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn deactivate_disables_and_purges_sessions() {
        let ledger = tmp_path("scim-deact-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-deact");
        let addr = serve(app.clone()).await;

        // Create the user via SCIM.
        let body = scim_user_body("carol@corp.com", true, "ext-carol");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("tok-deact"))).await;
        assert_eq!(parse_status(&r), 201, "create: {r}");
        let uid: i64 = json_of(&r)["id"].as_str().unwrap().parse().unwrap();

        // Open a live session for that user, and prove it resolves.
        let sess = crate::create_session(&app, uid).0;
        let w = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={sess}\r\n"))).await;
        assert!(body_of(&w).contains("\"login\":\"carol.corp.com\""), "session live pre-deactivation: {}", body_of(&w));

        // SCIM PATCH active=false (Azure-style string value to exercise coercion).
        let patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "replace", "path": "active", "value": "False" }]
        })
        .to_string();
        let p = http_raw(addr, &body_req("PATCH", &format!("/scim/v2/Users/{uid}"), &patch, &bearer_hdr("tok-deact"))).await;
        assert_eq!(parse_status(&p), 200, "patch deactivate: {p}");
        assert_eq!(json_of(&p)["active"], false, "resource now inactive: {}", body_of(&p));

        // User disabled + session purged (immediate revocation).
        {
            let db = app.db();
            let disabled: i64 = db.query_row("SELECT disabled FROM users WHERE id=?", [uid], |r| r.get(0)).unwrap();
            assert_eq!(disabled, 1, "user disabled");
            let sessions: i64 = db.query_row("SELECT COUNT(*) FROM session WHERE user_id=?", [uid], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(sessions, 0, "sessions purged");
        }
        // And the (now-purged) session no longer authenticates.
        let w2 = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={sess}\r\n"))).await;
        assert!(body_of(&w2).contains("\"authenticated\":false"), "purged session dead: {}", body_of(&w2));

        // Ledgered as an update with sessions_purged=true.
        let lines = crate::read_ledger_lines(&ledger);
        let last = lines.last().expect("ledger");
        assert_eq!(last["kind"], "console.scim.user.update");
        assert_eq!(last["detail"]["sessions_purged"], true);
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 4b) DELETE de-provisions: disables + purges + no longer SCIM-managed (subsequent GET 404).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn delete_deprovisions_user() {
        let ledger = tmp_path("scim-del-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-del");
        let addr = serve(app.clone()).await;
        let body = scim_user_body("dave@corp.com", true, "ext-dave");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("tok-del"))).await;
        let uid: i64 = json_of(&r)["id"].as_str().unwrap().parse().unwrap();
        let sess = crate::create_session(&app, uid).0;

        let d = http_raw(addr, &body_req("DELETE", &format!("/scim/v2/Users/{uid}"), "", &bearer_hdr("tok-del"))).await;
        assert_eq!(parse_status(&d), 204, "delete → 204: {d}");
        {
            let db = app.db();
            let disabled: i64 = db.query_row("SELECT disabled FROM users WHERE id=?", [uid], |r| r.get(0)).unwrap();
            assert_eq!(disabled, 1, "user disabled after delete");
            let sessions: i64 = db.query_row("SELECT COUNT(*) FROM session WHERE user_id=?", [uid], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(sessions, 0, "sessions purged after delete");
        }
        let _ = sess;
        // No longer SCIM-managed → GET now 404.
        let g = http_raw(addr, &get_req(&format!("/scim/v2/Users/{uid}"), &bearer_hdr("tok-del"))).await;
        assert_eq!(parse_status(&g), 404, "deprovisioned user GET → 404: {g}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 5) TOKEN HASHED / REDACTED — rotate returns the token ONCE; DB stores only the hash; GET redacts.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn token_is_hashed_and_redacted() {
        let ledger = tmp_path("scim-tok-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        let admin_tok = admin_session(&app);
        let addr = serve(app.clone()).await;
        let auth = bearer_hdr(&admin_tok);

        // Rotate a token via the admin config route.
        let rot = http_raw(addr, &body_req("POST", "/api/scim/config", "{\"rotate\":true}", &auth)).await;
        assert_eq!(parse_status(&rot), 200, "rotate: {rot}");
        let raw = json_of(&rot)["token"].as_str().expect("raw token returned once").to_string();
        assert!(raw.len() >= 32, "token looks random: {raw}");

        // DB stores the SHA, never the raw token.
        {
            
            let stored = crate::settings_get(&app.db(), TOKEN_KEY).unwrap();
            assert_eq!(stored, crate::sha_hex(&raw), "DB stores SHA of the token");
            assert_ne!(stored, raw, "DB does not store the raw token");
        }
        // GET config never returns the token, only presence.
        let g = http_raw(addr, &get_req("/api/scim/config", &auth)).await;
        assert_eq!(parse_status(&g), 200, "config get: {g}");
        assert!(!body_of(&g).contains(&raw), "GET must not echo the token: {}", body_of(&g));
        assert_eq!(json_of(&g)["token_set"], true, "presence flagged");

        // Ledger never carries the token.
        let lines = crate::read_ledger_lines(&ledger);
        assert!(!serde_json::to_string(&lines).unwrap().contains(&raw), "token never ledgered");

        // And the rotated token actually authenticates a SCIM call.
        let body = scim_user_body("erin@corp.com", true, "ext-erin");
        let c = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr(&raw))).await;
        assert_eq!(parse_status(&c), 201, "rotated token authenticates: {c}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 6) FLAG OFF — every /scim/* and /api/scim/config route is disabled (404), even with a valid token.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn flag_off_disables_scim() {
        let ledger = tmp_path("scim-off-ledger");
        let app = scim_test_app(&ledger);
        // NOTE: flag NOT engaged. Even set a token in the DB to prove the flag — not the token — gates.
        set_token(&app, "valid-but-flag-off");
        // Provision a local admin so /api/login stays exercised as byte-identical community behaviour.
        {
            let hash = crate::hash_pw("localpw");
            let db = app.db();
            crate::upsert_user(&db, "root", "admin", &hash).unwrap();
        }
        app.recompute_auth_required();
        let addr = serve(app).await;

        for (method, path) in [
            ("GET", "/scim/v2/Users"),
            ("GET", "/scim/v2/Users/1"),
            ("GET", "/scim/v2/Groups"),
            ("GET", "/scim/v2/ServiceProviderConfig"),
            ("GET", "/api/scim/config"),
        ] {
            let req = if method == "GET" {
                get_req(path, &bearer_hdr("valid-but-flag-off"))
            } else {
                body_req(method, path, "{}", &bearer_hdr("valid-but-flag-off"))
            };
            let r = http_raw(addr, &req).await;
            assert_eq!(parse_status(&r), 404, "flag off → {method} {path} disabled (404): {r}");
        }
        // POST create is also absent.
        let c = http_raw(
            addr,
            &body_req("POST", "/scim/v2/Users", &scim_user_body("x@y.com", true, "e"), &bearer_hdr("valid-but-flag-off")),
        )
        .await;
        assert_eq!(parse_status(&c), 404, "flag off → POST /scim/v2/Users disabled: {c}");

        // LOCAL login is unchanged.
        let lr = http_raw(addr, &format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            "{\"login\":\"root\",\"password\":\"localpw\"}".len(),
            "{\"login\":\"root\",\"password\":\"localpw\"}"
        )).await;
        assert_eq!(parse_status(&lr), 200, "local login still works: {lr}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 7) GET filter + PUT reactivation round-trip.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn filter_and_put_reactivate() {
        let ledger = tmp_path("scim-filter-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-f");
        let addr = serve(app.clone()).await;
        let body = scim_user_body("frank@corp.com", true, "ext-frank");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("tok-f"))).await;
        let uid: i64 = json_of(&r)["id"].as_str().unwrap().parse().unwrap();

        // Filter by userName (login) → exactly one result.
        let f = http_raw(
            addr,
            &get_req("/scim/v2/Users?filter=userName%20eq%20%22frank.corp.com%22", &bearer_hdr("tok-f")),
        )
        .await;
        assert_eq!(parse_status(&f), 200, "filter list: {f}");
        assert_eq!(json_of(&f)["totalResults"], 1, "one match: {}", body_of(&f));

        // Filter miss → zero.
        let f0 = http_raw(addr, &get_req("/scim/v2/Users?filter=userName%20eq%20%22nobody%22", &bearer_hdr("tok-f"))).await;
        assert_eq!(json_of(&f0)["totalResults"], 0, "no match: {}", body_of(&f0));

        // PUT active=false then active=true reactivates.
        let put_off = json!({ "schemas": [SCHEMA_USER], "userName": "frank@corp.com", "active": false }).to_string();
        let _ = http_raw(addr, &body_req("PUT", &format!("/scim/v2/Users/{uid}"), &put_off, &bearer_hdr("tok-f"))).await;
        let put_on = json!({ "schemas": [SCHEMA_USER], "userName": "frank@corp.com", "active": true }).to_string();
        let on = http_raw(addr, &body_req("PUT", &format!("/scim/v2/Users/{uid}"), &put_on, &bearer_hdr("tok-f"))).await;
        assert_eq!(json_of(&on)["active"], true, "reactivated: {}", body_of(&on));
        {
            
            let disabled: i64 = app.db().query_row("SELECT disabled FROM users WHERE id=?", [uid], |r| r.get(0)).unwrap();
            assert_eq!(disabled, 0, "user re-enabled");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 8) SUPER-ADMIN PROTECTION — SCIM cannot create a designated super-admin login.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn scim_cannot_provision_superadmin() {
        let ledger = tmp_path("scim-sa-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-sa");
        {
            let db = app.db();
            // Designate 'root.corp.com' as a super-admin (provisioning-only key).
            crate::settings_set(&db, "enterprise.superadmin", "root.corp.com").unwrap();
        }
        let addr = serve(app.clone()).await;
        let body = scim_user_body("root@corp.com", true, "ext-root");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("tok-sa"))).await;
        assert_eq!(parse_status(&r), 403, "SCIM cannot provision a super-admin login: {r}");
        {
            
            let n: i64 = app.db().query_row("SELECT COUNT(*) FROM users WHERE login=?", ["root.corp.com"], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "no super-admin account created via SCIM");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 9) SCIM F7 — a group's members list NEVER discloses a local (non-SCIM) account, and a non-SCIM
    //    user is never added to a SCIM group (membership is SCIM-scoped).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn group_members_does_not_disclose_local_account() {
        let ledger = tmp_path("scim-f7-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-f7");
        // A LOCAL (non-SCIM) admin — must never surface through a SCIM group members list.
        let local_uid: i64 = {
            let db = app.db();
            let hash = crate::hash_pw("localpw");
            crate::upsert_user(&db, "localadmin", "admin", &hash).unwrap();
            db.query_row("SELECT id FROM users WHERE login=?", ["localadmin"], |r| r.get(0)).unwrap()
        };
        let addr = serve(app.clone()).await;
        // Provision a genuine SCIM user (gets a scim_user row).
        let cr = http_raw(
            addr,
            &body_req("POST", "/scim/v2/Users", &scim_user_body("scimuser@corp.com", true, "ext-s"), &bearer_hdr("tok-f7")),
        )
        .await;
        assert_eq!(parse_status(&cr), 201, "scim user created: {cr}");
        let scim_uid = json_of(&cr)["id"].as_str().unwrap().to_string();
        // Create a group whose members include BOTH the local admin and the SCIM user.
        let gbody = json!({
            "schemas": [SCHEMA_GROUP],
            "displayName": "Forge Readers",
            "members": [{ "value": local_uid.to_string() }, { "value": scim_uid }],
        })
        .to_string();
        let gr = http_raw(addr, &body_req("POST", "/scim/v2/Groups", &gbody, &bearer_hdr("tok-f7"))).await;
        assert_eq!(parse_status(&gr), 201, "group created: {gr}");
        // The local (non-SCIM) admin must NOT appear; the SCIM member does.
        assert!(!body_of(&gr).contains("localadmin"), "local admin login must NOT be disclosed: {}", body_of(&gr));
        assert!(body_of(&gr).contains("scimuser.corp.com"), "SCIM member disclosed: {}", body_of(&gr));
        // The local admin's role is untouched, and it was never inserted into scim_group_member.
        {
            let db = app.db();
            let role: String = db.query_row("SELECT role FROM users WHERE id=?", [local_uid], |r| r.get(0)).unwrap();
            let n: i64 = db.query_row("SELECT COUNT(*) FROM scim_group_member WHERE user_id=?", [local_uid], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(role, "admin", "local admin role untouched by SCIM");
            assert_eq!(n, 0, "non-SCIM user never added to a SCIM group");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 10) SCIM F8 — add_member is guarded against mutating a designated super-admin; the op fails BEFORE
    //     ledgering and the super-admin's role is never downgraded.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn group_add_member_guards_superadmin() {
        let ledger = tmp_path("scim-f8-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-f8");
        let sa_uid: i64 = {
            let db = app.db();
            crate::settings_set(&db, "enterprise.superadmin", "super.admin").unwrap();
            let hash = crate::hash_pw("sapw");
            crate::upsert_user(&db, "super.admin", "admin", &hash).unwrap();
            db.query_row("SELECT id FROM users WHERE login=?", ["super.admin"], |r| r.get(0)).unwrap()
        };
        let addr = serve(app.clone()).await;
        let before = crate::read_ledger_lines(&ledger).len();
        // "Forge Operators" -> operator role; adding the super-admin must be guarded (op fails).
        let gbody = json!({
            "schemas": [SCHEMA_GROUP],
            "displayName": "Forge Operators",
            "members": [{ "value": sa_uid.to_string() }],
        })
        .to_string();
        let gr = http_raw(addr, &body_req("POST", "/scim/v2/Groups", &gbody, &bearer_hdr("tok-f8"))).await;
        assert_eq!(parse_status(&gr), 500, "super-admin member add is guarded (op fails): {gr}");
        {
            let db = app.db();
            let role: String = db.query_row("SELECT role FROM users WHERE id=?", [sa_uid], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(role, "admin", "super-admin role NEVER downgraded by SCIM group");
        }
        // No group.create ledger for the aborted op (guard fired before ledgering).
        let lines = crate::read_ledger_lines(&ledger);
        assert_eq!(lines.len(), before, "guarded op does not ledger a mutation");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 10b) SCIM L7 — group membership PATCH `remove` is applied TRANSACTIONALLY and error-checked: the
    //      removal lands (200), the retained member stays (consistent membership), and the previously
    //      SWALLOWED DELETE result is now matched (a real failure would 500 before the ledger).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn group_patch_remove_member_is_transactional() {
        let ledger = tmp_path("scim-l7-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "tok-l7");
        let addr = serve(app.clone()).await;
        // Two genuine SCIM users (each gets a scim_user row, so both can join a SCIM group).
        let c1 = http_raw(addr, &body_req("POST", "/scim/v2/Users", &scim_user_body("u1@corp.com", true, "ext-1"), &bearer_hdr("tok-l7"))).await;
        let c2 = http_raw(addr, &body_req("POST", "/scim/v2/Users", &scim_user_body("u2@corp.com", true, "ext-2"), &bearer_hdr("tok-l7"))).await;
        let u1 = json_of(&c1)["id"].as_str().unwrap().to_string();
        let u2 = json_of(&c2)["id"].as_str().unwrap().to_string();
        // A group carrying both members.
        let gbody = json!({
            "schemas": [SCHEMA_GROUP],
            "displayName": "Forge Readers",
            "members": [{ "value": u1 }, { "value": u2 }],
        })
        .to_string();
        let gr = http_raw(addr, &body_req("POST", "/scim/v2/Groups", &gbody, &bearer_hdr("tok-l7"))).await;
        assert_eq!(parse_status(&gr), 201, "group created: {gr}");
        let gid = json_of(&gr)["id"].as_str().unwrap().to_string();
        // PATCH remove u2 via the `members[value eq "<id>"]` path form.
        let patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "remove", "path": format!("members[value eq \"{u2}\"]") }],
        })
        .to_string();
        let pr = http_raw(addr, &body_req("PATCH", &format!("/scim/v2/Groups/{gid}"), &patch, &bearer_hdr("tok-l7"))).await;
        assert_eq!(parse_status(&pr), 200, "[L7] patch remove -> 200: {pr}");
        // u2 removed, u1 retained — membership is consistent (atomic remove landed, no partial state).
        {
            let db = app.db();
            let gid_i: i64 = gid.parse().unwrap();
            let u2_i: i64 = u2.parse().unwrap();
            let u1_i: i64 = u1.parse().unwrap();
            let has_u2: i64 = db.query_row("SELECT COUNT(*) FROM scim_group_member WHERE group_id=? AND user_id=?", [gid_i, u2_i], |r| r.get(0)).unwrap();
            let has_u1: i64 = db.query_row("SELECT COUNT(*) FROM scim_group_member WHERE group_id=? AND user_id=?", [gid_i, u1_i], |r| r.get(0)).unwrap();
            assert_eq!(has_u2, 0, "[L7] removed member is gone");
            assert_eq!(has_u1, 1, "[L7] other member retained (consistent membership)");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 11) UNIT — pure helpers.
    // ------------------------------------------------------------------------------------------------
    #[test]
    fn unit_helpers() {
        assert_eq!(derive_login("Alice@Corp.com", "").unwrap(), "alice.corp.com");
        assert_eq!(derive_login("", "okta|abc").unwrap(), "okta-abc");
        assert!(derive_login("", "").is_err());
        assert_eq!(parse_username_filter("userName eq \"Bob@x.com\"").as_deref(), Some("Bob@x.com"));
        assert_eq!(parse_username_filter("displayName eq \"x\""), None);
        assert_eq!(coerce_bool(&json!(false)), Some(false));
        assert_eq!(coerce_bool(&json!("False")), Some(false));
        assert_eq!(coerce_bool(&json!("TRUE")), Some(true));
        assert_eq!(coerce_bool(&json!(3)), None);
        assert_eq!(role_for_group("Forge Operators"), "operator");
        assert_eq!(role_for_group("readers"), "viewer");
        assert_eq!(extract_member_path_id("members[value eq \"42\"]"), Some(42));
        assert_eq!(parse_id("7"), Some(7));
        assert_eq!(parse_id("0"), None);
        assert_eq!(parse_id("abc"), None);
        // PATCH value-object form (Okta deprovision).
        let doc = json!({"Operations":[{"op":"replace","value":{"active":false}}]});
        assert_eq!(UserAttrs::from_patch(&doc).active, Some(false));
    }

    /// FAIL-CLOSED (user_delete de-provision — écriture avalée corrigée) — INJECTION D'ÉCHEC : un trigger
    /// `BEFORE DELETE ON scim_user RAISE(ABORT)` fait ÉCHOUER la séquence de de-provision (`with_tx`). Le
    /// handler DOIT alors : (a) renvoyer 500 (PAS un faux 204), (b) N'ÉCRIRE AUCUNE entrée ledger
    /// `console.scim.user.delete` (anti divergence ledger↔DB — la piste tamper-evident ne doit jamais
    /// attester une de-provision qui n'a pas eu lieu), (c) laisser le compte INTOUCHÉ (ROLLBACK : toujours
    /// SCIM-managed, NON désactivé). Régression directe du write avalé (`let _ = store.execute`).
    #[tokio::test]
    async fn user_delete_db_failure_500_and_no_ledger() {
        let ledger = tmp_path("scim-del-fail-ledger");
        let app = scim_test_app(&ledger);
        engage_flag(&app);
        set_token(&app, "scim-secret-token-value");
        let addr = serve(app.clone()).await;
        // provisionne un user SCIM (mapping scim_user présent) via le vrai chemin POST.
        let body = scim_user_body("Bob@Corp.com", true, "okta-bob");
        let r = http_raw(addr, &body_req("POST", "/scim/v2/Users", &body, &bearer_hdr("scim-secret-token-value"))).await;
        assert_eq!(parse_status(&r), 201, "seed create doit 201: {r}");
        let uid: i64 = app.db().query_row("SELECT id FROM users WHERE login=?", ["bob.corp.com"], |r| r.get(0)).unwrap();
        // injecte l'échec d'ÉCRITURE : tout DELETE de scim_user est ABORTé (les SELECT/existence restent OK).
        app.db().execute_batch(
            "CREATE TRIGGER t_block_del_scim BEFORE DELETE ON scim_user BEGIN SELECT RAISE(ABORT,'boom'); END;"
        ).unwrap();
        let before = crate::read_ledger_lines(&ledger).len();

        let r = http_raw(addr, &body_req("DELETE", &format!("/scim/v2/Users/{uid}"), "", &bearer_hdr("scim-secret-token-value"))).await;
        assert_eq!(parse_status(&r), 500, "de-provision échouée -> 500 (PAS un faux 204): {r}");

        // (b) aucune entrée ledger ajoutée (ne ledgerise PAS une de-provision non appliquée).
        let lines = crate::read_ledger_lines(&ledger);
        assert_eq!(lines.len(), before, "un échec d'écriture NE ledgerise PAS");
        if let Some(last) = lines.last() {
            assert_ne!(last["kind"], "console.scim.user.delete", "aucune attestation de de-provision");
        }
        // (c) ROLLBACK : le compte reste SCIM-managed ET non désactivé (aucune mutation partielle).
        let (disabled, mapped): (i64, i64) = app.db().query_row(
            "SELECT u.disabled, (SELECT COUNT(*) FROM scim_user s WHERE s.user_id=u.id) FROM users u WHERE u.id=?",
            [uid], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(disabled, 0, "ROLLBACK : compte NON désactivé");
        assert_eq!(mapped, 1, "ROLLBACK : mapping scim_user intact (toujours SCIM-managed)");
    }

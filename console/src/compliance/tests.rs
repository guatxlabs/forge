// SPDX-License-Identifier: AGPL-3.0-or-later
//! `compliance` — module de test EXTRAIT (PURE MOVE depuis `console/src/compliance.rs`).
//! Corps IDENTIQUE ; ENFANT de `compliance`, il voit donc toujours ses items privés.
use super::*;

    use super::*;
    use crate::testutil::tmp_path;
    use rusqlite::Connection;
    use serde_json::json;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    /// App backed by an in-memory DB (mirrors scim::tests::scim_test_app) + migrate (tenant_id column).
    fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        crate::migrate(&conn);
        let (events, _) = broadcast::channel::<crate::RunEvent>(64);
        let app = App {
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
        };
        // engagement #1 must exist for tenant_id resolution + ledger_path.
        {
            let db = app.db();
            let _ = db.execute(
                "INSERT OR IGNORE INTO engagement(id,name,status,mode,scope_json,ledger_path,tenant_id,created,updated)
                 VALUES(1,'default','active','grey','{}',?,1,'','')",
                rusqlite::params![ledger_path],
            );
        }
        app
    }

    /// Engage the enterprise flag on THIS db (per-DB, isolated — no env mutation, no parallel races).
    fn engage(app: &App) {
        let db = app.db();
        crate::settings_set(&db, "enterprise.compliance", "on").unwrap();
    }

    /// Provision a local admin + open an admin session; returns the bearer session token.
    fn admin_session(app: &App) -> String {
        let hash = crate::hash_pw("adminpw");
        let db = app.db();
        crate::upsert_user(&db, "root", "admin", &hash).unwrap();
        let id: i64 = db.query_row("SELECT id FROM users WHERE login=?", ["root"], |r| r.get(0)).unwrap();
        drop(db);
        app.recompute_auth_required();
        crate::create_session(app, id).0
    }

    fn bearer(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {tok}").parse().unwrap());
        h
    }

    /// Append a sha256-console entry to `path` with an EXPLICIT `@<ts_epoch>` (so retention can be tested
    /// with old entries). Returns the new head hash. Mirrors append_console_ledger's pre-image.
    fn seed_entry(path: &str, prev: &str, seq: i64, ts_epoch: i64, kind: &str, detail: &Value) -> String {
        let ts = format!("@{ts_epoch}");
        let preimage = format!("{prev}|{seq}|{ts}|{kind}|{}", crate::canon_json(detail));
        let hash = crate::sha_hex(&preimage);
        let rec = json!({"seq":seq,"ts":ts,"kind":kind,"detail":detail,"prev":prev,"hash":hash,"alg":CONSOLE_ALG,"sig":""});
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
        writeln!(f, "{}", crate::canon_json(&rec)).unwrap();
        hash
    }

    /// Seed a ledger with `n_old` entries aged `old_age` seconds + `n_new` entries aged `new_age` seconds.
    /// Returns the file path. All sha256-console. Chain valid.
    fn seed_ledger(path: &str, now: i64, n_old: i64, old_age: i64, n_new: i64, new_age: i64) {
        let mut prev = GENESIS.to_string();
        let mut seq = 0i64;
        for i in 0..n_old {
            seq += 1;
            prev = seed_entry(path, &prev, seq, now - old_age, "console.run.start", &json!({"i": i, "phase": "old"}));
        }
        for i in 0..n_new {
            seq += 1;
            prev = seed_entry(path, &prev, seq, now - new_age, "console.run.end", &json!({"i": i, "phase": "new"}));
        }
    }

    // ---- POLICY + HOLD RESOLUTION ----

    #[test]
    fn retention_most_specific_wins() {
        let path = tmp_path("comp-ret");
        let app = test_app(&path);
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "10").unwrap();
            crate::settings_set(&db, &ret_key_tenant(1), "20").unwrap();
        }
        assert_eq!(resolve_retention_secs(&app, 1, Some(1)), Some(20)); // tenant over global
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_engagement(1), "30").unwrap();
        }
        assert_eq!(resolve_retention_secs(&app, 1, Some(1)), Some(30)); // engagement over tenant
    }

    #[test]
    fn legal_hold_any_scope_wins() {
        let path = tmp_path("comp-hold");
        let app = test_app(&path);
        assert_eq!(legal_hold_scope(&app, 1, Some(1)), None);
        {
            let db = app.db();
            crate::settings_set(&db, &hold_key_global(), "on").unwrap();
        }
        assert_eq!(legal_hold_scope(&app, 1, Some(1)), Some("global"));
        {
            let db = app.db();
            crate::settings_set(&db, &hold_key_engagement(1), "on").unwrap();
        }
        assert_eq!(legal_hold_scope(&app, 1, Some(1)), Some("engagement")); // most-restrictive/specific first
    }

    // ---- FLAG OFF => INERT / BYTE-IDENTICAL ----

    #[tokio::test]
    async fn flag_off_purge_is_404_and_ledger_untouched() {
        let path = tmp_path("comp-off");
        let app = test_app(&path);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 3, 1_000_000, 0, 0); // all old, but flag OFF
        let before = std::fs::read_to_string(&path).unwrap();
        // deletion_blocked is inert when flag OFF (community byte-identical).
        assert_eq!(deletion_blocked(&app, 1), None);
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "flag OFF must leave the ledger byte-identical");
    }

    // ---- WORM: legal hold blocks purge (fail-closed) ----

    #[tokio::test]
    async fn hold_blocks_purge_ledger_unchanged() {
        let path = tmp_path("comp-holdblock");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 3, 1_000_000, 1, 0);
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap(); // expired
            crate::settings_set(&db, "compliance.archive_key", "pw").unwrap();
            crate::settings_set(&db, &hold_key_engagement(1), "on").unwrap(); // HOLD
        }
        let before = std::fs::read_to_string(&path).unwrap();
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        // MUTATION SENTINEL: if the legal_hold_scope check in purge() were removed, this would 200 and purge —
        // proving the hold check is load-bearing.
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "hold must leave the ledger byte-identical (no purge, no archive)");
        // deletion_blocked also reports the hold (used by engagement delete/archive WORM guard).
        assert_eq!(deletion_blocked(&app, 1), Some("engagement".to_string()));
    }

    // ---- WORM: under-retention blocks purge (no-op) ----

    #[tokio::test]
    async fn under_retention_is_noop() {
        let path = tmp_path("comp-underret");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 0, 0, 3, 10); // all fresh (age 10s)
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "1000").unwrap(); // window 1000s > 10s
            crate::settings_set(&db, "compliance.archive_key", "pw").unwrap();
        }
        let before = std::fs::read_to_string(&path).unwrap();
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["purged_ledger_entries"], 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before, "no expired entries => byte-identical");
    }

    // ---- WORM: refuse to purge without an archive key (never a silent delete) ----

    #[tokio::test]
    async fn purge_without_archive_key_refused() {
        let path = tmp_path("comp-nokey");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 3, 1_000_000, 1, 0);
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap();
            // NO archive key set
        }
        let before = std::fs::read_to_string(&path).unwrap();
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before, "no archive key => no purge, byte-identical");
    }

    // ---- GOVERNED PURGE: succeeds after expiry + no hold; archives; emits signed checkpoint; verifies ----

    #[tokio::test]
    async fn governed_purge_archives_reanchors_and_verifies() {
        let path = tmp_path("comp-purge");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        // 3 old (expired) + 2 new (survive).
        seed_ledger(&path, now, 3, 1_000_000, 2, 5);
        // also an OLD finding (should be archived+deleted) + a NEW finding (kept).
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap();
            crate::settings_set(&db, "compliance.archive_key", "correct horse").unwrap();
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,engagement_id) VALUES(?,?,?,?,?,?,?,?,1)",
                rusqlite::params![format!("@{}", now - 1_000_000), "c", "t", "old-finding", "HIGH", "x", "", "open"],
            ).unwrap();
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,engagement_id) VALUES(?,?,?,?,?,?,?,?,1)",
                rusqlite::params![format!("@{}", now - 5), "c", "t", "new-finding", "LOW", "x", "", "open"],
            ).unwrap();
            drop(db);
        }
        // sanity: chain valid before purge.
        assert!(crate::verify_ledger_chain(&path).ok, "seeded ledger must verify");

        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;

        assert_eq!(body["purged_ledger_entries"], 3, "3 expired entries purged");
        assert_eq!(body["survivors"], 2, "2 entries survive");
        assert_eq!(body["purged_findings"], 1, "1 expired finding purged");
        assert_eq!(body["ledger_verified"], true, "re-anchored ledger must verify");
        let archive_path = body["archive_path"].as_str().unwrap().to_string();
        let seg_sha = body["segment_sha256"].as_str().unwrap().to_string();

        // (a) the ledger re-verifies under the EXISTING verifier (tamper-evident chain preserved).
        assert!(crate::verify_ledger_chain(&path).ok, "ledger must remain verifiable after governed purge");

        // (b) it emits a signed checkpoint `console.compliance.purge` (the re-anchor / genesis entry).
        let pairs = read_ledger_pairs(&path);
        assert_eq!(pairs[0].1["kind"], PURGE_KIND, "first entry is the purge checkpoint (re-anchor)");
        assert_eq!(pairs[0].1["prev"], GENESIS, "checkpoint is genesis-rooted");
        assert_eq!(pairs[0].1["detail"]["purged_ledger_entries"], 3);
        assert_eq!(pairs[0].1["detail"]["segment_sha256"].as_str().unwrap(), seg_sha);
        assert_eq!(pairs.len(), 3, "checkpoint + 2 survivors");
        // survivors' audited content preserved (kind of the last survivor is console.run.end phase=new).
        assert_eq!(pairs[2].1["kind"], "console.run.end");
        assert_eq!(pairs[2].1["detail"]["phase"], "new");

        // (c) the archive exists, is encrypted (not the plaintext), and decrypts to the segment we hashed.
        let enc = std::fs::read(&archive_path).unwrap();
        assert!(!enc.windows(9).any(|w| w == b"old-findi"), "archive must be encrypted (no plaintext leak)");
        let dec = crate::backup_decrypt(&enc, "correct horse").unwrap();
        assert_eq!(crate::sha256_hex_bytes(&dec), seg_sha, "decrypted archive matches the checkpoint segment hash");
        let doc: Value = serde_json::from_slice(&dec).unwrap();
        assert_eq!(doc["ledger_segment"].as_array().unwrap().len(), 3, "3 purged ledger lines archived verbatim");
        assert_eq!(doc["findings"].as_array().unwrap().len(), 1, "the expired finding archived");

        // (d) expired finding deleted; recent finding kept.
        {
            let db = app.db();
            let n: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=1", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 1, "only the recent finding remains");
            let title: String = db.query_row("SELECT title FROM finding WHERE engagement_id=1", [], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(title, "new-finding");
        }

        // (e) the ledger still APPENDS cleanly after a purge (head cache rebuilt) — chain stays valid.
        crate::append_console_ledger(&app, "console.run.start", json!({"after": "purge"}));
        assert!(crate::verify_ledger_chain(&path).ok, "ledger must verify after a post-purge append");
    }

    // ---- FAIL-CLOSED: refuse to re-anchor a SIGNED surviving entry (would break its Ed25519 sig) ----

    #[tokio::test]
    async fn signed_survivor_refuses_purge() {
        let path = tmp_path("comp-signed");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        // one OLD console entry (expired) + one NEW ed25519-signed engine entry (survivor).
        let prev = seed_entry(&path, GENESIS, 1, now - 1_000_000, "console.run.start", &json!({"i": 0}));
        // an ed25519 survivor (non-console kind, alg ed25519) — content need not have a valid sig for this
        // test; the purge must refuse purely on the SURVIVOR being non-console-alg (before any rewrite).
        let detail = json!({"verdict": "FIRE"});
        let ts2 = format!("@{}", now - 5);
        let pre2 = format!("{prev}|2|{ts2}|roe.decision|{}", crate::canon_json(&detail));
        let h2 = crate::sha_hex(&pre2);
        let rec2 = json!({"seq":2,"ts":ts2,"kind":"roe.decision","detail":detail,"prev":prev,"hash":h2,"alg":"ed25519","sig":"00"});
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "{}", crate::canon_json(&rec2)).unwrap();
        }
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap();
            crate::settings_set(&db, "compliance.archive_key", "pw").unwrap();
        }
        let before = std::fs::read_to_string(&path).unwrap();
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "must refuse to re-anchor a signed survivor");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before, "refused purge => ledger byte-identical");
    }

    // ---- FIX 1: SHARED GLOBAL LEDGER — a hold on ANOTHER tenant REFUSES the (engagement-#1) global purge ----

    #[tokio::test]
    async fn global_ledger_purge_refused_by_other_tenant_hold() {
        let path = tmp_path("comp-globalhold");
        let app = test_app(&path); // engagement #1 (tenant #1) — its ledger IS App.ledger_path (the GLOBAL ledger)
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 3, 1_000_000, 1, 0); // an expired prefix a naive purge would truncate
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap(); // expired past retention
            crate::settings_set(&db, "compliance.archive_key", "pw").unwrap();
            // A legal hold on a DIFFERENT tenant (#2). legal_hold_scope(app,1,tenant#1) would NOT see this —
            // the pre-fix bug let the shared-ledger purge destroy tenant #2's interleaved records. Fixed: the
            // global purge gates on ANY hold ANYWHERE (any_legal_hold_key) and must REFUSE.
            crate::settings_set(&db, &hold_key_tenant(2), "on").unwrap();
        }
        let before = std::fs::read_to_string(&path).unwrap();
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "a hold on ANY scope must refuse the shared-global-ledger purge");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before, "refused global purge => ledger byte-identical (no cross-tenant audit loss)");
    }

    // ---- FIX 1: SHARED GLOBAL LEDGER — the purge checkpoint is HONESTLY scoped "global" ----

    #[tokio::test]
    async fn global_ledger_purge_checkpoint_scope_is_global() {
        let path = tmp_path("comp-globalscope");
        let app = test_app(&path); // engagement #1 ledger == App.ledger_path (global)
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 3, 1_000_000, 2, 5);
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap();
            crate::settings_set(&db, "compliance.archive_key", "pw").unwrap();
        }
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let pairs = read_ledger_pairs(&path);
        assert_eq!(pairs[0].1["kind"], PURGE_KIND, "first entry is the purge checkpoint");
        assert_eq!(pairs[0].1["detail"]["scope"], "global", "shared-global-ledger purge MUST record scope=global (honest scoping)");
        assert!(crate::verify_ledger_chain(&path).ok, "re-anchored global ledger still verifies");
    }

    // ---- FIX C: engagement #1 keeps GLOBAL semantics even if its ledger_path column desyncs (env repoint) ----

    #[tokio::test]
    async fn default_engagement_is_global_despite_repointed_ledger() {
        let path_a = tmp_path("comp-fixc-a"); // App.ledger_path (runtime)
        let path_b = tmp_path("comp-fixc-b"); // engagement #1's STORED ledger_path after a repoint
        let app = test_app(&path_a);
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path_b, now, 3, 1_000_000, 1, 0); // expired prefix a naive scoped purge would truncate
        {
            let db = app.db();
            // Desync #1's stored column away from App.ledger_path (simulates FORGE_CONSOLE_LEDGER repoint).
            db.execute("UPDATE engagement SET ledger_path=? WHERE id=1", [&path_b]).unwrap();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap();
            crate::settings_set(&db, "compliance.archive_key", "pw").unwrap();
            // A hold on a DIFFERENT tenant (#2): only the GLOBAL any-hold-anywhere gate sees it. Pre-FIX-C
            // is_global would be false (path_b != path_a) => scoped gate misses it => purge proceeds (200).
            crate::settings_set(&db, &hold_key_tenant(2), "on").unwrap();
            drop(db); // release before the read-back/assertions below (no DB access there)
        }
        let before = std::fs::read_to_string(&path_b).unwrap();
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "engagement #1 stays global => cross-tenant hold refuses (FIX C)");
        assert_eq!(std::fs::read_to_string(&path_b).unwrap(), before, "refused => ledger byte-identical");
    }

    // ---- FIX 2: retention wins on delete/archive — a within-retention record blocks it (dedicated ledger) ----

    #[test]
    fn retention_blocks_delete_within_window() {
        let path = tmp_path("comp-retdel");
        let app = test_app(&path);
        engage(&app);
        let path2 = tmp_path("comp-retdel2");
        add_engagement(&app, 2, 1, &path2); // engagement #2, tenant #1, its OWN dedicated ledger
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "1000").unwrap();
        }
        let now = crate::now_epoch();
        seed_finding(&app, 2, "fresh", now - 5); // age 5s < 1000s => WITHIN retention
        assert!(retention_blocked(&app, 2).is_some(), "a within-retention record must block delete/archive (WORM)");
        // once it ages past retention, retention no longer blocks.
        {
            
            app.db().execute("UPDATE finding SET ts=? WHERE engagement_id=2", [format!("@{}", now - 5000)]).unwrap();
        }
        assert!(retention_blocked(&app, 2).is_none(), "an expired record no longer blocks delete/archive");
        // flag OFF => inert (community byte-identical) even with a fresh record.
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.compliance", "").unwrap();
        }
        seed_finding(&app, 2, "fresh2", now);
        assert!(retention_blocked(&app, 2).is_none(), "flag OFF => retention gate inert");
    }

    // ---- FIX D: a within-retention roe_decision (audit verdict) ALSO blocks delete/archive ----

    #[test]
    fn retention_blocks_delete_on_roe_decision() {
        let path = tmp_path("comp-roedel");
        let app = test_app(&path);
        engage(&app);
        add_engagement(&app, 2, 1, &tmp_path("comp-roedel2")); // engagement #2, tenant #1
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "1000").unwrap();
        }
        let now = crate::now_epoch();
        // NO finding/runrecord for #2 — ONLY a fresh roe_decision. Pre-FIX-D this returned None (unblocked).
        {
            
            app.db().execute(
                "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,engagement_id) VALUES(?,?,?,?,?,?,?,?)",
                rusqlite::params![format!("@{}", now - 5), "c", "r1", "a1", "t", "recon.http", "FIRE", 2],
            )
            .unwrap();
        }
        assert!(
            retention_blocked(&app, 2).is_some(),
            "a within-retention roe_decision must block delete/archive (FIX D)"
        );
        // once it ages past retention (and no other rows exist) it no longer blocks.
        {
            
            app.db().execute("UPDATE roe_decision SET ts=? WHERE engagement_id=2", [format!("@{}", now - 5000)]).unwrap();
        }
        assert!(
            retention_blocked(&app, 2).is_none(),
            "an expired roe_decision no longer blocks delete/archive"
        );
    }

    // ---- FIX 3: a concurrent append during a purge is not lost and the chain still verifies ----

    #[tokio::test]
    async fn concurrent_append_during_purge_not_lost() {
        let path = tmp_path("comp-race");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 3, 1_000_000, 1, 5); // 3 expired (purged) + 1 fresh (survivor)
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap();
            crate::settings_set(&db, "compliance.archive_key", "pw").unwrap();
        }
        // Fire 5 fresh console appends CONCURRENTLY with the purge. They share App.ledger_lock with the purge
        // rewrite, so none may be lost or corrupt the chain. (Fresh ts => never in the purged prefix.)
        let app2 = app.clone();
        let writer = std::thread::spawn(move || {
            for i in 0..5 {
                crate::append_console_ledger(&app2, "console.race.append", json!({ "i": i }));
            }
        });
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        writer.join().unwrap();
        assert!(crate::verify_ledger_chain(&path).ok, "chain must verify after concurrent append + purge");
        let pairs = read_ledger_pairs(&path);
        let appended = pairs.iter().filter(|(_, r)| r["kind"] == "console.race.append").count();
        assert_eq!(appended, 5, "no concurrent append may be lost under the shared ledger_lock");
    }

    // ---- H1: a CROSS-PROCESS (flock-only) engine/peer append during a purge is not lost (WORM) ----
    //
    // The PRE-FIX purge held ONLY the in-proc `ledger_lock` and rewrote via rename (inode swap). A Python
    // ENGINE append (`forge/ledger.py`) or an HA PEER uses `fcntl.flock` on the file — NOT the Rust in-proc
    // mutex — so it could interleave in the snapshot->rename window and be SILENTLY DROPPED when the rename
    // unlinked the inode it had written to, while `verify` still said ok. This test mimics that appender with
    // `append_sha256_console_locked` (the flock-ONLY primitive, NO `ledger_lock`), hammers it concurrently
    // with a purge, and asserts ZERO signed entries lost + `verify` stays ok. The fix (flock held across the
    // whole read+rewrite + IN-PLACE rewrite) makes the appender block until the purge finishes and then chain
    // onto the re-anchored head — never onto an orphaned inode. Fresh ts => these are survivors, never in the
    // purged prefix, so any loss would be pure data loss.
    #[tokio::test]
    async fn cross_process_append_during_purge_not_lost() {
        let path = tmp_path("comp-race-xproc");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 3, 1_000_000, 1, 5); // 3 expired (purged) + 1 fresh (survivor)
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap();
            // a REAL archive key => backup_encrypt does its (slow) KDF, WIDENING the purge critical section
            // so the flock-only appender genuinely piles up against the lock (adversarial timing).
            crate::settings_set(&db, "compliance.archive_key", "correct horse battery").unwrap();
        }
        // A flock-ONLY appender (NO app.ledger_lock) — a faithful stand-in for the Python engine / an HA
        // peer PROCESS. It hammers the SAME file while the purge runs.
        let p2 = path.clone();
        let writer = std::thread::spawn(move || {
            let mut ok = 0usize;
            for i in 0..40 {
                if crate::append_sha256_console_locked(&p2, "engine.race.append", &json!({ "i": i })).is_ok() {
                    ok += 1;
                }
            }
            ok
        });
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let appended_ok = writer.join().unwrap();
        // (a) the re-anchored chain still verifies (no fork, no torn in-place rewrite).
        assert!(crate::verify_ledger_chain(&path).ok, "chain must verify after cross-process append + purge");
        // (b) EVERY successfully-appended engine entry is PRESENT — none dropped by the purge rewrite.
        let pairs = read_ledger_pairs(&path);
        let present = pairs.iter().filter(|(_, r)| r["kind"] == "engine.race.append").count();
        assert!(appended_ok > 0, "the appender must have written at least one entry (test is non-vacuous)");
        assert_eq!(present, appended_ok, "no cross-process (flock-only) append may be lost by the purge (H1)");
    }

    // ---- FIX A: the RETENTION path over a finding with a multibyte ts does NOT panic and RETAINS it ----

    #[test]
    fn retention_multibyte_ts_retains_no_panic() {
        let path = tmp_path("comp-mbts");
        let app = test_app(&path);
        engage(&app);
        add_engagement(&app, 2, 1, &tmp_path("comp-mbts2"));
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "1000").unwrap();
            // finding whose ts is unparseable due to a multibyte char (stored verbatim from ingest).
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,engagement_id) VALUES(?,?,?,?,?,?,?,?,?)",
                rusqlite::params!["2025-01-01T00:00:0é", "c", "t", "mb", "HIGH", "x", "", "open", 2],
            )
            .unwrap();
        }
        // Must not panic; unparseable ts => within-retention (fail-closed) => delete/archive blocked.
        assert!(
            retention_blocked(&app, 2).is_some(),
            "multibyte/unparseable ts => within-retention => blocked, no panic"
        );
    }

    // ---- FIX B: any_legal_hold_key fails CLOSED (assumes a hold) on a DB/query error ----

    #[test]
    fn any_legal_hold_fails_closed_on_db_error() {
        let path = tmp_path("comp-failclosed");
        let app = test_app(&path);
        {
            let db = app.db();
            db.execute_batch("DROP TABLE settings").unwrap(); // make the hold query unreadable
        }
        // Unreadable settings => Some (a hold is ASSUMED) => the shared-global purge refuses. Never None.
        assert!(
            any_legal_hold_key(&app).is_some(),
            "unreadable settings must fail closed (assume a hold), not fail open"
        );
    }

    #[tokio::test]
    async fn malformed_finding_ts_is_retained_not_purged() {
        let path = tmp_path("comp-badts");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 2, 1_000_000, 1, 5); // an expired prefix so the purge proceeds
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap();
            crate::settings_set(&db, "compliance.archive_key", "pw").unwrap();
            // a finding whose ts is MALFORMED — must be RETAINED (never date-unknown-delete), and must not panic.
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,engagement_id) VALUES('not-a-date','c','t','bad-ts','LOW','x','','open',1)",
                [],
            )
            .unwrap();
        }
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        
        let n: i64 = app.db().query_row("SELECT COUNT(*) FROM finding WHERE title='bad-ts'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "malformed-ts finding retained (fail-closed), no panic");
    }

    // ---- ADMIN GATE ----

    #[tokio::test]
    async fn non_admin_denied_when_enabled() {
        let path = tmp_path("comp-noadmin");
        let app = test_app(&path);
        engage(&app);
        // no session => not admin
        let resp = purge(State(app.clone()), HeaderMap::new(), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // =====================================================================================
    // EVIDENCE EXPORT (SOC 2 / ISO) — read-only bundle: isolation + redaction + ledger integrity
    // attestation + role-gate + ledgered + flag-off absence. These lock the auditor-facing surface.
    // =====================================================================================

    /// Register a SECOND engagement `id` in tenant `tenant` with its OWN ledger file (isolation fixture).
    fn add_engagement(app: &App, id: i64, tenant: i64, ledger_path: &str) {
        
        app.db().execute(
            "INSERT OR IGNORE INTO engagement(id,name,status,mode,scope_json,ledger_path,tenant_id,created,updated)
             VALUES(?,?,?,?,'{}',?,?,'','')",
            rusqlite::params![id, format!("eng{id}"), "active", "grey", ledger_path, tenant],
        )
        .unwrap();
    }

    /// Insert a finding attributed to `eid`.
    fn seed_finding(app: &App, eid: i64, title: &str, ts_epoch: i64) {
        
        app.db().execute(
            "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,engagement_id) VALUES(?,?,?,?,?,?,?,?,?)",
            rusqlite::params![format!("@{ts_epoch}"), "c", "t", title, "HIGH", "x", "", "open", eid],
        )
        .unwrap();
    }

    // ---- FLAG OFF => the evidence route is ABSENT (404) — byte-identical community ----
    #[tokio::test]
    async fn evidence_flag_off_is_404() {
        let path = tmp_path("comp-ev-off");
        let app = test_app(&path); // flag NOT engaged
        let tok = admin_session(&app);
        let mut q = HashMap::new();
        q.insert("engagement_id".to_string(), "1".to_string());
        let resp = evidence_export(State(app.clone()), bearer(&tok), Query(q)).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "flag OFF => evidence route 404 (no compliance surface)");
    }

    // ---- ROLE-GATED: enabled but non-admin => 403 ----
    #[tokio::test]
    async fn evidence_non_admin_denied() {
        let path = tmp_path("comp-ev-noadmin");
        let app = test_app(&path);
        engage(&app);
        let mut q = HashMap::new();
        q.insert("engagement_id".to_string(), "1".to_string());
        let resp = evidence_export(State(app.clone()), HeaderMap::new(), Query(q)).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "evidence export is admin-only");
    }

    // ---- ISOLATION: evidence for engagement A carries ONLY A's data (never B's) ----
    #[test]
    fn evidence_isolation_only_engagement_a_data() {
        let path_a = tmp_path("comp-ev-a");
        let app = test_app(&path_a); // engagement #1, tenant #1, ledger path_a
        engage(&app);
        let path_b = tmp_path("comp-ev-b");
        add_engagement(&app, 2, 2, &path_b); // engagement #2, tenant #2, its OWN ledger
        let now = crate::now_epoch();
        // distinct authorization events in each engagement's OWN ledger.
        seed_entry(&path_a, GENESIS, 1, now - 10, "roe.decision", &json!({"actor": "alice", "scope": "A-scope"}));
        seed_entry(&path_b, GENESIS, 1, now - 10, "roe.decision", &json!({"actor": "bob", "scope": "B-scope"}));
        // findings: 1 for A, 2 for B.
        seed_finding(&app, 1, "A-find", now);
        seed_finding(&app, 2, "B-find-1", now);
        seed_finding(&app, 2, "B-find-2", now);
        // RBAC grants: alice -> tenant 1, bob -> tenant 2.
        {
            let db = app.db();
            crate::upsert_user(&db, "alice", "operator", &crate::hash_pw("x")).unwrap();
            crate::upsert_user(&db, "bob", "operator", &crate::hash_pw("x")).unwrap();
            let aid: i64 = db.query_row("SELECT id FROM users WHERE login=?", ["alice"], |r| r.get(0)).unwrap();
            let bid: i64 = db.query_row("SELECT id FROM users WHERE login=?", ["bob"], |r| r.get(0)).unwrap();
            db.execute("INSERT INTO tenant_grant(user_id,tenant_id,role) VALUES(?,1,'tenant_admin')", [aid]).unwrap();
            db.execute("INSERT INTO tenant_grant(user_id,tenant_id,role) VALUES(?,2,'tenant_admin')", [bid]).unwrap();
        }

        let b = build_evidence(&app, 1, None, None).expect("evidence bundle for engagement 1");

        // (a) engagement identity is A.
        assert_eq!(b["engagement"]["id"], 1);
        assert_eq!(b["engagement"]["tenant_id"], 1);
        // (b) counts scoped to A (1 finding), never B's (2).
        assert_eq!(b["counts"]["findings"], 1, "only engagement A's findings are counted");
        // (c) the attested ledger is A's own file; B's ledger/actor never leak.
        assert_eq!(b["ledger_integrity"]["path"], path_a);
        let trail = b["authorization_audit_trail"].as_array().unwrap();
        assert!(trail.iter().any(|e| e["scope"] == "A-scope"), "A's authorization event present");
        assert!(!trail.iter().any(|e| e["scope"] == "B-scope"), "B's authorization event MUST NOT leak");
        let access = b["access_mutation_log"].as_array().unwrap();
        assert!(!access.iter().any(|e| e["actor"] == "bob"), "engagement B actor MUST NOT appear in A's access log");
        // (d) tenant grants: only tenant 1's grant (alice), never tenant 2's (bob).
        let grants = b["rbac_grant_state"]["tenant_grants"].as_array().unwrap();
        assert!(grants.iter().any(|g| g["login"] == "alice"), "tenant A grant present");
        assert!(!grants.iter().any(|g| g["login"] == "bob"), "tenant B grant MUST NOT leak into A's evidence");
    }

    // ---- REDACTION: secrets in a ledger detail become [REDACTED]; the public key is PRESERVED ----
    #[test]
    fn evidence_redacts_secrets_preserves_pubkey() {
        let path = tmp_path("comp-ev-redact");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        // an authorization-kind entry whose detail carries BOTH secrets and a public key.
        seed_entry(
            &path,
            GENESIS,
            1,
            now - 10,
            "roe.decision",
            &json!({"actor": "root", "scope": "prod", "credential": "SUPERSECRET", "token": "tok_abc", "pubkey": "deadbeefcafe"}),
        );
        let b = build_evidence(&app, 1, None, None).expect("evidence bundle");
        let trail = b["authorization_audit_trail"].as_array().unwrap();
        let d = &trail[0]["detail"];
        assert_eq!(d["credential"], "[REDACTED]", "secret 'credential' must be redacted");
        assert_eq!(d["token"], "[REDACTED]", "secret 'token' must be redacted");
        assert_eq!(d["pubkey"], "deadbeefcafe", "public key is verification material — PRESERVED");
        assert_eq!(d["scope"], "prod", "non-secret structural field preserved");
        // FAIL-SAFE: no secret VALUE may appear anywhere in the serialized bundle.
        let s = serde_json::to_string(&b).unwrap();
        assert!(!s.contains("SUPERSECRET"), "no secret value may appear anywhere in the bundle");
        assert!(!s.contains("tok_abc"), "no token value may appear anywhere in the bundle");
    }

    // ---- LEDGER INTEGRITY ATTESTATION present + accurate (head hash + verify + ed25519 material) ----
    #[test]
    fn evidence_has_ledger_integrity_attestation() {
        let path = tmp_path("comp-ev-integ");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 0, 0, 3, 5); // 3 valid sha256-console entries
        assert!(crate::verify_ledger_chain(&path).ok, "seeded ledger verifies");
        let b = build_evidence(&app, 1, None, None).expect("evidence bundle");
        let li = &b["ledger_integrity"];
        assert_eq!(li["chain_ok"], true, "attestation reports a verified chain");
        assert_eq!(li["entries"].as_u64().unwrap(), 3);
        assert_eq!(li["head"].as_str().unwrap().len(), 64, "head hash present (sha256 hex, 64 chars)");
        assert!(li["verify_command"].as_str().unwrap().contains("forge ledger verify"), "external verify command present");
        assert!(li["signature_algorithm"].as_str().unwrap().contains("ed25519"), "ed25519 non-repudiation attested");
        // schema markers a SOC 2 / ISO auditor keys on.
        assert_eq!(b["schema"], "forge-compliance-evidence-1");
        assert!(b["framework"].as_str().unwrap().contains("SOC 2"), "framework label present");
    }

    // ---- The ACT of exporting evidence is itself LEDGERED (and the chain stays verifiable) ----
    #[tokio::test]
    async fn evidence_export_is_ledgered() {
        let path = tmp_path("comp-ev-ledgered");
        let app = test_app(&path);
        engage(&app);
        let tok = admin_session(&app);
        let mut q = HashMap::new();
        q.insert("engagement_id".to_string(), "1".to_string());
        q.insert("format".to_string(), "json".to_string());
        let resp = evidence_export(State(app.clone()), bearer(&tok), Query(q)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        // the export ACT is audited into the engagement ledger.
        let entries = crate::read_ledger_lines(&path);
        assert!(
            entries.iter().any(|r| r["kind"] == "console.compliance.evidence.export"),
            "the evidence export must be ledgered"
        );
        // and the append did not corrupt the tamper-evident chain.
        assert!(crate::verify_ledger_chain(&path).ok, "ledger verifies after the export append");
    }

    async fn body_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or(json!({}))
    }

    /// FAIL-CLOSED (delete_rows — écriture avalée corrigée) — INJECTION D'ÉCHEC : un trigger
    /// `BEFORE DELETE ON finding RAISE(ABORT)` fait ÉCHOUER la suppression des lignes expirées (le ledger
    /// est déjà ré-ancré, attestant `purged_findings`). Le handler purge DOIT alors renvoyer 500
    /// `purge_delete_failed` (PAS un faux 200 « purgé ») et la ligne expirée DOIT rester (with_tx ROLLBACK —
    /// aucune suppression partielle). Sans le fix, l'ancien `let _ = execute` avalait l'échec et renvoyait 200.
    #[tokio::test]
    async fn purge_delete_failure_500_and_rows_intact() {
        let path = tmp_path("comp-purge-delfail");
        let app = test_app(&path);
        engage(&app);
        let now = crate::now_epoch();
        seed_ledger(&path, now, 3, 1_000_000, 2, 5);
        {
            let db = app.db();
            crate::settings_set(&db, &ret_key_global(), "100").unwrap();
            crate::settings_set(&db, "compliance.archive_key", "correct horse").unwrap();
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,engagement_id) VALUES(?,?,?,?,?,?,?,?,1)",
                rusqlite::params![format!("@{}", now - 1_000_000), "c", "t", "old-finding", "HIGH", "x", "", "open"],
            ).unwrap();
            // injecte l'échec d'ÉCRITURE : tout DELETE de finding est ABORTé (lectures + archivage restent OK).
            db.execute_batch("CREATE TRIGGER t_block_del_finding BEFORE DELETE ON finding BEGIN SELECT RAISE(ABORT,'boom'); END;").unwrap();
            drop(db);
        }
        let tok = admin_session(&app);
        let resp = purge(State(app.clone()), bearer(&tok), Json(json!({"engagement_id": 1}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR, "delete échoué -> 500 (PAS un faux 200)");
        let body = body_json(resp).await;
        assert_eq!(body["error"], "purge_delete_failed", "erreur typée (anti false-200)");
        // with_tx ROLLBACK : la ligne expirée reste (aucune suppression partielle silencieuse).
        {
            let db = app.db();
            let n: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=1 AND title='old-finding'", [], |r| r.get(0)).unwrap();
            drop(db);
            assert_eq!(n, 1, "la ligne expirée RESTE (delete rollback, pas de suppression partielle)");
        }
    }

// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ha` — module de test EXTRAIT (PURE MOVE depuis `console/src/ha.rs`).
//! Corps IDENTIQUE ; ENFANT de `ha`, il voit donc toujours ses items privés.
//! Renommé `pg_tests` -> `tests_pg` : `tests/test_portability_guard.py` n'exclut
//! que les fichiers `tests.rs` / `tests_*` et scannerait l'autre nom (garde au ROUGE).
use super::*;

    use super::*;
    use crate::store::Store;

    #[test]
    fn pg_lease_acquire_renew_takeover_single_row() {
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_lease] TEST_PG_URL unset — skipping (set it to run against a real Postgres)");
                return;
            }
        };
        let client = crate::store::connect_postgres(&url).expect("connect TEST_PG_URL");
        let m = std::sync::Mutex::new(client);

        // Fresh table (isolated from the seam suite's tables).
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute_batch("DROP TABLE IF EXISTS leader_lease").expect("drop lease");
            s.execute_batch(
                "CREATE TABLE leader_lease(scope TEXT PRIMARY KEY, instance_id TEXT, acquired BIGINT, last_seen BIGINT)",
            )
            .expect("create lease");
        }
        // A acquires (fresh) -> leader; renew -> still leader.
        assert!(acquire_or_renew(&Store::postgres(m.lock().unwrap()), "A"), "PG: fresh acquire => leader");
        assert!(acquire_or_renew(&Store::postgres(m.lock().unwrap()), "A"), "PG: renew => leader");
        // B refused while A fresh.
        assert!(!acquire_or_renew(&Store::postgres(m.lock().unwrap()), "B"), "PG: fresh lease held by A => B not leader");
        // Age A past TTL, B takes over, A loses.
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute(
                "UPDATE leader_lease SET last_seen = last_seen - ? WHERE scope='run-worker'",
                &crate::sql_params![LEASE_TTL_SECS + 10],
            )
            .expect("age lease");
        }
        assert!(acquire_or_renew(&Store::postgres(m.lock().unwrap()), "B"), "PG: expired lease => B takes over");
        assert!(!acquire_or_renew(&Store::postgres(m.lock().unwrap()), "A"), "PG: A lost the lease to B");
        // Exactly one row, held by B.
        let (n, holder): (i64, String) = Store::postgres(m.lock().unwrap())
            .query_row(
                "SELECT COUNT(*), MAX(instance_id) FROM leader_lease WHERE scope='run-worker'",
                &crate::sql_params![],
                |r| Ok((r.get_i64(0)?, r.get_str(1)?)),
            )
            .expect("count lease");
        assert_eq!(n, 1, "PG: single lease row");
        assert_eq!(holder, "B", "PG: held by B after takeover");
    }

    /// B5 — LEDGER MULTI-INSTANCE (no chain forks). Two "instances" (SEPARATE PG connections) hammer appends
    /// to the SAME shared ledger file, each serialising via `pg_advisory_xact_lock(hashtext(path))` inside a
    /// tx and re-reading the tail from disk (`ledger_append_standalone` — the same preimage the API verifies).
    /// Proves the SHA-256 chain stays INTACT (no fork, contiguous seq) under real cross-connection concurrency
    /// -> GET /api/ledger/verify would return {ok:true}. This is the code-level analogue of the docker-compose
    /// "drive runs/imports from BOTH instances then verify" check.
    #[test]
    fn pg_ledger_no_fork_under_advisory_lock() {
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_ledger] TEST_PG_URL unset — skipping");
                return;
            }
        };
        let path = std::env::temp_dir()
            .join(format!("forge-wavec-ledger-{}.jsonl", crate::gen_token()))
            .to_string_lossy()
            .into_owned();
        const N: i64 = 30;
        let handles: Vec<_> = (0..2)
            .map(|tid| {
                let url = url.clone();
                let path = path.clone();
                std::thread::spawn(move || {
                    let client = crate::store::connect_postgres(&url).expect("connect");
                    let m = std::sync::Mutex::new(client);
                    for i in 0..N {
                        let store = Store::postgres(m.lock().unwrap());
                        // SAME critical section as ha::with_ledger_lock: advisory xact lock (keyed on the
                        // shared path) + re-read tail from disk + append. A peer blocks until COMMIT.
                        let _ = store.with_tx(|tx| {
                            tx.execute(
                                "SELECT pg_advisory_xact_lock(hashtext(?))",
                                &crate::sql_params![path.as_str()],
                            )?;
                            let _ = crate::ledger_append_standalone(
                                &path,
                                "console.race",
                                &serde_json::json!({"t": tid, "i": i}),
                            );
                            Ok::<(), crate::store::StoreError>(())
                        });
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let v = crate::verify_ledger_chain(&path);
        let _ = std::fs::remove_file(&path);
        assert!(v.ok, "PG: chain intact under concurrent cross-instance appends (why={:?})", v.why);
        assert_eq!(v.entries, (2 * N) as usize, "PG: every append landed, contiguous SHA-256 chain, no fork");
    }

    /// FIX #17 — SINGLE-LOCK LEDGER SERIALISER, POOLED-CONNECTION RACE (the exact production geometry the old
    /// disjoint flock fallback broke). MODELS the partial-outage race: replica A holds a LIVE, PERSISTENT
    /// (pooled) PG connection, takes `pg_advisory_xact_lock`, and is MID-APPEND; replica B (a SEPARATE pooled
    /// connection) then tries to acquire the SAME advisory lock. With ONE authoritative mechanism, B's acquire
    /// MUST BLOCK until A COMMITs — B can NEVER enter the critical section while A is in it — so the two never
    /// read the same tail seq=N and both write seq=N+1 (the fork the flock path produced, because flock and
    /// the advisory lock are DISJOINT and don't mutually exclude).
    ///
    /// This is the precise scenario the FINDING describes (pooled connection alive on A while B falls to a
    /// second lock). Both appenders use PERSISTENT connections held for the whole test — NOT fresh-connect-
    /// per-attempt — reproducing the pool. Assertions: (a) MUTUAL EXCLUSION — when B finally acquires, A has
    /// already LEFT the critical section (`overlap` never set); (b) B genuinely BLOCKED on A's held lock (its
    /// acquire waited a meaningful fraction of A's hold); (c) NO FORK — the SHA-256 chain is contiguous
    /// (seq 1 then 2, verify {ok:true}), which is impossible if the two ever overlapped.
    #[test]
    fn pg_ledger_single_lock_blocks_pooled_second_appender() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_pooled_race] TEST_PG_URL unset — skipping");
                return;
            }
        };
        let path = std::env::temp_dir()
            .join(format!("forge-fix17-pooled-{}.jsonl", crate::gen_token()))
            .to_string_lossy()
            .into_owned();

        // `a_in_crit`: true while A holds the advisory lock AND is inside read-tail->append. `overlap`: set iff
        // B ever observes A still in the critical section at the instant B acquires the lock (i.e. the DISJOINT-
        // lock bug). `(tx_held, rx_held)`: A signals "I now hold the advisory lock" so B starts racing for it.
        let a_in_crit = Arc::new(AtomicBool::new(false));
        let overlap = Arc::new(AtomicBool::new(false));
        let (tx_held, rx_held) = std::sync::mpsc::channel::<()>();

        // Replica A: PERSISTENT pooled connection. Acquire the advisory xact lock, enter crit, append seq=1,
        // HOLD the lock ~1000 ms (so B's acquire has to block on it), leave crit, then COMMIT (releasing lock).
        let a = {
            let (url, path) = (url.clone(), path.clone());
            let (a_in_crit, tx_held) = (a_in_crit.clone(), tx_held);
            std::thread::spawn(move || {
                let client = crate::store::connect_postgres(&url).expect("A connect (pooled)");
                let m = std::sync::Mutex::new(client);
                Store::postgres(m.lock().unwrap())
                    .with_tx(|tx| {
                        tx.execute(
                            "SELECT pg_advisory_xact_lock(hashtext(?))",
                            &crate::sql_params![path.as_str()],
                        )?;
                        a_in_crit.store(true, Ordering::SeqCst);
                        let _ = tx_held.send(()); // lock is HELD -> tell B to start racing for the SAME lock.
                        let _ = crate::ledger_append_standalone(
                            &path,
                            "console.race",
                            &serde_json::json!({"replica": "A", "seq_intent": 1}),
                        );
                        // Hold the advisory lock across B's blocked acquire. 1000 ms (pas 250) : B doit
                        // d'abord se CONNECTER (spawn thread + connect_postgres, ~100-300 ms selon la machine/
                        // le runner) avant d'émettre son acquire, et ce délai grignote la fenêtre de hold. À
                        // 250 ms la fenêtre restante pouvait tomber sous le seuil de 100 ms (flaky, cf. échec
                        // "waited 53ms"). 1000 ms laisse une marge >700 ms même sur un connect lent -> le
                        // `waited >= 100ms` devient déterministe sans dépendre de la latence de connexion de B.
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        a_in_crit.store(false, Ordering::SeqCst); // leave crit BEFORE the COMMIT releases the lock.
                        Ok::<(), crate::store::StoreError>(())
                    })
                    .expect("A tx commits (advisory lock released here)");
            })
        };

        // Wait until A actually holds the lock, THEN race B for it.
        rx_held.recv().expect("A signalled the advisory lock is held");

        // Replica B: a DIFFERENT persistent pooled connection. Try to acquire the SAME advisory lock. With one
        // authoritative mechanism this BLOCKS until A COMMITs; the moment B holds it, A must have LEFT the crit
        // section. (Under the old disjoint flock path, B would have taken a DIFFERENT lock and appended
        // concurrently -> `overlap` set + seq collision.)
        let b = {
            let (url, path) = (url.clone(), path.clone());
            let (a_in_crit, overlap) = (a_in_crit.clone(), overlap.clone());
            std::thread::spawn(move || -> std::time::Duration {
                let client = crate::store::connect_postgres(&url).expect("B connect (pooled)");
                let m = std::sync::Mutex::new(client);
                let t0 = std::time::Instant::now();
                let waited = Store::postgres(m.lock().unwrap())
                    .with_tx(|tx| {
                        tx.execute(
                            "SELECT pg_advisory_xact_lock(hashtext(?))",
                            &crate::sql_params![path.as_str()],
                        )?;
                        let waited = t0.elapsed();
                        // The ONLY way to be here is A already COMMITted (single lock) -> A must be out of crit.
                        if a_in_crit.load(Ordering::SeqCst) {
                            overlap.store(true, Ordering::SeqCst);
                        }
                        let _ = crate::ledger_append_standalone(
                            &path,
                            "console.race",
                            &serde_json::json!({"replica": "B", "seq_intent": 2}),
                        );
                        Ok::<std::time::Duration, crate::store::StoreError>(waited)
                    })
                    .expect("B tx commits");
                waited
            })
        };

        a.join().unwrap();
        let waited = b.join().unwrap();

        assert!(
            !overlap.load(Ordering::SeqCst),
            "SINGLE LOCK: B must NOT enter the critical section while A holds it (no disjoint flock window)"
        );
        assert!(
            waited >= std::time::Duration::from_millis(100),
            "B's advisory acquire BLOCKED on A's held lock (serialised, not concurrent) — waited {waited:?}"
        );

        let v = crate::verify_ledger_chain(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
        assert!(v.ok, "no fork: contiguous SHA-256 chain after serialised appends (why={:?})", v.why);
        assert_eq!(v.entries, 2, "exactly two appends, serialised seq 1 then 2 — no tail re-read collision");
    }

    /// B7 — PRESENCE PG TABLE (rosters span instances). Exercises the exact SQL the PG-backed
    /// `PresenceRegistry` runs: join (upsert), snapshot (SELECT, incl. a NULL engagement), lazy-TTL GC
    /// (DELETE stale), touch (UPDATE last_seen), leave (DELETE). A snapshot taken via ANY connection sees the
    /// rows written by BOTH "instances" (inst-A + inst-B) -> the roster spans replicas.
    #[test]
    fn pg_presence_table_roundtrip() {
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_presence] TEST_PG_URL unset — skipping");
                return;
            }
        };
        let client = crate::store::connect_postgres(&url).expect("connect");
        let m = std::sync::Mutex::new(client);
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute_batch("DROP TABLE IF EXISTS presence").expect("drop");
            s.execute_batch(
                "CREATE TABLE presence(conn_id TEXT PRIMARY KEY, login TEXT NOT NULL, role TEXT NOT NULL, \
                 engagement_id BIGINT, instance_id TEXT, since BIGINT, last_seen BIGINT)",
            )
            .expect("create");
        }
        let join = |cid: &str, login: &str, role: &str, eng: Option<i64>, inst: &str, ts: i64| {
            let s = Store::postgres(m.lock().unwrap());
            s.execute(
                "INSERT INTO presence(conn_id,login,role,engagement_id,instance_id,since,last_seen) \
                 VALUES(?,?,?,?,?,?,?) ON CONFLICT(conn_id) DO UPDATE SET last_seen=excluded.last_seen",
                &crate::sql_params![cid, login, role, eng, inst, ts, ts],
            )
            .expect("join");
        };
        // instance A hosts alice(eng2); instance B hosts bob(no engagement).
        join("c1", "alice", "operator", Some(2), "inst-A", 100);
        join("c2", "bob", "viewer", None, "inst-B", 101);
        // snapshot (either connection) sees BOTH instances' operators.
        let rows: Vec<(String, Option<i64>, String)> = {
            let s = Store::postgres(m.lock().unwrap());
            s.query(
                "SELECT login, engagement_id, instance_id FROM presence ORDER BY login",
                &crate::sql_params![],
                |r| Ok((r.get_str(0)?, r.get_opt_i64(1)?, r.get_str(2)?)),
            )
            .expect("snapshot")
        };
        assert_eq!(rows.len(), 2, "roster spans both instances");
        assert_eq!(rows[0], ("alice".to_string(), Some(2), "inst-A".to_string()));
        assert_eq!(rows[1], ("bob".to_string(), None, "inst-B".to_string()));
        // touch bob (UPDATE), leave alice (DELETE).
        {
            let s = Store::postgres(m.lock().unwrap());
            assert_eq!(
                s.execute("UPDATE presence SET last_seen=? WHERE login=?", &crate::sql_params![200i64, "bob"]).unwrap(),
                1,
                "touch refreshes exactly bob's row"
            );
            s.execute("DELETE FROM presence WHERE conn_id=?", &crate::sql_params!["c1"]).expect("leave");
        }
        let remaining: i64 = {
            let s = Store::postgres(m.lock().unwrap());
            s.query_row("SELECT count(*) FROM presence", &crate::sql_params![], |r| r.get_i64(0)).unwrap()
        };
        assert_eq!(remaining, 1, "leave removed alice; bob remains");
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute_batch("DROP TABLE presence").expect("cleanup");
        }
    }

    /// B6 — CROSS-INSTANCE CACHE INVALIDATION (MONOTONIC epoch increment). Proves the exact atomic-increment
    /// SQL `App::bump_cache_epoch` runs: every bump STRICTLY increases `cache_epoch`, so TWO bumps in the SAME
    /// second still yield distinct values (the wall-clock-stamp bug this fix replaces would collide). A peer
    /// reads a different value after each bump => reload. Uses a scoped throwaway table (same shape as the
    /// real `settings`) to avoid clobbering the shared row.
    #[test]
    fn pg_cache_epoch_monotonic_increment() {
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_cache_epoch] TEST_PG_URL unset — skipping");
                return;
            }
        };
        let client = crate::store::connect_postgres(&url).expect("connect");
        let m = std::sync::Mutex::new(client);
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute_batch("DROP TABLE IF EXISTS settings_wavec").expect("drop");
            s.execute_batch("CREATE TABLE settings_wavec(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated TEXT NOT NULL)")
                .expect("create");
        }
        // The EXACT production increment (table name swapped for the throwaway) — atomic UPDATE, no params.
        let bump = || {
            let s = Store::postgres(m.lock().unwrap());
            s.execute(
                "INSERT INTO settings_wavec(key,value,updated) VALUES('cache_epoch','1',CAST(CURRENT_TIMESTAMP AS TEXT)) \
                 ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(settings_wavec.value AS INTEGER) + 1 AS TEXT), \
                   updated=CAST(CURRENT_TIMESTAMP AS TEXT)",
                &crate::sql_params![],
            )
            .expect("bump");
        };
        let read = || -> i64 {
            let s = Store::postgres(m.lock().unwrap());
            s.query_row("SELECT value FROM settings_wavec WHERE key='cache_epoch'", &crate::sql_params![], |r| r.get_str(0))
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0)
        };
        assert_eq!(read(), 0, "unset epoch reads 0 (no spurious reload at boot)");
        bump();
        assert_eq!(read(), 1, "first bump seeds at 1");
        // TWO bumps back-to-back (same wall-clock second): a seconds-stamp would collide; the counter must not.
        bump();
        bump();
        assert_eq!(read(), 3, "two same-second bumps strictly increase (2 -> 3) — no staleness window");
        {
            let s = Store::postgres(m.lock().unwrap());
            s.execute_batch("DROP TABLE settings_wavec").expect("cleanup");
        }
    }

    /// FIX #17 — LEDGER NO-FORK UNDER A POSTGRES OUTAGE, SINGLE-LOCK (the docker-compose scenario, code-level
    /// analogue). Two "instances" (separate PG connections, fresh-connected per attempt like `app.store()`'s
    /// pool healing) hammer appends to the SAME shared ledger file through the EXACT two-tier `with_ledger_lock`
    /// logic: (1) advisory-lock tx w/ bounded backoff, then (2) FAIL-CLOSED (refuse/defer) — there is NO flock
    /// tier, so no disjoint window. Partway through, this test STOPS the Postgres container (the outage the
    /// task drives with `docker stop`), then RESTARTS it. During the outage, appends whose connect stays down
    /// across the retry budget DEFER (fail-closed, dropped) rather than take a second lock; once PG heals they
    /// resume under the advisory lock. Asserts the SHA-256 chain stays INTACT (no fork, contiguous seq,
    /// verify {ok:true}) across the whole outage, that every LANDED append is exactly the advisory-serialised
    /// count, and that the outage actually exercised the fail-closed path (`deferred > 0`). Then proves the OLD
    /// (unlocked/disjoint) behaviour COULD fork by constructing the two-writers-same-tail state and showing
    /// verify catches it.
    ///
    /// Gated on `FORGE_OUTAGE_PG_CONTAINER` (docker container name of the PG under `TEST_PG_URL`) so normal
    /// `cargo test` skips it — it manipulates a real container. Run it explicitly with both env vars set.
    #[test]
    fn pg_ledger_no_fork_under_pg_outage() {
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("[pg_outage] TEST_PG_URL unset — skipping");
                return;
            }
        };
        let container = match std::env::var("FORGE_OUTAGE_PG_CONTAINER") {
            Ok(c) if !c.is_empty() => c,
            _ => {
                eprintln!("[pg_outage] FORGE_OUTAGE_PG_CONTAINER unset — skipping (set it to the PG docker container name)");
                return;
            }
        };
        let docker = |args: &[&str]| {
            std::process::Command::new("docker").args(args).output().map(|o| o.status.success()).unwrap_or(false)
        };
        let pg_ready = |u: &str| crate::store::connect_postgres(u).is_ok();

        let path = std::env::temp_dir()
            .join(format!("forge-outage-ledger-{}.jsonl", crate::gen_token()))
            .to_string_lossy()
            .into_owned();

        // The EXACT two-tier critical section of `ha::with_ledger_lock`, per-append (fresh connect each
        // attempt so a healed PG resumes the advisory path — like the pool). The SOLE serialiser is the
        // advisory lock; if PG stays down across the whole retry budget, we FAIL-CLOSED (defer) — never a
        // second/disjoint lock. Returns which tier landed (or "deferred").
        let url_c = url.clone();
        let path_c = path.clone();
        let append_one = move |tid: i64, i: i64| -> &'static str {
            let detail = serde_json::json!({"t": tid, "i": i});
            // TIER 1 — advisory lock inside a tx, retried with the SAME bounded backoff as production.
            for (attempt, backoff_ms) in std::iter::once(0u64)
                .chain(LEDGER_LOCK_RETRY_BACKOFF_MS.iter().copied())
                .enumerate()
            {
                if attempt > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                }
                let client = match crate::store::connect_postgres(&url_c) {
                    Ok(c) => c,
                    Err(_) => continue, // PG down -> retry, then FAIL-CLOSED (no second lock to fall to).
                };
                let m = std::sync::Mutex::new(client);
                let mut ran = false;
                let res = Store::postgres(m.lock().unwrap()).with_tx(|tx| {
                    tx.execute("SELECT pg_advisory_xact_lock(hashtext(?))", &crate::sql_params![path_c.as_str()])?;
                    let _ = crate::ledger_append_standalone(&path_c, "console.race", &detail);
                    ran = true;
                    Ok::<(), crate::store::StoreError>(())
                });
                if res.is_ok() {
                    return "advisory";
                }
                if ran {
                    return "advisory"; // appended under the held lock; only COMMIT failed.
                }
            }
            // TIER 2 — FAIL-CLOSED: PG unreachable across the whole retry budget. REFUSE the append (deferred,
            // NOT written, NOT via any second lock). Integrity > availability: a dropped entry beats a fork.
            "deferred"
        };
        let append_one = std::sync::Arc::new(append_one);

        const N: i64 = 60;
        let tally = std::sync::Arc::new(std::sync::Mutex::new((0usize, 0usize))); // advisory, deferred
        let handles: Vec<_> = (0..2)
            .map(|tid| {
                let append_one = append_one.clone();
                let tally = tally.clone();
                std::thread::spawn(move || {
                    for i in 0..N {
                        let tier = append_one(tid, i);
                        let mut t = tally.lock().unwrap();
                        match tier {
                            "advisory" => t.0 += 1,
                            _ => t.1 += 1,
                        }
                        drop(t);
                        std::thread::sleep(std::time::Duration::from_millis(8));
                    }
                })
            })
            .collect();

        // Drive the OUTAGE mid-run: stop PG, hold it down, restart, wait ready.
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(docker(&["stop", &container]), "docker stop {container}");
        eprintln!("[pg_outage] Postgres STOPPED — appends must now FAIL-CLOSED (defer), never fork.");
        std::thread::sleep(std::time::Duration::from_millis(700));
        assert!(docker(&["start", &container]), "docker start {container}");
        for _ in 0..100 {
            if pg_ready(&url) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        eprintln!("[pg_outage] Postgres RESTARTED.");

        for h in handles {
            h.join().unwrap();
        }

        let (adv, defr) = *tally.lock().unwrap();
        eprintln!("[pg_outage] appends: advisory={adv} deferred={defr} (total={})", adv + defr);
        let v = crate::verify_ledger_chain(&path);
        eprintln!("[pg_outage] verify: ok={} entries={} why={:?}", v.ok, v.entries, v.why);
        assert!(v.ok, "chain INTACT across the PG outage (no fork); why={:?}", v.why);
        assert_eq!(adv + defr, (2 * N) as usize, "every append was accounted for (advisory-landed or deferred)");
        assert_eq!(v.entries, adv, "exactly the advisory-serialised appends landed — deferred entries never wrote");
        assert!(defr > 0, "the outage exercised the FAIL-CLOSED path (some appends were deferred, none forked)");

        // ── CONTRAST: the OLD unlocked path COULD fork. Two writers reading the SAME tail then both writing
        //    seq=N is what an unlocked concurrent append produces; verify DETECTS it (ok:false). We construct
        //    that exact state to prove the invariant verify enforces (and thus what the fix prevents).
        let fork_path = format!("{path}.forked");
        // Two entries both claiming seq=1 off the empty tail (prev = 64 zeros) — a genuine fork.
        let prev0 = "0".repeat(64);
        for who in ["A", "B"] {
            let detail = serde_json::json!({"replica": who});
            let ts = "@0".to_string();
            let preimage = format!("{prev0}|1|{ts}|console.race|{}", crate::canon_json(&detail));
            let hash = crate::sha_hex(&preimage);
            let rec = serde_json::json!({
                "seq": 1, "ts": ts, "kind": "console.race", "detail": detail,
                "prev": prev0, "hash": hash, "alg": "sha256-console", "sig": ""
            });
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&fork_path).unwrap();
            writeln!(f, "{}", crate::canon_json(&rec)).unwrap();
        }
        let vf = crate::verify_ledger_chain(&fork_path);
        eprintln!("[pg_outage] OLD-behaviour forked chain -> verify ok={} why={:?}", vf.ok, vf.why);
        assert!(!vf.ok, "a forked chain (two writers, same tail) is REJECTED by verify — this is what the fix prevents");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
        let _ = std::fs::remove_file(&fork_path);
    }

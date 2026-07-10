// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — HIGH AVAILABILITY (#10) Wave A : FOUNDATION (leader lease + heartbeat), INERT.
//!
//! Multi-instance HA runs N console replicas behind a load-balancer, all sharing ONE Postgres store.
//! Some work must run on EXACTLY ONE replica at a time (the future run-worker / reconcile / scheduled
//! backup). This module provides the SUBSTRATE for that — a SINGLE-ROW leader lease renewed by a
//! per-instance heartbeat — but wires NO consumer yet: `reconcile_runs`/run-create/the backup scheduler
//! are UNCHANGED this wave. It only publishes `leader`/`instance_id` on `/health`.
//!
//! OPT-IN + FAIL-CLOSED : HA engages only when `FORGE_HA` is truthy AND the ACTIVE store is Postgres
//! (`App.pg.is_some()`). On SQLite a shared lease is meaningless (each replica has its OWN file) and
//! UNSAFE, so boot FAILS CLOSED if `FORGE_HA` is set without Postgres (see `main.rs`). Because HA can
//! only ever run on Postgres, this whole module is gated on the `store-postgres` feature EXCEPT the
//! pure, dialect-portable lease step (`acquire_or_renew` + its SQL/TTL), which is ALSO compiled under
//! `test` so the single-statement acquire/renew/takeover logic is exercised on SQLite by `cargo test`.
//!
//! ATOMICITY : acquire and renew are the SAME statement — an `INSERT … ON CONFLICT(scope) DO UPDATE …
//! WHERE (I already hold it) OR (the lease expired) RETURNING instance_id`. A row comes back IFF the
//! upsert wrote, and the `DO UPDATE SET instance_id=me` makes the returned holder ALWAYS me when a row is
//! returned; a still-fresh lease held by someone else yields NO row (⇒ not leader). One round-trip, no
//! read-modify-write race between replicas. Routed through the store seam so it is dialect-portable
//! (`?`→`$n`, same table on both backends).

/// The atomic acquire-or-renew statement. `scope='run-worker'` is the only lease today. Placeholders
//
// LEASE CORE — gated on `store-postgres` (the backend HA runs on) OR `test` (the dialect-portable step is
// exercised on SQLite by `cargo test`). The community NON-test build compiles NONE of it (it is unused
// there — the heartbeat that drives it is PG-only), so it never becomes dead code.
#[cfg(any(feature = "store-postgres", test))]
/// (SQLite `?` style; the seam rewrites them to `$n` on Postgres) bind, IN ORDER:
///   1 me, 2 now, 3 now            — VALUES(scope, instance_id, acquired, last_seen) on a FRESH insert
///   4 me                          — DO UPDATE SET instance_id = me (I take/keep the lease)
///   5 me, 6 now                   — acquired = CASE WHEN holder was ALREADY me THEN keep it ELSE now (takeover time)
///   7 now                         — SET last_seen = now (heartbeat freshness)
///   8 me, 9 cutoff                — WHERE I already hold it OR the current lease is stale (last_seen < now-TTL)
/// The upsert updates (and thus RETURNs a row) ONLY when the WHERE matches — otherwise a fresh lease is
/// held by another instance and RETURNING yields no row. `RETURNING instance_id` is read as column 0.
pub(crate) const LEASE_UPSERT_SQL: &str = "\
INSERT INTO leader_lease(scope, instance_id, acquired, last_seen) \
VALUES('run-worker', ?, ?, ?) \
ON CONFLICT(scope) DO UPDATE SET \
  instance_id = ?, \
  acquired = CASE WHEN leader_lease.instance_id = ? THEN leader_lease.acquired ELSE ? END, \
  last_seen = ? \
WHERE leader_lease.instance_id = ? OR leader_lease.last_seen < ? \
RETURNING instance_id";

/// Lease time-to-live (seconds). A lease not renewed within this window is considered EXPIRED and may be
/// taken over by another instance. Aligned with `presence::PRESENCE_TTL_SECS` (45s) — the same
/// "liveness window" scale used elsewhere in the console.
#[cfg(any(feature = "store-postgres", test))]
pub(crate) const LEASE_TTL_SECS: i64 = 45;

/// Heartbeat cadence (seconds) — renew every ~TTL/3 so two consecutive missed ticks still stay within the
/// TTL (no leadership flap on a transient hiccup). PG-only: the ticker only runs when HA is engaged.
#[cfg(feature = "store-postgres")]
pub(crate) const HEARTBEAT_TICK_SECS: u64 = 15;

/// Run ONE atomic acquire-or-renew of the `run-worker` lease for `instance_id` and return whether THIS
/// instance now holds it. `now`/`cutoff` are bound values (not SQL `now()`), so the statement is fully
/// deterministic in its parameters. Routed via the store seam (`query_opt`) so it works on both backends:
/// a returned row (holder == me, always, since the DO UPDATE forces `instance_id=me`) ⇒ leader; NO row
/// (a still-fresh lease held elsewhere) ⇒ not leader. Any DB error ⇒ NOT leader (fail-closed).
///
/// On Postgres `query_opt` rides `pg_run_read` (single-shot reconnect+retry on a broken connection). That
/// is SOUND here even though this is a write: the upsert is IDEMPOTENT in its bound params (`me`/`now`/
/// `cutoff` are fixed for the call), so re-running it after a transient reconnect converges to the same
/// single row — never a duplicate (the PK is `scope`).
#[cfg(any(feature = "store-postgres", test))]
pub(crate) fn acquire_or_renew(store: &crate::store::Store, instance_id: &str) -> bool {
    let now = crate::now_epoch();
    let cutoff = now - LEASE_TTL_SECS;
    let holder: Option<String> = store
        .query_opt(
            LEASE_UPSERT_SQL,
            &crate::sql_params![
                instance_id, now, now, // VALUES(scope,instance_id,acquired,last_seen) — fresh insert
                instance_id,           // DO UPDATE SET instance_id = me
                instance_id, now,      // acquired = CASE WHEN holder=me THEN keep ELSE now
                now,                   // SET last_seen = now
                instance_id, cutoff    // WHERE holder=me OR last_seen < now-TTL
            ],
            |r| r.get_str(0),
        )
        .unwrap_or(None);
    holder.as_deref() == Some(instance_id)
}

/// Is HA ENGAGED for this process? The once-at-boot predicate `flags::env_truthy("FORGE_HA") &&
/// pg.is_some()`, cached on `App.ha` at construction (see `main.rs`). When false the console is a single
/// instance and everything runs locally as today.
#[cfg(feature = "store-postgres")]
pub(crate) fn ha_enabled(app: &crate::App) -> bool {
    app.ha
}

/// Am I the leader? TRUE when HA is NOT engaged (single instance is trivially always "leader" — all work
/// runs locally, exactly as the community build) OR when this instance currently holds the lease
/// (`App.is_leader`, refreshed by the heartbeat). Wave B gates the boot side-effects (reconcile/populate)
/// and the run-leader (enqueue/claim/spawn) on this predicate.
#[cfg(feature = "store-postgres")]
pub(crate) fn is_leader(app: &crate::App) -> bool {
    !ha_enabled(app) || app.is_leader.load(std::sync::atomic::Ordering::SeqCst)
}

// ── PORTABLE MIRRORS (community build, no `store-postgres` feature) ───────────────────────────────
// HA is only ever engaged on a Postgres store, so the DEFAULT/community binary compiles NONE of the HA
// fields (`App.ha`/`is_leader`/`instance_id` don't exist). These const-folding mirrors let the SHARED
// run-flow code (`runs::run_create` gate, `claim_and_spawn`, `reconcile_runs` scoping) reference
// `ha::ha_enabled`/`ha::is_leader`/`ha::my_instance_id` UNCONDITIONALLY: in community they collapse to
// "HA off / always leader / no owner id", so the compiler prunes the HA branches and the community
// binary stays byte-identical to today (direct spawn, reconcile-all, local cancel).

/// Community mirror of [`ha_enabled`] — HA is impossible without the Postgres backend, so ALWAYS false.
#[cfg(not(feature = "store-postgres"))]
pub(crate) fn ha_enabled(_app: &crate::App) -> bool {
    false
}

/// Community mirror of [`is_leader`] — a single unsynchronised instance is trivially always the leader
/// (all work runs locally, exactly as today). ALWAYS true.
#[cfg(not(feature = "store-postgres"))]
pub(crate) fn is_leader(_app: &crate::App) -> bool {
    true
}

/// This instance's OWNER identity for `run_job.owner_instance`, or `None` when ownership is not tracked.
/// `Some(instance_id)` ONLY when HA is engaged (`app.ha`) — then every run this instance spawns is stamped
/// with its id so reconcile can owner-scope reaping. `None` when HA is OFF (single-instance / non-HA
/// Postgres) so `owner_instance` stays NULL and reconcile reaps ALL running exactly as today. PG-only arm.
#[cfg(feature = "store-postgres")]
pub(crate) fn my_instance_id(app: &crate::App) -> Option<String> {
    if app.ha {
        Some((*app.instance_id).clone())
    } else {
        None
    }
}

/// Community mirror of [`my_instance_id`] — no HA, no owner id tracked. ALWAYS `None` (owner_instance NULL,
/// reconcile-all preserved).
#[cfg(not(feature = "store-postgres"))]
pub(crate) fn my_instance_id(_app: &crate::App) -> Option<String> {
    None
}

/// Heartbeat ticker (spawned only when HA is engaged, see `main.rs`). Every `HEARTBEAT_TICK_SECS` it
/// renews/acquires the lease via the store seam and publishes the result on `App.is_leader` so `/health`
/// (and, later, the gated consumers) can read it. The `Store` guard is `!Send` and is scoped to the sync
/// block — it is DROPPED before the next `.await`, so this future stays `Send` (spawnable) and never holds
/// a DB lock across a suspension point.
#[cfg(feature = "store-postgres")]
pub(crate) async fn heartbeat_loop(app: crate::App) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(HEARTBEAT_TICK_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let leader = {
            let store = app.store();
            // (Fix #3) LIVENESS PAR-INSTANCE : CHAQUE réplica (leader OU non) rafraîchit SON `last_seen` dans
            // `ha_instance` à chaque tick. C'est ce qui permet au failover-reap du leader de distinguer un
            // owner MORT (pas de heartbeat frais) d'un pair VIVANT-MAIS-DEMOTED (flap) — et de ne JAMAIS
            // flipper 'failed' le run d'un pair encore vivant. Upsert idempoté par la PK instance_id.
            let now = crate::now_epoch();
            let _ = store.execute(
                "INSERT INTO ha_instance(instance_id, last_seen) VALUES(?, ?) \
                 ON CONFLICT(instance_id) DO UPDATE SET last_seen = ?",
                &crate::sql_params![app.instance_id.as_str(), now, now],
            );
            let leader = acquire_or_renew(&store, &app.instance_id);
            drop(store); // release the single-tick DB session after the last read (heartbeat + acquire done)
            leader
        };
        app.is_leader.store(leader, std::sync::atomic::Ordering::SeqCst);
    }
}

// ================================================================================================
// WAVE C — multi-instance completion. Everything below is gated on `ha_enabled(app)` so the community
// single-instance build stays BYTE-IDENTICAL (the HA arms are const-folded away, the community mirrors
// are pass-throughs / no-ops).
// ================================================================================================

/// Fixed advisory-lock key for the COLD-START SCHEMA-INIT critical section (Wave-B LOW fix). Two replicas
/// booting a FRESH cluster both run `execute_batch(PG_SCHEMA)` + the id=1 seeders simultaneously; `CREATE
/// … IF NOT EXISTS` and `SELECT COUNT(*) … then INSERT id=1` are NOT concurrency-safe on the shared PG
/// catalog (one replica panics on a duplicate `pg_type`/`pg_class` tuple or a duplicate PK). Holding this
/// cluster-global `pg_advisory_xact_lock` around the whole DDL+seed block SERIALIZES init: only one replica
/// applies DDL/seeds at a time, the others wait then see everything already exists (idempotent). Arbitrary
/// stable 64-bit constant (namespaced away from any hashtext(ledger_path) key by being fixed & explicit).
#[cfg(feature = "store-postgres")]
pub(crate) const BOOT_DDL_LOCK_KEY: i64 = 0x_F0_67_65_DD_10_00_01; // "Forge" DDL lock #1

/// Cadence (seconds) of the cross-instance cache-invalidation poll (B6). Each instance polls the shared
/// `settings.cache_epoch` and reloads its local caches when it changed on a peer. Short enough that a
/// detection-source / user mutation on instance A is reflected on instance B within a few seconds.
#[cfg(feature = "store-postgres")]
pub(crate) const CACHE_POLL_SECS: u64 = 4;

/// Bounded backoff (milliseconds) for RE-ACQUIRING the ledger advisory lock when the first attempt fails
/// (PG connection blip). PG blips recover fast, so a few short sleeps ride out a reconnect without giving up
/// the single-writer guarantee. Total worst case ≈ sum ≈ 400 ms — comparable to the fsync this call already
/// does — before we fall back to the cross-instance FILE lock. Kept small: INTEGRITY over latency.
#[cfg(feature = "store-postgres")]
pub(crate) const LEDGER_LOCK_RETRY_BACKOFF_MS: &[u64] = &[25, 50, 75, 100, 150];

/// FALLBACK cross-instance serialisation when Postgres is UNREACHABLE: an exclusive `flock(LOCK_EX)` on a
/// sidecar `<ledger>.lock` file living on the SAME shared RWX volume as the ledger. `flock` is associated
/// with the OPEN FILE DESCRIPTION (not the append fd) so it serialises appends ACROSS instances/processes
/// that mount the same volume — a peer appending to the same ledger BLOCKS on its own `LOCK_EX` until we
/// release ours. Runs `g` EXACTLY ONCE while the lock is held; releases on `LOCK_UN` + close.
///
/// Returns `true` iff `g` ran under a held lock. `false` (could not open/lock the sidecar) => the caller
/// must NOT append unlocked (fail-closed on integrity — a deferred entry beats a forked chain).
///
/// NFS CAVEAT: `flock` is reliable on LOCAL / overlay / bind-mounted / tmpfs volumes (the docker-compose &
/// k8s shared ledger volume). On some ancient/misconfigured NFS `flock` can degrade to a no-op; the shipped
/// compose/k8s deployment uses a local shared volume where `flock` is authoritative (validated). If you run
/// the ledger on NFS, mount with `-o local_lock=all` (or accept the advisory-lock primary path only).
#[cfg(feature = "store-postgres")]
fn with_ledger_flock(path: &str, g: impl FnOnce()) -> bool {
    use std::os::unix::io::AsRawFd;
    let lock_path = format!("{path}.lock");
    if let Some(parent) = std::path::Path::new(&lock_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Sidecar lock file on the shared volume. Separate from the append fd so flock never interferes with the
    // O_APPEND write itself.
    let file = match std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&lock_path) {
        Ok(f) => f,
        Err(_) => return false, // cannot create the sidecar -> fail-closed (no unlocked append)
    };
    let fd = file.as_raw_fd();
    // Blocking EXCLUSIVE lock: waits until we hold it cluster-wide on the shared volume.
    // SAFETY: `fd` is a valid open descriptor owned by `file` for the whole call.
    if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
        return false; // flock failed -> fail-closed (do NOT append unlocked)
    }
    g();
    // Explicit unlock then drop; close() would release too, but be deterministic about ordering.
    // SAFETY: same valid `fd`.
    unsafe {
        libc::flock(fd, libc::LOCK_UN);
    }
    drop(file);
    true
}

/// B5 — LEDGER MULTI-INSTANCE (no chain forks). Run the ledger append critical section `f` (read-tail ->
/// compute -> append) under a CROSS-INSTANCE lock so two replicas never read the same tail hash and both
/// append (which would fork the SHA-256 chain and break /api/ledger/verify). Under HA we take a PG
/// `pg_advisory_xact_lock(hashtext(path))` — cluster-global, keyed on the ledger file path — inside a short
/// transaction; the caller invalidates its (possibly stale) head cache and re-reads the tail from the
/// SHARED file INSIDE this lock. Single writer at a time => the existing in-proc `ledger_lock` + preimage/
/// hash stay correct and byte-identical, so verify is unchanged; zero forks by construction.
///
/// INTEGRITY > AVAILABILITY (tamper-evident ledger). `f` NEVER runs UNLOCKED — a fork is worse than a
/// deferred entry. Path selection:
///   1. PRIMARY — advisory lock inside a tx, RETRIED with a short bounded backoff ([`LEDGER_LOCK_RETRY_BACKOFF_MS`])
///      to ride out a PG connection blip. `f` runs inside the tx while the cluster-global lock is held.
///   2. FALLBACK — PG still unreachable after the retries: serialise cross-instance via `flock(LOCK_EX)` on a
///      sidecar lock file on the SHARED volume ([`with_ledger_flock`]). During a full PG outage EVERY replica
///      converges on this same file lock, so appends stay serialised (single writer) — no fork, no data loss.
///   3. FAIL-CLOSED — even the file lock is unavailable (sidecar cannot be created/locked): REFUSE the append
///      (the entry is DEFERRED, not forked). The chain stays contiguous and /api/ledger/verify stays {ok:true};
///      the missing entry is the integrity-preserving outcome under a total lock outage.
///
/// `f` runs AT MOST ONCE across all paths (guarded by `slot.take()`). Single-instance (!ha): pure
/// pass-through — the in-proc `ledger_lock` alone is authoritative, exactly as today.
#[cfg(feature = "store-postgres")]
pub(crate) fn with_ledger_lock(app: &crate::App, path: &str, f: impl FnOnce()) {
    if !ha_enabled(app) {
        f();
        return;
    }

    let mut slot = Some(f);
    // 1) PRIMARY: advisory-lock inside a tx, retried with bounded backoff on a transient PG failure.
    for (attempt, backoff_ms) in std::iter::once(0u64)
        .chain(LEDGER_LOCK_RETRY_BACKOFF_MS.iter().copied())
        .enumerate()
    {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
        }
        let res = (app.store()).with_tx(|tx| {
            // Cluster-global advisory lock keyed on the ledger path; auto-released at COMMIT/ROLLBACK. A peer
            // appending to the SAME file blocks here until we commit -> serialised single writer.
            tx.execute("SELECT pg_advisory_xact_lock(hashtext(?))", &crate::sql_params![path])?;
            if let Some(g) = slot.take() {
                g();
            }
            Ok::<(), crate::store::StoreError>(())
        });
        if res.is_ok() {
            return; // appended under the advisory lock (released at COMMIT).
        }
        // with_tx failed. If `slot` is now empty, `f` ALREADY ran while the lock was held (only COMMIT
        // failed afterwards) -> it was serialised; do NOT re-run. Otherwise BEGIN/lock failed before `f`
        // ran -> retry (or fall through to the file-lock fallback).
        if slot.is_none() {
            return;
        }
    }

    // 2) FALLBACK: PG stayed unreachable across every retry. Do NOT append unlocked — serialise
    //    cross-instance via a shared-volume FILE lock instead so the outage never forks the chain.
    if let Some(g) = slot.take() {
        if !with_ledger_flock(path, g) {
            // 3) FAIL-CLOSED: neither PG nor the file lock is available -> REFUSE the append (deferred, not
            //    forked). The entry is dropped THIS call; the tamper-evident chain stays contiguous & verifiable.
            eprintln!(
                "[forge-console] LEDGER TEMPORARILY UNAVAILABLE — Postgres unreachable and flock fallback \
                 failed on '{path}.lock'; audit entry DEFERRED (integrity > availability, no unlocked fork)."
            );
        }
    }
}

/// Community mirror of [`with_ledger_lock`] — HA is impossible without Postgres, so the ledger is never
/// shared cross-instance: run `f` directly (the in-proc `ledger_lock` is authoritative). Byte-identical.
#[cfg(not(feature = "store-postgres"))]
pub(crate) fn with_ledger_lock(_app: &crate::App, _path: &str, f: impl FnOnce()) {
    f();
}

/// B6 — CROSS-INSTANCE CACHE INVALIDATION (poll). Spawned once per instance when HA is engaged. Polls the
/// shared `settings.cache_epoch` every [`CACHE_POLL_SECS`]; when a PEER bumped it (a detection-source /
/// user create-disable-role-delete mutation calls `App::bump_cache_epoch`), reloads THIS instance's local
/// caches via the SAME single-call fns used locally today (`reload_detection_source` +
/// `recompute_auth_required`) — they already do the right thing, just triggered by a remote change here.
/// Reloading both on any bump is cheap + idempotent (up-to-poll staleness, acceptable for v1). The `Store`
/// guard is `!Send` and scoped to the sync method bodies (dropped before every `.await`), so this future
/// stays `Send`/spawnable. Single-instance (!ha): never spawned — caches reload locally as today.
#[cfg(feature = "store-postgres")]
pub(crate) async fn cache_poll_loop(app: crate::App) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(CACHE_POLL_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Seed with the epoch observed at boot so we only reload on a CHANGE (not once spuriously at start).
    let mut last = app.current_cache_epoch();
    loop {
        ticker.tick().await;
        let epoch = app.current_cache_epoch();
        if epoch != last {
            last = epoch;
            app.reload_detection_source();
            app.recompute_auth_required();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    /// Fresh in-memory SQLite with the base SCHEMA (which now carries `leader_lease`), wrapped in a Mutex
    /// so we can hand `Store::sqlite` a held guard per call (mirrors `App::store()`'s held-guard model).
    fn mem() -> std::sync::Mutex<rusqlite::Connection> {
        let conn = rusqlite::Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        std::sync::Mutex::new(conn)
    }

    /// The full lease lifecycle on SQLite: fresh acquire ⇒ leader; renew by holder ⇒ leader; a second
    /// instance is REFUSED while the lease is fresh; after the lease ages past the TTL the second instance
    /// TAKES OVER; the former holder then loses it — and there is always EXACTLY ONE row.
    #[test]
    fn acquire_renew_takeover_single_row() {
        let m = mem();
        // A acquires (fresh) -> leader.
        assert!(acquire_or_renew(&Store::sqlite(m.lock().unwrap()), "A"), "fresh acquire => leader");
        // A renews -> still leader (acquired must be PRESERVED across a renew).
        let acquired_a: i64 = Store::sqlite(m.lock().unwrap())
            .query_row("SELECT acquired FROM leader_lease WHERE scope='run-worker'", &crate::sql_params![], |r| r.get_i64(0))
            .unwrap();
        assert!(acquire_or_renew(&Store::sqlite(m.lock().unwrap()), "A"), "renew by same holder => leader");
        let acquired_a2: i64 = Store::sqlite(m.lock().unwrap())
            .query_row("SELECT acquired FROM leader_lease WHERE scope='run-worker'", &crate::sql_params![], |r| r.get_i64(0))
            .unwrap();
        assert_eq!(acquired_a, acquired_a2, "renew keeps the original acquired time");

        // B is refused while A's lease is fresh.
        assert!(!acquire_or_renew(&Store::sqlite(m.lock().unwrap()), "B"), "fresh lease held by A => B not leader");

        // Age A's lease past the TTL, then B takes over.
        Store::sqlite(m.lock().unwrap())
            .execute(
                "UPDATE leader_lease SET last_seen = last_seen - ? WHERE scope='run-worker'",
                &crate::sql_params![LEASE_TTL_SECS + 10],
            )
            .unwrap();
        assert!(acquire_or_renew(&Store::sqlite(m.lock().unwrap()), "B"), "expired lease => B takes over");
        // A has now lost it (B just renewed -> fresh).
        assert!(!acquire_or_renew(&Store::sqlite(m.lock().unwrap()), "A"), "A lost the lease to B");

        // Exactly one row, held by B.
        let (n, holder): (i64, String) = Store::sqlite(m.lock().unwrap())
            .query_row(
                "SELECT COUNT(*), MAX(instance_id) FROM leader_lease WHERE scope='run-worker'",
                &crate::sql_params![],
                |r| Ok((r.get_i64(0)?, r.get_str(1)?)),
            )
            .unwrap();
        assert_eq!(n, 1, "single lease row (one leader across the cluster)");
        assert_eq!(holder, "B", "held by B after takeover");
    }
}

// ================================================================================================
// PG-BACKED lease test — proves the SAME single-statement acquire/renew/takeover on a REAL Postgres
// (the backend HA actually runs on), through the store seam (`?`->`$n` translation, PG upsert +
// RETURNING). Gated on `store-postgres` + a live server via `TEST_PG_URL` (skips cleanly when unset),
// mirroring `store.rs::pg_tests`. This is the substitute the task allows when the full multi-replica
// image build is too heavy: it validates the lease core against docker Postgres.
// ================================================================================================
#[cfg(all(test, feature = "store-postgres"))]
mod pg_tests {
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

    /// FIX #1 — LEDGER NO-FORK UNDER A POSTGRES OUTAGE (the docker-compose scenario, code-level analogue).
    /// Two "instances" (separate PG connections, fresh-connected per attempt like `app.store()`'s pool)
    /// hammer appends to the SAME shared ledger file through the EXACT three-tier `with_ledger_lock` logic
    /// (advisory-lock tx w/ bounded backoff -> REAL [`with_ledger_flock`] fallback -> fail-closed). Partway
    /// through, this test STOPS the Postgres container (simulating the outage the task drives with
    /// `docker stop`), then RESTARTS it. Asserts the SHA-256 chain stays INTACT (no fork, contiguous seq,
    /// verify {ok:true}) across the whole outage — during the outage every append serialises via the shared-
    /// volume flock, exactly as two compose replicas would. Then proves the OLD (unlocked) behaviour COULD
    /// fork by constructing the two-writers-same-tail state and showing verify catches it.
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

        // The EXACT three-tier critical section of `ha::with_ledger_lock`, per-append (fresh connect each
        // attempt so a healed PG resumes the advisory path — like the pool). Returns which tier landed it.
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
                    Err(_) => continue, // PG down -> retry, then fall through to flock.
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
            // TIER 2 — FALLBACK: the REAL shared-volume flock helper. Serialises across "instances".
            let mut ran = false;
            let ok = with_ledger_flock(&path_c, || {
                let _ = crate::ledger_append_standalone(&path_c, "console.race", &detail);
                ran = true;
            });
            if ok && ran {
                "flock"
            } else {
                "deferred" // TIER 3 fail-closed (never reached on a writable shared volume).
            }
        };
        let append_one = std::sync::Arc::new(append_one);

        const N: i64 = 60;
        let tally = std::sync::Arc::new(std::sync::Mutex::new((0usize, 0usize, 0usize))); // advisory, flock, deferred
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
                            "flock" => t.1 += 1,
                            _ => t.2 += 1,
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
        eprintln!("[pg_outage] Postgres STOPPED — appends must now serialise via flock (no unlocked fork).");
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

        let (adv, fl, defr) = *tally.lock().unwrap();
        eprintln!("[pg_outage] appends: advisory={adv} flock={fl} deferred={defr} (total={})", adv + fl + defr);
        let v = crate::verify_ledger_chain(&path);
        eprintln!("[pg_outage] verify: ok={} entries={} why={:?}", v.ok, v.entries, v.why);
        assert!(v.ok, "chain INTACT across the PG outage (no fork); why={:?}", v.why);
        assert_eq!(v.entries, (2 * N) as usize, "every append landed, contiguous SHA-256 chain, no fork/drop");
        assert!(fl > 0, "the outage exercised the flock fallback (some appends took the file lock)");

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
}

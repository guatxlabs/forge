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
            acquire_or_renew(&store, &app.instance_id)
        };
        app.is_leader.store(leader, std::sync::atomic::Ordering::SeqCst);
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
}

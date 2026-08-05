// SPDX-License-Identifier: AGPL-3.0-or-later
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
/// does — before we FAIL-CLOSED (refuse the append). The advisory lock is the SOLE cross-instance
/// serialiser; there is no second lock to fall back to. Kept small: INTEGRITY over latency.
#[cfg(feature = "store-postgres")]
pub(crate) const LEDGER_LOCK_RETRY_BACKOFF_MS: &[u64] = &[25, 50, 75, 100, 150];

/// Returned by [`with_ledger_lock`] when an HA ledger append could NOT be serialised: Postgres — and thus
/// the SOLE cross-instance serialiser, `pg_advisory_xact_lock` — stayed unreachable across the whole
/// [`LEDGER_LOCK_RETRY_BACKOFF_MS`] retry budget. The append was REFUSED (deferred), NOT written: `f` never
/// ran, so the tamper-evident chain stays contiguous and /api/ledger/verify stays {ok:true}. The CALLER
/// MUST surface this — a governed action must not proceed as though its audit entry landed. This is only
/// reachable under HA when THIS replica's Postgres is down; since the data plane is `store()`=Postgres, the
/// governing action is already failing, so refusing the audit append is the consistent, integrity-first
/// outcome. Defined unconditionally so the community mirror shares the signature (it never returns `Err`).
#[derive(Debug, Clone)]
pub(crate) struct LedgerUnavailable {
    pub(crate) path: String,
}

impl std::fmt::Display for LedgerUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ledger temporarily unavailable — append deferred/refused (Postgres advisory lock unreachable for '{}')",
            self.path
        )
    }
}

impl std::error::Error for LedgerUnavailable {}

/// B5 / FIX #17 — LEDGER MULTI-INSTANCE, SINGLE AUTHORITATIVE SERIALISER (no chain forks, no disjoint lock
/// window). Run the ledger append critical section `f` (read-tail -> compute -> append) under ONE
/// cross-instance lock so two replicas never read the same tail hash and both append (which would fork the
/// SHA-256 chain and break /api/ledger/verify). Under HA the SOLE serialiser is a PG
/// `pg_advisory_xact_lock(hashtext(path))` — cluster-global, keyed on the ledger file path — taken inside a
/// short transaction; the caller invalidates its (possibly stale) head cache and re-reads the tail from the
/// SHARED file INSIDE this lock. Single writer at a time => the existing in-proc `ledger_lock` + preimage/
/// hash stay correct and byte-identical, so verify is unchanged; zero forks by construction.
///
/// WHY ONE LOCK (the fork window this closes): a prior design used the advisory lock as PRIMARY with a
/// shared-volume `flock` FALLBACK. Those two mechanisms are DISJOINT — they do not mutually exclude — so a
/// PARTIAL outage opened a race: replica A (pooled PG connection still alive) holds the advisory lock and
/// appends, while replica B (its connect fails) falls to the flock and appends CONCURRENTLY; both read tail
/// seq=N and write seq=N+1 -> forked chain (verify rejects it). Removing the flock entirely leaves exactly
/// ONE mechanism governing every HA append regardless of PG state, so there is no transition window where
/// two appenders both enter the critical section.
///
/// INTEGRITY > AVAILABILITY (tamper-evident ledger). `f` NEVER runs UNLOCKED, and never via a second,
/// disjoint lock — a fork is worse than a deferred entry:
///   1. ACQUIRE — advisory lock inside a tx, RETRIED with a short bounded backoff ([`LEDGER_LOCK_RETRY_BACKOFF_MS`])
///      to ride out a PG connection blip (blips recover in ms). `f` runs inside the tx while the
///      cluster-global lock is held, then the lock releases at COMMIT.
///   2. FAIL-CLOSED — PG stays unreachable after the whole retry budget: REFUSE the append (the entry is
///      DEFERRED, not forked, and NOT written via any second path). Return [`LedgerUnavailable`] so the
///      CALLER surfaces it. Partial outage is handled by construction: the replica whose PG is up appends
///      under the advisory lock; the replica whose PG is down fails to acquire and defers here — it never
///      reaches a disjoint path, so the two can never both write seq=N+1.
///
/// `f` runs AT MOST ONCE (guarded by `slot.take()`) and only ever under the held advisory lock. Returns
/// `Ok(())` iff the append was serialised (or single-instance pass-through); `Err(LedgerUnavailable)` iff it
/// was refused. Single-instance (!ha): pure pass-through — the in-proc `ledger_lock` alone is authoritative,
/// `f` always runs, always `Ok`, exactly as today.
#[cfg(feature = "store-postgres")]
pub(crate) fn with_ledger_lock(
    app: &crate::App,
    path: &str,
    f: impl FnOnce(),
) -> Result<(), LedgerUnavailable> {
    if !ha_enabled(app) {
        f();
        return Ok(());
    }

    let mut slot = Some(f);
    // SOLE SERIALISER: advisory-lock inside a tx, retried with bounded backoff on a transient PG failure.
    for (attempt, backoff_ms) in std::iter::once(0u64)
        .chain(LEDGER_LOCK_RETRY_BACKOFF_MS.iter().copied())
        .enumerate()
    {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
        }
        let res = (app.store()).with_tx(|tx| {
            // Cluster-global advisory lock keyed on the ledger path; auto-released at COMMIT/ROLLBACK. A peer
            // appending to the SAME file blocks here until we commit -> serialised single writer. This is the
            // ONLY mechanism that governs the critical section — there is no second (disjoint) lock.
            tx.execute("SELECT pg_advisory_xact_lock(hashtext(?))", &crate::sql_params![path])?;
            if let Some(g) = slot.take() {
                g();
            }
            Ok::<(), crate::store::StoreError>(())
        });
        if res.is_ok() {
            return Ok(()); // appended under the advisory lock (released at COMMIT).
        }
        // with_tx failed. If `slot` is now empty, `f` ALREADY ran while the lock was held (only COMMIT
        // failed afterwards) -> it was serialised under the lock; do NOT re-run and do NOT report an outage.
        // Otherwise BEGIN/lock failed before `f` ran -> retry.
        if slot.is_none() {
            return Ok(());
        }
    }

    // FAIL-CLOSED: PG stayed unreachable across every retry. Do NOT append — not unlocked, and not via any
    // second/disjoint lock (there is none). Drop `f` unexecuted and surface the outage so the CALLER refuses
    // to proceed as if audited. The tamper-evident chain stays contiguous & /api/ledger/verify stays {ok:true}.
    drop(slot); // `f` never ran; the closure is dropped without being invoked.
    eprintln!(
        "[forge] LEDGER TEMPORARILY UNAVAILABLE — Postgres advisory lock unreachable for '{path}' \
         after the retry budget; audit entry REFUSED (integrity > availability, no unlocked/disjoint fork)."
    );
    Err(LedgerUnavailable { path: path.to_string() })
}

/// Community mirror of [`with_ledger_lock`] — HA is impossible without Postgres, so the ledger is never
/// shared cross-instance: run `f` directly (the in-proc `ledger_lock` is authoritative) and always succeed.
/// Byte-identical behaviour to the historical `()`-returning helper (the `Ok(())` is never inspected off
/// the happy path in this build). Signature matches the HA arm so callers compile identically.
#[cfg(not(feature = "store-postgres"))]
pub(crate) fn with_ledger_lock(
    _app: &crate::App,
    _path: &str,
    f: impl FnOnce(),
) -> Result<(), LedgerUnavailable> {
    f();
    Ok(())
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
mod tests;

// ================================================================================================
// PG-BACKED lease test — proves the SAME single-statement acquire/renew/takeover on a REAL Postgres
// (the backend HA actually runs on), through the store seam (`?`->`$n` translation, PG upsert +
// RETURNING). Gated on `store-postgres` + a live server via `TEST_PG_URL` (skips cleanly when unset),
// mirroring `store.rs::pg_tests`. This is the substitute the task allows when the full multi-replica
// image build is too heavy: it validates the lease core against docker Postgres.
// ================================================================================================
#[cfg(all(test, feature = "store-postgres"))]
mod tests_pg;

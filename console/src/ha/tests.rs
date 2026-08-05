// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ha` — module de test EXTRAIT (PURE MOVE depuis `console/src/ha.rs`).
//! Corps IDENTIQUE ; ENFANT de `ha`, il voit donc toujours ses items privés.
use super::*;

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

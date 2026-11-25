// SPDX-License-Identifier: AGPL-3.0-or-later
//! RENAMED SETTINGS KEYS — the per-database keys that engage the advanced modules were called
//! `enterprise.<suffix>` and are now `advanced.<suffix>` (forge has no paid edition). The rename has NO
//! read alias: the modules read the new name only, and nothing in this binary writes the old one. It is the
//! settings-table twin of the `FORGE_ENTERPRISE_*` -> `FORGE_ADVANCED_*` environment rename
//! (`flags::retired_env_gate`).
//!
//! ADDITIVE. The FIRST migration COPIES `enterprise.<suffix>` to `advanced.<suffix>` (same value) and LEAVES
//! the old row in place: the console ships as several replicas upgraded one by one (`k8s/40-console.yaml`,
//! RollingUpdate) and an older replica, or an older image rolled back to, keeps reading the old row.
//!
//! THE STAMP IS NOT A MEMORY. An older binary that starts on the database stamps its own schema version (2)
//! again. Replaying the copy then would bring back an `advanced.*` key the operator deleted since — a revoked
//! super-administrator would be one again. So the first migration also writes, in the same transaction, a
//! PERSISTED RECORD [`MIGRATION_RECORD_KEY`] whose value is the list of suffixes that existed under the old
//! name at that moment (an empty list is allowed; never a setting value). Its presence means "the copy was
//! done": it is never done again.
//!
//! Decision, inside every schema pass (SQLite `migrate()`, the Postgres boot transaction, `forge
//! migrate-store`), in the same transaction as the schema version stamp:
//! - stamped [`SETTINGS_COPY_SCHEMA_VERSION`] or later: nothing (the old rows are inert leftovers);
//! - below, WITHOUT the record: first migration — copy where the new key is absent, nothing where both are
//!   equal, REFUSE where they differ; then write the record;
//! - below, WITH the record (an older binary ran since): NO copy, ever. Each suffix of the record must have
//!   both names present and equal; a suffix outside it whose old name is present (written under the older
//!   binary) must have the new name present and equal. The record is read CLOSED: an element that is not
//!   one of the five suffixes is named and REFUSED. Anything else is REFUSED.
//!
//! A refusal writes nothing, names the keys out of step with `present` / `absent` / `differs`, never a value
//! (a super-admin list is an identity), and says what to do. Removing the leftovers (docs/UPGRADE.md §8) is
//! one transaction: delete the five old keys AND empty the record's list — after it nothing is compared.

/// Prefix of the RETIRED settings keys. Read by this migration only, never written.
pub(crate) const RETIRED_SETTING_PREFIX: &str = "enterprise.";
/// Prefix of their successors, the only names the modules read.
pub(crate) const ADVANCED_SETTING_PREFIX: &str = "advanced.";
/// Suffixes renamed `enterprise.<suffix>` -> `advanced.<suffix>`.
pub(crate) const RENAMED_SETTING_SUFFIXES: [&str; 5] = ["tenancy", "sso", "scim", "compliance", "superadmin"];
/// Schema version that carries this migration. A database stamped at it (or later) is not checked.
pub(crate) const SETTINGS_COPY_SCHEMA_VERSION: i64 = 3;
/// Settings key of the PERSISTED RECORD of the first migration. Value: the comma-separated suffixes that
/// existed under the old name at that moment, in [`RENAMED_SETTING_SUFFIXES`] order (`""` when none).
pub(crate) const MIGRATION_RECORD_KEY: &str = "migration.renamed_settings";

/// Where a refusal happens — it decides the last sentence of the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalContext {
    /// Server start (SQLite or Postgres), and `forge seed-demo`.
    Boot,
    /// `forge migrate-store` (SQLite -> Postgres).
    MigrateStore,
    /// `forge migrate` and `POST /api/setup/migrate`.
    Import,
    /// `forge upgrade`.
    Upgrade,
}

impl RefusalContext {
    fn clause(self) -> &'static str {
        match self {
            RefusalContext::Boot => "Refusing to start rather than pick one.",
            RefusalContext::MigrateStore => {
                "migrate-store refused: its transaction is rolled back, the target holds no copied row."
            }
            RefusalContext::Import => {
                "Import refused: the target database was copied but not migrated; correct the source, then import again."
            }
            RefusalContext::Upgrade => "Upgrade refused: the database goes back to its pre-upgrade snapshot.",
        }
    }
}

/// One write decided by [`plan_settings_copy`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MigrationStep {
    /// First migration only: copy the old key's row under the new name.
    Copy { from: String, to: String },
    /// First migration only, always last: write the record with this list.
    Record { suffixes: String },
}

/// Pairs (suffix, old, new) of every renamed key, in [`RENAMED_SETTING_SUFFIXES`] order.
fn renamed_pairs() -> Vec<(&'static str, String, String)> {
    RENAMED_SETTING_SUFFIXES
        .iter()
        .map(|s| (*s, format!("{RETIRED_SETTING_PREFIX}{s}"), format!("{ADVANCED_SETTING_PREFIX}{s}")))
        .collect()
}

/// Text of the refusal. `gaps` = one `"<old> <state>, <new> <state>"` per suffix out of step.
fn refusal_message(gaps: &[String], ctx: RefusalContext) -> String {
    format!(
        "settings keys out of step: {}. The enterprise.* settings keys were renamed advanced.* (no alias); until \
         the enterprise.* leftovers are removed, both names must hold the same value. Give BOTH names the same \
         intended value; never delete an advanced.* key to get past this; if the enterprise.* rows were removed \
         on purpose, run the complete removal of docs/UPGRADE.md §8. {}",
        gaps.join("; "),
        ctx.clause()
    )
}

/// Longest part of an unknown record element shown in a refusal.
const SHOWN_RECORD_ELEMENT_MAX: usize = 32;

/// An unknown element of the record as a refusal shows it: a suffix name, never a setting value, still
/// bounded to [`SHOWN_RECORD_ELEMENT_MAX`] characters (then `...`), each character outside printable
/// ASCII shown as `?`.
fn shown_record_element(element: &str) -> String {
    let mut shown: String = element
        .chars()
        .take(SHOWN_RECORD_ELEMENT_MAX)
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
        .collect();
    if element.chars().count() > SHOWN_RECORD_ELEMENT_MAX {
        shown.push_str("...");
    }
    shown
}

fn state(v: Option<&str>) -> &'static str {
    if v.is_some() { "present" } else { "absent" }
}

/// PURE planner over the `(key, value)` rows of `settings` (any subset that contains the watched keys, the
/// schema version stamp and the record). `Ok(steps)` — possibly empty — or `Err(refusal)`; on a refusal no
/// step is returned at all, so nothing is half-applied.
pub(crate) fn plan_settings_copy(rows: &[(String, String)], ctx: RefusalContext) -> Result<Vec<MigrationStep>, String> {
    let get = |k: &str| rows.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());
    let stamped = get(crate::schema::SCHEMA_VERSION_KEY).and_then(|v| v.trim().parse::<i64>().ok());
    if stamped.is_some_and(|v| v >= SETTINGS_COPY_SCHEMA_VERSION) {
        return Ok(Vec::new());
    }
    let mut steps = Vec::new();
    let mut gaps = Vec::new();
    match get(MIGRATION_RECORD_KEY) {
        // FIRST migration: copy, then record which suffixes existed under the old name.
        None => {
            let mut recorded = Vec::new();
            for (suffix, old, new) in renamed_pairs() {
                match (get(&old), get(&new)) {
                    (None, _) => {}
                    (Some(_), None) => {
                        recorded.push(suffix);
                        steps.push(MigrationStep::Copy { from: old, to: new });
                    }
                    (Some(a), Some(b)) if a == b => recorded.push(suffix),
                    (Some(_), Some(_)) => gaps.push(format!("{old} present, {new} differs")),
                }
            }
            steps.push(MigrationStep::Record { suffixes: recorded.join(",") });
        }
        // An OLDER binary ran since the first migration: no copy, compare only.
        Some(record) => {
            // Read CLOSED: the list is written by `run` exactly as the suffixes joined by ','. Any element that is
            // not one of them (other case, spaces, unknown word, empty element) is refused, never skipped.
            let listed: Vec<&str> = if record.is_empty() { Vec::new() } else { record.split(',').collect() };
            for element in listed.iter().filter(|e| !RENAMED_SETTING_SUFFIXES.contains(e)) {
                gaps.push(format!("{MIGRATION_RECORD_KEY} lists unknown name \"{}\"", shown_record_element(element)));
            }
            for (suffix, old, new) in renamed_pairs() {
                let (o, n) = (get(&old), get(&new));
                let in_step = match (o, n) {
                    (Some(a), Some(b)) => a == b,
                    (None, _) => !listed.contains(&suffix),
                    (Some(_), None) => false,
                };
                if !in_step {
                    let new_state = match (o, n) {
                        (Some(a), Some(b)) if a != b => "differs",
                        _ => state(n),
                    };
                    gaps.push(format!("{old} {}, {new} {new_state}", state(o)));
                }
            }
        }
    }
    if gaps.is_empty() {
        Ok(steps)
    } else {
        Err(refusal_message(&gaps, ctx))
    }
}

/// `SELECT key, value FROM settings WHERE key IN (?, …)` over the ten watched keys, the version stamp and
/// the record, and those keys.
fn watched_query() -> (String, Vec<String>) {
    let mut keys: Vec<String> = renamed_pairs().into_iter().flat_map(|(_, o, n)| [o, n]).collect();
    keys.push(crate::schema::SCHEMA_VERSION_KEY.to_string());
    keys.push(MIGRATION_RECORD_KEY.to_string());
    let placeholders = vec!["?"; keys.len()].join(",");
    (format!("SELECT key, value FROM settings WHERE key IN ({placeholders})"), keys)
}

/// Backend-neutral driver: read the watched rows, plan, then apply each step through `exec(sql, params)`.
/// The statements are plain SQL valid on SQLite and Postgres (`datetime('now')` is lowered by the store on
/// Postgres); a setting value is copied row to row, never bound nor printed. Returns the number of keys copied.
fn run(
    read: impl FnOnce(&str, &[String]) -> Result<Vec<(String, String)>, String>,
    mut exec: impl FnMut(&str, &[&str]) -> Result<(), String>,
    ctx: RefusalContext,
) -> Result<usize, String> {
    let (sql, keys) = watched_query();
    let rows = read(&sql, &keys)?;
    let steps = plan_settings_copy(&rows, ctx)?;
    let mut copied = 0;
    for step in &steps {
        match step {
            MigrationStep::Copy { from, to } => {
                exec("INSERT INTO settings(key, value, updated) SELECT ?, value, updated FROM settings WHERE key=?", &[to, from])?;
                copied += 1;
                println!("[forge] settings: {from} copied to {to} (value kept; the old row stays for older replicas)");
            }
            MigrationStep::Record { suffixes } => {
                exec("INSERT INTO settings(key, value, updated) VALUES(?, ?, datetime('now'))", &[MIGRATION_RECORD_KEY, suffixes])?;
            }
        }
    }
    Ok(copied)
}

/// The migration on a raw SQLite connection — called by `schema::migrate_in()` INSIDE its transaction,
/// right before the schema version stamp.
pub(crate) fn copy_renamed_settings_conn(db: &rusqlite::Connection, ctx: RefusalContext) -> Result<usize, String> {
    run(
        |sql, keys| {
            let mut stmt = db.prepare(sql).map_err(|e| format!("settings rename: read failed: {e}"))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(keys.iter()), |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| format!("settings rename: read failed: {e}"))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|e| format!("settings rename: read failed: {e}"))
        },
        |sql, params| {
            db.execute(sql, rusqlite::params_from_iter(params.iter()))
                .map(|_| ())
                .map_err(|e| format!("settings rename: write failed: {e}"))
        },
        ctx,
    )
}

/// The migration through the store seam — called INSIDE a transaction (`tx.store()`) by the Postgres boot
/// and by `forge migrate-store` (after the row-count check), each followed by the schema version stamp.
#[cfg(feature = "store-postgres")]
pub(crate) fn copy_renamed_settings_store(store: &crate::store::Store, ctx: RefusalContext) -> Result<usize, String> {
    run(
        |sql, keys| {
            let params: Vec<crate::store::Param> = keys.iter().map(crate::store::Param::from).collect();
            store
                .query(sql, &params, |r| Ok((r.get_str(0)?, r.get_str(1)?)))
                .map_err(|e| format!("settings rename: read failed: {e}"))
        },
        |sql, params| {
            let params: Vec<crate::store::Param> = params.iter().map(|p| crate::store::Param::from(*p)).collect();
            store.execute(sql, &params).map(|_| ()).map_err(|e| format!("settings rename: write failed: {e}"))
        },
        ctx,
    )
}

#[cfg(test)]
pub(crate) mod tests;

// SPDX-License-Identifier: AGPL-3.0-or-later
//! ENTERPRISE (E3 COMPLIANCE) — PURE POLICY / WORM / legal-hold / retention math + timestamp parsing.
//!
//! Extracted from `compliance.rs` (PURE MOVE — byte-identical bodies, only relocation + visibility +
//! use-paths). This is the AUDIT-CRITICAL, fail-closed core: given a retention window + a record age +
//! a legal-hold flag it decides whether a record may be purged (`worm_purgeable`), resolves the effective
//! retention/legal-hold for a scope (`resolve_retention_secs` / `legal_hold_scope`), gates external
//! delete/archive paths (`deletion_blocked` / `retention_blocked`), and parses ledger/record timestamps
//! (`parse_ts_epoch` / `days_from_civil`). Splitting it into its own module makes the pure math
//! independently testable (the cohesive pure tests live here). The HTTP handlers + governed purge +
//! evidence export call into this module from `compliance.rs` / `compliance_evidence.rs`.
use crate::App;
use crate::compliance::enabled;

// ============================================================================================
// PURE WORM PREDICATE — the fail-closed core. HOLD ALWAYS WINS. (Mirrors forge/compliance_signer.py.)
// ============================================================================================

/// May a single record be purged NOW?  FAIL-CLOSED, LEGAL-HOLD ALWAYS WINS:
///   1. `legal_hold` true  → NEVER (a held record survives regardless of retention);
///   2. `retention_secs` unset / <= 0 → NEVER (no policy configured = keep forever);
///   3. else purgeable IFF the record is OLDER than the retention window (`age_secs >= retention_secs`).
///
/// MUTATION SENTINEL: delete the `if legal_hold` line and a held-but-expired record becomes purgeable — the
/// `worm_hold_beats_expired_retention` test flips RED. Pure: no clock, no I/O (age is passed in).
pub fn worm_purgeable(retention_secs: Option<i64>, age_secs: i64, legal_hold: bool) -> bool {
    if legal_hold {
        return false; // LEGAL-HOLD ALWAYS WINS — do not remove: WORM fail-closed depends on this line
    }
    match retention_secs {
        Some(r) if r > 0 => age_secs >= r,
        _ => false, // no retention policy => never purge (fail-closed)
    }
}

// ============================================================================================
// POLICY RESOLUTION — retention + legal-hold, per global/tenant/engagement.
// ============================================================================================

pub(crate) fn ret_key_global() -> String {
    "compliance.retention.global".to_string()
}
pub(crate) fn ret_key_tenant(id: i64) -> String {
    format!("compliance.retention.tenant.{id}")
}
pub(crate) fn ret_key_engagement(id: i64) -> String {
    format!("compliance.retention.engagement.{id}")
}
pub(crate) fn hold_key_global() -> String {
    "compliance.hold.global".to_string()
}
pub(crate) fn hold_key_tenant(id: i64) -> String {
    format!("compliance.hold.tenant.{id}")
}
pub(crate) fn hold_key_engagement(id: i64) -> String {
    format!("compliance.hold.engagement.{id}")
}

/// The tenant owning an engagement (ENTERPRISE column, DEFAULT 1). None if the engagement is unknown.
pub(crate) fn engagement_tenant_id(app: &App, engagement_id: i64) -> Option<i64> {
    let store = app.store();
    store.query_row("SELECT tenant_id FROM engagement WHERE id=?", &crate::sql_params![engagement_id], |r| r.get_i64(0)).ok()
}

pub(crate) fn setting_i64(app: &App, key: &str) -> Option<i64> {
    let store = app.store();
    crate::settings_get_store(&store, key).and_then(|s| s.trim().parse::<i64>().ok())
}

pub(crate) fn setting_truthy(app: &App, key: &str) -> bool {
    let store = app.store();
    matches!(crate::settings_get_store(&store, key).as_deref(), Some("on") | Some("1") | Some("true") | Some("yes"))
}

/// Effective retention (seconds) for an engagement: MOST-SPECIFIC wins (engagement → tenant → global).
/// None => no retention policy configured anywhere (fail-closed: nothing is ever purgeable).
pub fn resolve_retention_secs(app: &App, engagement_id: i64, tenant_id: Option<i64>) -> Option<i64> {
    if let Some(v) = setting_i64(app, &ret_key_engagement(engagement_id)) {
        return Some(v);
    }
    if let Some(tid) = tenant_id {
        if let Some(v) = setting_i64(app, &ret_key_tenant(tid)) {
            return Some(v);
        }
    }
    setting_i64(app, &ret_key_global())
}

/// The legal-hold SCOPE in force for an engagement, if any: MOST-RESTRICTIVE wins (ANY applicable hold
/// blocks). Returns which scope holds ("engagement" | "tenant" | "global") or None (no hold). Hold ALWAYS
/// wins over retention — a held record is never purgeable/deletable.
pub fn legal_hold_scope(app: &App, engagement_id: i64, tenant_id: Option<i64>) -> Option<&'static str> {
    if setting_truthy(app, &hold_key_engagement(engagement_id)) {
        return Some("engagement");
    }
    if let Some(tid) = tenant_id {
        if setting_truthy(app, &hold_key_tenant(tid)) {
            return Some("tenant");
        }
    }
    if setting_truthy(app, &hold_key_global()) {
        return Some("global");
    }
    None
}

/// ANY active legal hold ACROSS ALL SCOPES — every engagement, every tenant, AND global. Returns the
/// settings key of the first hold found (for the error message), else None. This is the GLOBAL-LEDGER purge
/// gate (FIX 1): the shared console ledger (App.ledger_path == engagement #1's resolved ledger) interleaves
/// PLATFORM-GLOBAL + CROSS-TENANT governance records, so a hold placed on ANY other scope must block its
/// purge — `legal_hold_scope` (engagement-#1 / its tenant / global only) is NOT enough and would let a
/// cross-tenant hold be bypassed. Scans `compliance.hold.*` truthy keys directly (fail-closed). Distinct
/// from `legal_hold_scope`, which stays the correct gate for a DEDICATED per-engagement ledger.
pub(crate) fn any_legal_hold_key(app: &App) -> Option<String> {
    // FAIL-CLOSED (FIX B — defense-in-depth): the previous `.ok()?` made a DB/query error fail OPEN
    // (return None => "no hold" => the shared-global purge proceeds). An unreadable settings table must
    // instead be treated as "a hold MIGHT exist" so the purge REFUSES — never destroy audit records on
    // an error we cannot interpret. Any prepare/query/row error => return a sentinel key (Some => block).
    const UNREADABLE: &str = "compliance.hold.<unreadable-settings>";
    let store = app.store();
    // STRICT `query` (fail-closed) : toute erreur prepare/bind OU ligne malformée SINKS toute la lecture
    // (Err) -> sentinelle UNREADABLE (bloque la purge). Miroir exact de l'ancien fail-closed sur
    // prepare/query_map/row-error. NB: `query` matérialise avant de rendre — pour ces clés (`key`/`value`
    // TEXT NOT NULL écrites par settings_set) `get_str` ne peut échouer, donc le résultat est identique
    // au parcours paresseux d'origine ; une vraie erreur DB (I/O, table illisible) faillit toujours à
    // UNREADABLE. (query_lax est PROSCRIT ici : il SKIPPERAIT une ligne mauvaise au lieu de fail-closed.)
    let rows: Vec<(String, String)> = match store.query(
        "SELECT key, value FROM settings WHERE key LIKE 'compliance.hold.%'",
        &[],
        |r| Ok((r.get_str(0)?, r.get_str(1)?)),
    ) {
        Ok(v) => v,
        Err(_) => return Some(UNREADABLE.to_string()),
    };
    drop(store);
    for (key, value) in rows {
        if matches!(value.trim(), "on" | "1" | "true" | "yes") {
            return Some(key);
        }
    }
    None
}

/// WORM guard for an EXTERNAL delete/archive path (e.g. engagement delete): Some(reason) if a legal hold
/// blocks the mutation, None otherwise. INERT (None) when the enterprise flag is OFF => community
/// byte-identical. Wired into `engagements_update` (delete/archive) as a minimal, flag-gated check.
pub fn deletion_blocked(app: &App, engagement_id: i64) -> Option<String> {
    if !enabled(app) {
        return None; // community: no WORM surface, byte-identical
    }
    let tid = engagement_tenant_id(app, engagement_id);
    legal_hold_scope(app, engagement_id, tid).map(|s| s.to_string())
}

/// WORM RETENTION guard for the EXTERNAL delete/archive path (FIX 2 + FIX D): Some(reason) if the
/// engagement still OWNS ledgered records (findings / runrecords / roe_decisions) that are WITHIN the
/// retention window (not yet expired). A delete/archive of the engagement also removes roe_decision AUDIT
/// rows (per-action VETO/DRY_RUN/FIRE verdicts), so a within-retention roe_decision must block it exactly
/// like a finding/runrecord (FIX D — completeness). Such
/// records cannot be destroyed by a delete/archive any more than by a purge — RETENTION WINS on delete/
/// archive exactly as it does on purge. INERT (None) when the flag is OFF (community byte-identical) or when
/// no retention window is configured (nothing to enforce — only a legal hold can block then). Mirrors
/// purge()'s expiry test (`worm_purgeable`) so the two paths agree. Fail-closed: an UNPARSEABLE ts counts as
/// within-retention (never destroy a record we cannot date).
pub fn retention_blocked(app: &App, engagement_id: i64) -> Option<String> {
    if !enabled(app) {
        return None; // community: no WORM surface, byte-identical
    }
    let tid = engagement_tenant_id(app, engagement_id);
    let retention = match resolve_retention_secs(app, engagement_id, tid) {
        Some(r) if r > 0 => r,
        _ => return None, // no retention window configured => retention does not block (hold still can)
    };
    let now = crate::now_epoch();
    
    // FIXED table literals (never user input) — no SQL-injection surface. roe_decision (FIX D) carries
    // per-action audit verdicts also destroyed by delete/archive; each has ts + engagement_id columns.
    for table in ["finding", "runrecord", "roe_decision"] {
        let sql = format!("SELECT ts FROM {table} WHERE engagement_id=?");
        let rows = app.store().query_lax(&sql, &crate::sql_params![engagement_id], |r| r.get_opt_str(0)).unwrap_or_default();
        for ts in rows {
            let ts = ts.unwrap_or_default();
            // "within retention" <=> NOT purgeable. Unparseable ts => not purgeable => within (fail-closed).
            let within = match parse_ts_epoch(&ts) {
                Some(ep) => !worm_purgeable(Some(retention), now - ep, false),
                None => true,
            };
            if within {
                return Some(format!(
                    "retention window active — a {table} is still within retention; delete/archive blocked (WORM, fail-closed)"
                ));
            }
        }
    }
    None
}

// ============================================================================================
// TIMESTAMP PARSING — ledger console ts is `@<epoch>`; engine/finding ts is ISO-8601. Fail-closed: an
// UNPARSEABLE ts yields None => the record is treated as NOT expired (kept) — never purged on ambiguity.
// ============================================================================================

/// Howard Hinnant's days-from-civil. CHECKED throughout (FIX 4 — no panic on an attacker-controlled
/// timestamp): a gigantic/degenerate year (e.g. `i64::MAX-01-01`) would overflow the plain `*`/`-` and
/// PANIC in a debug build (Rust overflow check). Every arithmetic step is `checked_*` => an overflow
/// yields None, which parse_ts_epoch propagates => the record is treated as NON-expired (RETAINED). Never
/// crash, never date-unknown-delete.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = (if y >= 0 { y } else { y.checked_sub(399)? }) / 400;
    let yoe = y - era.checked_mul(400)?; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era.checked_mul(146097)?.checked_add(doe)?.checked_sub(719468)
}

/// Parse a ledger/record timestamp to a UTC epoch (seconds). Supports `@<epoch>`, a bare integer, and
/// ISO-8601 `YYYY-MM-DDTHH:MM:SS` (any trailing `Z`/fraction/offset ignored). None if unparseable.
pub fn parse_ts_epoch(ts: &str) -> Option<i64> {
    let t = ts.trim();
    if let Some(rest) = t.strip_prefix('@') {
        return rest.trim().parse::<i64>().ok();
    }
    if let Ok(n) = t.parse::<i64>() {
        return Some(n);
    }
    // ISO-8601: need at least "YYYY-MM-DDTHH:MM:SS" (19 chars). Split on 'T'/' '.
    // CHAR-SAFETY (FIX A — reachable panic / DoS): every `&t[a..b]` below is a BYTE-index slice; if a
    // multibyte UTF-8 sequence straddled index 10/11/19 it would PANIC ('byte index N is not a char
    // boundary') on attacker-controlled input (a ts stored verbatim from /api/ingest), defeating the
    // "unparseable => retained, never crash" contract. A valid ISO-8601 basic timestamp is PURE ASCII,
    // so reject any non-ASCII input up front => None => the record is RETAINED (never crash). With ASCII
    // guaranteed, byte indices coincide with char boundaries and the slices below cannot panic.
    if !t.is_ascii() {
        return None;
    }
    let bytes = t.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let date = &t[0..10];
    let sep = bytes[10];
    if sep != b'T' && sep != b' ' {
        return None;
    }
    let time = &t[11..19];
    let d: Vec<&str> = date.split('-').collect();
    let ti: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || ti.len() != 3 {
        return None;
    }
    let y = d[0].parse::<i64>().ok()?;
    let mo = d[1].parse::<i64>().ok()?;
    let da = d[2].parse::<i64>().ok()?;
    let hh = ti[0].parse::<i64>().ok()?;
    let mm = ti[1].parse::<i64>().ok()?;
    let ss = ti[2].parse::<i64>().ok()?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // CHECKED (FIX 4): days*86400 + hms could overflow for a huge year — never panic, yield None (retain).
    let secs_of_day = hh * 3600 + mm * 60 + ss; // bounded (hh<=23,mm<=59,ss<=60) — cannot overflow
    days_from_civil(y, mo, da)?.checked_mul(86400)?.checked_add(secs_of_day)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PURE WORM PREDICATE ----

    #[test]
    fn worm_expired_no_hold_is_purgeable() {
        assert!(worm_purgeable(Some(100), 500, false));
    }

    #[test]
    fn worm_under_retention_not_purgeable() {
        assert!(!worm_purgeable(Some(100), 50, false));
    }

    #[test]
    fn worm_retention_unset_never_purges() {
        assert!(!worm_purgeable(None, 1_000_000_000, false));
        assert!(!worm_purgeable(Some(0), 1_000_000_000, false));
    }

    #[test]
    fn worm_hold_beats_expired_retention() {
        // MUTATION SENTINEL: remove `if legal_hold { return false; }` from worm_purgeable and this flips RED
        // (an expired-but-held record would become purgeable). HOLD ALWAYS WINS.
        assert!(!worm_purgeable(Some(100), 1_000_000_000, true));
    }

    #[test]
    fn parse_ts_epoch_forms() {
        assert_eq!(parse_ts_epoch("@1700000000"), Some(1_700_000_000));
        assert_eq!(parse_ts_epoch("1700000000"), Some(1_700_000_000));
        assert_eq!(parse_ts_epoch("1970-01-01T00:00:00"), Some(0));
        assert_eq!(parse_ts_epoch("2021-01-01T00:00:00Z"), Some(1_609_459_200));
        assert_eq!(parse_ts_epoch("not-a-date"), None);
    }

    // ---- FIX 4: a malformed timestamp neither panics nor gets purged (retained, fail-closed) ----

    #[test]
    fn parse_ts_epoch_overflow_is_none_not_panic() {
        // Attacker-controlled gigantic/degenerate years must NOT panic (checked arithmetic) => None => retained.
        assert_eq!(parse_ts_epoch("9223372036854775807-01-01T00:00:00"), None);
        assert_eq!(parse_ts_epoch("-9223372036854775808-01-01T00:00:00"), None);
        assert_eq!(parse_ts_epoch("99999999999999-13-40T99:99:99"), None);
        assert_eq!(parse_ts_epoch("not-a-date"), None);
    }

    // ---- FIX A: a multibyte/non-ASCII ts must yield None, NEVER panic (reachable /api/ingest DoS) ----

    #[test]
    fn parse_ts_epoch_multibyte_is_none_not_panic() {
        // Byte index 19 straddles the é (bytes 18..=19) — pre-fix `&t[11..19]` panicked ('not a char
        // boundary'). >=19 bytes so the length check does not short-circuit first.
        assert_eq!(parse_ts_epoch("2025-01-01T00:00:0é"), None);
        // Byte index 10 straddles a multibyte char near the date slice — pre-fix `&t[0..10]` panicked.
        assert_eq!(parse_ts_epoch("2025-01-0é-01T00:00:00"), None);
        // A short multibyte input is None too (contract: unparseable => None => RETAINED).
        assert_eq!(parse_ts_epoch("2025-01-0é"), None);
        // Sanity: an all-ASCII but malformed separator is still None (unchanged behavior).
        assert_eq!(parse_ts_epoch("2025-01-01X00:00:00"), None);
    }
}

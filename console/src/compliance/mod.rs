// SPDX-License-Identifier: AGPL-3.0-or-later
//! ENTERPRISE (E3 COMPLIANCE) — WORM / retention / legal-hold on the audit ledger + engagement data
//! (SEPARABLE, FLAG-GATED module).
//!
//! Open-core discipline (mirrors `tenancy.rs` / `sso.rs` / `scim.rs` / `rbac.rs`): this is an ENTERPRISE
//! feature. The COMMUNITY (default) build behaves EXACTLY as today — every route here is a NO-OP (404
//! `not_found`) unless the enterprise flag is ENGAGED (`enabled()` false => community, byte-identical).
//! It never weakens the open governance/audit surface; it only ADDS retention/hold policy + a GOVERNED
//! purge that PRESERVES the tamper-evident ledger.
//!
//! WHAT IT ADDS (all admin-gated + ledgered, all fail-closed):
//!   1. RETENTION POLICY — a configurable retention duration for the audit trail + findings/runs, settable
//!      per GLOBAL / per TENANT / per ENGAGEMENT (most-specific wins: engagement → tenant → global).
//!   2. LEGAL-HOLD — a per global/tenant/engagement flag that BLOCKS any deletion/purge REGARDLESS of
//!      retention. HOLD ALWAYS WINS (most-restrictive wins: ANY applicable hold blocks). Fail-closed.
//!   3. WORM ENFORCEMENT — while a ledger record is UNDER RETENTION or UNDER LEGAL-HOLD it CANNOT be
//!      deleted/altered/purged. A GOVERNED purge is allowed ONLY when retention has EXPIRED for the record
//!      AND there is no legal-hold. The purge NEVER silently deletes: it (a) ARCHIVES the expired segment
//!      first — ENCRYPTED, reusing the backup discipline (`backup_encrypt`, XChaCha20-Poly1305) — then
//!      (b) RE-ANCHORS the ledger so it stays verifiable, recording a signed checkpoint ledger event
//!      `console.compliance.purge` (counts, segment hash, archive hash, purged head, time, actor). The
//!      REMAINING chain re-verifies under the EXISTING verifier (`crate::verify_ledger_chain`) AND the
//!      Python `Ledger.verify` — no verifier change, no weakened trust.
//!
//! HOW THE RE-ANCHOR PRESERVES INTEGRITY (the crux):
//!   The ledger is an append-only SHA-256 hash-chain (`prev|seq|ts|kind|canon(detail)`), multi-alg
//!   (console entries `sha256-console` unsigned + engine entries `ed25519` signed). Purging the OLDEST
//!   (expired) PREFIX would orphan the first survivor's `prev`. We RE-ANCHOR: a fresh genesis-rooted
//!   `console.compliance.purge` checkpoint entry R (`prev=GENESIS`) is written first, then the SURVIVING
//!   entries are RE-LINKED onto R by recomputing ONLY their `prev`/`hash` — their audited content
//!   (`seq/ts/kind/detail/alg/sig`) is byte-preserved. The result is a clean genesis-rooted chain the
//!   EXISTING verifier accepts. FAIL-CLOSED: because re-linking recomputes a survivor's hash, it would
//!   INVALIDATE an Ed25519 signature — so the purge REFUSES (409 `signed_survivor`) if any SURVIVING entry
//!   is signed (ed25519/hmac). Such ledgers keep their signed entries intact (never corrupted). The purged
//!   (removed) prefix may be any alg — it is archived verbatim + hashed in the checkpoint, then dropped.
//!
//! SECURITY (fail-closed — weaken any check and a test flips RED):
//!   - LEGAL-HOLD beats retention ALWAYS (`worm_purgeable` returns false under hold even if expired);
//!   - a purge with NO archive key configured is REFUSED (never a silent, unrecoverable delete);
//!   - the archive passphrase is NEVER returned/logged/ledgered (redacted like any secret);
//!   - flag OFF => every `/api/compliance/*` route 404s and the ledger/data are byte-identical.

use crate::App;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;

// Policy/WORM/retention math + timestamp parsing (PURE MOVE -> compliance_policy.rs), re-exported so
// external `compliance::deletion_blocked`/`compliance::retention_blocked` call sites stay stable and
// the handlers below resolve resolve_retention_secs/legal_hold_scope/parse_ts_epoch/worm_purgeable/…
pub(crate) use crate::compliance_policy::*;
// Evidence export/rendering + governed-purge read/delete helpers (PURE MOVE -> compliance_evidence.rs).
use crate::compliance_evidence::*;

/// Genesis hash (64 zero hex) — MUST match `crate::verify_ledger_chain`'s GENESIS so a re-anchored ledger
/// verifies under the SAME code path.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// The unsigned console hash-chain alg. Only SURVIVING entries of this alg can be re-anchored (re-hashing a
/// signed entry would break its signature) — see the module header.
const CONSOLE_ALG: &str = "sha256-console";
/// The re-anchor / purge checkpoint kind (console.* prefix => sha256-console entry, honoured by the
/// ledger's alg↔kind guard — an ed25519 sig is NEVER placed on a console.* kind).
const PURGE_KIND: &str = "console.compliance.purge";

// ============================================================================================
// FLAG — is enterprise COMPLIANCE ENGAGED? Community default = OFF (every /api/compliance/* route 404s).
// Two sources (either engages it): env `FORGE_ENTERPRISE_COMPLIANCE` (truthy) OR the per-DB config key
// `enterprise.compliance` (on|1|true|yes). Config is per-DB so tests toggle it in isolation. Mirrors sso/scim.
// ============================================================================================

/// Is enterprise COMPLIANCE engaged?  false => community (every `/api/compliance/*` route 404s, ledger/data
/// byte-identical, WORM/retention/hold inert).
pub fn enabled(app: &App) -> bool {
    crate::flags::enterprise_enabled(app, "FORGE_ENTERPRISE_COMPLIANCE", "enterprise.compliance")
}

// ============================================================================================
// RESPONSE HELPERS
// ============================================================================================

// `err` / `disabled` sont consolidés dans `common` (corps byte-identiques à tenancy/sso/scim — dedup Wave).
// Re-export `pub(crate)` de `err` : `crate::compliance::err` reste valide (compliance_evidence.rs l'importe).
pub(crate) use crate::common::err;
use crate::common::disabled;

/// Common gate: enterprise engaged + admin session. Returns the short-circuit Response, or None to proceed.
fn gate(app: &App, headers: &HeaderMap) -> Option<Response> {
    if !enabled(app) {
        return Some(disabled());
    }
    if !crate::check_admin(app, headers) {
        return Some(err(StatusCode::FORBIDDEN, "admin_required", "compliance administration is admin-only"));
    }
    None
}

// ============================================================================================
// ROUTES — merged into the protected router (inherits auth_guard/host_guard). Each route self-gates.
// ============================================================================================

pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/compliance/policy", get(policy_get).post(policy_set))
        .route("/api/compliance/legal-hold", post(legal_hold_set))
        .route("/api/compliance/purge", post(purge))
        .route("/api/compliance/evidence", get(evidence_export))
}

/// A LOG-SAFE view of the ledger-signer (KMS/HSM) configuration for the admin UI — mirrors
/// `forge/signing.py::redact_signer_config`. Surfaces ONLY the non-secret fields: the signer `mode` and the
/// PUBLIC key (verification material). The endpoint/credential/argv are SECRET and NEVER returned — only a
/// boolean `*_set` says whether they are configured. Read from the SAME env the Python engine ledger reads
/// (`FORGE_LEDGER_SIGNER*`); with nothing set the community default is `{"mode":"local"}` (on-disk key).
fn redacted_ledger_signer() -> Value {
    let raw_mode = std::env::var("FORGE_LEDGER_SIGNER").unwrap_or_default();
    let mode = {
        let m = raw_mode.trim().to_ascii_lowercase();
        if m.is_empty() { "local".to_string() } else { m }
    };
    let off_host = !matches!(mode.as_str(), "local" | "file" | "localfile");
    // `*_set` booleans stay HONEST when the operator supplies the value via a `*_FILE` Docker/k8s
    // secret instead of an inline env (the Python signer resolves the credential the same way).
    let set = |k: &str| {
        std::env::var(k).map(|v| !v.trim().is_empty()).unwrap_or(false)
            || std::env::var(format!("{k}_FILE")).map(|v| !v.trim().is_empty()).unwrap_or(false)
    };
    // The PUBLIC key is safe to show (it is the verification material). Prefer the signer pubkey, then the
    // console ledger pubkey — never a private key (there is no env that holds one).
    let pubkey = std::env::var("FORGE_LEDGER_SIGNER_PUBKEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("FORGE_CONSOLE_LEDGER_PUBKEY").ok())
        .unwrap_or_default();
    let endpoint_set = set("FORGE_LEDGER_SIGNER_ENDPOINT");
    let argv_set = set("FORGE_LEDGER_SIGNER_ARGV");
    json!({
        "mode": mode,
        "off_host": off_host,
        "enterprise_flag": crate::flags::env_truthy("FORGE_ENTERPRISE_COMPLIANCE"),
        "pubkey": pubkey,
        "endpoint": if endpoint_set { "***REDACTED***" } else { "" },
        "endpoint_set": endpoint_set,
        "credential_set": set("FORGE_LEDGER_SIGNER_CREDENTIAL"),
        "argv": if argv_set { "***REDACTED***" } else { "" },
        "argv_set": argv_set,
        "note": "Private key lives OFF-HOST (KMS/HSM/exec) when mode != local. Verify uses the PUBLIC key ALONE; endpoint/credential/argv are secret and never shown (only *_set booleans).",
    })
}

/// GET /api/compliance/policy?engagement_id=<id> — the EFFECTIVE retention + legal-hold for an engagement
/// scope, plus the raw global/tenant/engagement values (admin UI). Admin + flag.
async fn policy_get(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let eid: i64 = q.get("engagement_id").and_then(|s| s.parse().ok()).unwrap_or(1);
    let tid = engagement_tenant_id(&app, eid);
    let retention = resolve_retention_secs(&app, eid, tid);
    let hold = legal_hold_scope(&app, eid, tid);
    (
        StatusCode::OK,
        Json(json!({
            "enabled": true,
            "engagement_id": eid,
            "tenant_id": tid,
            "effective_retention_secs": retention,
            "legal_hold": hold.is_some(),
            "legal_hold_scope": hold,
            "ledger_signer": redacted_ledger_signer(),
            "raw": {
                "retention": {
                    "global": setting_i64(&app, &ret_key_global()),
                    "tenant": tid.and_then(|t| setting_i64(&app, &ret_key_tenant(t))),
                    "engagement": setting_i64(&app, &ret_key_engagement(eid)),
                },
                "hold": {
                    "global": setting_truthy(&app, &hold_key_global()),
                    "tenant": tid.map(|t| setting_truthy(&app, &hold_key_tenant(t))),
                    "engagement": setting_truthy(&app, &hold_key_engagement(eid)),
                }
            }
        })),
    )
        .into_response()
}

/// POST /api/compliance/policy {scope, id?, retention_secs} — set/clear a retention duration. Admin + flag.
/// `scope` ∈ global|tenant|engagement (tenant/engagement require `id`). `retention_secs`: a positive integer
/// to set, or null/0 to CLEAR. Ledgered `console.compliance.policy.set`.
async fn policy_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let scope = body.get("scope").and_then(|v| v.as_str()).unwrap_or("");
    let key = match scoped_key(scope, &body, ret_key_global, ret_key_tenant, ret_key_engagement) {
        Ok(k) => k,
        Err(e) => return *e,
    };
    // retention_secs: null/absent/0 => clear ; positive int => set. Negative => reject.
    let ret = body.get("retention_secs");
    let (action, value): (&str, Option<i64>) = match ret {
        None | Some(Value::Null) => ("clear", None),
        Some(v) => match v.as_i64() {
            Some(0) => ("clear", None),
            Some(n) if n > 0 => ("set", Some(n)),
            _ => return err(StatusCode::BAD_REQUEST, "bad_retention", "retention_secs must be a positive integer, 0, or null"),
        },
    };
    let actor = crate::attribution_login(&app, &headers);
    {
        let store = app.store();
        let res = match value {
            Some(n) => crate::settings_set_store(&store, &key, &n.to_string()),
            None => crate::settings_set_store(&store, &key, ""), // empty => setting_i64 parses to None (cleared)
        };
        drop(store);
        if let Err(e) = res {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed", e);
        }
    }
    crate::append_console_ledger(
        &app,
        "console.compliance.policy.set",
        json!({ "actor": actor, "scope": scope, "key": key, "action": action, "retention_secs": value }),
    );
    (StatusCode::OK, Json(json!({ "ok": true, "scope": scope, "action": action, "retention_secs": value }))).into_response()
}

/// POST /api/compliance/legal-hold {scope, id?, hold} — set/clear a legal hold. Admin + flag. `hold` bool
/// (true=place, false=release). Ledgered `console.compliance.hold.set|clear`. HOLD ALWAYS WINS over retention.
async fn legal_hold_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let scope = body.get("scope").and_then(|v| v.as_str()).unwrap_or("");
    let key = match scoped_key(scope, &body, hold_key_global, hold_key_tenant, hold_key_engagement) {
        Ok(k) => k,
        Err(e) => return *e,
    };
    let hold = match body.get("hold").and_then(|v| v.as_bool()) {
        Some(b) => b,
        None => return err(StatusCode::BAD_REQUEST, "bad_hold", "hold must be a boolean (true=place, false=release)"),
    };
    let actor = crate::attribution_login(&app, &headers);
    {
        let store = app.store();
        let res = if hold {
            crate::settings_set_store(&store, &key, "on")
        } else {
            crate::settings_set_store(&store, &key, "") // empty => setting_truthy false (released)
        };
        if let Err(e) = res {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed", e);
        }
    }
    let kind = if hold { "console.compliance.hold.set" } else { "console.compliance.hold.clear" };
    crate::append_console_ledger(&app, kind, json!({ "actor": actor, "scope": scope, "key": key, "hold": hold }));
    (StatusCode::OK, Json(json!({ "ok": true, "scope": scope, "hold": hold }))).into_response()
}

/// Build the settings key for a scoped policy/hold mutation. Validates scope ∈ global|tenant|engagement and
/// that tenant/engagement carry a positive `id`.
fn scoped_key(
    scope: &str,
    body: &Value,
    global: fn() -> String,
    tenant: fn(i64) -> String,
    engagement: fn(i64) -> String,
) -> Result<String, Box<Response>> {
    match scope {
        "global" => Ok(global()),
        "tenant" | "engagement" => {
            let id = body.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
            if id <= 0 {
                return Err(Box::new(err(StatusCode::BAD_REQUEST, "bad_id", format!("scope '{scope}' requires a positive id"))));
            }
            Ok(if scope == "tenant" { tenant(id) } else { engagement(id) })
        }
        _ => Err(Box::new(err(StatusCode::BAD_REQUEST, "bad_scope", "scope must be global|tenant|engagement"))),
    }
}

// ============================================================================================
// GOVERNED PURGE — the WORM-preserving purge (archive-first, re-anchor, signed checkpoint).
// ============================================================================================

fn seq_to_str(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Resolve the archive passphrase (XChaCha20-Poly1305, reuse of the backup discipline). Preference: env
/// `FORGE_COMPLIANCE_ARCHIVE_KEY` (NOT stored at rest), else per-DB `compliance.archive_key` (ops/test
/// convenience). Empty => None => the purge is REFUSED (never a silent, unrecoverable delete). The
/// passphrase is NEVER returned/logged/ledgered.
fn archive_passphrase(app: &App) -> Option<String> {
    // FORGE_COMPLIANCE_ARCHIVE_KEY with a `*_FILE` fallback (Docker/k8s secret) — the passphrase can
    // live in a mounted file instead of a plaintext env beside the app. Empty/unreadable => fall to
    // the per-DB setting (and ultimately None => purge refused; never a silent unrecoverable delete).
    if let Some(v) = crate::secret_from_env("FORGE_COMPLIANCE_ARCHIVE_KEY") {
        return Some(v);
    }
    let store = app.store();
    crate::settings_get_store(&store, "compliance.archive_key").filter(|s| !s.is_empty())
}

/// POST /api/compliance/purge {engagement_id} — governed WORM purge of an engagement's audit ledger +
/// expired findings/runs. Admin + flag. FAIL-CLOSED at every step (see module header). Never a silent delete.
async fn purge(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let eid = body.get("engagement_id").and_then(|v| v.as_i64()).unwrap_or(1);
    let tid = match engagement_tenant_id(&app, eid) {
        Some(t) => Some(t),
        None => return err(StatusCode::NOT_FOUND, "unknown_engagement", format!("engagement {eid} introuvable")),
    };
    // Resolve the TARGET ledger FIRST — the hold gate + checkpoint scope depend on WHICH file this is.
    let ledger_path = crate::engagement_ledger_path(&app, eid);
    // GLOBAL-LEDGER DETECTION (FIX 1): engagement #1 binds its ledger_path to App.ledger_path — the SHARED
    // console ledger, which carries PLATFORM-GLOBAL + CROSS-TENANT governance events (holds/backups/exports/
    // lifecycle of OTHER scopes), not just #1's own run/finding events. A prefix purge of THAT file destroys
    // cross-scope audit records, so it must obey GLOBAL semantics: hold-gate on ANY hold ANYWHERE + an
    // honest scope="global" checkpoint. A DEDICATED per-engagement ledger (path != App.ledger_path) only
    // carries its own events => the per-engagement prefix logic is genuinely scoped and stays as-is.
    // FIX C (robustness): engagement #1 is, BY CONSTRUCTION, ALWAYS the default/global engagement
    // (ensure_default_engagement binds it to App.ledger_path; dedicated per-engagement ledgers are #2+).
    // If FORGE_CONSOLE_LEDGER is repointed post-provision, engagement #1's STORED ledger_path column can
    // desync from the runtime App.ledger_path, making the path comparison wrongly false and dropping #1 to
    // scoped semantics (a cross-scope audit-loss hole). Anchor on the invariant `eid == 1` too so the
    // default engagement ALWAYS uses global semantics regardless of env repointing. Per-engagement ledgers
    // (#2+) are unaffected: eid != 1 and their path != App.ledger_path => is_global stays false.
    let is_global = ledger_path.as_str() == app.ledger_path.as_str() || eid == 1;
    // 1) LEGAL-HOLD ALWAYS WINS — refuse before touching anything (WORM fail-closed).
    //    GLOBAL target => ANY active hold across ALL scopes blocks (a cross-tenant hold protects records that
    //    live INTERLEAVED in this shared file). DEDICATED target => only a hold applicable to THIS scope.
    if is_global {
        if let Some(key) = any_legal_hold_key(&app) {
            return err(
                StatusCode::FORBIDDEN,
                "legal_hold",
                format!("an active legal hold exists ({key}); the shared global audit ledger carries cross-scope records — purge blocked (WORM, fail-closed)"),
            );
        }
    } else if let Some(scope) = legal_hold_scope(&app, eid, tid) {
        return err(StatusCode::FORBIDDEN, "legal_hold", format!("legal hold ({scope}) in force — purge blocked (WORM, fail-closed)"));
    }
    // 2) retention must be configured (else nothing is ever purgeable).
    let retention = match resolve_retention_secs(&app, eid, tid) {
        Some(r) if r > 0 => r,
        _ => return err(StatusCode::BAD_REQUEST, "retention_unset", "no retention policy configured for this scope — nothing is purgeable (fail-closed)"),
    };
    // 3) an archive key MUST exist — we NEVER purge without archiving first.
    let passphrase = match archive_passphrase(&app) {
        Some(p) => p,
        None => return err(StatusCode::BAD_REQUEST, "archive_key_unset", "no archive key (FORGE_COMPLIANCE_ARCHIVE_KEY) — refusing to purge without an encrypted archive (fail-closed)"),
    };
    let actor = crate::attribution_login(&app, &headers);
    let now = crate::now_epoch();

    // Expired findings/runrecords are gathered from the DB BEFORE the cross-process ledger lock, so the
    // flock critical section (below) touches ONLY the ledger FILE — no nested `store()` access while HA's
    // `with_ledger_lock` holds a Postgres transaction. Their DELETE still happens AFTER the re-anchor
    // attests the counts (step 10). Unparseable ts => kept (fail-closed).
    let (arch_findings, del_finding_ids) = collect_expired_rows(&app, eid, retention, now, "finding");
    let (arch_runs, del_run_ids) = collect_expired_rows(&app, eid, retention, now, "runrecord");

    // CRITICAL SECTION (FIX H1): snapshot -> archive -> re-anchor -> REWRITE must be atomic vs a concurrent
    // append from ANY writer — the same-process console (`append_console_ledger`), the Python ENGINE
    // process (`forge/ledger.py`, `fcntl.flock`), and an HA PEER replica. The previous version held ONLY the
    // in-proc `ledger_lock`, so an engine/peer append that flock the shared file could interleave and be
    // silently lost when the rename swapped the inode. We now take the SAME three-tier lock as appends, in
    // the SAME order to preclude deadlock:  in-proc `ledger_lock` -> `ha::with_ledger_lock` (PG advisory
    // xact lock, cross-instance) -> `FlockExclusive` (fcntl.flock, cross-process). And we REWRITE IN PLACE
    // (no rename) so a blocked appender that flock the SAME path keeps contending on the SAME inode — a
    // rename would swap the inode out from under it and drop its entry (the H1 write-loss). We hold the
    // in-proc guard across the whole thing and invalidate the head cache IN PLACE (head.loaded=false):
    // calling app.invalidate_ledger_head() while holding it would re-lock the same non-reentrant mutex.
    let mut head = app.ledger_lock.lock().unwrap_or_else(|e| e.into_inner());
    let mut section: Option<Result<Option<PurgeOk>, Response>> = None;
    let ha = crate::ha::with_ledger_lock(&app, &ledger_path, || {
        section = Some(purge_locked_section(
            &ledger_path, is_global, eid, tid, retention, now, &actor, &passphrase,
            arch_findings, arch_runs, del_finding_ids.len(), del_run_ids.len(),
        ));
    });
    // Head cache invalidated in place (we hold the in-proc lock) whether or not the rewrite ran; the next
    // append rebuilds head from disk regardless. Release the in-proc lock: the DB deletes + verify below do
    // NOT touch the ledger chain.
    head.loaded = false;
    drop(head);

    if let Err(e) = ha {
        // FAIL-CLOSED HA outage: the PG advisory lock stayed unreachable across the retry budget, so the
        // section NEVER ran and the ledger is UNTOUCHED. Refuse the purge (integrity > availability) — do
        // not report success as though records were archived/purged.
        return err(StatusCode::SERVICE_UNAVAILABLE, "ledger_unavailable", e.to_string());
    }
    let ok = match section {
        Some(Ok(Some(o))) => o, // ledger re-anchored in place -> proceed to DB deletes + verify.
        Some(Ok(None)) => {
            // nothing expired => no-op (ledger untouched, byte-identical). Not an error.
            return (StatusCode::OK, Json(json!({ "ok": true, "purged_ledger_entries": 0, "note": "nothing expired past retention" }))).into_response();
        }
        Some(Err(resp)) => return resp, // fail-closed abort (signed survivor / archive / write / changed).
        None => return err(StatusCode::INTERNAL_SERVER_ERROR, "ledger_lock_failed", "purge critical section did not run".to_string()),
    };

    // 10) delete the archived (expired) findings/runrecords rows. FAIL-CLOSED : the ledger was ALREADY
    // re-anchored above attesting `purged_findings`/`purged_runrecords` — a silent delete failure would
    // diverge ledger↔DB. On Err, surface 500 (the encrypted archive is safe on disk; a retry re-runs the
    // idempotent DELETE-by-id). No new ledger entry is written on this error path.
    if let Err(e) = delete_rows(&app, "finding", &del_finding_ids)
        .and_then(|_| delete_rows(&app, "runrecord", &del_run_ids))
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "purge_delete_failed", format!("{e} (archive preserved at {})", ok.archive_path));
    }

    // 11) verify the re-anchored ledger under the EXISTING verifier (must stay OK).
    let v = crate::verify_ledger_chain(&ledger_path);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "engagement_id": eid,
            "purged_ledger_entries": ok.cut,
            "purged_findings": del_finding_ids.len(),
            "purged_runrecords": del_run_ids.len(),
            "survivors": ok.survivors_len,
            "archive_path": ok.archive_path,
            "archive_sha256": ok.archive_sha256,
            "segment_sha256": ok.segment_sha256,
            "purged_head": ok.purged_head,
            "new_head": ok.new_head,
            "ledger_verified": v.ok,
            "checkpoint_kind": PURGE_KIND,
        })),
    )
        .into_response()
}

/// Outputs of the LOCKED ledger section that the caller needs AFTER releasing the cross-process lock
/// (build the success JSON + do the DB deletes). All ledger-file mutation is already durable when this is
/// returned.
struct PurgeOk {
    cut: usize,
    survivors_len: usize,
    archive_path: String,
    archive_sha256: String,
    segment_sha256: String,
    purged_head: String,
    new_head: String,
}

/// The governed purge's LEDGER-FILE critical section (H1). Runs while the caller holds the FULL append
/// lock stack (in-proc `ledger_lock` + `ha::with_ledger_lock` + — acquired HERE — `FlockExclusive`), so a
/// concurrent append from any writer (console / Python engine / HA peer) can be neither lost nor fork the
/// chain. Snapshots the ledger UNDER the flock, archives the expired prefix (encrypted, separate file),
/// builds the re-anchored chain, RE-READS the ledger under the lock and ABORTS if it changed since the
/// snapshot (belt-and-suspenders: cannot happen while the flock is held), then rewrites IN PLACE (no rename
/// — inode-stable so a blocked appender keeps contending on the same lock). Returns:
///   Ok(Some(PurgeOk)) — re-anchored; caller proceeds to DB deletes + verify.
///   Ok(None)          — nothing expired (no-op); ledger byte-identical.
///   Err(Response)     — fail-closed abort (signed survivor / archive failure / write failure / changed).
#[allow(clippy::too_many_arguments)]
fn purge_locked_section(
    ledger_path: &str,
    is_global: bool,
    eid: i64,
    tid: Option<i64>,
    retention: i64,
    now: i64,
    actor: &str,
    passphrase: &str,
    arch_findings: Vec<Value>,
    arch_runs: Vec<Value>,
    del_findings_n: usize,
    del_runs_n: usize,
) -> Result<Option<PurgeOk>, Response> {
    // Open + flock the ledger for an IN-PLACE rewrite (same fcntl.flock the engine/console appenders take).
    let file = crate::open_ledger_rw(ledger_path)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "ledger_open_failed", e))?;
    let _flock = crate::FlockExclusive::acquire(&file)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "ledger_lock_failed", e))?;

    // SNAPSHOT under the flock — the AUTHORITATIVE current content. `snapshot` (raw bytes) drives the
    // change-detection compare (8b); `entries` is the parsed view via the SHARED `read_ledger_pairs`
    // helper. Both reads happen UNDER the flock, so they see the same inode content.
    let snapshot = std::fs::read_to_string(ledger_path).unwrap_or_default();
    let entries = read_ledger_pairs(ledger_path);

    // 4) compute the expired LEADING prefix (append-only => expired entries are oldest-first).
    let mut cut = 0usize;
    for (_, rec) in entries.iter() {
        let ts = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let age = match parse_ts_epoch(ts) {
            Some(ep) => now - ep,
            None => break, // unparseable ts => not expired (fail-closed) => stop the prefix here
        };
        if worm_purgeable(Some(retention), age, false) {
            cut += 1;
        } else {
            break; // first non-expired entry ends the purgeable prefix
        }
    }
    if cut == 0 {
        return Ok(None); // nothing expired => no-op (ledger untouched, byte-identical).
    }
    let survivors = &entries[cut..];
    // 5) FAIL-CLOSED: a SURVIVING signed entry cannot be re-anchored (re-hashing breaks its Ed25519 sig).
    if let Some((_, bad)) = survivors.iter().find(|(_, r)| r.get("alg").and_then(|v| v.as_str()) != Some(CONSOLE_ALG)) {
        let alg = bad.get("alg").and_then(|v| v.as_str()).unwrap_or("?");
        return Err(err(
            StatusCode::CONFLICT,
            "signed_survivor",
            format!("a surviving entry is signed (alg '{alg}') — re-anchoring would invalidate its signature; purge refused (fail-closed)"),
        ));
    }

    // 7) ARCHIVE FIRST (encrypted, reuse of the backup discipline). Nothing is mutated until this succeeds.
    let purged_lines: Vec<&str> = entries[..cut].iter().map(|(l, _)| l.as_str()).collect();
    let purged_head = entries[cut - 1].1.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let old_head = entries.last().and_then(|(_, r)| r.get("hash").and_then(|v| v.as_str())).unwrap_or("").to_string();
    let archive_doc = json!({
        "schema": "forge-compliance-archive-1",
        "engagement_id": eid,
        "tenant_id": tid,
        "created_at": now,
        "retention_secs": retention,
        "purged_head": purged_head,
        "ledger_segment": purged_lines,
        "findings": arch_findings,
        "runrecords": arch_runs,
    });
    let plaintext = match serde_json::to_vec(&archive_doc) {
        Ok(b) => b,
        Err(e) => return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "archive_build_failed", e.to_string())),
    };
    let segment_sha256 = crate::sha256_hex_bytes(&plaintext);
    let encrypted = match crate::backup_encrypt(&plaintext, passphrase) {
        Ok(c) => c,
        Err(e) => return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "archive_encrypt_failed", e)),
    };
    let archive_sha256 = crate::sha256_hex_bytes(&encrypted);
    let archive_path = format!("{ledger_path}.purged-{now}.enc");
    if let Err(e) = crate::backup_write_atomic(&archive_path, &encrypted, 0o600) {
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "archive_write_failed", e));
    }

    // 8) build the re-anchored ledger: [checkpoint R @ genesis] + [survivors re-linked (content preserved)].
    // HONEST SCOPE (FIX 1): a purge of the SHARED global ledger is scope="global" (it touches cross-scope
    // records), NOT scope=engagement/engagement_id=1 — recording "engagement" here would be a dishonest,
    // audit-defeating label. A dedicated per-engagement ledger stays scope="engagement".
    let checkpoint_detail = json!({
        "actor": actor,
        "scope": if is_global { "global" } else { "engagement" },
        "engagement_id": eid,
        "tenant_id": tid,
        "retention_secs": retention,
        "now": now,
        "purged_ledger_entries": cut,
        "purged_seq_from": entries[0].1.get("seq").cloned().unwrap_or(Value::Null),
        "purged_seq_to": entries[cut - 1].1.get("seq").cloned().unwrap_or(Value::Null),
        "purged_head": purged_head,
        "prev_before_purge": old_head,
        "segment_sha256": segment_sha256,
        "archive_path": archive_path,
        "archive_sha256": archive_sha256,
        "purged_findings": del_findings_n,
        "purged_runrecords": del_runs_n,
        "reanchor": true,
    });
    let r_seq: i64 = 0; // re-genesis marker
    let r_ts = format!("@{now}");
    let r_preimage = format!("{GENESIS}|{r_seq}|{r_ts}|{PURGE_KIND}|{}", crate::canon_json(&checkpoint_detail));
    let r_hash = crate::sha_hex(&r_preimage);
    let r_rec = json!({
        "seq": r_seq, "ts": r_ts, "kind": PURGE_KIND, "detail": checkpoint_detail,
        "prev": GENESIS, "hash": r_hash, "alg": CONSOLE_ALG, "sig": ""
    });
    let mut out = String::new();
    out.push_str(&crate::canon_json(&r_rec));
    out.push('\n');
    let mut prev = r_hash.clone();
    for (_, rec) in survivors.iter() {
        let seq = rec.get("seq").cloned().unwrap_or(Value::Null);
        let ts = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let detail = rec.get("detail").cloned().unwrap_or(Value::Null);
        let preimage = format!("{prev}|{}|{ts}|{kind}|{}", seq_to_str(&seq), crate::canon_json(&detail));
        let hash = crate::sha_hex(&preimage);
        // preserve audited content (seq/ts/kind/detail/alg/sig); re-link ONLY prev/hash.
        let mut relinked = rec.clone();
        relinked["prev"] = json!(prev);
        relinked["hash"] = json!(hash);
        out.push_str(&crate::canon_json(&relinked));
        out.push('\n');
        prev = hash;
    }

    // 8b) RE-READ under the flock just before writing; ABORT if the file changed since the snapshot. While
    // the flock is held this can't happen, but it makes the "no lost append" invariant explicit and guards
    // any future refactor that would release the lock between snapshot and write.
    let current = std::fs::read_to_string(ledger_path).unwrap_or_default();
    if current != snapshot {
        return Err(err(
            StatusCode::CONFLICT,
            "ledger_changed",
            "the ledger changed under the purge lock — aborting to avoid clobbering a concurrent append (retry); archive preserved".to_string(),
        ));
    }

    // 9) REWRITE IN PLACE on the flocked fd (NO rename — inode preserved). The archive is already durable.
    crate::rewrite_ledger_in_place(&file, out.as_bytes()).map_err(|e| {
        err(StatusCode::INTERNAL_SERVER_ERROR, "ledger_write_failed", format!("{e} (archive preserved at {archive_path})"))
    })?;

    Ok(Some(PurgeOk {
        cut,
        survivors_len: survivors.len(),
        archive_path,
        archive_sha256,
        segment_sha256,
        purged_head,
        new_head: prev,
    }))
    // _flock dropped here (LOCK_UN), then `file` dropped (close).
}

// ============================================================================================
// COMPLIANCE EVIDENCE EXPORT (READ-ONLY) — the SOC 2 / ISO 27001 audit bundle for ONE engagement.
// --------------------------------------------------------------------------------------------
// A GET, admin + flag gated, that assembles — WITHOUT mutating any audited data — the evidence a
// SOC 2 / ISO 27001 auditor asks for, SCOPED to a single tenant/engagement (+ optional timeframe):
//   1. AUTHORIZATION AUDIT TRAIL — who authorized what, when, on which scope (from the engagement's
//      tamper-evident ledger: roe.* decisions/arm/approve + console.compliance.* policy/hold/purge).
//   2. RBAC / GRANT STATE — who has access to what: local console accounts, tenant grants for THIS
//      tenant, and IdP group→role mappings for THIS tenant (isolated by tenant_id).
//   3. ACCESS / MUTATION LOG — every ledgered entry (seq/ts/kind/actor) in the window.
//   4. BACKUP ATTESTATION — restore-PROVEN: derived from the console ledger's console.restore.validate
//      (ok=true) + console.backup events + the last scheduled backup timestamp.
//   5. LEDGER INTEGRITY ATTESTATION — head hash + entries + chain verify (console re-computation) +
//      the Ed25519 public key + the exact external `forge ledger verify --pubkey` command (public key
//      only, no secret) so a third party independently proves non-repudiation.
// ISOLATION: everything is filtered to the engagement's own ledger file + engagement_id + tenant_id —
// engagement A's bundle NEVER contains B's ledger/findings/grants/mappings. SECRETS: the whole bundle
// is passed through a key-based REDACTION (passphrases/tokens/credentials/client_secret/keys → [REDACTED])
// before it leaves the process. The EXPORT itself is ADMIN-gated + LEDGERED (console.compliance.evidence.export).
// Formats: JSON (machine) + human HTML, and PDF via the SHARED report path (render_pdf_from_html, cross-
// platform wkhtmltopdf/weasyprint discovery, DEGRADES to 503 + HTML/print hint when no engine is present).
// Flag OFF => the route 404s (community byte-identical), exactly like the rest of this module.
// ============================================================================================

/// GET /api/compliance/evidence?engagement_id=&format=json|html|pdf&from=&to= — the READ-ONLY SOC 2 / ISO
/// evidence bundle for one engagement. Admin + flag. LEDGERED (`console.compliance.evidence.export`). The
/// bundle is redacted + tenant/engagement-isolated. PDF reuses the shared report engine (degrades to 503).
async fn evidence_export(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(r) = gate(&app, &headers) {
        return r;
    }
    let eid: i64 = q.get("engagement_id").and_then(|s| s.parse().ok()).unwrap_or(1);
    let format = q.get("format").map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "json".to_string());
    let from = q.get("from").and_then(|s| s.parse::<i64>().ok());
    let to = q.get("to").and_then(|s| s.parse::<i64>().ok());
    let bundle = match build_evidence(&app, eid, from, to) {
        Ok(b) => b,
        Err(e) => return *e,
    };
    // The ACT of exporting evidence is itself audited (admin attribution + head snapshot).
    let actor = crate::attribution_login(&app, &headers);
    crate::append_console_ledger(
        &app,
        "console.compliance.evidence.export",
        json!({
            "actor": actor,
            "engagement_id": eid,
            "tenant_id": bundle["engagement"]["tenant_id"].clone(),
            "format": format,
            "from": from,
            "to": to,
            "ledger_entries": bundle["counts"]["ledger_entries"].clone(),
            "ledger_head": bundle["ledger_integrity"]["head"].clone(),
            "chain_ok": bundle["ledger_integrity"]["chain_ok"].clone(),
        }),
    );
    match format.as_str() {
        "json" => (
            StatusCode::OK,
            [
                ("content-type", "application/json; charset=utf-8".to_string()),
                ("content-disposition", format!("attachment; filename=\"forge-compliance-evidence-{eid}.json\"")),
            ],
            serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".to_string()),
        )
            .into_response(),
        "html" => ([("content-type", "text/html; charset=utf-8")], Html(render_evidence_html(&bundle))).into_response(),
        "pdf" => {
            let html = render_evidence_html(&bundle);
            match crate::render_pdf_from_html(&html).await {
                Ok(pdf) => (
                    StatusCode::OK,
                    [
                        ("content-type", "application/pdf".to_string()),
                        ("content-disposition", format!("inline; filename=\"forge-compliance-evidence-{eid}.pdf\"")),
                    ],
                    pdf,
                )
                    .into_response(),
                // BORNE franchie sur un moteur PRÉSENT : cause nommée (429/504/502/501), jamais « aucun
                // moteur détecté » — cf. crate::delegated_render_error.
                Err(crate::PdfErr::Bound(e)) => crate::delegated_render_error(
                    "pdf",
                    "réessayez, ou utilisez ?format=html puis « Imprimer » → « Enregistrer au format PDF », ou ?format=json",
                    None,
                    &e,
                ),
                Err(crate::PdfErr::NoEngine) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": "pdf_unavailable",
                        "why": "aucun moteur PDF (wkhtmltopdf/weasyprint) détecté sur l'hôte",
                        "hint": "utilisez ?format=html puis « Imprimer » → « Enregistrer au format PDF » (CSS @media print fourni), ou ?format=json",
                    })),
                )
                    .into_response(),
            }
        }
        other => err(StatusCode::BAD_REQUEST, "bad_format", format!("format inconnu '{other}' (json|html|pdf)")),
    }
}


#[cfg(test)]
mod tests;

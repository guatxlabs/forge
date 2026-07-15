// SPDX-License-Identifier: AGPL-3.0-only
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

    // CRITICAL SECTION (FIX 3): read → archive → re-anchor → write must be ATOMIC vs a concurrent
    // append_console_ledger on the SHARED ledger. Both take THE SAME `ledger_lock`, so an interleaved append
    // can neither be lost (over-written by our rewrite) nor corrupt the SHA-256 chain. We hold the guard
    // across the whole rewrite and invalidate the head IN PLACE (head.loaded=false) — we must NOT call
    // app.invalidate_ledger_head() while holding it (it re-locks the SAME non-reentrant mutex => deadlock).
    // No `.await` runs while the guard is held. (For a dedicated ledger this lock is a harmless extra
    // serialization; the shared-ledger case is the one that needs it.)
    let mut head = app.ledger_lock.lock().unwrap_or_else(|e| e.into_inner());

    // 4) compute the expired LEADING prefix of the ledger (append-only => expired entries are oldest-first).
    let entries = read_ledger_pairs(&ledger_path);
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
        // nothing expired => no-op (ledger untouched, byte-identical). Not an error.
        return (StatusCode::OK, Json(json!({ "ok": true, "purged_ledger_entries": 0, "note": "nothing expired past retention" }))).into_response();
    }
    let survivors = &entries[cut..];
    // 5) FAIL-CLOSED: a SURVIVING signed entry cannot be re-anchored (re-hashing breaks its Ed25519 sig).
    if let Some((_, bad)) = survivors.iter().find(|(_, r)| r.get("alg").and_then(|v| v.as_str()) != Some(CONSOLE_ALG)) {
        let alg = bad.get("alg").and_then(|v| v.as_str()).unwrap_or("?");
        return err(
            StatusCode::CONFLICT,
            "signed_survivor",
            format!("a surviving entry is signed (alg '{alg}') — re-anchoring would invalidate its signature; purge refused (fail-closed)"),
        );
    }

    // 6) gather expired findings/runrecords (archived + deleted). Unparseable ts => kept (fail-closed).
    let (arch_findings, del_finding_ids) = collect_expired_rows(&app, eid, retention, now, "finding");
    let (arch_runs, del_run_ids) = collect_expired_rows(&app, eid, retention, now, "runrecord");

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
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "archive_build_failed", e.to_string()),
    };
    let segment_sha256 = crate::sha256_hex_bytes(&plaintext);
    let encrypted = match crate::backup_encrypt(&plaintext, &passphrase) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "archive_encrypt_failed", e),
    };
    let archive_sha256 = crate::sha256_hex_bytes(&encrypted);
    let archive_path = format!("{ledger_path}.purged-{now}.enc");
    if let Err(e) = crate::backup_write_atomic(&archive_path, &encrypted, 0o600) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "archive_write_failed", e);
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
        "purged_findings": del_finding_ids.len(),
        "purged_runrecords": del_run_ids.len(),
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
    // 9) atomically replace the ledger with the re-anchored chain (archive already safe on disk).
    if let Err(e) = crate::backup_write_atomic(&ledger_path, out.as_bytes(), 0o600) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "ledger_write_failed", format!("{e} (archive preserved at {archive_path})"));
    }
    // Invalidate the head cache IN PLACE (we HOLD the lock — calling app.invalidate_ledger_head() would
    // re-lock the same non-reentrant mutex => deadlock). The next append rebuilds head from the re-anchored
    // file. Then RELEASE the lock: the DB deletes + verify below don't touch the ledger chain.
    head.loaded = false;
    drop(head);

    // 10) delete the archived (expired) findings/runrecords rows. FAIL-CLOSED : the ledger was ALREADY
    // re-anchored above attesting `purged_findings`/`purged_runrecords` — a silent delete failure would
    // diverge ledger↔DB. On Err, surface 500 (the encrypted archive is safe on disk; a retry re-runs the
    // idempotent DELETE-by-id). No new ledger entry is written on this error path.
    if let Err(e) = delete_rows(&app, "finding", &del_finding_ids)
        .and_then(|_| delete_rows(&app, "runrecord", &del_run_ids))
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "purge_delete_failed", format!("{e} (archive preserved at {archive_path})"));
    }

    // 11) verify the re-anchored ledger under the EXISTING verifier (must stay OK).
    let v = crate::verify_ledger_chain(&ledger_path);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "engagement_id": eid,
            "purged_ledger_entries": cut,
            "purged_findings": del_finding_ids.len(),
            "purged_runrecords": del_run_ids.len(),
            "survivors": survivors.len(),
            "archive_path": archive_path,
            "archive_sha256": archive_sha256,
            "segment_sha256": segment_sha256,
            "purged_head": purged_head,
            "new_head": prev,
            "ledger_verified": v.ok,
            "checkpoint_kind": PURGE_KIND,
        })),
    )
        .into_response()
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
                Some(pdf) => (
                    StatusCode::OK,
                    [
                        ("content-type", "application/pdf".to_string()),
                        ("content-disposition", format!("inline; filename=\"forge-compliance-evidence-{eid}.pdf\"")),
                    ],
                    pdf,
                )
                    .into_response(),
                None => (
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
mod tests {
    use super::*;
    use rusqlite::Connection;
    use serde_json::json;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        p.push(uniq);
        p.to_string_lossy().into_owned()
    }

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
}

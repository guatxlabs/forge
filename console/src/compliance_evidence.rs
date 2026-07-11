// SPDX-License-Identifier: AGPL-3.0-only
//! ENTERPRISE (E3 COMPLIANCE) — evidence export + rendering + purge helper reads/deletes.
//!
//! Extracted from `compliance.rs` (PURE MOVE — byte-identical bodies, only relocation + visibility +
//! use-paths). Holds the READ-ONLY SOC 2 / ISO 27001 evidence bundle assembly (`build_evidence`) and its
//! human-HTML renderer (`render_evidence_html`), plus the ledger/row helpers the governed purge relies on
//! (`read_ledger_pairs`, `collect_expired_rows`, `delete_rows`). The HTTP handlers (routes/policy/hold/
//! purge/evidence_export) stay in `compliance.rs` and call into this module + `compliance_policy.rs`.
use crate::App;
use crate::compliance::err;
use crate::compliance_policy::{legal_hold_scope, parse_ts_epoch, resolve_retention_secs, worm_purgeable};
// Secret-key detection + recursive evidence redaction now live in the shared `crate::redact` module
// (union of the reports.rs / compliance.rs sensitive-key lists — redacts AT LEAST what this module did).
use crate::redact::redact_evidence;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{json, Value};

/// Read a ledger file as (raw_line, parsed) pairs — mirrors `crate::read_ledger_lines` but keeps the raw
/// line (archived verbatim for the purged prefix). Blank/unparseable lines are skipped.
pub(crate) fn read_ledger_pairs(path: &str) -> Vec<(String, Value)> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Value>(l).ok().map(|v| (l.to_string(), v)))
            .collect(),
        Err(_) => vec![],
    }
}

/// Collect rows of `table` (finding|runrecord) for an engagement whose `ts` is expired past retention.
/// Returns (archived JSON rows, ids to delete). Unparseable ts => kept (fail-closed). Table name is a
/// FIXED literal (never user input) — no SQL-injection surface.
pub(crate) fn collect_expired_rows(app: &App, eid: i64, retention: i64, now: i64, table: &str) -> (Vec<Value>, Vec<i64>) {
    let cols = match table {
        "finding" => "id, ts, campaign, target, title, severity, category, mitre, status",
        "runrecord" => "id, ts, campaign, target, kind, mitre, fired",
        _ => return (vec![], vec![]),
    };
    let sql = format!("SELECT {cols} FROM {table} WHERE engagement_id=?");
    
    let rows = app.store()
        .query_lax(&sql, &crate::sql_params![eid], |r| {
            let id: i64 = r.get_i64(0)?;
            let ts: String = r.get_opt_str(1)?.unwrap_or_default();
            // capture the row as a name->value map for a faithful archive.
            let mut obj = serde_json::Map::new();
            obj.insert("id".into(), json!(id));
            obj.insert("ts".into(), json!(ts.clone()));
            for (i, name) in cols.split(", ").enumerate().skip(2) {
                let v: Option<String> = r.get_opt_str(i).ok().flatten();
                obj.insert(name.trim().to_string(), json!(v));
            }
            Ok((id, ts, Value::Object(obj)))
        })
        .unwrap_or_default();
    let mut arch = vec![];
    let mut ids = vec![];
    for row in rows {
        let (id, ts, obj) = row;
        match parse_ts_epoch(&ts) {
            Some(ep) if worm_purgeable(Some(retention), now - ep, false) => {
                arch.push(obj);
                ids.push(id);
            }
            _ => {} // unparseable or not expired => keep (fail-closed)
        }
    }
    (arch, ids)
}

/// Delete rows by id from a FIXED table (finding|runrecord), ATOMICALLY (with_tx : all-or-nothing).
/// Returns the number of rows deleted, or `Err` if any delete failed (rolled back). The caller MUST
/// surface an `Err` (the WORM purge already re-anchored its ledger attesting these counts, so a silent
/// failure would diverge ledger↔DB). `{table}` is a FIXED literal identifier from the allowlist below
/// (never user input) — column/table names can't be bound in SQL; the `id` VALUE is a BOUND Param.
pub(crate) fn delete_rows(app: &App, table: &str, ids: &[i64]) -> crate::store::StoreResult<usize> {
    if ids.is_empty() || !matches!(table, "finding" | "runrecord") {
        return Ok(0);
    }
    app.store().with_tx(|tx| {
        let mut n = 0usize;
        for id in ids {
            n += tx.execute(&format!("DELETE FROM {table} WHERE id=?"), &crate::sql_params![*id])?;
        }
        Ok(n)
    })
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

/// Ledger kinds that constitute the AUTHORIZATION audit trail (an authorization decision / grant / a
/// governed compliance action). Everything else is still captured in the access/mutation log.
fn is_authorization_kind(kind: &str) -> bool {
    kind.starts_with("roe.")
        || kind.ends_with(".decision")
        || kind.contains("approve")
        || kind.contains("authorize")
        || kind.starts_with("console.compliance.")
        || kind == "console.engagement.create"
        || kind == "console.setup.provision"
}

fn ledger_actor(detail: &Value) -> String {
    detail.get("actor").and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// Assemble the READ-ONLY evidence bundle for `eid`, scoped + isolated + redacted. Never mutates data.
/// `from`/`to` (epoch seconds, optional) bound the ledger window; an unparseable ts is KEPT (audit data
/// is never silently dropped). Err(Response) on an unknown engagement (404).
pub(crate) fn build_evidence(app: &App, eid: i64, from: Option<i64>, to: Option<i64>) -> Result<Value, Box<Response>> {
    // 1) engagement identity (isolation anchor).
    let (name, status, mode, tenant_id) = {
        let store = app.store();
        match store.query_row(
            "SELECT name, status, mode, tenant_id FROM engagement WHERE id=?",
            &crate::sql_params![eid],
            |r| Ok((r.get_str(0)?, r.get_str(1)?, r.get_str(2)?, r.get_i64(3)?)),
        ) {
            Ok(t) => t,
            Err(_) => return Err(Box::new(err(StatusCode::NOT_FOUND, "unknown_engagement", format!("engagement {eid} introuvable")))),
        }
    };

    // 2) ledger integrity attestation (this engagement's OWN tamper-evident ledger).
    let ledger_path = crate::engagement_ledger_path(app, eid);
    let verify = crate::verify_ledger_chain(&ledger_path);
    let pubkey = std::env::var("FORGE_CONSOLE_LEDGER_PUBKEY").unwrap_or_default();
    let verify_cmd = format!(
        "forge ledger verify --ledger {} --pubkey {}",
        ledger_path,
        if pubkey.is_empty() { "<pubkey_hex>" } else { pubkey.as_str() }
    );
    let entries = crate::read_ledger_lines(&ledger_path);

    // 3) walk the ledger ONCE → authorization audit trail + access/mutation log (timeframe-filtered).
    let in_window = |ts: &str| -> bool {
        match parse_ts_epoch(ts) {
            Some(ep) => from.is_none_or(|f| ep >= f) && to.is_none_or(|t| ep <= t),
            None => true, // unparseable => keep (never silently drop audit data)
        }
    };
    let mut auth_trail: Vec<Value> = vec![];
    let mut access_log: Vec<Value> = vec![];
    for rec in entries.iter() {
        let ts = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        if !in_window(ts) {
            continue;
        }
        let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let seq = rec.get("seq").cloned().unwrap_or(Value::Null);
        let detail = rec.get("detail").cloned().unwrap_or(Value::Null);
        let actor = ledger_actor(&detail);
        let epoch = parse_ts_epoch(ts);
        access_log.push(json!({
            "seq": seq, "ts": ts, "epoch": epoch, "kind": kind, "actor": actor,
            "alg": rec.get("alg").cloned().unwrap_or(Value::Null),
        }));
        if is_authorization_kind(kind) {
            let scope = detail
                .get("scope")
                .and_then(|v| v.as_str())
                .or_else(|| detail.get("target").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            auth_trail.push(json!({
                "seq": seq, "ts": ts, "epoch": epoch, "kind": kind, "actor": actor,
                "scope": scope, "detail": detail,
            }));
        }
    }

    // 4) RBAC / grant state — accounts (console roster) + tenant grants + IdP group mappings for THIS
    //    tenant (isolated by tenant_id). rbac_group_map is created lazily by rbac.rs => tolerate absence.
    let mut accounts: Vec<Value> = vec![];
    let mut tenant_grants: Vec<Value> = vec![];
    let mut group_mappings: Vec<Value> = vec![];
    {
        let store = app.store();
        accounts = store
            .query_lax("SELECT login, role, disabled FROM users ORDER BY login", &[], |r| {
                Ok(json!({ "login": r.get_str(0)?, "role": r.get_str(1)?, "disabled": r.get_i64(2)? != 0 }))
            })
            .unwrap_or_default();
        tenant_grants = store
            .query_lax(
                "SELECT u.login, tg.role FROM tenant_grant tg JOIN users u ON u.id=tg.user_id WHERE tg.tenant_id=? ORDER BY u.login",
                &crate::sql_params![tenant_id],
                |r| Ok(json!({ "login": r.get_str(0)?, "tenant_role": r.get_str(1)? })),
            )
            .unwrap_or_default();
        group_mappings = store
            .query_lax(
                "SELECT idp_group, role, tenant_id, tenant_role FROM rbac_group_map WHERE tenant_id=? ORDER BY idp_group",
                &crate::sql_params![tenant_id],
                |r| {
                    Ok(json!({
                        "idp_group": r.get_str(0)?, "role": r.get_str(1)?,
                        "tenant_id": r.get_opt_i64(2)?, "tenant_role": r.get_opt_str(3)?,
                    }))
                },
            )
            .unwrap_or_default();
    }

    // 5) backup attestation (restore-PROVEN) — scanned from the console (global) ledger: backup/restore
    //    are platform-wide operations, not per-engagement. NEVER carries a passphrase (metadata only).
    let mut restore_validations = 0i64;
    let mut restore_proven = false;
    let mut last_restore_at: Value = Value::Null;
    let mut backup_events = 0i64;
    let mut last_backup_at: Value = Value::Null;
    for rec in crate::read_ledger_lines(app.ledger_path.as_str()).iter() {
        let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let ts = rec.get("ts").cloned().unwrap_or(Value::Null);
        let detail = rec.get("detail").cloned().unwrap_or(Value::Null);
        if kind == "console.restore.validate" {
            restore_validations += 1;
            if detail.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                restore_proven = true;
                last_restore_at = ts.clone();
            }
        } else if kind.starts_with("console.backup") && !kind.ends_with(".error") {
            backup_events += 1;
            last_backup_at = ts.clone();
        }
    }
    let backup_last_run = {
        let store = app.store();
        crate::settings_get_store(&store, "backup_last_run")
    };
    let backup_configured = {
        let store = app.store();
        crate::settings_get_store(&store, "backup_policy").is_some()
    };

    // 6) counts (this engagement only) + retention/hold policy in force.
    let (n_findings, n_runrecords) = {
        let store = app.store();
        let nf: i64 = store.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=?", &crate::sql_params![eid], |r| r.get_i64(0)).unwrap_or(0);
        let nr: i64 = store.query_row("SELECT COUNT(*) FROM runrecord WHERE engagement_id=?", &crate::sql_params![eid], |r| r.get_i64(0)).unwrap_or(0);
        drop(store);
        (nf, nr)
    };
    let retention = resolve_retention_secs(app, eid, Some(tenant_id));
    let hold = legal_hold_scope(app, eid, Some(tenant_id));

    let mut bundle = json!({
        "schema": "forge-compliance-evidence-1",
        "framework": "SOC 2 / ISO 27001 — audit evidence bundle",
        "generated_at": crate::now_epoch(),
        "engagement": { "id": eid, "name": name, "status": status, "mode": mode, "tenant_id": tenant_id },
        "timeframe": { "from": from, "to": to },
        "ledger_integrity": {
            "path": ledger_path,
            "head": verify.head,
            "entries": verify.entries,
            "chain_ok": verify.ok,
            "alg": verify.alg,
            "why": verify.why,
            "pubkey": pubkey,
            "signature_algorithm": "ed25519 (asymmetric — non-repudiation, verifiable with the public key alone)",
            "verify_command": verify_cmd,
            "note": "The SHA-256 hash-chain is recomputed console-side (chain_ok). Full Ed25519 signature verification is run externally via verify_command using ONLY the public key — no secret is required or included.",
        },
        "authorization_audit_trail": auth_trail,
        "rbac_grant_state": {
            "accounts": accounts,
            "tenant_grants": tenant_grants,
            "group_mappings": group_mappings,
        },
        "access_mutation_log": access_log,
        "backup_attestation": {
            "restore_proven": restore_proven,
            "restore_validations": restore_validations,
            "last_restore_validated_at": last_restore_at,
            "backup_events": backup_events,
            "last_backup_event_at": last_backup_at,
            "backup_last_run": backup_last_run,
            "backup_policy_configured": backup_configured,
        },
        "retention_policy": {
            "effective_retention_secs": retention,
            "legal_hold": hold.is_some(),
            "legal_hold_scope": hold,
        },
        "counts": {
            "findings": n_findings,
            "runrecords": n_runrecords,
            "ledger_entries": entries.len(),
            "authorization_events": auth_trail.len(),
        },
        "redaction": "Secrets (passphrases, tokens, credentials, client_secret, private keys) are redacted with [REDACTED]. Public keys are preserved.",
    });
    // FAIL-SAFE: redact any secret-named field anywhere in the bundle before it leaves the process.
    redact_evidence(&mut bundle);
    Ok(bundle)
}

/// Render the evidence bundle as a self-contained, human-readable HTML document (the auditor-facing view;
/// also the PDF source). All dynamic text is HTML-escaped (crate::html_escape). The bundle is already
/// redacted, so nothing secret can reach this renderer.
pub(crate) fn render_evidence_html(b: &Value) -> String {
    let e = |s: &str| crate::html_escape(s);
    let sv = |v: &Value| -> String {
        match v {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        }
    };
    let eid = b["engagement"]["id"].as_i64().unwrap_or(0);
    let mut h = String::new();
    h.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    h.push_str(&format!("<title>Forge — Compliance Evidence — engagement {eid}</title>"));
    h.push_str("<style>");
    h.push_str("body{font:14px/1.55 system-ui,'Segoe UI',Roboto,sans-serif;color:#1a1f2b;margin:0;padding:34px;background:#fff}");
    h.push_str("h1{font-size:22px;margin:0 0 2px}h2{font-size:15px;margin:26px 0 8px;border-bottom:2px solid #2b3a55;padding-bottom:4px}");
    h.push_str(".muted{color:#5a6473}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}");
    h.push_str("table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px}th,td{border:1px solid #d5dae3;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f0f3f8}");
    h.push_str(".ok{color:#0a7d33;font-weight:600}.bad{color:#b40020;font-weight:600}");
    h.push_str(".pill{display:inline-block;background:#eef2f8;border:1px solid #d5dae3;border-radius:10px;padding:1px 8px;font-size:11px;margin-right:6px}");
    h.push_str("pre.cmd{background:#0f1626;color:#d7e2f4;padding:10px;border-radius:6px;overflow-x:auto;font-size:12px}");
    h.push_str("@media print{body{padding:0}h2{break-after:avoid}table{break-inside:auto}tr{break-inside:avoid}}");
    h.push_str("</style></head><body>");

    // Header
    h.push_str(&format!(
        "<h1>Forge — Compliance Evidence Bundle</h1><div class=\"muted\">{} · engagement <b>#{}</b> «&nbsp;{}&nbsp;» · tenant {} · mode {} · status {}</div>",
        e(b["framework"].as_str().unwrap_or("")),
        eid,
        e(b["engagement"]["name"].as_str().unwrap_or("")),
        b["engagement"]["tenant_id"].as_i64().unwrap_or(0),
        e(b["engagement"]["mode"].as_str().unwrap_or("")),
        e(b["engagement"]["status"].as_str().unwrap_or("")),
    ));
    let tf = &b["timeframe"];
    h.push_str(&format!(
        "<div class=\"muted\">generated_at {} (epoch) · timeframe from {} to {}</div>",
        b["generated_at"].as_i64().unwrap_or(0),
        if sv(&tf["from"]).is_empty() { "—".to_string() } else { sv(&tf["from"]) },
        if sv(&tf["to"]).is_empty() { "—".to_string() } else { sv(&tf["to"]) },
    ));

    // 1) Ledger integrity attestation
    let li = &b["ledger_integrity"];
    h.push_str("<h2>1. Ledger integrity attestation</h2>");
    let chain_ok = li["chain_ok"].as_bool().unwrap_or(false);
    h.push_str(&format!(
        "<p><span class=\"pill\">entries {}</span><span class=\"pill\">alg {}</span><span class=\"{}\">hash-chain {}</span></p>",
        li["entries"].as_u64().unwrap_or(0),
        e(li["alg"].as_str().unwrap_or("")),
        if chain_ok { "ok" } else { "bad" },
        if chain_ok { "VERIFIED" } else { "BROKEN" },
    ));
    h.push_str(&format!("<div class=\"muted\">head hash</div><div class=\"mono\">{}</div>", e(&sv(&li["head"]))));
    h.push_str(&format!("<div class=\"muted\" style=\"margin-top:6px\">Ed25519 public key</div><div class=\"mono\">{}</div>",
        { let pk = sv(&li["pubkey"]); if pk.is_empty() { "&lt;not exposed — set FORGE_CONSOLE_LEDGER_PUBKEY&gt;".to_string() } else { e(&pk) } }));
    h.push_str(&format!("<div class=\"muted\" style=\"margin-top:6px\">External non-repudiation verification (public key only):</div><pre class=\"cmd\">{}</pre>", e(li["verify_command"].as_str().unwrap_or(""))));

    // 2) Retention / legal-hold in force
    let rp = &b["retention_policy"];
    h.push_str("<h2>2. Retention &amp; legal-hold policy</h2>");
    h.push_str(&format!(
        "<p><span class=\"pill\">retention {}</span><span class=\"pill\">legal-hold {}</span>{}</p>",
        if sv(&rp["effective_retention_secs"]).is_empty() { "unset".to_string() } else { format!("{}s", sv(&rp["effective_retention_secs"])) },
        if rp["legal_hold"].as_bool().unwrap_or(false) { "ACTIVE" } else { "none" },
        rp["legal_hold_scope"].as_str().map(|s| format!("<span class=\"pill\">scope {}</span>", e(s))).unwrap_or_default(),
    ));

    // 3) Authorization audit trail
    h.push_str("<h2>3. Authorization audit trail</h2>");
    h.push_str("<div class=\"muted\">Who authorized what, when, on which scope (from the tamper-evident ledger).</div>");
    let auth = b["authorization_audit_trail"].as_array().cloned().unwrap_or_default();
    if auth.is_empty() {
        h.push_str("<p class=\"muted\">No authorization events in the selected window.</p>");
    } else {
        h.push_str("<table><thead><tr><th>seq</th><th>ts</th><th>kind</th><th>actor</th><th>scope</th></tr></thead><tbody>");
        for a in auth.iter() {
            h.push_str(&format!(
                "<tr><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                sv(&a["seq"]),
                e(a["ts"].as_str().unwrap_or("")),
                e(a["kind"].as_str().unwrap_or("")),
                e(a["actor"].as_str().unwrap_or("")),
                e(a["scope"].as_str().unwrap_or("")),
            ));
        }
        h.push_str("</tbody></table>");
    }

    // 4) RBAC / grant state
    let rg = &b["rbac_grant_state"];
    h.push_str("<h2>4. RBAC / grant state (who has access to what)</h2>");
    let accounts = rg["accounts"].as_array().cloned().unwrap_or_default();
    h.push_str("<h3 style=\"font-size:13px;margin:8px 0 2px\">Console accounts</h3><table><thead><tr><th>login</th><th>role</th><th>state</th></tr></thead><tbody>");
    for a in accounts.iter() {
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            e(a["login"].as_str().unwrap_or("")),
            e(a["role"].as_str().unwrap_or("")),
            if a["disabled"].as_bool().unwrap_or(false) { "<span class=\"bad\">disabled</span>" } else { "active" },
        ));
    }
    h.push_str("</tbody></table>");
    let grants = rg["tenant_grants"].as_array().cloned().unwrap_or_default();
    if !grants.is_empty() {
        h.push_str("<h3 style=\"font-size:13px;margin:8px 0 2px\">Tenant grants (this tenant)</h3><table><thead><tr><th>login</th><th>tenant role</th></tr></thead><tbody>");
        for g in grants.iter() {
            h.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", e(g["login"].as_str().unwrap_or("")), e(g["tenant_role"].as_str().unwrap_or(""))));
        }
        h.push_str("</tbody></table>");
    }
    let maps = rg["group_mappings"].as_array().cloned().unwrap_or_default();
    if !maps.is_empty() {
        h.push_str("<h3 style=\"font-size:13px;margin:8px 0 2px\">IdP group → role mappings (this tenant)</h3><table><thead><tr><th>group</th><th>role</th><th>tenant role</th></tr></thead><tbody>");
        for m in maps.iter() {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                e(m["idp_group"].as_str().unwrap_or("")),
                e(m["role"].as_str().unwrap_or("")),
                e(m["tenant_role"].as_str().unwrap_or("")),
            ));
        }
        h.push_str("</tbody></table>");
    }

    // 5) Backup attestation
    let ba = &b["backup_attestation"];
    h.push_str("<h2>5. Backup attestation (restore-proven)</h2>");
    let proven = ba["restore_proven"].as_bool().unwrap_or(false);
    h.push_str(&format!(
        "<p><span class=\"{}\">restore {}</span> · restore validations: {} · backup events: {} · last backup run: {}</p>",
        if proven { "ok" } else { "bad" },
        if proven { "PROVEN" } else { "NOT PROVEN" },
        ba["restore_validations"].as_i64().unwrap_or(0),
        ba["backup_events"].as_i64().unwrap_or(0),
        { let s = sv(&ba["backup_last_run"]); if s.is_empty() { "—".to_string() } else { e(&s) } },
    ));

    // 6) Counts
    let c = &b["counts"];
    h.push_str("<h2>6. Scope counts</h2>");
    h.push_str(&format!(
        "<p><span class=\"pill\">findings {}</span><span class=\"pill\">runrecords {}</span><span class=\"pill\">ledger entries {}</span><span class=\"pill\">authorization events {}</span></p>",
        c["findings"].as_i64().unwrap_or(0),
        c["runrecords"].as_i64().unwrap_or(0),
        c["ledger_entries"].as_i64().unwrap_or(0),
        c["authorization_events"].as_i64().unwrap_or(0),
    ));

    h.push_str(&format!("<hr style=\"margin:24px 0;border:0;border-top:1px solid #d5dae3\"><div class=\"muted\">{}</div>", e(b["redaction"].as_str().unwrap_or(""))));
    h.push_str("</body></html>");
    h
}

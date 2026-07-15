// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — CONSOLE FORGE IN-UI (roadmap P5). A GOUVERNED, ADMIN-ONLY runner of a SMALL, HARD
//! allowlist of `forge` subcommands, exposed as `POST /api/console/exec` and streamed live to the SPA
//! over SSE. It removes the need to `docker compose exec forge forge …` for common ops.
//!
//! THIS IS NOT A SHELL. There is no free-form command, no arbitrary flag, no shell metacharacter path.
//! Every request names ONE allowlisted subcommand (`status`, `ledger verify`, `read-*`, `backup`,
//! `upgrade`); each subcommand carries a per-command ARG SCHEMA (a fixed set of typed flags). The
//! server builds a FIXED argv array `[subcommand, --flag, typed-value, …]` from the VALIDATED
//! (command, allowlisted-flag, typed-value) triples and spawns the `forge` BINARY directly with that
//! argv — never `sh -c`, never a shell string, never user text promoted to a flag. Anything not in the
//! allowlist (unknown command, smuggled flag, shell metachar, traversal) is refused fail-closed (400).
//!
//! GOVERNANCE: admin-only (`check_admin`, 403 otherwise) · every exec is ledgered `console.exec`
//! (command + actor + REDACTED args — a passphrase VALUE is NEVER present, only the VAR NAME) ·
//! state-changing commands (`upgrade` non-dry-run) require an explicit `confirm:true` · output size +
//! runtime are capped (no DoS). Reuses the no-shell spawn (`spawn_setsid`/`kill_group`) + line-pump
//! plumbing of the run supervisor — a governed exec is a mini-run.
//!
//! Re-exported `pub(crate)` at the crate root; the route is merged into `build_router`'s protected
//! router (inherits `auth_guard`/`host_guard` like every other API route).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::{admin_denied, append_console_ledger, attribution_login, check_admin, App};

/// Hard allowlist of console-exposed subcommands (stable IDs used by the UI + the fail-closed error).
/// EXCLUDED on purpose (see module + docs): `restore` (destructive overwrite of db+ledger+key),
/// `migrate-store`/`migrate` (store cutover — destructive, operator-CLI only), `seed-demo` (dev
/// fixture), `useradd`/`hashpw` (the UI already manages users), `blob-selftest` (dev round-trip).
const ALLOWLIST: &[&str] = &[
    "status",
    "ledger-verify",
    "read-findings",
    "read-roe",
    "read-coverage",
    "backup",
    "upgrade",
];

/// Output cap for a single exec (bytes across stdout+stderr). Past the cap we stop EMITTING but keep
/// draining the pipes so the child never blocks on a full buffer. Prevents an unbounded-output DoS.
const OUTPUT_CAP_BYTES: usize = 256 * 1024;

/// Characters we refuse in ANY string value — shell metacharacters + whitespace. Defense in depth:
/// we never pass args through a shell (fixed argv), but a value carrying these is rejected anyway so a
/// crafted `/api/console/exec` cannot even ATTEMPT a smuggle. Control bytes are rejected separately.
const SHELL_META: &str = " \t\r\n;&|$`<>(){}[]!*?~#\"'\\";

fn has_shell_meta(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || SHELL_META.contains(c))
}

/// A validated, ready-to-spawn plan. `argv` is the FIXED subcommand-token array (NO binary, NO shell);
/// `redacted` is what we write to the ledger (secret VALUES never present — only var NAMES/basenames);
/// `state_changing` marks a command that mutates state and therefore requires an explicit `confirm`.
#[cfg_attr(test, derive(Debug))]
struct ExecPlan {
    argv: Vec<String>,
    redacted: Value,
    state_changing: bool,
}

/// Runtime cap for a single exec. Default 300s (backup/upgrade can be slow); env-overridable within
/// sane bounds. On timeout the whole process GROUP is killed (`kill_group`) and reaped.
fn exec_timeout() -> Duration {
    let secs = std::env::var("FORGE_CONSOLE_EXEC_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0 && *n <= 3600)
        .unwrap_or(300);
    Duration::from_secs(secs)
}

/// The `forge` binary to exec. FIXED — never derived from user input. Defaults to the running console
/// binary itself (its OWN CLI subcommands are exactly what we allowlist, cf. `dispatch_cli`).
/// Overridable ONLY via a trusted server-side env var (tests / non-standard installs).
fn forge_exec_bin() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("FORGE_CONSOLE_EXEC_BIN") {
        if !p.is_empty() {
            return p.into();
        }
    }
    std::env::current_exe().unwrap_or_else(|_| "forge".into())
}

/// Managed directory backups are written INTO. A console `backup --out` accepts only a BASENAME; the
/// server joins it under this dir, so no path a caller supplies can escape it (anti-traversal).
fn managed_backup_dir() -> String {
    std::env::var("FORGE_CONSOLE_BACKUP_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "console-backups".to_string())
}

fn bad(err: &str, why: &str) -> (StatusCode, Value) {
    (StatusCode::BAD_REQUEST, json!({ "error": err, "why": why }))
}

/// A restricted identifier: `[A-Za-z0-9._-]`, non-empty, length-capped, NOT starting with `-`
/// (anti-flag hygiene — a value must never be mistakable for an option). Excludes `/` and every shell
/// metachar by construction.
fn is_ident(s: &str, maxlen: usize) -> bool {
    !s.is_empty()
        && s.len() <= maxlen
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A SAFE backup filename: an identifier with NO `..` sequence and no leading dot (anti-traversal /
/// no hidden files). `/` is already excluded by `is_ident`.
fn is_safe_basename(s: &str) -> bool {
    is_ident(s, 80) && !s.contains("..") && !s.starts_with('.')
}

/// An ENV VARIABLE NAME (not a value): `^[A-Z_][A-Z0-9_]*$`, length-capped. This is what the caller
/// supplies for `--passphrase-env`; the SECRET itself is resolved server-side and never travels.
fn is_env_var_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().next().map(|c| c.is_ascii_uppercase() || c == '_').unwrap_or(false)
        && s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Validate a `--passphrase-env` VAR NAME and CONFIRM it resolves server-side via `secret_from_env`
/// (which also handles the `*_FILE` Docker/k8s indirection). The resolved VALUE is dropped immediately
/// and NEVER echoed, argv'd, or ledgered — the child `forge` process re-resolves it itself. Fail-closed
/// (400) if the name is malformed or the secret is empty/absent.
fn check_passphrase_env(var: &str) -> Result<(), (StatusCode, Value)> {
    if has_shell_meta(var) || !is_env_var_name(var) {
        return Err(bad(
            "invalid_arg",
            "passphrase-env : NOM de variable d'ENV ^[A-Z_][A-Z0-9_]*$ (≤64), pas une valeur",
        ));
    }
    match crate::secret_from_env(var) {
        Some(_secret) => Ok(()), // resolved — VALUE dropped HERE; never leaves the server
        None => Err(bad(
            "secret_unresolved",
            "passphrase-env : la variable (ou son *_FILE) est vide/absente côté serveur (fail-closed)",
        )),
    }
}

/// Refuse any arg key that is not in this command's schema (fail-closed on a smuggled flag).
fn reject_unknown_keys(
    args: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), (StatusCode, Value)> {
    for k in args.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "flag_not_in_schema",
                    "why": format!("argument '{k}' non autorisé pour cette commande (schéma strict, fail-closed)"),
                    "allowed_args": allowed,
                }),
            ));
        }
    }
    Ok(())
}

/// PURE validation core: (command, args) -> a fixed-argv `ExecPlan` OR a fail-closed 400. No spawn, no
/// side effects (except lazily ensuring the managed backup dir exists for `backup`). This is the single
/// choke point that turns untrusted input into a FIXED argv — the whole not-a-shell guarantee lives here.
fn plan_exec(
    command: &str,
    args: &serde_json::Map<String, Value>,
) -> Result<ExecPlan, (StatusCode, Value)> {
    let want_flag = |name: &str| -> bool { args.get(name).and_then(|v| v.as_bool()).unwrap_or(false) };
    let want_str = |name: &str| -> Option<String> {
        args.get(name).and_then(|v| v.as_str()).map(|s| s.to_string())
    };

    match command {
        // --- read-only, no args -------------------------------------------------------------------
        "status" => {
            reject_unknown_keys(args, &[])?;
            Ok(ExecPlan { argv: vec!["status".into()], redacted: json!({}), state_changing: false })
        }
        "ledger-verify" => {
            reject_unknown_keys(args, &[])?;
            Ok(ExecPlan {
                argv: vec!["ledger".into(), "verify".into()],
                redacted: json!({}),
                state_changing: false,
            })
        }

        // --- read-only reads (safe query args) ----------------------------------------------------
        "read-findings" | "read-roe" | "read-coverage" => {
            reject_unknown_keys(args, &["campaign", "json"])?;
            let sub = match command {
                "read-findings" => "findings",
                "read-roe" => "roe",
                _ => "coverage",
            };
            let mut argv = vec![sub.to_string()];
            let mut red = serde_json::Map::new();
            if let Some(c) = want_str("campaign") {
                if has_shell_meta(&c) || !is_ident(&c, 64) {
                    return Err(bad(
                        "invalid_arg",
                        "campaign : identifiant [A-Za-z0-9._-] (≤64), sans métacaractères",
                    ));
                }
                argv.push("--campaign".into());
                argv.push(c.clone());
                red.insert("campaign".into(), json!(c));
            }
            if want_flag("json") {
                argv.push("--json".into());
                red.insert("json".into(), json!(true));
            }
            Ok(ExecPlan { argv, redacted: Value::Object(red), state_changing: false })
        }

        // --- creates an encrypted backup file into the MANAGED dir --------------------------------
        "backup" => {
            reject_unknown_keys(args, &["out", "passphrase-env"])?;
            let out = want_str("out")
                .ok_or_else(|| bad("arg_required", "backup : --out <nom-de-fichier géré> requis"))?;
            if has_shell_meta(&out) || !is_safe_basename(&out) {
                return Err(bad(
                    "invalid_arg",
                    "out : nom de fichier simple [A-Za-z0-9._-] (≤80), sans '/' ni '..'",
                ));
            }
            let var = want_str("passphrase-env")
                .ok_or_else(|| bad("arg_required", "backup : --passphrase-env <VAR> requis"))?;
            check_passphrase_env(&var)?;
            let dir = managed_backup_dir();
            let _ = std::fs::create_dir_all(&dir);
            let full = format!("{}/{}", dir.trim_end_matches('/'), out);
            let argv = vec![
                "backup".into(),
                "--out".into(),
                full.clone(),
                "--passphrase-env".into(),
                var.clone(),
            ];
            Ok(ExecPlan {
                // out path + var NAME only — the passphrase VALUE is resolved by the child, never here.
                redacted: json!({ "out": full, "passphrase-env": var }),
                argv,
                state_changing: false, // creates a self-contained file; not a destructive mutation
            })
        }

        // --- state-changing (fail-closed pre-backup + rollback); requires confirm unless --dry-run -
        "upgrade" => {
            reject_unknown_keys(args, &["passphrase-env", "dry-run"])?;
            let var = want_str("passphrase-env")
                .ok_or_else(|| bad("arg_required", "upgrade : --passphrase-env <VAR> requis"))?;
            check_passphrase_env(&var)?;
            let dry = want_flag("dry-run");
            let mut argv = vec!["upgrade".into(), "--passphrase-env".into(), var.clone()];
            if dry {
                argv.push("--dry-run".into());
            }
            Ok(ExecPlan {
                redacted: json!({ "passphrase-env": var, "dry-run": dry }),
                argv,
                state_changing: !dry, // a REAL upgrade mutates -> must be confirmed; --dry-run mutates nothing
            })
        }

        _ => Err((
            StatusCode::BAD_REQUEST,
            json!({
                "error": "command_not_allowlisted",
                "why": "sous-commande non autorisée par la console (allowlist stricte, fail-closed)",
                "allowed": ALLOWLIST,
            }),
        )),
    }
}

/// Emit one output line to the SSE channel, enforcing the SHARED byte cap. Past the cap: emit a single
/// truncation notice and then swallow further lines (the caller keeps draining the pipe so the child
/// never blocks).
async fn emit_capped(
    tx: &tokio::sync::mpsc::Sender<Value>,
    sent: &AtomicUsize,
    trunc: &AtomicBool,
    stream: &str,
    line: String,
) {
    let n = line.len() + 1;
    let prev = sent.fetch_add(n, Ordering::Relaxed);
    if prev >= OUTPUT_CAP_BYTES {
        if !trunc.swap(true, Ordering::Relaxed) {
            let _ = tx
                .send(json!({"kind":"log","stream":"system","line":"[sortie tronquée — plafond de sortie atteint]"}))
                .await;
        }
        return;
    }
    let _ = tx.send(json!({"kind":"log","stream":stream,"line":line})).await;
}

/// POST /api/console/exec — ADMIN-ONLY, LEDGERED, STREAMED. Body: `{command, args?:{…}, confirm?:bool}`.
/// Validates against the allowlist + per-command arg schema (fail-closed 400 on anything unlisted or
/// smuggled), refuses a non-dry-run state-changing command without `confirm:true`, ledgers `console.exec`
/// (redacted), then spawns the `forge` binary with a FIXED argv (no shell) and streams stdout/stderr as
/// SSE (`log`/`status` events) with output + time caps.
pub(crate) async fn console_exec(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // (1) ADMIN-ONLY, fail-closed (no operator/env-hash fallback — individual attribution required).
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);

    // (2) command + args.
    let command = body.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if command.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"command_required","why":"champ 'command' requis (sous-commande allowlistée)"})),
        )
            .into_response();
    }
    let args = body
        .get("args")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    // (3) PLAN — allowlist + per-command arg schema. The ONLY place untrusted input becomes a fixed argv.
    let plan = match plan_exec(&command, &args) {
        Ok(p) => p,
        Err((code, j)) => return (code, Json(j)).into_response(),
    };

    // (4) state-changing commands demand an explicit confirm (deliberate action).
    let confirmed = body.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
    if plan.state_changing && !confirmed {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "confirm_required",
                "why": "commande à effet d'état — exige \"confirm\": true dans le corps (action délibérée)",
                "command": command,
            })),
        )
            .into_response();
    }

    // (5) LEDGER the governed exec BEFORE running it. Redacted args carry var NAMES/basenames only — no
    //     secret VALUE ever enters the ledger (the passphrase is resolved by the child, not here).
    append_console_ledger(
        &app,
        "console.exec",
        json!({
            "command": command,
            "by": actor,
            "args": plan.redacted,
            "confirm": confirmed,
            "state_changing": plan.state_changing,
            "argv": plan.argv, // fixed subcommand tokens (var NAMES / basenames only — never a secret value)
        }),
    );

    // (6) SPAWN — the `forge` binary with the FIXED argv. No shell, setsid (own process group so a
    //     timeout can killpg the whole subtree), piped stdout/stderr, kill_on_drop.
    let bin = forge_exec_bin();
    let mut cmd = tokio::process::Command::new(&bin);
    cmd.args(&plan.argv)
        .env("PYTHONUNBUFFERED", "1") // parity w/ run spawn: unbuffered child output -> live lines
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    crate::spawn_setsid(&mut cmd);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"spawn_failed","why": e.to_string()})),
            )
                .into_response();
        }
    };
    let pgid = child.id().map(|p| p as i32).unwrap_or(-1); // setsid => child PID == PGID
    let timeout = exec_timeout();

    // (7) STREAM — pump stdout+stderr lines into an mpsc channel (capped), await with a watchdog, then
    //     emit a terminal `status` event. The receiver is unfolded into an SSE response.
    let (tx, rx) = tokio::sync::mpsc::channel::<Value>(256);
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let sent = Arc::new(AtomicUsize::new(0));
        let trunc = Arc::new(AtomicBool::new(false));

        let (t1, s1, r1) = (tx.clone(), sent.clone(), trunc.clone());
        let pump_out = tokio::spawn(async move {
            if let Some(out) = stdout {
                let mut lines = BufReader::new(out).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    emit_capped(&t1, &s1, &r1, "stdout", line).await;
                }
            }
        });
        let (t2, s2, r2) = (tx.clone(), sent.clone(), trunc.clone());
        let pump_err = tokio::spawn(async move {
            if let Some(err) = stderr {
                let mut lines = BufReader::new(err).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    emit_capped(&t2, &s2, &r2, "stderr", line).await;
                }
            }
        });

        let (status_str, exit_code): (&str, Option<i64>) =
            match tokio::time::timeout(timeout, child.wait()).await {
                Ok(Ok(status)) => {
                    let code = status.code().map(|c| c as i64);
                    if status.success() { ("done", code) } else { ("failed", code) }
                }
                Ok(Err(_)) => ("failed", None),
                Err(_) => {
                    crate::kill_group(pgid);
                    let _ = child.wait().await; // reap
                    let _ = tx
                        .send(json!({"kind":"log","stream":"system",
                            "line": format!("[watchdog : délai {}s dépassé — process tué]", timeout.as_secs())}))
                        .await;
                    ("timeout", None)
                }
            };
        let _ = pump_out.await;
        let _ = pump_err.await;
        let _ = tx.send(json!({"kind":"status","status":status_str,"exit_code":exit_code})).await;
        // tx dropped here -> the SSE stream terminates.
    });

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Some(v) => {
                let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("log").to_string();
                let event = Event::default()
                    .event(kind)
                    .json_data(&v)
                    .unwrap_or_else(|_| Event::default().comment("bad"));
                Some((Ok::<Event, std::convert::Infallible>(event), rx))
            }
            None => None,
        }
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("keep-alive"))
        .into_response()
}

/// Route table — merged into `build_router`'s protected router (inherits auth_guard/host_guard).
pub(crate) fn routes() -> Router<App> {
    Router::new().route("/api/console/exec", post(console_exec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::*;
    use axum::http::StatusCode;
    use rusqlite::Connection;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    /// Minimal in-memory App for exec tests (ledger on disk, rest inert) — a local copy of main.rs's
    /// private `test_app` (that helper is not `pub(crate)`), kept in sync field-for-field.
    fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(SCHEMA).expect("schema");
        let (events, _) = broadcast::channel::<RunEvent>(64);
        App {
            db: StdArc::new(StdMutex::new(conn)),
            db_path: StdArc::new(":memory:".into()),
            #[cfg(feature = "store-postgres")]
            pg: None,
            #[cfg(feature = "store-postgres")]
            ha: false,
            #[cfg(feature = "store-postgres")]
            instance_id: StdArc::new("test-instance".into()),
            #[cfg(feature = "store-postgres")]
            is_leader: StdArc::new(AtomicBool::new(true)),
            token_sha: StdArc::new(sha_hex("t")),
            token_raw: StdArc::new("t".into()),
            user: StdArc::new("forge".into()),
            pass_hash: StdArc::new(String::new()),
            auth_required: StdArc::new(AtomicBool::new(false)),
            operator_hash: StdArc::new(String::new()),
            allowed_hosts: StdArc::new(vec!["localhost".into()]),
            ledger_path: StdArc::new(ledger_path.to_string()),
            pkg_dir: StdArc::new("..".into()),
            python: StdArc::new("python3".into()),
            scope_in: StdArc::new(vec![]),
            scope_mode: StdArc::new("grey".into()),
            detection_source: StdArc::new(std::sync::RwLock::new(StdArc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: StdArc::new(AsyncMutex::new(RunState { current: HashMap::new() })),
            run_reservations: StdArc::new(StdMutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: StdArc::new(StdMutex::new(LedgerHead::default())),
        }
    }

    // ---- PURE plan_exec validation (the not-a-shell choke point) --------------------------------

    fn args_of(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn allowlist_status_and_ledger_verify_build_fixed_argv() {
        let p = plan_exec("status", &args_of(json!({}))).expect("status ok");
        assert_eq!(p.argv, vec!["status"]);
        assert!(!p.state_changing);
        let p = plan_exec("ledger-verify", &args_of(json!({}))).expect("ledger-verify ok");
        assert_eq!(p.argv, vec!["ledger", "verify"]);
        assert!(!p.state_changing);
    }

    #[test]
    fn non_allowlisted_commands_are_rejected_fail_closed() {
        for c in ["restore", "seed-demo", "useradd", "migrate-store", "rm", "sh", "hashpw", ""] {
            let e = plan_exec(c, &args_of(json!({}))).expect_err("must reject");
            assert_eq!(e.0, StatusCode::BAD_REQUEST, "cmd {c:?} -> 400");
        }
        // the classic "sh -c …" smuggle is impossible: `sh` is not a command, and there is no free arg.
        let e = plan_exec("sh", &args_of(json!({"c": "id"}))).expect_err("sh rejected");
        assert_eq!(e.1["error"], "command_not_allowlisted");
    }

    #[test]
    fn smuggled_flag_not_in_schema_is_rejected() {
        // `status` has an EMPTY schema -> any arg key is refused.
        let e = plan_exec("status", &args_of(json!({"db": "/etc/shadow"}))).expect_err("smuggle");
        assert_eq!(e.1["error"], "flag_not_in_schema");
        // `read-findings` allows campaign/json only -> `--exec` style key refused.
        let e = plan_exec("read-findings", &args_of(json!({"soql": "x"}))).expect_err("smuggle");
        assert_eq!(e.1["error"], "flag_not_in_schema");
        // `upgrade` schema is passphrase-env/dry-run only.
        let e = plan_exec("upgrade", &args_of(json!({"to": "postgres://x"}))).expect_err("smuggle");
        assert_eq!(e.1["error"], "flag_not_in_schema");
    }

    #[test]
    fn shell_metachars_and_traversal_in_values_are_rejected() {
        // a shell metachar in a value -> refused (defense in depth; argv is fixed anyway).
        let e = plan_exec("read-findings", &args_of(json!({"campaign": "foo;rm -rf /"}))).expect_err("meta");
        assert_eq!(e.1["error"], "invalid_arg");
        let e = plan_exec("read-findings", &args_of(json!({"campaign": "a$(id)"}))).expect_err("meta");
        assert_eq!(e.1["error"], "invalid_arg");
        // leading '-' -> refused (anti-flag: a value must never look like an option).
        let e = plan_exec("read-findings", &args_of(json!({"campaign": "--json"}))).expect_err("anti-flag");
        assert_eq!(e.1["error"], "invalid_arg");
        // backup --out traversal -> refused.
        let _guard = env_lock();
        std::env::set_var("FORGE_PLAN_TEST_PASS", "irrelevant");
        for out in ["../../etc/cron.d/x", "a/b", "..", ".hidden"] {
            let e = plan_exec("backup", &args_of(json!({"out": out, "passphrase-env": "FORGE_PLAN_TEST_PASS"})))
                .expect_err("traversal");
            assert_eq!(e.1["error"], "invalid_arg", "out {out:?} rejected");
        }
        std::env::remove_var("FORGE_PLAN_TEST_PASS");
    }

    #[test]
    fn passphrase_env_takes_a_name_and_must_resolve() {
        let _guard = env_lock();
        // malformed name (lowercase/metachar) -> invalid_arg (never treated as a value).
        let e = plan_exec("upgrade", &args_of(json!({"passphrase-env": "not a var"}))).expect_err("bad name");
        assert_eq!(e.1["error"], "invalid_arg");
        // well-formed name that does NOT resolve -> secret_unresolved (fail-closed).
        std::env::remove_var("FORGE_PLAN_TEST_UNSET");
        let e = plan_exec("upgrade", &args_of(json!({"passphrase-env": "FORGE_PLAN_TEST_UNSET"})))
            .expect_err("unresolved");
        assert_eq!(e.1["error"], "secret_unresolved");
        // resolvable name -> ok; the VALUE never appears in the plan.
        std::env::set_var("FORGE_PLAN_TEST_SET", "top-secret-passphrase");
        let p = plan_exec("upgrade", &args_of(json!({"passphrase-env": "FORGE_PLAN_TEST_SET"}))).expect("ok");
        assert!(p.state_changing, "non-dry-run upgrade is state-changing");
        let ser = serde_json::to_string(&p.redacted).unwrap();
        assert!(ser.contains("FORGE_PLAN_TEST_SET"), "var NAME audited");
        assert!(!ser.contains("top-secret-passphrase"), "secret VALUE never in the plan");
        assert!(!p.argv.iter().any(|a| a.contains("top-secret-passphrase")), "secret VALUE never in argv");
        std::env::remove_var("FORGE_PLAN_TEST_SET");
    }

    #[test]
    fn upgrade_dry_run_is_not_state_changing() {
        let _guard = env_lock();
        std::env::set_var("FORGE_PLAN_TEST_DRY", "x");
        let p = plan_exec("upgrade", &args_of(json!({"passphrase-env": "FORGE_PLAN_TEST_DRY", "dry-run": true})))
            .expect("ok");
        assert!(!p.state_changing, "dry-run mutates nothing -> no confirm required");
        assert!(p.argv.iter().any(|a| a == "--dry-run"));
        std::env::remove_var("FORGE_PLAN_TEST_DRY");
    }

    // ---- HANDLER gating (admin-only, confirm gate) — no spawn reached --------------------------

    /// build an app + three sessions (viewer/operator/admin).
    fn app_with_roles(ledger: &str) -> (App, String, String, String) {
        let app = test_app(ledger);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let (v, _) = create_session(&app, uid_of(&app, "vv"));
        let (o, _) = create_session(&app, uid_of(&app, "oo"));
        let (a, _) = create_session(&app, uid_of(&app, "aa"));
        (app, v, o, a)
    }

    #[tokio::test]
    async fn non_admin_is_forbidden() {
        let ledger = tmp_path("exec-forbidden-ledger");
        let (app, v, o, _a) = app_with_roles(&ledger);
        for (who, tok) in [("viewer", &v), ("operator", &o)] {
            let r = console_exec(
                State(app.clone()),
                bearer_headers(tok),
                Json(json!({"command": "status"})),
            )
            .await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{who} -> 403");
        }
        // no session at all -> 403.
        let r = console_exec(State(app.clone()), HeaderMap::new(), Json(json!({"command":"status"}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "anon -> 403");
        // nothing was ledgered (refused before any exec).
        assert!(read_ledger_lines(&ledger).is_empty(), "no console.exec on refusal");
        let _ = std::fs::remove_file(&ledger);
    }

    #[tokio::test]
    async fn admin_unlisted_command_is_400_and_not_ledgered() {
        let ledger = tmp_path("exec-unlisted-ledger");
        let (app, _v, _o, a) = app_with_roles(&ledger);
        for cmd in [json!({"command":"restore"}), json!({"command":"seed-demo"}), json!({"command":"rm"})] {
            let r = console_exec(State(app.clone()), bearer_headers(&a), Json(cmd)).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "unlisted -> 400");
        }
        // a smuggled flag on a real command -> 400.
        let r = console_exec(
            State(app.clone()),
            bearer_headers(&a),
            Json(json!({"command":"status","args":{"db":"/etc/shadow"}})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "smuggled flag -> 400");
        assert!(read_ledger_lines(&ledger).is_empty(), "rejected exec is never ledgered");
        let _ = std::fs::remove_file(&ledger);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV process-global ; le garder à travers l'await est voulu
    async fn upgrade_without_confirm_is_refused() {
        let _guard = env_lock();
        std::env::set_var("FORGE_EXEC_UPG_PASS", "x");
        let ledger = tmp_path("exec-confirm-ledger");
        let (app, _v, _o, a) = app_with_roles(&ledger);
        // non-dry-run upgrade, no confirm -> 400 confirm_required (never spawns).
        let r = console_exec(
            State(app.clone()),
            bearer_headers(&a),
            Json(json!({"command":"upgrade","args":{"passphrase-env":"FORGE_EXEC_UPG_PASS"}})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "no confirm -> 400");
        let b = resp_json(r).await;
        assert_eq!(b["error"], "confirm_required");
        assert!(read_ledger_lines(&ledger).is_empty(), "refused-for-confirm exec is not ledgered");
        std::env::remove_var("FORGE_EXEC_UPG_PASS");
        let _ = std::fs::remove_file(&ledger);
    }

    // ---- HANDLER end-to-end: streams output + ledgers + never leaks the secret VALUE -----------

    /// Consume an SSE Response body to a String (our stream ends when the child exits).
    async fn sse_text(r: Response) -> String {
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&b).to_string()
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV process-global ; le garder à travers l'await est voulu
    async fn status_streams_output_and_writes_a_console_exec_ledger_entry() {
        let _guard = env_lock();
        // Point the exec at /bin/echo — a harmless stand-in binary — so the test is hermetic and does
        // not depend on the console binary being on disk. This exercises the SSE plumbing + ledger +
        // admin gate; the real `status` behavior is covered by run_status_cli's own tests.
        std::env::set_var("FORGE_CONSOLE_EXEC_BIN", "/bin/echo");
        let ledger = tmp_path("exec-status-ledger");
        let (app, _v, _o, a) = app_with_roles(&ledger);
        let r = console_exec(State(app.clone()), bearer_headers(&a), Json(json!({"command":"status"}))).await;
        assert_eq!(r.status(), StatusCode::OK, "admin status -> 200 SSE");
        let txt = sse_text(r).await;
        assert!(txt.contains("status"), "echo streamed the argv back: {txt}");
        assert!(txt.contains("\"kind\":\"status\""), "terminal status event present: {txt}");
        // ledger got exactly one console.exec entry attributed to the admin.
        let last = read_ledger_lines(&ledger).pop().expect("console.exec entry");
        assert_eq!(last["kind"], "console.exec");
        assert_eq!(last["detail"]["command"], "status");
        assert_eq!(last["detail"]["by"], "aa");
        std::env::remove_var("FORGE_CONSOLE_EXEC_BIN");
        let _ = std::fs::remove_file(&ledger);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV process-global ; le garder à travers l'await est voulu
    async fn ledger_verify_streams_output_admin() {
        let _guard = env_lock();
        std::env::set_var("FORGE_CONSOLE_EXEC_BIN", "/bin/echo");
        let ledger = tmp_path("exec-lv-ledger");
        let (app, _v, _o, a) = app_with_roles(&ledger);
        let r = console_exec(State(app.clone()), bearer_headers(&a), Json(json!({"command":"ledger-verify"}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let txt = sse_text(r).await;
        assert!(txt.contains("ledger verify"), "echo streamed 'ledger verify': {txt}");
        std::env::remove_var("FORGE_CONSOLE_EXEC_BIN");
        let _ = std::fs::remove_file(&ledger);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV process-global ; le garder à travers l'await est voulu
    async fn passphrase_env_value_never_appears_in_output_or_ledger() {
        let _guard = env_lock();
        std::env::set_var("FORGE_CONSOLE_EXEC_BIN", "/bin/echo");
        let bdir = tmp_dir("exec-bk-dir");
        std::env::set_var("FORGE_CONSOLE_BACKUP_DIR", &bdir);
        let secret = "SUPER-SECRET-PASSPHRASE-9182";
        std::env::set_var("FORGE_EXEC_BK_PASS", secret);
        let ledger = tmp_path("exec-bk-ledger");
        let (app, _v, _o, a) = app_with_roles(&ledger);
        let r = console_exec(
            State(app.clone()),
            bearer_headers(&a),
            Json(json!({"command":"backup","args":{"out":"snap.forge","passphrase-env":"FORGE_EXEC_BK_PASS"}})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "admin backup -> 200 SSE");
        let txt = sse_text(r).await;
        // echo prints the argv (incl. the var NAME + out path) but NEVER the resolved secret value.
        assert!(txt.contains("FORGE_EXEC_BK_PASS"), "var NAME echoed (argv): {txt}");
        assert!(!txt.contains(secret), "secret VALUE must NEVER be streamed: {txt}");
        let last = read_ledger_lines(&ledger).pop().expect("console.exec entry");
        let ser = canon_json(&last);
        assert!(ser.contains("FORGE_EXEC_BK_PASS"), "var NAME audited");
        assert!(!ser.contains(secret), "secret VALUE must NEVER enter the ledger: {ser}");
        std::env::remove_var("FORGE_CONSOLE_EXEC_BIN");
        std::env::remove_var("FORGE_CONSOLE_BACKUP_DIR");
        std::env::remove_var("FORGE_EXEC_BK_PASS");
        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_dir_all(&bdir);
    }
}

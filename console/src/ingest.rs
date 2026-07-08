// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — HANDLER D'INGESTION (le point de jonction de la boucle purple).
//! Bloc déplacé depuis main.rs (PURE MOVE). `POST /api/ingest` (token bearer) : le moteur Python
//! POSTe ici ses findings + run-records ATT&CK + décisions ROE + compteurs de couverture, chacun
//! ESTAMPILLÉ de son engagement (résolu depuis run_job). Réutilise App + les helpers de la racine de
//! crate (`check_token`/`gs`/`extract_cwe`/`cvss_base_for_severity`) via `use crate::*`, et est
//! re-exporté à la racine par `pub(crate) use crate::ingest::*` — la route de build_router et les
//! tests inline de main.rs (`super::*`) résolvent donc `ingest` INCHANGÉ.
use crate::*;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use serde_json::{json, Value};

pub(crate) async fn ingest(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_token(&app, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    }
    let campaign = body.get("campaign").and_then(|v| v.as_str()).unwrap_or("default").to_string();
    // run_id : corrèle ce lot de findings/run-records/décisions au run qui les a produits.
    let run_id = body.get("run_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let db = app.db();
    // ENGAGEMENT propriétaire de ce lot : résolu depuis le run_job créé par run_create (engagement_id).
    // run_id inconnu/absent (ingest hors run flow, ex. CLI directe) => engagement #1 (DEFAULT, rétro-
    // compat). Chaque finding/runrecord/roe_decision est ainsi ESTAMPILLÉ de SON engagement — jamais
    // celui d'un autre (isolation des données).
    let engagement_id: i64 = if run_id.is_empty() {
        1
    } else {
        db.query_row("SELECT engagement_id FROM run_job WHERE run_id=?", [&run_id], |r| r.get(0)).unwrap_or(1)
    };
    let (mut nf, mut nr, mut nd) = (0i64, 0i64, 0i64);
    if let Some(arr) = body.get("findings").and_then(|v| v.as_array()) {
        for f in arr {
            // CWE séparé : on prend `cwe` si fourni par le moteur, sinon on le dérive de `category`
            // (rétro-compat avec les anciens modules qui ne posaient que `category="CWE-639"`).
            let cwe = {
                let c = gs(f, "cwe");
                if c.is_empty() { extract_cwe(&gs(f, "category")) } else { c }
            };
            // CVSS de base : vecteur fourni, sinon dérivé de la sévérité (repère de priorisation).
            let (mut cvss_vec, mut cvss_score) = (gs(f, "cvss_vector"), f.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0));
            if cvss_vec.is_empty() && cvss_score == 0.0 {
                let (v, s) = cvss_base_for_severity(&gs(f, "severity"));
                cvss_vec = v.to_string();
                cvss_score = s;
            }
            if let Ok(n) = db.execute(
                "INSERT OR IGNORE INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score,engagement_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![gs(f,"ts"), campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                    gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                    gs(f,"fix"), run_id, cwe, cvss_vec, cvss_score, engagement_id],
            ) {
                nf += n as i64;
            }
        }
    }
    if let Some(arr) = body.get("run_records").and_then(|v| v.as_array()) {
        for rr in arr {
            let fired = if rr.get("fired").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
            if let Ok(n) = db.execute(
                "INSERT INTO runrecord(ts,campaign,target,kind,mitre,fired,detail,run_id,engagement_id) VALUES(?,?,?,?,?,?,?,?,?)",
                rusqlite::params![gs(rr,"ts"), campaign, gs(rr,"target"), gs(rr,"kind"), gs(rr,"mitre"), fired, gs(rr,"detail"), run_id, engagement_id],
            ) {
                nr += n as i64;
            }
        }
    }
    // roe_decisions : verdict par action (VETO/DRY_RUN/FIRE) — alimente GET /api/roe (transparence anti-masquage).
    if let Some(arr) = body.get("roe_decisions").and_then(|v| v.as_array()) {
        for d in arr {
            let ex = if d.get("exploit").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
            let de = if d.get("destructive").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
            let reasons = d.get("reasons").map(|r| r.to_string()).unwrap_or_else(|| "[]".into());
            if let Ok(n) = db.execute(
                "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons,engagement_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![gs(d,"ts"), campaign, run_id, gs(d,"action_id"), gs(d,"target"),
                    gs(d,"kind"), gs(d,"verdict"), ex, de, reasons, engagement_id],
            ) {
                nd += n as i64;
            }
        }
    }
    // run_job : si la console connaît ce run_id, on enregistre/actualise ses compteurs de couverture.
    if !run_id.is_empty() {
        let cov = body.get("coverage").cloned().unwrap_or_else(|| json!({}));
        let geti = |k: &str| cov.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        let gaps = body.get("coverage_gaps").map(|g| g.to_string()).unwrap_or_else(|| "{}".into());
        let skipped = body.get("skipped_budget").map(|s| s.to_string()).unwrap_or_else(|| "[]".into());
        let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let _ = db.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps)
             VALUES(?,?,datetime('now'),'done',?,?,?,?,?,?,?)
             ON CONFLICT(run_id) DO UPDATE SET status='done', mode=excluded.mode, fired=excluded.fired,
               dry_run=excluded.dry_run, vetoed=excluded.vetoed, errors=excluded.errors,
               skipped_budget=excluded.skipped_budget, coverage_gaps=excluded.coverage_gaps",
            rusqlite::params![run_id, campaign, mode, geti("fired"), geti("dry_run"),
                geti("vetoed"), geti("errors"), skipped, gaps],
        );
    }
    (StatusCode::OK, Json(json!({"findings_ingested": nf, "runrecords_ingested": nr, "roe_decisions_ingested": nd})))
}

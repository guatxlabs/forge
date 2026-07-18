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
    // partial : CHECKPOINT INCRÉMENTAL d'un run EN COURS (durabilité). Les findings/run-records/
    // décisions sont persistés comme d'habitude, MAIS le run_job n'est PAS marqué 'done' (le statut
    // 'running' est préservé -> l'index unique partiel HA + le watchdog restent valides, et le
    // superviseur pourra marquer 'timeout'/'done' honnêtement à la fin). Le flush FINAL (partial=false)
    // conserve le comportement historique (upsert 'done'). Défaut false -> rétro-compat byte-identique.
    let partial = body.get("partial").and_then(|v| v.as_bool()).unwrap_or(false);
    let store = app.store();
    // ENGAGEMENT propriétaire de ce lot : résolu depuis le run_job créé par run_create (engagement_id).
    // run_id inconnu/absent (ingest hors run flow, ex. CLI directe) => engagement #1 (DEFAULT, rétro-
    // compat). Chaque finding/runrecord/roe_decision est ainsi ESTAMPILLÉ de SON engagement — jamais
    // celui d'un autre (isolation des données).
    let engagement_id: i64 = if run_id.is_empty() {
        1
    } else {
        store.query_row("SELECT engagement_id FROM run_job WHERE run_id=?", &crate::sql_params![&run_id], |r| r.get_i64(0)).unwrap_or(1)
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
            if let Ok(n) = store.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score,engagement_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                &crate::sql_params![gs(f,"ts"), &campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                    gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                    gs(f,"fix"), &run_id, cwe, cvss_vec, cvss_score, engagement_id],
            ) {
                nf += n as i64;
            }
        }
    }
    if let Some(arr) = body.get("run_records").and_then(|v| v.as_array()) {
        for rr in arr {
            let fired = if rr.get("fired").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
            if let Ok(n) = store.execute(
                "INSERT INTO runrecord(ts,campaign,target,kind,mitre,fired,detail,run_id,engagement_id) VALUES(?,?,?,?,?,?,?,?,?)",
                &crate::sql_params![gs(rr,"ts"), &campaign, gs(rr,"target"), gs(rr,"kind"), gs(rr,"mitre"), fired, gs(rr,"detail"), &run_id, engagement_id],
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
            if let Ok(n) = store.execute(
                "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons,engagement_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                &crate::sql_params![gs(d,"ts"), &campaign, &run_id, gs(d,"action_id"), gs(d,"target"),
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
        if partial {
            // CHECKPOINT INCRÉMENTAL : met à jour UNIQUEMENT les compteurs de couverture, SANS toucher au
            // statut (le run est encore 'running'). Pas d'INSERT : run_create a déjà posé la ligne. Le garde
            // `status='running'` évite d'écraser un run déjà finalisé (fin/cancel arrivé entre-temps).
            let _ = store.execute(
                "UPDATE run_job SET fired=?, dry_run=?, vetoed=?, errors=?, skipped_budget=?, coverage_gaps=?
                 WHERE run_id=? AND status='running'",
                &crate::sql_params![geti("fired"), geti("dry_run"), geti("vetoed"), geti("errors"),
                    skipped, gaps, &run_id],
            );
        } else {
            let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // GARDE `WHERE run_job.status='running'` sur le DO UPDATE (miroir du garde de la branche partielle) :
            // un flush FINAL de complétion NATURELLE arrivant APRÈS un cancel ne doit PAS ré-ouvrir le run en
            // 'done' — un run 'cancelled' (ou tout statut terminal) reste tel quel (le conflit devient un no-op).
            // L'INSERT initial (run_id inconnu, ex. CLI hors run flow) est INCHANGÉ (pas de conflit -> ligne 'done').
            let _ = store.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps)
                 VALUES(?,?,datetime('now'),'done',?,?,?,?,?,?,?)
                 ON CONFLICT(run_id) DO UPDATE SET status='done', mode=excluded.mode, fired=excluded.fired,
                   dry_run=excluded.dry_run, vetoed=excluded.vetoed, errors=excluded.errors,
                   skipped_budget=excluded.skipped_budget, coverage_gaps=excluded.coverage_gaps
                 WHERE run_job.status='running'",
                &crate::sql_params![&run_id, &campaign, mode, geti("fired"), geti("dry_run"),
                    geti("vetoed"), geti("errors"), skipped, gaps],
            );
        }
        drop(store);
    }
    (StatusCode::OK, Json(json!({"findings_ingested": nf, "runrecords_ingested": nr, "roe_decisions_ingested": nd})))
}

#[cfg(test)]
mod partial_ingest_tests {
    use super::*;
    use crate::testutil::*;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::Json;

    fn bearer() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer t".parse().unwrap());   // token_sha = sha_hex("t") en test
        h
    }

    /// DURABILITÉ (fix D1) — un ingest `partial` (checkpoint incrémental d'un run EN COURS) PERSISTE
    /// findings/run-records/décisions et met à jour les COMPTEURS, mais laisse le run_job 'running'
    /// (jamais faussement 'done' -> le superviseur pourra marquer 'timeout' honnêtement). L'ingest FINAL
    /// (partial=false) marque 'done'. Prouve, côté handler, la branche qui fixe le symptôme « 487 FIRE,
    /// 0 persisté » sans casser la finalisation.
    #[tokio::test]
    async fn partial_persists_and_keeps_running_then_final_marks_done() {
        let app = test_app(&tmp_path("ingest-partial-d1"));
        {   // le run est DÉJÀ 'running' (posé par run_create) ; engagement_id défaut 1.
            let store = app.store();
            store.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode) VALUES(?,?,datetime('now'),'running','auto')",
                &crate::sql_params!["run-d1", "camp"],
            ).unwrap();
        }
        // (1) CHECKPOINT PARTIEL : findings/run-records/décisions + compteurs.
        let body = json!({
            "campaign": "camp", "run_id": "run-d1", "partial": true,
            "findings": [{"target": "a.test", "title": "hit a", "severity": "LOW"}],
            "run_records": [{"target": "a.test", "kind": "demo.probe", "mitre": "T1", "fired": true}],
            "roe_decisions": [{"action_id": "demo.probe:a.test", "target": "a.test",
                               "kind": "demo.probe", "verdict": "FIRE"}],
            "coverage": {"fired": 3, "dry_run": 0, "vetoed": 1, "errors": 0}
        });
        let _ = ingest(State(app.clone()), bearer(), Json(body)).await;
        {
            let store = app.store();
            let nf: i64 = store.query_row("SELECT COUNT(*) FROM finding WHERE run_id=?", &crate::sql_params!["run-d1"], |r| r.get_i64(0)).unwrap();
            let nr: i64 = store.query_row("SELECT COUNT(*) FROM runrecord WHERE run_id=?", &crate::sql_params!["run-d1"], |r| r.get_i64(0)).unwrap();
            let nd: i64 = store.query_row("SELECT COUNT(*) FROM roe_decision WHERE run_id=?", &crate::sql_params!["run-d1"], |r| r.get_i64(0)).unwrap();
            let status: String = store.query_row("SELECT status FROM run_job WHERE run_id=?", &crate::sql_params!["run-d1"], |r| r.get_str(0)).unwrap();
            let fired: i64 = store.query_row("SELECT fired FROM run_job WHERE run_id=?", &crate::sql_params!["run-d1"], |r| r.get_i64(0)).unwrap();
            assert_eq!((nf, nr, nd), (1, 1, 1), "le checkpoint partiel a PERSISTÉ le travail (pas 0)");
            assert_eq!(fired, 3, "compteurs mis à jour par le checkpoint partiel");
            assert_eq!(status, "running", "un checkpoint partiel ne marque JAMAIS 'done'");
        }
        // (2) FINAL (partial=false) : delta supplémentaire + marque 'done'.
        let body2 = json!({
            "campaign": "camp", "run_id": "run-d1", "partial": false,
            "findings": [{"target": "b.test", "title": "hit b", "severity": "LOW"}],
            "coverage": {"fired": 4, "dry_run": 0, "vetoed": 1, "errors": 0}
        });
        let _ = ingest(State(app.clone()), bearer(), Json(body2)).await;
        {
            let store = app.store();
            let nf: i64 = store.query_row("SELECT COUNT(*) FROM finding WHERE run_id=?", &crate::sql_params!["run-d1"], |r| r.get_i64(0)).unwrap();
            let status: String = store.query_row("SELECT status FROM run_job WHERE run_id=?", &crate::sql_params!["run-d1"], |r| r.get_str(0)).unwrap();
            let fired: i64 = store.query_row("SELECT fired FROM run_job WHERE run_id=?", &crate::sql_params!["run-d1"], |r| r.get_i64(0)).unwrap();
            assert_eq!(nf, 2, "l'ingest final ajoute son delta (b) au finding déjà persisté (a)");
            assert_eq!(status, "done", "l'ingest final marque le run 'done'");
            assert_eq!(fired, 4);
        }
    }

    /// [LOW — flush final ne réécrit PAS un run terminal] Un run `cancelled` (annulé) qui reçoit un flush
    /// FINAL de complétion NATURELLE tardif (partial=false) NE DOIT PAS être ré-ouvert en `done` : le garde
    /// `WHERE run_job.status='running'` ajouté au `ON CONFLICT DO UPDATE` rend le conflit un NO-OP (miroir du
    /// garde de la branche partielle). L'INSERT d'un run_id INCONNU (hors run flow, ex. CLI) reste inchangé.
    #[tokio::test]
    async fn final_flush_does_not_clobber_cancelled_run() {
        let app = test_app(&tmp_path("ingest-cancel-guard"));
        {   // le run est DÉJÀ 'cancelled' (annulé par l'opérateur) au moment du flush final tardif.
            let store = app.store();
            store.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode) VALUES(?,?,datetime('now'),'cancelled','auto')",
                &crate::sql_params!["run-cx", "camp"],
            ).unwrap();
        }
        // flush FINAL tardif (le moteur a fini naturellement APRÈS le cancel) -> ne doit PAS écraser 'cancelled'.
        let body = json!({"campaign": "camp", "run_id": "run-cx", "partial": false, "coverage": {"fired": 9}});
        let _ = ingest(State(app.clone()), bearer(), Json(body)).await;
        {
            let store = app.store();
            let status: String = store.query_row("SELECT status FROM run_job WHERE run_id=?", &crate::sql_params!["run-cx"], |r| r.get_str(0)).unwrap();
            assert_eq!(status, "cancelled", "un flush final NE ré-ouvre PAS un run annulé en 'done'");
        }
        // sanity : un run_id INCONNU (hors run flow) crée bien une ligne 'done' (INSERT inchangé).
        let body2 = json!({"campaign": "camp", "run_id": "run-new", "partial": false, "coverage": {"fired": 1}});
        let _ = ingest(State(app.clone()), bearer(), Json(body2)).await;
        {
            let store = app.store();
            let status2: String = store.query_row("SELECT status FROM run_job WHERE run_id=?", &crate::sql_params!["run-new"], |r| r.get_str(0)).unwrap();
            assert_eq!(status2, "done", "un run_id inconnu -> INSERT 'done' (comportement inchangé)");
        }
    }
}

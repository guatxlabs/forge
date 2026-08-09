// SPDX-License-Identifier: AGPL-3.0-or-later
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
    // COMPTABILITÉ DE CE QUE LE MOTEUR A ÉMIS, face à ce qui a été STOCKÉ. La table `finding` porte
    // `UNIQUE(campaign,target,title) ON CONFLICT IGNORE` et l'INSERT ci-dessous renforce avec
    // `ON CONFLICT DO NOTHING` : un finding refusé par cette clef rendait `Ok(0)` et disparaissait
    // sans un mot. Le rapport annonçait ensuite un « Total émis » qui était un total STOCKÉ — la
    // classe de défaut qu'on répare partout : une affirmation plus large que ce qu'elle recouvre.
    // Mesuré sur une campagne réelle : 499 findings sur 5 318 (9,4 %) refusés, dont 8 `skipped`
    // (des TROUS DE COUVERTURE, l'information la plus précieuse sur une cible protégée).
    // On distingue DEUX causes, parce qu'elles n'appellent pas la même action :
    //   • `n_dropped` — refus de la clef d'unicité (`Ok(0)`) : le finding existe déjà sous ce triplet ;
    //   • `n_werr`    — échec d'écriture (`Err`) : la base n'a pas pu écrire (verrou, disque, schéma).
    // Les confondre annoncerait « collision » à un exploitant qui subit une base indisponible.
    let (mut n_attempted, mut n_werr) = (0i64, 0i64);
    if let Some(arr) = body.get("findings").and_then(|v| v.as_array()) {
        for f in arr {
            n_attempted += 1;
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
            match store.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score,engagement_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                &crate::sql_params![gs(f,"ts"), &campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                    gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                    gs(f,"fix"), &run_id, cwe, cvss_vec, cvss_score, engagement_id],
            ) {
                Ok(n) => nf += n as i64,
                Err(_) => n_werr += 1,
            }
        }
    }
    // Refusés par la clef d'unicité = émis − stockés − perdus en écriture. Jamais négatif :
    // `execute` rend soit `Ok(n)` (n ∈ {0,1} sur cet INSERT), soit `Err` — les trois branches sont
    // exhaustives et disjointes.
    let n_dropped = (n_attempted - nf - n_werr).max(0);
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
        // COMPTABILITÉ DES NON-STOCKÉS — statement DÉDIÉ, exécuté APRÈS l'upsert de statut et
        // VOLONTAIREMENT HORS du garde `status='running'` des deux branches ci-dessus : un run
        // `cancelled`/`timeout` a QUAND MÊME émis ces findings, et son rapport doit pouvoir le dire.
        // Le garde de statut protège le STATUT (ne pas ré-ouvrir un run terminal) — il n'a aucune
        // raison de faire disparaître une mesure.
        // Accumulation (`COALESCE(col,0)+?`) parce que chaque ingest porte un DELTA (checkpoints
        // incrémentaux puis flush final), là où fired/vetoed/… sont des totaux absolus ré-émis.
        // Le `COALESCE` fait la transition NULL (« inconnu, run antérieur ») -> entier connu : le
        // premier ingest d'un run le fait passer à une valeur MESURÉE, fût-elle 0.
        let _ = store.execute(
            "UPDATE run_job SET findings_dropped=COALESCE(findings_dropped,0)+?,
                    findings_write_errors=COALESCE(findings_write_errors,0)+?
             WHERE run_id=?",
            &crate::sql_params![n_dropped, n_werr, &run_id],
        );
        drop(store);
    }
    // La réponse dit la vérité MÊME quand rien n'a pu être persisté (ingest hors run flow : `run_id`
    // vide -> aucune ligne `run_job` où porter le compteur). C'est le seul endroit qui couvre ce cas ;
    // le moteur (console_client) le reçoit à chaque flush.
    (StatusCode::OK, Json(json!({
        "findings_ingested": nf,
        "findings_attempted": n_attempted,
        "findings_dropped": n_dropped,
        "findings_write_errors": n_werr,
        "runrecords_ingested": nr,
        "roe_decisions_ingested": nd,
    })))
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

/// COMPTABILITÉ DES FINDINGS NON STOCKÉS — la perte cesse d'être invisible.
///
/// `finding` porte `UNIQUE(campaign,target,title) ON CONFLICT IGNORE` et l'INSERT renforce avec
/// `ON CONFLICT DO NOTHING`. La clef n'inclut NI `run_id`, NI `tool`, NI `severity`. Mesuré sur la
/// campagne réelle (`gxrun2/ledger.jsonl`, 5 318 findings émis) : **499 refusés (9,4 %)** — pires cas
/// ×44 « nuclei: RDAP WHOIS », ×20 « subdomain.takeover non confirmé » — dont **8 `skipped`**, c'est-
/// à-dire 8 trous de couverture évaporés. Et un SECOND run de la même campagne voit TOUS ses findings
/// refusés : son rapport (`WHERE run_id=?`) est alors VIDE, ce qui se lit « rien trouvé ».
///
/// Le stockage n'est PAS changé (l'idempotence de retry documentée par
/// `forge/console_client.py::IncrementalIngest` en dépend). Ce qui change : la perte est COMPTÉE,
/// PERSISTÉE et RENDUE au rapport. Chaque assertion porteuse vit dans SON test.
#[cfg(test)]
mod not_stored_accounting_tests {
    use super::*;
    use crate::testutil::*;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::Json;

    fn bearer() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer t".parse().unwrap());
        h
    }

    fn start_run(app: &App, run_id: &str, status: &str) {
        let store = app.store();
        store
            .execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode) VALUES(?,'camp',datetime('now'),?,'auto')",
                &crate::sql_params![run_id, status],
            )
            .unwrap();
    }

    /// findings de MÊME (target,title) que ceux du corpus réel qui collisionnent.
    fn dup_body(run_id: &str, n: usize) -> Value {
        let f: Vec<Value> = (0..n)
            .map(|i| json!({"target": "guatx.com", "title": "nuclei: DNS WAF Detection",
                            "severity": "INFO", "status": "tested", "tool": format!("nuclei#{i}")}))
            .collect();
        json!({"campaign": "camp", "run_id": run_id, "partial": false, "findings": f, "coverage": {}})
    }

    fn counters(app: &App, run_id: &str) -> (Option<i64>, Option<i64>, i64) {
        let store = app.store();
        let (d, e) = store
            .query_row(
                "SELECT findings_dropped, findings_write_errors FROM run_job WHERE run_id=?",
                &crate::sql_params![run_id],
                |r| Ok((r.get_opt_i64(0)?, r.get_opt_i64(1)?)),
            )
            .unwrap();
        let stored: i64 = store
            .query_row("SELECT COUNT(*) FROM finding WHERE run_id=?", &crate::sql_params![run_id], |r| r.get_i64(0))
            .unwrap();
        (d, e, stored)
    }

    // --- la collision de clef est COMPTÉE ------------------------------------------------------

    #[tokio::test]
    async fn findings_refused_by_the_unique_key_are_counted() {
        let app = test_app(&tmp_path("ns-ingest-dup"));
        start_run(&app, "run-dup", "running");
        let _ = ingest(State(app.clone()), bearer(), Json(dup_body("run-dup", 5))).await;
        let (d, _e, stored) = counters(&app, "run-dup");
        assert_eq!(stored, 1, "un seul des 5 findings passe la clef d'unicité");
        assert_eq!(d, Some(4), "les 4 refus doivent être COMPTÉS, pas évaporés");
    }

    #[tokio::test]
    async fn the_ingest_response_reports_the_loss() {
        // La réponse HTTP est le SEUL endroit qui couvre l'ingest hors run flow (`run_id` vide) :
        // il n'y a alors aucune ligne `run_job` où porter le compteur.
        let app = test_app(&tmp_path("ns-ingest-resp"));
        let mut body = dup_body("", 3);
        body["run_id"] = json!("");
        let v = resp_json(ingest(State(app.clone()), bearer(), Json(body)).await.into_response()).await;
        assert_eq!(v["findings_attempted"], json!(3), "la réponse doit dire ce que le moteur a ENVOYÉ");
        assert_eq!(v["findings_ingested"], json!(1));
        assert_eq!(v["findings_dropped"], json!(2), "la réponse doit dire ce qui a été REFUSÉ");
    }

    #[tokio::test]
    async fn a_run_that_dropped_nothing_records_a_measured_zero() {
        // 0 est une MESURE (« rien n'a été refusé »), distincte de NULL (« run antérieur au comptage »).
        let app = test_app(&tmp_path("ns-ingest-zero"));
        start_run(&app, "run-zero", "running");
        let body = json!({"campaign": "camp", "run_id": "run-zero", "partial": false,
                          "findings": [{"target": "a.test", "title": "hit a", "severity": "LOW"}],
                          "coverage": {}});
        let _ = ingest(State(app.clone()), bearer(), Json(body)).await;
        let (d, e, stored) = counters(&app, "run-zero");
        assert_eq!((stored, d, e), (1, Some(0), Some(0)), "un run ingéré doit passer de NULL à une mesure");
    }

    #[tokio::test]
    async fn a_run_never_ingested_keeps_an_unknown_share() {
        let app = test_app(&tmp_path("ns-ingest-null"));
        start_run(&app, "run-virgin", "running");
        let (d, e, _s) = counters(&app, "run-virgin");
        assert_eq!((d, e), (None, None), "sans ingest, la part refusée est INCONNUE — jamais 0");
    }

    // --- LE cas catastrophique : un SECOND run de la même campagne -----------------------------

    #[tokio::test]
    async fn a_second_run_of_the_same_campaign_stores_nothing() {
        // Constat, avant toute réparation : la clef ne porte pas `run_id`, donc le second run est
        // intégralement refusé et son rapport (`SELECT … WHERE run_id=?`) est VIDE.
        let app = test_app(&tmp_path("ns-ingest-rerun"));
        // Séquence RÉELLE : A tourne, finit (l'ingest final le marque 'done'), PUIS B démarre —
        // l'index unique partiel HA interdit deux runs 'running' sur le même engagement.
        start_run(&app, "run-A", "running");
        let _ = ingest(State(app.clone()), bearer(), Json(dup_body("run-A", 3))).await;
        start_run(&app, "run-B", "running");
        let _ = ingest(State(app.clone()), bearer(), Json(dup_body("run-B", 3))).await;
        let (_d, _e, stored_b) = counters(&app, "run-B");
        assert_eq!(stored_b, 0, "le second run n'a stocké AUCUN finding (clef sans run_id)");
    }

    #[tokio::test]
    async fn a_second_run_of_the_same_campaign_says_what_it_lost() {
        // …et c'est CE compteur qui empêche de lire ce rapport vide comme « rien trouvé ».
        let app = test_app(&tmp_path("ns-ingest-rerun2"));
        start_run(&app, "run-A", "running");
        let _ = ingest(State(app.clone()), bearer(), Json(dup_body("run-A", 3))).await;
        start_run(&app, "run-B", "running");
        let _ = ingest(State(app.clone()), bearer(), Json(dup_body("run-B", 3))).await;
        let (d, _e, _s) = counters(&app, "run-B");
        assert_eq!(d, Some(3), "les 3 findings du second run doivent être comptés comme refusés");
    }

    // --- l'échec d'ÉCRITURE n'est PAS une collision --------------------------------------------

    #[tokio::test]
    async fn write_failures_are_counted_apart_from_key_collisions() {
        let app = test_app(&tmp_path("ns-ingest-werr"));
        start_run(&app, "run-werr", "running");
        {
            // la table `finding` disparaît -> chaque INSERT rend Err (et non Ok(0)).
            let db = app.db();
            db.execute("ALTER TABLE finding RENAME TO finding_gone", []).unwrap();
        }
        let body = json!({"campaign": "camp", "run_id": "run-werr", "partial": false,
                          "findings": [{"target": "a.test", "title": "x"}, {"target": "b.test", "title": "y"}],
                          "coverage": {}});
        let _ = ingest(State(app.clone()), bearer(), Json(body)).await;
        let store = app.store();
        let (d, e) = store
            .query_row(
                "SELECT findings_dropped, findings_write_errors FROM run_job WHERE run_id=?",
                &crate::sql_params!["run-werr"],
                |r| Ok((r.get_opt_i64(0)?, r.get_opt_i64(1)?)),
            )
            .unwrap();
        assert_eq!(e, Some(2), "2 findings perdus sur ÉCHEC D'ÉCRITURE");
        assert_eq!(d, Some(0), "un échec d'écriture ne doit PAS être compté comme une collision de clef");
    }

    // --- le compteur SURVIT aux gardes de statut -----------------------------------------------

    #[tokio::test]
    async fn a_cancelled_run_still_records_what_it_lost() {
        // Les deux branches de persistance du statut sont gardées par `status='running'` (pour ne pas
        // ré-ouvrir un run terminal). Ce garde protège le STATUT — il n'a aucune raison de faire
        // disparaître une MESURE : un run annulé a QUAND MÊME émis ces findings.
        let app = test_app(&tmp_path("ns-ingest-cancel"));
        start_run(&app, "run-cx", "cancelled");
        let _ = ingest(State(app.clone()), bearer(), Json(dup_body("run-cx", 4))).await;
        let (d, _e, _s) = counters(&app, "run-cx");
        assert_eq!(d, Some(3), "la mesure est perdue quand le run n'est plus 'running'");
    }

    #[tokio::test]
    async fn a_cancelled_run_keeps_its_terminal_status() {
        // …sans que la nouvelle écriture ne ré-ouvre le run (le garde historique tient toujours).
        let app = test_app(&tmp_path("ns-ingest-cancel2"));
        start_run(&app, "run-cx", "cancelled");
        let _ = ingest(State(app.clone()), bearer(), Json(dup_body("run-cx", 4))).await;
        let store = app.store();
        let st: String = store
            .query_row("SELECT status FROM run_job WHERE run_id=?", &crate::sql_params!["run-cx"], |r| r.get_str(0))
            .unwrap();
        assert_eq!(st, "cancelled");
    }

    #[tokio::test]
    async fn checkpoints_accumulate_instead_of_overwriting() {
        // Chaque ingest porte un DELTA (checkpoints incrémentaux puis flush final) : écraser au lieu
        // d'accumuler ne rapporterait que la perte du DERNIER flush.
        let app = test_app(&tmp_path("ns-ingest-accum"));
        start_run(&app, "run-acc", "running");
        let mut b1 = dup_body("run-acc", 3);
        b1["partial"] = json!(true);
        let _ = ingest(State(app.clone()), bearer(), Json(b1)).await;
        let mut b2 = dup_body("run-acc", 2);
        b2["partial"] = json!(true);
        let _ = ingest(State(app.clone()), bearer(), Json(b2)).await;
        let (d, _e, stored) = counters(&app, "run-acc");
        assert_eq!(stored, 1, "un seul finding distinct sur les 5 envoyés");
        assert_eq!(d, Some(4), "2 + 2 refus cumulés sur les deux checkpoints");
    }

    // --- l'idempotence de retry, elle, est PRÉSERVÉE -------------------------------------------

    #[tokio::test]
    async fn a_retried_flush_still_does_not_duplicate_findings() {
        // `IncrementalIngest` n'avance ses offsets qu'APRÈS un envoi réussi : un flush qui lève après
        // que le serveur a écrit REJOUE le même delta. L'idempotence repose sur la clef d'unicité —
        // c'est la raison mesurée pour laquelle on ne l'ÉLARGIT PAS (cf. rapport de session).
        let app = test_app(&tmp_path("ns-ingest-retry"));
        start_run(&app, "run-rt", "running");
        let body = json!({"campaign": "camp", "run_id": "run-rt", "partial": true,
                          "findings": [{"target": "a.test", "title": "hit a", "severity": "LOW"}],
                          "coverage": {}});
        let _ = ingest(State(app.clone()), bearer(), Json(body.clone())).await;
        let _ = ingest(State(app.clone()), bearer(), Json(body)).await;
        let (d, _e, stored) = counters(&app, "run-rt");
        assert_eq!(stored, 1, "un rejeu ne doit pas DOUBLER le finding");
        assert_eq!(d, Some(1), "…et le rejeu absorbé est COMPTÉ, au lieu d'être invisible");
    }
}

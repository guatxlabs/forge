// SPDX-License-Identifier: AGPL-3.0-or-later
//! LE RAPPORT NE PEUT PLUS FAIRE PASSER UN TOTAL **STOCKÉ** POUR UN TOTAL **ÉMIS**.
//!
//! `finding` porte `UNIQUE(campaign,target,title) ON CONFLICT IGNORE` : ni `run_id`, ni `tool`, ni
//! `severity` n'entrent dans la clef. Mesuré sur la campagne réelle (`gxrun2/ledger.jsonl`,
//! 5 318 findings) : **499 refusés (9,4 %)**, dont 8 `skipped` — c'est-à-dire 8 TROUS DE COUVERTURE,
//! l'information la plus précieuse sur une cible protégée. Le rapport annonçait ensuite
//! « **Total émis** : **4819** » sans que rien, nulle part, ne permette de savoir qu'il en manquait 499.
//!
//! CE QUI EST GARDÉ ICI (chaque assertion porteuse dans SON test — une assertion qui échoue ne doit
//! pas empêcher la suivante de s'exécuter, sinon une mutation « verte » ne prouverait rien) :
//!   1. une perte MESURÉE est DITE, avec son compte et le total réellement émis ;
//!   2. un run où TOUT a été refusé (signature d'une RE-EXÉCUTION de la même campagne) le dit —
//!      c'est le cas où le rapport est VIDE pour une raison qui n'est pas « rien trouvé » ;
//!   3. un échec d'ÉCRITURE a sa propre phrase (cause distincte d'une collision de clef) ;
//!   4. une mesure ABSENTE (run antérieur au comptage) se dit INCONNUE — jamais 0 ;
//!   5. une mesure PRÉSENTE ET NULLE ne dit RIEN — et dans ce cas seulement « Total émis » est vrai ;
//!   6. la ligne « Total émis » elle-même reste VERBATIM (miroir de `forge/report_view.py`, comparé
//!      label par label par le garde-fou de parité) : on la BORNE, on ne la réécrit pas.
#![cfg(test)]
use crate::testutil::*;
use crate::*;
use serde_json::json;

/// Monte une base avec `n` findings sur `run_id`, et une ligne `run_job` dont la comptabilité des
/// non-stockés vaut `dropped`/`write_errors` (`None` = colonne laissée NULL == run ANTÉRIEUR au
/// comptage). Rend le markdown du rapport de run.
fn report_md(tag: &str, n: usize, dropped: Option<i64>, write_errors: Option<i64>) -> String {
    let (md, _html) = report_both(tag, n, dropped, write_errors);
    md
}

/// La SECTION VERDICT seule (`## Verdict` -> section suivante). Les assertions positives y sont
/// confinées : sans ça, une borne rendue AILLEURS dans le document (l'annexe en porte une aussi)
/// suffirait à les faire passer, et une mutation qui supprime la borne DU VERDICT resterait verte.
fn verdict_section(md: &str) -> String {
    let start = md.find("\n## Verdict").expect("section Verdict");
    let rest = &md[start + 1..];
    let end = rest[3..].find("\n## ").map(|i| i + 4).unwrap_or(rest.len());
    rest[..end].to_string()
}

fn report_both(tag: &str, n: usize, dropped: Option<i64>, write_errors: Option<i64>) -> (String, String) {
    let app = test_app(&tmp_path(tag));
    {
        let db = app.db();
        for i in 0..n {
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,status,tool,run_id)
                 VALUES('t','camp',?,?,'INFO','tested','nuclei',?)",
                rusqlite::params![format!("t{i}.example.com"), format!("hit {i}"), tag],
            )
            .unwrap();
        }
        db.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,mode,started_by,targets,findings_dropped,findings_write_errors)
             VALUES(?,'camp',datetime('now'),'done','propose','operator','[]',?,?)",
            rusqlite::params![tag, dropped, write_errors],
        )
        .unwrap();
    }
    let store = app.store();
    let job = store
        .query_row(
            &format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"),
            &crate::sql_params![tag],
            run_job_json,
        )
        .unwrap();
    let custody = crate::report_render::build_ledger_custody(&app, "operator");
    let md = crate::report_render::render_run_report_md(&store, tag, &job, None, None);
    let html = crate::report_render::render_run_report_html(&store, tag, &job, None, &custody);
    drop(store);
    (md, html)
}

// --- 1. une perte mesurée est DITE ------------------------------------------------------------

#[test]
fn a_measured_loss_is_announced() {
    let md = verdict_section(&report_md("ns-said", 4, Some(3), Some(0)));
    assert!(
        md.contains("3 finding(s) émis par le moteur et REFUSÉS au stockage"),
        "une perte MESURÉE de 3 findings n'est pas annoncée :\n{md}"
    );
}

#[test]
fn the_announced_total_is_named_as_a_stored_total() {
    let md = verdict_section(&report_md("ns-stored", 4, Some(3), Some(0)));
    assert!(
        md.contains("total **STOCKÉ**, pas un total ÉMIS"),
        "le rapport laisse encore croire que son total est celui du moteur :\n{md}"
    );
}

#[test]
fn the_real_emitted_total_is_given() {
    // 4 stockés + 3 refusés + 2 perdus en écriture = 9 émis. Un compte de perte SANS le total réel
    // oblige le lecteur à faire l'addition — et il ne peut la faire que s'il connaît les deux causes.
    let md = verdict_section(&report_md("ns-emis", 4, Some(3), Some(2)));
    assert!(md.contains("le moteur en a émis **9**"), "le total ÉMIS n'est pas donné :\n{md}");
}

#[test]
fn the_unicity_key_that_refused_them_is_named() {
    // Sans le nom de la clef, l'exploitant ne peut ni reproduire ni corriger. Et le fait que
    // `run_id`/`tool`/`severity` n'en fassent PAS partie est précisément ce qui rend la perte massive.
    let md = verdict_section(&report_md("ns-key", 2, Some(1), Some(0)));
    assert!(md.contains("campaign+target+title"), "la clef d'unicité n'est pas nommée :\n{md}");
    assert!(
        md.contains("ni `run_id`, ni `tool`, ni `severity`"),
        "ce qui MANQUE à la clef n'est pas dit :\n{md}"
    );
}

// --- 2. le run vidé par une RE-EXÉCUTION -------------------------------------------------------

#[test]
fn a_run_that_stored_nothing_at_all_names_the_re_run_signature() {
    // 0 stocké, 12 refusés : c'est EXACTEMENT ce qu'un second run de la même campagne produit.
    // Le rapport serait autrement VIDE, et « rien d'actionnable trouvé » se lirait comme un verdict.
    let md = verdict_section(&report_md("ns-rerun", 0, Some(12), Some(0)));
    assert!(
        md.contains("AUCUN finding de ce run n'a été stocké"),
        "un rapport vidé par la clef d'unicité ne dit pas pourquoi il est vide :\n{md}"
    );
}

#[test]
fn the_re_run_sentence_says_the_emptiness_is_not_an_absence_of_findings() {
    let md = verdict_section(&report_md("ns-rerun2", 0, Some(12), Some(0)));
    assert!(
        md.contains("une raison qui n'est pas « rien trouvé »"),
        "le rapport laisse conclure « rien trouvé » sur un rapport vidé au stockage :\n{md}"
    );
}

#[test]
fn a_non_empty_run_does_not_claim_to_be_a_re_run() {
    // la phrase de RE-EXÉCUTION ne doit apparaître QUE sur un rapport réellement vide, sinon elle
    // devient du bruit et on n'y croira plus le jour où elle compte.
    let md = report_md("ns-rerun3", 5, Some(2), Some(0));
    assert!(!md.contains("AUCUN finding de ce run n'a été stocké"), "phrase de re-run sur un run non vide :\n{md}");
}

// --- 3. l'échec d'écriture a sa PROPRE cause ---------------------------------------------------

#[test]
fn write_failures_have_their_own_sentence() {
    let md = verdict_section(&report_md("ns-werr", 2, Some(0), Some(5)));
    assert!(
        md.contains("5 finding(s) PERDUS sur échec d'écriture"),
        "les findings perdus sur erreur d'écriture ne sont pas dits :\n{md}"
    );
}

#[test]
fn write_failures_are_not_announced_as_key_collisions() {
    // Confondre les deux enverrait l'exploitant corriger une clef d'unicité alors que sa base est
    // indisponible. La phrase de collision ne doit PAS apparaître quand seule l'écriture a échoué.
    let md = report_md("ns-werr2", 2, Some(0), Some(5));
    assert!(
        !md.contains("REFUSÉS au stockage"),
        "un échec d'écriture est annoncé comme une collision de clef :\n{md}"
    );
}

// --- 4/5. mesure ABSENTE vs mesure NULLE -------------------------------------------------------

#[test]
fn an_unmeasured_run_says_the_share_is_unknown() {
    let md = verdict_section(&report_md("ns-unknown", 3, None, None));
    assert!(
        md.contains("Part NON stockée : INCONNUE"),
        "un run antérieur au comptage laisse croire que son total est complet :\n{md}"
    );
}

#[test]
fn an_unmeasured_run_never_claims_zero_loss() {
    // NULL veut dire « je ne sais pas », pas « rien n'a été perdu ». Les deux affirmations sont
    // différentes et c'est toute la raison du `DEFAULT NULL` (et non `DEFAULT 0`) dans le schéma.
    let md = report_md("ns-unknown2", 3, None, None);
    assert!(!md.contains("0 finding(s) émis par le moteur et REFUSÉS"), "un « inconnu » rendu comme un zéro :\n{md}");
}

#[test]
fn a_measured_and_empty_loss_says_nothing_at_all() {
    // C'est le SEUL cas où « Total émis » est une affirmation vraie : aucune borne ne doit alors
    // polluer le verdict (sinon la borne devient du décor et cesse d'alerter).
    let md = report_md("ns-zero", 3, Some(0), Some(0));
    assert!(!md.contains("Part NON stockée"), "une perte mesurée NULLE ne doit rien afficher :\n{md}");
    assert!(!md.contains("REFUSÉS au stockage"), "une perte mesurée NULLE ne doit rien afficher :\n{md}");
    assert!(!md.contains("échec d'écriture"), "une perte mesurée NULLE ne doit rien afficher :\n{md}");
}

// --- 6. la ligne de parité reste VERBATIM ------------------------------------------------------

#[test]
fn the_total_line_itself_is_left_verbatim() {
    // `forge/report_view.py` rend la MÊME ligne et le garde-fou de parité la compare LABEL PAR LABEL
    // (`tests_reports_purple::skeleton_of`). La borner est légitime ; la RÉÉCRIRE d'un seul côté
    // ferait diverger deux rendus de la même donnée. Ce test dit que le choix est délibéré.
    let md = report_md("ns-verbatim", 3, Some(2), Some(0));
    assert!(
        md.contains("- **Total émis** : **3** findings (vue `pentest`)."),
        "la ligne de parité « Total émis » a été réécrite :\n{md}"
    );
}

#[test]
fn the_bound_follows_the_total_line_immediately() {
    // Une borne posée loin de l'affirmation qu'elle borne ne borne rien : elle doit être la ligne
    // SUIVANTE, sur l'écran du lecteur qui vient de lire le total.
    let md = report_md("ns-order", 3, Some(2), Some(0));
    let lines: Vec<&str> = md.lines().collect();
    let i = lines.iter().position(|l| l.starts_with("- **Total émis**")).expect("ligne « Total émis »");
    assert!(
        lines[i + 1].contains("REFUSÉS au stockage"),
        "la borne ne suit pas immédiatement le total qu'elle borne : {:?}",
        &lines[i..(i + 3).min(lines.len())]
    );
}

// --- le SECOND site du même travers : la comptabilité de l'annexe ------------------------------

#[test]
fn the_annex_accounting_is_bounded_too() {
    // « = N émis au total » compte lui aussi des findings STOCKÉS. L'équation reste exacte (elle
    // porte sur le repliage) ; c'est le mot « émis » qui déborde dès que l'ingestion a refusé.
    let md = report_md("ns-annex", 3, Some(4), Some(0));
    let i = md.find("émis au total").expect("ligne de comptabilité de l'annexe");
    assert!(
        md[i..].contains("REFUSÉS au stockage"),
        "la comptabilité de l'annexe annonce un total « émis » sans le borner :\n{}",
        &md[i..(i + 400).min(md.len())]
    );
}

#[test]
fn the_annex_accounting_equation_is_left_verbatim() {
    // La ligne elle-même est comparée par le garde-fou de parité (`skeleton_of` en extrait les
    // entiers) : on la BORNE, on ne la réécrit pas.
    let md = report_md("ns-annex2", 3, Some(4), Some(0));
    assert!(
        md.contains("> **3 finding(s) rendus, 0 repliés** (= 3 émis au total)"),
        "l'équation de comptabilité de l'annexe a été réécrite :\n{md}"
    );
}

#[test]
fn the_annex_accounting_stays_clean_without_loss() {
    let md = report_md("ns-annex3", 3, Some(0), Some(0));
    let i = md.find("émis au total").expect("ligne de comptabilité de l'annexe");
    assert!(!md[i..].contains("REFUSÉS au stockage"), "borne parasite sur une annexe sans perte :\n{md}");
}

// --- le LIVRABLE CLIENT (HTML) porte la même comptabilité --------------------------------------

#[test]
fn the_html_deliverable_carries_the_same_accounting() {
    let (_md, html) = report_both("ns-html", 4, Some(3), Some(0));
    assert!(
        html.contains("REFUSÉS au stockage"),
        "le HTML brandé (livrable client) ne dit pas ce qui manque"
    );
}

#[test]
fn the_html_deliverable_says_unknown_when_it_is_unknown() {
    let (_md, html) = report_both("ns-html2", 4, None, None);
    assert!(html.contains("Part NON stockée : INCONNUE"), "le HTML ne dit pas que la part perdue est inconnue");
}

#[test]
fn the_html_deliverable_stays_clean_when_the_loss_is_measured_and_zero() {
    let (_md, html) = report_both("ns-html3", 4, Some(0), Some(0));
    assert!(!html.contains("Part NON stockée"), "borne parasite sur un run sans perte");
    assert!(!html.contains("REFUSÉS au stockage"), "borne parasite sur un run sans perte");
}

// --- LOI DE CONSERVATION, éprouvée sur le corpus RÉEL ------------------------------------------

/// Corpus de collision par DÉFAUT — reproduit le motif EXACT mesuré sur la campagne réelle
/// (`gxrun2/ledger.jsonl`) : un même (target,title) ré-émis depuis plusieurs angles de scan, avec un
/// `tool` et un `poc` DIFFÉRENTS à chaque fois. C'est pourquoi élargir la clef à `tool` ne récupérait
/// que 8 findings sur 499 : la collision porte sur le couple (target,title), pas sur le module.
const DEFAULT_COLLISION_CORPUS: &[(&str, &str, &str)] = &[
    ("guatx.com", "nuclei: DNS WAF Detection", "nuclei:dns"),
    ("guatx.com", "nuclei: DNS WAF Detection", "nuclei:http"),
    ("guatx.com", "nuclei: DNS WAF Detection", "nuclei:tls"),
    ("guatx.com", "nuclei: NS Record Detection", "nuclei:dns"),
    ("guatx.com", "nuclei: NS Record Detection", "nuclei:dns"),
    ("www.guatx.com", "subdomain.takeover non confirmé", "takeover"),
    ("www.guatx.com", "subdomain.takeover non confirmé", "takeover"),
    ("51.195.100.61", "IP résolue HORS-SCOPE", "scopeguard"),
];

/// Charge le corpus à ingérer : `FORGE_REAL_LEDGER=<ledger.jsonl>` fait tourner CE MÊME test sur la
/// campagne réelle (11 Mo, 5 318 findings) — il ne DÉSARME rien, il change seulement les données.
/// Rend `(target, title, tool)` dans l'ordre d'ÉMISSION.
fn collision_corpus() -> Vec<(String, String, String)> {
    match std::env::var("FORGE_REAL_LEDGER") {
        Ok(path) => {
            let text = std::fs::read_to_string(&path).expect("ledger réel lisible");
            let mut out = Vec::new();
            for line in text.lines() {
                let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
                if v.get("kind").and_then(|k| k.as_str()) != Some("finding") {
                    continue;
                }
                let d = v.get("detail").cloned().unwrap_or(json!({}));
                let g = |k: &str| d.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                out.push((g("target"), g("title"), g("tool")));
            }
            assert!(!out.is_empty(), "aucun finding dans le ledger fourni");
            out
        }
        Err(_) => DEFAULT_COLLISION_CORPUS
            .iter()
            .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
            .collect(),
    }
}

/// Ingère `corpus` sur un run neuf et rend `((émis, stockés, refusés, erreurs_écriture), markdown)` —
/// le rapport passe donc par le MÊME chemin que la production : handler d'ingest réel, puis rendu réel.
async fn ingest_corpus_and_render(tag: &str, corpus: &[(String, String, String)]) -> ((i64, i64, i64, i64), String) {
    let app = test_app(&tmp_path(tag));
    {
        let store = app.store();
        store
            .execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode) VALUES(?,'real',datetime('now'),'running','auto')",
                &crate::sql_params![tag],
            )
            .unwrap();
    }
    let findings: Vec<Value> = corpus
        .iter()
        .map(|(t, ti, tool)| json!({"target": t, "title": ti, "tool": tool, "severity": "INFO", "status": "tested"}))
        .collect();
    let body = json!({"campaign": "real", "run_id": tag, "partial": false, "findings": findings, "coverage": {}});
    // `test_app` pose token_sha = sha_hex("t") — le bearer de test.
    let _ = crate::ingest::ingest(axum::extract::State(app.clone()), bearer_headers("t"), axum::Json(body)).await;
    let store = app.store();
    let stored: i64 = store
        .query_row("SELECT COUNT(*) FROM finding WHERE run_id=?", &crate::sql_params![tag], |r| r.get_i64(0))
        .unwrap();
    let (d, e) = store
        .query_row(
            "SELECT COALESCE(findings_dropped,-1), COALESCE(findings_write_errors,-1) FROM run_job WHERE run_id=?",
            &crate::sql_params![tag],
            |r| Ok((r.get_i64(0)?, r.get_i64(1)?)),
        )
        .unwrap();
    let job = store
        .query_row(
            &format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"),
            &crate::sql_params![tag],
            run_job_json,
        )
        .unwrap();
    let md = crate::report_render::render_run_report_md(&store, tag, &job, None, None);
    drop(store);
    ((corpus.len() as i64, stored, d, e), md)
}

#[tokio::test]
async fn emitted_equals_stored_plus_dropped_plus_write_errors() {
    // LOI DE CONSERVATION : rien ne peut plus disparaître entre le moteur et la console sans être
    // porté par l'un des trois compteurs. C'est la propriété qui rend la perte IMPOSSIBLE à cacher,
    // quel que soit le corpus. Sur la campagne réelle : 5318 = 4819 + 499 + 0.
    let corpus = collision_corpus();
    let ((emitted, stored, dropped, werr), _md) = ingest_corpus_and_render("ns-conserv", &corpus).await;
    // Sur un corpus RÉEL fourni par l'exploitant, on IMPRIME la mesure (`--nocapture`) : c'est le
    // chiffre qu'on veut lire, pas seulement un vert/rouge.
    if std::env::var("FORGE_REAL_LEDGER").is_ok() {
        println!("[corpus réel] émis={emitted} · stockés={stored} · refusés(clef)={dropped} · erreurs_écriture={werr} \
                  ({:.2} % non stockés)", 100.0 * (dropped + werr) as f64 / emitted as f64);
    }
    assert_eq!(
        emitted,
        stored + dropped + werr,
        "{emitted} émis ≠ {stored} stockés + {dropped} refusés + {werr} en erreur — il en manque"
    );
}

#[tokio::test]
async fn the_collision_corpus_really_loses_findings() {
    // Une loi de conservation vérifiée sur un corpus SANS collision ne prouverait rien : ce test dit
    // que le corpus de l'assertion précédente PERD réellement des findings.
    let corpus = collision_corpus();
    let ((emitted, stored, dropped, _werr), _md) = ingest_corpus_and_render("ns-conserv2", &corpus).await;
    assert!(dropped > 0, "corpus sans collision : la loi de conservation ne prouverait rien");
    assert!(stored < emitted, "{stored} stockés sur {emitted} émis — aucune perte à mesurer");
}

#[tokio::test]
async fn the_report_of_a_lossy_ingest_states_the_loss_end_to_end() {
    // CHEMIN COMPLET, sans truquage : findings postés au handler d'ingest réel -> stockage réel ->
    // rendu réel. Ce qui suit est ce qu'un opérateur LIT. Avant ce lot, ces lignes n'existaient pas
    // et « Total émis » était le SEUL nombre du verdict — il valait le total STOCKÉ.
    let corpus = collision_corpus();
    let ((emitted, stored, dropped, _werr), full_md) = ingest_corpus_and_render("ns-e2e", &corpus).await;
    let md = verdict_section(&full_md);
    if std::env::var("FORGE_REAL_LEDGER").is_ok() {
        for l in full_md.lines().filter(|l| l.starts_with("- **Total émis**") || l.contains("REFUSÉS au stockage")) {
            println!("[rapport réel] {l}");
        }
    }
    assert!(md.contains(&format!("- **Total émis** : **{stored}** findings")), "le total rendu n'est pas le total STOCKÉ");
    assert!(
        md.contains(&format!("{dropped} finding(s) émis par le moteur et REFUSÉS au stockage")),
        "le rapport ne dit pas les {dropped} findings perdus :\n{}",
        md.lines().take(40).collect::<Vec<_>>().join("\n")
    );
    assert!(md.contains(&format!("le moteur en a émis **{emitted}**")), "le rapport ne donne pas le total ÉMIS");
}

// --- la lecture des colonnes : NULL ≠ 0 --------------------------------------------------------

#[test]
fn read_not_stored_maps_absent_columns_to_unknown() {
    assert_eq!(crate::report_render::read_not_stored(&json!({})), crate::report_render::view::NotStored::Unknown);
    assert_eq!(
        crate::report_render::read_not_stored(&json!({"findings_dropped": null, "findings_write_errors": null})),
        crate::report_render::view::NotStored::Unknown
    );
}

#[test]
fn read_not_stored_maps_zeroes_to_a_measured_zero() {
    assert_eq!(
        crate::report_render::read_not_stored(&json!({"findings_dropped": 0, "findings_write_errors": 0})),
        crate::report_render::view::NotStored::Counted { dropped: 0, write_errors: 0 },
        "0 est une MESURE (« rien n'a été refusé »), pas une absence de mesure"
    );
}

#[test]
fn read_not_stored_keeps_the_two_causes_apart() {
    assert_eq!(
        crate::report_render::read_not_stored(&json!({"findings_dropped": 7, "findings_write_errors": 2})),
        crate::report_render::view::NotStored::Counted { dropped: 7, write_errors: 2 }
    );
}

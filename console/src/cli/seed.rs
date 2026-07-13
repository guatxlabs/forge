// SPDX-License-Identifier: AGPL-3.0-only
//! `forge seed-demo` — amorçage de l'engagement de référence (PURE MOVE depuis cli.rs).
// ===========================================================================================
// `forge seed-demo` — amorce la base SQLite avec l'ENGAGEMENT DE RÉFÉRENCE fourni
// (examples/reference-engagement/), pour qu'une console fraîche affiche IMMÉDIATEMENT des
// Findings / Coverage / Purple / Runs peuplés, HORS-LIGNE et sans réseau. Voie d'ingestion
// LOCALE (écrit directement dans SQLite, PAS via /api/ingest) — réutilise la MÊME dérivation
// CWE/CVSS que le handler ingest pour un résultat identique. Idempotent : purge d'abord les
// lignes de la campagne démo, puis réinsère (rejouer `seed-demo` ne duplique rien et ne touche
// AUCUNE autre campagne). Données 100 % synthétiques (TLD .example réservé) — jamais une cible réelle.
// ===========================================================================================
use crate::*;
use rusqlite::Connection;
use serde_json::Value;

/// Campagne par défaut de l'engagement de référence (surchargée via `--campaign`).
const SEED_DEMO_CAMPAIGN: &str = "acme-lab";
/// run_id fixe du run synthétique de la démo (idempotence : rejouer écrase au lieu de dupliquer).
const SEED_DEMO_RUN_ID: &str = "seed-demo-acme-lab";

/// Lit un fichier JSONL en `Vec<Value>` (ignore lignes vides / commentaires `#`). `required=false`
/// -> fichier absent = liste vide (pas une erreur). Erreur lisible si une ligne n'est pas du JSON.
pub(crate) fn read_jsonl(path: &std::path::Path, required: bool) -> Result<Vec<Value>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            if !required && e.kind() == std::io::ErrorKind::NotFound {
                return Ok(vec![]);
            }
            return Err(format!("lecture de '{}' impossible: {e}", path.display()));
        }
    };
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => out.push(v),
            Err(e) => return Err(format!("{}:{}: JSON invalide: {e}", path.display(), i + 1)),
        }
    }
    Ok(out)
}

/// Résout le dossier de l'engagement de référence indépendamment du cwd (make lance depuis la
/// racine ; un humain peut lancer depuis console/). Ordre : `--dir` explicite, cwd/examples,
/// FORGE_PKG_DIR, ../examples, puis relatif au binaire (target/release -> racine du repo).
/// Le 1er candidat contenant `findings.jsonl` gagne ; sinon on renvoie le chemin par défaut tel quel
/// (l'appelant émettra une erreur de lecture lisible).
pub(crate) fn resolve_seed_dir(explicit: Option<&str>) -> std::path::PathBuf {
    let rel = std::path::Path::new("examples").join("reference-engagement");
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(d) = explicit {
        candidates.push(std::path::PathBuf::from(d));
    }
    candidates.push(rel.clone());
    if let Ok(pkg) = std::env::var("FORGE_PKG_DIR") {
        candidates.push(std::path::PathBuf::from(pkg).join(&rel));
    }
    candidates.push(std::path::Path::new("..").join(&rel));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // target/release/forge -> release -> target -> console -> racine du repo
            candidates.push(dir.join("..").join("..").join("..").join(&rel));
        }
    }
    for c in &candidates {
        if c.join("findings.jsonl").is_file() {
            return c.clone();
        }
    }
    // repli : 1er candidat (défaut) — l'appelant échouera proprement à la lecture.
    candidates.into_iter().next().unwrap_or(rel)
}

/// `forge seed-demo [--dir <path>] [--campaign <name>]` — amorce la base avec l'engagement
/// de référence fourni. Codes : 0 OK, 2 erreur (dossier/JSON/IO). Écrit directement dans SQLite.
pub(crate) fn run_seed_demo_cli(args: &[String]) -> i32 {
    let campaign = cli_opt(args, "campaign").unwrap_or_else(|| SEED_DEMO_CAMPAIGN.to_string());
    let dir = resolve_seed_dir(cli_opt(args, "dir").as_deref());
    let findings = match read_jsonl(&dir.join("findings.jsonl"), true) {
        Ok(v) => v,
        Err(e) => { eprintln!("[forge] seed-demo: {e}"); return 2; }
    };
    let runrecords = match read_jsonl(&dir.join("runrecords.jsonl"), true) {
        Ok(v) => v,
        Err(e) => { eprintln!("[forge] seed-demo: {e}"); return 2; }
    };
    let roe = match read_jsonl(&dir.join("roe_decisions.jsonl"), false) {
        Ok(v) => v,
        Err(e) => { eprintln!("[forge] seed-demo: {e}"); return 2; }
    };

    // POSTGRES (feature `store-postgres`) : sème le backend PG à travers le seam. Les lectures JSONL
    // ci-dessus sont backend-agnostiques (fichiers) ; on branche ICI, après elles, pour laisser le
    // chemin SQLite ci-dessous BYTE-IDENTIQUE. En community (bloc non compilé) et hors mode PG : SQLite.
    #[cfg(feature = "store-postgres")]
    if let Some(url) = cli_pg_url() {
        return run_seed_demo_pg(&url, &campaign, &dir, &findings, &runrecords, &roe);
    }

    let db_path = cli_db_path();
    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => { eprintln!("[forge] seed-demo: ouverture de '{db_path}' impossible: {e}"); return 2; }
    };
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    if conn.execute_batch(SCHEMA).is_err() {
        eprintln!("[forge] seed-demo: initialisation du schéma impossible");
        return 2;
    }
    migrate(&conn); // colonnes additives (run_id, cwe/cvss, run_job C2) — requises par les INSERT ci-dessous

    // IDEMPOTENCE : purge UNIQUEMENT la campagne démo (+ son run) avant de réinsérer. N'affecte
    // aucune autre campagne réelle stockée dans la même base.
    let _ = conn.execute("DELETE FROM finding WHERE campaign=?", rusqlite::params![campaign]);
    let _ = conn.execute("DELETE FROM runrecord WHERE campaign=?", rusqlite::params![campaign]);
    let _ = conn.execute("DELETE FROM roe_decision WHERE campaign=?", rusqlite::params![campaign]);
    let _ = conn.execute("DELETE FROM run_job WHERE run_id=?", rusqlite::params![SEED_DEMO_RUN_ID]);

    // --- findings : MÊME dérivation CWE/CVSS que le handler /api/ingest (résultat identique) ---
    let mut nf = 0i64;
    for f in &findings {
        let cwe = {
            let c = gs(f, "cwe");
            if c.is_empty() { extract_cwe(&gs(f, "category")) } else { c }
        };
        let (mut cvss_vec, mut cvss_score) =
            (gs(f, "cvss_vector"), f.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0));
        if cvss_vec.is_empty() && cvss_score == 0.0 {
            let (v, s) = cvss_base_for_severity(&gs(f, "severity"));
            cvss_vec = v.to_string();
            cvss_score = s;
        }
        if let Ok(n) = conn.execute(
            "INSERT OR IGNORE INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rusqlite::params![gs(f,"ts"), campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                gs(f,"fix"), SEED_DEMO_RUN_ID, cwe, cvss_vec, cvss_score],
        ) { nf += n as i64; }
    }

    // --- run-records (fires ATT&CK) : alimentent /api/coverage ET la corrélation purple ---
    let (mut nr, mut fired_cnt) = (0i64, 0i64);
    let mut targets: Vec<String> = Vec::new();
    let mut modules: Vec<String> = Vec::new();
    for rr in &runrecords {
        let fired = if rr.get("fired").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
        let (tgt, kind) = (gs(rr, "target"), gs(rr, "kind"));
        if !tgt.is_empty() && !targets.contains(&tgt) { targets.push(tgt.clone()); }
        if !kind.is_empty() && !modules.contains(&kind) { modules.push(kind.clone()); }
        if let Ok(n) = conn.execute(
            "INSERT INTO runrecord(ts,campaign,target,kind,mitre,fired,detail,run_id) VALUES(?,?,?,?,?,?,?,?)",
            rusqlite::params![gs(rr,"ts"), campaign, tgt, kind, gs(rr,"mitre"), fired, gs(rr,"detail"), SEED_DEMO_RUN_ID],
        ) { nr += n as i64; fired_cnt += fired as i64; }
    }

    // --- décisions ROE (transparence anti-masquage : FIRE / VETO / DRY_RUN) -> /api/roe ---
    let (mut nd, mut vetoed_cnt, mut dry_run_cnt) = (0i64, 0i64, 0i64);
    for d in &roe {
        let verdict = gs(d, "verdict");
        match verdict.as_str() {
            "VETO" => vetoed_cnt += 1,
            "DRY_RUN" => dry_run_cnt += 1,
            _ => {}
        }
        let ex = if d.get("exploit").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
        let de = if d.get("destructive").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
        let reasons = d.get("reasons").map(|r| r.to_string()).unwrap_or_else(|| "[]".into());
        if let Ok(n) = conn.execute(
            "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons)
             VALUES(?,?,?,?,?,?,?,?,?,?)",
            rusqlite::params![gs(d,"ts"), campaign, SEED_DEMO_RUN_ID, gs(d,"action_id"), gs(d,"target"),
                gs(d,"kind"), verdict, ex, de, reasons],
        ) { nd += n as i64; }
    }

    // --- un run_job récapitulatif : alimente l'onglet Runs (compteurs cohérents avec ci-dessus) ---
    let targets_json = serde_json::to_string(&targets).unwrap_or_else(|_| "[]".into());
    let modules_json = serde_json::to_string(&modules).unwrap_or_else(|_| "[]".into());
    // lacune de couverture volontaire (defer != delete) : classe jamais tentée + action déférée budget.
    let coverage_gaps = "{\"shop.lab.example\":[\"injection.sqli\"]}";
    let skipped_budget = "[{\"kind\":\"web.xss\",\"target\":\"shop.lab.example\",\"cls\":\"xss\"}]";
    let _ = conn.execute(
        "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps,started_by,reason,targets,modules,started,finished,exit_code)
         VALUES(?,?,datetime('now'),'done','grey',?,?,?,0,?,?,'seed-demo','bundled reference engagement (synthetic lab — examples/reference-engagement)',?,?,datetime('now'),datetime('now'),0)",
        rusqlite::params![SEED_DEMO_RUN_ID, campaign, fired_cnt, dry_run_cnt, vetoed_cnt,
            skipped_budget, coverage_gaps, targets_json, modules_json],
    );

    println!("[forge] seed-demo : engagement de référence chargé depuis {}", dir.display());
    println!("[forge] base={db_path}  campagne='{campaign}'  run_id={SEED_DEMO_RUN_ID}");
    println!("[forge] findings={nf}  run-records={nr} (fired={fired_cnt})  roe={nd} (veto={vetoed_cnt}, dry_run={dry_run_cnt})");
    println!("[forge] Findings / Coverage / Runs peuplés. Pour l'onglet Purple : lance tools/mock_plume.py + PLUME_URL (voir `make demo-purple`).");
    0
}

/// Chemin POSTGRES de `seed-demo` (feature `store-postgres`). Sème le MÊME engagement de référence que
/// le chemin SQLite, à travers le seam (`Store::postgres`), en DIALECTE PG : `INSERT OR IGNORE` ->
/// `INSERT … ON CONFLICT DO NOTHING`, `datetime('now')` -> `CAST(CURRENT_TIMESTAMP AS TEXT)` (cf.
/// state.rs). N'applique NI le PRAGMA WAL NI `migrate()` (spécifiques SQLite) : `PG_SCHEMA` porte déjà
/// toutes les colonnes de migrate. Idempotent : purge la campagne démo (+ son run) puis réinsère.
/// Réutilise la MÊME dérivation CWE/CVSS que le handler ingest / le chemin SQLite (résultat identique).
#[cfg(feature = "store-postgres")]
#[allow(clippy::too_many_arguments)]
fn run_seed_demo_pg(
    url: &str,
    campaign: &str,
    dir: &std::path::Path,
    findings: &[Value],
    runrecords: &[Value],
    roe: &[Value],
) -> i32 {
    let outcome = with_pg_store(url, |store| -> Result<(i64, i64, i64, i64, i64, i64), String> {
        store
            .execute_batch(crate::schema::PG_SCHEMA)
            .map_err(|e| format!("initialisation du schéma Postgres impossible: {e}"))?;

        // IDEMPOTENCE : purge UNIQUEMENT la campagne démo (+ son run) — n'affecte aucune autre campagne.
        let _ = store.execute("DELETE FROM finding WHERE campaign=?", &crate::sql_params![campaign]);
        let _ = store.execute("DELETE FROM runrecord WHERE campaign=?", &crate::sql_params![campaign]);
        let _ = store.execute("DELETE FROM roe_decision WHERE campaign=?", &crate::sql_params![campaign]);
        let _ = store.execute("DELETE FROM run_job WHERE run_id=?", &crate::sql_params![SEED_DEMO_RUN_ID]);

        // --- findings : MÊME dérivation CWE/CVSS que /api/ingest et le chemin SQLite ---
        let mut nf = 0i64;
        for f in findings {
            let cwe = {
                let c = gs(f, "cwe");
                if c.is_empty() { extract_cwe(&gs(f, "category")) } else { c }
            };
            let (mut cvss_vec, mut cvss_score) =
                (gs(f, "cvss_vector"), f.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0));
            if cvss_vec.is_empty() && cvss_score == 0.0 {
                let (v, s) = cvss_base_for_severity(&gs(f, "severity"));
                cvss_vec = v.to_string();
                cvss_score = s;
            }
            if let Ok(n) = store.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                &crate::sql_params![gs(f,"ts"), campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                    gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                    gs(f,"fix"), SEED_DEMO_RUN_ID, cwe, cvss_vec, cvss_score],
            ) { nf += n as i64; }
        }

        // --- run-records (fires ATT&CK) ---
        let (mut nr, mut fired_cnt) = (0i64, 0i64);
        let mut targets: Vec<String> = Vec::new();
        let mut modules: Vec<String> = Vec::new();
        for rr in runrecords {
            let fired = if rr.get("fired").and_then(|v| v.as_bool()).unwrap_or(false) { 1i64 } else { 0 };
            let (tgt, kind) = (gs(rr, "target"), gs(rr, "kind"));
            if !tgt.is_empty() && !targets.contains(&tgt) { targets.push(tgt.clone()); }
            if !kind.is_empty() && !modules.contains(&kind) { modules.push(kind.clone()); }
            if let Ok(n) = store.execute(
                "INSERT INTO runrecord(ts,campaign,target,kind,mitre,fired,detail,run_id) VALUES(?,?,?,?,?,?,?,?)",
                &crate::sql_params![gs(rr,"ts"), campaign, tgt, kind, gs(rr,"mitre"), fired, gs(rr,"detail"), SEED_DEMO_RUN_ID],
            ) { nr += n as i64; fired_cnt += fired; }
        }

        // --- décisions ROE (FIRE / VETO / DRY_RUN) ---
        let (mut nd, mut vetoed_cnt, mut dry_run_cnt) = (0i64, 0i64, 0i64);
        for d in roe {
            let verdict = gs(d, "verdict");
            match verdict.as_str() {
                "VETO" => vetoed_cnt += 1,
                "DRY_RUN" => dry_run_cnt += 1,
                _ => {}
            }
            let ex = if d.get("exploit").and_then(|v| v.as_bool()).unwrap_or(false) { 1i64 } else { 0 };
            let de = if d.get("destructive").and_then(|v| v.as_bool()).unwrap_or(false) { 1i64 } else { 0 };
            let reasons = d.get("reasons").map(|r| r.to_string()).unwrap_or_else(|| "[]".into());
            if let Ok(n) = store.execute(
                "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons)
                 VALUES(?,?,?,?,?,?,?,?,?,?)",
                &crate::sql_params![gs(d,"ts"), campaign, SEED_DEMO_RUN_ID, gs(d,"action_id"), gs(d,"target"),
                    gs(d,"kind"), verdict, ex, de, reasons],
            ) { nd += n as i64; }
        }

        // --- un run_job récapitulatif (onglet Runs) — `datetime('now')` -> CAST(CURRENT_TIMESTAMP AS TEXT) ---
        let targets_json = serde_json::to_string(&targets).unwrap_or_else(|_| "[]".into());
        let modules_json = serde_json::to_string(&modules).unwrap_or_else(|_| "[]".into());
        let coverage_gaps = "{\"shop.lab.example\":[\"injection.sqli\"]}";
        let skipped_budget = "[{\"kind\":\"web.xss\",\"target\":\"shop.lab.example\",\"cls\":\"xss\"}]";
        let _ = store.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps,started_by,reason,targets,modules,started,finished,exit_code)
             VALUES(?,?,CAST(CURRENT_TIMESTAMP AS TEXT),'done','grey',?,?,?,0,?,?,'seed-demo','bundled reference engagement (synthetic lab — examples/reference-engagement)',?,?,CAST(CURRENT_TIMESTAMP AS TEXT),CAST(CURRENT_TIMESTAMP AS TEXT),0)",
            &crate::sql_params![SEED_DEMO_RUN_ID, campaign, fired_cnt, dry_run_cnt, vetoed_cnt,
                skipped_budget, coverage_gaps, targets_json, modules_json],
        );
        Ok((nf, nr, fired_cnt, nd, vetoed_cnt, dry_run_cnt))
    });

    match outcome {
        Ok(Ok((nf, nr, fired_cnt, nd, vetoed_cnt, dry_run_cnt))) => {
            println!("[forge] seed-demo (Postgres) : engagement de référence chargé depuis {}", dir.display());
            println!("[forge] backend=postgres  campagne='{campaign}'  run_id={SEED_DEMO_RUN_ID}");
            println!("[forge] findings={nf}  run-records={nr} (fired={fired_cnt})  roe={nd} (veto={vetoed_cnt}, dry_run={dry_run_cnt})");
            0
        }
        Ok(Err(e)) | Err(e) => {
            eprintln!("[forge] seed-demo: {e}");
            2
        }
    }
}

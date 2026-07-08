// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SOUS-SYSTÈME CLI (parité LECTURE + provisioning + seed-demo + ledger verify).
//! Bloc déplacé depuis main.rs (PURE MOVE, Wave 2). Ces sous-commandes sont dispatchées par main()
//! (hors chemin HTTP) : `useradd`, `seed-demo`, `findings|roe|coverage|query`, `ledger verify`.
//! Réutilise App + les helpers de la racine de crate (validate_login/hash_pw/upsert_user/SCHEMA/
//! migrate/gs/extract_cwe/cvss_base_for_severity/exec_soql/cell/verify_ledger_chain/…) via `use
//! crate::*`, et est re-exporté à la racine par `pub(crate) use crate::cli::*` — les tests inline de
//! main.rs (`super::*`) et le dispatch de main() résolvent donc ces fonctions INCHANGÉS.
use crate::*;
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

// =====================================================================================
// Parité LECTURE en ligne de commande — `forge-console findings|roe|coverage|query`.
//
// Réutilise la connexion SQLite en READ-ONLY (SQLITE_OPEN_READ_ONLY, défense en profondeur :
// même un bug ne peut pas muter la base depuis ces sous-commandes) et, pour `query`, le compilateur
// `soql::compile` DÉJÀ partagé avec l'API web. Sortie en table (défaut) ou JSON (--json).
// Le provisioning opérateur reste, lui, via `hashpw-operator` (déjà présent).
// =====================================================================================

/// Chemin de la base lue par les sous-commandes CLI (idem boot : $FORGE_CONSOLE_DB sinon défaut).
pub(crate) fn cli_db_path() -> String {
    std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge-console.db".to_string())
}

/// Ouvre la base en READ-ONLY pour les lectures CLI. Renvoie None (et journalise) si l'ouverture
/// échoue (base absente, etc.) — l'appelant sort alors en code 2 (erreur d'usage/IO).
pub(crate) fn cli_open_ro(db_path: &str) -> Option<Connection> {
    match Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    ) {
        Ok(c) => {
            let _ = c.busy_timeout(std::time::Duration::from_secs(3));
            Some(c)
        }
        Err(e) => {
            eprintln!("[forge-console] lecture CLI: ouverture read-only de '{db_path}' impossible: {e}");
            None
        }
    }
}

/// Extrait `--<name> <value>` d'une liste d'arguments plats (best-effort, ordre libre).
pub(crate) fn cli_opt(args: &[String], name: &str) -> Option<String> {
    let flag = format!("--{name}");
    args.iter().position(|a| *a == flag).and_then(|i| args.get(i + 1).cloned())
}

/// Vrai si le drapeau booléen `--<name>` est présent.
pub(crate) fn cli_flag(args: &[String], name: &str) -> bool {
    let flag = format!("--{name}");
    args.contains(&flag)
}

/// Imprime un tableau ASCII simple (colonnes alignées) — sans dépendance externe. Les cellules
/// non-textuelles sont rendues compactes ; les valeurs longues sont laissées telles quelles (lecture
/// locale par l'opérateur). Vide -> ligne « (aucune ligne) ».
pub(crate) fn print_table(columns: &[String], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("(aucune ligne)");
        return;
    }
    let mut widths: Vec<usize> = columns.iter().map(|c| c.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
    }
    let sep = |w: &[usize]| w.iter().map(|n| "-".repeat(n + 2)).collect::<Vec<_>>().join("+");
    let fmt_row = |cells: &[String]| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!(" {:<width$} ", c, width = widths.get(i).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join("|")
    };
    println!("{}", fmt_row(columns));
    println!("{}", sep(&widths));
    for row in rows {
        println!("{}", fmt_row(row));
    }
    println!("({} ligne(s))", rows.len());
}

/// Rend une valeur JSON en cellule de tableau compacte (scalaires bruts, conteneurs sérialisés).
pub(crate) fn cell_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Imprime une liste d'objets JSON (tous mêmes clés `cols`) en table ou JSON selon `as_json`.
pub(crate) fn print_objects(cols: &[&str], rows: &[Value], as_json: bool) {
    if as_json {
        println!("{}", serde_json::to_string_pretty(&Value::Array(rows.to_vec())).unwrap_or_else(|_| "[]".into()));
        return;
    }
    let columns: Vec<String> = cols.iter().map(|c| c.to_string()).collect();
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|r| cols.iter().map(|c| cell_string(r.get(*c).unwrap_or(&Value::Null))).collect())
        .collect();
    print_table(&columns, &table);
}

/// `forge-console useradd <login> <role> [--pass <pw>]` — provisionne un compte individuel.
/// Le mot de passe est lu sur STDIN (recommandé : pas de fuite argv) ; `--pass` le fournit en argv
/// (scripting). Calcule le hash argon2id et l'écrit dans `users` (upsert par login). Ouvre la base en
/// ÉCRITURE (mêmes PRAGMA que le boot) et garantit le schéma (execute_batch) avant l'insertion — la
/// sous-commande peut donc créer le 1er compte sur une base neuve. Codes : 0 OK, 2 erreur d'usage/IO.
pub(crate) fn run_useradd_cli(args: &[String]) -> i32 {
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let (login, role) = match (positional.first(), positional.get(1)) {
        (Some(l), Some(r)) => (l.as_str(), r.as_str()),
        _ => {
            eprintln!("usage: forge-console useradd <login> <role> [--pass <password>]   (role: viewer|operator|admin)");
            return 2;
        }
    };
    if let Err(e) = validate_login(login) {
        eprintln!("[forge-console] useradd: login invalide: {e}");
        return 2;
    }
    if let Err(e) = validate_role(role) {
        eprintln!("[forge-console] useradd: {e}");
        return 2;
    }
    // mot de passe : --pass (argv, scripting) sinon lecture sur STDIN (pas de fuite via ps).
    let pw = match cli_opt(args, "pass") {
        Some(p) => p,
        None => {
            eprintln!("[forge-console] useradd: entre le mot de passe (STDIN) :");
            use std::io::Read;
            let mut s = String::new();
            if std::io::stdin().read_to_string(&mut s).is_err() {
                eprintln!("[forge-console] useradd: lecture STDIN impossible");
                return 2;
            }
            s.trim_end_matches(['\n', '\r']).to_string()
        }
    };
    if pw.is_empty() {
        eprintln!("[forge-console] useradd: mot de passe vide refusé");
        return 2;
    }
    let db_path = cli_db_path();
    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[forge-console] useradd: ouverture de '{db_path}' impossible: {e}");
            return 2;
        }
    };
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    // garantit le schéma (table users incluse) — permet de créer le 1er compte sur une base neuve.
    if conn.execute_batch(SCHEMA).is_err() {
        eprintln!("[forge-console] useradd: initialisation du schéma impossible");
        return 2;
    }
    let hash = hash_pw(&pw);
    match upsert_user(&conn, login, role, &hash) {
        Ok(role) => {
            println!("[forge-console] compte '{login}' (role={role}) provisionné dans {db_path}");
            0
        }
        Err(e) => {
            eprintln!("[forge-console] useradd: {e}");
            2
        }
    }
}

// ===========================================================================================
// `forge-console seed-demo` — amorce la base SQLite avec l'ENGAGEMENT DE RÉFÉRENCE fourni
// (examples/reference-engagement/), pour qu'une console fraîche affiche IMMÉDIATEMENT des
// Findings / Coverage / Purple / Runs peuplés, HORS-LIGNE et sans réseau. Voie d'ingestion
// LOCALE (écrit directement dans SQLite, PAS via /api/ingest) — réutilise la MÊME dérivation
// CWE/CVSS que le handler ingest pour un résultat identique. Idempotent : purge d'abord les
// lignes de la campagne démo, puis réinsère (rejouer `seed-demo` ne duplique rien et ne touche
// AUCUNE autre campagne). Données 100 % synthétiques (TLD .example réservé) — jamais une cible réelle.
// ===========================================================================================

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
            // target/release/forge-console -> release -> target -> console -> racine du repo
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

/// `forge-console seed-demo [--dir <path>] [--campaign <name>]` — amorce la base avec l'engagement
/// de référence fourni. Codes : 0 OK, 2 erreur (dossier/JSON/IO). Écrit directement dans SQLite.
pub(crate) fn run_seed_demo_cli(args: &[String]) -> i32 {
    let campaign = cli_opt(args, "campaign").unwrap_or_else(|| SEED_DEMO_CAMPAIGN.to_string());
    let dir = resolve_seed_dir(cli_opt(args, "dir").as_deref());
    let findings = match read_jsonl(&dir.join("findings.jsonl"), true) {
        Ok(v) => v,
        Err(e) => { eprintln!("[forge-console] seed-demo: {e}"); return 2; }
    };
    let runrecords = match read_jsonl(&dir.join("runrecords.jsonl"), true) {
        Ok(v) => v,
        Err(e) => { eprintln!("[forge-console] seed-demo: {e}"); return 2; }
    };
    let roe = match read_jsonl(&dir.join("roe_decisions.jsonl"), false) {
        Ok(v) => v,
        Err(e) => { eprintln!("[forge-console] seed-demo: {e}"); return 2; }
    };

    let db_path = cli_db_path();
    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => { eprintln!("[forge-console] seed-demo: ouverture de '{db_path}' impossible: {e}"); return 2; }
    };
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    if conn.execute_batch(SCHEMA).is_err() {
        eprintln!("[forge-console] seed-demo: initialisation du schéma impossible");
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

    println!("[forge-console] seed-demo : engagement de référence chargé depuis {}", dir.display());
    println!("[forge-console] base={db_path}  campagne='{campaign}'  run_id={SEED_DEMO_RUN_ID}");
    println!("[forge-console] findings={nf}  run-records={nr} (fired={fired_cnt})  roe={nd} (veto={vetoed_cnt}, dry_run={dry_run_cnt})");
    println!("[forge-console] Findings / Coverage / Runs peuplés. Pour l'onglet Purple : lance tools/mock_plume.py + PLUME_URL (voir `make demo-purple`).");
    0
}

/// Dispatch des sous-commandes de lecture. Retourne un code de sortie : 0 = OK, 2 = erreur (IO/SOQL).
pub(crate) fn run_read_cli(cmd: &str, args: &[String]) -> i32 {
    let as_json = cli_flag(args, "json");
    let campaign = cli_opt(args, "campaign");
    let db_path = cli_db_path();
    match cmd {
        "findings" => {
            let conn = match cli_open_ro(&db_path) { Some(c) => c, None => return 2 };
            let (where_, params): (String, Vec<String>) = match &campaign {
                Some(c) => (" WHERE campaign=?".into(), vec![c.clone()]),
                None => (String::new(), vec![]),
            };
            let sql = format!(
                "SELECT id,ts,campaign,target,title,severity,category,mitre,status,tool,run_id FROM finding{where_} ORDER BY id DESC LIMIT 1000"
            );
            let rows = cli_query_rows(&conn, &sql, &params, &[
                "id", "ts", "campaign", "target", "title", "severity", "category", "mitre", "status", "tool", "run_id",
            ]);
            print_objects(&["id", "ts", "campaign", "target", "title", "severity", "status", "mitre", "tool"], &rows, as_json);
            0
        }
        "roe" => {
            let conn = match cli_open_ro(&db_path) { Some(c) => c, None => return 2 };
            let (where_, params): (String, Vec<String>) = match &campaign {
                Some(c) => (" WHERE campaign=?".into(), vec![c.clone()]),
                None => (String::new(), vec![]),
            };
            let sql = format!(
                "SELECT id,ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons FROM roe_decision{where_} ORDER BY id DESC LIMIT 2000"
            );
            let rows = cli_query_rows(&conn, &sql, &params, &[
                "id", "ts", "campaign", "run_id", "action_id", "target", "kind", "verdict", "exploit", "destructive", "reasons",
            ]);
            print_objects(&["id", "ts", "campaign", "run_id", "target", "kind", "verdict", "exploit", "destructive"], &rows, as_json);
            0
        }
        "coverage" => {
            let conn = match cli_open_ro(&db_path) { Some(c) => c, None => return 2 };
            let (sql, params): (&str, Vec<String>) = match &campaign {
                Some(c) => (
                    "SELECT mitre, COUNT(*) runs, COALESCE(SUM(fired),0) fired FROM runrecord WHERE mitre<>'' AND campaign=? GROUP BY mitre ORDER BY runs DESC",
                    vec![c.clone()],
                ),
                None => (
                    "SELECT mitre, COUNT(*) runs, COALESCE(SUM(fired),0) fired FROM runrecord WHERE mitre<>'' GROUP BY mitre ORDER BY runs DESC",
                    vec![],
                ),
            };
            let rows = cli_query_rows(&conn, sql, &params, &["mitre", "runs", "fired"]);
            print_objects(&["mitre", "runs", "fired"], &rows, as_json);
            0
        }
        "query" => {
            // --soql '...' (ou repli sur le 1er argument positionnel non-drapeau) -> soql::compile.
            let soql = cli_opt(args, "soql").or_else(|| {
                let mut it = args.iter();
                while let Some(a) = it.next() {
                    if a == "--campaign" || a == "--soql" {
                        it.next(); // consomme la valeur du drapeau
                        continue;
                    }
                    if !a.starts_with("--") {
                        return Some(a.clone());
                    }
                }
                None
            });
            let soql = match soql {
                Some(s) if !s.is_empty() => s,
                _ => {
                    eprintln!("usage: forge-console query --soql '<pipeline soql>' [--json]");
                    return 2;
                }
            };
            match exec_soql(&db_path, &soql) {
                Ok(v) => {
                    if as_json {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()));
                    } else {
                        let cols: Vec<String> = v.get("columns").and_then(|c| c.as_array())
                            .map(|a| a.iter().map(cell_string).collect()).unwrap_or_default();
                        let table: Vec<Vec<String>> = v.get("rows").and_then(|r| r.as_array())
                            .map(|rows| rows.iter().map(|row| {
                                row.as_array().map(|cells| cells.iter().map(cell_string).collect())
                                    .unwrap_or_default()
                            }).collect())
                            .unwrap_or_default();
                        print_table(&cols, &table);
                    }
                    0
                }
                Err((_, e)) => {
                    eprintln!("[forge-console] query: SOQL invalide: {e}");
                    2
                }
            }
        }
        _ => 2,
    }
}

/// Exécute une requête SQL paramétrée et renvoie chaque ligne en objet JSON {col: valeur}, en
/// préservant le type SQLite via `cell()`. Best-effort : une erreur de préparation -> vec vide.
pub(crate) fn cli_query_rows(conn: &Connection, sql: &str, params: &[String], cols: &[&str]) -> Vec<Value> {
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[forge-console] lecture CLI: requête invalide: {e}");
            return vec![];
        }
    };
    let ncol = cols.len();
    stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
        let mut o = serde_json::Map::new();
        for (i, c) in cols.iter().enumerate().take(ncol) {
            o.insert((*c).to_string(), cell(row, i));
        }
        Ok(Value::Object(o))
    })
    .map(|it| it.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Sous-commande LECTURE SEULE, NON INTERACTIVE et RAPIDE : `forge-console ledger verify [--ledger <path>]
/// [--json]`. Recompute la chaîne SHA-256 (prev|seq|ts|kind|canon(detail)) du ledger JSONL et VÉRIFIE
/// chaque hash + le chaînage `prev` — MÊME algorithme que GET /api/ledger/verify et `migrate --verify`
/// (verify_ledger_chain, source de vérité unique). Ne démarre AUCUN serveur, n'ouvre AUCUNE base SQLite,
/// ne lit AUCUN STDIN : pure lecture du fichier -> exit immédiat (jamais de blocage). La vérif de
/// SIGNATURE (Ed25519/HMAC) reste côté `forge ledger verify --pubkey` (Python) : la console n'a pas la
/// clé privée -> `sig_checked:false`. Chemin résolu : `--ledger` sinon $FORGE_CONSOLE_LEDGER sinon défaut
/// `engagement.jsonl` (parité boot). Codes de sortie : 0 = chaîne intègre (ou fichier présent mais vide) ;
/// 1 = rupture/altération détectée OU ledger absent ; 2 = erreur d'usage (sous-commande absente/inconnue).
pub(crate) fn run_ledger_cli(args: &[String]) -> i32 {
    // sous-commande positionnelle (verify). FAIL-CLOSED sur l'inconnu : on ne RETOMBE JAMAIS sur le
    // démarrage serveur (c'était le bug — `ledger verify` bootait la console et pendait indéfiniment).
    let sub = args.iter().find(|a| !a.starts_with("--")).map(|s| s.as_str());
    match sub {
        Some("verify") => {}
        _ => {
            eprintln!("usage: forge-console ledger verify [--ledger <path>] [--json]");
            eprintln!("  Vérifie le hash-chaining SHA-256 du ledger JSONL (lecture seule, non interactive,");
            eprintln!("  ne démarre pas le serveur). La vérif de signature (Ed25519/HMAC) reste côté");
            eprintln!("  `forge ledger verify --pubkey`. Codes : 0=intègre, 1=rompu/absent, 2=usage.");
            return 2;
        }
    }
    let as_json = cli_flag(args, "json");
    let path = cli_opt(args, "ledger")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("FORGE_CONSOLE_LEDGER").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "engagement.jsonl".to_string());
    let v = verify_ledger_chain(&path);
    if as_json {
        let out = ledger_verify_api_json(&v, &path);
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into()));
    } else if v.empty {
        // fichier absent OU 0 entrée exploitable : lisible, jamais un « OK » trompeur sur un ledger absent.
        let why = v.why.clone().unwrap_or_else(|| "ledger vide (0 entrée)".to_string());
        println!("ledger {} : {} — {}", path, if v.ok { "vide (présent, 0 entrée)" } else { "INVALIDE" }, why);
    } else if v.ok {
        let alg = if v.alg.is_empty() { "sha256" } else { v.alg.as_str() };
        println!("ledger {} : OK — {} entrée(s), alg={}, head={}",
            path, v.entries, alg, v.head.as_deref().unwrap_or(""));
    } else {
        let why = v.why.clone().unwrap_or_else(|| "chaîne rompue".to_string());
        println!("ledger {} : INVALIDE — {} (entrée seq={}, après {} entrée(s) valides)",
            path, why, v.broken, v.entries.saturating_sub(1));
    }
    if v.ok { 0 } else { 1 }
}

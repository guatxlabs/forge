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

// =====================================================================================
// ROUTAGE POSTGRES DES SOUS-COMMANDES CLI (Stage 2b) — les sous-commandes CLI ouvrent leur PROPRE
// connexion (elles court-circuitent l'App, qui n'existe pas hors du chemin HTTP). Quand le backend
// enterprise Postgres est sélectionné (FORGE_ENTERPRISE_STORE=postgres + FORGE_DB_URL) ET que la
// feature `store-postgres` est compilée, elles se connectent à Postgres et exécutent leur DML/DDL À
// TRAVERS LE SEAM (`Store::postgres`), pour que `forge-console useradd`/`seed-demo`/lectures marchent
// sur un déploiement PG — la gate de démarrage fail-closée ne bloque QUE le serveur, pas le
// provisioning CLI de la base PG en amont. Hors de ce cas (et TOUJOURS en community, blocs non
// compilés) : SQLite EXACTEMENT comme avant (byte-identique). Tout ce bloc PG est gardé par la feature.
// =====================================================================================

/// URL Postgres si la CLI doit cibler PG : `FORGE_ENTERPRISE_STORE=postgres` + `FORGE_DB_URL` non vide.
/// `None` => SQLite. En community (feature absente) cette fonction n'existe pas : les sites d'appel
/// sont eux aussi gardés `#[cfg(feature = "store-postgres")]`, donc le build par défaut est inchangé.
#[cfg(feature = "store-postgres")]
fn cli_pg_url() -> Option<String> {
    if std::env::var("FORGE_ENTERPRISE_STORE").as_deref() == Ok("postgres") {
        match std::env::var("FORGE_DB_URL") {
            Ok(u) if !u.is_empty() => return Some(u),
            _ => eprintln!("[forge-console] FORGE_ENTERPRISE_STORE=postgres mais FORGE_DB_URL absent/vide — repli SQLite"),
        }
    }
    None
}

/// Connecte un client Postgres session-pinné pour `url`, en construit un `Store::postgres` (même
/// modèle held-guard que `App::store()` : le client est verrouillé pour la vie du `Store`), et passe
/// ce store à `f`. Le client est connecté HORS de tout runtime tokio (contexte CLI synchrone), ce que
/// `connect_postgres` requiert. Renvoie `Err(String)` (message lisible) si la connexion échoue.
#[cfg(feature = "store-postgres")]
fn with_pg_store<T: Send>(url: &str, f: impl FnOnce(&crate::store::Store) -> T + Send) -> Result<T, String> {
    // Run the WHOLE lifecycle — connect, seam ops, AND drop of the client — on a dedicated `std::thread`,
    // clear of the tokio runtime. The CLI subcommands are dispatched from inside `#[tokio::main]`, and the
    // synchronous `postgres` client drives its OWN `block_on` both at connect time AND in its `Drop`
    // (connection close); either panics "runtime within a runtime" if it happens on a runtime worker. A
    // plain std thread has no ambient runtime, so `pg_block` runs the client calls directly and the client
    // closes cleanly when it drops at the end of the thread scope. `thread::scope` lets the closure borrow
    // `url`/captures without a `'static` bound; `T: Send` + `f: Send` carry the result back.
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let client = crate::store::connect_postgres(url)?;
                let m = std::sync::Mutex::new(client);
                let store = crate::store::Store::postgres(m.lock().unwrap_or_else(|e| e.into_inner()));
                Ok(f(&store)) // store guard then `m` (client) drop HERE, on this off-runtime thread
            })
            .join()
            .map_err(|_| "postgres worker thread panicked".to_string())?
    })
}

/// Analogue seam de [`cli_query_rows`] : exécute un SELECT paramétré à travers le `Store` (donc PG) et
/// renvoie chaque ligne en objet JSON {col: valeur}, en préservant le type via `Row::get_value` +
/// `store::value_to_json` — MÊME typage par cellule que `cell`/`cli_query_rows`. Les paramètres sont
/// liés en TEXT (comme la version SQLite qui bind des `String`). LAX : `query_lax` saute les lignes
/// dont le map échoue et propage une erreur de préparation (best-effort -> vec vide).
#[cfg(feature = "store-postgres")]
fn cli_query_rows_store(store: &crate::store::Store, sql: &str, params: &[String], cols: &[&str]) -> Vec<Value> {
    let binds: Vec<crate::store::Param> = params.iter().map(|s| crate::store::Param::Text(s.clone())).collect();
    store
        .query_lax(sql, &binds, |row| {
            let mut o = serde_json::Map::new();
            for (i, c) in cols.iter().enumerate() {
                let v = match row.get_value(i) {
                    Ok(v) => crate::store::value_to_json(&v),
                    Err(_) => Value::Null,
                };
                o.insert((*c).to_string(), v);
            }
            Ok(Value::Object(o))
        })
        .unwrap_or_default()
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
    // POSTGRES (feature `store-postgres`) : provisionne le compte dans PG via le seam. En community
    // (bloc non compilé) et hors mode PG, on continue sur le chemin SQLite INCHANGÉ ci-dessous.
    #[cfg(feature = "store-postgres")]
    if let Some(url) = cli_pg_url() {
        return run_useradd_pg(&url, login, role, &pw);
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

/// Chemin POSTGRES de `useradd` (feature `store-postgres`). Connecte PG, garantit le schéma
/// (`PG_SCHEMA` — permet de créer le 1er compte sur une base PG neuve, parité avec `execute_batch(SCHEMA)`
/// côté SQLite) puis upsert via `upsert_user_store` (le MÊME analogue seam que le runtime — DRY : une
/// seule définition de l'upsert users). Codes : 0 OK, 2 erreur (connexion/schéma/écriture).
#[cfg(feature = "store-postgres")]
fn run_useradd_pg(url: &str, login: &str, role: &str, pw: &str) -> i32 {
    let hash = hash_pw(pw);
    let outcome = with_pg_store(url, |store| {
        store
            .execute_batch(crate::state::PG_SCHEMA)
            .map_err(|e| format!("initialisation du schéma Postgres impossible: {e}"))?;
        upsert_user_store(store, login, role, &hash)
    });
    match outcome {
        Ok(Ok(role)) => {
            println!("[forge-console] compte '{login}' (role={role}) provisionné dans Postgres");
            0
        }
        Ok(Err(e)) | Err(e) => {
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
            .execute_batch(crate::state::PG_SCHEMA)
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
            println!("[forge-console] seed-demo (Postgres) : engagement de référence chargé depuis {}", dir.display());
            println!("[forge-console] backend=postgres  campagne='{campaign}'  run_id={SEED_DEMO_RUN_ID}");
            println!("[forge-console] findings={nf}  run-records={nr} (fired={fired_cnt})  roe={nd} (veto={vetoed_cnt}, dry_run={dry_run_cnt})");
            0
        }
        Ok(Err(e)) | Err(e) => {
            eprintln!("[forge-console] seed-demo: {e}");
            2
        }
    }
}

/// Dispatch des sous-commandes de lecture. Retourne un code de sortie : 0 = OK, 2 = erreur (IO/SOQL).
pub(crate) fn run_read_cli(cmd: &str, args: &[String]) -> i32 {
    let as_json = cli_flag(args, "json");
    let campaign = cli_opt(args, "campaign");
    let db_path = cli_db_path();
    // POSTGRES (feature `store-postgres`) : parité LECTURE contre PG (mêmes SELECT, moteur SoQL inclus),
    // à travers le seam. En community (bloc non compilé) et hors mode PG : chemin SQLite INCHANGÉ.
    #[cfg(feature = "store-postgres")]
    if let Some(url) = cli_pg_url() {
        return run_read_cli_pg(cmd, &url, args, as_json, campaign.as_deref());
    }
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

/// Chemin POSTGRES de [`run_read_cli`] (feature `store-postgres`). Même sémantique/mêmes colonnes que
/// le chemin SQLite, mais lu à travers le seam (`Store::postgres` + `cli_query_rows_store` pour les
/// SELECT statiques, `exec_soql_time_pg_store` pour `query`). Les SELECT `findings`/`roe`/`coverage`
/// sont dialect-neutres (aucun `datetime('now')` ni `INSERT OR IGNORE`), donc réutilisés VERBATIM.
#[cfg(feature = "store-postgres")]
fn run_read_cli_pg(cmd: &str, url: &str, args: &[String], as_json: bool, campaign: Option<&str>) -> i32 {
    let outcome = with_pg_store(url, |store| -> i32 {
        match cmd {
            "findings" => {
                let (where_, params): (String, Vec<String>) = match campaign {
                    Some(c) => (" WHERE campaign=?".into(), vec![c.to_string()]),
                    None => (String::new(), vec![]),
                };
                let sql = format!(
                    "SELECT id,ts,campaign,target,title,severity,category,mitre,status,tool,run_id FROM finding{where_} ORDER BY id DESC LIMIT 1000"
                );
                let rows = cli_query_rows_store(store, &sql, &params, &[
                    "id", "ts", "campaign", "target", "title", "severity", "category", "mitre", "status", "tool", "run_id",
                ]);
                print_objects(&["id", "ts", "campaign", "target", "title", "severity", "status", "mitre", "tool"], &rows, as_json);
                0
            }
            "roe" => {
                let (where_, params): (String, Vec<String>) = match campaign {
                    Some(c) => (" WHERE campaign=?".into(), vec![c.to_string()]),
                    None => (String::new(), vec![]),
                };
                let sql = format!(
                    "SELECT id,ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons FROM roe_decision{where_} ORDER BY id DESC LIMIT 2000"
                );
                let rows = cli_query_rows_store(store, &sql, &params, &[
                    "id", "ts", "campaign", "run_id", "action_id", "target", "kind", "verdict", "exploit", "destructive", "reasons",
                ]);
                print_objects(&["id", "ts", "campaign", "run_id", "target", "kind", "verdict", "exploit", "destructive"], &rows, as_json);
                0
            }
            "coverage" => {
                let (sql, params): (&str, Vec<String>) = match campaign {
                    Some(c) => (
                        "SELECT mitre, COUNT(*) runs, COALESCE(SUM(fired),0) fired FROM runrecord WHERE mitre<>'' AND campaign=? GROUP BY mitre ORDER BY runs DESC",
                        vec![c.to_string()],
                    ),
                    None => (
                        "SELECT mitre, COUNT(*) runs, COALESCE(SUM(fired),0) fired FROM runrecord WHERE mitre<>'' GROUP BY mitre ORDER BY runs DESC",
                        vec![],
                    ),
                };
                let rows = cli_query_rows_store(store, sql, &params, &["mitre", "runs", "fired"]);
                print_objects(&["mitre", "runs", "fired"], &rows, as_json);
                0
            }
            "query" => {
                // --soql '...' (ou 1er positionnel non-drapeau) — MÊME extraction que le chemin SQLite.
                let soql = cli_opt(args, "soql").or_else(|| {
                    let mut it = args.iter();
                    while let Some(a) = it.next() {
                        if a == "--campaign" || a == "--soql" { it.next(); continue; }
                        if !a.starts_with("--") { return Some(a.clone()); }
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
                // MÊME moteur SoQL read-only que l'API, routé sur PG (transaction READ ONLY sur ce store).
                match crate::exec_soql_time_pg_store(store, &soql, 0, 0) {
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
    });
    match outcome {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[forge-console] lecture CLI (Postgres): {e}");
            2
        }
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

// ===========================================================================================
// `forge-console migrate-store` (feature `store-postgres`) — MIGRATEUR DE DONNÉES GOUVERNÉ
// SQLite -> Postgres. Copie CHAQUE table du backend SQLite (source) vers un Postgres (cible) À
// TRAVERS LE SEAM (`Store`), en PRÉSERVANT les ids exacts et le typage par cellule (int/real/text/
// blob/null ; bool=0/1), en ORDRE de dépendance FK (parents avant enfants), puis RECALE toutes les
// séquences IDENTITY et VÉRIFIE le nombre de lignes table par table. Gouvernance : refuse d'écraser
// une cible non vide sans `--force` (avec `--force` -> TRUNCATE ... RESTART IDENTITY des tables cibles).
// `--dry-run` : lecture seule, n'écrit RIEN dans la cible. Émet un checkpoint ledger SIGNÉ (chaîné
// SHA-256, alg `sha256-console`, comme tout acte console) `console.store.migrate` traçant la provenance
// (source, cible RÉDIGÉE sans credentials, comptes par table, horodatage, drapeau dry-run).
//
// TOUT ce bloc est gardé `#[cfg(feature = "store-postgres")]` : le build community (défaut) ne le
// compile pas et reste BYTE-IDENTICAL + openssl-free. Aucune dépendance nouvelle (réutilise le seam
// postgres/rustls + l'infra ledger `ledger_append_standalone`/`verify_ledger_chain`).
// ===========================================================================================

/// ORDRE de dépendance FK (tri topologique) — parents AVANT enfants. Dérivé des FK LOGIQUES de
/// `PG_SCHEMA` + des tables ENTERPRISE (aucune contrainte `REFERENCES` dure n'est déclarée, donc l'ordre
/// d'insertion est en fait libre côté contrainte ; on le fixe quand même pour la CORRECTION si des FK
/// sont un jour ajoutées et pour la lisibilité du rapport). Ce n'est PAS la liste autoritative des tables
/// à migrer — celle-ci est ÉNUMÉRÉE DYNAMIQUEMENT depuis `sqlite_master` (cf. `enumerate_source_tables`) ;
/// cette constante ne sert QUE de HINT d'ordonnancement (`order_migration_tables`). Couvre les 17 tables
/// de base de `PG_SCHEMA` PUIS les 5 tables enterprise créées paresseusement (`scim_*`/`sso_pending`/
/// `rbac_group_map`, hors `PG_SCHEMA` — matérialisées sur la cible par leurs modules via `ensure_pg_schema`).
/// Toute table source ABSENTE de ce hint est quand même migrée (appended à la fin par `order_migration_tables`)
/// ou hard-fail si la cible ne peut la créer — JAMAIS de skip silencieux.
#[cfg(feature = "store-postgres")]
const MIGRATE_STORE_FK_ORDER: &[&str] = &[
    // racines (aucun parent logique)
    "tenant",          // parent de engagement, rbac_group_map
    "users",           // parent de session, tenant_grant, scim_user, scim_group_member
    "dashboard",       // parent de panel
    "campaign",
    "module",
    "settings",
    "finding_template",
    "ledger_entry",
    // enfants (base)
    "engagement",      // -> tenant
    "tenant_grant",    // -> users, tenant
    "panel",           // -> dashboard
    "session",         // -> users
    "finding",         // -> engagement
    "runrecord",       // -> engagement
    "roe_decision",    // -> engagement
    "run_job",         // -> engagement
    "run_log",         // -> run_job (par run_id, FK souple)
    // tables ENTERPRISE (créées paresseusement, hors PG_SCHEMA ; dépendent de users/tenant déjà copiés)
    "scim_user",         // -> users (user_id = users.id, PK explicite)
    "scim_group",        // racine (id IDENTITY BY DEFAULT — recalée par advance_pg_identity_sequences_all)
    "scim_group_member", // -> scim_group, users
    "sso_pending",       // racine (PK state TEXT ; état d'auth OIDC éphémère)
    "rbac_group_map",    // -> tenant (tenant_id nullable ; mappings IdP-groupe -> rôle)
];

/// Rédige les credentials d'une URL Postgres pour l'audit (le ledger ne DOIT jamais contenir de secret) :
/// `postgres://user:pass@host:5432/db?sslmode=require` -> `postgres://host:5432/db`. Supprime le userinfo
/// (`user:pass@`) et la query-string. Best-effort : si l'URL n'a pas la forme attendue on renvoie au
/// minimum le schéma + hôte, jamais le mot de passe.
#[cfg(feature = "store-postgres")]
fn redact_pg_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => return "<redacted>".to_string(),
    };
    // authority = jusqu'au premier '/' (ou toute la chaîne) ; on droppe la query-string éventuelle.
    let rest = rest.split('?').next().unwrap_or(rest);
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (rest, None),
    };
    // droppe le userinfo (tout jusqu'au dernier '@' inclus).
    let hostport = match authority.rsplit_once('@') {
        Some((_userinfo, hp)) => hp,
        None => authority,
    };
    match path {
        Some(p) => format!("{scheme}://{hostport}/{p}"),
        None => format!("{scheme}://{hostport}"),
    }
}

/// Convertit une cellule lue (`Value`, côté READ) en paramètre lié (`Param`, côté BIND) en préservant le
/// typage exact : Int->Int, Real->Real, Text->Text, Blob->Blob, Null->Null. Les booléens SQLite sont déjà
/// des `Int` 0/1 (SQLite n'a pas de classe bool) et se relient en BIGINT 0/1 côté PG (parité du schéma).
#[cfg(feature = "store-postgres")]
fn value_to_param(v: crate::store::Value) -> crate::store::Param {
    use crate::store::{Param, Value};
    match v {
        Value::Int(i) => Param::Int(i),
        Value::Real(f) => Param::Real(f),
        Value::Text(s) => Param::Text(s),
        Value::Blob(b) => Param::Blob(b),
        Value::Null => Param::Null,
    }
}

/// Noms de colonnes d'une table SQLite source, dans l'ordre du schéma (`PRAGMA table_info`). On copie
/// EXACTEMENT ces colonnes (INSERT nommé) -> aucune liste codée en dur, robuste à la dérive de schéma ;
/// PG mappe par NOM donc l'ordre interne de la cible est indifférent.
#[cfg(feature = "store-postgres")]
fn sqlite_table_columns(src: &crate::store::Store, table: &str) -> crate::store::StoreResult<Vec<String>> {
    // `PRAGMA table_info` renvoie (cid, name, type, notnull, dflt_value, pk) — le nom est en index 1.
    src.query(&format!("PRAGMA table_info({table})"), &crate::sql_params![], |r| r.get_str(1))
}

/// ÉNUMÈRE les tables UTILISATEUR de la source SQLite — l'ensemble AUTORITATIF à migrer, découvert
/// DYNAMIQUEMENT (jamais une liste codée en dur). `SELECT name FROM sqlite_master WHERE type='table'` ;
/// exclut les tables INTERNES SQLite (`sqlite_%` : `sqlite_sequence`, `sqlite_stat*`, etc.). Aucune table de
/// bookkeeping de migration n'existe côté console (les migrations additives passent par `ALTER TABLE`
/// error-ignored, pas par une table `schema_migrations`), donc `NOT LIKE 'sqlite_%'` suffit. C'est CE set
/// (et non les 22 du hint FK) qui pilote copie + vérif : une table enterprise créée paresseusement
/// (`scim_*`/`sso_pending`/`rbac_group_map`) présente dans la source est donc TOUJOURS reprise.
#[cfg(feature = "store-postgres")]
fn enumerate_source_tables(src: &crate::store::Store) -> crate::store::StoreResult<Vec<String>> {
    src.query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        &crate::sql_params![],
        |r| r.get_str(0),
    )
}

/// ÉNUMÈRE les tables présentes sur la CIBLE Postgres (`information_schema.tables` du schéma courant) —
/// sert au contrôle « la cible possède-t-elle CHAQUE table source ? » AVANT copie (no silent skip).
#[cfg(feature = "store-postgres")]
fn enumerate_dest_tables(store: &crate::store::Store) -> crate::store::StoreResult<Vec<String>> {
    store.query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()",
        &crate::sql_params![],
        |r| r.get_str(0),
    )
}

/// ORDONNE l'ensemble énuméré `src_tables` en ordre de dépendance FK : d'abord les tables connues dans
/// l'ordre de `MIGRATE_STORE_FK_ORDER` (parents avant enfants — filtrées à celles réellement présentes dans
/// la source), PUIS toute table source INCONNUE du hint, ajoutée à la fin (jamais droppée). Une table
/// inconnue échouera le contrôle de présence côté cible avec un message clair — jamais de skip silencieux.
#[cfg(feature = "store-postgres")]
fn order_migration_tables(src_tables: &[String]) -> Vec<String> {
    let mut ordered: Vec<String> = Vec::with_capacity(src_tables.len());
    for known in MIGRATE_STORE_FK_ORDER {
        if src_tables.iter().any(|t| t == known) {
            ordered.push((*known).to_string());
        }
    }
    for t in src_tables {
        if !MIGRATE_STORE_FK_ORDER.contains(&t.as_str()) {
            ordered.push(t.clone());
        }
    }
    ordered
}

/// Compte les lignes d'une table via le seam (source SQLite ou cible PG). `count(*)` -> entier.
#[cfg(feature = "store-postgres")]
fn count_rows(store: &crate::store::Store, table: &str) -> crate::store::StoreResult<i64> {
    store.query_row(&format!("SELECT count(*) FROM {table}"), &crate::sql_params![], |r| r.get_i64(0))
}

/// Compte les lignes cible en TOLÉRANT une table absente (renvoie 0) — pour le rapport `--dry-run` sur une
/// cible dont le schéma n'a pas (encore) été appliqué.
#[cfg(feature = "store-postgres")]
fn count_rows_lenient(store: &crate::store::Store, table: &str) -> i64 {
    count_rows(store, table).unwrap_or(0)
}

/// Une ligne du tableau de vérification : table, comptes source et cible.
#[cfg(feature = "store-postgres")]
struct MigTableCount {
    table: String,
    source: i64,
    dest: i64,
}

/// Rapport de migration renvoyé par le cœur, consommé par le checkpoint ledger + l'affichage.
#[cfg(feature = "store-postgres")]
struct MigrationReport {
    counts: Vec<MigTableCount>,
    identity: Vec<(String, String, i64)>,
    total_rows: i64,
}

/// Copie une table de la source vers la cible (dans la transaction `tx`), en préservant ids + typage.
/// Renvoie le nombre de lignes copiées. Colonnes lues dynamiquement (`PRAGMA table_info`), valeurs via
/// l'accesseur dynamique `Row::get_value` -> `Param` (typage exact conservé). INSERT nommé -> ids explicites
/// PRÉSERVÉS (la colonne IDENTITY est `GENERATED BY DEFAULT`, donc un id fourni est accepté tel quel).
#[cfg(feature = "store-postgres")]
fn copy_table(
    src: &crate::store::Store,
    tx: &crate::store::Tx,
    table: &str,
) -> crate::store::StoreResult<i64> {
    let cols = sqlite_table_columns(src, table)?;
    if cols.is_empty() {
        return Ok(0);
    }
    let col_list = cols.join(", ");
    let placeholders = vec!["?"; cols.len()].join(", ");
    let insert_sql = format!("INSERT INTO {table} ({col_list}) VALUES ({placeholders})");
    let select_sql = format!("SELECT {col_list} FROM {table}");
    let ncols = cols.len();
    // Lit toutes les lignes source en vecteurs de Param (typage exact), STRICT : une cellule illisible
    // sinke la migration (jamais de perte silencieuse). `query` (pas `query_lax`) -> échec dur au 1er souci.
    let rows: Vec<Vec<crate::store::Param>> = src.query(&select_sql, &crate::sql_params![], |row| {
        let mut binds = Vec::with_capacity(ncols);
        for i in 0..ncols {
            binds.push(value_to_param(row.get_value(i)?));
        }
        Ok(binds)
    })?;
    let mut copied = 0i64;
    for binds in &rows {
        tx.execute(&insert_sql, binds)?;
        copied += 1;
    }
    Ok(copied)
}

/// Cœur de la migration : applique le schéma cible (hors dry-run), vérifie la gouvernance (refuse une
/// cible non vide sans `--force`), copie toutes les tables en ordre FK dans UNE transaction, recale les
/// séquences IDENTITY, vérifie les comptes ligne à ligne, et COMMIT seulement si tout concorde (sinon
/// ROLLBACK -> aucune migration partielle silencieuse). `Ok(Some(report))` = migration effectuée/dry-run ;
/// `Ok(None)` = refus de gouvernance (cible non vide, pas de `--force`) ; `Err` = échec dur (comptes
/// discordants -> rollback, ou erreur IO/SQL).
#[cfg(feature = "store-postgres")]
fn migrate_store_core(
    src: &crate::store::Store,
    dst: &crate::store::Store,
    dry_run: bool,
    force: bool,
) -> crate::store::StoreResult<Option<MigrationReport>> {
    use crate::store::StoreError;

    // ENSEMBLE AUTORITATIF : CHAQUE table utilisateur de la source, énumérée DYNAMIQUEMENT depuis
    // `sqlite_master` (jamais une liste codée en dur) — couvre les tables enterprise créées paresseusement
    // (`scim_*`/`sso_pending`/`rbac_group_map`) si elles existent dans la source. Ordonnée en dépendance FK
    // (parents avant enfants ; toute table inconnue du hint est appended, jamais droppée).
    let src_tables = enumerate_source_tables(src)?;
    let tables = order_migration_tables(&src_tables);

    if dry_run {
        // LECTURE SEULE : n'applique PAS le schéma, n'écrit RIEN. Rapporte les comptes source (ce qui SERAIT
        // copié) + les comptes cible actuels (tolérant si une table n'existe pas côté cible).
        let mut counts = Vec::with_capacity(tables.len());
        let mut total = 0i64;
        for t in &tables {
            let s = count_rows(src, t)?;
            total += s;
            counts.push(MigTableCount { table: t.clone(), source: s, dest: count_rows_lenient(dst, t) });
        }
        return Ok(Some(MigrationReport { counts, identity: vec![], total_rows: total }));
    }

    // 1) Schéma cible idempotent (CREATE TABLE IF NOT EXISTS ...). Non destructif ; hors transaction pour
    //    que les tables persistent même si la copie rollback (elles servent aussi au compte de gouvernance).
    //    On applique le SCHÉMA DE BASE (`PG_SCHEMA`) PUIS les tables ENTERPRISE créées paresseusement via le
    //    chemin PG `ensure_schema` de chaque module (scim/sso/rbac) — sinon `scim_*`/`sso_pending`/
    //    `rbac_group_map` seraient absentes de la cible et la copie perdrait identités provisionnées + mappings
    //    d'autorisation IdP->rôle EN SILENCE. C'est ce que corrige ce bloc.
    dst.execute_batch(crate::state::PG_SCHEMA)?;
    crate::scim::ensure_pg_schema(dst);
    crate::sso::ensure_pg_schema(dst);
    crate::rbac::ensure_pg_schema(dst);

    // 2) NO SILENT SKIP : toute table source ÉNUMÉRÉE encore ABSENTE de la cible après (1) (une table
    //    inconnue que ni `PG_SCHEMA` ni les modules enterprise ne créent) -> HARD-FAIL en la NOMMANT. On ne
    //    DEVINE JAMAIS un DDL (option sûre : plutôt échouer clairement que copier une table à la structure
    //    incertaine). Zéro écriture de données à ce stade -> rien à rollback, aucun checkpoint émis.
    let dest_tables = enumerate_dest_tables(dst)?;
    let missing: Vec<String> = tables.iter().filter(|t| !dest_tables.contains(*t)).cloned().collect();
    if !missing.is_empty() {
        return Err(StoreError::Backend(format!(
            "cible dépourvue de {} table(s) source (aucun schéma connu — base ou enterprise — ne les crée ; \
             migration REFUSÉE plutôt qu'un skip silencieux ou un DDL deviné) : {}",
            missing.len(),
            missing.join(", ")
        )));
    }

    // 3) GOUVERNANCE : si une table cible contient déjà des données -> refus sauf `--force`.
    let mut existing = 0i64;
    for t in &tables {
        existing += count_rows(dst, t)?;
    }
    if existing > 0 && !force {
        return Ok(None);
    }

    // 4) Copie atomique : TRUNCATE (si --force) -> copie ordre FK -> recale IDENTITY -> vérif -> commit.
    let report = dst.with_tx(|tx| {
        if force && existing > 0 {
            // TRUNCATE ... RESTART IDENTITY CASCADE remet les tables cibles à zéro ET réinitialise leurs
            // séquences ; les ids explicites recopiés puis `advance_pg_identity_sequences_all` fixent la suite.
            let all = tables.join(", ");
            tx.execute_batch(&format!("TRUNCATE {all} RESTART IDENTITY CASCADE"))?;
        }
        // Copie CHAQUE table énumérée (ensemble autoritatif de `sqlite_master`, PAS un sous-ensemble codé en
        // dur) — chaque table copiée est ensuite vérifiée source==cible ci-dessous.
        let mut counts = Vec::with_capacity(tables.len());
        let mut total = 0i64;
        for t in &tables {
            let copied = copy_table(src, tx, t)?;
            total += copied;
            counts.push(MigTableCount { table: t.clone(), source: copied, dest: 0 });
        }
        // Recale TOUTES les séquences IDENTITY (id + seq + scim_*/sso_* éventuels) — après insertion des
        // ids explicites, sinon le 1er INSERT-sans-id post-migration collisionne. Dans la transaction (setval
        // est transactionnel en PG) : rollback -> séquences aussi restaurées.
        let identity = crate::state::advance_pg_identity_sequences_all(tx.store())?;
        // VÉRIFICATION : source vs cible, table par table (comptes relus DANS la transaction).
        let mut mismatch = false;
        for c in counts.iter_mut() {
            let dest = count_rows(tx.store(), &c.table)?;
            c.dest = dest;
            let src_n = count_rows(src, &c.table)?;
            c.source = src_n;
            if dest != src_n {
                mismatch = true;
            }
        }
        if mismatch {
            // Échec DUR -> `Err` déclenche le ROLLBACK de `with_tx` : la cible reste intacte (jamais de
            // migration partielle silencieuse). Le message liste les tables discordantes.
            let detail: Vec<String> = counts
                .iter()
                .filter(|c| c.source != c.dest)
                .map(|c| format!("{}(src={}, dst={})", c.table, c.source, c.dest))
                .collect();
            return Err(StoreError::Backend(format!("row-count mismatch: {}", detail.join(", "))));
        }
        Ok(MigrationReport { counts, identity, total_rows: total })
    })?;
    Ok(Some(report))
}

/// Imprime le tableau de vérification des comptes (table | source | cible | ok).
#[cfg(feature = "store-postgres")]
fn print_migration_counts(report: &MigrationReport) {
    let columns = vec!["table".to_string(), "source".to_string(), "dest".to_string(), "match".to_string()];
    let rows: Vec<Vec<String>> = report
        .counts
        .iter()
        .map(|c| {
            vec![
                c.table.clone(),
                c.source.to_string(),
                c.dest.to_string(),
                if c.source == c.dest { "OK".to_string() } else { "MISMATCH".to_string() },
            ]
        })
        .collect();
    print_table(&columns, &rows);
}

/// `forge-console migrate-store --to <postgres-url> [--from <sqlite-path>] [--dry-run] [--force]
///   [--ledger <path>]` — migrateur gouverné SQLite -> Postgres (feature `store-postgres`).
/// Codes de sortie : 0 = OK ; 1 = refus de gouvernance (cible non vide sans `--force`) OU comptes
/// discordants (rollback) ; 2 = usage / connexion / schéma.
#[cfg(feature = "store-postgres")]
pub(crate) fn run_migrate_store_cli(args: &[String]) -> i32 {
    let to_url = match cli_opt(args, "to").filter(|s| !s.is_empty()) {
        Some(u) => u,
        None => {
            eprintln!("usage: forge-console migrate-store --to <postgres-url> [--from <sqlite-path>] [--dry-run] [--force] [--ledger <path>]");
            eprintln!("  Migre le backend SQLite (source) vers Postgres (cible), ids + typage préservés,");
            eprintln!("  ordre FK, recalage IDENTITY, vérif des comptes, checkpoint ledger signé. `--dry-run`");
            eprintln!("  n'écrit RIEN. Sans `--force`, refuse d'écraser une cible non vide (idempotence).");
            return 2;
        }
    };
    let from = cli_opt(args, "from").filter(|s| !s.is_empty()).unwrap_or_else(cli_db_path);
    let dry_run = cli_flag(args, "dry-run");
    let force = cli_flag(args, "force");
    let ledger_path = cli_opt(args, "ledger")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("FORGE_CONSOLE_LEDGER").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "engagement.jsonl".to_string());

    let dest_redacted = redact_pg_url(&to_url);
    eprintln!("[forge-console] migrate-store: source SQLite='{from}' -> cible PG='{dest_redacted}'{}{}",
        if dry_run { "  [DRY-RUN]" } else { "" },
        if force { "  [--force]" } else { "" });

    // La source SQLite est ouverte en READ-ONLY (défense en profondeur : la migration ne mute JAMAIS la
    // source). Le client PG et la connexion source vivent sur le MÊME thread hors-runtime (`with_pg_store`)
    // — requis par le client postgres synchrone (connect + Drop pilotent leur propre `block_on`).
    let outcome: Result<crate::store::StoreResult<Option<MigrationReport>>, String> =
        with_pg_store(&to_url, |dst| {
            let src_conn = match crate::cli::cli_open_ro(&from) {
                Some(c) => c,
                None => return Err(crate::store::StoreError::Backend(format!("source SQLite illisible: {from}"))),
            };
            let src_mutex = std::sync::Mutex::new(src_conn);
            let src = crate::store::Store::sqlite(src_mutex.lock().unwrap_or_else(|e| e.into_inner()));
            migrate_store_core(&src, dst, dry_run, force)
        });

    let report = match outcome {
        Ok(Ok(Some(r))) => r,
        Ok(Ok(None)) => {
            eprintln!("[forge-console] migrate-store: REFUSÉ — la cible contient déjà des données.");
            eprintln!("  Relance avec --force pour ÉCRASER (TRUNCATE ... RESTART IDENTITY des tables cibles),");
            eprintln!("  ou --dry-run pour inspecter sans écrire. Aucune donnée n'a été touchée.");
            return 1;
        }
        Ok(Err(e)) => {
            // Inclut le rollback sur comptes discordants (message "row-count mismatch: ...").
            eprintln!("[forge-console] migrate-store: ÉCHEC — {e}");
            let es = e.to_string();
            return if es.contains("row-count mismatch") { 1 } else { 2 };
        }
        Err(e) => {
            eprintln!("[forge-console] migrate-store: {e}");
            return 2;
        }
    };

    // Ordre RÉEL des tables migrées (ensemble énuméré dynamiquement, en ordre FK) — dérivé du rapport, PAS
    // d'une constante : c'est la VRAIE liste reprise (base + enterprise), servie au rapport ET au checkpoint.
    let migrated_order: Vec<String> = report.counts.iter().map(|c| c.table.clone()).collect();

    // Rapport lisible : ordre FK + tableau de comptes + recalage des séquences.
    println!("[forge-console] migrate-store: ordre FK (parents -> enfants) :");
    println!("  {}", migrated_order.join(" -> "));
    if dry_run {
        println!("[forge-console] migrate-store [DRY-RUN] : lignes QUI SERAIENT copiées (source) vs cible actuelle :");
    } else {
        println!("[forge-console] migrate-store : vérification des comptes (source == cible) :");
    }
    print_migration_counts(&report);
    if !dry_run && !report.identity.is_empty() {
        println!("[forge-console] migrate-store : séquences IDENTITY recalées (table.colonne -> valeur) :");
        for (t, c, v) in &report.identity {
            println!("  {t}.{c} -> {v}");
        }
    }

    // CHECKPOINT LEDGER SIGNÉ (chaîné SHA-256, alg `sha256-console`, sig chaîne — comme tout acte console ;
    // un sig Ed25519 sur un kind `console.*` est INTERDIT par la garde alg<->kind, cf. compliance.rs). La
    // cible est RÉDIGÉE (aucun credential dans l'audit). Émis aussi en dry-run (trace qu'un dry-run a eu lieu).
    let per_table: Vec<Value> = report
        .counts
        .iter()
        .map(|c| serde_json::json!({"table": c.table, "source": c.source, "dest": c.dest}))
        .collect();
    let detail = serde_json::json!({
        "source": from,
        "dest": dest_redacted,
        "dry_run": dry_run,
        "forced": force,
        "total_rows": report.total_rows,
        "fk_order": migrated_order,
        "tables": per_table,
        "ts_unix": crate::state::chrono_now_compact(),
    });
    match crate::dbmigrate::ledger_append_standalone(&ledger_path, "console.store.migrate", &detail) {
        Ok(hash) => {
            println!("[forge-console] migrate-store : checkpoint ledger '{ledger_path}' (console.store.migrate) signé, hash={hash}");
        }
        Err(e) => {
            eprintln!("[forge-console] migrate-store: AVERTISSEMENT — écriture du checkpoint ledger échouée: {e}");
        }
    }

    if dry_run {
        println!("[forge-console] migrate-store [DRY-RUN] terminé — AUCUNE écriture dans la cible.");
    } else {
        println!("[forge-console] migrate-store terminé — {} ligne(s) migrée(s), comptes vérifiés.", report.total_rows);
    }
    0
}

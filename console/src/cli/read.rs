// SPDX-License-Identifier: AGPL-3.0-or-later
//! `forge findings|roe|coverage|query` — parité LECTURE CLI (PURE MOVE depuis cli.rs).
use crate::*;
use rusqlite::Connection;
use serde_json::Value;

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
                    eprintln!("usage: forge query --soql '<pipeline soql>' [--json]");
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
                    eprintln!("[forge] query: SOQL invalide: {e}");
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
                        eprintln!("usage: forge query --soql '<pipeline soql>' [--json]");
                        return 2;
                    }
                };
                // MÊME moteur SoQL read-only que l'API, routé sur PG (transaction READ ONLY sur ce store).
                // Schéma community nu (`Schema::forge()`) — pas d'App/tenant en CLI, comme le chemin SQLite.
                match crate::exec_soql_time_pg_store(store, &soql, 0, 0, &guatx_core::soql::Schema::forge()) {
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
                        eprintln!("[forge] query: SOQL invalide: {e}");
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
            eprintln!("[forge] lecture CLI (Postgres): {e}");
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
            eprintln!("[forge] lecture CLI: requête invalide: {e}");
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

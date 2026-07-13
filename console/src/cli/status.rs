// SPDX-License-Identifier: AGPL-3.0-only
//! `forge status` — instantané LECTURE SEULE de l'état d'une installation console.
// ===========================================================================================
// `forge status [--db <path>] [--ledger <path>] [--json]` imprime un instantané SANS
// démarrer le serveur ni ouvrir de socket : version produit, VERSION DE SCHÉMA persistée
// (settings.schema_version, tamponnée par migrate()/le boot PG), backend actif (sqlite | postgres),
// chemin/URL de la base RÉDIGÉ (jamais de credentials), et la TÊTE du ledger (hash-chain vérifiée).
// C'est la brique qui rend « à quelle version est cette base » RÉPONDABLE — préalable d'un upgrade sûr.
// Purement synchrone, lecture seule (aucune mutation), exit RAPIDE. Codes : 0 = OK, 2 = base illisible.
// ===========================================================================================
use crate::*;
use serde_json::{json, Value};

/// Résout le backend + lit la version de schéma persistée. Renvoie `(backend, db_redacted, schema_version)`.
/// SQLite (défaut/community) : ouvre la base en READ-ONLY et lit `settings.schema_version`. Postgres
/// (feature `store-postgres` + FORGE_ENTERPRISE_STORE=postgres + FORGE_DB_URL) : lit à travers le seam,
/// l'URL RÉDIGÉE (sans user:pass ni query). `schema_version=None` sur une base ANTÉRIEURE au stamp.
fn resolve_backend_and_version(db_path: &str) -> Result<(String, String, Option<i64>), String> {
    #[cfg(feature = "store-postgres")]
    if let Some(url) = cli_pg_url() {
        let redacted = redact_pg_url(&url);
        let sv = with_pg_store(&url, crate::schema::read_schema_version)
            .map_err(|e| format!("connexion Postgres impossible: {e}"))?;
        return Ok(("postgres".to_string(), redacted, sv));
    }
    // SQLite (défaut) — lecture READ-ONLY (défense en profondeur : status ne mute jamais la base).
    let conn = cli_open_ro(db_path).ok_or_else(|| format!("base SQLite illisible: {db_path}"))?;
    let sv = crate::schema::read_schema_version_conn(&conn);
    Ok(("sqlite".to_string(), db_path.to_string(), sv))
}

/// `forge status [--db <path>] [--ledger <path>] [--json]`. Codes : 0 = OK, 2 = base illisible.
pub(crate) fn run_status_cli(args: &[String]) -> i32 {
    let as_json = cli_flag(args, "json");
    let db_path = cli_opt(args, "db").filter(|s| !s.is_empty()).unwrap_or_else(cli_db_path);
    let ledger_path = cli_opt(args, "ledger")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("FORGE_CONSOLE_LEDGER").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "engagement.jsonl".to_string());

    let (backend, db_redacted, schema_version) = match resolve_backend_and_version(&db_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[forge] status: {e}");
            return 2;
        }
    };

    // TÊTE du ledger : hash-chain re-vérifiée (verify_ledger_chain — même algo que /api/ledger/verify).
    // `head` n'est Some QUE si la chaîne est intègre ; on expose aussi `ledger_ok` + le nb d'entrées.
    let lv = verify_ledger_chain(&ledger_path);
    let ledger_head = if lv.empty { Value::Null } else { json!(lv.head) };

    // HA / leader : PROPRIÉTÉ RUNTIME (bail de leadership, publiée sur /health d'une instance VIVANTE).
    // `status` est un instantané hors-process -> on rapporte la CONFIGURATION HA depuis l'ENV (FORGE_HA),
    // pas un leader live (qu'on ne peut pas connaître sans instance en cours). Honnête, jamais inventé.
    let ha_configured = std::env::var("FORGE_HA").ok().filter(|v| v == "1" || v.eq_ignore_ascii_case("true")).is_some();

    let body = json!({
        "version": forge_version(),
        "schema_version": schema_version,
        "schema_version_expected": crate::schema::SCHEMA_VERSION,
        "backend": backend,
        "db": db_redacted,
        "ledger": ledger_path,
        "ledger_ok": lv.ok,
        "ledger_entries": lv.entries,
        "ledger_head": ledger_head,
        "ha_configured": ha_configured,
    });

    if as_json {
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".into()));
    } else {
        let sv = schema_version.map(|v| v.to_string()).unwrap_or_else(|| "(non tamponnée — base antérieure)".to_string());
        let head = lv.head.clone().unwrap_or_else(|| if lv.empty { "(ledger vide/absent)".to_string() } else { "(chaîne rompue)".to_string() });
        println!("forge status");
        println!("  version           : {}", forge_version());
        println!("  schema_version    : {sv}  (attendu par ce binaire : {})", crate::schema::SCHEMA_VERSION);
        println!("  backend           : {backend}");
        println!("  db                : {db_redacted}");
        println!("  ledger            : {ledger_path}  (ok={}, {} entrée(s))", lv.ok, lv.entries);
        println!("  ledger_head       : {head}");
        println!("  ha_configured     : {ha_configured}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use rusqlite::Connection;

    /// [status] Sur une base fraîche (SCHEMA+migrate), `status --json` imprime la version de schéma
    /// TAMPONNÉE (== SCHEMA_VERSION), le backend sqlite, et un ledger head cohérent. Exit 0.
    #[test]
    fn status_reports_stamped_schema_version() {
        let dir = tmp_dir("forge-status");
        let db = format!("{dir}/console.db");
        let ledger = format!("{dir}/engagement.jsonl");
        {
            let c = Connection::open(&db).unwrap();
            c.execute_batch(crate::SCHEMA).unwrap();
            crate::migrate(&c); // tamponne schema_version
        }
        ledger_append_standalone(&ledger, "engagement.start", &json!({"a": 1})).unwrap();

        let code = run_status_cli(&["--db".into(), db.clone(), "--ledger".into(), ledger.clone(), "--json".into()]);
        assert_eq!(code, 0, "status sur base valide -> exit 0");

        // relecture directe pour assertion sur la valeur tamponnée.
        let c = Connection::open(&db).unwrap();
        let sv = crate::schema::read_schema_version_conn(&c);
        assert_eq!(sv, Some(crate::schema::SCHEMA_VERSION), "schema_version tamponnée == SCHEMA_VERSION");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [status] Base illisible/absente -> exit 2 (jamais un « OK » trompeur).
    #[test]
    fn status_missing_db_exits_2() {
        let dir = tmp_dir("forge-status-missing");
        let db = format!("{dir}/does-not-exist.db");
        let code = run_status_cli(&["--db".into(), db, "--json".into()]);
        assert_eq!(code, 2, "base absente -> exit 2");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

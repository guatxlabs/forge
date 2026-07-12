// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SOUS-SYSTÈME CLI (parité LECTURE + provisioning + seed-demo + ledger verify).
//! Bloc déplacé depuis main.rs (PURE MOVE, Wave 2), puis éclaté en sous-modules cohérents (PURE MOVE :
//! corps identiques, seule la localisation + la visibilité + les chemins d'import changent). Ces
//! sous-commandes sont dispatchées par main() (hors chemin HTTP) : `useradd`, `seed-demo`,
//! `findings|roe|coverage|query`, `ledger verify`, `migrate-store` (feature `store-postgres`).
//! Réutilise App + les helpers de la racine de crate (validate_login/hash_pw/upsert_user/SCHEMA/
//! migrate/gs/extract_cwe/cvss_base_for_severity/exec_soql/cell/verify_ledger_chain/…) via `use
//! crate::*`, et est re-exporté à la racine par `pub(crate) use crate::cli::*` — les tests inline de
//! main.rs (`super::*`) et le dispatch de main() résolvent donc ces fonctions INCHANGÉS. Ce fichier
//! (cli/mod.rs) porte les HELPERS PARTAGÉS (table/objets/args/pg-store) ; les sous-commandes vivent
//! dans les sous-modules ci-dessous et sont re-exportées ICI pour que `crate::cli::*` reste stable.
//! Les sous-modules résolvent les helpers de la racine de crate ET ces helpers partagés via `use
//! crate::*` (grâce au re-export racine `pub(crate) use crate::cli::*`).
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

mod ledger;
mod read;
mod seed;
mod status;
mod upgrade;
mod user;
#[cfg(feature = "store-postgres")]
mod migrate_store;

pub(crate) use ledger::*;
pub(crate) use read::*;
pub(crate) use seed::*;
pub(crate) use status::*;
pub(crate) use upgrade::*;
pub(crate) use user::*;
#[cfg(feature = "store-postgres")]
pub(crate) use migrate_store::*;

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
pub(crate) fn cli_pg_url() -> Option<String> {
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
pub(crate) fn with_pg_store<T: Send>(url: &str, f: impl FnOnce(&crate::store::Store) -> T + Send) -> Result<T, String> {
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

/// Rédige les credentials d'une URL Postgres pour l'audit (le ledger ne DOIT jamais contenir de secret) :
/// `postgres://user:pass@host:5432/db?sslmode=require` -> `postgres://host:5432/db`. Supprime le userinfo
/// (`user:pass@`) et la query-string. Best-effort : si l'URL n'a pas la forme attendue on renvoie au
/// minimum le schéma + hôte, jamais le mot de passe.
#[cfg(feature = "store-postgres")]
pub(crate) fn redact_pg_url(url: &str) -> String {
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

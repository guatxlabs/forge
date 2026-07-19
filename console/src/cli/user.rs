// SPDX-License-Identifier: AGPL-3.0-or-later
//! `forge useradd` — provisioning d'un compte individuel (PURE MOVE depuis cli.rs).
use crate::*;
use rusqlite::Connection;

/// `forge useradd <login> <role> [--pass <pw>]` — provisionne un compte individuel.
/// Le mot de passe est lu sur STDIN (recommandé : pas de fuite argv) ; `--pass` le fournit en argv
/// (scripting). Calcule le hash argon2id et l'écrit dans `users` (upsert par login). Ouvre la base en
/// ÉCRITURE (mêmes PRAGMA que le boot) et garantit le schéma (execute_batch) avant l'insertion — la
/// sous-commande peut donc créer le 1er compte sur une base neuve. Codes : 0 OK, 2 erreur d'usage/IO.
pub(crate) fn run_useradd_cli(args: &[String]) -> i32 {
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let (login, role) = match (positional.first(), positional.get(1)) {
        (Some(l), Some(r)) => (l.as_str(), r.as_str()),
        _ => {
            eprintln!("usage: forge useradd <login> <role> [--pass <password>]   (role: viewer|operator|admin)");
            return 2;
        }
    };
    if let Err(e) = validate_login(login) {
        eprintln!("[forge] useradd: login invalide: {e}");
        return 2;
    }
    if let Err(e) = validate_role(role) {
        eprintln!("[forge] useradd: {e}");
        return 2;
    }
    // mot de passe : --pass (argv, scripting) sinon lecture sur STDIN (pas de fuite via ps).
    let pw = match cli_opt(args, "pass") {
        Some(p) => p,
        None => {
            eprintln!("[forge] useradd: entre le mot de passe (STDIN) :");
            use std::io::Read;
            let mut s = String::new();
            if std::io::stdin().read_to_string(&mut s).is_err() {
                eprintln!("[forge] useradd: lecture STDIN impossible");
                return 2;
            }
            s.trim_end_matches(['\n', '\r']).to_string()
        }
    };
    if pw.is_empty() {
        eprintln!("[forge] useradd: mot de passe vide refusé");
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
            eprintln!("[forge] useradd: ouverture de '{db_path}' impossible: {e}");
            return 2;
        }
    };
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    // garantit le schéma (table users incluse) — permet de créer le 1er compte sur une base neuve.
    if conn.execute_batch(SCHEMA).is_err() {
        eprintln!("[forge] useradd: initialisation du schéma impossible");
        return 2;
    }
    let hash = hash_pw(&pw);
    match upsert_user(&conn, login, role, &hash) {
        Ok(role) => {
            println!("[forge] compte '{login}' (role={role}) provisionné dans {db_path}");
            0
        }
        Err(e) => {
            eprintln!("[forge] useradd: {e}");
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
            .execute_batch(crate::schema::PG_SCHEMA)
            .map_err(|e| format!("initialisation du schéma Postgres impossible: {e}"))?;
        upsert_user_store(store, login, role, &hash)
    });
    match outcome {
        Ok(Ok(role)) => {
            println!("[forge] compte '{login}' (role={role}) provisionné dans Postgres");
            0
        }
        Ok(Err(e)) | Err(e) => {
            eprintln!("[forge] useradd: {e}");
            2
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! `forge ledger verify` — vérif hash-chaining lecture-seule (PURE MOVE depuis cli.rs).
use crate::*;

/// Sous-commande LECTURE SEULE, NON INTERACTIVE et RAPIDE : `forge ledger verify [--ledger <path>]
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
            eprintln!("usage: forge ledger verify [--ledger <path>] [--json]");
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::time::Duration;

    /// [ledger verify CLI] `run_ledger_cli(["verify","--ledger",path])` sur un ledger VALIDE renvoie 0,
    /// sur un ledger ALTÉRÉ renvoie 1, sur un ledger ABSENT renvoie 1, et une sous-commande absente/
    /// inconnue renvoie 2. Chaque appel se termine RAPIDEMENT (garde-fou anti-hang : < 10s, alors que
    /// le bug bootait le serveur ad vitam). Aucune I/O réseau, aucune base ouverte, aucun STDIN lu.
    #[test]
    fn ledger_verify_cli_fast_valid_tampered_absent() {
        use std::time::Instant;
        let dir = tmp_dir("forge-ledger-verify-cli");
        let path = format!("{dir}/engagement.jsonl");
        // ledger VALIDE : 2 entrées chaînées (même algo que le boot -> verify_ledger_chain OK).
        ledger_append_standalone(&path, "engagement.start", &json!({"marker": "ORIGINAL", "n": 1})).unwrap();
        ledger_append_standalone(&path, "console.detection.test", &json!({"reachable": false})).unwrap();

        // (1) VALIDE -> 0, et RAPIDE (pas de démarrage serveur : le test lui-même prouve l'absence de hang).
        let t0 = Instant::now();
        let code_ok = run_ledger_cli(&["verify".into(), "--ledger".into(), path.clone()]);
        let elapsed = t0.elapsed();
        assert_eq!(code_ok, 0, "ledger valide -> exit 0");
        assert!(elapsed < Duration::from_secs(10), "ledger verify doit être quasi-instantané (anti-hang), pris {elapsed:?}");

        // (1b) --json : sortie parsable, contrat historique (ok:true).
        let code_json = run_ledger_cli(&["verify".into(), "--ledger".into(), path.clone(), "--json".into()]);
        assert_eq!(code_json, 0, "verify --json ledger valide -> 0");

        // (2) ALTÉRÉ : on modifie le detail de la 1re entrée SANS recalculer son hash -> chaîne rompue.
        let tampered = std::fs::read_to_string(&path).unwrap().replace("ORIGINAL", "TAMPERED");
        std::fs::write(&path, tampered).unwrap();
        let code_bad = run_ledger_cli(&["verify".into(), "--ledger".into(), path.clone()]);
        assert_eq!(code_bad, 1, "ledger altéré -> exit 1 (rupture détectée)");

        // (3) ABSENT -> 1 (on ne peut pas vérifier un ledger manquant ; jamais un « OK » trompeur).
        let missing = format!("{dir}/does-not-exist.jsonl");
        assert_eq!(run_ledger_cli(&["verify".into(), "--ledger".into(), missing]), 1, "ledger absent -> exit 1");

        // (4) sous-commande absente/inconnue -> 2 (usage), JAMAIS de repli sur le démarrage serveur.
        assert_eq!(run_ledger_cli(&[]), 2, "aucune sous-commande -> exit 2 (usage)");
        assert_eq!(run_ledger_cli(&["frobnicate".into()]), 2, "sous-commande inconnue -> exit 2 (usage)");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

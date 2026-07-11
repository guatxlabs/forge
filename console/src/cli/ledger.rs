// SPDX-License-Identifier: AGPL-3.0-only
//! `forge-console ledger verify` — vérif hash-chaining lecture-seule (PURE MOVE depuis cli.rs).
use crate::*;

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

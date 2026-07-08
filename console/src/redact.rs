// SPDX-License-Identifier: AGPL-3.0-only
//! Secret redaction — the ONE copy of the two redactors previously duplicated in `reports.rs`
//! (`redact_secrets`, string scan + PEM-block stripping) and `compliance.rs` (`redact_evidence`,
//! JSON-key redaction). The shared engine is PARAMETERISED by the CALLER's key-set/config: each
//! public entry point supplies its OWN original list (and recursion semantics), so the output is
//! BYTE-IDENTICAL to the pre-consolidation behaviour of both callers — no single hardcoded union.
//! No new deps (no regex): PEM-block strip + word scan / JSON walk.

use serde_json::{json, Value};

/// The replacement marker (both redactors emit this exact token).
pub(crate) const REDACT: &str = "[REDACTED]";

// -------------------------------------------------------------------------------------------------
//  CALLER KEY-SETS — each caller keeps its EXACT original list. NOT merged into a union.
// -------------------------------------------------------------------------------------------------

/// reports.rs original sensitive keys, NORMALISED (alphanumeric lowercase) — compared against a
/// normalised key in the string redactor. Verbatim pre-consolidation list (does NOT include the
/// `passphrase` / `credential` keys the compliance module used — those never applied here).
const REPORTS_SENSITIVE_KEYS: &[&str] = &[
    "password", "passwd", "pwd", "secret", "secretkey", "clientsecret", "apikey", "accesskey",
    "accesstoken", "token", "authorization", "auth", "xapikey", "cookie", "setcookie", "privatekey",
    "sessiontoken", "session",
];

/// compliance.rs original exact JSON-key list — compared by lowercase FULL name in the JSON
/// redactor. Verbatim pre-consolidation list of 10 keys (does NOT include reports' `auth`/`session`/
/// … keys, so a sub-object keyed `auth`/`session` is RECURSED into, not wholesale-replaced).
const COMPLIANCE_EXACT_KEYS: &[&str] = &[
    "passphrase", "password", "credential", "secret", "token", "apikey", "api_key", "cookie",
    "authorization", "private_key",
];

// -------------------------------------------------------------------------------------------------
//  STRING REDACTOR (used by reports.rs). Keys are matched after NORMALISATION to alphanumeric
//  lowercase, against the CALLER-SUPPLIED key-set.
// -------------------------------------------------------------------------------------------------

/// Rédige les blocs PEM de clef privée (`-----BEGIN … PRIVATE KEY----- … -----END … PRIVATE KEY-----`).
fn redact_private_key_blocks(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(b) = out.find("-----BEGIN ") {
        // le bloc doit contenir un marqueur PRIVATE KEY (sinon ce n'est pas une clef privée).
        if out[b..].find("PRIVATE KEY-----").is_none() {
            break;
        }
        let Some(e_rel) = out[b..].find("-----END ") else { break };
        let after_end = b + e_rel;
        let Some(ke_rel) = out[after_end..].find("PRIVATE KEY-----") else { break };
        let end = after_end + ke_rel + "PRIVATE KEY-----".len();
        out.replace_range(b..end, REDACT);
    }
    out
}

/// Vrai si `raw` (jeton isolé) a la FORME d'un secret connu (préfixe/structure). Bornes de longueur
/// pour éviter les faux positifs sur du texte courant.
fn is_secret_token(raw: &str) -> bool {
    let w = raw.trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | ',' | ';' | '.'));
    // AWS access key id : AKIA/ASIA + 16 [A-Z0-9], longueur 20.
    if (w.starts_with("AKIA") || w.starts_with("ASIA"))
        && w.len() == 20
        && w[4..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return true;
    }
    // JWT : trois segments base64url séparés par des points, 1er commençant par eyJ.
    if w.starts_with("eyJ") {
        let parts: Vec<&str> = w.split('.').collect();
        if parts.len() == 3
            && parts.iter().all(|p| p.len() >= 4 && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        {
            return true;
        }
    }
    for pre in [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
        "AIza", "sk-",
    ] {
        if w.starts_with(pre) && w.len() >= pre.len() + 8 {
            return true;
        }
    }
    false
}

/// Rédige UN mot. `sensitive_keys` = le key-set du caller. `prev_bearer` = le mot précédent était le
/// mot-clef « Bearer » (ce jeton est alors le token à masquer). Renvoie `(mot rédigé, ce mot est-il le
/// mot-clef Bearer ?)`.
fn redact_word(sensitive_keys: &[&str], prev_bearer: bool, word: &str) -> (String, bool) {
    if prev_bearer {
        return (REDACT.to_string(), false);
    }
    let core_lower = word
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_ascii_lowercase();
    let is_bearer_kw = core_lower == "bearer";
    // paire clef=valeur / clef:valeur.
    if let Some(pos) = word.find(['=', ':']) {
        let (k, _) = word.split_at(pos);
        let sep = &word[pos..pos + 1];
        let val = &word[pos + 1..];
        let knorm: String = k
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if !val.is_empty() && (sensitive_keys.contains(&knorm.as_str()) || is_secret_token(val)) {
            return (format!("{k}{sep}{REDACT}"), is_bearer_kw);
        }
    }
    if is_secret_token(word) {
        return (REDACT.to_string(), is_bearer_kw);
    }
    (word.to_string(), is_bearer_kw)
}

/// Engine: neutralise les secrets d'une chaîne (blocs PEM + scan mot-à-mot) avec le key-set fourni.
/// Préserve les blancs (formatage).
fn redact_secrets_with(input: &str, sensitive_keys: &[&str]) -> String {
    let s = redact_private_key_blocks(input);
    let mut out = String::with_capacity(s.len());
    let mut word = String::new();
    let mut prev_bearer = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !word.is_empty() {
                let (red, is_b) = redact_word(sensitive_keys, prev_bearer, &word);
                out.push_str(&red);
                prev_bearer = is_b;
                word.clear();
            } else {
                // un blanc n'annule pas le drapeau bearer seulement s'il n'y a pas eu de mot entre-temps
            }
            out.push(ch);
        } else {
            word.push(ch);
        }
    }
    if !word.is_empty() {
        let (red, _) = redact_word(sensitive_keys, prev_bearer, &word);
        out.push_str(&red);
    }
    out
}

/// Neutralise les secrets d'une chaîne pour reports.rs — utilise le key-set ORIGINAL de reports.
pub(crate) fn redact_secrets(input: &str) -> String {
    redact_secrets_with(input, REPORTS_SENSITIVE_KEYS)
}

// -------------------------------------------------------------------------------------------------
//  JSON REDACTOR (used by compliance.rs). Keys are matched by lowercase full name against the
//  CALLER-SUPPLIED exact list + compliance's original suffix rules. Sub-objects whose KEY name is
//  not itself secret are RECURSED into (structural fidelity preserved for SOC2/ISO evidence).
// -------------------------------------------------------------------------------------------------

/// Is a JSON object key SECRET (its value must be redacted before export)? Deliberately PRECISE (not a
/// broad substring) so structural keys survive: e.g. `authorization_audit_trail` is NOT a secret, but a
/// `credential` / `client_secret` / `archive_key` value IS. A PUBLIC key (`pubkey`/`public_key`) is NEVER
/// redacted (it is the verification material, by design public). `exact` = the caller's exact key-set.
fn is_secret_key(exact: &[&str], key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    if exact.contains(&k.as_str()) {
        return true;
    }
    k.ends_with("_secret")
        || k.ends_with("_token")
        || k.ends_with("_password")
        || k.ends_with("_credential")
        || k.ends_with("_passphrase")
        || k.ends_with("_key")
        || k.ends_with("_apikey")
}

/// Engine: recursively REDACT any secret-named field's value with the caller's exact key-set. A
/// sub-object whose key is NOT secret is RECURSED into (only nested secret-keyed values are masked).
fn redact_evidence_with(v: &mut Value, exact: &[&str]) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if is_secret_key(exact, k) {
                    if !val.is_null() {
                        *val = json!("[REDACTED]");
                    }
                } else {
                    redact_evidence_with(val, exact);
                }
            }
        }
        Value::Array(a) => {
            for it in a.iter_mut() {
                redact_evidence_with(it, exact);
            }
        }
        _ => {}
    }
}

/// Recursively REDACT any secret-named field's value to `"[REDACTED]"` for compliance.rs (fail-safe:
/// run over the WHOLE assembled bundle right before it leaves the process, so even an unforeseen secret
/// in a ledger detail never leaks). Uses compliance's ORIGINAL exact key-set; public keys / structural
/// keys are preserved (and non-secret sub-objects are recursed into, not wholesale-replaced).
pub(crate) fn redact_evidence(v: &mut Value) {
    redact_evidence_with(v, COMPLIANCE_EXACT_KEYS);
}

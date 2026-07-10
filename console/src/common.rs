//! Helpers "feuilles" SANS ÉTAT extraits de main.rs (Wave-2 — PURE MOVE, corps/signatures inchangés).
//! Crypto/hash, échappement HTML, mapping CWE/CVSS, pagination, et les VALIDATEURS purs des entrées.
//! Zéro état App, zéro I/O. Ré-exportés au crate root (`pub(crate) use crate::common::*;`) pour que
//! `crate::<helper>` (appels cross-module) et `super::<helper>` (bloc de tests inline) résolvent
//! toujours à l'identique — aucun call site ni test n'a besoin d'être modifié.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub(crate) fn sha_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

/// Comparaison à TEMPS CONSTANT de deux empreintes (anti timing-oracle sur le bearer/token).
/// Les deux opérandes sont des hex de sha256 (longueur fixe 64) -> la divulgation de longueur est
/// inoffensive ; on protège contre la fuite octet-par-octet d'un `==` court-circuitant.
pub(crate) fn ct_eq_str(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub(crate) fn gen_token() -> String {
    // CSPRNG OS (getrandom) — le Result DOIT être propagé : un échec d'entropie laisserait un buffer
    // tous-zeros et produirait un token bearer PRÉVISIBLE (auth /api/ingest contournable). On panique
    // plutôt que de générer un secret faible (fail-closed sur l'entropie).
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("CSPRNG (getrandom) indisponible — refus de générer un token faible");
    hex(&b)
}

/// Extrait un identifiant CWE canonique ('CWE-639') d'une chaîne arbitraire ('cwe_639', 'CWE 639',
/// 'access_control.CWE-862'), ou '' si absent. Miroir Rust de `schema.extract_cwe` (rétro-compat :
/// permet de dériver le CWE depuis `category` quand le moteur ne fournit pas le champ `cwe` dédié).
pub(crate) fn extract_cwe(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if let Some(pos) = lower.find("cwe") {
        let rest = &lower[pos + 3..];
        // saute un éventuel séparateur (espace, '_', '-') puis lit les chiffres.
        let digits: String = rest
            .trim_start_matches([' ', '_', '-'])
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !digits.is_empty() {
            return format!("CWE-{digits}");
        }
    }
    String::new()
}

/// (vecteur, score) CVSS 3.1 de BASE pour une sévérité — repère grossier de priorisation, PAS un
/// calcul CVSS complet par finding. Miroir de `schema.CVSS_BASE_BY_SEVERITY`. ('', 0.0) si inconnue
/// (ex INFO) — fail-open : le rapport affiche alors '—' au lieu d'inventer un score.
pub(crate) fn cvss_base_for_severity(severity: &str) -> (&'static str, f64) {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        "HIGH" => ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        "MEDIUM" => ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 5.3),
        "LOW" => ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 3.1),
        _ => ("", 0.0),
    }
}

/// Échappement HTML minimal (texte -> contenu/attribut sûr) — empêche toute injection dans le
/// rapport HTML branded (les findings/notes proviennent du moteur ; on ne fait JAMAIS confiance au
/// contenu). Échappe & < > " '. Suffisant pour du texte inséré dans des nœuds/attributs HTML.
pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

// --- auth opérateur (argon2) : vérification/hachage de mot de passe (feuilles pures) ---

pub(crate) fn verify_pw(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .map(|ph| Argon2::default().verify_password(pw.as_bytes(), &ph).is_ok())
        .unwrap_or(false)
}

pub(crate) fn hash_pw(pw: &str) -> String {
    // Sel argon2id via CSPRNG OS (getrandom) — le Result DOIT être propagé : un échec d'entropie
    // laisserait un sel tous-zeros (CONSTANT) -> hash identique pour un même mot de passe sur toutes
    // les installs, cassant la résistance aux rainbow tables. On panique plutôt que de saler à zéro.
    let mut s = [0u8; 16];
    getrandom::getrandom(&mut s).expect("CSPRNG (getrandom) indisponible — refus de générer un sel faible");
    let salt = SaltString::encode_b64(&s).expect("salt");
    Argon2::default().hash_password(pw.as_bytes(), &salt).expect("hash").to_string()
}

/// Rôles valides — contrainte APPLICATIVE (la table stocke un TEXT libre). `viewer` lit, `operator`
/// arme le C2, `admin` = superset (peut aussi armer). Tout autre rôle est refusé à la création.
pub(crate) fn validate_role(r: &str) -> Result<String, String> {
    match r {
        "viewer" | "operator" | "admin" => Ok(r.to_string()),
        _ => Err("rôle invalide (attendu: viewer|operator|admin)".into()),
    }
}

/// Validation stricte d'un login : `[A-Za-z0-9._-]{1,64}`, non vide, pas de `-` en tête (parité avec
/// validate_campaign — anti confusion avec un flag CLI et entrées hostiles).
pub(crate) fn validate_login(s: &str) -> Result<String, String> {
    if s.is_empty() || s.len() > 64 {
        return Err("login vide ou > 64 caractères".into());
    }
    if s.starts_with('-') {
        return Err("login ne peut pas commencer par '-'".into());
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
        return Err("login : seuls [A-Za-z0-9._-] sont autorisés".into());
    }
    Ok(s.to_string())
}

/// Validation stricte d'un nom de campagne : `[A-Za-z0-9._-]{1,64}`, jamais vide, pas de `-` en
/// tête (anti confusion avec un flag CLI). Renvoie la valeur validée ou une erreur.
pub(crate) fn validate_campaign(s: &str) -> Result<String, String> {
    if s.is_empty() || s.len() > 64 {
        return Err("campaign vide ou > 64 caractères".into());
    }
    if s.starts_with('-') {
        return Err("campaign ne peut pas commencer par '-'".into());
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
        return Err("campaign : seuls [A-Za-z0-9._-] sont autorisés".into());
    }
    Ok(s.to_string())
}

/// Valide un hôte cible : hostname (labels alphanum + `-`, points) OU CIDR/IP (a.b.c.d[/n]).
/// REJETTE tout métacaractère shell, espace, NUL, et le `-` en tête (anti-injection d'option CLI).
/// Les cibles sont écrites dans un FICHIER puis passées par chemin — jamais concaténées à un shell —
/// mais on durcit malgré tout la forme pour refuser des entrées manifestement hostiles.
pub(crate) fn validate_host(s: &str) -> Result<String, String> {
    if s.is_empty() || s.len() > 253 {
        return Err("hôte vide ou trop long".into());
    }
    if s.starts_with('-') {
        return Err(format!("hôte '{s}' ne peut pas commencer par '-'"));
    }
    // rejet dur : NUL, espaces/whitespace, métacaractères shell et glob/redirections.
    const BAD: &[char] = &[
        ' ', '\t', '\n', '\r', '\0', ';', '&', '|', '`', '$', '(', ')', '<', '>',
        '{', '}', '[', ']', '!', '\\', '"', '\'', '*', '?', '~', '#', '@', '^', '%', '+', '=', ',',
    ];
    if let Some(c) = s.chars().find(|c| BAD.contains(c)) {
        return Err(format!("hôte '{s}' contient un caractère interdit: {c:?}"));
    }
    // CIDR / IP ?
    if let Some((ip, mask)) = s.split_once('/') {
        if ip.parse::<std::net::IpAddr>().is_ok() && mask.parse::<u8>().map(|m| m <= 128).unwrap_or(false) {
            return Ok(s.to_string());
        }
        return Err(format!("'{s}' : CIDR invalide"));
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return Ok(s.to_string());
    }
    // hostname : labels [A-Za-z0-9-] séparés par '.', label ni vide ni bordé de '-'.
    let valid_host = s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    if valid_host {
        Ok(s.to_string())
    } else {
        Err(format!("'{s}' n'est ni un hostname ni un CIDR valide"))
    }
}

/// LIMIT/OFFSET bornés et validés (anti-injection : on n'inline que des entiers parsés).
pub(crate) fn paginate(q: &HashMap<String, String>, default_limit: i64, max_limit: i64) -> (i64, i64) {
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(default_limit).clamp(1, max_limit);
    let offset = q.get("offset").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0).max(0);
    (limit, offset)
}

/// KEYSET (seek) pagination — CURSEUR OPAQUE pour les listes triées `ORDER BY id DESC`. Pour ces listes
/// `id` EST À LA FOIS la clé de tri ET un tiebreaker UNIQUE (clé primaire monotone) : encoder l'`id` de
/// la dernière ligne suffit — deux lignes ne peuvent jamais avoir la même clé, donc aucune ligne n'est
/// SAUTÉE ni DUPLIQUÉE à la frontière de page (contrairement à OFFSET sous inserts concurrents).
///
/// Le jeton est base64url-sans-padding de `f1:<id>` (versionné `f1` pour pouvoir évoluer sans casser les
/// vieux clients). Le contenu N'EST JAMAIS interpolé dans du SQL : le décodage rend un `i64` STRICTEMENT
/// parsé (même discipline que `paginate`) qui est ensuite LIÉ comme `Param::Int` via le seam Store —
/// zéro surface d'injection. `encode`/`decode` sont PURES (aucun état, aucune I/O).
pub(crate) fn encode_id_cursor(id: i64) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("f1:{id}"))
}

/// Décode un curseur keyset -> `Some(id)` bien formé, ou `None` FAIL-CLOSED sur tout jeton malformé
/// (base64 invalide, UTF-8 invalide, version inconnue, entier non parsable / hors `i64`). Le caller
/// traduit `None` en `400` — JAMAIS un scan de table complet ni une requête non bornée. Un `id` négatif
/// ou énorme reste un `i64` VALIDE (pas d'erreur) : lié en paramètre, il borne simplement le seek
/// (`id < ?`) et la requête garde son `LIMIT` — aucune pathologie.
pub(crate) fn decode_id_cursor(s: &str) -> Option<i64> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()?;
    let text = std::str::from_utf8(&raw).ok()?;
    let rest = text.strip_prefix("f1:")?;
    // Anti-injection : parse STRICT en i64. Un suffixe non numérique, vide, ou hors bornes -> None.
    rest.parse::<i64>().ok()
}

/// Nom de workflow / kind d'étape bien formé : `[A-Za-z0-9._-]{1,64}`, non vide, pas de `-` en tête
/// (parité avec validate_login/validate_campaign — anti-flag + entrées hostiles). Fonction PURE.
pub(crate) fn valid_workflow_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Formats d'import acceptés par l'endpoint (alias inclus ; le moteur Python les normalise). "auto"
/// déclenche l'auto-détection côté moteur. Grammaire FERMÉE (fail-closed) : un format inconnu -> 400.
pub(crate) fn valid_import_format(f: &str) -> bool {
    matches!(f,
        "auto" | "nmap" | "nuclei" | "burp" | "httpx" | "ffuf" | "hosts"
        | "generic-json" | "generic-csv" | "subfinder" | "amass" | "json" | "csv" | "generic"
        | "nmap-xml" | "burp-xml" | "hostlist" | "subdomains")
}

/// Nom de fichier SÛR pour l'attribution ledger/UI : basename seul, caractères ASCII sûrs, borné.
/// JAMAIS utilisé comme chemin (le contenu est écrit dans un fichier temp au nom fixe) — purement
/// informatif. Zéro traversée de chemin, zéro métacaractère, zéro NUL.
pub(crate) fn sanitize_filename(s: &str) -> String {
    let base = s.rsplit(['/', '\\']).next().unwrap_or("");
    base.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')).take(128).collect()
}

/// Valide une CHAÎNE issue des params par-module avant de l'écrire dans scope.json/targets.json.
/// Le moteur lit ces fichiers sans shell, mais on durcit malgré tout : refus des octets NUL et des
/// chaînes démesurées (anti-DoS d'écriture). Les métacaractères shell sont tolérés DANS les valeurs
/// (ex: une URL avec `?`, `&`) car elles ne sont jamais concaténées à un shell — seulement le NUL et
/// une borne de longueur sont durs. C'est cohérent avec validate_host (qui, lui, gardait des HÔTES).
pub(crate) fn validate_param_string(s: &str) -> Result<(), String> {
    if s.len() > 2048 {
        return Err("valeur de param trop longue (>2048)".into());
    }
    if s.contains('\0') {
        return Err("valeur de param contient un octet NUL".into());
    }
    Ok(())
}

/// Profondeur/validation récursive d'une valeur de param (anti-bombe JSON : profondeur bornée).
pub(crate) fn validate_param_value(v: &Value, depth: u32) -> Result<(), String> {
    if depth > 8 {
        return Err("params imbriqués trop profondément (>8)".into());
    }
    match v {
        Value::String(s) => validate_param_string(s),
        Value::Array(a) => {
            if a.len() > 256 {
                return Err("tableau de params trop long (>256)".into());
            }
            for x in a { validate_param_value(x, depth + 1)?; }
            Ok(())
        }
        Value::Object(m) => {
            if m.len() > 128 {
                return Err("objet de params trop large (>128 clés)".into());
            }
            for (k, x) in m {
                validate_param_string(k)?;
                validate_param_value(x, depth + 1)?;
            }
            Ok(())
        }
        // null / bool / number : inoffensifs.
        _ => Ok(()),
    }
}

/// Nom d'engagement bien formé : 1..80 caractères imprimables (lettres/chiffres/espace + `.`_-/()#`),
/// pas vide, pas de `-` en tête (anti confusion flag). Fonction PURE.
pub(crate) fn valid_engagement_name(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.chars().count() <= 80 && !t.starts_with('-')
        && t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-' | '/' | '(' | ')' | '#'))
}

/// Entrée de scope (motif in/out) bien formée : 1..253 caractères d'un jeu host/CIDR/wildcard
/// (`[A-Za-z0-9._*/:-]`), pas d'espace. Plus permissif que validate_host (autorise `*.` et CIDR) car
/// c'est un MOTIF de périmètre, pas une cible ; le scope-guard du moteur (host_in_scope_list) reste juge.
pub(crate) fn valid_scope_entry(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*' | '/' | ':'))
}

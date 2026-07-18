// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — OUTILS AJOUTÉS PAR L'UI (« add a tool from the web UI »), gouvernés.
//!
//! Un opérateur red-team déclare SON PROPRE outil CLI depuis l'UI — SANS éditer de fichier ni recompiler —
//! sous la MÊME gouvernance qu'un module natif. L'endpoint accepte un `ToolSpec` DÉCLARATIF (binaire +
//! `argv_template` TOKENISÉ no-shell + `flag_allowlist` + `params_schema` typé) ; il ne prend JAMAIS de
//! code Python arbitraire (voir la note « plugin upload » à la fin). Le spec validé est PERSISTÉ en JSON
//! (0600) dans un dossier SERVER-MANAGED (le dir `FORGE_TOOLSPECS`), puis le catalogue est RE-SONDÉ à chaud
//! (`populate_modules` re-spawn `forge modules --json` avec ce dir dans `FORGE_TOOLSPECS`) — l'outil
//! apparaît immédiatement dans la table `module` + `GET /api/modules` + le formulaire de Lancement (son
//! `params_schema` est rendu dynamiquement).
//!
//! GOUVERNANCE (jamais affaiblie — héritée du wrapper `ExternalToolModule` Python) :
//!   - ADMIN-ONLY (`check_admin`, fail-closed 403) + attribué + LEDGERISÉ (`console.tool.add`/`.remove`) ;
//!   - VALIDATION FAIL-CLOSED : `kind` bien formé dans le NAMESPACE `custom.*` (ne peut PAS surcharger un
//!     module natif) ; `argv_template` = LISTE de tokens (jamais une chaîne shell) ; seuls les placeholders
//!     `{target}`/`{target_host}`/`{target_url}`/`{param:NAME}`/`{args}` ; `{args}` EXIGE une
//!     `flag_allowlist` ; binaires interpréteurs (sh/bash/python/…) et drapeaux d'exfiltration
//!     (output-file/config-read/proxy) REFUSÉS ; caps de taille + rejet des octets NUL ;
//!   - ANTI-TRAVERSÉE : le fichier de spec est écrit dans le dir managé via un nom dérivé du `kind`
//!     assaini (aucun `/`, `\`, `..`) — impossible d'écrire hors du dir ;
//!   - À l'EXÉCUTION (côté Python) : scope-guard ROE fail-closed, argv FIXE no-shell, allowlist de
//!     drapeaux, statut CLAMPÉ à {tested, reported_by_tool} (JAMAIS `vulnerable`), plancher exploit
//!     (un outil `exploit=true` reste gaté par operator+arm+reason). Rien de tout cela n'est contournable
//!     depuis cet endpoint : il ne fait que DÉCLARER l'outil ; le moteur le gouverne à l'identique.
//!
//! Un outil dont le `binary`/`docker_image` est ABSENT du runtime dégrade en `available:false`/skipped
//! (il ne prétend jamais tourner). Rendre le binaire dispo : le baker dans une image custom, fournir un
//! script auto-contenu que l'argv invoque, sinon il est simplement skippé (offline-safe). En conteneur
//! sans socket docker, un outil `docker_image` ne peut pas tourner -> privilégier un binaire présent dans
//! l'image (cf. docs/TOOLS.md).
use crate::*;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Map, Value};

// --- Bornes fail-closed (anti-abus : un spec est de la DONNÉE de déclaration, jamais un blob) ---
const MAX_SPEC_BYTES: usize = 32 * 1024; // corps entrant sérialisé
const MAX_ARGV_TOKENS: usize = 64; // éléments de argv_template (groupes comptés à plat)
const MAX_TOKEN_LEN: usize = 512; // longueur d'un token / valeur
const MAX_FLAGS: usize = 128; // entrées de flag_allowlist
const MAX_PARAMS: usize = 64; // descripteurs de params_schema
const MAX_LABEL_LEN: usize = 400; // label / valeur textuelle de descripteur
const MAX_DESCR_LEN: usize = 4000; // description libre

// =================================================================================================
//  DOSSIER SERVER-MANAGED des ToolSpecs (source de vérité des outils ajoutés par l'UI)
// =================================================================================================
/// Dossier managé où les specs ajoutés par l'UI sont persistés : `FORGE_TOOLSPECS_DIR` si posé/non vide ;
/// sinon un `toolspecs/` sibling de la base (dossier de `FORGE_CONSOLE_DB`) ; sinon `./toolspecs`.
/// (Miroir de `default_blob_dir` — aucune valeur codée en dur ailleurs.)
pub(crate) fn managed_toolspec_dir() -> String {
    if let Ok(d) = std::env::var("FORGE_TOOLSPECS_DIR") {
        if !d.is_empty() {
            return d;
        }
    }
    let db = crate::cli_db_path();
    std::path::Path::new(&db)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.join("toolspecs").to_string_lossy().into_owned())
        .unwrap_or_else(|| "toolspecs".to_string())
}

/// Valeur `FORGE_TOOLSPECS` à passer au process de SONDE (`populate_modules`) : le dir managé, FUSIONNÉ
/// (séparateur de chemin) avec un éventuel `FORGE_TOOLSPECS` de l'opérateur (ses propres specs restent
/// chargés, mais NE SONT PAS marqués `user_added` — donc ni listés ni supprimables via /api/tools).
/// Crée le dir managé au passage (best-effort) pour que la sonde ne journalise pas « introuvable ».
pub(crate) fn probe_toolspecs_env() -> String {
    let managed = managed_toolspec_dir();
    let _ = std::fs::create_dir_all(&managed); // best-effort ; l'écriture réelle re-tente + remonte l'erreur
    match std::env::var("FORGE_TOOLSPECS") {
        Ok(existing) if !existing.is_empty() && existing != managed => {
            let sep = if cfg!(windows) { ";" } else { ":" };
            format!("{existing}{sep}{managed}")
        }
        _ => managed,
    }
}

/// Nom de fichier de spec pour un `kind` (déjà validé `custom.<...>`, sans `/`, `\`, ni `..`). Défense en
/// profondeur : re-vérifie l'absence de séparateur/`..` et joint SOUS le dir managé (anti-traversée).
pub(crate) fn spec_file_path(kind: &str) -> Result<std::path::PathBuf, String> {
    if kind.contains('/') || kind.contains('\\') || kind.contains("..") || kind.contains('\0') {
        return Err("kind contient un séparateur de chemin ou '..' — refusé (anti-traversée)".into());
    }
    let name = format!("{kind}.json");
    Ok(std::path::Path::new(&managed_toolspec_dir()).join(name))
}

/// Kinds actuellement présents dans le dir managé (dérivés du champ `kind` de CHAQUE fichier, repli sur le
/// nom de fichier). Source de vérité des outils ajoutés par l'UI (pour re-marquer `user_added` au boot).
pub(crate) fn managed_toolspec_kinds() -> Vec<String> {
    let dir = managed_toolspec_dir();
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(_) => return out, // dir absent/illisible -> aucun outil (offline-safe)
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let kind = std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(|s| s.to_string()))
            .or_else(|| p.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string()));
        if let Some(k) = kind {
            if !k.is_empty() {
                out.push(k);
            }
        }
    }
    out
}

/// Re-marque `module.user_added=1` pour chaque kind présent dans le dir managé. Appelée au BOOT (après
/// `populate_modules` : le re-probe upsert le module mais `user_added` a son DEFAULT 0) et après chaque
/// add/delete. Idempotente. Un built-in n'a jamais de fichier -> jamais marqué (reste supprimable=non).
pub(crate) fn sync_user_added_flags(store: &crate::store::Store) {
    for kind in managed_toolspec_kinds() {
        let _ = store.execute(
            "UPDATE module SET user_added=1 WHERE kind=?",
            &crate::sql_params![&kind],
        );
    }
}

// =================================================================================================
//  VALIDATION FAIL-CLOSED d'un ToolSpec entrant
// =================================================================================================
const ALLOWED_TOP_FIELDS: &[&str] = &[
    "kind", "vuln_class", "binary", "docker_image", "argv_template", "params_schema", "flag_allowlist",
    "parser", "parser_regex", "parser_json_path", "mitre", "cwe", "phase", "capability", "attck_tactic",
    "exploit", "destructive", "severity", "hit_status", "hit_is_asset", "timeout", "tool_name", "description",
];
const ALLOWED_PARAM_KEYS: &[&str] = &["name", "type", "label", "flag", "allowed", "default"];
const PARAM_TYPES: &[&str] = &["text", "number", "select", "list", "flag"];
const PARSERS: &[&str] = &["lines", "regex", "json", "jsonl", "none"];
const PHASES: &[&str] = &["recon", "access", "exploit"];
const CAPABILITIES: &[&str] = &["passive", "active", "exploit"];
const SEVERITIES: &[&str] = &["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const HIT_STATUSES: &[&str] = &["tested", "reported_by_tool"];

/// Basenames INTERDITS pour `binary` : shells + interpréteurs + wrappers d'exécution. Autoriser l'un
/// d'eux réintroduirait le shell (`bash -c "<cmd>"`) et contournerait tout le no-shell. Fail-closed.
const INTERPRETER_BINARIES: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "busybox", "env", "python",
    "python2", "python3", "perl", "ruby", "node", "nodejs", "deno", "bun", "php", "lua", "awk", "gawk",
    "mawk", "expect", "tclsh", "wish", "powershell", "pwsh", "cmd", "xargs", "find", "eval", "exec",
    "source", "sudo", "doas", "ssh", "scp", "sftp", "socat", "nc", "ncat", "netcat", "telnet", "rsync",
];

/// Métacaractères shell rejetés dans la partie LITTÉRALE d'un token/binaire (les `{...}` de placeholder
/// sont traités à part). L'argv est no-shell, mais on durcit la forme (défense en profondeur + lisibilité).
const SHELL_METACHARS: &[char] = &[';', '|', '&', '$', '`', '<', '>', '\n', '\r', '\0', '\\'];

/// Un token/drapeau smuggle-t-il une écriture-fichier / lecture-config / proxy (exfil) ? Même curation que
/// les allowlists natives (sqlmap/ffuf/nuclei EXCLUENT -o/--output/--proxy/--config/--file-*). Renvoie
/// `Some(raison)` si dangereux. Appliqué au binaire, aux tokens-drapeaux, à la `flag_allowlist` et aux
/// `flag` des descripteurs — JAMAIS aux textes libres (description/label).
fn dangerous_flag(tok: &str) -> Option<String> {
    let raw = tok.trim();
    // Drapeaux COURTS curl d'exfil, CASE-SENSITIVE : `-T`/`--upload-file` (fichier→URL), `-K` (lecture
    // d'un fichier de config, forme courte de `--config`), `-F` (upload de fichier de formulaire
    // `-F name=@file`). On DOIT les distinguer de leurs homologues MINUSCULES très courants et légitimes
    // (`-t` threads/templates, `-k` insecure-TLS, `-f` fail) — d'où la comparaison AVANT le lowercase.
    const EXACT_CS: &[&str] = &["-T", "-K", "-F"];
    if EXACT_CS.contains(&raw) {
        return Some(format!("drapeau '{tok}' exfiltre (upload-file/config-read/form-file curl) — refusé"));
    }
    let t = raw.to_ascii_lowercase();
    // drapeaux EXACTS d'écriture-fichier (famille -o de nmap/httpx/…), de proxy et d'upload (--upload-file).
    const EXACT: &[&str] = &[
        "-o", "-oa", "-on", "-ox", "-og", "-oj", "-os", "-of", "-x", "-r", "--output", "--proxy",
        "--config", "--file-read", "--file-write", "--os-shell", "--os-cmd", "--sql-shell", "--eval",
        "--tamper", "--dump", "--dump-all", "--upload-file",
    ];
    if EXACT.contains(&t.as_str()) {
        return Some(format!("drapeau '{tok}' exfiltre (output-file/config-read/proxy/upload/shell) — refusé"));
    }
    // sous-chaînes signant la même intention (couvre --output-dir, -replay-proxy, --config-file,
    // --upload-file=…, …).
    const SUBSTR: &[&str] = &[
        "output", "proxy", "config", "file-write", "file-read", "upload-file", "os-shell", "os-cmd",
        "os-pwn", "sql-shell", "tamper", "debug-log", "--dump",
    ];
    for s in SUBSTR {
        if t.contains(s) {
            return Some(format!("drapeau '{tok}' contient '{s}' (exfil output/config/proxy) — refusé"));
        }
    }
    None
}

/// Valide un `kind` d'outil UI : NAMESPACE `custom.*` OBLIGATOIRE (ne peut donc PAS collisionner avec un
/// module natif — recon.*/web.*/xss.*/… ne commencent jamais par `custom.`) + grammaire de nom de fichier
/// sûre (anti-traversée). Retourne le kind normalisé.
pub(crate) fn validate_kind(kind: &str) -> Result<String, String> {
    if kind.len() < 8 || kind.len() > 64 {
        return Err("kind : longueur 8..=64 requise (ex 'custom.mytool')".into());
    }
    if !kind.starts_with("custom.") {
        return Err("kind doit être dans le namespace 'custom.<nom>' (interdit de surcharger un module natif)".into());
    }
    let rest = &kind["custom.".len()..];
    if rest.is_empty() {
        return Err("kind : le nom après 'custom.' est vide".into());
    }
    if kind.contains("..") {
        return Err("kind : '..' interdit (anti-traversée)".into());
    }
    // grammaire : après le préfixe, [a-z0-9] séparés par un unique . _ - ; commence et finit par [a-z0-9].
    let ok_char = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-';
    if !kind.chars().all(ok_char) {
        return Err("kind : seuls [a-z0-9._-] sont autorisés (minuscules)".into());
    }
    let first = rest.chars().next().unwrap();
    let last = rest.chars().last().unwrap();
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !(last.is_ascii_lowercase() || last.is_ascii_digit())
    {
        return Err("kind : le nom doit commencer et finir par [a-z0-9]".into());
    }
    Ok(kind.to_string())
}

/// Vérifie qu'un binaire est acceptable : non-interpréteur, sans métacaractère shell/NUL, longueur bornée.
fn validate_binary(binary: &str) -> Result<(), String> {
    if binary.len() > MAX_TOKEN_LEN {
        return Err("binary trop long".into());
    }
    if binary.chars().any(|c| SHELL_METACHARS.contains(&c)) {
        return Err(format!("binary '{binary}' contient un métacaractère shell — refusé"));
    }
    let base = binary.rsplit(['/', '\\']).next().unwrap_or(binary).to_ascii_lowercase();
    // retire un éventuel suffixe .exe/.bat/.cmd pour la comparaison.
    let base = base.split('.').next().unwrap_or(&base);
    if INTERPRETER_BINARIES.contains(&base) {
        return Err(format!(
            "binary '{binary}' est un interpréteur/shell ('{base}') — refusé (réintroduirait le shell)"
        ));
    }
    if let Some(why) = dangerous_flag(binary) {
        return Err(why);
    }
    Ok(())
}

/// Valide UN token-string d'argv. `depth>0` = à l'intérieur d'un groupe (le `{args}` y est interdit).
/// Met `args_used=true` si le token est le placeholder standalone `{args}`. Fail-closed.
fn validate_argv_token(tok: &str, depth: usize, args_used: &mut bool) -> Result<(), String> {
    if tok.contains('\0') {
        return Err("token argv contient un octet NUL — refusé".into());
    }
    if tok.len() > MAX_TOKEN_LEN {
        return Err("token argv trop long".into());
    }
    // placeholder EXTRA-ARGS gouverné : autorisé UNIQUEMENT standalone au top-level.
    if tok.trim() == "{args}" {
        if depth > 0 {
            return Err("'{args}' n'est autorisé qu'au niveau supérieur (pas dans un groupe)".into());
        }
        *args_used = true;
        return Ok(());
    }
    // parcours des placeholders {...} : chaque corps doit être un placeholder CONNU (jamais 'args' ici).
    let bytes = tok.as_bytes();
    let mut i = 0;
    let mut literal = String::new();
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let close = tok[i..].find('}').map(|p| i + p);
            let end = close.ok_or_else(|| format!("token '{tok}' : accolade '{{' non fermée"))?;
            let body = &tok[i + 1..end];
            validate_placeholder_body(body, tok)?;
            i = end + 1;
        } else {
            if bytes[i] == b'}' {
                return Err(format!("token '{tok}' : '}}' sans '{{' correspondant"));
            }
            literal.push(bytes[i] as char);
            i += 1;
        }
    }
    // partie littérale (hors placeholders) : pas de métacaractère shell.
    if let Some(c) = literal.chars().find(|c| SHELL_METACHARS.contains(c)) {
        return Err(format!("token '{tok}' contient un métacaractère shell {c:?} — refusé"));
    }
    // si le token EST un drapeau (commence par '-'), sa tête (avant tout '{') passe la curation d'exfil.
    if literal.starts_with('-') {
        let head = literal.split('{').next().unwrap_or(&literal);
        if let Some(why) = dangerous_flag(head) {
            return Err(why);
        }
    }
    Ok(())
}

/// Corps d'un placeholder `{...}` autorisé : `target` | `target_host` | `target_url` | `param:NAME` |
/// `param:NAME:DEFAULT`. Tout autre (`args` inclus ici — il doit être standalone) est REFUSÉ.
fn validate_placeholder_body(body: &str, tok: &str) -> Result<(), String> {
    match body {
        "target" | "target_host" | "target_url" => Ok(()),
        _ if body.starts_with("param:") => {
            let rest = &body["param:".len()..];
            let mut parts = rest.splitn(2, ':');
            let name = parts.next().unwrap_or("");
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("token '{tok}' : nom de param invalide dans {{param:{rest}}} (attendu [A-Za-z0-9_]+)"));
            }
            if let Some(def) = parts.next() {
                if def.chars().any(|c| c == '\0' || SHELL_METACHARS.contains(&c)) {
                    return Err(format!("token '{tok}' : défaut de {{param:...}} contient un caractère interdit"));
                }
                // M2 FIX — le SEGMENT DEFAULT est matérialisé TEL QUEL dans l'argv à l'exécution : il doit
                // subir la MÊME curation d'option-injection que les tokens littéraux (mirror du garde
                // literal-token plus haut). Un défaut commençant par '-' (ex `-oN/tmp/pwned`) smugglerait un
                // drapeau d'écriture-fichier/exfil que le scan des tokens littéraux ne voit pas. Refus.
                if def.starts_with('-') {
                    return Err(format!("token '{tok}' : le défaut de {{param:...}} ne peut pas commencer par '-' (option-injection)"));
                }
                if let Some(why) = dangerous_flag(def) {
                    return Err(format!("token '{tok}' : défaut de {{param:...}} : {why}"));
                }
            }
            Ok(())
        }
        _ => Err(format!(
            "token '{tok}' : placeholder {{{body}}} inconnu — seuls {{target}}/{{target_host}}/{{target_url}}/{{param:NAME}}/{{args}} sont permis"
        )),
    }
}

/// Valide `argv_template` (LISTE de tokens ; un élément peut être un GROUPE = liste de tokens). Retourne la
/// valeur canonique (re-sérialisable) + `args_used`. Fail-closed sur toute forme non conforme.
fn validate_argv_template(v: &Value) -> Result<(Value, bool), String> {
    let arr = v.as_array().ok_or("argv_template doit être une LISTE de tokens (jamais une chaîne shell)")?;
    if arr.is_empty() {
        return Err("argv_template vide — au moins un token requis".into());
    }
    let mut args_used = false;
    let mut count = 0usize;
    let mut out: Vec<Value> = Vec::with_capacity(arr.len());
    for el in arr {
        match el {
            Value::String(s) => {
                count += 1;
                validate_argv_token(s, 0, &mut args_used)?;
                out.push(Value::String(s.clone()));
            }
            Value::Array(group) => {
                if group.is_empty() {
                    return Err("un groupe de argv_template est vide".into());
                }
                let mut gout = Vec::with_capacity(group.len());
                for g in group {
                    count += 1;
                    let s = g.as_str().ok_or("un groupe de argv_template ne peut contenir que des tokens string")?;
                    validate_argv_token(s, 1, &mut args_used)?;
                    gout.push(Value::String(s.to_string()));
                }
                out.push(Value::Array(gout));
            }
            _ => return Err("token argv invalide : chaque élément doit être une string ou un groupe (liste de strings)".into()),
        }
        if count > MAX_ARGV_TOKENS {
            return Err(format!("argv_template : trop de tokens (max {MAX_ARGV_TOKENS})"));
        }
    }
    Ok((Value::Array(out), args_used))
}

/// Valide la `flag_allowlist` : liste de drapeaux (`-x`/`--x`) exacts, non dangereux, sans '='.
fn validate_flag_allowlist(v: &Value) -> Result<Value, String> {
    let arr = v.as_array().ok_or("flag_allowlist doit être une liste de drapeaux")?;
    if arr.len() > MAX_FLAGS {
        return Err(format!("flag_allowlist : trop d'entrées (max {MAX_FLAGS})"));
    }
    let mut out = Vec::with_capacity(arr.len());
    for el in arr {
        let f = el.as_str().ok_or("flag_allowlist : chaque entrée doit être une string")?;
        if f.contains('\0') || f.len() > 64 {
            return Err("flag_allowlist : entrée trop longue ou NUL".into());
        }
        if !(f.starts_with('-') && f.len() >= 2) {
            return Err(format!("flag_allowlist : '{f}' n'est pas un drapeau (attendu -x ou --xxx)"));
        }
        if f.contains('=') || f.chars().any(|c| c.is_whitespace() || SHELL_METACHARS.contains(&c)) {
            return Err(format!("flag_allowlist : '{f}' contient '=' / espace / métacaractère — utiliser la forme '--flag val' (2 tokens)"));
        }
        if let Some(why) = dangerous_flag(f) {
            return Err(why);
        }
        out.push(Value::String(f.to_string()));
    }
    Ok(Value::Array(out))
}

/// Valide `params_schema` : liste de descripteurs typés servis à l'UI (formulaire dynamique). Clés
/// whitelistées ; un `flag` mappé passe la curation d'exfil. Retourne la valeur canonique.
fn validate_params_schema(v: &Value) -> Result<Value, String> {
    let arr = v.as_array().ok_or("params_schema doit être une liste de descripteurs")?;
    if arr.len() > MAX_PARAMS {
        return Err(format!("params_schema : trop de champs (max {MAX_PARAMS})"));
    }
    let mut out = Vec::with_capacity(arr.len());
    for d in arr {
        let obj = d.as_object().ok_or("params_schema : chaque descripteur doit être un objet")?;
        for k in obj.keys() {
            if !ALLOWED_PARAM_KEYS.contains(&k.as_str()) {
                return Err(format!("params_schema : clé de descripteur inconnue '{k}'"));
            }
        }
        let name = obj.get("name").and_then(|x| x.as_str()).unwrap_or("");
        if name.is_empty() || name.len() > 64 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err("params_schema : 'name' requis, [A-Za-z0-9_]+, <=64".into());
        }
        let mut nd = Map::new();
        nd.insert("name".into(), Value::String(name.to_string()));
        let ty = obj.get("type").and_then(|x| x.as_str()).unwrap_or("text");
        if !PARAM_TYPES.contains(&ty) {
            return Err(format!("params_schema : type '{ty}' invalide (text|number|select|list|flag)"));
        }
        nd.insert("type".into(), Value::String(ty.to_string()));
        if let Some(lbl) = obj.get("label").and_then(|x| x.as_str()) {
            if lbl.len() > MAX_LABEL_LEN || lbl.contains('\0') {
                return Err("params_schema : 'label' trop long ou NUL".into());
            }
            nd.insert("label".into(), Value::String(lbl.to_string()));
        }
        if let Some(flag) = obj.get("flag").and_then(|x| x.as_str()) {
            if !flag.is_empty() {
                if flag.contains('\0') || flag.len() > 64 || flag.chars().any(|c| c.is_whitespace() || SHELL_METACHARS.contains(&c)) {
                    return Err("params_schema : 'flag' contient un caractère interdit".into());
                }
                if let Some(why) = dangerous_flag(flag) {
                    return Err(why);
                }
            }
            nd.insert("flag".into(), Value::String(flag.to_string()));
        }
        if let Some(allowed) = obj.get("allowed") {
            let av = allowed.as_array().ok_or("params_schema : 'allowed' doit être une liste")?;
            if av.len() > 64 {
                return Err("params_schema : 'allowed' trop long".into());
            }
            let mut ao = Vec::with_capacity(av.len());
            for a in av {
                let s = a.as_str().ok_or("params_schema : 'allowed' doit contenir des strings")?;
                if s.len() > MAX_LABEL_LEN || s.contains('\0') {
                    return Err("params_schema : valeur 'allowed' trop longue ou NUL".into());
                }
                ao.push(Value::String(s.to_string()));
            }
            nd.insert("allowed".into(), Value::Array(ao));
        }
        if let Some(def) = obj.get("default") {
            match def {
                Value::String(s) if s.len() <= MAX_LABEL_LEN && !s.contains('\0') => { nd.insert("default".into(), def.clone()); }
                Value::Number(_) | Value::Bool(_) => { nd.insert("default".into(), def.clone()); }
                _ => return Err("params_schema : 'default' doit être une string bornée, un nombre ou un booléen".into()),
            }
        }
        out.push(Value::Object(nd));
    }
    Ok(Value::Array(out))
}

/// Valide une string courte à charset borné (mitre/cwe/vuln_class/attck_tactic/tool_name).
fn validate_short_str(v: &Value, field: &str, max: usize) -> Result<String, String> {
    let s = v.as_str().ok_or_else(|| format!("{field} doit être une string"))?;
    if s.len() > max || s.contains('\0') {
        return Err(format!("{field} trop long ou NUL"));
    }
    if s.chars().any(|c| SHELL_METACHARS.contains(&c)) {
        return Err(format!("{field} contient un métacaractère interdit"));
    }
    Ok(s.to_string())
}

/// VALIDE un ToolSpec entrant (fail-closed) et renvoie `(kind, canonical_json)` prêt à persister. Le JSON
/// canonique ne contient QUE des champs connus/validés — chargeable par `load_toolspec_file` (Python) et
/// gouverné comme un module natif. Aucune capacité non déclarée n'est acceptée (champ inconnu -> 400).
pub(crate) fn validate_toolspec(body: &Value) -> Result<(String, Value), (StatusCode, String)> {
    let bad = |m: String| (StatusCode::BAD_REQUEST, m);
    let obj = body.as_object().ok_or_else(|| bad("le corps doit être un objet ToolSpec".into()))?;
    // taille + champs inconnus (fail-closed : aucune capacité surprise).
    if serde_json::to_vec(body).map(|b| b.len()).unwrap_or(usize::MAX) > MAX_SPEC_BYTES {
        return Err(bad(format!("spec trop volumineux (max {MAX_SPEC_BYTES} octets)")));
    }
    for k in obj.keys() {
        if !ALLOWED_TOP_FIELDS.contains(&k.as_str()) {
            return Err(bad(format!("champ inconnu '{k}' — refusé (spec déclaratif borné)")));
        }
    }
    let mut out = Map::new();

    // --- champs REQUIS ---
    let kind = obj.get("kind").and_then(|x| x.as_str()).ok_or_else(|| bad("kind requis".into()))?;
    let kind = validate_kind(kind).map_err(bad)?;
    out.insert("kind".into(), Value::String(kind.clone()));

    let vuln_class = obj.get("vuln_class").ok_or_else(|| bad("vuln_class requis".into()))?;
    let vc = validate_short_str(vuln_class, "vuln_class", 64).map_err(bad)?;
    if vc.is_empty() {
        return Err(bad("vuln_class ne peut pas être vide".into()));
    }
    out.insert("vuln_class".into(), Value::String(vc));

    // binary : requis comme CLÉ (le constructeur ToolSpec l'exige) ; valeur peut être "" si docker_image.
    let binary = obj.get("binary").and_then(|x| x.as_str()).unwrap_or("");
    let docker_image = obj.get("docker_image").and_then(|x| x.as_str()).unwrap_or("");
    if binary.is_empty() && docker_image.is_empty() {
        return Err(bad("au moins un de binary / docker_image doit être fourni".into()));
    }
    if !binary.is_empty() {
        validate_binary(binary).map_err(bad)?;
    }
    out.insert("binary".into(), Value::String(binary.to_string()));
    if !docker_image.is_empty() {
        // image docker : charset borné (pas de shell/NUL), pas d'interpréteur déguisé via entrypoint ici
        // (on ne contrôle pas l'entrypoint de l'image — cf. docs : préférer un binaire présent dans l'image).
        if docker_image.len() > MAX_TOKEN_LEN || docker_image.contains('\0')
            || docker_image.chars().any(|c| SHELL_METACHARS.contains(&c) || c.is_whitespace())
        {
            return Err(bad("docker_image contient un caractère interdit".into()));
        }
        out.insert("docker_image".into(), Value::String(docker_image.to_string()));
    }

    let argv = obj.get("argv_template").ok_or_else(|| bad("argv_template requis".into()))?;
    let (argv_canon, args_used) = validate_argv_template(argv).map_err(bad)?;
    out.insert("argv_template".into(), argv_canon);

    // flag_allowlist : REQUISE si {args} est utilisé.
    let flag_allowlist = match obj.get("flag_allowlist") {
        Some(v) => Some(validate_flag_allowlist(v).map_err(bad)?),
        None => None,
    };
    if args_used {
        let has = flag_allowlist
            .as_ref()
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if !has {
            return Err(bad("'{args}' utilisé mais flag_allowlist absente/vide — refusé (extra-args non gouvernés)".into()));
        }
    }
    if let Some(fa) = flag_allowlist {
        out.insert("flag_allowlist".into(), fa);
    }

    // --- champs OPTIONNELS ---
    if let Some(v) = obj.get("params_schema") {
        out.insert("params_schema".into(), validate_params_schema(v).map_err(bad)?);
    }
    if let Some(v) = obj.get("parser") {
        let p = v.as_str().ok_or_else(|| bad("parser doit être une string".into()))?;
        if !PARSERS.contains(&p) {
            return Err(bad(format!("parser '{p}' invalide (lines|regex|json|jsonl|none)")));
        }
        out.insert("parser".into(), Value::String(p.to_string()));
    }
    if let Some(v) = obj.get("parser_regex") {
        let r = v.as_str().ok_or_else(|| bad("parser_regex doit être une string".into()))?;
        if r.len() > MAX_TOKEN_LEN || r.contains('\0') {
            return Err(bad("parser_regex trop long ou NUL".into()));
        }
        out.insert("parser_regex".into(), Value::String(r.to_string()));
    }
    if let Some(v) = obj.get("parser_json_path") {
        let a = v.as_array().ok_or_else(|| bad("parser_json_path doit être une liste de clés".into()))?;
        if a.len() > 32 {
            return Err(bad("parser_json_path trop long".into()));
        }
        let mut po = Vec::with_capacity(a.len());
        for k in a {
            let s = k.as_str().ok_or_else(|| bad("parser_json_path : clés string attendues".into()))?;
            if s.len() > 128 || s.contains('\0') {
                return Err(bad("parser_json_path : clé trop longue ou NUL".into()));
            }
            po.push(Value::String(s.to_string()));
        }
        out.insert("parser_json_path".into(), Value::Array(po));
    }
    for (field, max) in [("mitre", 64usize), ("cwe", 64), ("attck_tactic", 64), ("tool_name", 64)] {
        if let Some(v) = obj.get(field) {
            out.insert(field.into(), Value::String(validate_short_str(v, field, max).map_err(bad)?));
        }
    }
    if let Some(v) = obj.get("phase") {
        let p = v.as_str().unwrap_or("");
        if !PHASES.contains(&p) {
            return Err(bad(format!("phase '{p}' invalide (recon|access|exploit)")));
        }
        out.insert("phase".into(), Value::String(p.to_string()));
    }
    if let Some(v) = obj.get("capability") {
        let c = v.as_str().unwrap_or("");
        if !CAPABILITIES.contains(&c) {
            return Err(bad(format!("capability '{c}' invalide (passive|active|exploit)")));
        }
        out.insert("capability".into(), Value::String(c.to_string()));
    }
    if let Some(v) = obj.get("severity") {
        let s = v.as_str().unwrap_or("");
        if !SEVERITIES.contains(&s) {
            return Err(bad(format!("severity '{s}' invalide (INFO|LOW|MEDIUM|HIGH|CRITICAL)")));
        }
        out.insert("severity".into(), Value::String(s.to_string()));
    }
    if let Some(v) = obj.get("hit_status") {
        // CLAMP dur : un outil ne peut JAMAIS se promouvoir 'vulnerable' (proof-oriented).
        let h = v.as_str().unwrap_or("");
        if !HIT_STATUSES.contains(&h) {
            return Err(bad(format!("hit_status '{h}' invalide (tested|reported_by_tool) — 'vulnerable' interdit")));
        }
        out.insert("hit_status".into(), Value::String(h.to_string()));
    }
    for field in ["exploit", "destructive", "hit_is_asset"] {
        if let Some(v) = obj.get(field) {
            let b = v.as_bool().ok_or_else(|| bad(format!("{field} doit être un booléen")))?;
            out.insert(field.into(), Value::Bool(b));
        }
    }
    if let Some(v) = obj.get("timeout") {
        let t = v.as_i64().ok_or_else(|| bad("timeout doit être un entier (secondes)".into()))?;
        if !(1..=3600).contains(&t) {
            return Err(bad("timeout hors bornes (1..=3600 s)".into()));
        }
        out.insert("timeout".into(), Value::Number(t.into()));
    }
    if let Some(v) = obj.get("description") {
        let d = v.as_str().ok_or_else(|| bad("description doit être une string".into()))?;
        if d.len() > MAX_DESCR_LEN || d.contains('\0') {
            return Err(bad("description trop longue ou NUL".into()));
        }
        out.insert("description".into(), Value::String(d.to_string()));
    }

    Ok((kind, Value::Object(out)))
}

// =================================================================================================
//  HANDLERS HTTP (admin-only, ledgerisés)
// =================================================================================================

/// Vue d'un outil ajouté par l'UI : entrée du catalogue `module` (kind/available/params_schema/…) ENRICHIE
/// du spec persisté (binary/docker_image/argv_template) pour l'affichage + la suppression.
fn user_tool_view(store: &crate::store::Store, kind: &str) -> Value {
    let catalog = modules_catalog(store)
        .into_iter()
        .find(|m| m.get("kind").and_then(|v| v.as_str()) == Some(kind))
        .unwrap_or_else(|| json!({"kind": kind}));
    let spec = spec_file_path(kind)
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or(Value::Null);
    json!({"kind": kind, "module": catalog, "spec": spec})
}

/// GET /api/tools — liste les outils AJOUTÉS PAR L'UI (module.user_added=1). Admin-only (fail-closed 403).
pub(crate) async fn tools_list(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let store = app.store();
    let kinds: Vec<String> = store
        .query_lax("SELECT kind FROM module WHERE user_added=1 ORDER BY kind", &[], |r| r.get_str(0))
        .unwrap_or_default();
    let tools: Vec<Value> = kinds.iter().map(|k| user_tool_view(&store, k)).collect();
    (StatusCode::OK, Json(json!({"tools": tools, "dir": managed_toolspec_dir()}))).into_response()
}

/// POST /api/tools — AJOUTE un outil déclaratif (ToolSpec). Admin-only, validé fail-closed, PERSISTÉ 0600
/// dans le dir managé, HOT-RELOAD via re-probe, LEDGERISÉ `console.tool.add`. Renvoie l'outil créé.
pub(crate) async fn tools_add(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let (kind, canon) = match validate_toolspec(&body) {
        Ok(v) => v,
        Err((s, why)) => return (s, Json(json!({"error": "tool_invalid", "why": why}))).into_response(),
    };
    // anti-collision : refuse un kind DÉJÀ présent qui ne serait PAS un outil UI (défense en profondeur —
    // un custom.* ne peut pas être natif, mais on ne réécrit jamais un module non-user_added par surprise).
    {
        let store = app.store();
        let existing: Option<i64> = store
            .query_opt("SELECT user_added FROM module WHERE kind=?", &crate::sql_params![&kind], |r| r.get_opt_i64(0).map(|o| o.unwrap_or(0)))
            .ok()
            .flatten();
        if matches!(existing, Some(0)) {
            return (StatusCode::CONFLICT, Json(json!({"error": "kind_conflict", "why": format!("le kind '{kind}' existe déjà comme module non-UI — refusé")}))).into_response();
        }
    }
    // PERSISTANCE 0600 dans le dir managé (anti-traversée : nom dérivé du kind assaini).
    let path = match spec_file_path(&kind) {
        Ok(p) => p,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "tool_path", "why": why}))).into_response(),
    };
    let bytes = match serde_json::to_vec_pretty(&canon) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "tool_serialize", "why": e.to_string()}))).into_response(),
    };
    if let Err(why) = crate::backup_write_atomic(&path.to_string_lossy(), &bytes, 0o600) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "tool_write", "why": why}))).into_response();
    }
    // HOT-RELOAD : re-probe (FORGE_TOOLSPECS pointe le dir managé) -> le module apparaît dans la table.
    let view = {
        let store = app.store();
        populate_modules(&store);
        sync_user_added_flags(&store);
        user_tool_view(&store, &kind)
    };
    // si le re-probe n'a pas fait apparaître le module (registre Python indisponible), on ne PRÉTEND pas :
    // le fichier est écrit (il sera pris au prochain boot) mais on signale l'état dégradé.
    let present = view.get("module").and_then(|m| m.get("kind")).and_then(|k| k.as_str()) == Some(kind.as_str());
    let available = view.get("module").and_then(|m| m.get("available")).and_then(|b| b.as_bool()).unwrap_or(false);
    append_console_ledger(&app, "console.tool.add", json!({
        "actor": actor,
        "kind": kind,
        "binary": canon.get("binary").cloned().unwrap_or(Value::Null),
        "docker_image": canon.get("docker_image").cloned().unwrap_or(Value::Null),
        "registered": present,
        "available": available,
    }));
    (StatusCode::OK, Json(json!({"tool": view, "registered": present}))).into_response()
}

/// DELETE /api/tools/:kind — RETIRE un outil ajouté par l'UI. Admin-only, LEDGERISÉ `console.tool.remove`.
/// Refuse un module NON user_added (jamais un built-in). Supprime le fichier + la ligne + re-probe.
pub(crate) async fn tools_delete(State(app): State<App>, headers: HeaderMap, Path(kind): Path<String>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    // le kind DOIT être un outil UI existant (user_added=1) — sinon 404/refus (jamais un natif).
    {
        let store = app.store();
        let ua: Option<i64> = store
            .query_opt("SELECT user_added FROM module WHERE kind=?", &crate::sql_params![&kind], |r| r.get_opt_i64(0).map(|o| o.unwrap_or(0)))
            .ok()
            .flatten();
        match ua {
            None => return (StatusCode::NOT_FOUND, Json(json!({"error": "tool_unknown", "why": format!("outil '{kind}' inconnu")}))).into_response(),
            Some(0) => return (StatusCode::FORBIDDEN, Json(json!({"error": "not_user_tool", "why": format!("'{kind}' n'est pas un outil ajouté par l'UI — suppression refusée")}))).into_response(),
            Some(_) => {}
        }
    }
    // supprime le fichier de spec (idempotent) — anti-traversée via spec_file_path.
    match spec_file_path(&kind) {
        Ok(p) => {
            if let Err(e) = std::fs::remove_file(&p) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "tool_delete", "why": e.to_string()}))).into_response();
                }
            }
        }
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "tool_path", "why": why}))).into_response(),
    }
    // retire la ligne (GARDÉE user_added=1 : jamais un built-in) puis re-probe (ne le ré-ajoute pas : fichier parti).
    {
        let store = app.store();
        let _ = store.execute("DELETE FROM module WHERE kind=? AND user_added=1", &crate::sql_params![&kind]);
        populate_modules(&store);
        sync_user_added_flags(&store);
    }
    append_console_ledger(&app, "console.tool.remove", json!({"actor": actor, "kind": kind}));
    (StatusCode::OK, Json(json!({"removed": kind}))).into_response()
}

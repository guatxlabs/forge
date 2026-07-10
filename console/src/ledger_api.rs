// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SOUS-SYSTÈME LEDGER (lecture + vérification de la chaîne SHA-256 + écriture).
//! Bloc déplacé depuis main.rs (PURE MOVE). Regroupe : la canonicalisation JSON (canon_json/…), la
//! lecture du JSONL (read_ledger_lines), la re-vérification hash-chain (verify_ledger_chain +
//! LedgerVerify + ledger_verify_api_json), les handlers HTTP GET /api/ledger et /api/ledger/verify,
//! la résolution du ledger d'un engagement (engagement_ledger_path) et l'append console
//! (append_console_ledger). Réutilise App + les helpers de la racine de crate (sha_hex / paginate /
//! resolve_view_engagement_id / chrono_now_compact / tenancy) via `use crate::…`, et est re-exporté à
//! la racine par `pub(crate) use crate::ledger_api::*` — les tests inline de main.rs (`super::*`) ET
//! les appelants inter-modules (`crate::canon_json`, `crate::verify_ledger_chain`,
//! `crate::append_console_ledger`, `crate::read_ledger_lines`, `crate::engagement_ledger_path`,
//! `crate::ledger_verify_api_json`, `LedgerVerify`) résolvent donc ces symboles INCHANGÉS.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::{chrono_now_compact, paginate, resolve_view_engagement_id, sha_hex, tenancy, App};

// --- ledger d'engagement : lecture + re-vérification de la chaîne SHA-256 (sans la clé de signature) ---

/// Canonicalisation JSON identique à `ledger._canon` côté Python :
/// json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).
/// Indispensable pour recalculer `_entry_hash` à l'identique en Rust.
pub(crate) fn canon_json(v: &Value) -> String {
    let mut s = String::new();
    canon_into(v, &mut s);
    s
}

fn canon_into(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => canon_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 { out.push(','); }
                canon_into(item, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            // tri lexicographique des clés (sort_keys=True). Les clés Python sont des str.
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 { out.push(','); }
                canon_str(k, out);
                out.push(':');
                canon_into(&m[*k], out);
            }
            out.push('}');
        }
    }
}

/// Échappement de chaîne JSON minimal compatible json.dumps(ensure_ascii=False) :
/// échappe \" \\ et les contrôles < 0x20, laisse l'UTF-8 tel quel.
fn canon_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub(crate) fn read_ledger_lines(path: &str) -> Vec<Value> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .collect(),
        Err(_) => vec![],
    }
}

/// GET /api/ledger — liste les entrées du ledger (depuis le JSONL disque), paginé (limit/offset).
pub(crate) async fn ledger(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : chaque engagement porte SON ledger DÉDIÉ (fichier JSONL). La vue lit UNIQUEMENT le
    // ledger de l'engagement actif — jamais celui d'un autre engagement (isolation tamper-evident).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let (limit, offset) = paginate(&q, 200, 2000);
    // ENTERPRISE fail-closed : un engagement d'un tenant NON accordé résout vers NO_ENGAGEMENT. On ne
    // DOIT PAS appeler engagement_ledger_path (qui retomberait sur le ledger console par défaut = leak) :
    // on renvoie un ledger VIDE. No-op en community (enabled=false, eid réel).
    if tenancy::enabled(&app) && eid == tenancy::NO_ENGAGEMENT {
        return Json(json!({"total": 0, "limit": limit, "offset": offset, "path": "", "engagement": eid, "entries": []}));
    }
    let path = engagement_ledger_path(&app, eid);
    let entries = read_ledger_lines(&path);
    let total = entries.len();
    let page: Vec<Value> = entries.into_iter().skip(offset as usize).take(limit as usize).collect();
    Json(json!({"total": total, "limit": limit, "offset": offset, "path": path, "engagement": eid, "entries": page}))
}

/// Résultat de la recomputation de la chaîne SHA-256 d'un ledger JSONL — PARTAGÉ par le handler
/// GET /api/ledger/verify ET la migration (`migrate --verify`). NE vérifie PAS les signatures
/// (Ed25519/HMAC) : la console n'a pas la clé privée -> seul le hash-chaining est recalculé.
pub(crate) struct LedgerVerify {
    pub(crate) ok: bool,
    pub(crate) entries: usize,
    pub(crate) broken: Value,        // seq de l'entrée rompue (ou Null)
    pub(crate) why: Option<String>,
    pub(crate) head: Option<String>, // hash de tête (Some UNIQUEMENT quand la chaîne est intègre)
    pub(crate) alg: String,
    pub(crate) exists: bool,         // le fichier ledger existe-t-il sur disque ?
    pub(crate) empty: bool,          // 0 entrée exploitable (fichier absent OU toutes lignes malformées)
}

/// Recompute et vérifie la chaîne SHA-256 (prev|seq|ts|kind|canon(detail)) d'un ledger JSONL à `path`.
/// S'arrête à la 1re rupture (prev désaligné ou hash recalculé != stocké). Fonction PURE (I/O lecture
/// seule) : elle est la SEULE source de vérité de la vérif hash-chain, réutilisée par l'API et la
/// migration pour ne jamais dupliquer la logique.
pub(crate) fn verify_ledger_chain(path: &str) -> LedgerVerify {
    const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let entries = read_ledger_lines(path);
    if entries.is_empty() {
        // soit fichier absent/vide, soit toutes lignes malformées
        let exists = std::path::Path::new(path).exists();
        return LedgerVerify {
            ok: exists, entries: 0, broken: Value::Null,
            why: if exists { None } else { Some("ledger absent".to_string()) },
            head: None, alg: String::new(), exists, empty: true,
        };
    }
    let mut prev = GENESIS.to_string();
    let mut head = GENESIS.to_string();
    let mut alg = String::new();
    for (n, rec) in entries.iter().enumerate() {
        let seq = rec.get("seq").cloned().unwrap_or(Value::Null);
        let ts = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let detail = rec.get("detail").cloned().unwrap_or(Value::Null);
        let stored_prev = rec.get("prev").and_then(|v| v.as_str()).unwrap_or("");
        let stored_hash = rec.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        alg = rec.get("alg").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if stored_prev != prev {
            return LedgerVerify {
                ok: false, entries: n + 1, broken: seq,
                why: Some("chaînage rompu (prev)".to_string()),
                head: None, alg, exists: true, empty: false,
            };
        }
        // seq sérialisé tel quel (entier sans guillemets) — cohérent avec le format Python f-string.
        let seq_str = match &seq { Value::Number(num) => num.to_string(), Value::Null => String::new(), other => other.to_string() };
        let preimage = format!("{prev}|{seq_str}|{ts}|{kind}|{}", canon_json(&detail));
        let recomputed = sha_hex(&preimage);
        if recomputed != stored_hash {
            return LedgerVerify {
                ok: false, entries: n + 1, broken: seq,
                why: Some("hash recalculé != hash stocké (entrée altérée)".to_string()),
                head: None, alg, exists: true, empty: false,
            };
        }
        prev = stored_hash.to_string();
        head = stored_hash.to_string();
    }
    LedgerVerify {
        ok: true, entries: entries.len(), broken: Value::Null, why: None,
        head: Some(head), alg, exists: true, empty: false,
    }
}

/// Sérialise un `LedgerVerify` au format JSON HISTORIQUE de GET /api/ledger/verify (clés identiques
/// par branche : vide / rompu / intègre — parité stricte avec le contrat SPA app.js qui lit
/// alg/broken/why). `sig_checked` toujours false (la console ne détient pas la clé privée).
pub(crate) fn ledger_verify_api_json(v: &LedgerVerify, path: &str) -> Value {
    if v.empty {
        return json!({
            "ok": v.ok, "entries": 0, "broken": Value::Null, "sig_checked": false,
            "path": path, "why": match &v.why { Some(w) => json!(w), None => Value::Null }
        });
    }
    if v.ok {
        return json!({
            "ok": true, "entries": v.entries, "broken": Value::Null, "head": v.head,
            "alg": v.alg, "sig_checked": false, "path": path
        });
    }
    json!({
        "ok": false, "entries": v.entries, "broken": v.broken, "why": v.why,
        "sig_checked": false, "alg": v.alg, "path": path
    })
}

/// GET /api/ledger/verify — recalcule la chaîne SHA-256 (prev|seq|ts|kind|canon(detail))
/// et vérifie chaque hash + le chaînage `prev`. NE vérifie PAS les signatures (Ed25519/HMAC) :
/// la console n'a pas la clé -> `sig_checked: false` (la vérif signature reste côté `forge ledger verify`).
pub(crate) async fn ledger_verify(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : vérifie la chaîne du ledger DÉDIÉ de l'engagement actif (isolation).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // ENTERPRISE fail-closed : tenant non accordé -> NO_ENGAGEMENT ; ne PAS retomber sur le ledger par
    // défaut (leak). On renvoie le contrat « ledger vide » (empty=true). No-op en community.
    if tenancy::enabled(&app) && eid == tenancy::NO_ENGAGEMENT {
        let v = LedgerVerify { ok: false, entries: 0, broken: Value::Null, why: Some("ledger absent".to_string()),
            head: None, alg: String::new(), exists: false, empty: true };
        return (StatusCode::OK, Json(ledger_verify_api_json(&v, "")));
    }
    let path = engagement_ledger_path(&app, eid);
    let v = verify_ledger_chain(&path);
    (StatusCode::OK, Json(ledger_verify_api_json(&v, &path)))
}

/// Résout le `ledger_path` DÉDIÉ d'un engagement (par id). Défaut : App.ledger_path (engagement #1 /
/// rétro-compat) si l'id est inconnu ou son ledger vide. ISOLATION : la vue /api/ledger d'un engagement
/// lit UNIQUEMENT le fichier ledger de CET engagement.
pub(crate) fn engagement_ledger_path(app: &App, eid: i64) -> String {
    let store = app.store();
    store.query_row("SELECT ledger_path FROM engagement WHERE id=?", &crate::sql_params![eid], |r| r.get_str(0))
        .ok().filter(|s| !s.is_empty())
        .unwrap_or_else(|| app.ledger_path.as_str().to_string())
}

/// Ajoute une entrée au ledger JSONL côté console (chaîne SHA-256, alg "sha256-console", sig "").
/// Compatible avec /api/ledger/verify (qui ne vérifie pas la signature, seulement le hash-chaining).
pub(crate) fn append_console_ledger(app: &App, kind: &str, detail: Value) {
    let path = app.ledger_path.as_str();
    // VERROU ledger : couvre lecture-head -> calcul hash -> écriture en UNE section critique. Sans lui,
    // deux appends concurrents lisaient le MÊME prev/seq puis écrivaient deux entrées de même seq/prev
    // -> chaîne SHA-256 cassée (la vérif /api/ledger/verify échouerait). Empoisonnement récupéré
    // (into_inner) : un panic passé ne doit pas geler l'audit.
    let mut head = app.ledger_lock.lock().unwrap_or_else(|e| e.into_inner());
    // B5 — LEDGER MULTI-INSTANCE : sous HA le fichier ledger est PARTAGÉ entre réplicas ; un pair a pu
    // appender depuis notre dernier head EN CACHE. On sérialise la section critique read-tail->compute->
    // append CROSS-INSTANCE via un verrou consultatif PG (`ha::with_ledger_lock`, keyed sur le path) et, à
    // l'intérieur du verrou, on INVALIDE le cache pour RELIRE la tête du fichier partagé -> aucune fourche
    // de la chaîne SHA-256 (verify inchangé). Single-instance (!ha) : `with_ledger_lock` est un pass-through
    // et le verrou in-proc + le cache O(1) restent autoritatifs, byte-identique à avant.
    crate::ha::with_ledger_lock(app, path, || {
        if crate::ha::ha_enabled(app) {
            // Un pair a pu écrire dans le fichier partagé -> notre (prev,seq) en cache est périmé. On force
            // une relecture de la tête depuis le disque SOUS le verrou consultatif (single writer garanti).
            head.loaded = false;
        }
        // initialisation paresseuse du head depuis le disque (une seule relecture intégrale, au 1er append) ;
        // ensuite on garde (prev,seq) en cache -> O(1) amorti au lieu de relire tout le fichier (O(n²)).
        if !head.loaded {
            head.prev = "0".repeat(64);
            head.seq = 0;
            if let Ok(s) = std::fs::read_to_string(path) {
                for line in s.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(rec) = serde_json::from_str::<Value>(line) {
                        if let Some(h) = rec.get("hash").and_then(|v| v.as_str()) { head.prev = h.to_string(); }
                        if let Some(q) = rec.get("seq").and_then(|v| v.as_i64()) { head.seq = q; }
                    }
                }
            }
            head.loaded = true;
        }
        let prev = head.prev.clone();
        let seq = head.seq + 1;
        let ts = {
            // ISO-ish UTC sans dépendance : on réutilise le compact + 'Z' épochal. verify ne parse pas ts.
            format!("@{}", chrono_now_compact())
        };
        let preimage = format!("{prev}|{seq}|{ts}|{kind}|{}", canon_json(&detail));
        let hash = sha_hex(&preimage);
        let rec = json!({
            "seq": seq, "ts": ts, "kind": kind, "detail": detail,
            "prev": prev, "hash": hash, "alg": "sha256-console", "sig": ""
        });
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        use std::io::Write;
        // n'avance le head EN CACHE que si l'écriture disque réussit (sinon on relira au prochain append).
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            // SYS-2 : fsync APRÈS un writeln! réussi -> le journal tamper-evident est DURABLE (survit à un
            // crash/coupure post-écriture). N'avance le head en cache qu'après un flush disque confirmé.
            if writeln!(f, "{}", canon_json(&rec)).is_ok() && f.sync_all().is_ok() {
                head.prev = hash;
                head.seq = seq;
            } else {
                head.loaded = false; // écriture partielle/échouée -> forcer une relecture au prochain append
            }
        } else {
            head.loaded = false;
        }
    });
}

/// Routes du sous-système ledger — GET /api/ledger (liste paginée) + GET /api/ledger/verify
/// (re-vérification hash-chain). Fusionnées dans le routeur `protected` de build_router (main.rs)
/// AVANT le fallback + le route_layer => elles héritent de l'auth_guard/host_guard comme toute route
/// protégée, à l'identique de leur câblage inline d'origine (parité stricte).
pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/ledger", get(ledger))
        .route("/api/ledger/verify", get(ledger_verify))
}

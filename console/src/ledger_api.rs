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
/// PARITÉ Python (M1) : `json.dumps` émet les SHORT escapes `\b` (0x08) et `\f` (0x0c) — comme
/// `\n`/`\r`/`\t` — et non ``/``. Ces deux arms DOIVENT précéder l'arm générique `< 0x20`,
/// sinon une entrée moteur (Python) portant 0x08/0x0c dans un champ `detail` (injectable par ingestion :
/// titre de finding, kind ROE) produirait un préimage Rust différent -> `verify_ledger_chain` crierait
/// « entrée altérée » sur une entrée légitime (fausse alarme d'intégrité).
fn canon_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),  // parité json.dumps : 0x08 -> \b (AVANT l'arm < 0x20)
            '\u{000c}' => out.push_str("\\f"),  // parité json.dumps : 0x0c -> \f (AVANT l'arm < 0x20)
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

/// (prev_hash, seq) de la DERNIÈRE entrée valide du ledger JSONL sur disque, ou (GENESIS, 0) si
/// vide/absent. Miroir strict de `forge/ledger.py::_disk_tail` : une dernière ligne corrompue/tronquée
/// (crash en plein write) est ignorée — on chaîne sur la dernière entrée valide. DOIT être appelé SOUS
/// le verrou fichier (l'append re-lit la queue ici pour chaîner sur une écriture concurrente d'un AUTRE
/// processus — la console ET le moteur Python écrivent le MÊME fichier).
fn read_disk_tail(path: &str) -> (String, i64) {
    let mut prev = "0".repeat(64);
    let mut seq = 0i64;
    if let Ok(s) = std::fs::read_to_string(path) {
        for line in s.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(rec) = serde_json::from_str::<Value>(line) {
                if let Some(h) = rec.get("hash").and_then(|v| v.as_str()) { prev = h.to_string(); }
                if let Some(q) = rec.get("seq").and_then(|v| v.as_i64()) { seq = q; }
            }
        }
    }
    (prev, seq)
}

/// Verrou consultatif EXCLUSIF cross-processus sur le fichier ledger, via `fcntl.flock(LOCK_EX)` — LA
/// MÊME sémantique POSIX que `forge/ledger.py::append`. C'est LE chaînon manquant de B1 : la console
/// Rust et le moteur Python écrivent le MÊME `engagement.jsonl` ; sans un verrou PARTAGÉ ENTRE
/// PROCESSUS, un append moteur interleavé et un append console lisaient tous deux la même queue en
/// cache et écrivaient deux entrées de même (prev,seq) -> fourche de la chaîne SHA-256. flock() étant
/// pris sur LE MÊME fichier par les deux, l'un bloque l'autre : lecture-queue -> calcul -> write ->
/// fsync forment UNE section critique cross-processus. Relâché au Drop (LOCK_UN puis close du fd).
#[cfg(unix)]
pub(crate) struct FlockExclusive {
    fd: std::os::unix::io::RawFd,
}

#[cfg(unix)]
impl FlockExclusive {
    /// Prend LOCK_EX (bloquant) sur le fd du fichier ouvert. Le fd reste valide tant que le `File`
    /// emprunté vit ; on garde le guard MOINS longtemps que le `File` (déclaré après lui -> droppé
    /// avant), donc aucun usage après close.
    pub(crate) fn acquire(f: &std::fs::File) -> Result<Self, String> {
        use std::os::unix::io::AsRawFd;
        let fd = f.as_raw_fd();
        // SAFETY : fd valide (emprunté au File vivant) ; LOCK_EX bloque jusqu'à obtention du verrou.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc != 0 {
            return Err(format!("flock LOCK_EX échoué: {}", std::io::Error::last_os_error()));
        }
        Ok(Self { fd })
    }
}

#[cfg(unix)]
impl Drop for FlockExclusive {
    fn drop(&mut self) {
        // Relâche explicite (la fermeture du fd relâcherait aussi le verrou, mais on le fait avant le
        // fsync/close pour une section critique nette). Best-effort : un échec de LOCK_UN est ignoré.
        unsafe { libc::flock(self.fd, libc::LOCK_UN); }
    }
}

#[cfg(not(unix))]
pub(crate) struct FlockExclusive;

#[cfg(not(unix))]
impl FlockExclusive {
    // Non-POSIX (Windows) : pas de flock -> repli sans verrou (sûr en écrivain unique uniquement,
    // parité avec le repli `fcntl is None` de forge/ledger.py). La cible de déploiement est Linux.
    pub(crate) fn acquire(_f: &std::fs::File) -> Result<Self, String> { Ok(Self) }
}

/// Ouvre le fichier ledger pour une RÉÉCRITURE IN-PLACE (read+write, créé si absent) — utilisé par le
/// purge de conformité gouverné (compliance.rs) pour le `flock` avec le MÊME `FlockExclusive` que les
/// appends, puis le réécrire SANS rename (inode stable). Un rename échangerait l'inode sous un appender
/// bloqué sur le flock -> son entrée serait écrite sur l'inode délié = PERDUE (la perte d'écriture H1).
pub(crate) fn open_ledger_rw(path: &str) -> Result<std::fs::File, String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    std::fs::OpenOptions::new()
        .create(true).read(true).write(true).open(path)
        .map_err(|e| format!("ouverture ledger '{path}' pour réécriture impossible: {e}"))
}

/// Réécrit le ledger IN-PLACE sur un fd DÉJÀ flocké : seek 0, write `data`, tronque à sa longueur, fsync.
/// AUCUN rename — l'inode est préservé, donc un appender concurrent qui `flock` le MÊME chemin continue de
/// contendre sur le MÊME verrou (un rename échangerait l'inode et perdrait silencieusement l'entrée d'un
/// appender bloqué — la perte d'écriture H1). DOIT être appelé en tenant `FlockExclusive` sur `f`.
pub(crate) fn rewrite_ledger_in_place(f: &std::fs::File, data: &[u8]) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    let mut fw: &std::fs::File = f;                 // impl Write/Seek pour &File
    fw.seek(SeekFrom::Start(0)).map_err(|e| format!("seek ledger échoué: {e}"))?;
    fw.write_all(data).map_err(|e| format!("réécriture in-place ledger échouée: {e}"))?;
    fw.flush().map_err(|e| format!("flush ledger échoué: {e}"))?;
    f.set_len(data.len() as u64).map_err(|e| format!("truncate ledger échoué: {e}"))?;
    // fsync AVANT de relâcher le flock (fait par le Drop du guard côté appelant) -> réécriture DURABLE.
    f.sync_all().map_err(|e| format!("sync ledger échoué: {e}"))?;
    Ok(())
}

/// Append UNE entrée `sha256-console` (chaîne SHA-256 NON signée, sig "") à `path`, SÉRIALISÉ
/// CROSS-PROCESSUS par un `fcntl.flock(LOCK_EX)` tenu de la relecture de la queue jusqu'au fsync. Le
/// même verrou est pris par le moteur Python (`forge/ledger.py`) sur le même fichier -> les deux
/// processus ne partagent JAMAIS un (prev,seq) : le prev/seq est TOUJOURS dérivé de la queue RELUE
/// SUR DISQUE sous le verrou (jamais d'un compteur en mémoire qui devient périmé quand l'autre
/// processus a appendé). Renvoie (prev, seq, hash) de l'entrée écrite, ou Err lisible sur échec I/O.
/// C'est la SOURCE UNIQUE d'append console : `append_console_ledger` (ledger de la console) ET
/// `ledger_append_standalone` (ledger dédié d'un engagement) passent tous deux par ici.
pub(crate) fn append_sha256_console_locked(
    path: &str, kind: &str, detail: &Value,
) -> Result<(String, i64, String), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    use std::io::Write;
    // read(true) requis pour pouvoir relire l'octet de fin sous le verrou (garde ligne tronquée).
    let mut f = std::fs::OpenOptions::new()
        .create(true).read(true).append(true).open(path)
        .map_err(|e| format!("ouverture ledger '{path}' impossible: {e}"))?;
    // Verrou consultatif cross-processus (bloquant) : sérialise vs le moteur Python sur le même fichier.
    let _flock = FlockExclusive::acquire(&f)?;
    // Queue AUTORITATIVE relue sur disque SOUS le verrou : un append moteur interleavé est CHAÎNÉ
    // dessus (jamais écrasé). C'est ce qui rend impossible la collision de seq observée en B1.
    let (prev, tail_seq) = read_disk_tail(path);
    let seq = tail_seq + 1;
    let ts = format!("@{}", chrono_now_compact());
    let preimage = format!("{prev}|{seq}|{ts}|{kind}|{}", canon_json(detail));
    let hash = sha_hex(&preimage);
    let rec = json!({
        "seq": seq, "ts": ts, "kind": kind, "detail": detail,
        "prev": prev, "hash": hash, "alg": "sha256-console", "sig": ""
    });
    // Si le dernier octet disque n'est pas '\n' (un writer a crashé en plein write), repartir sur une
    // ligne fraîche pour ne pas coller sur un enregistrement tronqué (parité forge/ledger.py).
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        if let Ok(meta) = f.metadata() {
            let end = meta.len();
            if end > 0 {
                let mut last = [0u8; 1];
                if f.read_exact_at(&mut last, end - 1).is_ok() && last[0] != b'\n' {
                    let _ = f.write_all(b"\n");
                }
            }
        }
    }
    writeln!(f, "{}", canon_json(&rec)).map_err(|e| format!("écriture ledger '{path}' échouée: {e}"))?;
    // SYS-2 : fsync AVANT de relâcher le verrou -> l'entrée tamper-evident est DURABLE.
    f.sync_all().map_err(|e| format!("sync ledger '{path}' échoué: {e}"))?;
    Ok((prev, seq, hash))
    // _flock droppé ici (LOCK_UN), puis f droppé (close).
}

/// Ajoute une entrée au ledger JSONL côté console (chaîne SHA-256, alg "sha256-console", sig "").
/// Compatible avec /api/ledger/verify (qui ne vérifie pas la signature, seulement le hash-chaining).
pub(crate) fn append_console_ledger(app: &App, kind: &str, detail: Value) {
    let path = app.ledger_path.as_str();
    // VERROU ledger in-proc : sérialise les appends console DU MÊME processus + protège le cache de head.
    // Empoisonnement récupéré (into_inner) : un panic passé ne doit pas geler l'audit. B1 — le prev/seq
    // AUTORITATIF ne vient PLUS du cache en mémoire (qui devenait périmé quand le moteur Python appendait
    // entre deux appends console -> fourche) mais TOUJOURS de la queue relue sur disque SOUS le
    // `fcntl.flock` cross-processus de `append_sha256_console_locked` (même verrou que forge/ledger.py).
    let mut head = app.ledger_lock.lock().unwrap_or_else(|e| e.into_inner());
    // B5 — LEDGER MULTI-INSTANCE : sous HA le fichier est aussi PARTAGÉ entre réplicas ; on garde le
    // verrou consultatif PG cross-INSTANCE (`ha::with_ledger_lock`) EN PLUS du flock cross-PROCESSUS.
    // Les deux sont complémentaires et IMBRIQUÉS (PG dehors, flock dedans) — pas deux mécanismes
    // disjoints/alternatifs : le flock sérialise les processus d'un même host (console + moteur), le
    // verrou PG sérialise les réplicas d'un cluster. Single-instance (!ha) : PG = pass-through, seul le
    // flock (+ mutex in-proc) gouverne. Fire-and-forget (63 sites) : sous une panne FAIL-CLOSED HA
    // l'append est REFUSÉ ; F5 OBSERVABILITY : on log le `kind` + la raison (entrée d'audit perdue visible).
    if let Err(e) = crate::ha::with_ledger_lock(app, path, || {
        match append_sha256_console_locked(path, kind, &detail) {
            Ok((_prev, seq, hash)) => {
                // le cache est mis à jour mais N'EST PLUS la source du prochain seq (toujours relu du disque).
                head.prev = hash;
                head.seq = seq;
                head.loaded = true;
            }
            Err(err) => {
                head.loaded = false;
                eprintln!("[forge] LEDGER DROP — {err} (kind={kind}) : entrée d'audit PERDUE");
            }
        }
    }) {
        // FAIL-CLOSED outage (PG advisory lock unreachable across the retry budget). `with_ledger_lock`
        // already logged the outage; here we ADD the `kind` of the specific dropped entry so the lost
        // attestation is traceable, not just "an append failed somewhere".
        eprintln!("[forge] LEDGER DROP — entrée d'audit REFUSÉE (kind={kind}) : {e}");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// M1 — PARITÉ canon_str vs Python `json.dumps(obj, ensure_ascii=False)` sur TOUS les octets de
    /// contrôle 0x00..0x1f. Python émet les SHORT escapes `\b \t \n \f \r` (0x08,0x09,0x0a,0x0c,0x0d) et
    /// `\u00xx` (hex minuscule) pour le reste ; `"` et `\` s'échappent aussi. Avant le fix, 0x08/0x0c
    /// sortaient en ``/`` côté Rust -> préimage divergent -> fausse « entrée altérée ».
    /// Les valeurs attendues ci-dessous sont EXACTEMENT ce que produit `json.dumps` (hardcodées, pas
    /// dérivées du code testé) — c'est une preuve byte-à-byte de la parité.
    #[test]
    fn canon_str_matches_python_json_dumps_control_bytes() {
        // Le short-escape Python attendu pour chaque octet de contrôle (None => \u00xx générique).
        let short = |b: u32| -> Option<&'static str> {
            match b {
                0x08 => Some("\\b"),
                0x09 => Some("\\t"),
                0x0a => Some("\\n"),
                0x0c => Some("\\f"),
                0x0d => Some("\\r"),
                _ => None,
            }
        };
        for b in 0x00u32..=0x1f {
            let c = char::from_u32(b).unwrap();
            let s: String = c.to_string();
            let got = canon_json(&Value::String(s));
            let expected = match short(b) {
                Some(esc) => format!("\"{esc}\""),
                None => format!("\"\\u{b:04x}\""), // json.dumps : \u00xx, hex MINUSCULE
            };
            assert_eq!(got, expected, "canon_str diverge de json.dumps pour l'octet 0x{b:02x}");
        }
        // Sanity : `"` et `\` restent échappés comme json.dumps (\" et \\).
        assert_eq!(canon_json(&Value::String("\"".into())), "\"\\\"\"");
        assert_eq!(canon_json(&Value::String("\\".into())), "\"\\\\\"");
        // Sanity : l'UTF-8 non-contrôle est laissé tel quel (ensure_ascii=False).
        assert_eq!(canon_json(&Value::String("é→😀".into())), "\"é→😀\"");
    }
}

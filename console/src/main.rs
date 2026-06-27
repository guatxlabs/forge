//! Forge console — store + API pour les findings/run-records de Forge.
//!
//! Fork minimal de la colonne Plume (axum + rusqlite, binaire unique). Donne à Forge :
//!   - un store SQLite du modèle ROUGE (finding / runrecord) — au lieu d'event/metric côté Plume ;
//!   - `POST /api/ingest` (token bearer) = LE point de jonction de la boucle purple : le moteur
//!     Python POSTe ses findings + run-records ATT&CK ici ; Plume corrèle ensuite par champ `mitre` ;
//!   - des endpoints de lecture (findings / runrecords / coverage) + une console opérateur minimale.
//!
//! Bind 127.0.0.1 par défaut. `ingest` exige le token ; les lectures sont localhost-only (v0).
//! Durcissement prévu (réutiliser auth_guard/RBAC de Plume) : voir ARCHITECTURE.md. Single binary.

use guatx_core::soql; // cœur partagé (extrait) — remplace l'ancien `mod soql;`

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use base64::Engine;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;

use axum::response::sse::{Event, KeepAlive, Sse};
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex as AsyncMutex};

// SCHEMA de base (idempotent — execute_batch). Les ajouts de colonnes sur les tables existantes
// passent par `migrate()` (ALTER error-ignored) pour ne pas casser une base déjà peuplée.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS campaign(id INTEGER PRIMARY KEY, name TEXT, started TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS finding(
  id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, title TEXT, severity TEXT,
  category TEXT, mitre TEXT, status TEXT, evidence TEXT, tool TEXT, poc TEXT,
  UNIQUE(campaign, target, title) ON CONFLICT IGNORE);
CREATE TABLE IF NOT EXISTS runrecord(
  id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, kind TEXT, mitre TEXT,
  fired INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS panel(
  id INTEGER PRIMARY KEY, name TEXT, query TEXT, viz TEXT DEFAULT 'table', position INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS dashboard(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, descr TEXT DEFAULT '', position INTEGER DEFAULT 0,
  created TEXT DEFAULT '', updated TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS module(
  kind TEXT PRIMARY KEY, exploit INTEGER DEFAULT 0, destructive INTEGER DEFAULT 0,
  available INTEGER DEFAULT 1, mitre TEXT DEFAULT '', descr TEXT DEFAULT '',
  web_allowed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS roe_decision(
  id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, run_id TEXT, action_id TEXT, target TEXT,
  kind TEXT, verdict TEXT, exploit INTEGER DEFAULT 0, destructive INTEGER DEFAULT 0, reasons TEXT);
CREATE TABLE IF NOT EXISTS run_job(
  id INTEGER PRIMARY KEY, run_id TEXT UNIQUE, campaign TEXT, ts TEXT, status TEXT,
  mode TEXT, fired INTEGER DEFAULT 0, dry_run INTEGER DEFAULT 0, vetoed INTEGER DEFAULT 0,
  errors INTEGER DEFAULT 0, skipped_budget TEXT DEFAULT '[]', coverage_gaps TEXT DEFAULT '{}', detail TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS ledger_entry(
  seq INTEGER PRIMARY KEY, ts TEXT, kind TEXT, detail TEXT, prev TEXT, hash TEXT, alg TEXT, sig TEXT);
CREATE TABLE IF NOT EXISTS run_log(
  id INTEGER PRIMARY KEY, run_id TEXT, ts TEXT, stream TEXT, line TEXT);
CREATE INDEX IF NOT EXISTS idx_run_log_run ON run_log(run_id, id);
";

/// Migrations additives (ALTER) — chaque ALTER est error-ignored : si la colonne existe déjà
/// (base ancienne ou re-boot) SQLite renvoie une erreur qu'on absorbe. Idempotent.
fn migrate(db: &Connection) {
    let alters = [
        // run_id corrèle finding/runrecord avec le run_job qui les a produits (boucle purple).
        "ALTER TABLE finding ADD COLUMN run_id TEXT DEFAULT ''",
        "ALTER TABLE finding ADD COLUMN fix TEXT DEFAULT ''",
        "ALTER TABLE runrecord ADD COLUMN run_id TEXT DEFAULT ''",
        // panel étendu : description, largeur de colonne, horodatage de mise à jour.
        "ALTER TABLE panel ADD COLUMN descr TEXT DEFAULT ''",
        "ALTER TABLE panel ADD COLUMN col_span INTEGER DEFAULT 1",
        "ALTER TABLE panel ADD COLUMN updated TEXT DEFAULT ''",
        // dashboard_id : un panel appartient à un dashboard (vue). DEFAULT 1 = dashboard par défaut
        // (créé/garanti au boot par ensure_default_dashboard) -> rétro-compat : les panels existants
        // d'une base ancienne héritent du dashboard #1 sans intervention.
        "ALTER TABLE panel ADD COLUMN dashboard_id INTEGER DEFAULT 1",
        // run_job étendu (C2-light) : provenance opérateur + traçage du process spawné.
        // `pid` = PID du groupe de process (setsid) pour cancel/watchdog ; -1 si terminé.
        "ALTER TABLE run_job ADD COLUMN pid INTEGER DEFAULT -1",
        "ALTER TABLE run_job ADD COLUMN started_by TEXT DEFAULT ''",
        "ALTER TABLE run_job ADD COLUMN reason TEXT DEFAULT ''",
        "ALTER TABLE run_job ADD COLUMN targets TEXT DEFAULT '[]'",
        "ALTER TABLE run_job ADD COLUMN modules TEXT DEFAULT '[]'",
        "ALTER TABLE run_job ADD COLUMN started TEXT DEFAULT ''",
        "ALTER TABLE run_job ADD COLUMN finished TEXT DEFAULT ''",
        "ALTER TABLE run_job ADD COLUMN exit_code INTEGER DEFAULT NULL",
    ];
    for a in alters {
        let _ = db.execute(a, []); // error-ignored (colonne déjà présente)
    }
}

/// Garantit l'existence du dashboard par défaut (id=1) — rétro-compat : la colonne `panel.dashboard_id`
/// a DEFAULT 1, donc tout panel pré-existant pointe déjà ici. Idempotent (INSERT OR IGNORE sur id=1).
/// Recale aussi les panels orphelins (dashboard_id NULL/0/inexistant) vers le dashboard #1.
fn ensure_default_dashboard(db: &Connection) {
    let _ = db.execute(
        "INSERT OR IGNORE INTO dashboard(id,name,descr,position,created,updated)
         VALUES(1,'Défaut','Dashboard par défaut (rétro-compat)',0,datetime('now'),datetime('now'))",
        [],
    );
    // panels sans dashboard valide -> rattachés au défaut (ne casse jamais un panel existant).
    let _ = db.execute(
        "UPDATE panel SET dashboard_id=1
         WHERE dashboard_id IS NULL OR dashboard_id NOT IN (SELECT id FROM dashboard)",
        [],
    );
}

/// `web_allowed` : un module est lançable depuis l'UI web seulement s'il n'exploite pas, n'est pas
/// destructif, et n'est pas l'interception IDOR (qui tamper une requête en vol — réservé CLI/opérateur).
fn module_web_allowed(kind: &str, exploit: bool, destructive: bool) -> bool {
    !exploit && !destructive && kind != "evasion.idor_intercept"
}

/// Résout le répertoire des assets web statiques (style.css/app.js/fonts/…) de façon robuste,
/// indépendamment du cwd — sans ça, le défaut relatif `"web"` est servi en 0 octet quand la console
/// est lancée hors `console/` (seul index.html survit via include_str!). Ordre de priorité :
///   1) $FORGE_CONSOLE_WEB s'il est posé (override explicite de l'opérateur) ;
///   2) <dir-du-binaire>/web et <dir-du-binaire>/../web (cas `./target/{debug,release}/forge-console`
///      lancé de n'importe où : les assets sont copiés/symlinkés à côté, ou restent dans console/web) ;
///   3) $FORGE_PKG_DIR/console/web puis ./console/web puis ./web (cas lancé depuis console/ ou la racine) ;
///   4) repli `"web"` (comportement historique, lancé depuis console/).
fn resolve_web_dir() -> String {
    if let Ok(w) = std::env::var("FORGE_CONSOLE_WEB") {
        if !w.is_empty() {
            return w;
        }
    }
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // assets copiés/symlinkés à côté du binaire (déploiement)
            candidates.push(dir.join("web"));
            // ./console/target/{debug,release}/forge-console -> remonter au crate console/, puis web/
            // (target/release -> target -> console -> console/web)
            candidates.push(dir.join("..").join("..").join("web"));
            // tolérance si le binaire est une marche plus haut (target/forge-console)
            candidates.push(dir.join("..").join("web"));
        }
    }
    if let Ok(pkg) = std::env::var("FORGE_PKG_DIR") {
        candidates.push(std::path::PathBuf::from(&pkg).join("console").join("web"));
    }
    candidates.push(std::path::PathBuf::from("console").join("web"));
    candidates.push(std::path::PathBuf::from("web"));
    for c in &candidates {
        if c.join("style.css").is_file() {
            return c.to_string_lossy().into_owned();
        }
    }
    // aucun asset trouvé : repli historique (au moins index.html via include_str! reste servi).
    "web".to_string()
}

/// Charge le scope serveur autorisé (in_scope + mode) pour pré-filtrer les cibles lançables via le
/// web. Source : $FORGE_CONSOLE_SCOPE s'il pointe un scope.json ; sinon <pkg_dir>/scope.json. Si rien
/// n'est trouvé/parsable -> in_scope VIDE (fail-closed : aucune cible lançable depuis le web).
fn load_server_scope(pkg_dir: &str) -> (Vec<String>, String) {
    let path = std::env::var("FORGE_CONSOLE_SCOPE")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| std::path::Path::new(pkg_dir).join("scope.json").to_string_lossy().into_owned());
    match std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
        Some(v) => {
            let in_scope = v.get("in_scope").and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let mode = v.get("mode").and_then(|m| m.as_str()).unwrap_or("grey").to_string();
            (in_scope, mode)
        }
        None => {
            eprintln!("[forge-console] scope serveur introuvable ({path}) — C2 fail-closed (aucune cible lançable)");
            (vec![], "grey".to_string())
        }
    }
}

/// Peuple la table `module` au boot depuis le registre Python (`python3 -m forge.cli modules`).
/// Tente d'abord `--json` (si la CLI le supporte un jour), sinon parse la sortie texte :
///   "  <kind>   exploit=<bool> destructive=<bool>". Best-effort : si python/forge absent, on
///   laisse la table en l'état (les lectures /api/modules renverront ce qu'il y a). `forge` est
///   importé depuis le parent du cwd console ; on lance depuis FORGE_PKG_DIR si défini, sinon `..`.
fn populate_modules(db: &Connection) {
    let pkg_dir = std::env::var("FORGE_PKG_DIR").unwrap_or_else(|_| "..".to_string());
    let py = std::env::var("FORGE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    // 1) essai JSON
    let parsed = std::process::Command::new(&py)
        .args(["-m", "forge.cli", "modules", "--json"])
        .current_dir(&pkg_dir)
        .output()
        .ok()
        .and_then(|o| if o.status.success() { parse_modules_json(&String::from_utf8_lossy(&o.stdout)) } else { None })
        // 2) repli texte
        .or_else(|| {
            std::process::Command::new(&py)
                .args(["-m", "forge.cli", "modules"])
                .current_dir(&pkg_dir)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| parse_modules_text(&String::from_utf8_lossy(&o.stdout)))
        });
    let mods = match parsed {
        Some(m) if !m.is_empty() => m,
        _ => {
            eprintln!("[forge-console] modules: registre Python indisponible (table `module` inchangée)");
            return;
        }
    };
    let mut n = 0;
    for m in &mods {
        let kind = m.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if kind.is_empty() { continue; }
        let exploit = m.get("exploit").and_then(|v| v.as_bool()).unwrap_or(false);
        let destructive = m.get("destructive").and_then(|v| v.as_bool()).unwrap_or(false);
        let available = m.get("available").and_then(|v| v.as_bool()).unwrap_or(true);
        let mitre = m.get("mitre").and_then(|v| v.as_str()).unwrap_or("");
        let descr = m.get("descr").or_else(|| m.get("desc")).and_then(|v| v.as_str()).unwrap_or("");
        let web_allowed = module_web_allowed(kind, exploit, destructive);
        let _ = db.execute(
            "INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed)
             VALUES(?,?,?,?,?,?,?)
             ON CONFLICT(kind) DO UPDATE SET exploit=excluded.exploit, destructive=excluded.destructive,
               available=excluded.available, mitre=excluded.mitre, descr=excluded.descr, web_allowed=excluded.web_allowed",
            rusqlite::params![kind, exploit as i64, destructive as i64, available as i64, mitre, descr, web_allowed as i64],
        );
        n += 1;
    }
    println!("[forge-console] modules: {n} enregistrés dans la table `module`");
}

fn parse_modules_json(s: &str) -> Option<Vec<Value>> {
    let v: Value = serde_json::from_str(s.trim()).ok()?;
    match v {
        Value::Array(a) => Some(a),
        Value::Object(ref o) => o.get("modules").and_then(|m| m.as_array()).cloned(),
        _ => None,
    }
}

/// Parse la sortie texte de `forge modules` :
///   "Modules enregistrés :"
///   "  access_control.idor      exploit=True destructive=False"
fn parse_modules_text(s: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in s.lines() {
        let t = line.trim();
        if t.is_empty() || !t.contains("exploit=") { continue; }
        let kind = match t.split_whitespace().next() { Some(k) => k, None => continue };
        let exploit = t.contains("exploit=True");
        let destructive = t.contains("destructive=True");
        out.push(json!({ "kind": kind, "exploit": exploit, "destructive": destructive }));
    }
    out
}

/// Évènement SSE diffusé pendant un run (lignes stdout/stderr du moteur + transitions de statut).
#[derive(Clone)]
struct RunEvent {
    run_id: String,
    kind: String, // "log" | "status"
    payload: Value,
}

/// État partagé du run courant (C2-light : un seul run à la fois — FIFO).
/// `current` est `Some` tant qu'un run est vivant ; protège la sérialisation FIFO via le verrou
/// async dans /api/run (refus 409 si déjà occupé). Le `broadcast::Sender` SSE vit hors de ce verrou
/// (clone lock-free dans App.events) pour que les pompes stdout puissent diffuser sans le prendre.
struct RunState {
    current: Option<RunHandle>,
}

struct RunHandle {
    run_id: String,
    pgid: i32, // group de process (setsid) -> kill group pour cancel/watchdog
}

#[derive(Clone)]
struct App {
    db: Arc<Mutex<Connection>>,
    db_path: Arc<String>,
    token_sha: Arc<String>,
    token_raw: Arc<String>,          // token bearer EN CLAIR — passé au moteur spawné pour /api/ingest
    user: Arc<String>,
    pass_hash: Arc<String>,          // argon2id ; vide = auth OFF (dev localhost)
    operator_hash: Arc<String>,      // argon2id du rôle OPÉRATEUR (C2) ; vide => FAIL-CLOSED (403 sur tout C2)
    allowed_hosts: Arc<Vec<String>>, // anti-DNS-rebinding
    ledger_path: Arc<String>,        // JSONL du ledger d'engagement (FORGE_CONSOLE_LEDGER)
    pkg_dir: Arc<String>,            // racine du paquet Forge (cwd du spawn `python -m forge.cli`)
    python: Arc<String>,            // interpréteur python (FORGE_PYTHON, défaut python3)
    scope_in: Arc<Vec<String>>,      // in_scope autorisé (recopié dans le scope du run, fail-closed)
    scope_mode: Arc<String>,         // mode du scope (white|grey|black) recopié tel quel
    // PURPLE (défensif) : URL de la colonne BLEUE Plume (SOC) + credential pour interroger
    // GET {plume_url}/api/coverage/detections. Vide => couverture purple en FAIL-OPEN LISIBLE
    // (plume_reachable:false). plume_token = base64 d'un `user:pass` envoyé en `Authorization: Basic`
    // (la route détections de Plume exige Basic/SSO ; les Bearer d'agent n'y sont PAS acceptés). Vide
    // => aucun en-tête d'auth (cas SOC_PUBLIC_DEMO=1 côté Plume).
    plume_url: Arc<String>,
    plume_token: Arc<String>,
    run_timeout_secs: u64,           // watchdog (FORGE_RUN_TIMEOUT, défaut 1800s)
    run_state: Arc<AsyncMutex<RunState>>,
    events: broadcast::Sender<RunEvent>, // bus SSE lock-free (clone du Sender)
    // Sérialise lecture-head -> calcul -> écriture du ledger JSONL (anti-race : deux appends
    // concurrents liraient le MÊME prev/seq et casseraient la chaîne SHA-256). Cache aussi le head
    // (prev,seq) pour éviter de relire tout le fichier à chaque append (O(n²) -> O(1) amorti).
    ledger_lock: Arc<Mutex<LedgerHead>>,
}

/// Head courant du ledger console (dernier hash + dernière seq), maintenu sous `ledger_lock`.
/// `loaded=false` => pas encore initialisé depuis le disque (lecture paresseuse au 1er append).
#[derive(Default)]
struct LedgerHead {
    prev: String,
    seq: i64,
    loaded: bool,
}

impl App {
    /// Verrouille la connexion SQLite en RÉCUPÉRANT un mutex empoisonné (un panic en section
    /// critique empoisonnait le Mutex et tout `.lock().unwrap()` ultérieur paniquait à son tour ->
    /// DoS API permanent). `into_inner()` reprend la garde : la connexion rusqlite reste utilisable
    /// (une requête échouée renvoie une Err, pas un état mémoire corrompu). Fail-open contrôlé.
    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn sha_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

/// Comparaison à TEMPS CONSTANT de deux empreintes (anti timing-oracle sur le bearer/token).
/// Les deux opérandes sont des hex de sha256 (longueur fixe 64) -> la divulgation de longueur est
/// inoffensive ; on protège contre la fuite octet-par-octet d'un `==` court-circuitant.
fn ct_eq_str(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn gen_token() -> String {
    // CSPRNG OS (getrandom) — le Result DOIT être propagé : un échec d'entropie laisserait un buffer
    // tous-zeros et produirait un token bearer PRÉVISIBLE (auth /api/ingest contournable). On panique
    // plutôt que de générer un secret faible (fail-closed sur l'entropie).
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("CSPRNG (getrandom) indisponible — refus de générer un token faible");
    hex(&b)
}

fn gs(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

// --- auth opérateur (argon2) + RBAC, repris du modèle auth_guard/host_guard de Plume ---

fn verify_pw(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .map(|ph| Argon2::default().verify_password(pw.as_bytes(), &ph).is_ok())
        .unwrap_or(false)
}

fn hash_pw(pw: &str) -> String {
    // Sel argon2id via CSPRNG OS (getrandom) — le Result DOIT être propagé : un échec d'entropie
    // laisserait un sel tous-zeros (CONSTANT) -> hash identique pour un même mot de passe sur toutes
    // les installs, cassant la résistance aux rainbow tables. On panique plutôt que de saler à zéro.
    let mut s = [0u8; 16];
    getrandom::getrandom(&mut s).expect("CSPRNG (getrandom) indisponible — refus de générer un sel faible");
    let salt = SaltString::encode_b64(&s).expect("salt");
    Argon2::default().hash_password(pw.as_bytes(), &salt).expect("hash").to_string()
}

fn check_basic(app: &App, b64: &str) -> bool {
    let raw = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let s = match String::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut it = s.splitn(2, ':');
    let u = it.next().unwrap_or("");
    let p = it.next().unwrap_or("");
    u == app.user.as_str() && verify_pw(p, &app.pass_hash)
}

// --- rôle OPÉRATEUR (C2-light) — FAIL-CLOSED, indépendant du viewer ---
//
// Le lancement de campagnes (POST /api/run, cancel) est une capacité PRIVILÉGIÉE, distincte de la
// simple lecture du dashboard (viewer Basic/Bearer). Elle exige une preuve d'opérateur dédiée via
// l'en-tête `X-Forge-Operator: <mot de passe>` vérifiée contre `operator_hash` (argon2id).
//
// FAIL-CLOSED : si `operator_hash` est vide (non configuré), AUCUN endpoint C2 n'est ouvert — 403,
// même quand le viewer tourne en mode dev-open (pass_hash vide). check_operator NE consulte JAMAIS
// pass_hash/token : l'authz C2 est totalement découplée de l'auth viewer. Sous-commande pour le
// hash : `forge-console hashpw-operator <mot de passe>`.

/// Vrai seulement si un opérateur est configuré ET que l'en-tête `X-Forge-Operator` correspond.
/// Vide => toujours faux (fail-closed). Aucune dépendance au viewer (pass_hash/token).
fn check_operator(app: &App, headers: &HeaderMap) -> bool {
    if app.operator_hash.is_empty() {
        return false; // FAIL-CLOSED : rôle opérateur non provisionné -> tout C2 refusé
    }
    let supplied = headers
        .get("x-forge-operator")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if supplied.is_empty() {
        return false;
    }
    verify_pw(supplied, &app.operator_hash)
}

/// Réponse standard d'un refus C2 (403). Distingue « non provisionné » (501-like message) de
/// « mauvaise preuve » sans fuir lequel — message stable, code 403 dans les deux cas (fail-closed).
fn operator_denied(app: &App) -> (StatusCode, Json<Value>) {
    let why = if app.operator_hash.is_empty() {
        "rôle opérateur non provisionné (FORGE_CONSOLE_OPERATOR_HASH absent) — C2 fermé"
    } else {
        "preuve opérateur invalide ou absente (en-tête X-Forge-Operator requis)"
    };
    (StatusCode::FORBIDDEN, Json(json!({"error": "operator_required", "why": why})))
}

/// Validation stricte d'un nom de campagne : `[A-Za-z0-9._-]{1,64}`, jamais vide, pas de `-` en
/// tête (anti confusion avec un flag CLI). Renvoie la valeur validée ou une erreur.
fn validate_campaign(s: &str) -> Result<String, String> {
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
fn validate_host(s: &str) -> Result<String, String> {
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

/// Anti-DNS-rebinding : l'en-tête Host doit être NON VIDE et présent dans l'allowlist.
/// FAIL-CLOSED : un Host absent/vide est REFUSÉ (avant, il passait — fail-open exploitable par un
/// client qui omet/efface Host pour contourner le filtre anti-rebinding). 421 dans tous les cas non
/// autorisés (Host vide OU hors allowlist).
async fn host_guard(State(app): State<App>, req: Request, next: Next) -> Response {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    if host_allowed(host, &app.allowed_hosts) {
        next.run(req).await
    } else {
        (StatusCode::MISDIRECTED_REQUEST, "host non autorisé (anti-rebinding)").into_response()
    }
}

/// Décision pure du host_guard (testable) : le Host (port retiré) doit être NON VIDE et présent dans
/// l'allowlist. FAIL-CLOSED sur Host vide/absent.
fn host_allowed(host_header: &str, allowed: &[String]) -> bool {
    let h = host_header.split(':').next().unwrap_or("");
    !h.is_empty() && allowed.iter().any(|a| a == h)
}

/// RBAC : si un hash est configuré, exige Basic (opérateur=viewer) OU Bearer (agent/admin=token).
/// Sans hash -> mode dev localhost ouvert (les ÉCRITURES restent gatées par leur propre check_token).
async fn auth_guard(State(app): State<App>, req: Request, next: Next) -> Response {
    if app.pass_hash.is_empty() {
        return next.run(req).await;
    }
    let authz = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(b64) = authz.strip_prefix("Basic ") {
        if check_basic(&app, b64.trim()) {
            return next.run(req).await;
        }
    }
    if let Some(tok) = authz.strip_prefix("Bearer ") {
        if ct_eq_str(&sha_hex(tok.trim()), &app.token_sha) {
            return next.run(req).await;
        }
    }
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Basic realm=\"forge\"")],
        "auth requise",
    )
        .into_response()
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

/// Vérifie le bearer token (sha256). Gate des écritures (ingest, panels).
fn check_token(app: &App, headers: &HeaderMap) -> bool {
    let tok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    ct_eq_str(&sha_hex(tok), &app.token_sha)
}

async fn ingest(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_token(&app, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    }
    let campaign = body.get("campaign").and_then(|v| v.as_str()).unwrap_or("default").to_string();
    // run_id : corrèle ce lot de findings/run-records/décisions au run qui les a produits.
    let run_id = body.get("run_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let db = app.db();
    let (mut nf, mut nr, mut nd) = (0i64, 0i64, 0i64);
    if let Some(arr) = body.get("findings").and_then(|v| v.as_array()) {
        for f in arr {
            if let Ok(n) = db.execute(
                "INSERT OR IGNORE INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![gs(f,"ts"), campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                    gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                    gs(f,"fix"), run_id],
            ) {
                nf += n as i64;
            }
        }
    }
    if let Some(arr) = body.get("run_records").and_then(|v| v.as_array()) {
        for rr in arr {
            let fired = if rr.get("fired").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
            if let Ok(n) = db.execute(
                "INSERT INTO runrecord(ts,campaign,target,kind,mitre,fired,detail,run_id) VALUES(?,?,?,?,?,?,?,?)",
                rusqlite::params![gs(rr,"ts"), campaign, gs(rr,"target"), gs(rr,"kind"), gs(rr,"mitre"), fired, gs(rr,"detail"), run_id],
            ) {
                nr += n as i64;
            }
        }
    }
    // roe_decisions : verdict par action (VETO/DRY_RUN/FIRE) — alimente GET /api/roe (transparence anti-masquage).
    if let Some(arr) = body.get("roe_decisions").and_then(|v| v.as_array()) {
        for d in arr {
            let ex = if d.get("exploit").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
            let de = if d.get("destructive").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
            let reasons = d.get("reasons").map(|r| r.to_string()).unwrap_or_else(|| "[]".into());
            if let Ok(n) = db.execute(
                "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons)
                 VALUES(?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![gs(d,"ts"), campaign, run_id, gs(d,"action_id"), gs(d,"target"),
                    gs(d,"kind"), gs(d,"verdict"), ex, de, reasons],
            ) {
                nd += n as i64;
            }
        }
    }
    // run_job : si la console connaît ce run_id, on enregistre/actualise ses compteurs de couverture.
    if !run_id.is_empty() {
        let cov = body.get("coverage").cloned().unwrap_or_else(|| json!({}));
        let geti = |k: &str| cov.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        let gaps = body.get("coverage_gaps").map(|g| g.to_string()).unwrap_or_else(|| "{}".into());
        let skipped = body.get("skipped_budget").map(|s| s.to_string()).unwrap_or_else(|| "[]".into());
        let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let _ = db.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps)
             VALUES(?,?,datetime('now'),'done',?,?,?,?,?,?,?)
             ON CONFLICT(run_id) DO UPDATE SET status='done', mode=excluded.mode, fired=excluded.fired,
               dry_run=excluded.dry_run, vetoed=excluded.vetoed, errors=excluded.errors,
               skipped_budget=excluded.skipped_budget, coverage_gaps=excluded.coverage_gaps",
            rusqlite::params![run_id, campaign, mode, geti("fired"), geti("dry_run"),
                geti("vetoed"), geti("errors"), skipped, gaps],
        );
    }
    (StatusCode::OK, Json(json!({"findings_ingested": nf, "runrecords_ingested": nr, "roe_decisions_ingested": nd})))
}

#[allow(dead_code)] // helper générique conservé (colonnes texte) ; les handlers typés le court-circuitent.
fn rows_to_json(db: &Connection, sql: &str, args: &[String], cols: &[&str]) -> Vec<Value> {
    let mut stmt = match db.prepare(sql) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let ncol = cols.len();
    let mapped = stmt.query_map(rusqlite::params_from_iter(args.iter()), |row| {
        let mut o = serde_json::Map::new();
        for (i, c) in cols.iter().enumerate() {
            let v = row.get::<_, Option<String>>(i).unwrap_or(None);
            o.insert((*c).to_string(), json!(v.unwrap_or_default()));
        }
        let _ = ncol;
        Ok(Value::Object(o))
    });
    match mapped {
        Ok(it) => it.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    }
}

/// LIMIT/OFFSET bornés et validés (anti-injection : on n'inline que des entiers parsés).
fn paginate(q: &HashMap<String, String>, default_limit: i64, max_limit: i64) -> (i64, i64) {
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(default_limit).clamp(1, max_limit);
    let offset = q.get("offset").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0).max(0);
    (limit, offset)
}

async fn findings(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let db = app.db();
    let (mut conds, mut args): (Vec<&str>, Vec<String>) = (vec![], vec![]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?"); args.push(c.clone()); }
    if let Some(s) = q.get("severity") { conds.push("severity=?"); args.push(s.clone()); }
    if let Some(s) = q.get("status") { conds.push("status=?"); args.push(s.clone()); }
    if let Some(t) = q.get("target") { conds.push("target=?"); args.push(t.clone()); }
    if let Some(m) = q.get("mitre") { conds.push("mitre=?"); args.push(m.clone()); }
    if let Some(r) = q.get("run_id") { conds.push("run_id=?"); args.push(r.clone()); }
    let where_ = if conds.is_empty() { String::new() } else { format!(" WHERE {}", conds.join(" AND ")) };
    let total: i64 = db
        .query_row(&format!("SELECT COUNT(*) FROM finding{where_}"), rusqlite::params_from_iter(args.iter()), |r| r.get(0))
        .unwrap_or(0);
    let (limit, offset) = paginate(&q, 200, 1000);
    let sql = format!(
        "SELECT id,ts,campaign,target,title,severity,category,mitre,status,tool,run_id FROM finding{where_} ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
    );
    // requête typée : `id` est un entier (rows_to_json le rendrait vide en le lisant comme String).
    let mut stmt = match db.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Json(json!({"total": total, "limit": limit, "offset": offset, "findings": []})),
    };
    let rows: Vec<Value> = stmt
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "ts": r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                "campaign": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                "target": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                "title": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                "severity": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "category": r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                "mitre": r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                "status": r.get::<_, Option<String>>(8)?.unwrap_or_default(),
                "tool": r.get::<_, Option<String>>(9)?.unwrap_or_default(),
                "run_id": r.get::<_, Option<String>>(10)?.unwrap_or_default(),
            }))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    Json(json!({"total": total, "limit": limit, "offset": offset, "findings": rows}))
}

async fn finding_detail(State(app): State<App>, Path(id): Path<i64>) -> impl IntoResponse {
    let db = app.db();
    let row = db.query_row(
        "SELECT id,ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id FROM finding WHERE id=?",
        [id],
        |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "ts": r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                "campaign": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                "target": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                "title": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                "severity": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "category": r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                "mitre": r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                "status": r.get::<_, Option<String>>(8)?.unwrap_or_default(),
                "evidence": r.get::<_, Option<String>>(9)?.unwrap_or_default(),
                "tool": r.get::<_, Option<String>>(10)?.unwrap_or_default(),
                "poc": r.get::<_, Option<String>>(11)?.unwrap_or_default(),
                "fix": r.get::<_, Option<String>>(12)?.unwrap_or_default(),
                "run_id": r.get::<_, Option<String>>(13)?.unwrap_or_default(),
            }))
        },
    );
    match row {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({"error": "finding introuvable"}))),
    }
}

async fn runrecords(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let db = app.db();
    let (mut conds, mut args): (Vec<&str>, Vec<String>) = (vec![], vec![]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?"); args.push(c.clone()); }
    if let Some(t) = q.get("target") { conds.push("target=?"); args.push(t.clone()); }
    if let Some(m) = q.get("mitre") { conds.push("mitre=?"); args.push(m.clone()); }
    if let Some(r) = q.get("run_id") { conds.push("run_id=?"); args.push(r.clone()); }
    if q.get("fired").map(|v| v == "1" || v == "true").unwrap_or(false) { conds.push("fired=1"); }
    let where_ = if conds.is_empty() { String::new() } else { format!(" WHERE {}", conds.join(" AND ")) };
    let (limit, offset) = paginate(&q, 500, 2000);
    let sql = format!(
        "SELECT id,ts,campaign,target,kind,mitre,fired,detail,run_id FROM runrecord{where_} ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
    );
    // `fired` est un entier (0/1) — colonne réelle ; on la rend telle quelle via une requête typée.
    let mut stmt = match db.prepare(&sql) { Ok(s) => s, Err(_) => return Json(json!([])) };
    let out: Vec<Value> = stmt
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "ts": r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                "campaign": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                "target": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                "kind": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                "mitre": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "fired": r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                "detail": r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                "run_id": r.get::<_, Option<String>>(8)?.unwrap_or_default(),
            }))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    Json(Value::Array(out))
}

async fn modules(State(app): State<App>) -> impl IntoResponse {
    let db = app.db();
    let mut stmt = match db.prepare(
        "SELECT kind,exploit,destructive,available,mitre,descr,web_allowed FROM module ORDER BY kind",
    ) { Ok(s) => s, Err(_) => return Json(json!([])) };
    let out: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "kind": r.get::<_, String>(0)?,
                "exploit": r.get::<_, i64>(1)? != 0,
                "destructive": r.get::<_, i64>(2)? != 0,
                "available": r.get::<_, i64>(3)? != 0,
                "mitre": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                "descr": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "web_allowed": r.get::<_, i64>(6)? != 0,
            }))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    Json(Value::Array(out))
}

async fn campaigns(State(app): State<App>) -> impl IntoResponse {
    let db = app.db();
    // Agrège depuis les findings (source réelle) + table campaign (métadonnées). Pas de JOIN strict :
    // on liste les campagnes vues côté findings + celles déclarées, avec leurs compteurs.
    let mut stmt = match db.prepare(
        "SELECT campaign, COUNT(*) AS findings, MAX(ts) AS last_ts FROM finding WHERE campaign<>'' GROUP BY campaign ORDER BY last_ts DESC",
    ) { Ok(s) => s, Err(_) => return Json(json!([])) };
    let out: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "campaign": r.get::<_, String>(0)?,
                "findings": r.get::<_, i64>(1)?,
                "last_ts": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            }))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    Json(Value::Array(out))
}

async fn roe(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let db = app.db();
    let (mut conds, mut args): (Vec<&str>, Vec<String>) = (vec![], vec![]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?"); args.push(c.clone()); }
    if let Some(r) = q.get("run_id") { conds.push("run_id=?"); args.push(r.clone()); }
    if let Some(v) = q.get("verdict") { conds.push("verdict=?"); args.push(v.clone()); }
    let where_ = if conds.is_empty() { String::new() } else { format!(" WHERE {}", conds.join(" AND ")) };
    let (limit, offset) = paginate(&q, 500, 2000);
    let sql = format!(
        "SELECT id,ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons FROM roe_decision{where_} ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
    );
    let mut stmt = match db.prepare(&sql) { Ok(s) => s, Err(_) => return Json(json!([])) };
    let out: Vec<Value> = stmt
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            // reasons stocké en JSON (array) — on le re-parse pour le rendre structuré au front.
            let reasons_raw: String = r.get::<_, Option<String>>(10)?.unwrap_or_default();
            let reasons = serde_json::from_str::<Value>(&reasons_raw).unwrap_or(Value::String(reasons_raw));
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "ts": r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                "campaign": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                "run_id": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                "action_id": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                "target": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "kind": r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                "verdict": r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                "exploit": r.get::<_, i64>(8)? != 0,
                "destructive": r.get::<_, i64>(9)? != 0,
                "reasons": reasons,
            }))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    Json(Value::Array(out))
}

fn cell(row: &rusqlite::Row, i: usize) -> Value {
    match row.get_ref(i) {
        Ok(ValueRef::Null) | Err(_) => Value::Null,
        Ok(ValueRef::Integer(n)) => json!(n),
        Ok(ValueRef::Real(f)) => json!(f),
        Ok(ValueRef::Text(t)) => json!(String::from_utf8_lossy(t)),
        Ok(ValueRef::Blob(_)) => Value::Null,
    }
}

/// Compile soql -> SQL et l'exécute sur une connexion SQLITE_OPEN_READ_ONLY (défense en profondeur).
/// Réutilisé par /api/query (GET+POST) et /api/panels/:id/data.
/// Réponse : {columns, rows, total, stats, compiled}.
///   - `total` : nb de lignes renvoyées (après LIMIT éventuel du pipeline soql) ;
///   - `stats` : agrégats légers par colonne numérique (min/max/sum) — utile aux viz du dashboard.
fn exec_soql(db_path: &str, q: &str) -> Result<Value, (StatusCode, String)> {
    exec_soql_time(db_path, q, 0, 0)
}

/// Variante avec bornes temporelles (epoch ; 0 = pas de borne) — utilisée par panel_data (from/to).
fn exec_soql_time(db_path: &str, q: &str, from: i64, to: i64) -> Result<Value, (StatusCode, String)> {
    let c = soql::compile_with_time(q, from, to, &soql::Schema::forge()).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(3));
    let mut stmt = conn.prepare(&c.sql).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let ncol = c.columns.len();
    let rows: Vec<Value> = stmt
        .query_map([], |row| {                       // SQL inline (valeurs échappées), pas de params liés
            Ok(Value::Array((0..ncol).map(|i| cell(row, i)).collect()))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    let stats = soql_stats(&c.columns, &rows);
    Ok(json!({"columns": c.columns, "rows": rows, "total": rows.len(), "stats": stats, "compiled": c.sql}))
}

/// Stats par colonne sur le jeu de résultats : pour chaque colonne entièrement numérique,
/// renvoie {min,max,sum,count}. Léger (pas de 2e requête SQL) — calculé en mémoire sur les rows.
fn soql_stats(columns: &[String], rows: &[Value]) -> Value {
    let mut out = serde_json::Map::new();
    for (i, col) in columns.iter().enumerate() {
        let mut count = 0i64;
        let (mut min, mut max, mut sum) = (f64::INFINITY, f64::NEG_INFINITY, 0.0f64);
        let mut all_num = true;
        for row in rows {
            let v = row.get(i);
            let n = match v {
                Some(Value::Number(n)) => n.as_f64(),
                Some(Value::String(s)) => s.parse::<f64>().ok(),
                Some(Value::Null) | None => continue,
                _ => None,
            };
            match n {
                Some(f) => { count += 1; min = min.min(f); max = max.max(f); sum += f; }
                None => { all_num = false; break; }
            }
        }
        if all_num && count > 0 {
            out.insert(col.clone(), json!({"min": min, "max": max, "sum": sum, "count": count}));
        }
    }
    Value::Object(out)
}

async fn query(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let qs = q.get("q").cloned().unwrap_or_else(|| "search".to_string());
    match exec_soql(&app.db_path, &qs) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err((s, e)) => (s, Json(json!({"error": e}))),
    }
}

/// POST /api/query {"soql": "...", "q": "..."} -> {columns, rows, total, stats, compiled}.
/// Accepte `soql` ou `q` (alias). Même moteur read-only que le GET ; permet des requêtes
/// longues qui ne tiennent pas en query-string.
async fn query_post(State(app): State<App>, Json(body): Json<Value>) -> impl IntoResponse {
    let qs = body
        .get("soql")
        .or_else(|| body.get("q"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "search".to_string());
    match exec_soql(&app.db_path, &qs) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err((s, e)) => (s, Json(json!({"error": e}))),
    }
}

// --- dashboards / vues : regroupement de panels (CRUD) ---
//
// Un « dashboard » (alias « vue ») est un conteneur nommé de panels. Le panel porte `dashboard_id`
// (défaut 1 = dashboard par défaut, garanti au boot). CRUD gaté par le même token que les panels
// (check_token) ; les lectures sont sous auth_guard comme le reste de l'API.

/// GET /api/dashboards — liste les dashboards (ordre `position`, id). Lecture (viewer).
async fn dashboards_list(State(app): State<App>) -> impl IntoResponse {
    let db = app.db();
    let mut stmt = match db.prepare(
        "SELECT d.id, d.name, d.descr, d.position, d.created, d.updated,
                (SELECT COUNT(*) FROM panel p WHERE p.dashboard_id=d.id) AS panels
         FROM dashboard d ORDER BY d.position, d.id",
    ) { Ok(s) => s, Err(_) => return Json(json!([])) };
    let out: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
                "descr": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                "position": r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                "created": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                "updated": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "panels": r.get::<_, i64>(6)?,
            }))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    Json(Value::Array(out))
}

/// POST /api/dashboards {name, descr?, position?} -> {id}. Écriture (token).
async fn dashboard_create(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_token(&app, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    }
    let name = gs(&body, "name");
    if name.is_empty() || name.len() > 128 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "name requis (1..128)"})));
    }
    let descr = gs(&body, "descr");
    let position = body.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    let db = app.db();
    match db.execute(
        "INSERT INTO dashboard(name,descr,position,created,updated) VALUES(?,?,?,datetime('now'),datetime('now'))",
        rusqlite::params![name, descr, position],
    ) {
        Ok(_) => (StatusCode::OK, Json(json!({"id": db.last_insert_rowid()}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

/// POST /api/dashboards/:id {name?, descr?, position?} — met à jour (champs présents). Écriture (token).
async fn dashboard_update(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_token(&app, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    }
    let db = app.db();
    let mut sets: Vec<String> = Vec::new();
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(v) = body.get("name").and_then(|v| v.as_str()) {
        if v.is_empty() || v.len() > 128 {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "name invalide (1..128)"})));
        }
        sets.push("name=?".into()); args.push(Box::new(v.to_string()));
    }
    if let Some(v) = body.get("descr").and_then(|v| v.as_str()) { sets.push("descr=?".into()); args.push(Box::new(v.to_string())); }
    if let Some(v) = body.get("position").and_then(|v| v.as_i64()) { sets.push("position=?".into()); args.push(Box::new(v)); }
    if sets.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "aucun champ à mettre à jour"})));
    }
    sets.push("updated=datetime('now')".into());
    args.push(Box::new(id));
    let sql = format!("UPDATE dashboard SET {} WHERE id=?", sets.join(","));
    let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
    match db.execute(&sql, refs.as_slice()) {
        Ok(0) => (StatusCode::NOT_FOUND, Json(json!({"error": "dashboard introuvable"}))),
        Ok(_) => (StatusCode::OK, Json(json!({"updated": id}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

/// DELETE /api/dashboards/:id — supprime un dashboard et réassigne ses panels au dashboard #1.
/// Le dashboard #1 (défaut) est PROTÉGÉ (409) — il garantit la rétro-compat. Écriture (token).
async fn dashboard_delete(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>) -> impl IntoResponse {
    if !check_token(&app, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    }
    if id == 1 {
        return (StatusCode::CONFLICT, Json(json!({"error": "default_protected", "why": "le dashboard par défaut (#1) ne peut pas être supprimé"})));
    }
    let db = app.db();
    // les panels du dashboard supprimé retombent sur le défaut (jamais perdus/orphelins).
    let _ = db.execute("UPDATE panel SET dashboard_id=1 WHERE dashboard_id=?", [id]);
    match db.execute("DELETE FROM dashboard WHERE id=?", [id]) {
        Ok(0) => (StatusCode::NOT_FOUND, Json(json!({"error": "dashboard introuvable"}))),
        Ok(_) => (StatusCode::OK, Json(json!({"deleted": id, "panels_reassigned_to": 1}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

// --- dashboards : panels soql sauvegardés (modèle query-driven de Plume) ---

/// GET /api/panels?dashboard_id=N — liste les panels, optionnellement filtrés par dashboard.
/// Sans `dashboard_id` : tous les panels (rétro-compat). `dashboard_id` est lié (param), pas inliné.
async fn panels_list(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let db = app.db();
    let (where_, args): (&str, Vec<i64>) = match q.get("dashboard_id").and_then(|s| s.parse::<i64>().ok()) {
        Some(d) => (" WHERE dashboard_id=?", vec![d]),
        None => ("", vec![]),
    };
    let sql = format!("SELECT id,name,query,viz,position,descr,col_span,updated,dashboard_id FROM panel{where_} ORDER BY position, id");
    let mut stmt = match db.prepare(&sql) { Ok(s) => s, Err(_) => return Json(json!([])) };
    let out: Vec<Value> = stmt
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
                "query": r.get::<_, String>(2)?,
                "viz": r.get::<_, Option<String>>(3)?.unwrap_or_else(|| "table".to_string()),
                "position": r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                "descr": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "col_span": r.get::<_, Option<i64>>(6)?.unwrap_or(1),
                "updated": r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                "dashboard_id": r.get::<_, Option<i64>>(8)?.unwrap_or(1),
            }))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    Json(Value::Array(out))
}

async fn panel_create(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_token(&app, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    }
    let name = gs(&body, "name");
    let qy = gs(&body, "query");
    let viz = { let v = gs(&body, "viz"); if v.is_empty() { "table".to_string() } else { v } };
    let descr = gs(&body, "descr");
    let col_span = body.get("col_span").and_then(|v| v.as_i64()).unwrap_or(1).clamp(1, 4);
    let position = body.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    // dashboard_id : défaut 1 (dashboard par défaut). On vérifie l'existence pour ne pas créer un
    // panel orphelin (FK soft) ; absent => défaut.
    let dashboard_id = body.get("dashboard_id").and_then(|v| v.as_i64()).unwrap_or(1);
    if name.is_empty() || qy.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "name et query requis"})));
    }
    if let Err(e) = soql::compile(&qy, &soql::Schema::forge()) {     // ne sauve pas un panel à la requête invalide
        return (StatusCode::BAD_REQUEST, Json(json!({"error": format!("query invalide: {e}")})));
    }
    let db = app.db();
    let exists: bool = db.query_row("SELECT 1 FROM dashboard WHERE id=?", [dashboard_id], |_| Ok(())).is_ok();
    if !exists {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "unknown_dashboard", "why": format!("dashboard #{dashboard_id} inexistant")})));
    }
    match db.execute(
        "INSERT INTO panel(name,query,viz,descr,col_span,position,dashboard_id,updated) VALUES(?,?,?,?,?,?,?,datetime('now'))",
        rusqlite::params![name, qy, viz, descr, col_span, position, dashboard_id],
    ) {
        Ok(_) => (StatusCode::OK, Json(json!({"id": db.last_insert_rowid()}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

/// POST /api/panels/:id — met à jour un panel existant (champs présents seulement).
/// Corps : {name?, query?, viz?, descr?, col_span?, position?}. La query, si fournie, est validée.
async fn panel_update(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>, Json(body): Json<Value>) -> impl IntoResponse {
    if !check_token(&app, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    }
    if let Some(qy) = body.get("query").and_then(|v| v.as_str()) {
        if let Err(e) = soql::compile(qy, &soql::Schema::forge()) {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": format!("query invalide: {e}")})));
        }
    }
    let db = app.db();
    let mut sets: Vec<String> = Vec::new();
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(v) = body.get("name").and_then(|v| v.as_str()) { sets.push("name=?".into()); args.push(Box::new(v.to_string())); }
    if let Some(v) = body.get("query").and_then(|v| v.as_str()) { sets.push("query=?".into()); args.push(Box::new(v.to_string())); }
    if let Some(v) = body.get("viz").and_then(|v| v.as_str()) { sets.push("viz=?".into()); args.push(Box::new(v.to_string())); }
    if let Some(v) = body.get("descr").and_then(|v| v.as_str()) { sets.push("descr=?".into()); args.push(Box::new(v.to_string())); }
    if let Some(v) = body.get("col_span").and_then(|v| v.as_i64()) { sets.push("col_span=?".into()); args.push(Box::new(v.clamp(1, 4))); }
    if let Some(v) = body.get("position").and_then(|v| v.as_i64()) { sets.push("position=?".into()); args.push(Box::new(v)); }
    // ré-assignation de dashboard : vérifiée pour éviter l'orphelinage (FK soft).
    if let Some(v) = body.get("dashboard_id").and_then(|v| v.as_i64()) {
        let exists: bool = db.query_row("SELECT 1 FROM dashboard WHERE id=?", [v], |_| Ok(())).is_ok();
        if !exists {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "unknown_dashboard", "why": format!("dashboard #{v} inexistant")})));
        }
        sets.push("dashboard_id=?".into()); args.push(Box::new(v));
    }
    if sets.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "aucun champ à mettre à jour"})));
    }
    sets.push("updated=datetime('now')".into());
    args.push(Box::new(id));
    let sql = format!("UPDATE panel SET {} WHERE id=?", sets.join(","));
    let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
    match db.execute(&sql, refs.as_slice()) {
        Ok(0) => (StatusCode::NOT_FOUND, Json(json!({"error": "panel introuvable"}))),
        Ok(_) => (StatusCode::OK, Json(json!({"updated": id}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

async fn panel_delete(State(app): State<App>, headers: HeaderMap, Path(id): Path<i64>) -> impl IntoResponse {
    if !check_token(&app, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    }
    let db = app.db();
    let _ = db.execute("DELETE FROM panel WHERE id=?", [id]);
    (StatusCode::OK, Json(json!({"deleted": id})))
}

/// GET /api/panels/:id/data?from=&to= — exécute la query du panel.
/// `from`/`to` (epoch seconds) bornent `ts` via compile_with_time (0 = pas de borne).
async fn panel_data(State(app): State<App>, Path(id): Path<i64>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let qy: Option<String> = {
        let db = app.db();
        db.query_row("SELECT query FROM panel WHERE id=?", [id], |r| r.get::<_, String>(0)).ok()
    };
    let from = q.get("from").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let to = q.get("to").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    match qy {
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "panel introuvable"}))),
        Some(q) => match exec_soql_time(&app.db_path, &q, from, to) {
            Ok(v) => (StatusCode::OK, Json(v)),
            Err((s, e)) => (s, Json(json!({"error": e}))),
        },
    }
}

// --- ledger d'engagement : lecture + re-vérification de la chaîne SHA-256 (sans la clé de signature) ---

/// Canonicalisation JSON identique à `ledger._canon` côté Python :
/// json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).
/// Indispensable pour recalculer `_entry_hash` à l'identique en Rust.
fn canon_json(v: &Value) -> String {
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

fn read_ledger_lines(path: &str) -> Vec<Value> {
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
async fn ledger(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let entries = read_ledger_lines(&app.ledger_path);
    let total = entries.len();
    let (limit, offset) = paginate(&q, 200, 2000);
    let page: Vec<Value> = entries.into_iter().skip(offset as usize).take(limit as usize).collect();
    Json(json!({"total": total, "limit": limit, "offset": offset, "path": app.ledger_path.as_str(), "entries": page}))
}

/// GET /api/ledger/verify — recalcule la chaîne SHA-256 (prev|seq|ts|kind|canon(detail))
/// et vérifie chaque hash + le chaînage `prev`. NE vérifie PAS les signatures (Ed25519/HMAC) :
/// la console n'a pas la clé -> `sig_checked: false` (la vérif signature reste côté `forge ledger verify`).
async fn ledger_verify(State(app): State<App>) -> impl IntoResponse {
    const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let entries = read_ledger_lines(&app.ledger_path);
    if entries.is_empty() {
        // soit fichier absent/vide, soit toutes lignes malformées
        let exists = std::path::Path::new(app.ledger_path.as_str()).exists();
        return (StatusCode::OK, Json(json!({
            "ok": exists, "entries": 0, "broken": Value::Null, "sig_checked": false,
            "path": app.ledger_path.as_str(),
            "why": if exists { Value::Null } else { json!("ledger absent") }
        })));
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
            return (StatusCode::OK, Json(json!({
                "ok": false, "entries": n + 1, "broken": seq, "why": "chaînage rompu (prev)",
                "sig_checked": false, "alg": alg, "path": app.ledger_path.as_str()
            })));
        }
        // seq sérialisé tel quel (entier sans guillemets) — cohérent avec le format Python f-string.
        let seq_str = match &seq { Value::Number(num) => num.to_string(), Value::Null => String::new(), other => other.to_string() };
        let preimage = format!("{prev}|{seq_str}|{ts}|{kind}|{}", canon_json(&detail));
        let recomputed = sha_hex(&preimage);
        if recomputed != stored_hash {
            return (StatusCode::OK, Json(json!({
                "ok": false, "entries": n + 1, "broken": seq,
                "why": "hash recalculé != hash stocké (entrée altérée)",
                "sig_checked": false, "alg": alg, "path": app.ledger_path.as_str()
            })));
        }
        prev = stored_hash.to_string();
        head = stored_hash.to_string();
    }
    (StatusCode::OK, Json(json!({
        "ok": true, "entries": entries.len(), "broken": Value::Null, "head": head,
        "alg": alg, "sig_checked": false, "path": app.ledger_path.as_str()
    })))
}

async fn coverage(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let db = app.db();
    // filtre campaign optionnel (param lié — pas d'inlining).
    let (sql, args): (&str, Vec<String>) = match q.get("campaign") {
        Some(c) => (
            "SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' AND campaign=? GROUP BY mitre ORDER BY n DESC",
            vec![c.clone()],
        ),
        None => (
            "SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' GROUP BY mitre ORDER BY n DESC",
            vec![],
        ),
    };
    let mut stmt = match db.prepare(sql) { Ok(s) => s, Err(_) => return Json(json!([])) };
    let out: Vec<Value> = stmt
        .query_map(rusqlite::params_from_iter(args.iter()), |row| {
            Ok(json!({
                "mitre": row.get::<_, String>(0)?,
                "runs": row.get::<_, i64>(1)?,
                "fired": row.get::<_, i64>(2)?
            }))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    Json(Value::Array(out))
}

// ===========================================================================================
// PURPLE-TEAM (DÉFENSIF) — mesure de la couverture de DÉTECTION du SOC.
//
// Objectif blue-team : pour chaque technique ATT&CK TIRÉE en red-team autorisée par Forge
// (runrecord.fired=1), vérifier si la colonne BLEUE Plume l'a DÉTECTÉE (une alerte taguée du
// même `mitre`). On expose les TROUS de détection (missed) + le délai moyen de détection (MTTD).
//
// Source RED  : table `runrecord` (fired=1) de CETTE console — la technique + l'horodatage du tir.
// Source BLUE : GET {PLUME_URL}/api/coverage/detections -> [{mitre, count, first_ts}] (epoch s).
// Jointure    : sur le champ `mitre` commun (ex T1190/T1046/T1110).
//   detected = techniques tirées présentes côté Plume ; missed = tirées ABSENTES de Plume.
//   MTTD/tech = first_ts(détection) - ts(tir red) en secondes (>=0 ; négatif tronqué à 0 — une
//   détection antérieure au tir vient d'un run précédent, on ne « gagne » pas de temps négatif).
//
// FAIL-OPEN LISIBLE (NON négociable) : si Plume est injoignable / PLUME_URL absent / réponse
// illisible, on renvoie `plume_reachable:false` et on NE FABRIQUE JAMAIS de detected/missed/MTTD
// (listes vides, agrégats nuls). Un SOC muet ne doit pas se traduire en « tout détecté » NI en
// « tout raté » — l'opérateur voit explicitement que la mesure n'a pas pu être faite.
// LECTURE pure : aucun spawn, aucune écriture ; gardée par auth_guard comme le reste de l'API.
// ===========================================================================================

/// Parse un horodatage de tir red-team en epoch secondes (i64). Forge émet de l'ISO-8601 UTC
/// (`2026-06-26T12:00:00+00:00` / `...Z`) ; on tolère aussi un epoch déjà nu (défensif). Renvoie
/// `None` si illisible -> le MTTD de cette technique est marqué indisponible (jamais inventé).
fn parse_fire_ts(ts: &str) -> Option<i64> {
    let s = ts.trim();
    if s.is_empty() {
        return None;
    }
    // 1) epoch nu déjà fourni (ex "1719403200") — tolérance, pas le cas nominal.
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    // 2) ISO-8601 : YYYY-MM-DDTHH:MM:SS[.frac][Z|±HH:MM]. On lit la partie civile UTC et applique
    //    l'offset éventuel. Pas de chrono : conversion calendaire jours-depuis-epoch à la main
    //    (algorithme « days_from_civil », valable pour le calendrier grégorien proleptique).
    let (date_part, rest) = s.split_once('T').or_else(|| s.split_once(' '))?;
    let mut d = date_part.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // sépare l'heure de l'offset/zone (Z, +hh:mm, -hh:mm). On coupe au 1er marqueur d'offset.
    let mut offset_secs: i64 = 0;
    let time_str: &str = {
        let r = rest.trim_end();
        if let Some(stripped) = r.strip_suffix('Z').or_else(|| r.strip_suffix('z')) {
            stripped
        } else {
            // l'offset commence au 1er '+'/'-' rencontré dans `rest` (HH:MM:SS n'en contient pas) ;
            // le 'T' a déjà été retiré en amont, donc tout signe ici borne le décalage de fuseau.
            if let Some(pos) = r.find(['+', '-']) {
                let (t, off) = r.split_at(pos);
                let sign = if off.starts_with('-') { -1 } else { 1 };
                let off = &off[1..];
                let mut op = off.split(':');
                let oh: i64 = op.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                let om: i64 = op.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                offset_secs = sign * (oh * 3600 + om * 60);
                t
            } else {
                r
            }
        }
    };
    // heure civile (on coupe une éventuelle fraction de seconde).
    let time_core = time_str.split('.').next().unwrap_or(time_str);
    let mut t = time_core.split(':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let ss: i64 = t.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    if !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=60).contains(&ss) {
        return None;
    }
    // days_from_civil (Howard Hinnant) : jours depuis 1970-01-01 pour une date grégorienne.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0,365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468;
    let epoch_utc = days * 86400 + hh * 3600 + mm * 60 + ss;
    // l'horodatage civil était exprimé dans le fuseau `offset_secs` -> on revient à l'UTC.
    Some(epoch_utc - offset_secs)
}

/// GET HTTP/1.1 minimal et BLOQUANT (lancé via spawn_blocking) — pas de dépendance HTTP lourde.
/// Ne gère QUE `http://host[:port]/path` (Plume bind en HTTP clair, derrière Traefik/forward-auth
/// en prod ; pour TLS, mettre PLUME_URL=http://service-cluster-interne). `basic_b64` non vide =>
/// en-tête `Authorization: Basic <basic_b64>`. Renvoie le corps (string) en cas de 200, sinon Err.
/// Timeout dur (connect + lecture) pour ne jamais bloquer le handler axum.
fn http_get_blocking(url: &str, basic_b64: &str, timeout: Duration) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let rest = url.strip_prefix("http://").ok_or_else(|| "PLUME_URL doit commencer par http:// (TLS non géré côté console — utiliser un endpoint interne)".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = authority.split(':').next().unwrap_or(authority);
    let port: u16 = authority.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(80);
    // résolution + connexion avec timeout (évite un blocage si Plume est down).
    use std::net::ToSocketAddrs;
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("résolution {host}:{port} échouée: {e}"))?
        .next()
        .ok_or_else(|| format!("aucune adresse pour {host}:{port}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connexion {addr} échouée: {e}"))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: forge-console-purple\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if !basic_b64.is_empty() {
        req.push_str(&format!("Authorization: Basic {basic_b64}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).map_err(|e| format!("écriture requête échouée: {e}"))?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| format!("lecture réponse échouée: {e}"))?;
    let text = String::from_utf8_lossy(&raw);
    // sépare l'en-tête du corps (CRLFCRLF). Vérifie un statut 200.
    let split = text.find("\r\n\r\n").ok_or_else(|| "réponse HTTP malformée (pas d'en-tête/corps)".to_string())?;
    let head = &text[..split];
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200") {
        return Err(format!("statut HTTP inattendu: {status_line}"));
    }
    let body = &text[split + 4..];
    // gère un éventuel Transfer-Encoding: chunked (Plume/axum peut chunker) — décode best-effort.
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        Ok(dechunk(body))
    } else {
        Ok(body.to_string())
    }
}

/// Décode un corps HTTP `chunked` (best-effort) : tailles hex par ligne, terminé par un chunk 0.
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some(nl) = rest.find("\r\n") {
        let size_line = &rest[..nl];
        // la taille peut porter des extensions après ';' — on ne garde que l'hex.
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(hex, 16) {
            Ok(s) => s,
            Err(_) => break,
        };
        if size == 0 {
            break;
        }
        let start = nl + 2;
        let end = start + size;
        if end > rest.len() {
            out.push_str(&rest[start..]);
            break;
        }
        out.push_str(&rest[start..end]);
        // saute le CRLF de fin de chunk.
        rest = if end + 2 <= rest.len() { &rest[end + 2..] } else { "" };
    }
    out
}

/// Corrélation PURE (testable, sans I/O) red-team(tiré) × blue-team(détecté).
///
/// - `fired` : techniques tirées par Forge -> (mitre, ts_epoch_du_tir Option). Une technique peut
///   apparaître plusieurs fois (plusieurs tirs) ; on prend le tir le PLUS RÉCENT pour le MTTD (le SOC
///   doit détecter le tir courant), et on compte les tirs.
/// - `detections` : map mitre -> (count_alertes, first_ts_epoch) renvoyée par Plume.
///
/// Renvoie l'objet JSON exposé par /api/purple/coverage (hors champ plume_reachable, ajouté par
/// le handler). detected/missed sont des intersections/différences STRICTES sur `mitre`.
fn compute_purple_coverage(
    fired: &[(String, Option<i64>)],
    detections: &std::collections::HashMap<String, (i64, i64)>,
) -> Value {
    // agrège les tirs par technique : nb de tirs + horodatage du tir le plus récent (pour MTTD).
    let mut fired_by: std::collections::BTreeMap<String, (i64, Option<i64>)> = std::collections::BTreeMap::new();
    for (mitre, ts) in fired {
        if mitre.is_empty() {
            continue;
        }
        let e = fired_by.entry(mitre.clone()).or_insert((0, None));
        e.0 += 1;
        if let Some(t) = ts {
            // on garde le tir le PLUS RÉCENT (max) -> MTTD calculé contre le dernier tir.
            e.1 = Some(e.1.map_or(*t, |cur: i64| cur.max(*t)));
        }
    }

    let mut detected: Vec<Value> = Vec::new();
    let mut missed: Vec<Value> = Vec::new();
    let mut mttd_samples: Vec<i64> = Vec::new();

    for (mitre, (fires, last_fire_ts)) in &fired_by {
        match detections.get(mitre) {
            Some((count, first_ts)) => {
                // MTTD = première détection - dernier tir. Indisponible si le ts du tir est illisible.
                // Tronqué à 0 si négatif (détection antérieure = run précédent ; pas de gain négatif).
                let mttd = last_fire_ts.map(|ft| (*first_ts - ft).max(0));
                if let Some(m) = mttd {
                    mttd_samples.push(m);
                }
                detected.push(json!({
                    "mitre": mitre,
                    "fires": fires,
                    "alert_count": count,
                    "first_detection_ts": first_ts,
                    "fire_ts": last_fire_ts,
                    "mttd_secs": mttd,
                }));
            }
            None => {
                missed.push(json!({
                    "mitre": mitre,
                    "fires": fires,
                    "fire_ts": last_fire_ts,
                }));
            }
        }
    }

    let n_fired = fired_by.len() as i64;
    let n_detected = detected.len() as i64;
    let n_missed = missed.len() as i64;
    let detection_rate = if n_fired > 0 { n_detected as f64 / n_fired as f64 } else { 0.0 };
    let mttd_avg = if !mttd_samples.is_empty() {
        Some(mttd_samples.iter().sum::<i64>() as f64 / mttd_samples.len() as f64)
    } else {
        None
    };
    let mttd_max = mttd_samples.iter().copied().max();

    json!({
        "techniques_fired": n_fired,
        "techniques_detected": n_detected,
        "techniques_missed": n_missed,
        "detection_rate": detection_rate,   // [0,1] — part des techniques tirées détectées par le SOC
        "mttd_avg_secs": mttd_avg,           // null si aucun échantillon mesurable
        "mttd_max_secs": mttd_max,           // null si aucun échantillon mesurable
        "detected": detected,                // techniques tirées ET détectées (avec MTTD)
        "missed": missed,                    // TROUS de détection : tirées mais jamais alertées
    })
}

/// Construit l'objet de FAIL-OPEN LISIBLE (plume_reachable:false) : compte les techniques tirées
/// (pour information) mais NE FABRIQUE PAS de detected/missed/MTTD. Réutilisé par tous les chemins
/// où la mesure n'a pas pu se faire (Plume absent/injoignable/illisible, lecture DB échouée).
fn purple_fail_open(plume_url: &str, fired: &[(String, Option<i64>)], reason: &str) -> Value {
    let n_fired = fired
        .iter()
        .filter(|(m, _)| !m.is_empty())
        .map(|(m, _)| m.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as i64;
    json!({
        "plume_reachable": false,
        "plume_url": plume_url,
        "error": reason,
        "techniques_fired": n_fired,
        "techniques_detected": 0,
        "techniques_missed": 0,
        "detection_rate": 0.0,
        "mttd_avg_secs": Value::Null,
        "mttd_max_secs": Value::Null,
        "detected": [],
        "missed": [],
    })
}

/// Lit les techniques tirées (runrecord.fired=1, mitre non vide) + horodatage du tir, filtrées par
/// une clause WHERE additionnelle (campaign ou run_id) déjà validée par l'appelant (param lié).
fn read_fired_techniques(app: &App, extra_cond: Option<(&str, &str)>) -> Vec<(String, Option<i64>)> {
    let db = app.db();
    let (sql, args): (String, Vec<String>) = match extra_cond {
        Some((col, val)) => (
            format!("SELECT mitre, ts FROM runrecord WHERE fired=1 AND mitre<>'' AND {col}=?"),
            vec![val.to_string()],
        ),
        None => (
            "SELECT mitre, ts FROM runrecord WHERE fired=1 AND mitre<>''".to_string(),
            vec![],
        ),
    };
    let mut stmt = match db.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
        let mitre: String = r.get::<_, Option<String>>(0)?.unwrap_or_default();
        let ts_raw: String = r.get::<_, Option<String>>(1)?.unwrap_or_default();
        Ok((mitre, parse_fire_ts(&ts_raw)))
    })
    .map(|it| it.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Interroge Plume et corrèle avec les techniques `fired` -> objet purple coverage complet.
/// FAIL-OPEN LISIBLE à chaque étape qui peut échouer (URL absente, HTTP KO, JSON invalide) :
/// `plume_reachable:false` + raison, JAMAIS de detected/missed/MTTD inventés. Réutilisé par
/// l'endpoint /api/purple/coverage ET la section purple du rapport de run.
async fn fetch_purple_coverage(app: &App, fired: Vec<(String, Option<i64>)>) -> Value {
    // FAIL-OPEN LISIBLE : Plume non configuré -> on n'invente RIEN.
    if app.plume_url.is_empty() {
        return purple_fail_open("", &fired, "PLUME_URL non configuré (couverture de détection indisponible)");
    }
    // côté BLUE : interroge Plume. `since` = plus ancien tir red (borne la fenêtre côté Plume) ;
    // 0 si aucun tir horodaté lisible (on prend tout). Requête bloquante isolée dans spawn_blocking.
    let since = fired.iter().filter_map(|(_, t)| *t).min().unwrap_or(0);
    let url = format!("{}/api/coverage/detections?since={}", app.plume_url.as_str(), since);
    let token = app.plume_token.as_str().to_string();
    let timeout = Duration::from_secs(8);
    let fetched = tokio::task::spawn_blocking(move || http_get_blocking(&url, &token, timeout))
        .await
        .unwrap_or_else(|e| Err(format!("tâche HTTP interrompue: {e}")));
    let body = match fetched {
        Ok(b) => b,
        Err(e) => return purple_fail_open(app.plume_url.as_str(), &fired, &format!("Plume injoignable: {e}")),
    };
    // parse la réponse Plume {detections:[{mitre,count,first_ts}]}. Réponse illisible -> fail-open.
    let parsed: Value = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(e) => return purple_fail_open(app.plume_url.as_str(), &fired, &format!("réponse Plume illisible (JSON invalide): {e}")),
    };
    let mut detections: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
    if let Some(arr) = parsed.get("detections").and_then(|v| v.as_array()) {
        for d in arr {
            let mitre = d.get("mitre").and_then(|v| v.as_str()).unwrap_or("");
            if mitre.is_empty() {
                continue;
            }
            let count = d.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            let first_ts = d.get("first_ts").and_then(|v| v.as_i64()).unwrap_or(0);
            detections.insert(mitre.to_string(), (count, first_ts));
        }
    }
    // corrélation pure -> réponse purple. plume_reachable:true (la mesure a bien eu lieu).
    let mut cov = compute_purple_coverage(&fired, &detections);
    if let Value::Object(ref mut m) = cov {
        m.insert("plume_reachable".into(), json!(true));
        m.insert("plume_url".into(), json!(app.plume_url.as_str()));
    }
    cov
}

/// GET /api/purple/coverage[?campaign=X] — couverture de DÉTECTION (purple-team défensif).
/// Joint runrecord[fired=1] (techniques tirées en red-team Forge) avec les détections du SOC Plume
/// (GET {PLUME_URL}/api/coverage/detections). Réponse :
///   {
///     "plume_reachable": bool,         // false => FAIL-OPEN lisible (mesure impossible, rien d'inventé)
///     "plume_url": "...",              // pour traçabilité (vide si non configuré)
///     "techniques_fired|detected|missed": i64,
///     "detection_rate": f64,           // [0,1]
///     "mttd_avg_secs"|"mttd_max_secs": f64|i64|null,
///     "detected": [ {mitre, fires, alert_count, first_detection_ts, fire_ts, mttd_secs} ],
///     "missed":   [ {mitre, fires, fire_ts} ],
///     ("error": "...")                 // présent UNIQUEMENT si plume_reachable=false (raison lisible)
///   }
/// Si plume_reachable=false : detected/missed=[], compteurs/MTTD nuls — jamais de faux détecté/raté.
async fn purple_coverage(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // côté RED : techniques tirées (fired=1) + horodatage du tir, filtrées par campaign optionnelle.
    let fired = read_fired_techniques(&app, q.get("campaign").map(|c| ("campaign", c.as_str())));
    (StatusCode::OK, Json(fetch_purple_coverage(&app, fired).await))
}

// ===========================================================================================
// Endpoints de PARITÉ LECTURE / GOUVERNANCE (viewer, aucun spawn armé).
//
// Ces routes exposent la décision de scope, un plan « à blanc » (dry-plan, rien ne tire), le
// rafraîchissement du registre de modules, et le rendu markdown d'un rapport de run. Toutes
// réutilisent les garde-fous existants (host_in_server_scope, validate_*, scope FORCÉ allow_*=false).
// ===========================================================================================

/// POST /api/scope-check {target} -> {target, in_scope, mode, allow_exploit, allow_destructive}.
/// LECTURE pure : réutilise host_in_server_scope (même règle que le pré-filtre de /api/run). Les
/// capacités exposées sont CELLES IMPOSÉES par la console au lancement web (exploit/destructif
/// toujours false depuis le web) — pas une bascule, juste de la transparence.
async fn scope_check(State(app): State<App>, Json(body): Json<Value>) -> impl IntoResponse {
    let target = body.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let validated = match validate_host(target) {
        Ok(h) => h,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_target", "why": e})));
        }
    };
    let in_scope = host_in_server_scope(&app, &validated);
    (StatusCode::OK, Json(json!({
        "target": validated,
        "in_scope": in_scope,
        "mode": app.scope_mode.as_str(),
        // ce que la console autorise depuis le web pour cette cible — INVARIANT (plancher exploit).
        "allow_exploit": false,
        "allow_destructive": false,
    })))
}

/// POST /api/plan {targets, modules?} -> dry-plan INERTE. Spawne `forge.cli campaign --mode propose`
/// (jamais armé : scope FORCÉ allow_exploit=false/allow_destructive=false, --modules borné aux kinds
/// web_allowed non-exploit), CAPTURE sa sortie et renvoie la liste action->verdict (VETO/DRY_RUN).
/// Aucune action ne tire — c'est un aperçu de gouvernance. Réutilise toutes les validations de
/// /api/run (campaign/host/modules/plancher exploit) SANS persister de run_job ni ouvrir le slot FIFO.
async fn plan(State(app): State<App>, Json(body): Json<Value>) -> impl IntoResponse {
    // (1) validation des cibles : host bien formé ET ⊆ scope serveur (fail-closed, comme /api/run).
    let targets_in = match body.get("targets").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_targets", "why": "targets[] requis (non vide)"}))),
    };
    let mut targets: Vec<String> = Vec::new();
    for t in &targets_in {
        let host = t.as_str().unwrap_or("");
        match validate_host(host) {
            Ok(h) => {
                if !host_in_server_scope(&app, &h) {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "out_of_scope", "why": format!("'{h}' hors du scope serveur autorisé")})));
                }
                targets.push(h);
            }
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_target", "why": e}))),
        }
    }
    // (2) modules : mêmes contraintes que /api/run (⊆ kinds connus, web_allowed, plancher exploit).
    // Le dry-plan est INERTE par construction (allow_high_impact=false) : le plancher exploit tient
    // toujours ici, l'opt-in haut-impact n'a pas de sens pour un aperçu qui ne tire rien.
    let requested_modules: Vec<String> = body
        .get("modules")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if let Err((code, j)) = validate_modules(&app, &requested_modules, false) {
        return (code, j);
    }

    // (3) dir temp éphémère : scope.json (allow_* FORCÉS false) + targets.json. Nettoyé en fin.
    let stamp = format!("plan-{}-{}", chrono_now_compact(), gen_token().chars().take(8).collect::<String>());
    let plan_dir = std::env::temp_dir().join(format!("forge-run-{stamp}"));
    if let Err(e) = std::fs::create_dir_all(&plan_dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "mkdir_failed", "why": e.to_string()})));
    }
    let scope_doc = json!({
        "_comment": format!("dry-plan {stamp} — INERTE (exploit/destructif forcés false, mode propose)"),
        "mode": app.scope_mode.as_str(),
        "in_scope": targets,
        "out_scope": [],
        "rate": 5,
        "allow_exploit": false,
        "allow_destructive": false,
        "known_creds": [],
        "idor_targets": [],
        "notes": "dry-plan via console (gouverné) — rien ne tire"
    });
    let targets_doc: Vec<Value> = targets.iter().map(|h| json!({"host": h, "kind": "host"})).collect();
    let scope_path = plan_dir.join("scope.json");
    let targets_path = plan_dir.join("targets.json");
    if std::fs::write(&scope_path, serde_json::to_vec(&scope_doc).unwrap()).is_err()
        || std::fs::write(&targets_path, serde_json::to_vec(&Value::Array(targets_doc)).unwrap()).is_err()
    {
        let _ = std::fs::remove_dir_all(&plan_dir);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write_failed", "why": "écriture scope/targets impossible"})));
    }

    // (4) argv FIXE, --mode propose (NON armé). Pas de --ledger/--console : on ne persiste rien et on
    // ne POST aucun finding ; on capture juste la sortie pour en extraire les verdicts (transparence).
    let mut argv: Vec<String> = vec![
        "-m".into(), "forge.cli".into(), "campaign".into(),
        "--scope".into(), scope_path.to_string_lossy().into_owned(),
        "--targets".into(), targets_path.to_string_lossy().into_owned(),
        "--campaign".into(), "dry-plan".into(),
        "--mode".into(), "propose".into(),
        "--run-id".into(), stamp.clone(),
    ];
    if !requested_modules.is_empty() {
        argv.push("--modules".into());
        argv.push(requested_modules.join(","));
    }

    let output = std::process::Command::new(app.python.as_str())
        .args(&argv)
        .current_dir(app.pkg_dir.as_str())
        .stdin(std::process::Stdio::null())
        .output();
    let _ = std::fs::remove_dir_all(&plan_dir); // nettoyage best-effort quel que soit le résultat

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
            // extraction best-effort des verdicts de la sortie du moteur (propose -> DRY_RUN/VETO).
            let actions = parse_plan_verdicts(&stdout);
            (StatusCode::OK, Json(json!({
                "dry_run": true,
                "mode": "propose",
                "targets": targets,
                "modules": requested_modules,
                "actions": actions,
                "exit_ok": o.status.success(),
                "stdout": stdout,
                "stderr": stderr,
                "note": "dry-plan INERTE — aucune action n'a été tirée (exploit/destructif forcés false)"
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "spawn_failed", "why": e.to_string()}))),
    }
}

/// Extrait les couples action->verdict de la sortie texte du moteur en mode propose. Sortie :
/// [{kind, target, verdict, line}], une entrée PAR ACTION réelle (pas par compteur de synthèse).
///
/// Le rapport (`report.py`) liste chaque action sous un en-tête de section (`**Simulées …**`,
/// `**Refusées (VETO)**`, `**Erreurs / skips**`, `**Déférées (budget)**`) avec des lignes
/// `- `kind` → `target` : raisons` qui ne portent PAS le mot-clé du verdict — celui-ci vient de la
/// section. On lève donc le verdict du CONTEXTE de section, et on ignore les lignes de SYNTHÈSE en
/// gras (`- **Tirées (FIRE)** : 0`) qui contiennent un mot-clé mais ne sont pas des actions (sinon
/// elles polluaient le plan de faux verdicts). On tolère aussi le format inline `[VERDICT] kind →
/// target` (CLI `forge plan`) : si la ligne porte un mot-clé de verdict hors d'un en-tête en gras,
/// il prime. Backticks et puce de liste retirés des cellules.
fn parse_plan_verdicts(stdout: &str) -> Vec<Value> {
    const VERDICTS: &[&str] = &["VETO", "DRY_RUN", "FIRE", "SKIP"];
    // En-tête de section -> verdict des lignes d'action qui suivent (jusqu'au prochain en-tête).
    fn section_verdict(line: &str) -> Option<&'static str> {
        if !line.starts_with("**") {
            return None;
        }
        if line.contains("VETO") {
            Some("VETO")
        } else if line.contains("Simulées") || line.contains("DRY_RUN") {
            Some("DRY_RUN")
        } else if line.contains("Erreurs") || line.contains("skips") || line.contains("Déférées") {
            Some("SKIP")
        } else {
            None
        }
    }
    // Découpe `kind → target` (ou `->`) en cellules nettoyées (backticks/espaces retirés).
    fn split_kind_target(line: &str) -> Option<(String, String)> {
        let unquote = |s: &str| s.trim().trim_matches('`').trim().to_string();
        line.split_once('→')
            .or_else(|| line.split_once("->"))
            .map(|(k, t)| {
                // kind = dernier jeton avant la flèche (après la puce/`[verdict]`), target = 1er après.
                let kind = unquote(k.split_whitespace().last().unwrap_or(""));
                // la cellule target peut être suivie de ` : raisons` -> on coupe au `:` hors-backtick.
                let t = t.split(" : ").next().unwrap_or(t);
                let target = unquote(t.split_whitespace().next().unwrap_or(""));
                (kind, target)
            })
    }

    let mut out = Vec::new();
    let mut section: Option<&'static str> = None;
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // 1) en-tête de section en gras -> (re)bascule le contexte : verdict connu, ou None pour
        //    une section neutre (`**Classes jamais tentées**`, `**Déférées (budget)**`…) afin que
        //    ses lignes ne héritent pas du verdict de la section précédente. Ne produit aucune action.
        if line.starts_with("**") {
            section = section_verdict(line);
            continue;
        }
        // 2) ligne de SYNTHÈSE en gras (`- **Tirées (FIRE)** : 0`) -> jamais une action.
        if line.trim_start_matches("- ").starts_with("**") {
            continue;
        }
        // 3) verdict inline explicite (CLI `forge plan` : `[DRY_RUN] kind → target`) -> prioritaire.
        let inline = VERDICTS.iter().find(|v| line.contains(*v)).copied();
        // 4) sinon, on retient la ligne SEULEMENT si elle décrit une action (`kind → target`) sous
        //    une section connue : c'est le format réel du rapport (lignes sans mot-clé de verdict).
        let verdict = match (inline, section) {
            (Some(v), _) => v,
            (None, Some(v)) if line.starts_with("- ") && (line.contains('→') || line.contains("->")) => v,
            _ => continue,
        };
        let (kind, target) = split_kind_target(line).unwrap_or_default();
        out.push(json!({
            "kind": kind,
            "target": target,
            "verdict": verdict,
            "line": line,
        }));
    }
    out
}

/// POST /api/modules/refresh — re-spawne `forge.cli modules --json` et re-seed la table `module`
/// (registre vivant). LECTURE/gouvernance : ne lance aucune campagne, n'arme rien — il rafraîchit
/// seulement le catalogue de capacités. Gaté par le rôle opérateur (fail-closed) car il modifie une
/// table d'état serveur. Renvoie le catalogue rafraîchi (même forme que GET /api/modules).
async fn modules_refresh(State(app): State<App>, headers: HeaderMap) -> impl IntoResponse {
    if !check_operator(&app, &headers) {
        let (s, j) = operator_denied(&app);
        return (s, j);
    }
    {
        let db = app.db();
        populate_modules(&db); // re-spawn `forge.cli modules --json` + UPSERT dans `module`
    }
    // relit le catalogue pour le renvoyer (transparence : l'opérateur voit l'état post-refresh).
    let db = app.db();
    let mut stmt = match db.prepare(
        "SELECT kind,exploit,destructive,available,mitre,descr,web_allowed FROM module ORDER BY kind",
    ) {
        Ok(s) => s,
        Err(_) => return (StatusCode::OK, Json(json!({"refreshed": 0, "modules": []}))),
    };
    let mods: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "kind": r.get::<_, String>(0)?,
                "exploit": r.get::<_, i64>(1)? != 0,
                "destructive": r.get::<_, i64>(2)? != 0,
                "available": r.get::<_, i64>(3)? != 0,
                "mitre": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                "descr": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "web_allowed": r.get::<_, i64>(6)? != 0,
            }))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    (StatusCode::OK, Json(json!({"refreshed": mods.len(), "modules": mods})))
}

/// GET /api/runs/:id/report — rend en markdown un rapport d'engagement pour CE run, à partir des
/// données stockées côté console (run_job + findings + roe_decision pour le run_id). Miroir Rust de
/// `forge.report.build_report` (synthèse, findings, transparence ROE). LECTURE (viewer).
/// 404 si le run_id est inconnu de run_job.
async fn run_report(State(app): State<App>, Path(id): Path<String>) -> Response {
    // le run doit exister (sinon 404, comme run_detail). Le verrou DB est confiné dans ce bloc :
    // AUCUN MutexGuard rusqlite (!Send) ne doit survivre à l'await réseau plus bas.
    let (job, fired) = {
        let db = app.db();
        let job = match db.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), [&id], run_job_json) {
            Ok(v) => v,
            Err(_) => return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"}))).into_response(),
        };
        // PURPLE : techniques TIRÉES par CE run (red) — lues avant de relâcher le verrou.
        drop(db);
        let fired = read_fired_techniques(&app, Some(("run_id", &id)));
        (job, fired)
    };
    // I/O réseau Plume HORS verrou DB. Fail-open lisible si Plume injoignable.
    let purple = fetch_purple_coverage(&app, fired).await;
    let md = {
        let db = app.db();
        render_run_report_md(&db, &id, &job, Some(&purple))
    };
    (StatusCode::OK, [("content-type", "text/markdown; charset=utf-8")], md).into_response()
}

/// Rend le markdown du rapport d'un run depuis les données console (miroir de build_report Python) :
/// synthèse par sévérité, findings détaillés, section transparence ROE (FIRE/DRY_RUN/VETO/erreurs),
/// et section PURPLE (couverture de détection SOC : detected/missed/MTTD) quand `purple` est fourni.
/// Les compteurs proviennent de run_job ; le détail des findings/verdicts des tables finding/roe_decision.
fn render_run_report_md(db: &Connection, run_id: &str, job: &Value, purple: Option<&Value>) -> String {
    const SEVERITIES: &[&str] = &["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
    let campaign = job.get("campaign").and_then(|v| v.as_str()).unwrap_or("");
    let mut out: Vec<String> = vec![
        format!("# Forge — rapport d'engagement (`{run_id}`)"),
        String::new(),
        format!(
            "- **Campagne** : {}  ·  **Mode** : {}  ·  **Statut** : {}",
            campaign,
            job.get("mode").and_then(|v| v.as_str()).unwrap_or("—"),
            job.get("status").and_then(|v| v.as_str()).unwrap_or("—"),
        ),
        format!(
            "- **Démarré** : {}  ·  **Terminé** : {}  ·  **Par** : {}",
            job.get("started").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—"),
            job.get("finished").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—"),
            job.get("started_by").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—"),
        ),
        String::new(),
    ];

    // --- synthèse findings par sévérité (sur les findings de CE run) ---
    let mut by_sev: HashMap<String, i64> = HashMap::new();
    let finding_rows: Vec<(String, String, String, String, String, String, String, String, String, String)> = {
        let mut stmt = match db.prepare(
            "SELECT title,target,severity,category,mitre,status,tool,evidence,poc,fix FROM finding WHERE run_id=? ORDER BY id DESC",
        ) {
            Ok(s) => s,
            Err(_) => return out.join("\n"),
        };
        stmt.query_map([run_id], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                r.get::<_, Option<String>>(8)?.unwrap_or_default(),
                r.get::<_, Option<String>>(9)?.unwrap_or_default(),
            ))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    };
    for (_, _, sev, _, _, _, _, _, _, _) in &finding_rows {
        *by_sev.entry(sev.clone()).or_insert(0) += 1;
    }
    out.push("## Synthèse".into());
    out.push(String::new());
    out.push("| Sévérité | # |".into());
    out.push("|---|---|".into());
    for s in SEVERITIES.iter().rev() {
        out.push(format!("| {s} | {} |", by_sev.get(*s).copied().unwrap_or(0)));
    }
    out.push(String::new());

    // --- findings détaillés ---
    out.push("## Findings".into());
    out.push(String::new());
    if finding_rows.is_empty() {
        out.push("_Aucun finding._".into());
        out.push(String::new());
    }
    fn dash(s: &str) -> &str {
        if s.is_empty() { "—" } else { s }
    }
    for (title, target, sev, cat, mitre, status, tool, evidence, poc, fix) in &finding_rows {
        out.push(format!("### [{sev}] {title} — `{target}`"));
        out.push(format!("- **Catégorie** : {}  ·  **ATT&CK** : {}  ·  **Statut** : {}", dash(cat), dash(mitre), dash(status)));
        out.push(format!("- **Outil** : {}", dash(tool)));
        if !evidence.is_empty() {
            out.push(format!("- **Evidence** : {evidence}"));
        }
        if !poc.is_empty() {
            out.push(format!("- **PoC** : {poc}"));
        }
        if !fix.is_empty() {
            out.push(format!("- **Remediation** : {fix}"));
        }
        out.push(String::new());
    }

    // --- transparence ROE (anti-masquage) : compteurs run_job + détail roe_decision ---
    out.push("## Couverture & transparence (ROE / anti-masquage)".into());
    out.push(String::new());
    let geti = |k: &str| job.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    out.push(format!("- **Tirées (FIRE)** : {}", geti("fired")));
    out.push(format!("- **Simulées (DRY_RUN)** : {}", geti("dry_run")));
    out.push(format!("- **Refusées (VETO — hors scope / capacité non autorisée)** : {}", geti("vetoed")));
    out.push(format!("- **Erreurs / skips** : {}", geti("errors")));
    out.push(String::new());

    // détail des verdicts non-FIRE (DRY_RUN/VETO) — réutilise la table roe_decision de l'ingest.
    let verdict_rows: Vec<(String, String, String, String)> = {
        let mut stmt = match db.prepare(
            "SELECT verdict,kind,target,reasons FROM roe_decision WHERE run_id=? AND verdict<>'FIRE' ORDER BY id",
        ) {
            Ok(s) => s,
            Err(_) => return out.join("\n"),
        };
        stmt.query_map([run_id], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            ))
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    };
    if !verdict_rows.is_empty() {
        for (verdict, kind, target, reasons_raw) in &verdict_rows {
            // reasons stocké en JSON (array de chaînes) — on les joint, repli sur le brut.
            let reasons = serde_json::from_str::<Value>(reasons_raw)
                .ok()
                .and_then(|v| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>().join(" ; ")))
                .unwrap_or_else(|| reasons_raw.clone());
            out.push(format!("- `{verdict}` `{kind}` → `{target}` : {reasons}"));
        }
        out.push(String::new());
    }

    // --- coverage gaps + déférées par budget (depuis run_job, comme build_report) ---
    if let Some(gaps) = job.get("coverage_gaps").and_then(|g| g.as_object()) {
        if !gaps.is_empty() {
            out.push("**Classes jamais tentées**".into());
            for (tgt, miss) in gaps {
                let list = miss.as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
                    .unwrap_or_else(|| miss.to_string());
                out.push(format!("- `{tgt}` : {list}"));
            }
            out.push(String::new());
        }
    }
    if let Some(skipped) = job.get("skipped_budget").and_then(|s| s.as_array()) {
        if !skipped.is_empty() {
            out.push("**Déférées (budget)**".into());
            for a in skipped {
                out.push(format!("- {}", cell_string(a)));
            }
            out.push(String::new());
        }
    }

    // --- PURPLE : couverture de DÉTECTION (red tiré vs blue détecté). Optionnelle : présente
    // seulement si l'appelant a fourni la mesure (le rapport API la joint ; le test la passe None).
    if let Some(p) = purple {
        render_purple_section(&mut out, p);
    }

    out.join("\n")
}

/// Section markdown « Couverture détection (purple) » du rapport : detected / missed / MTTD.
/// FAIL-OPEN LISIBLE : si `plume_reachable=false`, on l'indique explicitement et on n'affiche
/// AUCUN détecté/raté (cohérent avec l'endpoint — un SOC muet n'est jamais « tout détecté »).
fn render_purple_section(out: &mut Vec<String>, p: &Value) {
    out.push("## Couverture détection (purple)".into());
    out.push(String::new());
    let reachable = p.get("plume_reachable").and_then(|v| v.as_bool()).unwrap_or(false);
    if !reachable {
        let why = p.get("error").and_then(|v| v.as_str()).unwrap_or("colonne bleue (Plume) injoignable");
        out.push(format!("_Mesure indisponible (fail-open) : {why}. Aucune couverture inventée._"));
        out.push(String::new());
        return;
    }
    let fired = p.get("techniques_fired").and_then(|v| v.as_i64()).unwrap_or(0);
    let detected = p.get("techniques_detected").and_then(|v| v.as_i64()).unwrap_or(0);
    let missed = p.get("techniques_missed").and_then(|v| v.as_i64()).unwrap_or(0);
    let rate = p.get("detection_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let mttd_avg = p.get("mttd_avg_secs").and_then(|v| v.as_f64());
    let mttd_max = p.get("mttd_max_secs").and_then(|v| v.as_i64());
    out.push(format!("- **Techniques tirées (red)** : {fired}"));
    out.push(format!("- **Détectées par le SOC (blue)** : {detected}  ·  **Taux de détection** : {:.0}%", rate * 100.0));
    out.push(format!("- **Trous de détection (missed)** : {missed}"));
    out.push(format!(
        "- **MTTD moyen** : {}  ·  **MTTD max** : {}",
        mttd_avg.map(|m| format!("{m:.0}s")).unwrap_or_else(|| "—".into()),
        mttd_max.map(|m| format!("{m}s")).unwrap_or_else(|| "—".into()),
    ));
    out.push(String::new());
    // détail des trous de détection (priorité blue-team : ce que le SOC n'a PAS vu).
    if let Some(arr) = p.get("missed").and_then(|v| v.as_array()) {
        if !arr.is_empty() {
            out.push("**Techniques NON détectées (trous SOC)**".into());
            for m in arr {
                let mitre = m.get("mitre").and_then(|v| v.as_str()).unwrap_or("?");
                let fires = m.get("fires").and_then(|v| v.as_i64()).unwrap_or(0);
                out.push(format!("- `{mitre}` (tirée {fires}×) — aucune alerte SOC"));
            }
            out.push(String::new());
        }
    }
    // détail des détections (avec MTTD par technique).
    if let Some(arr) = p.get("detected").and_then(|v| v.as_array()) {
        if !arr.is_empty() {
            out.push("**Techniques détectées (avec MTTD)**".into());
            for d in arr {
                let mitre = d.get("mitre").and_then(|v| v.as_str()).unwrap_or("?");
                let alert_count = d.get("alert_count").and_then(|v| v.as_i64()).unwrap_or(0);
                let mttd = d.get("mttd_secs").and_then(|v| v.as_i64());
                out.push(format!(
                    "- `{mitre}` — {alert_count} alerte(s), MTTD {}",
                    mttd.map(|m| format!("{m}s")).unwrap_or_else(|| "—".into()),
                ));
            }
            out.push(String::new());
        }
    }
}

// ===========================================================================================
// C2-light — lancement GOUVERNÉ + AUDITÉ de campagnes Forge depuis l'UI web.
//
// Modèle de sûreté (non négociable) :
//   1. Rôle OPÉRATEUR fail-closed (check_operator) sur TOUTES les routes C2.
//   2. Validation stricte de l'entrée (campaign regex ; hosts hostname-ou-CIDR sans métacaractères ;
//      modules ⊆ kinds connus ET web_allowed=1).
//   3. PLANCHER EXPLOIT (défaut) : 400 si un module demandé est exploit=1 OU destructive=1. Levé
//      UNIQUEMENT par l'opt-in HAUT-IMPACT GOUVERNÉ : `allow_high_impact=true` honoré seulement si
//      operator authentifié (check_operator) + `arm=true` + `reason` non vide (sinon 400
//      'high_impact_requires_arm_and_reason'). Hors opt-in, le plancher tient comme avant.
//   4. Spawn SANS shell : argv fixe via tokio::process::Command ; scope & targets passés par FICHIERS
//      dans un dir temp par run ; le scope écrit force allow_exploit/allow_destructive = valeur de
//      l'opt-in honoré (false par défaut). L'opt-in ne touche QUE allow_exploit/destructive — JAMAIS
//      in_scope/out_scope : le scope-guard du moteur reste seul juge du périmètre (hors-scope = VETO).
//   5. setsid (process group) -> cancel/watchdog tuent le GROUPE ; watchdog timeout (FORGE_RUN_TIMEOUT).
//   6. FIFO : un seul run vivant à la fois (refus 409 sinon).
//   7. Reconciler au boot : tout run_job 'running' orphelin -> 'failed'.
// ===========================================================================================

/// pré-exec hook posix : place l'enfant dans un nouveau groupe de session (setsid) pour que
/// cancel/watchdog puissent tuer TOUT le sous-arbre via killpg, et pour qu'un Ctrl-C console
/// ne propage pas au moteur (et inversement). Sans shell — argv fixe.
#[cfg(unix)]
fn spawn_setsid(cmd: &mut tokio::process::Command) {
    // `pre_exec` est la méthode inhérente de tokio::process::Command (pas le trait std CommandExt).
    unsafe {
        cmd.pre_exec(|| {
            // nouveau groupe de session ; le PID enfant devient le PGID.
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Tue le groupe de process (SIGTERM puis on laisse le watchdog/await récupérer le code).
fn kill_group(pgid: i32) {
    if pgid > 1 {
        unsafe {
            // négatif => cible le GROUPE entier (cf. killpg).
            libc::kill(-pgid, libc::SIGTERM);
        }
    }
}

/// Réconcilie les run_job 'running' au boot : un process spawné qui n'a pas survécu au reboot de la
/// console est orphelin -> 'failed' (jamais laissé 'running' à tort). En PLUS :
///   - tue le GROUPE de process (killpg) de tout pgid enregistré et encore vivant (un moteur détaché
///     qui aurait survécu à un simple restart console deviendrait sinon incontrôlable -> on le coupe) ;
///   - purge les dirs temp `forge-run-*` (scope.json/targets.json) laissés par des runs interrompus.
fn reconcile_runs(db: &Connection) {
    // 1) collecter les pgid des runs marqués 'running' (avant de les flipper).
    let orphan_pgids: Vec<i32> = {
        let stmt = db.prepare("SELECT pid FROM run_job WHERE status='running' AND pid>1");
        match stmt {
            Ok(mut s) => s
                .query_map([], |r| r.get::<_, i64>(0))
                .map(|it| it.filter_map(|r| r.ok()).map(|p| p as i32).collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        }
    };
    // 2) couper tout groupe encore vivant (best-effort ; SIGTERM via killpg). kill_group ignore <=1.
    for pgid in &orphan_pgids {
        kill_group(*pgid);
    }
    // 3) marquer les runs orphelins comme 'failed'.
    let n = db
        .execute(
            "UPDATE run_job SET status='failed', finished=datetime('now'), pid=-1,
               detail=COALESCE(NULLIF(detail,''),'')||' [reconciled: orphelin au boot]'
             WHERE status='running'",
            [],
        )
        .unwrap_or(0);
    if n > 0 {
        println!(
            "[forge-console] reconcile: {n} run(s) orphelin(s) 'running' -> 'failed' ({} groupe(s) signalé(s))",
            orphan_pgids.len()
        );
    }
    // 4) purge des dirs temp de runs (forge-run-*) laissés derrière par des runs interrompus.
    purge_stale_run_dirs();
}

/// Supprime les répertoires temporaires `forge-run-*` (scope.json/targets.json par run) restés dans
/// le tempdir après une interruption (crash/reboot console) — best-effort, jamais fatal.
fn purge_stale_run_dirs() {
    let tmp = std::env::temp_dir();
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        let mut purged = 0;
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("forge-run-") && e.path().is_dir() && std::fs::remove_dir_all(e.path()).is_ok() {
                purged += 1;
            }
        }
        if purged > 0 {
            println!("[forge-console] reconcile: {purged} dir(s) temp forge-run-* purgé(s)");
        }
    }
}

/// Écrit une ligne de log de run en base ET la diffuse aux abonnés SSE.
fn push_run_log(app: &App, run_id: &str, stream: &str, line: &str) {
    {
        let db = app.db();
        let _ = db.execute(
            "INSERT INTO run_log(run_id,ts,stream,line) VALUES(?,datetime('now'),?,?)",
            rusqlite::params![run_id, stream, line],
        );
    }
    // bus SSE lock-free (best-effort : ignore l'absence d'abonné)
    let _ = app.events.send(RunEvent {
        run_id: run_id.to_string(),
        kind: "log".into(),
        payload: json!({"stream": stream, "line": line}),
    });
}

/// POST /api/run — démarre une campagne. Corps JSON :
///   {campaign, targets:[host…], modules:[kind…]?, mode:"propose"|"auto"?, budget:num?,
///    exhaustive:bool?, reason:str?, arm:bool?, allow_high_impact:bool?}
/// Auth : X-Forge-Operator (FAIL-CLOSED). Renvoie 202 {run_id, status:"running", high_impact:bool}.
/// Opt-in haut-impact GOUVERNÉ : `allow_high_impact=true` n'est honoré qu'avec operator + `arm=true`
/// + `reason` non vide (sinon 400 'high_impact_requires_arm_and_reason'). Honoré => le plancher
/// exploit est levé (validate_modules) et le scope du run écrit allow_exploit/destructive=true ;
/// l'autorisation est journalisée au ledger. Hors opt-in : comportement actuel inchangé.
async fn run_create(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    // (1) rôle opérateur fail-closed
    if !check_operator(&app, &headers) {
        let (s, j) = operator_denied(&app);
        return (s, j);
    }

    // (2) validation stricte de l'entrée
    let campaign = match validate_campaign(body.get("campaign").and_then(|v| v.as_str()).unwrap_or("")) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_campaign", "why": e}))),
    };
    let targets_in = match body.get("targets").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_targets", "why": "targets[] requis (non vide)"}))),
    };
    let mut targets: Vec<String> = Vec::new();
    for t in &targets_in {
        let host = t.as_str().unwrap_or("");
        match validate_host(host) {
            Ok(h) => {
                // le scope du run est restreint AU scope serveur (in_scope) — fail-closed : une cible
                // hors du scope serveur est refusée AVANT même le spawn (le moteur la vétoerait, mais
                // on ne dépense pas de process pour ça et on n'élargit jamais le périmètre via le web).
                if !host_in_server_scope(&app, &h) {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "out_of_scope", "why": format!("'{h}' hors du scope serveur autorisé")})));
                }
                targets.push(h);
            }
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_target", "why": e}))),
        }
    }

    // Opt-in haut-impact GOUVERNÉ. Lu AVANT validate_modules car il décide si le plancher exploit
    // tient. `arm` et `reason` sont parsés ici (besoin du gate) — réutilisés tels quels plus bas.
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("").chars().take(200).collect::<String>();
    let arm = body.get("arm").and_then(|v| v.as_bool()).unwrap_or(false);
    let allow_high_impact = body.get("allow_high_impact").and_then(|v| v.as_bool()).unwrap_or(false);
    // GATE : honore l'opt-in seulement si operator (déjà vérifié ci-dessus) + arm=true + reason non
    // vide. Sinon 400 explicite. Ok(false) => plancher exploit inchangé (comportement actuel).
    let high_impact = match high_impact_gate(allow_high_impact, true, arm, &reason) {
        Ok(v) => v,
        Err((code, j)) => return (code, j),
    };

    // modules demandés : ⊆ kinds connus ET web_allowed=1 ; PLANCHER EXPLOIT (exploit|destructive => 400)
    // SAUF si l'opt-in haut-impact est honoré (high_impact=true) — alors exploit/destructif autorisés.
    let requested_modules: Vec<String> = body
        .get("modules")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if let Err((code, j)) = validate_modules(&app, &requested_modules, high_impact) {
        return (code, j);
    }

    // params PAR-MODULE (passthrough) : validés (taille/profondeur/NUL/kind bien formé) puis
    // transportés tels quels jusqu'au moteur via scope.json + targets.json (cf. plus bas). Ne
    // touche AUCUN garde-fou : ce sont des paramètres d'exécution, pas des bascules de capacité —
    // allow_exploit/destructive restent forcés false plus bas, quel que soit le contenu des params.
    let module_params = match validate_module_params(&body, &requested_modules) {
        Ok(m) => m,
        Err((code, j)) => return (code, j),
    };

    let mode = match body.get("mode").and_then(|v| v.as_str()).unwrap_or("propose") {
        "auto" => "auto",
        "propose" => "propose",
        other => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_mode", "why": format!("mode '{other}' invalide (propose|auto)")}))),
    };
    let budget = body.get("budget").and_then(|v| v.as_f64());
    let exhaustive = body.get("exhaustive").and_then(|v| v.as_bool()).unwrap_or(false);
    // `reason`, `arm` et `allow_high_impact`/`high_impact` ont été parsés/évalués plus haut (le gate
    // les exige avant validate_modules). `arm` reste journalisé ; sans opt-in haut-impact honoré il
    // est inerte côté capacité (le scope écrit ci-dessous force allow_*=false dans ce cas).

    // (6) FIFO : un seul run vivant. Le verrou async sérialise les /api/run concurrents ; si un run
    // est déjà enregistré comme courant -> 409 (refus immédiat, pas de file d'attente).
    let mut state = app.run_state.lock().await;
    if state.current.is_some() {
        return (StatusCode::CONFLICT, Json(json!({"error": "run_in_progress", "why": "un run est déjà en cours (FIFO : un seul à la fois)"})));
    }

    // run_id : horodaté + suffixe aléatoire (traçable, unique).
    let run_id = format!("run-{}-{}", chrono_now_compact(), gen_token().chars().take(8).collect::<String>());

    // (4) dir temp par run : scope.json (FORCÉ non-exploit/non-destructif) + targets.json.
    let run_dir = std::env::temp_dir().join(format!("forge-run-{run_id}"));
    if let Err(e) = std::fs::create_dir_all(&run_dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "mkdir_failed", "why": e.to_string()})));
    }
    // scope du run : RESTREINT aux cibles validées. allow_exploit/destructive suivent l'opt-in
    // haut-impact GOUVERNÉ (high_impact) : false par défaut (plancher), true UNIQUEMENT si l'opt-in
    // a été honoré (operator + arm + reason). INVARIANT : on ne touche QUE allow_exploit/destructive —
    // in_scope/out_scope (le périmètre) restent dictés par le scope serveur, le scope-guard du moteur
    // reste seul juge et VÉTOE toute cible hors-scope même avec l'opt-in.
    // `module_params` est transporté tel quel (clé additive ignorée par le ROE/Scope actuel —
    // forward-compat : le moteur la consommera sans changement de l'API de la console).
    let scope_comment = if high_impact {
        format!("scope généré par la console pour {run_id} — HAUT-IMPACT GOUVERNÉ (allow_exploit/destructive=true, autorisé par operator armé)")
    } else {
        format!("scope généré par la console pour {run_id} — exploit/destructif IMPOSSIBLES (forcés false)")
    };
    let scope_notes = if high_impact {
        "lancé via console C2-light (gouverné/audité) — opt-in HAUT-IMPACT honoré (operator+arm+reason) ; scope-guard moteur inchangé (hors-scope = VETO)"
    } else {
        "lancé via console C2-light (gouverné/audité) — non-exploit, non-destructif forcés"
    };
    let scope_doc = json!({
        "_comment": scope_comment,
        "mode": app.scope_mode.as_str(),
        "in_scope": targets,
        "out_scope": [],
        "rate": 5,
        "allow_exploit": high_impact,
        "allow_destructive": high_impact,
        "known_creds": [],
        "idor_targets": [],
        "module_params": Value::Object(module_params.clone()),
        "notes": scope_notes
    });
    // Chaque cible porte les params par-module dans `attrs.module_params` (le moteur charge déjà
    // Target.attrs tel quel). Doublon volontaire avec le scope : selon que le module lit le scope
    // global ou les attrs de sa cible, les params sont disponibles des deux côtés (passthrough sûr).
    let module_params_val = Value::Object(module_params.clone());
    let targets_doc: Vec<Value> = scope_doc["in_scope"].as_array().unwrap().iter()
        .map(|h| json!({"host": h, "kind": "host", "attrs": {"module_params": module_params_val.clone()}}))
        .collect();
    let scope_path = run_dir.join("scope.json");
    let targets_path = run_dir.join("targets.json");
    if std::fs::write(&scope_path, serde_json::to_vec(&scope_doc).unwrap()).is_err()
        || std::fs::write(&targets_path, serde_json::to_vec(&Value::Array(targets_doc)).unwrap()).is_err()
    {
        let _ = std::fs::remove_dir_all(&run_dir);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write_failed", "why": "écriture scope/targets impossible"})));
    }

    // (4) argv FIXE — aucun shell. Les valeurs proviennent de fichiers (chemins) ou sont validées.
    // Le token de la console (en clair) est transmis au moteur UNIQUEMENT via l'environnement
    // (FORGE_CONSOLE_TOKEN), JAMAIS en argv : argv est visible de tout utilisateur local via
    // `ps`/proc/<pid>/cmdline -> y mettre le bearer fuiterait le secret. console_client.ingest lit
    // déjà FORGE_CONSOLE_TOKEN en repli quand --console-token est absent.
    let token: Option<String> = if app.token_raw.is_empty() { None } else { Some(app.token_raw.as_str().to_string()) };
    let console_url = format!("http://{}", std::env::var("FORGE_CONSOLE_ADDR").unwrap_or_else(|_| "127.0.0.1:7100".to_string()));
    let mut argv: Vec<String> = vec![
        "-m".into(), "forge.cli".into(), "campaign".into(),
        "--scope".into(), scope_path.to_string_lossy().into_owned(),
        "--targets".into(), targets_path.to_string_lossy().into_owned(),
        "--campaign".into(), campaign.clone(),
        "--mode".into(), mode.to_string(),
        "--run-id".into(), run_id.clone(),
        "--ledger".into(), app.ledger_path.as_str().to_string(),
        "--console".into(), console_url.clone(),
    ];
    if let Some(b) = budget { argv.push("--budget".into()); argv.push(format!("{b}")); }
    if exhaustive { argv.push("--exhaustive".into()); }
    // sélection de modules de l'UI -> --modules kind1,kind2 : RESTREINT le plan du moteur aux
    // kinds demandés (déjà validés : ⊆ kinds connus, web_allowed=1, ni exploit ni destructif).
    // Vide -> flag omis -> le moteur garde le plan complet du cerveau (comportement inchangé).
    // Les kinds passent la grammaire validate_modules (kind bien formé) : pas d'injection d'argv
    // (argv FIXE, aucun shell), et la gate ROE reste seule juge des capacités.
    if !requested_modules.is_empty() {
        argv.push("--modules".into());
        argv.push(requested_modules.join(","));
    }
    if !reason.is_empty() { argv.push("--reason".into()); argv.push(reason.clone()); }
    // --arm : armement explicite. Sans opt-in haut-impact honoré il reste inerte côté capacité (le
    // scope écrit force allow_*=false). Avec l'opt-in honoré (high_impact), le scope écrit
    // allow_exploit/destructive=true -> le moteur peut exécuter les modules haut-impact AUTORISÉS,
    // toujours sous le veto scope-guard pour le périmètre.
    if arm { argv.push("--arm".into()); }
    // NB: pas de `--console-token` en argv (fuite via ps/cmdline) — passé par env ci-dessous.

    let mut cmd = tokio::process::Command::new(app.python.as_str());
    cmd.args(&argv)
        .current_dir(app.pkg_dir.as_str())
        .env("FORGE_CONSOLE_URL", &console_url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(t) = &token { cmd.env("FORGE_CONSOLE_TOKEN", t); }
    #[cfg(unix)]
    spawn_setsid(&mut cmd);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&run_dir);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "spawn_failed", "why": e.to_string()})));
        }
    };
    let pid = child.id().map(|p| p as i32).unwrap_or(-1);
    let pgid = pid; // setsid => le PID enfant EST le PGID.

    // AUDIT haut-impact : si l'opt-in a été honoré, lister précisément les modules exploit/destructif
    // explicitement demandés qui ont été DÉBLOQUÉS (pour la traçabilité ; vide si le planner choisit
    // seul). N'altère aucun garde-fou — lecture du registre uniquement.
    let hi_modules: Vec<String> = if high_impact { high_impact_modules(&app, &requested_modules) } else { vec![] };

    // run_job 'running' + provenance opérateur. Le started_by est volontairement non-PII (rôle) ;
    // on y encode aussi l'autorisation haut-impact ("operator+high_impact") pour que tout run armé
    // soit traçable depuis run_job sans nouvelle colonne (audit renforcé). `reason` est déjà persisté.
    let started_by = if high_impact { "operator+high_impact" } else { "operator" };
    {
        let db = app.db();
        let _ = db.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,mode,pid,started_by,reason,targets,modules,started)
             VALUES(?,?,datetime('now'),'running',?,?,?,?,?,?,datetime('now'))
             ON CONFLICT(run_id) DO UPDATE SET status='running', pid=excluded.pid, started=excluded.started",
            rusqlite::params![
                run_id, campaign, mode, pgid, started_by, reason,
                serde_json::to_string(&body.get("targets").cloned().unwrap_or(json!([]))).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&requested_modules).unwrap_or_else(|_| "[]".into())
            ],
        );
    }
    // ledger : trace l'acte de lancement (qui/quoi/quand) — preuve d'audit côté console. Quand
    // l'opt-in haut-impact est honoré, on JOURNALISE EXPLICITEMENT l'autorisation (operator + reason
    // + liste des modules exploit/destructif débloqués), de sorte que tout lancement haut-impact soit
    // traçable et non-répudiable dans la chaîne du ledger.
    if high_impact {
        append_console_ledger(&app, "console.run.high_impact_authorized", json!({
            "run_id": run_id, "campaign": campaign, "by": "operator",
            "arm": arm, "reason": reason,
            "exploit_modules_authorized": hi_modules,
            "requested_modules": requested_modules,
            "allow_exploit": true, "allow_destructive": true,
            "note": "opt-in haut-impact GOUVERNÉ honoré (operator+arm+reason) ; scope-guard moteur inchangé (hors-scope = VETO)"
        }));
    }
    append_console_ledger(&app, "console.run.start", json!({
        "run_id": run_id, "campaign": campaign, "mode": mode, "by": "operator",
        "targets": body.get("targets").cloned().unwrap_or(json!([])), "modules": requested_modules,
        "module_params": Value::Object(module_params.clone()),
        "reason": reason, "arm_requested": arm,
        "high_impact": high_impact,
        "exploit_floor": if high_impact { "lifted via governed high-impact opt-in (allow_exploit=true allow_destructive=true)" } else { "forced allow_exploit=false allow_destructive=false" }
    }));

    state.current = Some(RunHandle { run_id: run_id.clone(), pgid });
    let _ = app.events.send(RunEvent { run_id: run_id.clone(), kind: "status".into(), payload: json!({"status": "running"}) });
    drop(state); // libère le verrou FIFO avant de détacher le superviseur

    // superviseur : pompe stdout/stderr -> run_log + SSE ; watchdog timeout ; finalisation atomique.
    spawn_supervisor(app.clone(), child, run_id.clone(), run_dir);

    (StatusCode::ACCEPTED, Json(json!({"run_id": run_id, "status": "running", "campaign": campaign, "mode": mode, "high_impact": high_impact})))
}

/// Valide une CHAÎNE issue des params par-module avant de l'écrire dans scope.json/targets.json.
/// Le moteur lit ces fichiers sans shell, mais on durcit malgré tout : refus des octets NUL et des
/// chaînes démesurées (anti-DoS d'écriture). Les métacaractères shell sont tolérés DANS les valeurs
/// (ex: une URL avec `?`, `&`) car elles ne sont jamais concaténées à un shell — seulement le NUL et
/// une borne de longueur sont durs. C'est cohérent avec validate_host (qui, lui, gardait des HÔTES).
fn validate_param_string(s: &str) -> Result<(), String> {
    if s.len() > 2048 {
        return Err("valeur de param trop longue (>2048)".into());
    }
    if s.contains('\0') {
        return Err("valeur de param contient un octet NUL".into());
    }
    Ok(())
}

/// Profondeur/validation récursive d'une valeur de param (anti-bombe JSON : profondeur bornée).
fn validate_param_value(v: &Value, depth: u32) -> Result<(), String> {
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

/// Valide les params PAR-MODULE du corps /api/run. Forme attendue :
///   "module_params": { "<kind>": { ... }, ... }
/// Règles : chaque clé doit être un `kind` bien formé ([A-Za-z0-9._-], 1..64) ; si une allow-list de
/// modules est fournie (modules non vide), la clé DOIT y appartenir (on ne transporte pas de params
/// pour un module qui ne sera pas lancé) ; chaque valeur est un objet, validé récursivement (taille,
/// profondeur, NUL). Renvoie la map normalisée (kind -> objet params) ou 400. Absent/vide => map vide.
fn validate_module_params(
    body: &Value,
    modules: &[String],
) -> Result<serde_json::Map<String, Value>, (StatusCode, Json<Value>)> {
    let mut out = serde_json::Map::new();
    let raw = match body.get("module_params") {
        None | Some(Value::Null) => return Ok(out),
        Some(Value::Object(m)) => m,
        Some(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(json!({
                "error": "bad_module_params", "why": "module_params doit être un objet {kind: {params}}"
            }))));
        }
    };
    if raw.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, Json(json!({
            "error": "bad_module_params", "why": "trop de modules dans module_params (>128)"
        }))));
    }
    for (kind, params) in raw {
        // clé = kind bien formé (même grammaire que validate_campaign : pas de métacaractère/-en-tête).
        if let Err(e) = validate_campaign(kind) {
            return Err((StatusCode::BAD_REQUEST, Json(json!({
                "error": "bad_module_params", "why": format!("clé module '{kind}' invalide: {e}")
            }))));
        }
        // si une allow-list explicite est fournie, on n'accepte de params QUE pour ces modules.
        if !modules.is_empty() && !modules.iter().any(|m| m == kind) {
            return Err((StatusCode::BAD_REQUEST, Json(json!({
                "error": "param_for_unrequested_module",
                "why": format!("params fournis pour '{kind}' qui n'est pas dans modules[]")
            }))));
        }
        if !params.is_object() {
            return Err((StatusCode::BAD_REQUEST, Json(json!({
                "error": "bad_module_params", "why": format!("params de '{kind}' doivent être un objet")
            }))));
        }
        if let Err(e) = validate_param_value(params, 0) {
            return Err((StatusCode::BAD_REQUEST, Json(json!({
                "error": "bad_module_params", "why": format!("params de '{kind}': {e}")
            }))));
        }
        out.insert(kind.clone(), params.clone());
    }
    Ok(out)
}

/// Vérifie qu'un module demandé existe (kinds connus), est web_allowed=1, et N'EST NI exploit NI
/// destructive (PLANCHER EXPLOIT). 400 sinon. Liste vide => OK (le planner choisira tout seul, et le
/// scope force allow_*=false de toute façon).
///
/// `allow_high_impact` : quand l'opt-in haut-impact gouverné est HONORÉ (operator + arm + reason —
/// cf. `high_impact_gate`), le PLANCHER EXPLOIT est levé : les modules exploit/destructive sont
/// acceptés (et la dérivée `web_allowed=0` qui n'existe QUE parce que exploit/destructif/idor est
/// elle aussi tolérée). Le contrôle `unknown_module` reste TOUJOURS appliqué — on n'accepte jamais
/// un kind inconnu du registre, même armé. `false` (défaut) => comportement actuel inchangé.
fn validate_modules(app: &App, modules: &[String], allow_high_impact: bool) -> Result<(), (StatusCode, Json<Value>)> {
    if modules.is_empty() {
        return Ok(());
    }
    let db = app.db();
    for m in modules {
        let row = db.query_row(
            "SELECT exploit,destructive,web_allowed FROM module WHERE kind=?",
            [m],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
        );
        match row {
            Ok((exploit, destructive, web_allowed)) => {
                // Opt-in haut-impact honoré : on NE rejette PAS exploit/destructif. Le scope-guard du
                // moteur reste seul juge des cibles (hors-scope = VETO), l'écriture allow_* ne touche
                // que la capacité, jamais le périmètre.
                if allow_high_impact {
                    continue;
                }
                if exploit != 0 || destructive != 0 {
                    return Err((StatusCode::BAD_REQUEST, Json(json!({
                        "error": "exploit_floor",
                        "why": format!("module '{m}' est exploit/destructif — interdit depuis le web (sans opt-in haut-impact gouverné)")
                    }))));
                }
                if web_allowed == 0 {
                    return Err((StatusCode::BAD_REQUEST, Json(json!({
                        "error": "not_web_allowed",
                        "why": format!("module '{m}' n'est pas lançable depuis le web (web_allowed=0)")
                    }))));
                }
            }
            Err(_) => {
                return Err((StatusCode::BAD_REQUEST, Json(json!({
                    "error": "unknown_module",
                    "why": format!("module '{m}' inconnu du registre")
                }))));
            }
        }
    }
    Ok(())
}

/// Liste, parmi `modules`, ceux marqués exploit OU destructive dans le registre — c.-à-d. les
/// modules HAUT-IMPACT effectivement autorisés par un opt-in honoré. Sert UNIQUEMENT à l'audit
/// (ledger + run_job) : tracer précisément quelles capacités haut-impact ont été débloquées pour ce
/// run. N'altère aucun garde-fou. Liste vide => le planner choisit seul (rien d'explicitement listé).
fn high_impact_modules(app: &App, modules: &[String]) -> Vec<String> {
    let db = app.db();
    modules
        .iter()
        .filter(|m| {
            db.query_row(
                "SELECT exploit,destructive FROM module WHERE kind=?",
                [m.as_str()],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )
            .map(|(e, d)| e != 0 || d != 0)
            .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// GATE de gouvernance haut-impact — fonction PURE (testable, aucun effet de bord).
///
/// Décide si l'opt-in `allow_high_impact` du corps /api/run est HONORÉ. L'opt-in n'est honoré QUE si
/// les TROIS conditions de gouvernance sont réunies :
///   (1) requête authentifiée operator (vérifiée en amont par `check_operator`, fail-closed —
///       passée ici via `operator_ok` pour garder la fonction pure et testable) ;
///   (2) `arm == true` (armement explicite) ;
///   (3) `reason` non vide (raison obligatoire, déjà bornée à 200 car. par l'appelant).
///
/// Retour :
///   - `Ok(false)` : opt-in NON demandé (`allow_high_impact=false`) -> comportement ACTUEL inchangé
///     (plancher exploit tient, scope écrit allow_*=false) ;
///   - `Ok(true)`  : opt-in demandé ET les 3 conditions réunies -> capacité haut-impact autorisée ;
///   - `Err((code, json))` : opt-in demandé mais une condition manque -> 400 explicite.
fn high_impact_gate(
    allow_high_impact: bool,
    operator_ok: bool,
    arm: bool,
    reason: &str,
) -> Result<bool, (StatusCode, Json<Value>)> {
    if !allow_high_impact {
        return Ok(false); // défaut : aucune dérogation, plancher exploit inchangé
    }
    // operator_ok est en principe TOUJOURS vrai à ce stade (check_operator a déjà gaté l'endpoint) ;
    // on le revérifie ici par défense en profondeur — un opt-in haut-impact ne peut JAMAIS être
    // honoré sans preuve operator, quelle que soit l'ordre des futurs appelants (fail-closed).
    if !operator_ok || !arm || reason.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(json!({
            "error": "high_impact_requires_arm_and_reason",
            "why": "allow_high_impact n'est honoré qu'avec operator authentifié + arm=true + reason non vide"
        }))));
    }
    Ok(true)
}

/// Vrai si l'hôte appartient au scope serveur (in_scope). Match littéral exact ou suffixe de domaine
/// (sous-domaine d'une entrée listée). Conservateur : pas de glob côté console — le moteur Python
/// applique le vrai matching ROE, ceci n'est qu'un pré-filtre fail-closed pour ne pas spawner hors scope.
fn host_in_server_scope(app: &App, host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    if app.scope_in.is_empty() {
        return false; // fail-closed : scope serveur vide => rien n'est lançable
    }
    app.scope_in.iter().any(|p| {
        let p = p.to_ascii_lowercase();
        let p = p.strip_prefix("*.").unwrap_or(&p);
        h == p || h.ends_with(&format!(".{p}"))
    })
}

/// Horodatage compact UTC pour les run_id, sans dépendance chrono : YYYYmmddHHMMSS dérivé du temps
/// unix (suffisant pour l'unicité combiné au token aléatoire).
fn chrono_now_compact() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// Ajoute une entrée au ledger JSONL côté console (chaîne SHA-256, alg "sha256-console", sig "").
/// Compatible avec /api/ledger/verify (qui ne vérifie pas la signature, seulement le hash-chaining).
fn append_console_ledger(app: &App, kind: &str, detail: Value) {
    let path = app.ledger_path.as_str();
    // VERROU ledger : couvre lecture-head -> calcul hash -> écriture en UNE section critique. Sans lui,
    // deux appends concurrents lisaient le MÊME prev/seq puis écrivaient deux entrées de même seq/prev
    // -> chaîne SHA-256 cassée (la vérif /api/ledger/verify échouerait). Empoisonnement récupéré
    // (into_inner) : un panic passé ne doit pas geler l'audit.
    let mut head = app.ledger_lock.lock().unwrap_or_else(|e| e.into_inner());
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
        if writeln!(f, "{}", canon_json(&rec)).is_ok() {
            head.prev = hash;
            head.seq = seq;
        } else {
            head.loaded = false; // écriture partielle/échouée -> forcer une relecture au prochain append
        }
    } else {
        head.loaded = false;
    }
}

/// Détache le superviseur du run : pompe stdout/stderr ligne à ligne vers run_log+SSE, applique le
/// watchdog (FORGE_RUN_TIMEOUT) qui tue le GROUPE, puis finalise le run_job (status terminal) et
/// libère le slot FIFO. Atomique : quel que soit le chemin de sortie, le run est marqué terminal.
fn spawn_supervisor(app: App, mut child: tokio::process::Child, run_id: String, run_dir: std::path::PathBuf) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    tokio::spawn(async move {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        // pompes stdout/stderr concurrentes
        let (app_o, rid_o) = (app.clone(), run_id.clone());
        let pump_out = tokio::spawn(async move {
            if let Some(out) = stdout {
                let mut lines = BufReader::new(out).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    push_run_log(&app_o, &rid_o, "stdout", &line);
                }
            }
        });
        let (app_e, rid_e) = (app.clone(), run_id.clone());
        let pump_err = tokio::spawn(async move {
            if let Some(err) = stderr {
                let mut lines = BufReader::new(err).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    push_run_log(&app_e, &rid_e, "stderr", &line);
                }
            }
        });

        // attente du process avec watchdog timeout -> kill group.
        let timeout = Duration::from_secs(app.run_timeout_secs);
        let (final_status, exit_code): (&str, Option<i64>) = match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => {
                let code = status.code().map(|c| c as i64);
                if status.success() { ("done", code) } else { ("failed", code) }
            }
            Ok(Err(_)) => ("failed", None),
            Err(_) => {
                // timeout : tuer le groupe, récupérer.
                push_run_log(&app, &run_id, "system", &format!("watchdog: timeout {}s — kill group", app.run_timeout_secs));
                let pgid = {
                    let st = app.run_state.lock().await;
                    st.current.as_ref().filter(|h| h.run_id == run_id).map(|h| h.pgid).unwrap_or(-1)
                };
                kill_group(pgid);
                let _ = child.wait().await;
                ("timeout", None)
            }
        };
        let _ = pump_out.await;
        let _ = pump_err.await;

        // finalisation : status terminal + exit_code + finished. Ne pas écraser un statut 'cancelled'
        // déjà posé par run_cancel (cancel l'emporte sur la cause secondaire SIGTERM).
        {
            let db = app.db();
            // UPDATE conditionnel : ne finalise QUE si le run est encore 'running' ou 'cancelled'
            // (course superviseur vs cancel). Un statut déjà terminal posé ailleurs n'est pas écrasé.
            // CASE préserve 'cancelled' (cancel l'emporte sur la cause secondaire SIGTERM/timeout).
            let _ = db.execute(
                "UPDATE run_job SET status=CASE WHEN status='cancelled' THEN 'cancelled' ELSE ? END,
                   finished=datetime('now'), pid=-1, exit_code=?
                 WHERE run_id=? AND status IN ('running','cancelled')",
                rusqlite::params![final_status, exit_code, run_id],
            );
        }
        let terminal: String = {
            let db = app.db();
            db.query_row("SELECT status FROM run_job WHERE run_id=?", [&run_id], |r| r.get::<_, String>(0))
                .unwrap_or_else(|_| final_status.to_string())
        };
        append_console_ledger(&app, "console.run.end", json!({
            "run_id": run_id, "status": terminal, "exit_code": exit_code
        }));

        // libère le slot FIFO + diffuse le statut terminal.
        {
            let mut st = app.run_state.lock().await;
            if st.current.as_ref().map(|h| h.run_id == run_id).unwrap_or(false) {
                st.current = None;
            }
        }
        let _ = app.events.send(RunEvent { run_id: run_id.clone(), kind: "status".into(), payload: json!({"status": terminal, "exit_code": exit_code}) });
        // nettoyage du dir temp (scope/targets) — best-effort.
        let _ = std::fs::remove_dir_all(&run_dir);
    });
}

/// POST /api/runs/:id/cancel — annule un run vivant (kill group). Opérateur fail-closed.
async fn run_cancel(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> impl IntoResponse {
    if !check_operator(&app, &headers) {
        let (s, j) = operator_denied(&app);
        return (s, j);
    }
    let pgid = {
        let st = app.run_state.lock().await;
        match &st.current {
            Some(h) if h.run_id == id => h.pgid,
            _ => -1,
        }
    };
    if pgid <= 1 {
        // run inconnu ou déjà terminé.
        let exists: bool = {
            let db = app.db();
            db.query_row("SELECT 1 FROM run_job WHERE run_id=?", [&id], |_| Ok(())).is_ok()
        };
        return if exists {
            (StatusCode::CONFLICT, Json(json!({"error": "not_running", "why": "le run n'est pas en cours"})))
        } else {
            (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"})))
        };
    }
    // marque 'cancelled' AVANT le kill, mais SEULEMENT si le run est encore 'running' (UPDATE
    // conditionnel : course cancel vs finalisation superviseur — on ne ré-ouvre pas un run déjà
    // terminal en 'cancelled'). Le superviseur, lui, préserve 'cancelled' s'il le voit posé.
    {
        let db = app.db();
        let _ = db.execute("UPDATE run_job SET status='cancelled' WHERE run_id=? AND status='running'", [&id]);
    }
    push_run_log(&app, &id, "system", "cancel demandé par l'opérateur — kill group");
    append_console_ledger(&app, "console.run.cancel", json!({"run_id": id, "by": "operator"}));
    kill_group(pgid);
    (StatusCode::OK, Json(json!({"run_id": id, "status": "cancelling"})))
}

/// Sérialise un run_job en JSON (vue détaillée / liste).
fn run_job_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "run_id": r.get::<_, String>(0)?,
        "campaign": r.get::<_, Option<String>>(1)?.unwrap_or_default(),
        "ts": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
        "status": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
        "mode": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
        "fired": r.get::<_, Option<i64>>(5)?.unwrap_or(0),
        "dry_run": r.get::<_, Option<i64>>(6)?.unwrap_or(0),
        "vetoed": r.get::<_, Option<i64>>(7)?.unwrap_or(0),
        "errors": r.get::<_, Option<i64>>(8)?.unwrap_or(0),
        "skipped_budget": serde_json::from_str::<Value>(&r.get::<_, Option<String>>(9)?.unwrap_or_else(|| "[]".into())).unwrap_or(json!([])),
        "coverage_gaps": serde_json::from_str::<Value>(&r.get::<_, Option<String>>(10)?.unwrap_or_else(|| "{}".into())).unwrap_or(json!({})),
        "started_by": r.get::<_, Option<String>>(11)?.unwrap_or_default(),
        "reason": r.get::<_, Option<String>>(12)?.unwrap_or_default(),
        "targets": serde_json::from_str::<Value>(&r.get::<_, Option<String>>(13)?.unwrap_or_else(|| "[]".into())).unwrap_or(json!([])),
        "modules": serde_json::from_str::<Value>(&r.get::<_, Option<String>>(14)?.unwrap_or_else(|| "[]".into())).unwrap_or(json!([])),
        "started": r.get::<_, Option<String>>(15)?.unwrap_or_default(),
        "finished": r.get::<_, Option<String>>(16)?.unwrap_or_default(),
        "exit_code": r.get::<_, Option<i64>>(17)?,
    }))
}

const RUN_JOB_COLS: &str = "run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps,started_by,reason,targets,modules,started,finished,exit_code";

/// GET /api/runs — liste les runs (récents d'abord). Lecture (viewer) — pas besoin d'opérateur.
async fn runs_list(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let db = app.db();
    let (mut conds, mut args): (Vec<&str>, Vec<String>) = (vec![], vec![]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?"); args.push(c.clone()); }
    if let Some(s) = q.get("status") { conds.push("status=?"); args.push(s.clone()); }
    let where_ = if conds.is_empty() { String::new() } else { format!(" WHERE {}", conds.join(" AND ")) };
    let (limit, offset) = paginate(&q, 100, 1000);
    let sql = format!("SELECT {RUN_JOB_COLS} FROM run_job{where_} ORDER BY id DESC LIMIT {limit} OFFSET {offset}");
    let mut stmt = match db.prepare(&sql) { Ok(s) => s, Err(_) => return Json(json!([])) };
    let out: Vec<Value> = stmt
        .query_map(rusqlite::params_from_iter(args.iter()), run_job_json)
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    Json(Value::Array(out))
}

/// GET /api/runs/:id — détail d'un run. Lecture (viewer).
async fn run_detail(State(app): State<App>, Path(id): Path<String>) -> impl IntoResponse {
    let db = app.db();
    let sql = format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?");
    match db.query_row(&sql, [&id], run_job_json) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"}))),
    }
}

/// GET /api/runs/:id/logs?after=ID — lignes de log d'un run (fallback polling de SSE).
/// `after` (id de ligne) permet l'incrémental ; renvoie {last_id, lines:[{id,ts,stream,line}]}.
async fn run_logs(State(app): State<App>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let after = q.get("after").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(2000).clamp(1, 5000);
    let db = app.db();
    let mut stmt = match db.prepare(
        "SELECT id,ts,stream,line FROM run_log WHERE run_id=? AND id>? ORDER BY id LIMIT ?",
    ) { Ok(s) => s, Err(_) => return Json(json!({"last_id": after, "lines": []})) };
    let mut last = after;
    let lines: Vec<Value> = stmt
        .query_map(rusqlite::params![id, after, limit], |r| {
            let lid: i64 = r.get(0)?;
            Ok((lid, json!({
                "id": lid,
                "ts": r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                "stream": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                "line": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            })))
        })
        .map(|it| it.filter_map(|r| r.ok()).map(|(lid, v)| { if lid > last { last = lid; } v }).collect())
        .unwrap_or_default();
    Json(json!({"last_id": last, "lines": lines}))
}

/// GET /api/runs/:id/events — flux SSE des lignes de log + transitions de statut d'un run.
/// Events : `log` ({stream,line}) et `status` ({status,exit_code?}). Fallback : /api/runs/:id/logs.
/// Diffuse les events broadcast filtrés sur run_id. Termine quand le statut devient terminal.
async fn run_sse(State(app): State<App>, Path(id): Path<String>) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let rx = app.events.subscribe();
    let stream = futures_util::stream::unfold((rx, id, false), |(mut rx, id, mut done)| async move {
        if done {
            return None;
        }
        loop {
            match rx.recv().await {
                Ok(ev) if ev.run_id == id => {
                    if ev.kind == "status" {
                        let s = ev.payload.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        if matches!(s, "done" | "failed" | "timeout" | "cancelled") {
                            done = true;
                        }
                    }
                    let event = Event::default().event(ev.kind.clone()).json_data(&ev.payload).unwrap_or_else(|_| Event::default().comment("bad"));
                    return Some((Ok(event), (rx, id, done)));
                }
                Ok(_) => continue, // évènement d'un autre run
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // le consommateur SSE a pris du retard et a PERDU `n` évènements (buffer broadcast
                    // débordé). On émet un event `lag` explicite -> le client sait qu'il a un trou et
                    // peut se resynchroniser via /api/runs/:id/logs?after=... (au lieu d'un silence).
                    let event = Event::default().event("lag")
                        .json_data(json!({"dropped": n}))
                        .unwrap_or_else(|_| Event::default().comment("lag"));
                    return Some((Ok(event), (rx, id, done)));
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("keep-alive"))
}

// =====================================================================================
// Parité LECTURE en ligne de commande — `forge-console findings|roe|coverage|query`.
//
// Réutilise la connexion SQLite en READ-ONLY (SQLITE_OPEN_READ_ONLY, défense en profondeur :
// même un bug ne peut pas muter la base depuis ces sous-commandes) et, pour `query`, le compilateur
// `soql::compile` DÉJÀ partagé avec l'API web. Sortie en table (défaut) ou JSON (--json).
// Le provisioning opérateur reste, lui, via `hashpw-operator` (déjà présent).
// =====================================================================================

/// Chemin de la base lue par les sous-commandes CLI (idem boot : $FORGE_CONSOLE_DB sinon défaut).
fn cli_db_path() -> String {
    std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge-console.db".to_string())
}

/// Ouvre la base en READ-ONLY pour les lectures CLI. Renvoie None (et journalise) si l'ouverture
/// échoue (base absente, etc.) — l'appelant sort alors en code 2 (erreur d'usage/IO).
fn cli_open_ro(db_path: &str) -> Option<Connection> {
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
fn cli_opt(args: &[String], name: &str) -> Option<String> {
    let flag = format!("--{name}");
    args.iter().position(|a| *a == flag).and_then(|i| args.get(i + 1).cloned())
}

/// Vrai si le drapeau booléen `--<name>` est présent.
fn cli_flag(args: &[String], name: &str) -> bool {
    let flag = format!("--{name}");
    args.contains(&flag)
}

/// Imprime un tableau ASCII simple (colonnes alignées) — sans dépendance externe. Les cellules
/// non-textuelles sont rendues compactes ; les valeurs longues sont laissées telles quelles (lecture
/// locale par l'opérateur). Vide -> ligne « (aucune ligne) ».
fn print_table(columns: &[String], rows: &[Vec<String>]) {
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
fn cell_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Imprime une liste d'objets JSON (tous mêmes clés `cols`) en table ou JSON selon `as_json`.
fn print_objects(cols: &[&str], rows: &[Value], as_json: bool) {
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

/// Dispatch des sous-commandes de lecture. Retourne un code de sortie : 0 = OK, 2 = erreur (IO/SOQL).
fn run_read_cli(cmd: &str, args: &[String]) -> i32 {
    let as_json = cli_flag(args, "json");
    let campaign = cli_opt(args, "campaign");
    let db_path = cli_db_path();
    match cmd {
        "findings" => {
            let conn = match cli_open_ro(&db_path) { Some(c) => c, None => return 2 };
            let (where_, params): (String, Vec<String>) = match &campaign {
                Some(c) => (" WHERE campaign=?".into(), vec![c.clone()]),
                None => (String::new(), vec![]),
            };
            let sql = format!(
                "SELECT id,ts,campaign,target,title,severity,category,mitre,status,tool,run_id FROM finding{where_} ORDER BY id DESC LIMIT 1000"
            );
            let rows = cli_query_rows(&conn, &sql, &params, &[
                "id", "ts", "campaign", "target", "title", "severity", "category", "mitre", "status", "tool", "run_id",
            ]);
            print_objects(&["id", "ts", "campaign", "target", "title", "severity", "status", "mitre", "tool"], &rows, as_json);
            0
        }
        "roe" => {
            let conn = match cli_open_ro(&db_path) { Some(c) => c, None => return 2 };
            let (where_, params): (String, Vec<String>) = match &campaign {
                Some(c) => (" WHERE campaign=?".into(), vec![c.clone()]),
                None => (String::new(), vec![]),
            };
            let sql = format!(
                "SELECT id,ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons FROM roe_decision{where_} ORDER BY id DESC LIMIT 2000"
            );
            let rows = cli_query_rows(&conn, &sql, &params, &[
                "id", "ts", "campaign", "run_id", "action_id", "target", "kind", "verdict", "exploit", "destructive", "reasons",
            ]);
            print_objects(&["id", "ts", "campaign", "run_id", "target", "kind", "verdict", "exploit", "destructive"], &rows, as_json);
            0
        }
        "coverage" => {
            let conn = match cli_open_ro(&db_path) { Some(c) => c, None => return 2 };
            let (sql, params): (&str, Vec<String>) = match &campaign {
                Some(c) => (
                    "SELECT mitre, COUNT(*) runs, COALESCE(SUM(fired),0) fired FROM runrecord WHERE mitre<>'' AND campaign=? GROUP BY mitre ORDER BY runs DESC",
                    vec![c.clone()],
                ),
                None => (
                    "SELECT mitre, COUNT(*) runs, COALESCE(SUM(fired),0) fired FROM runrecord WHERE mitre<>'' GROUP BY mitre ORDER BY runs DESC",
                    vec![],
                ),
            };
            let rows = cli_query_rows(&conn, sql, &params, &["mitre", "runs", "fired"]);
            print_objects(&["mitre", "runs", "fired"], &rows, as_json);
            0
        }
        "query" => {
            // --soql '...' (ou repli sur le 1er argument positionnel non-drapeau) -> soql::compile.
            let soql = cli_opt(args, "soql").or_else(|| {
                let mut it = args.iter();
                while let Some(a) = it.next() {
                    if a == "--campaign" || a == "--soql" {
                        it.next(); // consomme la valeur du drapeau
                        continue;
                    }
                    if !a.starts_with("--") {
                        return Some(a.clone());
                    }
                }
                None
            });
            let soql = match soql {
                Some(s) if !s.is_empty() => s,
                _ => {
                    eprintln!("usage: forge-console query --soql '<pipeline soql>' [--json]");
                    return 2;
                }
            };
            match exec_soql(&db_path, &soql) {
                Ok(v) => {
                    if as_json {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()));
                    } else {
                        let cols: Vec<String> = v.get("columns").and_then(|c| c.as_array())
                            .map(|a| a.iter().map(cell_string).collect()).unwrap_or_default();
                        let table: Vec<Vec<String>> = v.get("rows").and_then(|r| r.as_array())
                            .map(|rows| rows.iter().map(|row| {
                                row.as_array().map(|cells| cells.iter().map(cell_string).collect())
                                    .unwrap_or_default()
                            }).collect())
                            .unwrap_or_default();
                        print_table(&cols, &table);
                    }
                    0
                }
                Err((_, e)) => {
                    eprintln!("[forge-console] query: SOQL invalide: {e}");
                    2
                }
            }
        }
        _ => 2,
    }
}

/// Exécute une requête SQL paramétrée et renvoie chaque ligne en objet JSON {col: valeur}, en
/// préservant le type SQLite via `cell()`. Best-effort : une erreur de préparation -> vec vide.
fn cli_query_rows(conn: &Connection, sql: &str, params: &[String], cols: &[&str]) -> Vec<Value> {
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[forge-console] lecture CLI: requête invalide: {e}");
            return vec![];
        }
    };
    let ncol = cols.len();
    stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
        let mut o = serde_json::Map::new();
        for (i, c) in cols.iter().enumerate().take(ncol) {
            o.insert((*c).to_string(), cell(row, i));
        }
        Ok(Value::Object(o))
    })
    .map(|it| it.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // sous-commandes de provisioning de hash argon2id :
    //   forge-console hashpw <password>           -> hash du viewer (FORGE_CONSOLE_PASS_HASH)
    //   forge-console hashpw-operator <password>  -> hash du rôle OPÉRATEUR C2 (FORGE_CONSOLE_OPERATOR_HASH)
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("hashpw") | Some("hashpw-operator") => {
            match args.get(2) {
                Some(pw) if !pw.is_empty() => {
                    println!("{}", hash_pw(pw));
                    return;
                }
                _ => {
                    eprintln!("usage: forge-console {} <password>", args[1]);
                    std::process::exit(2);
                }
            }
        }
        // Parité LECTURE locale (CLI) : lit la MÊME base SQLite que l'API, en READ-ONLY, et
        // imprime en table (défaut) ou JSON (--json). Aucune écriture, aucun spawn — pure lecture.
        Some(cmd @ ("findings" | "roe" | "coverage" | "query")) => {
            std::process::exit(run_read_cli(cmd, &args[2..]));
        }
        _ => {}
    }

    let db_path = std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge-console.db".to_string());
    let conn = Connection::open(&db_path).expect("open db");
    // WAL : meilleure concurrence lecture/écriture (les /api lecture-seule via une 2e connexion
    // read-only ne bloquent plus les écritures) + reprise sur crash plus propre. busy_timeout évite
    // qu'une écriture concurrente échoue immédiatement sur SQLITE_BUSY. Best-effort (PRAGMA renvoie une
    // ligne -> query_row), error-ignoré : si le FS ne supporte pas WAL, on retombe sur le mode par défaut.
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    conn.execute_batch(SCHEMA).expect("schema");
    migrate(&conn); // ALTER additifs error-ignored (run_id, fix, panel étendu, run_job C2, dashboard_id)
    ensure_default_dashboard(&conn); // dashboard #1 (rétro-compat) + rattache les panels orphelins
    populate_modules(&conn); // table `module` peuplée depuis `forge.cli modules`
    reconcile_runs(&conn); // run_job 'running' orphelins (reboot console) -> 'failed'

    let token = std::env::var("FORGE_CONSOLE_TOKEN").unwrap_or_else(|_| gen_token());
    let user = std::env::var("FORGE_CONSOLE_USER").unwrap_or_else(|_| "forge".to_string());
    let pass_hash = std::env::var("FORGE_CONSOLE_PASS_HASH").unwrap_or_default();
    // rôle OPÉRATEUR (C2) — FAIL-CLOSED : vide => tout endpoint C2 renvoie 403.
    let operator_hash = std::env::var("FORGE_CONSOLE_OPERATOR_HASH").unwrap_or_default();
    // racine du paquet Forge (où vit `forge/`) — cwd du spawn `python -m forge.cli campaign`.
    let pkg_dir = std::env::var("FORGE_PKG_DIR").unwrap_or_else(|_| "..".to_string());
    let python = std::env::var("FORGE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let run_timeout_secs = std::env::var("FORGE_RUN_TIMEOUT").ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1800); // 30 min
    // scope serveur autorisé : pré-filtre fail-closed des cibles lançables depuis le web.
    // Source : FORGE_CONSOLE_SCOPE (chemin d'un scope.json) ; sinon scope.json relatif au pkg_dir.
    let (scope_in, scope_mode) = load_server_scope(&pkg_dir);
    // PURPLE (mesure de couverture de détection) : colonne BLEUE Plume (SOC). PLUME_URL vide =>
    // /api/purple/coverage répond en FAIL-OPEN LISIBLE (plume_reachable:false). On normalise l'URL
    // (retrait du '/' final) pour concaténer proprement le chemin.
    let plume_url = std::env::var("PLUME_URL").unwrap_or_default().trim_end_matches('/').to_string();
    let plume_token = std::env::var("PLUME_TOKEN").unwrap_or_default();
    let mut allowed = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
    if let Ok(h) = std::env::var("FORGE_CONSOLE_HOST") {
        if !h.is_empty() {
            allowed.push(h);
        }
    }

    // ledger JSONL : chemin par défaut relatif au pkg dir Forge (où `forge campaign --ledger` écrit).
    let ledger_path = std::env::var("FORGE_CONSOLE_LEDGER").unwrap_or_else(|_| "engagement.jsonl".to_string());
    // racine des assets web statiques (style.css/app.js/fonts/…) servis en fallback.
    let web_dir = resolve_web_dir();
    println!("[forge-console] web assets: {web_dir}");

    // NE PAS journaliser le token en clair (fuite via logs/journald/historique terminal). On affiche
    // une empreinte courte (8 hex de sha256) — suffisante pour corréler/diagnostiquer sans exposer le
    // secret. Le token en clair reste disponible à l'opérateur via FORGE_CONSOLE_TOKEN (qu'il a posé).
    let token_was_provided = std::env::var("FORGE_CONSOLE_TOKEN").map(|v| !v.is_empty()).unwrap_or(false);
    let token_fp = &sha_hex(&token)[..8];
    if token_was_provided {
        println!("[forge-console] ingest token: (fourni via env) fp=sha8:{token_fp}");
    } else {
        // token auto-généré : l'opérateur DOIT pouvoir le récupérer une fois. On l'imprime alors en
        // clair (sinon /api/ingest serait inutilisable), mais on signale qu'il est éphémère.
        println!("[forge-console] ingest token (auto-généré, éphémère — pose FORGE_CONSOLE_TOKEN pour le fixer): {token}  fp=sha8:{token_fp}");
    }
    println!("[forge-console] db: {db_path}");
    println!("[forge-console] ledger: {ledger_path}");
    if pass_hash.is_empty() {
        println!("[forge-console] AUTH OFF (dev localhost) — défini FORGE_CONSOLE_PASS_HASH (forge-console hashpw '...') pour activer Basic auth");
    } else {
        println!("[forge-console] auth ON — user={user}, lectures protégées (Basic), écritures par token");
    }
    if operator_hash.is_empty() {
        println!("[forge-console] C2 FAIL-CLOSED — rôle opérateur NON provisionné (FORGE_CONSOLE_OPERATOR_HASH absent) : /api/run* renverra 403. `forge-console hashpw-operator '...'` pour l'activer.");
    } else {
        println!("[forge-console] C2 armé — rôle opérateur via en-tête X-Forge-Operator ; cibles ⊆ scope serveur ({} entrée(s)) ; exploit/destructif possibles UNIQUEMENT via opt-in haut-impact gouverné (allow_high_impact + arm + reason, journalisé au ledger) ; scope-guard moteur inchangé (hors-scope = VETO) ; watchdog={run_timeout_secs}s", scope_in.len());
    }

    if plume_url.is_empty() {
        println!("[forge-console] PURPLE OFF — PLUME_URL absent : /api/purple/coverage répondra en fail-open lisible (plume_reachable:false). Pose PLUME_URL (+ PLUME_TOKEN base64 user:pass) pour mesurer la couverture de détection SOC.");
    } else {
        println!("[forge-console] PURPLE armé — couverture de détection via GET {plume_url}/api/coverage/detections (auth {}) ; LECTURE seule, joint runrecord[fired] (red) vs détections Plume (blue).",
            if plume_token.is_empty() { "anonyme (SOC_PUBLIC_DEMO)" } else { "Basic" });
    }

    let (events, _) = broadcast::channel::<RunEvent>(1024);
    let app = App {
        db: Arc::new(Mutex::new(conn)),
        db_path: Arc::new(db_path.clone()),
        token_sha: Arc::new(sha_hex(&token)),
        token_raw: Arc::new(token.clone()),
        user: Arc::new(user),
        pass_hash: Arc::new(pass_hash),
        operator_hash: Arc::new(operator_hash),
        allowed_hosts: Arc::new(allowed),
        ledger_path: Arc::new(ledger_path),
        pkg_dir: Arc::new(pkg_dir),
        python: Arc::new(python),
        scope_in: Arc::new(scope_in),
        scope_mode: Arc::new(scope_mode),
        plume_url: Arc::new(plume_url),
        plume_token: Arc::new(plume_token),
        run_timeout_secs,
        run_state: Arc::new(AsyncMutex::new(RunState { current: None })),
        events,
        ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
    };

    // routes protégées par auth_guard ; /health reste ouvert ; host_guard sur tout.
    // ServeDir sert les assets statiques (style.css/app.js/quetzal.svg/favicon.svg/fonts/…) en
    // fallback pour toute route non-API non matchée — l'index `/` reste rendu par include_str!.
    let protected = Router::new()
        .route("/", get(index))
        .route("/api/ingest", post(ingest))
        .route("/api/findings", get(findings))
        .route("/api/findings/:id", get(finding_detail))
        .route("/api/runrecords", get(runrecords))
        .route("/api/coverage", get(coverage))
        .route("/api/purple/coverage", get(purple_coverage))
        .route("/api/modules", get(modules))
        .route("/api/modules/refresh", post(modules_refresh))
        .route("/api/campaigns", get(campaigns))
        .route("/api/roe", get(roe))
        // --- parité LECTURE / gouvernance ---
        .route("/api/scope-check", post(scope_check))
        .route("/api/plan", post(plan))
        .route("/api/ledger", get(ledger))
        .route("/api/ledger/verify", get(ledger_verify))
        .route("/api/query", get(query).post(query_post))
        .route("/api/dashboards", get(dashboards_list).post(dashboard_create))
        .route("/api/dashboards/:id", post(dashboard_update).delete(dashboard_delete))
        .route("/api/panels", get(panels_list).post(panel_create))
        .route("/api/panels/:id", post(panel_update).delete(panel_delete))
        .route("/api/panels/:id/data", get(panel_data))
        // --- C2-light : lancement gouverné/audité (opérateur fail-closed sur run/cancel) ---
        .route("/api/run", post(run_create))
        .route("/api/runs", get(runs_list))
        .route("/api/runs/:id", get(run_detail))
        .route("/api/runs/:id/report", get(run_report))
        .route("/api/runs/:id/cancel", post(run_cancel))
        .route("/api/runs/:id/logs", get(run_logs))
        .route("/api/runs/:id/events", get(run_sse))
        .fallback_service(ServeDir::new(&web_dir))
        .route_layer(middleware::from_fn_with_state(app.clone(), auth_guard));
    let router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(protected)
        .layer(middleware::from_fn_with_state(app.clone(), host_guard))
        .with_state(app);

    let addr = std::env::var("FORGE_CONSOLE_ADDR").unwrap_or_else(|_| "127.0.0.1:7100".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("[forge-console] http://{addr}");
    axum::serve(listener, router).await.expect("serve");
}

// =====================================================================================
// Tests de régression des correctifs de sûreté/sécurité (durcissement audit).
// =====================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// App minimale pour tester append_console_ledger (ledger sur disque, reste inerte).
    fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(SCHEMA).expect("schema");
        let (events, _) = broadcast::channel::<RunEvent>(64);
        App {
            db: Arc::new(Mutex::new(conn)),
            db_path: Arc::new(":memory:".into()),
            token_sha: Arc::new(sha_hex("t")),
            token_raw: Arc::new("t".into()),
            user: Arc::new("forge".into()),
            pass_hash: Arc::new(String::new()),
            operator_hash: Arc::new(String::new()),
            allowed_hosts: Arc::new(vec!["localhost".into()]),
            ledger_path: Arc::new(ledger_path.to_string()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            plume_url: Arc::new(String::new()),
            plume_token: Arc::new(String::new()),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(RunState { current: None })),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        }
    }

    fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        let uniq = format!("{}-{}-{}", name, std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        p.push(uniq);
        p.to_string_lossy().into_owned()
    }

    /// [HIGH] gen_token : entropie CSPRNG -> non tous-zeros, longueur fixe, valeurs distinctes.
    #[test]
    fn gen_token_is_random_not_zero() {
        let a = gen_token();
        let b = gen_token();
        assert_eq!(a.len(), 32, "16 octets -> 32 hex");
        assert_ne!(a, "0".repeat(32), "token tous-zeros = entropie ignorée (régression)");
        assert_ne!(a, b, "deux tokens consécutifs doivent différer");
    }

    /// [HIGH] hash_pw : sel CSPRNG -> deux hash du MÊME mot de passe diffèrent (sel non constant),
    /// et la vérification réussit (format argon2id valide).
    #[test]
    fn hash_pw_salt_is_random_and_verifies() {
        let h1 = hash_pw("hunter2");
        let h2 = hash_pw("hunter2");
        assert_ne!(h1, h2, "même mdp -> hash identiques = sel constant/tous-zeros (régression)");
        assert!(verify_pw("hunter2", &h1), "hash doit se vérifier");
        assert!(!verify_pw("wrong", &h1), "mauvais mdp doit échouer");
    }

    /// [LOW sec] ct_eq_str : égalité correcte, inégalité correcte (la propriété temps-constant n'est
    /// pas mesurable en test unitaire, mais on garantit la correction fonctionnelle).
    #[test]
    fn ct_eq_str_correctness() {
        assert!(ct_eq_str("deadbeef", "deadbeef"));
        assert!(!ct_eq_str("deadbeef", "deadbee0"));
        assert!(!ct_eq_str("deadbeef", "deadbeeff")); // longueurs différentes
        assert!(!ct_eq_str("", "x"));
    }

    /// [LOW sec] host_guard fail-closed : Host vide/absent REFUSÉ ; hors allowlist refusé ; in-allowlist
    /// accepté (port ignoré).
    #[test]
    fn host_guard_rejects_empty_and_unknown() {
        let allow = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        assert!(!host_allowed("", &allow), "Host vide doit être refusé (fail-closed)");
        assert!(!host_allowed(":7100", &allow), "Host vide avec port doit être refusé");
        assert!(!host_allowed("evil.example", &allow), "Host hors allowlist refusé");
        assert!(host_allowed("localhost", &allow));
        assert!(host_allowed("localhost:7100", &allow), "port ignoré");
        assert!(host_allowed("127.0.0.1:8080", &allow));
    }

    /// [MED race ledger] append_console_ledger : la chaîne SHA-256 reste valide sur N appends
    /// séquentiels (prev chaîné, seq incrémental). Recalcule la chaîne comme /api/ledger/verify.
    #[test]
    fn ledger_chain_is_consistent() {
        let path = tmp_path("forge-test-ledger");
        let app = test_app(&path);
        for i in 0..25 {
            append_console_ledger(&app, "console.test", json!({"i": i, "msg": "événement"}));
        }
        let entries = read_ledger_lines(&path);
        assert_eq!(entries.len(), 25, "25 entrées écrites");
        const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
        let mut prev = GENESIS.to_string();
        for (n, rec) in entries.iter().enumerate() {
            let seq = rec.get("seq").and_then(|v| v.as_i64()).unwrap();
            assert_eq!(seq, (n as i64) + 1, "seq strictement incrémental sans trou ni doublon");
            let stored_prev = rec.get("prev").and_then(|v| v.as_str()).unwrap();
            assert_eq!(stored_prev, prev, "chaînage prev rompu à l'entrée {n}");
            let ts = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("");
            let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let detail = rec.get("detail").cloned().unwrap_or(Value::Null);
            let preimage = format!("{prev}|{seq}|{ts}|{kind}|{}", canon_json(&detail));
            let recomputed = sha_hex(&preimage);
            let stored_hash = rec.get("hash").and_then(|v| v.as_str()).unwrap();
            assert_eq!(recomputed, stored_hash, "hash recalculé != stocké à l'entrée {n}");
            prev = stored_hash.to_string();
        }
        let _ = std::fs::remove_file(&path);
    }

    /// [MED race ledger] head caché : un 2e cycle d'appends (après relecture disque par une AUTRE App)
    /// continue la chaîne sans réinitialiser seq/prev (pas de doublon de seq).
    #[test]
    fn ledger_continues_across_reload() {
        let path = tmp_path("forge-test-ledger-reload");
        {
            let app = test_app(&path);
            append_console_ledger(&app, "k", json!({"a": 1}));
            append_console_ledger(&app, "k", json!({"a": 2}));
        }
        // nouvelle App (head cache vide) -> doit relire le disque et reprendre à seq=3.
        let app2 = test_app(&path);
        append_console_ledger(&app2, "k", json!({"a": 3}));
        let entries = read_ledger_lines(&path);
        assert_eq!(entries.len(), 3);
        let seqs: Vec<i64> = entries.iter().filter_map(|e| e.get("seq").and_then(|v| v.as_i64())).collect();
        assert_eq!(seqs, vec![1, 2, 3], "seq doit reprendre après reload (pas de doublon)");
        let _ = std::fs::remove_file(&path);
    }

    /// [parité lecture] host_in_server_scope : match exact, suffixe de domaine, wildcard `*.`, et
    /// fail-closed quand le scope serveur est vide. Réutilisé par /api/scope-check ET le pré-filtre run.
    #[test]
    fn scope_check_decision_matches_server_scope() {
        let path = tmp_path("forge-test-scope");
        let mut app = test_app(&path);
        // scope vide -> rien n'est in_scope (fail-closed).
        assert!(!host_in_server_scope(&app, "example.com"), "scope vide => fail-closed");
        app.scope_in = Arc::new(vec!["example.com".to_string(), "*.lab.test".to_string()]);
        assert!(host_in_server_scope(&app, "example.com"), "match exact");
        assert!(host_in_server_scope(&app, "api.example.com"), "sous-domaine d'une entrée listée");
        assert!(host_in_server_scope(&app, "a.lab.test"), "wildcard *. -> suffixe");
        assert!(host_in_server_scope(&app, "lab.test"), "wildcard *. -> base elle-même");
        assert!(!host_in_server_scope(&app, "evil.test"), "hors scope refusé");
        assert!(!host_in_server_scope(&app, "notexample.com"), "pas un vrai suffixe de domaine");
        let _ = std::fs::remove_file(&path);
    }

    /// [parité lecture] parse_plan_verdicts : extrait verdict + kind→target des lignes du moteur
    /// (mode propose), ignore les lignes sans verdict, tolère `->` et `→`. Couvre le format inline
    /// (CLI `forge plan` : `[VERDICT] kind → target`).
    #[test]
    fn plan_verdicts_extracted_from_engine_output() {
        let stdout = "\
[plan] access_control.idor -> api.example.com : DRY_RUN (non armé)
[plan] exploit.rce -> api.example.com : VETO (capacité non autorisée)
ligne sans verdict ignorée
[plan] recon.http → web.example.com : FIRE
";
        let v = parse_plan_verdicts(stdout);
        assert_eq!(v.len(), 3, "3 lignes avec verdict reconnu (la 3e ignorée)");
        assert_eq!(v[0]["verdict"], "DRY_RUN");
        assert_eq!(v[0]["kind"], "access_control.idor");
        assert_eq!(v[0]["target"], "api.example.com");
        assert_eq!(v[1]["verdict"], "VETO");
        assert_eq!(v[2]["verdict"], "FIRE");
        assert_eq!(v[2]["kind"], "recon.http", "séparateur unicode → géré");
    }

    /// [parité lecture] parse_plan_verdicts sur la sortie RÉELLE du moteur (`report.py`) : les
    /// lignes d'action vivent sous un en-tête de section et ne portent PAS le mot-clé du verdict ;
    /// les compteurs de synthèse en gras (`- **Tirées (FIRE)** : 0`) ne doivent JAMAIS produire de
    /// faux verdicts. Régression du dry-plan console (gouvernance : 1 action réelle, pas 3 fantômes).
    #[test]
    fn plan_verdicts_from_real_report_section_aware() {
        let stdout = "\
Tirées=0  Simulées=1  Refusées=0  Erreurs=0  Findings=0
## Couverture & transparence (ROE / anti-masquage)

- **Tirées (FIRE)** : 0
- **Simulées (DRY_RUN)** : 1
- **Refusées (VETO — hors scope / capacité non autorisée)** : 0
- **Erreurs / skips** : 0

**Simulées (non armé/approuvé)**
- `recon.httpx` → `guatx.com` : engagement non armé (dry-run)

**Refusées (VETO)**
- `exploit.rce` → `evil.example` : capacité non autorisée

**Classes jamais tentées**
- `guatx.com` : access_control, auth, ato
";
        let v = parse_plan_verdicts(stdout);
        assert_eq!(v.len(), 2, "2 actions réelles (les compteurs en gras et la ligne 'classes' ignorés)");
        assert_eq!(v[0]["verdict"], "DRY_RUN", "verdict tiré de la section, pas du compteur");
        assert_eq!(v[0]["kind"], "recon.httpx", "backticks retirés");
        assert_eq!(v[0]["target"], "guatx.com", "raisons `: …` coupées de la cible");
        assert_eq!(v[1]["verdict"], "VETO");
        assert_eq!(v[1]["kind"], "exploit.rce");
        assert_eq!(v[1]["target"], "evil.example");
    }

    /// [parité lecture] render_run_report_md : miroir markdown de build_report — synthèse par
    /// sévérité (findings du run), findings détaillés, transparence ROE (compteurs run_job + verdicts).
    #[test]
    fn run_report_markdown_mirrors_build_report() {
        let path = tmp_path("forge-test-report");
        let app = test_app(&path);
        {
            let db = app.db();
            migrate(&db); // ALTER additifs (run_id sur finding/runrecord) — comme au boot réel
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,tool,run_id)
                 VALUES('t','c','api.example.com','IDOR exposé','HIGH','access_control','T1190','confirmé','idor','run-1')",
                [],
            ).unwrap();
            db.execute(
                "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons)
                 VALUES('t','c','run-1','a1','api.example.com','exploit.rce','VETO',1,0,'[\"capacité non autorisée\"]')",
                [],
            ).unwrap();
            db.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,started_by)
                 VALUES('run-1','c',datetime('now'),'done','propose',0,2,1,0,'operator')",
                [],
            ).unwrap();
        }
        let db = app.db();
        let job = db.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), ["run-1"], run_job_json).unwrap();
        let md = render_run_report_md(&db, "run-1", &job, None);
        assert!(md.contains("# Forge — rapport d'engagement (`run-1`)"), "titre avec run_id");
        assert!(md.contains("| HIGH | 1 |"), "synthèse sévérité HIGH=1");
        assert!(md.contains("### [HIGH] IDOR exposé — `api.example.com`"), "finding détaillé rendu");
        assert!(md.contains("**Refusées (VETO"), "section transparence ROE présente");
        assert!(md.contains("`VETO` `exploit.rce` → `api.example.com` : capacité non autorisée"), "verdict VETO détaillé avec raison");
        assert!(md.contains("**Simulées (DRY_RUN)** : 2"), "compteur dry_run depuis run_job");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    /// [purple] parse_fire_ts : l'ISO-8601 UTC émis par Forge -> epoch s correct (ancrage connu),
    /// offsets honorés (Z, +02:00, -05:00), fractions ignorées, epoch nu toléré, illisible -> None.
    #[test]
    fn parse_fire_ts_iso_to_epoch() {
        // 2026-06-26T00:00:00Z == 1782432000 (UTC). Vérifié par days_from_civil.
        assert_eq!(parse_fire_ts("2026-06-26T00:00:00+00:00"), Some(1782432000));
        assert_eq!(parse_fire_ts("2026-06-26T00:00:00Z"), Some(1782432000));
        // offset +02:00 -> le même instant UTC est 2h plus tôt -> epoch - 7200.
        assert_eq!(parse_fire_ts("2026-06-26T02:00:00+02:00"), Some(1782432000));
        // offset -05:00 -> 5h plus tard en UTC.
        assert_eq!(parse_fire_ts("2026-06-25T19:00:00-05:00"), Some(1782432000));
        // fraction de seconde ignorée.
        assert_eq!(parse_fire_ts("2026-06-26T00:00:00.512Z"), Some(1782432000));
        // epoch nu toléré (défensif).
        assert_eq!(parse_fire_ts("1782432000"), Some(1782432000));
        // illisible -> None (MTTD marqué indisponible, jamais inventé).
        assert_eq!(parse_fire_ts(""), None);
        assert_eq!(parse_fire_ts("pas-une-date"), None);
        // l'epoch Unix (référence) doit retomber sur 0.
        assert_eq!(parse_fire_ts("1970-01-01T00:00:00Z"), Some(0));
    }

    /// [purple] compute_purple_coverage : detected = intersection sur mitre, missed = techniques
    /// tirées absentes des détections, MTTD = first_detection - dernier tir (tronqué >=0), agrégats.
    #[test]
    fn compute_purple_coverage_detected_missed_mttd() {
        // T1110 tiré 2× (dernier tir @1000), détecté @1042 (MTTD=42) ; T1190 tiré @2000 détecté @1990
        // (détection ANTÉRIEURE -> MTTD tronqué à 0) ; T1046 tiré @3000 jamais détecté (missed).
        let fired = vec![
            ("T1110".to_string(), Some(500)),
            ("T1110".to_string(), Some(1000)),
            ("T1190".to_string(), Some(2000)),
            ("T1046".to_string(), Some(3000)),
            ("".to_string(), Some(9)), // mitre vide ignoré
        ];
        let mut det = std::collections::HashMap::new();
        det.insert("T1110".to_string(), (3i64, 1042i64));
        det.insert("T1190".to_string(), (1i64, 1990i64));
        let cov = compute_purple_coverage(&fired, &det);
        assert_eq!(cov["techniques_fired"], json!(3), "3 techniques distinctes tirées (mitre vide exclu)");
        assert_eq!(cov["techniques_detected"], json!(2), "T1110 + T1190 détectées");
        assert_eq!(cov["techniques_missed"], json!(1), "T1046 = trou de détection");
        // taux 2/3.
        let rate = cov["detection_rate"].as_f64().unwrap();
        assert!((rate - 2.0 / 3.0).abs() < 1e-9, "taux de détection = 2/3");
        // MTTD : T1110 = 1042-1000 = 42 ; T1190 = max(1990-2000,0) = 0 -> moyenne 21, max 42.
        assert_eq!(cov["mttd_avg_secs"].as_f64().unwrap(), 21.0);
        assert_eq!(cov["mttd_max_secs"], json!(42));
        // missed contient bien T1046.
        let missed = cov["missed"].as_array().unwrap();
        assert_eq!(missed.len(), 1);
        assert_eq!(missed[0]["mitre"], json!("T1046"));
        assert_eq!(missed[0]["fires"], json!(1));
        // detected T1110 porte fires=2 (dernier tir retenu pour le MTTD) et mttd_secs=42.
        let detected = cov["detected"].as_array().unwrap();
        let t1110 = detected.iter().find(|d| d["mitre"] == json!("T1110")).unwrap();
        assert_eq!(t1110["fires"], json!(2));
        assert_eq!(t1110["mttd_secs"], json!(42));
        assert_eq!(t1110["alert_count"], json!(3));
    }

    /// [purple FAIL-OPEN] aucune détection (SOC muet, map vide) NE produit PAS « tout détecté » :
    /// toutes les techniques tirées tombent en missed, taux 0, aucun MTTD inventé (null).
    #[test]
    fn compute_purple_coverage_empty_detections_all_missed() {
        let fired = vec![("T1110".to_string(), Some(1000)), ("T1046".to_string(), Some(2000))];
        let det = std::collections::HashMap::new();
        let cov = compute_purple_coverage(&fired, &det);
        assert_eq!(cov["techniques_detected"], json!(0), "rien détecté");
        assert_eq!(cov["techniques_missed"], json!(2), "tout en trou de détection");
        assert_eq!(cov["detection_rate"], json!(0.0));
        assert_eq!(cov["mttd_avg_secs"], Value::Null, "aucun MTTD inventé");
        assert_eq!(cov["mttd_max_secs"], Value::Null);
        assert!(cov["detected"].as_array().unwrap().is_empty());
    }

    /// [purple FAIL-OPEN LISIBLE] purple_fail_open : plume_reachable=false, raison présente,
    /// detected/missed VIDES et compteurs/MTTD nuls — un SOC injoignable n'est ni « tout détecté »
    /// ni « tout raté ». techniques_fired reste informatif (distinctes, mitre vide exclu).
    #[test]
    fn purple_fail_open_invents_nothing() {
        let fired = vec![
            ("T1110".to_string(), Some(1000)),
            ("T1110".to_string(), Some(1100)),
            ("T1046".to_string(), Some(2000)),
            ("".to_string(), None),
        ];
        let v = purple_fail_open("http://plume:7000", &fired, "Plume injoignable: timeout");
        assert_eq!(v["plume_reachable"], json!(false));
        assert_eq!(v["plume_url"], json!("http://plume:7000"));
        assert_eq!(v["error"], json!("Plume injoignable: timeout"));
        assert_eq!(v["techniques_fired"], json!(2), "T1110+T1046 distinctes, mitre vide exclu");
        assert_eq!(v["techniques_detected"], json!(0));
        assert_eq!(v["techniques_missed"], json!(0), "rien classé missed quand la mesure est impossible");
        assert_eq!(v["detection_rate"], json!(0.0));
        assert_eq!(v["mttd_avg_secs"], Value::Null);
        assert!(v["detected"].as_array().unwrap().is_empty());
        assert!(v["missed"].as_array().unwrap().is_empty());
    }

    /// [purple report] render_purple_section : la section markdown reflète detected/missed/MTTD
    /// quand plume_reachable=true, et affiche le fail-open lisible (sans couverture inventée) sinon.
    #[test]
    fn render_purple_section_reachable_and_fail_open() {
        // cas joignable : section avec compteurs + trous.
        let cov = json!({
            "plume_reachable": true,
            "techniques_fired": 2, "techniques_detected": 1, "techniques_missed": 1,
            "detection_rate": 0.5, "mttd_avg_secs": 42.0, "mttd_max_secs": 42,
            "detected": [{"mitre": "T1110", "alert_count": 3, "mttd_secs": 42}],
            "missed": [{"mitre": "T1046", "fires": 1}],
        });
        let mut out: Vec<String> = Vec::new();
        render_purple_section(&mut out, &cov);
        let md = out.join("\n");
        assert!(md.contains("## Couverture détection (purple)"));
        assert!(md.contains("**Techniques tirées (red)** : 2"));
        assert!(md.contains("**Taux de détection** : 50%"));
        assert!(md.contains("`T1046` (tirée 1×) — aucune alerte SOC"), "trou de détection listé");
        assert!(md.contains("`T1110` — 3 alerte(s), MTTD 42s"), "détection avec MTTD listée");

        // cas fail-open : la section l'indique explicitement, sans détecté/raté.
        let fo = purple_fail_open("", &[("T1110".to_string(), Some(1))], "PLUME_URL non configuré");
        let mut out2: Vec<String> = Vec::new();
        render_purple_section(&mut out2, &fo);
        let md2 = out2.join("\n");
        assert!(md2.contains("## Couverture détection (purple)"));
        assert!(md2.contains("Mesure indisponible (fail-open)"), "fail-open lisible dans le rapport");
        assert!(md2.contains("PLUME_URL non configuré"));
        assert!(!md2.contains("aucune alerte SOC"), "aucun trou inventé en fail-open");
    }

    /// [purple http] http_get_blocking : rejette une URL non-http:// (TLS non géré) avec un message
    /// lisible — garantit que la console ne tente pas un handshake qu'elle ne sait pas faire.
    #[test]
    fn http_get_blocking_rejects_non_http() {
        let e = http_get_blocking("https://plume:7000/api/coverage/detections", "", Duration::from_millis(50));
        assert!(e.is_err(), "https non géré -> Err");
        assert!(e.unwrap_err().contains("http://"), "message lisible mentionnant http://");
    }

    /// [parité lecture] validate_host : /api/scope-check rejette les cibles malformées (métacaractères,
    /// `-` en tête) avant même la décision de scope — pas d'injection possible via le champ target.
    #[test]
    fn scope_check_rejects_malformed_target() {
        assert!(validate_host("api.example.com").is_ok());
        assert!(validate_host("10.0.0.0/8").is_ok());
        assert!(validate_host("-evil").is_err(), "tête '-' refusée (anti flag CLI)");
        assert!(validate_host("a;rm -rf").is_err(), "métacaractère shell refusé");
        assert!(validate_host("").is_err(), "vide refusé");
    }

    /// [MED resource] db() récupère une connexion empoisonnée (un panic en section critique ne gèle
    /// plus l'API). On empoisonne volontairement le Mutex puis on vérifie que db() fonctionne encore.
    #[test]
    fn db_recovers_from_poison() {
        let path = tmp_path("forge-test-poison-ledger");
        let app = test_app(&path);
        let app2 = app.clone();
        // empoisonne : un thread panique en tenant le verrou DB.
        let h = std::thread::spawn(move || {
            let _g = app2.db.lock().unwrap();
            panic!("poison volontaire");
        });
        let _ = h.join(); // le panic empoisonne le Mutex
        assert!(app.db.lock().is_err(), "le Mutex doit être empoisonné");
        // db() doit malgré tout rendre une garde utilisable (into_inner).
        let db = app.db();
        let n: i64 = db.query_row("SELECT 1", [], |r| r.get(0)).expect("requête OK après poison");
        assert_eq!(n, 1, "la connexion reste exploitable après récupération du poison");
        let _ = std::fs::remove_file(&path);
    }

    /// Seed la table `module` d'une App de test avec un module recon (web_allowed) et un module
    /// exploit (haut-impact). Réutilisé par les tests du gate haut-impact.
    fn seed_modules(app: &App) {
        let db = app.db();
        // recon.httpx : ni exploit ni destructif -> web_allowed=1 (lançable web par défaut).
        db.execute(
            "INSERT OR REPLACE INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed)
             VALUES('recon.httpx',0,0,1,'','recon',1)", [],
        ).unwrap();
        // exploit.rce : exploit=1 -> web_allowed=0 (sous plancher exploit).
        db.execute(
            "INSERT OR REPLACE INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed)
             VALUES('exploit.rce',1,0,1,'T1190','rce',0)", [],
        ).unwrap();
    }

    /// [HIGH gouvernance] high_impact_gate (fonction pure) : honore l'opt-in UNIQUEMENT avec
    /// operator + arm + reason non vide ; défaut (opt-in absent) => Ok(false) inchangé ; toute
    /// condition manquante => Err 'high_impact_requires_arm_and_reason'.
    #[test]
    fn high_impact_gate_requires_all_conditions() {
        // défaut : opt-in non demandé -> Ok(false), comportement actuel (plancher tient).
        assert_eq!(high_impact_gate(false, true, true, "raison").unwrap(), false);
        assert_eq!(high_impact_gate(false, false, false, "").unwrap(), false,
            "opt-in absent prime : aucune erreur même sans arm/reason");
        // opt-in demandé + 3 conditions réunies -> Ok(true).
        assert_eq!(high_impact_gate(true, true, true, "test autorisé par l'opérateur").unwrap(), true);
        // opt-in demandé mais une condition manque -> Err 400 explicite.
        for (op, arm, reason) in [
            (false, true, "r"),   // pas operator
            (true, false, "r"),   // pas arm
            (true, true, ""),     // reason vide
            (true, true, "   "),  // reason blanche (trim)
        ] {
            let err = high_impact_gate(true, op, arm, reason).unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
            assert_eq!(err.1.0["error"], "high_impact_requires_arm_and_reason",
                "condition manquante (op={op}, arm={arm}, reason={reason:?}) doit 400");
        }
    }

    /// [HIGH gouvernance] validate_modules : SANS opt-in (allow_high_impact=false) le plancher tient
    /// (exploit.rce -> 400 exploit_floor) ; AVEC opt-in honoré, exploit.rce passe ; un kind inconnu
    /// est TOUJOURS refusé, même armé (le contrôle unknown_module ne s'affaiblit jamais).
    #[test]
    fn validate_modules_high_impact_lifts_floor_only() {
        let path = tmp_path("forge-test-vmods");
        let app = test_app(&path);
        seed_modules(&app);
        // sans opt-in : recon OK, exploit refusé (plancher).
        assert!(validate_modules(&app, &["recon.httpx".into()], false).is_ok());
        let err = validate_modules(&app, &["exploit.rce".into()], false).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.0["error"], "exploit_floor", "plancher exploit tient sans opt-in");
        // avec opt-in honoré : exploit accepté.
        assert!(validate_modules(&app, &["exploit.rce".into()], true).is_ok(),
            "opt-in honoré -> exploit/destructif acceptés");
        // INVARIANT : kind inconnu refusé même avec opt-in (anti-injection d'argv préservé).
        let err = validate_modules(&app, &["forge.injected".into()], true).unwrap_err();
        assert_eq!(err.1.0["error"], "unknown_module", "kind inconnu refusé même armé");
        let _ = std::fs::remove_file(&path);
    }

    /// [HIGH gouvernance] high_impact_modules : liste UNIQUEMENT les modules exploit/destructif parmi
    /// les demandés (pour l'audit ledger/run_job). Ignore les modules recon et les kinds inconnus.
    #[test]
    fn high_impact_modules_lists_only_high_impact() {
        let path = tmp_path("forge-test-himods");
        let app = test_app(&path);
        seed_modules(&app);
        let hi = high_impact_modules(&app, &["recon.httpx".into(), "exploit.rce".into(), "inconnu".into()]);
        assert_eq!(hi, vec!["exploit.rce".to_string()], "seul l'exploit listé pour l'audit");
        let _ = std::fs::remove_file(&path);
    }
}

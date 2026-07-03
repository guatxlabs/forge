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
use argon2::{Algorithm, Argon2, Params, Version};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
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
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;

use axum::response::sse::{Event, KeepAlive, Sse};
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex as AsyncMutex};

// Version produit — SOURCE DE VÉRITÉ UNIQUE : le fichier `VERSION` à la racine du repo, lu à la
// COMPILATION (`include_str!`). Le même fichier alimente le moteur Python (forge/__init__.py) et
// est vérifié en dérive par la CI (`make check-version`). `CARGO_MANIFEST_DIR` = `console/`, donc
// `../VERSION` = la racine. Un `\n` de fin est possible -> trim au point d'usage (forge_version()).
const FORGE_VERSION_RAW: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../VERSION"));

/// Version nettoyée (sans espaces/newline de fin), réutilisable partout (CLI `--version`,
/// JSON `/health`, pied de page de l'UI web). Reste `&'static` (sous-tranche de la const).
fn forge_version() -> &'static str {
    FORGE_VERSION_RAW.trim()
}

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
-- MODULE (connecteurs) : `available` = disponibilité SONDÉE au boot (host). `enabled` et
-- `available_override` = INTENTION OPÉRATEUR gouvernée depuis l'admin console (jamais écrasée par un
-- re-probe, cf. populate_modules) : `enabled=0` désinstalle opérationnellement le connecteur ;
-- `available_override` (NULL=suivre la sonde, 0/1=forcer) surcharge la disponibilité host. Disponibilité
-- EFFECTIVE = enabled AND (available_override ?? available). Un module désactivé (enabled=0 ou override=0)
-- est SKIP au tir même si son binaire est présent (scope.json disabled_modules -> engine.execute).
CREATE TABLE IF NOT EXISTS module(
  kind TEXT PRIMARY KEY, exploit INTEGER DEFAULT 0, destructive INTEGER DEFAULT 0,
  available INTEGER DEFAULT 1, mitre TEXT DEFAULT '', descr TEXT DEFAULT '',
  web_allowed INTEGER DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
  available_override INTEGER DEFAULT NULL);
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
-- COMPTES UTILISATEURS (#6) : identités individuelles + attribution. `role` ∈ {viewer|operator|admin}
-- (contrainte applicative, pas SQL — voir validate_role). `pass_hash` = argon2id (jamais en clair).
-- `disabled` = 1 désactive le compte (login refusé, fail-closed). UNIQUE(login) anti-doublon.
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, login TEXT UNIQUE NOT NULL, role TEXT NOT NULL,
  pass_hash TEXT NOT NULL, disabled INTEGER DEFAULT 0, created TEXT DEFAULT '');
-- SESSIONS COURTES : on stocke le SHA-256 du token (jamais le token en clair — fuite DB inoffensive),
-- l'user_id propriétaire, l'horodatage de création et d'expiration (epoch s). Index pour le purge/lookup.
CREATE TABLE IF NOT EXISTS session(
  token_sha TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id);
-- SETTINGS (KV) : configuration MUTABLE d'administration (politique opérateur, source de détection,
-- params par défaut, état du wizard de 1er déploiement…). `updated` = horodatage de dernière écriture.
-- Les mutations sont réservées à check_admin (attribution individuelle stricte) et ledgerisées par
-- l'appelant. Substrat neutre : une clé absente = comportement par défaut (aucune valeur inventée).
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated TEXT NOT NULL);
";

/// Migrations additives (ALTER) — chaque ALTER est error-ignored : si la colonne existe déjà
/// (base ancienne ou re-boot) SQLite renvoie une erreur qu'on absorbe. Idempotent.
fn migrate(db: &Connection) {
    let alters = [
        // run_id corrèle finding/runrecord avec le run_job qui les a produits (boucle purple).
        "ALTER TABLE finding ADD COLUMN run_id TEXT DEFAULT ''",
        "ALTER TABLE finding ADD COLUMN fix TEXT DEFAULT ''",
        // taxonomie client séparée (LOT REPORTING) : CWE dédié + CVSS de base (vecteur + score),
        // distincts de `category` (fourre-tout historique) et `mitre` (ATT&CK). Le moteur Python
        // (schema.Finding.to_dict) émet déjà ces champs ; l'ingest les capte si présents, sinon le
        // rapport dérive le CWE depuis `category` (rétro-compat). Additifs/error-ignored.
        "ALTER TABLE finding ADD COLUMN cwe TEXT DEFAULT ''",
        "ALTER TABLE finding ADD COLUMN cvss_vector TEXT DEFAULT ''",
        "ALTER TABLE finding ADD COLUMN cvss_score REAL DEFAULT 0",
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
        // GOUVERNANCE CONNECTEUR (#4) : intention opérateur persistée sur la table `module`, distincte
        // de la disponibilité SONDÉE (`available`). `enabled` NOT NULL DEFAULT 1 (autorisé par SQLite car
        // la colonne a un DEFAULT) ; `available_override` NULL = suivre la sonde. Ces deux colonnes ne
        // sont JAMAIS réécrites par populate_modules (re-probe) — seul l'admin les mute (POST /api/modules/:kind).
        "ALTER TABLE module ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE module ADD COLUMN available_override INTEGER DEFAULT NULL",
    ];
    for a in alters {
        let _ = db.execute(a, []); // error-ignored (colonne déjà présente)
    }
    // SETTINGS (KV) : re-créée ici (idempotent, CREATE IF NOT EXISTS) en plus du SCHEMA, pour qu'une
    // base ANTÉRIEURE à son introduction l'obtienne au 1er boot suivant la mise à jour. error-ignored.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated TEXT NOT NULL)",
        [],
    );
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

/// INTENTION OPÉRATEUR de désactiver un connecteur (gouvernance, indépendante de la sonde host) :
/// vrai si `enabled=0` OU `available_override=Some(false)` (override explicite « indisponible »). Un
/// simple binaire absent (probed=0, sans override) N'EST PAS une désactivation opérateur — le moteur
/// le SKIP déjà via sa propre sonde. C'est CE set qu'on refuse dans validate_modules et qu'on injecte
/// dans scope.json `disabled_modules` (pour que le moteur SKIP même un outil PRÉSENT que l'opérateur a
/// désactivé). Fonction PURE (testable, aucun I/O).
fn module_operator_disabled(enabled: bool, available_override: Option<bool>) -> bool {
    !enabled || available_override == Some(false)
}

/// Disponibilité EFFECTIVE d'un connecteur = `enabled AND (available_override ?? probed_available)`.
/// Exposée au front (badge « effectif ») et cohérente avec module_operator_disabled : effective=false
/// dès que l'opérateur désactive (enabled=0 / override=0) OU que la sonde host est négative sans override.
/// Fonction PURE (testable, aucun I/O).
fn module_effectively_available(enabled: bool, available_override: Option<bool>, probed_available: bool) -> bool {
    enabled && available_override.unwrap_or(probed_available)
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
        upsert_probed_module(db, kind, exploit, destructive, available, mitre, descr);
        n += 1;
    }
    println!("[forge-console] modules: {n} enregistrés dans la table `module`");
}

/// UPSERT d'un module SONDÉ, avec NO-CLOBBER de l'intention opérateur. Sur conflit (module déjà connu),
/// ne met à jour QUE les champs SONDÉS (exploit/destructive/available/mitre/descr) ; `web_allowed`
/// (posé au 1er INSERT via module_web_allowed), `enabled` et `available_override` sont ABSENTS de la
/// clause SET -> une ligne existante conserve son intention de gouvernance, tandis qu'un NOUVEAU module
/// hérite de web_allowed dérivé et des DEFAULT `enabled=1` / `available_override=NULL`. Extrait de
/// populate_modules pour être testé sans spawn Python (régression : un disable manuel survit au re-probe).
/// Le plancher exploit reste garanti indépendamment de web_allowed (validate_modules teste
/// exploit/destructive en propre, en amont).
fn upsert_probed_module(db: &Connection, kind: &str, exploit: bool, destructive: bool,
                        available: bool, mitre: &str, descr: &str) {
    let web_allowed = module_web_allowed(kind, exploit, destructive);
    let _ = db.execute(
        "INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed)
         VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(kind) DO UPDATE SET exploit=excluded.exploit, destructive=excluded.destructive,
           available=excluded.available, mitre=excluded.mitre, descr=excluded.descr",
        rusqlite::params![kind, exploit as i64, destructive as i64, available as i64, mitre, descr, web_allowed as i64],
    );
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
    // GATE D'AUTH ENGAGÉE ? — cache recalculé au boot ET à chaque mutation de comptes (create/disable/
    // role-change/delete) pour éviter une requête DB par requête HTTP. `true` dès qu'un hash env est
    // posé (FORGE_CONSOLE_PASS_HASH) OU qu'au moins un compte activé existe en base : la gate s'engage
    // sur l'ÉTAT DB, pas seulement sur l'env (ferme le trou dev-open « comptes en base, env vide »).
    // FAIL-CLOSED : tant qu'un compte activé ou un hash existe, la gate reste engagée.
    auth_required: Arc<AtomicBool>,
    operator_hash: Arc<String>,      // argon2id du rôle OPÉRATEUR (C2) ; vide => FAIL-CLOSED (403 sur tout C2)
    allowed_hosts: Arc<Vec<String>>, // anti-DNS-rebinding
    ledger_path: Arc<String>,        // JSONL du ledger d'engagement (FORGE_CONSOLE_LEDGER)
    pkg_dir: Arc<String>,            // racine du paquet Forge (cwd du spawn `python -m forge.cli`)
    python: Arc<String>,            // interpréteur python (FORGE_PYTHON, défaut python3)
    scope_in: Arc<Vec<String>>,      // in_scope autorisé (recopié dans le scope du run, fail-closed)
    scope_mode: Arc<String>,         // mode du scope (white|grey|black) recopié tel quel
    // DÉTECTION (défensif, purple) : SOURCE de détection CONFIGURABLE (plugin), plus rien de codé en
    // dur. Objet JSON `{kind, endpoint?, auth?:{type,secret}, query?, mapping?}` chargé au boot depuis
    // `settings.detection_source`, avec REPLI rétro-compat sur l'env legacy PLUME_URL/PLUME_TOKEN
    // (traité comme `{kind:plume, endpoint:PLUME_URL, auth:{type:basic,secret:PLUME_TOKEN}}`). `kind`
    // absent/none => couverture en FAIL-OPEN LISIBLE (source_reachable:false, aucune métrique inventée).
    // Le SECRET (auth.secret) n'est JAMAIS renvoyé par un GET, ni journalisé, ni ledgerisé (rédigé).
    // Verrou RW : rechargé (reload_detection_source) après toute mutation de `settings.detection_source`.
    detection_source: Arc<std::sync::RwLock<Arc<Value>>>,
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

    /// Vrai s'il existe AU MOINS un compte ACTIVÉ (`disabled=0`) dans la table `users`. Requête légère
    /// (`LIMIT 1`). Ne verrouille QUE le mutex DB : ne JAMAIS l'appeler en tenant déjà `self.db()`
    /// (deadlock). Un échec de lecture -> false (l'engagement de la gate retombe alors sur `pass_hash`).
    fn any_enabled_user(&self) -> bool {
        let db = self.db();
        db.query_row("SELECT 1 FROM users WHERE disabled=0 LIMIT 1", [], |_| Ok(())).is_ok()
    }

    /// Recalcule et met en cache `auth_required` : la gate d'auth s'engage si un hash d'env est posé
    /// (`FORGE_CONSOLE_PASS_HASH` non vide) OU si au moins un compte activé existe en base. À appeler
    /// au BOOT et après CHAQUE mutation de comptes pour que l'état DB pilote la gate sans requête par
    /// requête. FAIL-CLOSED : on n'ouvre jamais la gate tant qu'un compte activé ou un hash existe.
    /// Ne pas appeler en tenant `self.db()` (any_enabled_user reverrouille le mutex).
    fn recompute_auth_required(&self) {
        let required = !self.pass_hash.is_empty() || self.any_enabled_user();
        self.auth_required.store(required, Ordering::SeqCst);
    }

    /// Lecture O(1) du cache : la gate d'auth est-elle engagée ? (voir recompute_auth_required).
    fn auth_required(&self) -> bool {
        self.auth_required.load(Ordering::SeqCst)
    }

    /// Vrai s'il existe AU MOINS un compte ADMIN activé (`role='admin' AND disabled=0`). Distinct de
    /// any_enabled_user (qui compte TOUT rôle) : le wizard de 1er déploiement considère la console
    /// « provisionnée » dès qu'un ADMIN peut administrer (pas un simple viewer). Requête légère
    /// (`LIMIT 1`). Ne verrouille QUE le mutex DB (ne pas appeler en tenant déjà `self.db()`).
    fn any_enabled_admin(&self) -> bool {
        let db = self.db();
        db.query_row("SELECT 1 FROM users WHERE role='admin' AND disabled=0 LIMIT 1", [], |_| Ok(())).is_ok()
    }

    /// La console est-elle déjà PROVISIONNÉE ? Vrai si un admin activé existe en base OU si un hash
    /// d'amorçage env est posé (`FORGE_CONSOLE_PASS_HASH`). Pilote l'auto-désactivation du wizard de
    /// 1er déploiement : `POST /api/setup` se ferme (409) dès que `provisioned()` est vrai. Ne pas
    /// appeler en tenant déjà `self.db()` (any_enabled_admin reverrouille le mutex).
    fn provisioned(&self) -> bool {
        !self.pass_hash.is_empty() || self.any_enabled_admin()
    }

    /// Configuration COURANTE de la source de détection (clone bon-marché de l'`Arc<Value>` en cache).
    /// Récupère un verrou empoisonné (into_inner) : un panic passé ne doit pas geler la lecture purple.
    fn detection_config(&self) -> Arc<Value> {
        self.detection_source.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Recalcule le cache `detection_source` depuis `settings.detection_source` (repli env legacy
    /// PLUME_URL/PLUME_TOKEN si la clé est absente). À appeler au BOOT et après CHAQUE mutation de
    /// `settings.detection_source` (wizard/config admin) pour que la source pilote la couverture sans
    /// relire la table à chaque requête. Ne pas appeler en tenant déjà `self.db()` (relock du mutex DB).
    fn reload_detection_source(&self) {
        let cfg = {
            let db = self.db();
            resolve_detection_source(&db)
        };
        let mut w = self.detection_source.write().unwrap_or_else(|e| e.into_inner());
        *w = Arc::new(cfg);
    }

    /// Invalide le cache du head ledger (prev/seq) -> le PROCHAIN `append_console_ledger` relira le
    /// head depuis le disque. À appeler après une mutation du fichier ledger effectuée HORS de
    /// `append_console_ledger` (ex. un restore qui remplace intégralement le ledger par celui de
    /// l'archive) : sans cela, le cache (prev/seq) resterait périmé et le prochain append casserait la
    /// chaîne SHA-256. Récupère un verrou empoisonné (into_inner) : un panic passé ne gèle pas l'audit.
    fn invalidate_ledger_head(&self) {
        let mut head = self.ledger_lock.lock().unwrap_or_else(|e| e.into_inner());
        head.loaded = false;
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

/// Extrait un identifiant CWE canonique ('CWE-639') d'une chaîne arbitraire ('cwe_639', 'CWE 639',
/// 'access_control.CWE-862'), ou '' si absent. Miroir Rust de `schema.extract_cwe` (rétro-compat :
/// permet de dériver le CWE depuis `category` quand le moteur ne fournit pas le champ `cwe` dédié).
fn extract_cwe(text: &str) -> String {
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
fn cvss_base_for_severity(severity: &str) -> (&'static str, f64) {
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
fn html_escape(s: &str) -> String {
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

/// Preuve opérateur par HASH ENV (rétro-compat) : vrai seulement si `operator_hash` est configuré ET
/// que l'en-tête `X-Forge-Operator` correspond. Vide => toujours faux (fail-closed). Aucune
/// dépendance au viewer (pass_hash/token). C'est le repli 'bootstrap' quand aucun compte individuel
/// n'est en session.
fn check_operator_env(app: &App, headers: &HeaderMap) -> bool {
    if app.operator_hash.is_empty() {
        return false; // FAIL-CLOSED : rôle opérateur non provisionné via env -> repli C2 refusé
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

/// Test d'APPARTENANCE d'une IP à un CIDR (ou à une IP exacte quand il n'y a pas de `/`). std-only
/// (u32/u128 + masque de préfixe, aucune dépendance). Familles hétérogènes (v4 vs v6) -> false.
/// Réseau/préfixe malformé ou hors borne -> false (fail-closed pour CETTE entrée). Fonction PURE.
fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    let cidr = cidr.trim();
    let (net, prefix): (&str, Option<u32>) = match cidr.split_once('/') {
        Some((n, p)) => match p.trim().parse::<u32>() {
            Ok(v) => (n.trim(), Some(v)),
            Err(_) => return false, // préfixe non numérique -> entrée rejetée (fail-closed)
        },
        None => (cidr, None), // pas de '/' -> comparaison d'IP exacte
    };
    let net_ip: IpAddr = match net.parse() {
        Ok(i) => i,
        Err(_) => return false,
    };
    match (ip, net_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let bits = prefix.unwrap_or(32);
            if bits > 32 {
                return false;
            }
            let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(*a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let bits = prefix.unwrap_or(128);
            if bits > 128 {
                return false;
            }
            let mask: u128 = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(*a) & mask) == (u128::from(b) & mask)
        }
        _ => false, // v4 vs v6 : jamais dans le même réseau
    }
}

/// IP client EFFECTIVE pour la politique opérateur source-CIDR. Par défaut = IP du pair TCP
/// (ConnectInfo). On n'honore le DERNIER hop de `X-Forwarded-For` QUE si le pair TCP réel `peer` est
/// LUI-MÊME un proxy de confiance, c.-à-d. tombe dans l'un des `trusted_proxy_cidrs`. Sinon (client
/// direct qui court-circuite le vrai proxy, pair hors CIDR, ou pair inconnu) le XFF est INTÉGRALEMENT
/// IGNORÉ et on retombe FAIL-CLOSED sur `peer` — sans quoi un client se connectant directement à
/// l'origine pourrait forger `X-Forwarded-For: <IP-dans-l'allowlist>` et usurper la politique source.
/// La liste `trusted_proxy_cidrs` vide => aucun proxy de confiance => XFF toujours ignoré.
/// Fonction PURE (testable sans connexion réelle).
fn effective_client_ip(peer: Option<IpAddr>, headers: &HeaderMap, trusted_proxy_cidrs: &[String]) -> Option<IpAddr> {
    if let Some(p) = peer {
        // Le pair TCP DOIT être un proxy de confiance pour qu'on accorde foi au XFF qu'il a posé.
        if !trusted_proxy_cidrs.is_empty() && trusted_proxy_cidrs.iter().any(|c| ip_in_cidr(&p, c)) {
            if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                if let Some(last) = xff.split(',').map(|s| s.trim()).rfind(|s| !s.is_empty()) {
                    if let Ok(ip) = last.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
            // pair = proxy de confiance mais aucun XFF exploitable -> repli sur le pair (le proxy).
        }
    }
    // pair non-proxy (client direct), hors CIDR, ou inconnu -> XFF IGNORÉ, fail-closed sur le pair.
    peer
}

/// Test de VALIDITÉ d'une entrée CIDR (ou IP exacte sans `/`) selon les mêmes critères que
/// `ip_in_cidr` : IP v4/v6 parsable + préfixe numérique dans les bornes de la famille. Sert à
/// distinguer un `trusted_proxy` réellement configuré (au moins un CIDR valide) d'une valeur héritée
/// « truthy » non-CIDR (ex. "1", "true") qui NE doit PAS valoir « tout faire confiance ». Fonction PURE.
fn cidr_is_valid(cidr: &str) -> bool {
    let cidr = cidr.trim();
    match cidr.split_once('/') {
        Some((n, p)) => match p.trim().parse::<u32>() {
            Ok(bits) => match n.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => bits <= 32,
                Ok(IpAddr::V6(_)) => bits <= 128,
                Err(_) => false,
            },
            Err(_) => false,
        },
        None => cidr.parse::<IpAddr>().is_ok(),
    }
}

/// Parse le réglage `settings.trusted_proxy` en une LISTE de CIDRs de proxies de confiance. Accepte
/// (dans l'ordre) : (1) un tableau JSON de chaînes CIDR `["10.0.0.0/24","..."]` ; (2) une liste
/// séparée par des virgules `10.0.0.0/24, 172.16.0.0/12` ; (3) un CIDR unique. Chaque entrée est
/// VALIDÉE (`cidr_is_valid`) ; les entrées invalides sont écartées. RÉTRO-COMPAT / MIGRATION : une
/// valeur héritée « truthy » non-CIDR (ex. "1", "true", "yes") ne produit AUCUN CIDR valide -> liste
/// VIDE -> AUCUN proxy de confiance (repli fail-closed sur le pair). On ne conserve JAMAIS
/// silencieusement l'ancien comportement « boolean = fais confiance à tout XFF ». Fonction PURE.
fn parse_trusted_proxy_cidrs(raw: &str) -> Vec<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let candidates: Vec<String> = match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(arr)) => arr.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).collect(),
        // pas un tableau JSON (chaîne "1", bool true, CSV, CIDR nu…) -> split CSV / valeur unique.
        _ => raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
    };
    candidates.into_iter().filter(|c| cidr_is_valid(c)).collect()
}

/// POLITIQUE OPÉRATEUR source-CIDR — OPT-IN, fail-closed UNIQUEMENT quand configurée. Lit
/// `settings.operator_policy.source_cidrs` : si absent/vide -> AUCUNE restriction (true, défaut = none,
/// zéro valeur codée en dur). Sinon l'IP client effective (cf. effective_client_ip) DOIT tomber dans
/// l'un des CIDRs, faute de quoi l'action opérateur est refusée. Politique active + IP indéterminée
/// (aucun pair, aucun XFF) -> refus (fail-closed). Ne restreint QUE le C2 opérateur (appelée depuis
/// check_operator) — jamais l'admin ni le viewer.
fn operator_source_allowed(app: &App, headers: &HeaderMap, peer: Option<IpAddr>) -> bool {
    let (cidrs, trusted_proxy_cidrs) = {
        let db = app.db();
        let cidrs: Vec<String> = settings_get(&db, "operator_policy")
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.get("source_cidrs").and_then(|c| c.as_array()).cloned())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        // `trusted_proxy` = CIDR(s) des proxies de confiance (cf. parse_trusted_proxy_cidrs). Un XFF
        // n'est honoré que si le pair TCP tombe dans l'un d'eux ; sinon repli fail-closed sur le pair.
        let trusted_proxy_cidrs = settings_get(&db, "trusted_proxy")
            .map(|s| parse_trusted_proxy_cidrs(&s))
            .unwrap_or_default();
        (cidrs, trusted_proxy_cidrs)
    };
    if cidrs.is_empty() {
        return true; // aucune contrainte source configurée -> défaut = aucune restriction
    }
    match effective_client_ip(peer, headers, &trusted_proxy_cidrs) {
        Some(ip) => cidrs.iter().any(|c| ip_in_cidr(&ip, c)),
        None => false, // politique active mais IP client indéterminée -> fail-closed
    }
}

/// Authz C2 (run/cancel) — FAIL-CLOSED. Vrai si :
///   1) une SESSION valide porte un rôle operator|admin (compte individuel) OU la preuve par hash env
///      (X-Forge-Operator) matche (compte 'bootstrap'/admin) — un viewer en session ne passe JAMAIS ;
///   2) ET la politique source-CIDR (opt-in) l'autorise : si `settings.operator_policy.source_cidrs`
///      est configuré, l'IP client (`peer`, ou dernier hop XFF UNIQUEMENT si le pair TCP est lui-même
///      dans un CIDR de `settings.trusted_proxy`) doit être dans l'allowlist ; non configuré ->
///      aucune restriction (défaut = none).
///
/// `peer` = IP du pair TCP (ConnectInfo) fournie par le handler ; None dans les tests/harness où elle
/// est simulée. La contrainte source ne s'applique QU'AU C2 opérateur — jamais admin/viewer.
fn check_operator(app: &App, headers: &HeaderMap, peer: Option<IpAddr>) -> bool {
    // 1) AUTHN opérateur : l'identité réelle en session prime (viewer -> refus, pas de repli env),
    //    sinon repli rétro-compat par hash env.
    let authed = match resolve_session_identity(app, headers) {
        Some(id) => id.is_operator,
        None => check_operator_env(app, headers),
    };
    if !authed {
        return false;
    }
    // 2) contrainte source-CIDR (opt-in, fail-closed quand configurée).
    operator_source_allowed(app, headers, peer)
}

/// Réponse standard d'un refus C2 (403). Distingue « non provisionné » (501-like message) de
/// « mauvaise preuve » sans fuir lequel — message stable, code 403 dans les deux cas (fail-closed).
fn operator_denied(app: &App) -> (StatusCode, Json<Value>) {
    // Message stable et non-fuiteur. On ne distingue plus que le cas « aucune voie operator possible »
    // (ni hash env, ni — par construction — session valide ici) du cas « preuve invalide/insuffisante ».
    let why = if app.operator_hash.is_empty() {
        "rôle opérateur non provisionné (aucune session operator|admin valide, FORGE_CONSOLE_OPERATOR_HASH absent) — C2 fermé"
    } else {
        "preuve opérateur invalide ou absente (session operator|admin via POST /api/login, ou en-tête X-Forge-Operator)"
    };
    (StatusCode::FORBIDDEN, Json(json!({"error": "operator_required", "why": why})))
}

// --- rôle ADMIN (administration : setup, comptes, settings, gouvernance des connecteurs) ---
//
// Distinct de l'opérateur : administrer la console (créer/désactiver des comptes, muter la table
// `settings`, gouverner les connecteurs) est une capacité de plus haut privilège que lancer un run.
//
// FAIL-CLOSED + ATTRIBUTION INDIVIDUELLE STRICTE : check_admin exige une SESSION valide portant le
// rôle `admin` (resolve_session_identity). Contrairement à check_operator, il N'Y A PAS de repli par
// hash env — une mutation d'administration DOIT être imputable à un compte individuel nommé (pas à un
// secret partagé « bootstrap »). Sans session admin -> refus. Un viewer/operator ne passe JAMAIS.

/// Authz ADMINISTRATION — FAIL-CLOSED. Vrai UNIQUEMENT si une session valide porte le rôle `admin`.
/// Aucun repli env-hash (attribution individuelle obligatoire). Miroir de check_operator, plus strict.
fn check_admin(app: &App, headers: &HeaderMap) -> bool {
    match resolve_session_identity(app, headers) {
        Some(id) => id.role == "admin",
        None => false, // aucune session individuelle -> refus (pas de repli hash env pour l'admin)
    }
}

/// Réponse standard d'un refus admin (403). Message stable et non-fuiteur (fail-closed).
fn admin_denied() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "admin_required",
            "why": "administration réservée à une session au rôle admin (POST /api/login) — pas de repli par secret partagé"
        })),
    )
}

// --- settings KV : configuration mutable d'administration (get/set avec horodatage) ---

/// Lit une clé de configuration dans la table `settings`. None si absente ou erreur DB (fail-soft en
/// LECTURE : une clé non provisionnée => valeur par défaut côté appelant, jamais de valeur inventée).
#[allow(dead_code)] // substrat consommé par les routes settings/setup/detection à venir
fn settings_get(db: &Connection, key: &str) -> Option<String> {
    db.query_row("SELECT value FROM settings WHERE key=?", [key], |r| r.get::<_, String>(0)).ok()
}

/// Écrit (upsert) une clé de configuration avec l'horodatage `updated` courant. PRIMARY KEY sur `key`
/// => une seule ligne par clé (pas de doublon). Renvoie une erreur si l'écriture DB échoue (l'appelant
/// admin doit pouvoir la propager avant de ledgeriser). Mutations réservées à check_admin.
#[allow(dead_code)] // substrat consommé par les routes settings/setup/detection à venir
fn settings_set(db: &Connection, key: &str, value: &str) -> Result<(), String> {
    db.execute(
        "INSERT INTO settings(key,value,updated) VALUES(?,?,datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
        rusqlite::params![key, value],
    )
    .map(|_| ())
    .map_err(|e| format!("écriture settings échouée: {e}"))
}

// =====================================================================================
// COMPTES UTILISATEURS (#6) — identités individuelles + attribution.
//
// Avant : les 3 rôles (viewer/operator/admin) étaient des MOTS DE PASSE PARTAGÉS (hash via env) —
// impossible de savoir QUI a armé un exploit. On ajoute des comptes individuels (table `users`) +
// des sessions courtes (table `session`), tout en PRÉSERVANT la rétro-compat : si aucune session
// n'est présente, on retombe sur les hash via env (FORGE_CONSOLE_PASS_HASH/OPERATOR_HASH) en tant
// que compte 'bootstrap' (la console live tourne déjà comme ça — elle ne doit pas casser).
//
// FAIL-CLOSED : `operator` reste fail-closed (un viewer n'arme rien). L'attribution propage l'identité
// (login) au lieu du littéral 'operator' dans run_job.started_by, run_cancel et le ledger ('actor').

/// Durée de vie d'une session (secondes) — sessions COURTES. Override par FORGE_CONSOLE_SESSION_TTL.
fn session_ttl_secs() -> i64 {
    std::env::var("FORGE_CONSOLE_SESSION_TTL")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(3600) // 1 h par défaut
}

/// Epoch s courant (UTC). Sans dépendance chrono — SystemTime depuis l'UNIX_EPOCH.
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Rôles valides — contrainte APPLICATIVE (la table stocke un TEXT libre). `viewer` lit, `operator`
/// arme le C2, `admin` = superset (peut aussi armer). Tout autre rôle est refusé à la création.
fn validate_role(r: &str) -> Result<String, String> {
    match r {
        "viewer" | "operator" | "admin" => Ok(r.to_string()),
        _ => Err("rôle invalide (attendu: viewer|operator|admin)".into()),
    }
}

/// Validation stricte d'un login : `[A-Za-z0-9._-]{1,64}`, non vide, pas de `-` en tête (parité avec
/// validate_campaign — anti confusion avec un flag CLI et entrées hostiles).
fn validate_login(s: &str) -> Result<String, String> {
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

/// Identité résolue d'un appelant : login affiché en attribution + rôle effectif. `is_operator`
/// = peut armer le C2 (operator|admin OU bootstrap env-hash). `via_session` distingue un compte
/// individuel (true) du repli bootstrap par hash env (false).
#[derive(Clone, Debug)]
struct Identity {
    login: String,
    role: String,
    is_operator: bool,
    via_session: bool,
}

/// Extrait le token de session du porteur : en-tête `Authorization: Bearer <t>` (priorité) OU cookie
/// `forge_session=<t>`. Renvoie le token EN CLAIR (à hasher avant lookup), vide si absent.
fn session_token_from_headers(headers: &HeaderMap) -> String {
    if let Some(authz) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(tok) = authz.strip_prefix("Bearer ") {
            let t = tok.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    // cookie forge_session=...
    if let Some(cookie) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            let p = part.trim();
            if let Some(val) = p.strip_prefix("forge_session=") {
                if !val.is_empty() {
                    return val.to_string();
                }
            }
        }
    }
    String::new()
}

/// Résout l'identité depuis une session VALIDE (non expirée, compte non désactivé). None si pas de
/// session présentée, session inconnue/expirée, ou compte désactivé (fail-closed). Purge en passant
/// la session expirée (best-effort). Lecture du compte au moment du lookup => un rôle changé/désactivé
/// prend effet immédiatement même sur une session déjà émise.
fn resolve_session_identity(app: &App, headers: &HeaderMap) -> Option<Identity> {
    let tok = session_token_from_headers(headers);
    if tok.is_empty() {
        return None;
    }
    let token_sha = sha_hex(&tok);
    let db = app.db();
    let row = db.query_row(
        "SELECT s.expires, u.login, u.role, u.disabled
           FROM session s JOIN users u ON u.id = s.user_id
          WHERE s.token_sha = ?",
        [&token_sha],
        |r| Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
        )),
    );
    match row {
        Ok((expires, login, role, disabled)) => {
            if disabled != 0 {
                return None; // compte désactivé -> fail-closed
            }
            if now_epoch() >= expires {
                // session expirée -> purge best-effort et refus
                let _ = db.execute("DELETE FROM session WHERE token_sha=?", [&token_sha]);
                return None;
            }
            let is_operator = role == "operator" || role == "admin";
            Some(Identity { login, role, is_operator, via_session: true })
        }
        Err(_) => None,
    }
}

/// Identité effective d'un appelant pour l'ATTRIBUTION et l'AUTHZ C2 :
///   1) session valide (compte individuel) -> identité réelle (login/role) ;
///   2) SINON repli RÉTRO-COMPAT : preuve opérateur par hash env (X-Forge-Operator) -> compte
///      'bootstrap' (role=admin, is_operator=true) ; preuve viewer Basic -> 'bootstrap' viewer.
///
/// None => aucune identité (anonyme dev-open ou pas de preuve). via_session=false sur les replis env.
fn resolve_identity(app: &App, headers: &HeaderMap) -> Option<Identity> {
    if let Some(id) = resolve_session_identity(app, headers) {
        return Some(id);
    }
    // Repli bootstrap (rétro-compat) : l'en-tête opérateur env-hash agit comme un compte admin.
    if !app.operator_hash.is_empty() && check_operator_env(app, headers) {
        return Some(Identity {
            login: "bootstrap".into(),
            role: "admin".into(),
            is_operator: true,
            via_session: false,
        });
    }
    None
}

/// Login d'attribution : identité résolue si présente, sinon le littéral historique 'operator'
/// (ce qui préserve EXACTEMENT le comportement existant quand seul le hash env est en jeu mais qu'on
/// n'a pas matché ci-dessus — cas dev-open). N'altère aucun garde-fou.
fn attribution_login(app: &App, headers: &HeaderMap) -> String {
    resolve_identity(app, headers).map(|i| i.login).unwrap_or_else(|| "operator".into())
}

/// GET /api/whoami — identité effective de l'appelant (pour l'UI : afficher l'utilisateur connecté,
/// activer/masquer les actions C2 selon le rôle). Résout la session (compte individuel) ou le repli
/// bootstrap env-hash. `authenticated:false` si aucune identité (dev-open anonyme).
async fn whoami(State(app): State<App>, headers: HeaderMap) -> impl IntoResponse {
    match resolve_identity(&app, &headers) {
        Some(id) => Json(json!({
            "authenticated": true,
            "login": id.login,
            "role": id.role,
            "is_operator": id.is_operator,
            "via_session": id.via_session, // false => repli bootstrap (hash env), true => compte individuel
        })),
        None => Json(json!({"authenticated": false, "login": Value::Null, "role": Value::Null, "is_operator": false, "via_session": false})),
    }
}

/// Génère un token de session opaque (256 bits hex via CSPRNG OS). Le Result de getrandom est propagé
/// (panic) : un échec d'entropie produirait un token PRÉVISIBLE -> usurpation de session.
fn gen_session_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("CSPRNG (getrandom) indisponible — refus de générer une session faible");
    hex(&b)
}

/// Crée une session pour `user_id` (token EN CLAIR renvoyé à l'appelant, SHA-256 persisté). Retourne
/// (token_clair, expires_epoch). Purge en passant les sessions expirées de l'utilisateur (best-effort).
fn create_session(app: &App, user_id: i64) -> (String, i64) {
    let token = gen_session_token();
    let token_sha = sha_hex(&token);
    let now = now_epoch();
    let expires = now + session_ttl_secs();
    let db = app.db();
    let _ = db.execute("DELETE FROM session WHERE user_id=? AND expires<=?", rusqlite::params![user_id, now]);
    let _ = db.execute(
        "INSERT OR REPLACE INTO session(token_sha,user_id,created,expires) VALUES(?,?,?,?)",
        rusqlite::params![token_sha, user_id, now, expires],
    );
    (token, expires)
}

/// Provisionne un compte dans la table `users` (argon2id). Idempotent vis-à-vis du login : si le login
/// existe déjà, MET À JOUR rôle + hash + réactive (disabled=0). Renvoie le rôle validé ou une erreur.
/// Utilisé par la sous-commande CLI `useradd`. Validation login/role stricte (fail-closed).
fn upsert_user(db: &Connection, login: &str, role: &str, pass_hash: &str) -> Result<String, String> {
    let login = validate_login(login)?;
    let role = validate_role(role)?;
    if pass_hash.is_empty() {
        return Err("hash de mot de passe vide".into());
    }
    db.execute(
        "INSERT INTO users(login,role,pass_hash,disabled,created)
         VALUES(?,?,?,0,datetime('now'))
         ON CONFLICT(login) DO UPDATE SET role=excluded.role, pass_hash=excluded.pass_hash, disabled=0",
        rusqlite::params![login, role, pass_hash],
    )
    .map_err(|e| format!("écriture users échouée: {e}"))?;
    Ok(role)
}

// =====================================================================================
// ADMINISTRATION WEB DES COMPTES (#4) — CRUD réservé check_admin (session admin, fail-closed),
// chaque mutation ATTRIBUÉE à l'admin acteur et LEDGERISÉE (append_console_ledger). Aucune route ne
// renvoie jamais `pass_hash`. Après chaque mutation, `auth_required` est recalculé (la gate d'auth
// s'engage/se désengage sur l'ÉTAT DB — cf. recompute_auth_required). Les mots de passe/hash n'entrent
// JAMAIS dans le ledger (login/rôle/booléens seuls). Roles conservés tels quels : viewer|operator|admin.
// =====================================================================================

/// Rang de privilège d'un rôle (viewer < operator < admin). Sert à détecter une RÉTROGRADATION (rang
/// décroissant) qui doit purger les sessions du compte pour un effet immédiat. Rôle inconnu -> 0.
fn role_rank(r: &str) -> i32 {
    match r {
        "admin" => 3,
        "operator" => 2,
        "viewer" => 1,
        _ => 0,
    }
}

/// Nombre d'admins ACTIVÉS (`role='admin' AND disabled=0`). Substrat du garde-fou « dernier admin » :
/// on n'autorise JAMAIS une opération qui laisserait 0 admin activé (verrouillage total de l'admin).
/// À appeler EN TENANT DÉJÀ le guard `db` (pas de re-lock) pour que le check+mutation soient ATOMIQUES
/// sous le même mutex (anti-TOCTOU). Échec de lecture -> 0 => l'opération est refusée (fail-closed).
fn enabled_admin_count(db: &Connection) -> i64 {
    db.query_row("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0", [], |r| r.get(0)).unwrap_or(0)
}

/// Liste les comptes pour l'admin — `{login, role, disabled, created}`. Ne SÉLECTIONNE même pas
/// `pass_hash` (fuite structurellement impossible). Ordre alphabétique. Lecture pure (aucun ledger).
fn admin_list_users(app: &App) -> Vec<Value> {
    let db = app.db();
    let mut stmt = match db.prepare("SELECT login, role, disabled, created FROM users ORDER BY login") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map([], |r| {
        Ok(json!({
            "login": r.get::<_, String>(0)?,
            "role": r.get::<_, String>(1)?,
            "disabled": r.get::<_, i64>(2)? != 0,
            "created": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
        }))
    })
    .map(|it| it.filter_map(|x| x.ok()).collect())
    .unwrap_or_default()
}

/// Crée un compte individuel. Valide login/rôle (fail-closed), hash argon2id HORS mutex, refuse un login
/// déjà pris (409 — l'édition sert à muter). Recalcule `auth_required` (1er compte activé -> gate) et
/// ledgerise avec l'admin acteur (login/rôle seuls, JAMAIS le mot de passe). Retourne la vue publique.
fn admin_create_user(app: &App, actor: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    let login = validate_login(&gs(body, "login")).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let role = validate_role(&gs(body, "role")).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let password = gs(body, "password");
    if password.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "mot de passe vide refusé".into()));
    }
    // argon2id est coûteux -> on hash AVANT de prendre le mutex DB (ne pas geler l'API pendant le KDF).
    let hash = hash_pw(&password);
    {
        let db = app.db();
        // création STRICTE : un login déjà présent -> 409 (passer par l'édition pour modifier).
        if db.query_row("SELECT 1 FROM users WHERE login=?", [&login], |_| Ok(())).is_ok() {
            return Err((StatusCode::CONFLICT, format!("le compte '{login}' existe déjà (utilisez l'édition)")));
        }
        upsert_user(&db, &login, &role, &hash).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    app.recompute_auth_required();
    append_console_ledger(app, "console.admin.user.create", json!({"actor": actor, "login": login, "role": role}));
    Ok(json!({"login": login, "role": role, "disabled": false}))
}

/// Modifie un compte : changement de rôle, réinitialisation de mot de passe, (dé)activation (champs tous
/// optionnels). GARDE-FOU dernier admin (fail-closed, 409) : refuse toute opération qui retirerait le
/// DERNIER admin activé (désactivation ou rétrogradation du seul admin). PURGE les sessions du compte
/// quand l'effet doit être immédiat : désactivation, rétrogradation (rang décroissant) OU reset de mot
/// de passe (une session volée ne survit pas au reset). Check dernier-admin + mutations + purge sous UN
/// SEUL guard DB (atomique, anti-TOCTOU). Recalcule `auth_required`, ledgerise (jamais le mot de passe).
fn admin_update_user(app: &App, actor: &str, target_login: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    let target_login = validate_login(target_login).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let new_role: Option<String> = if body.get("role").is_some() {
        Some(validate_role(&gs(body, "role")).map_err(|e| (StatusCode::BAD_REQUEST, e))?)
    } else {
        None
    };
    let password = gs(body, "password");
    let reset_pw = !password.is_empty();
    let new_disabled: Option<bool> = body.get("disabled").and_then(|v| v.as_bool());
    if new_role.is_none() && !reset_pw && new_disabled.is_none() {
        return Err((StatusCode::BAD_REQUEST, "aucun changement fourni (role|password|disabled)".into()));
    }
    // hash HORS section critique (argon2id coûteux).
    let new_hash: Option<String> = if reset_pw { Some(hash_pw(&password)) } else { None };

    let (purge, eff_role, eff_disabled) = {
        let db = app.db();
        let (old_role, old_disabled_i): (String, i64) = db
            .query_row("SELECT role, disabled FROM users WHERE login=?", [&target_login], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|_| (StatusCode::NOT_FOUND, format!("compte '{target_login}' introuvable")))?;
        let old_disabled = old_disabled_i != 0;
        let eff_role = new_role.clone().unwrap_or_else(|| old_role.clone());
        let eff_disabled = new_disabled.unwrap_or(old_disabled);
        // GARDE-FOU dernier admin : si le compte ÉTAIT un admin activé et ne l'est PLUS après l'op,
        // refuser tant qu'il ne reste qu'un seul admin activé (fail-closed : jamais 0 admin -> lockout).
        let was_enabled_admin = old_role == "admin" && !old_disabled;
        let still_enabled_admin = eff_role == "admin" && !eff_disabled;
        if was_enabled_admin && !still_enabled_admin && enabled_admin_count(&db) <= 1 {
            return Err((
                StatusCode::CONFLICT,
                "impossible : dernier admin activé (désactivation/rétrogradation refusée, fail-closed)".into(),
            ));
        }
        if let Some(r) = &new_role {
            db.execute("UPDATE users SET role=? WHERE login=?", rusqlite::params![r, target_login])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj rôle échouée: {e}")))?;
        }
        if let Some(h) = &new_hash {
            db.execute("UPDATE users SET pass_hash=? WHERE login=?", rusqlite::params![h, target_login])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj mot de passe échouée: {e}")))?;
        }
        if let Some(d) = new_disabled {
            db.execute("UPDATE users SET disabled=? WHERE login=?", rusqlite::params![d as i64, target_login])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj état échouée: {e}")))?;
        }
        let downgrade = new_role.as_ref().map(|r| role_rank(r) < role_rank(&old_role)).unwrap_or(false);
        let disabling = new_disabled == Some(true);
        let purge = disabling || downgrade || reset_pw;
        if purge {
            // effet IMMÉDIAT : révoque toutes les sessions actives du compte (même mutex que l'update).
            let _ = db.execute(
                "DELETE FROM session WHERE user_id=(SELECT id FROM users WHERE login=?)",
                [&target_login],
            );
        }
        (purge, eff_role, eff_disabled)
    };
    app.recompute_auth_required();
    append_console_ledger(app, "console.admin.user.update", json!({
        "actor": actor,
        "login": target_login,
        "role": new_role,
        "disabled": new_disabled,
        "password_reset": reset_pw,
        "sessions_purged": purge,
    }));
    Ok(json!({
        "login": target_login,
        "role": eff_role,
        "disabled": eff_disabled,
        "sessions_purged": purge,
        "password_reset": reset_pw,
    }))
}

/// Supprime un compte. GARDE-FOU (fail-closed, 409) : refuse de supprimer le DERNIER admin activé
/// (verrouillage total de l'administration). Purge d'abord ses sessions, puis la ligne `users`, sous
/// UN SEUL guard DB (atomique). Recalcule `auth_required` et ledgerise l'action avec l'admin acteur.
fn admin_delete_user(app: &App, actor: &str, target_login: &str) -> Result<Value, (StatusCode, String)> {
    let target_login = validate_login(target_login).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    {
        let db = app.db();
        let (role, disabled): (String, i64) = db
            .query_row("SELECT role, disabled FROM users WHERE login=?", [&target_login], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|_| (StatusCode::NOT_FOUND, format!("compte '{target_login}' introuvable")))?;
        if role == "admin" && disabled == 0 && enabled_admin_count(&db) <= 1 {
            return Err((StatusCode::CONFLICT, "impossible de supprimer le dernier admin activé (fail-closed)".into()));
        }
        // révoque les sessions AVANT la suppression de la ligne (effet immédiat + pas d'orphelin).
        let _ = db.execute(
            "DELETE FROM session WHERE user_id=(SELECT id FROM users WHERE login=?)",
            [&target_login],
        );
        db.execute("DELETE FROM users WHERE login=?", [&target_login])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("suppression échouée: {e}")))?;
    }
    app.recompute_auth_required();
    append_console_ledger(app, "console.admin.user.delete", json!({"actor": actor, "login": target_login}));
    Ok(json!({"deleted": target_login}))
}

/// GOUVERNANCE CONNECTEUR (#4) — mute l'intention opérateur sur un module : `enabled` (install/uninstall
/// opérationnel), `available_override` (NULL=suivre la sonde host, true/false=forcer), `web_allowed`.
/// Chaque champ est OPTIONNEL (présence = mutation, absence = inchangé) ; `available_override` accepte
/// aussi `null` (EFFACER l'override). Le connecteur doit exister dans le registre (404 sinon — l'admin ne
/// crée pas de module fantôme). Mutation attribuée + ledgerisée (jamais de secret). Renvoie la vue à-jour
/// (avec `effective_available`). L'enforcement au tir vit ailleurs (scope.json disabled_modules + filtre
/// --modules + refus validate_modules) : ici on ne fait QUE persister l'intention.
fn admin_set_module(app: &App, actor: &str, kind: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    // kind = clé de module bien formée (même grammaire que validate_campaign) — anti entrée hostile.
    let kind = validate_campaign(kind).map_err(|e| (StatusCode::BAD_REQUEST, format!("kind invalide: {e}")))?;

    // Trois champs optionnels, typés stricts. available_override distingue 3 états (inchangé/effacé/forcé).
    #[derive(Clone, Copy)]
    enum Ov { Unchanged, Clear, Set(bool) }
    let enabled: Option<bool> = match body.get("enabled") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err((StatusCode::BAD_REQUEST, "enabled doit être un booléen".into())),
    };
    let web_allowed: Option<bool> = match body.get("web_allowed") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err((StatusCode::BAD_REQUEST, "web_allowed doit être un booléen".into())),
    };
    let ov: Ov = match body.get("available_override") {
        None => Ov::Unchanged,
        Some(Value::Null) => Ov::Clear,
        Some(Value::Bool(b)) => Ov::Set(*b),
        Some(_) => return Err((StatusCode::BAD_REQUEST, "available_override doit être un booléen ou null".into())),
    };
    if enabled.is_none() && web_allowed.is_none() && matches!(ov, Ov::Unchanged) {
        return Err((StatusCode::BAD_REQUEST, "aucun changement fourni (enabled|available_override|web_allowed)".into()));
    }

    let view = {
        let db = app.db();
        // le connecteur doit exister (catalogue = source de vérité des kinds, peuplé au boot).
        if db.query_row("SELECT 1 FROM module WHERE kind=?", [&kind], |_| Ok(())).is_err() {
            return Err((StatusCode::NOT_FOUND, format!("connecteur '{kind}' inconnu du registre")));
        }
        if let Some(e) = enabled {
            db.execute("UPDATE module SET enabled=? WHERE kind=?", rusqlite::params![e as i64, kind])
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj enabled échouée: {err}")))?;
        }
        if let Some(w) = web_allowed {
            db.execute("UPDATE module SET web_allowed=? WHERE kind=?", rusqlite::params![w as i64, kind])
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj web_allowed échouée: {err}")))?;
        }
        match ov {
            Ov::Unchanged => {}
            Ov::Clear => {
                db.execute("UPDATE module SET available_override=NULL WHERE kind=?", [&kind])
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj available_override échouée: {err}")))?;
            }
            Ov::Set(b) => {
                db.execute("UPDATE module SET available_override=? WHERE kind=?", rusqlite::params![b as i64, kind])
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj available_override échouée: {err}")))?;
            }
        }
        // vue à-jour (un seul row) pour la réponse ET le ledger (effective_available inclus).
        modules_catalog(&db)
            .into_iter()
            .find(|m| m.get("kind").and_then(|v| v.as_str()) == Some(kind.as_str()))
            .unwrap_or_else(|| json!({"kind": kind}))
    };
    // LEDGER : mutation d'administration attribuée à l'acteur (qui/quoi/quand). Aucun secret n'entre ici.
    append_console_ledger(app, "console.admin.module.set", json!({
        "actor": actor,
        "kind": kind,
        "enabled": enabled,
        "available_override": match ov { Ov::Unchanged => Value::Null, Ov::Clear => Value::String("cleared".into()), Ov::Set(b) => Value::Bool(b) },
        "web_allowed": web_allowed,
        "effective_available": view.get("effective_available").cloned().unwrap_or(Value::Null),
    }));
    Ok(view)
}

/// GET /api/users — liste des comptes (admin, fail-closed 403 sinon). Jamais `pass_hash`.
async fn users_list(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    (StatusCode::OK, Json(json!({"users": admin_list_users(&app)}))).into_response()
}

/// POST /api/users {login,role,password} — crée un compte (admin). Mutation attribuée + ledgerisée.
async fn users_create(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_create_user(&app, &actor, &body) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "user_create_failed", "why": why}))).into_response(),
    }
}

/// POST /api/users/:login {role?,password?,disabled?} — modifie un compte (admin). Purge les sessions
/// sur désactivation/rétrogradation/reset ; bloque le retrait du dernier admin activé (409).
async fn users_update(State(app): State<App>, headers: HeaderMap, Path(login): Path<String>, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_update_user(&app, &actor, &login, &body) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "user_update_failed", "why": why}))).into_response(),
    }
}

/// DELETE /api/users/:login — supprime un compte (admin). Bloque la suppression du dernier admin (409).
async fn users_delete(State(app): State<App>, headers: HeaderMap, Path(login): Path<String>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_delete_user(&app, &actor, &login) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "user_delete_failed", "why": why}))).into_response(),
    }
}

/// POST /api/modules/:kind {enabled?, available_override?, web_allowed?} — GOUVERNE un connecteur
/// (install/uninstall opérationnel). Réservé admin (check_admin, fail-closed 403 sinon). Mutation
/// attribuée à l'admin acteur + ledgerisée. Désactiver un connecteur l'empêche RÉELLEMENT de tirer
/// (scope.json disabled_modules + filtre --modules + refus validate_modules), y compris pour les modules
/// choisis par le planner. Cette route est la contrepartie « écriture » de GET /api/modules (lecture).
async fn module_governance(State(app): State<App>, headers: HeaderMap, Path(kind): Path<String>, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_set_module(&app, &actor, &kind, &body) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "module_set_failed", "why": why}))).into_response(),
    }
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

/// Décision PURE du auth_guard (testable sans middleware/HTTP) : la requête est-elle AUTORISÉE à
/// passer ? `true` => on laisse passer ; `false` => le middleware répond 401 (login portal côté SPA).
///
/// La gate s'engage sur `auth_required` (cache : hash env posé OU compte activé en base — voir
/// recompute_auth_required), et NON plus sur `pass_hash` seul : un fresh install avec des comptes en
/// base mais sans hash env est désormais GATÉ (ferme le trou dev-open historique). Quand la gate est
/// désengagée (dev-open : ni hash env, ni compte activé), tout passe (les ÉCRITURES restent gatées par
/// leur propre check_token/check_operator). Quand elle est engagée, on accepte : (1) une session
/// individuelle valide (cookie/Bearer <session>, tout rôle) ; (2) Basic viewer (pass_hash env) ;
/// (3) Bearer = token d'ingest. Sinon refus (401). FAIL-CLOSED.
fn auth_guard_allows(app: &App, headers: &HeaderMap) -> bool {
    if !app.auth_required() {
        return true; // dev-open : ni hash env ni compte activé -> gate désengagée
    }
    // Session individuelle (cookie forge_session ou Bearer <session>) -> accès lecture (tout rôle).
    // Vérifié AVANT le Bearer ingest-token : un token de session valide identifie un compte réel.
    if resolve_session_identity(app, headers).is_some() {
        return true;
    }
    let authz = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(b64) = authz.strip_prefix("Basic ") {
        if check_basic(app, b64.trim()) {
            return true;
        }
    }
    if let Some(tok) = authz.strip_prefix("Bearer ") {
        if ct_eq_str(&sha_hex(tok.trim()), &app.token_sha) {
            return true;
        }
    }
    false
}

/// RBAC (middleware) : la gate s'engage dès qu'un hash env est posé OU qu'un compte activé existe en
/// base (auth_required). Engagée + sans preuve valide -> 401 (le SPA affiche alors le portail de
/// login). Désengagée (dev-open) -> passe. Toute la décision vit dans auth_guard_allows (testable).
async fn auth_guard(State(app): State<App>, req: Request, next: Next) -> Response {
    if auth_guard_allows(&app, req.headers()) {
        return next.run(req).await;
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
            // CWE séparé : on prend `cwe` si fourni par le moteur, sinon on le dérive de `category`
            // (rétro-compat avec les anciens modules qui ne posaient que `category="CWE-639"`).
            let cwe = {
                let c = gs(f, "cwe");
                if c.is_empty() { extract_cwe(&gs(f, "category")) } else { c }
            };
            // CVSS de base : vecteur fourni, sinon dérivé de la sévérité (repère de priorisation).
            let (mut cvss_vec, mut cvss_score) = (gs(f, "cvss_vector"), f.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0));
            if cvss_vec.is_empty() && cvss_score == 0.0 {
                let (v, s) = cvss_base_for_severity(&gs(f, "severity"));
                cvss_vec = v.to_string();
                cvss_score = s;
            }
            if let Ok(n) = db.execute(
                "INSERT OR IGNORE INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![gs(f,"ts"), campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                    gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                    gs(f,"fix"), run_id, cwe, cvss_vec, cvss_score],
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

/// POST /api/login {login,password} -> pose une session COURTE (cookie + bearer renvoyés).
/// Vérifie le couple contre la table `users` (argon2id), refuse un compte désactivé. Réponse 200 :
///   {"token": <bearer>, "login", "role", "expires"} + en-tête Set-Cookie `forge_session=<token>`
///   (HttpOnly, SameSite=Strict, Path=/, Max-Age=TTL). Le client peut ensuite s'authentifier soit par
///   le cookie (UI), soit par `Authorization: Bearer <token>` (CLI/API). 401 sur identifiants invalides.
/// NB : route NON gardée par auth_guard (sinon impossible de se connecter quand pass_hash est posé) ;
/// elle est sous host_guard comme tout le reste. Échec d'identifiant -> message générique (anti-énum).
async fn login(State(app): State<App>, Json(body): Json<Value>) -> Response {
    let login_in = body.get("login").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if login_in.is_empty() || password.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "login et password requis"}))).into_response();
    }
    // lookup compte. On vérifie TOUJOURS le hash (même si compte introuvable : timing uniforme via un
    // hash factice) pour limiter l'oracle d'énumération de login.
    let (user_id, role, pass_hash, disabled): (i64, String, String, i64) = {
        let db = app.db();
        db.query_row(
            "SELECT id, role, pass_hash, disabled FROM users WHERE login=?",
            [login_in],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap_or((-1, String::new(), String::new(), 1))
    };
    // hash de référence : réel si compte trouvé, sinon un hash jetable (verify_pw échouera mais consomme
    // un temps comparable — pas de court-circuit révélateur de l'existence du login).
    let reference = if pass_hash.is_empty() {
        "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
    } else {
        pass_hash.clone()
    };
    let ok = verify_pw(password, &reference) && user_id >= 0 && disabled == 0;
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_credentials"}))).into_response();
    }
    let (token, expires) = create_session(&app, user_id);
    let ttl = session_ttl_secs();
    let cookie = format!("forge_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}");
    (
        StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(json!({"token": token, "login": login_in, "role": role, "expires": expires})),
    )
        .into_response()
}

// =====================================================================================
// WIZARD DE 1er DÉPLOIEMENT (self-deploy) — provisionner une install fraîche DEPUIS LE NAVIGATEUR.
//
// Deux routes PUBLIQUES (hors auth_guard, mais sous host_guard anti-rebinding) :
//   - GET  /api/setup/state : sonde d'état (provisioned/needs_setup/capabilities) — le SPA l'appelle
//     au boot pour décider s'il affiche le wizard.
//   - POST /api/setup       : AUTO-DÉSACTIVANTE — provisionne le PREMIER admin puis se ferme (409).
//
// PRINCIPE : ZÉRO défaut codé en dur. Chaque champ optionnel (operator_policy/detection_source/
// session_ttl) n'est persisté QUE s'il est fourni ; absent = rien stocké. La gate d'auth s'engage sur
// l'état DB (recompute_auth_required) dès qu'un admin activé existe.
// =====================================================================================

/// GET /api/setup/state — PUBLIC. `provisioned` = un admin ACTIVÉ existe en base OU un hash d'amorçage
/// env est posé (FORGE_CONSOLE_PASS_HASH). `needs_setup` = !provisioned. `capabilities.sqlcipher` =
/// capacité de chiffrement AU REPOS compilée (`cfg!(feature="encryption")`) — false dans le build par
/// défaut (l'implémentation arrive dans la tranche suivante ; le cfg est câblé dès maintenant). Aucun
/// secret exposé (ni hash, ni token, ni détail de compte).
async fn setup_state(State(app): State<App>) -> impl IntoResponse {
    let provisioned = app.provisioned();
    Json(json!({
        "provisioned": provisioned,
        "needs_setup": !provisioned,
        "capabilities": { "sqlcipher": cfg!(feature = "encryption") },
    }))
}

/// POST /api/setup — PUBLIC mais AUTO-DÉSACTIVANTE : 409 dès que `provisioned()` est vrai. Corps :
///   {admin_login, admin_password, session_ttl?, operator_policy?, detection_source?}
/// Valide le login (validate_login) et exige un mot de passe non vide (parité admin_create_user), hash
/// argon2id (hash_pw), upsert du compte role="admin". `operator_policy`/`detection_source` sont stockés
/// VERBATIM dans `settings` UNIQUEMENT s'ils sont fournis (objets JSON) — sinon rien (aucun défaut).
/// `session_ttl` (entier positif) est persisté comme substrat de config s'il est fourni. Recalcule la
/// gate d'auth (un admin activé existe désormais), ouvre une session (cookie forge_session) pour que le
/// navigateur atterrisse connecté, et ledgerise `console.setup.provision` (attribution = le login admin ;
/// JAMAIS le mot de passe ni le hash).
async fn setup_provision(State(app): State<App>, Json(body): Json<Value>) -> Response {
    // AUTO-DÉSACTIVANTE : une console déjà provisionnée ne peut plus être (re)provisionnée anonymement.
    if app.provisioned() {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "already_provisioned",
                "why": "console déjà provisionnée (un admin activé ou un hash d'amorçage existe) — /api/setup est fermée"
            })),
        )
            .into_response();
    }
    let login = match validate_login(&gs(&body, "admin_login")) {
        Ok(l) => l,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_login", "why": e}))).into_response(),
    };
    let password = gs(&body, "admin_password");
    if password.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_password", "why": "mot de passe vide refusé"}))).into_response();
    }
    // argon2id est coûteux -> hash HORS mutex DB (ne pas geler l'API pendant le KDF).
    let hash = hash_pw(&password);
    let op_set = body.get("operator_policy").map(|v| v.is_object()).unwrap_or(false);
    let det_set = body.get("detection_source").map(|v| v.is_object()).unwrap_or(false);
    let ttl_set = body.get("session_ttl").and_then(|v| v.as_i64()).map(|n| n > 0).unwrap_or(false);

    let user_id: i64 = {
        let db = app.db();
        // course anti-TOCTOU : re-vérifier sous le mutex qu'aucun admin activé n'a surgi entre-temps.
        if db.query_row("SELECT 1 FROM users WHERE role='admin' AND disabled=0 LIMIT 1", [], |_| Ok(())).is_ok() {
            return (StatusCode::CONFLICT, Json(json!({"error": "already_provisioned", "why": "un admin a été provisionné entre-temps"}))).into_response();
        }
        if let Err(e) = upsert_user(&db, &login, "admin", &hash) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "provision_failed", "why": e}))).into_response();
        }
        // settings optionnels — VERBATIM, uniquement si l'appelant les fournit (objets JSON). Un `null`
        // ou tout non-objet est ignoré silencieusement (aucun défaut inventé, cf. principe ZÉRO-défaut).
        if let Some(v) = body.get("operator_policy").filter(|v| v.is_object()) {
            let _ = settings_set(&db, "operator_policy", &v.to_string());
        }
        if let Some(v) = body.get("detection_source").filter(|v| v.is_object()) {
            let _ = settings_set(&db, "detection_source", &v.to_string());
        }
        if let Some(ttl) = body.get("session_ttl").and_then(|v| v.as_i64()).filter(|&n| n > 0) {
            let _ = settings_set(&db, "session_ttl", &ttl.to_string());
        }
        db.query_row("SELECT id FROM users WHERE login=?", [&login], |r| r.get::<_, i64>(0)).unwrap_or(-1)
    };
    if user_id < 0 {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "provision_failed", "why": "compte introuvable après création"}))).into_response();
    }
    // la gate d'auth s'engage : un admin activé existe désormais (état DB fait autorité).
    app.recompute_auth_required();
    // la source de détection a pu être écrite dans settings -> recharge le cache (sinon la couverture
    // resterait sur la config du boot, obsolète). No-op si detection_source n'a pas été fourni.
    if det_set {
        app.reload_detection_source();
    }
    // session immédiate -> le navigateur atterrit connecté en tant que nouvel admin.
    let (token, expires) = create_session(&app, user_id);
    let ttl = session_ttl_secs();
    let cookie = format!("forge_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}");
    // ledger : provision attribuée au nouvel admin. JAMAIS le mot de passe/hash (login + booléens seuls).
    append_console_ledger(&app, "console.setup.provision", json!({
        "actor": login,
        "admin_login": login,
        "operator_policy_set": op_set,
        "detection_source_set": det_set,
        "session_ttl_set": ttl_set,
    }));
    (
        StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(json!({"provisioned": true, "token": token, "login": login, "role": "admin", "expires": expires})),
    )
        .into_response()
}

/// POST /api/setup/migrate — PUBLIC mais PRÉ-PROVISION UNIQUEMENT (409 dès que `provisioned()`).
/// Lance la MÊME migration que la sous-commande CLI depuis une source POINTÉE (chemins serveur), et
/// renvoie le rapport (dont le résultat de vérification du ledger). VOIE MINIMALE : l'UX documentée
/// primaire reste `forge-console migrate` dans un conteneur one-shot ; cet endpoint dépanne le wizard.
/// Corps : {from:<dir|db>, to:<db>, ledger?:<path>, verify?:bool, encrypt?:bool, key_env?:<ENVVAR>}.
/// Le chiffrement exige la feature `encryption` (400 clair sinon). ZÉRO défaut : `from`/`to` requis.
async fn setup_migrate(State(app): State<App>, Json(body): Json<Value>) -> Response {
    // AUTO-DÉSACTIVANTE : un import de données n'a de sens qu'AVANT le 1er provisioning (sinon on
    // écraserait un install déjà en service). Une console provisionnée ferme la route (409).
    if app.provisioned() {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "already_provisioned",
                "why": "console déjà provisionnée — /api/setup/migrate est fermée (import réservé au pré-déploiement)"
            })),
        )
            .into_response();
    }
    // COUCHE 1 — OPT-IN : la migration via API est DÉSACTIVÉE par défaut (CLI-seule). Sans le flag,
    // on refuse AVANT toute I/O -> retire la primitive d'écriture/suppression de fichier non-auth du
    // déploiement par défaut. La voie CLI (`forge-console migrate …`, invocation locale de confiance)
    // reste pleinement fonctionnelle et NON restreinte (ce garde-fou ne touche QUE cet endpoint web).
    if !env_flag_enabled("FORGE_ALLOW_API_MIGRATE") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "api_migrate_disabled",
                "why": "migration via API désactivée — utiliser la CLI `forge-console migrate …` (poser FORGE_ALLOW_API_MIGRATE=1 pour ouvrir l'endpoint web)"
            })),
        )
            .into_response();
    }
    let from = gs(&body, "from");
    let to = gs(&body, "to");
    if from.is_empty() || to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "champs `from` et `to` requis"}))).into_response();
    }
    let ledger = body.get("ledger").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from);
    let encrypt = body.get("encrypt").and_then(|v| v.as_bool()).unwrap_or(false);
    if encrypt && !cfg!(feature = "encryption") {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "encryption_unavailable",
            "why": "chiffrement au repos non compilé (feature `encryption` absente) — recompiler avec --features encryption"
        }))).into_response();
    }
    // COUCHE 2 — le flag est actif : confinement anti-traversal des chemins SOUS la racine allowlistée
    // (racine de données console / $FORGE_CONSOLE_IMPORT_DIR). Rejette `..`, chemins absolus hors base,
    // et l'écrasement d'une cible préexistante hors base. UNIQUEMENT ici (jamais sur la voie CLI).
    if let Err(why) = validate_api_migrate_paths(&from, &to, ledger.as_deref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "path_rejected", "why": why})),
        )
            .into_response();
    }
    let opts = MigrateOpts {
        from,
        to,
        ledger,
        verify: body.get("verify").and_then(|v| v.as_bool()).unwrap_or(false),
        encrypt,
        key_env: body.get("key_env").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from),
        actor: "api:setup/migrate".to_string(),
    };
    // migration = I/O SQLite/FS bloquant -> hors du runtime async (spawn_blocking) pour ne pas geler
    // l'exécuteur. `opts` (Strings/bools) est Send ; la Connection est créée DANS run_migration.
    match tokio::task::spawn_blocking(move || run_migration(&opts)).await {
        Ok(Ok(report)) => (StatusCode::OK, Json(report)).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(json!({"error": "migrate_failed", "why": e}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "migrate_panicked", "why": e.to_string()}))).into_response(),
    }
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

/// Catalogue des modules (lecture partagée par GET /api/modules et le read-back de refresh).
/// Expose la disponibilité SONDÉE (`available`), l'INTENTION opérateur (`enabled`,
/// `available_override`) ET la disponibilité EFFECTIVE dérivée (`effective_available`) pour piloter la
/// table de gouvernance de l'admin. Lecture pure (aucun effet de bord).
fn modules_catalog(db: &Connection) -> Vec<Value> {
    let mut stmt = match db.prepare(
        "SELECT kind,exploit,destructive,available,mitre,descr,web_allowed,enabled,available_override \
         FROM module ORDER BY kind",
    ) { Ok(s) => s, Err(_) => return vec![] };
    stmt.query_map([], |r| {
        let probed = r.get::<_, i64>(3)? != 0;
        let enabled = r.get::<_, i64>(7)? != 0;
        let override_bool: Option<bool> = r.get::<_, Option<i64>>(8)?.map(|v| v != 0);
        Ok(json!({
            "kind": r.get::<_, String>(0)?,
            "exploit": r.get::<_, i64>(1)? != 0,
            "destructive": r.get::<_, i64>(2)? != 0,
            "available": probed,                 // disponibilité SONDÉE (host)
            "mitre": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            "descr": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            "web_allowed": r.get::<_, i64>(6)? != 0,
            "enabled": enabled,                  // intention opérateur : connecteur (dés)installé
            "available_override": match override_bool { Some(b) => Value::Bool(b), None => Value::Null },
            "effective_available": module_effectively_available(enabled, override_bool, probed),
        }))
    })
    .map(|it| it.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Ensemble des kinds DÉSACTIVÉS par l'opérateur (module_operator_disabled) — injecté tel quel dans le
/// `scope.json` du run (`disabled_modules`) pour que le moteur les SKIP, y compris les modules choisis
/// par le PLANNER (au-delà de `--modules`). N'inclut PAS les modules simplement absents de l'hôte (le
/// moteur les SKIP déjà via sa propre sonde, avec la raison « outil absent »). Fail-closed lisible : sur
/// erreur DB -> liste vide (aucune désactivation fabriquée ; l'enforcement retombe sur le filtre argv).
fn operator_disabled_modules(app: &App) -> Vec<String> {
    let db = app.db();
    let mut stmt = match db.prepare("SELECT kind,enabled,available_override FROM module ORDER BY kind") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map([], |r| {
        let kind: String = r.get(0)?;
        let enabled = r.get::<_, i64>(1)? != 0;
        let ov: Option<bool> = r.get::<_, Option<i64>>(2)?.map(|v| v != 0);
        Ok((kind, module_operator_disabled(enabled, ov)))
    })
    .map(|it| it.filter_map(|x| x.ok()).filter(|(_, dis)| *dis).map(|(k, _)| k).collect())
    .unwrap_or_default()
}

/// Filtre une liste de kinds demandés vers le SOUS-ENSEMBLE non désactivé par l'opérateur. Défense en
/// profondeur au spawn : la liste `--modules` passée au moteur EXCLUT tout connecteur désactivé (même si
/// validate_modules l'a déjà refusé en amont, cette barrière garantit qu'un kind désactivé n'atteint
/// JAMAIS l'argv). Testable seul.
fn filter_enabled_modules(app: &App, requested: &[String]) -> Vec<String> {
    let disabled = operator_disabled_modules(app);
    requested.iter().filter(|m| !disabled.contains(m)).cloned().collect()
}

async fn modules(State(app): State<App>) -> impl IntoResponse {
    let db = app.db();
    Json(Value::Array(modules_catalog(&db)))
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

/// Résultat de la recomputation de la chaîne SHA-256 d'un ledger JSONL — PARTAGÉ par le handler
/// GET /api/ledger/verify ET la migration (`migrate --verify`). NE vérifie PAS les signatures
/// (Ed25519/HMAC) : la console n'a pas la clé privée -> seul le hash-chaining est recalculé.
struct LedgerVerify {
    ok: bool,
    entries: usize,
    broken: Value,        // seq de l'entrée rompue (ou Null)
    why: Option<String>,
    head: Option<String>, // hash de tête (Some UNIQUEMENT quand la chaîne est intègre)
    alg: String,
    exists: bool,         // le fichier ledger existe-t-il sur disque ?
    empty: bool,          // 0 entrée exploitable (fichier absent OU toutes lignes malformées)
}

/// Recompute et vérifie la chaîne SHA-256 (prev|seq|ts|kind|canon(detail)) d'un ledger JSONL à `path`.
/// S'arrête à la 1re rupture (prev désaligné ou hash recalculé != stocké). Fonction PURE (I/O lecture
/// seule) : elle est la SEULE source de vérité de la vérif hash-chain, réutilisée par l'API et la
/// migration pour ne jamais dupliquer la logique.
fn verify_ledger_chain(path: &str) -> LedgerVerify {
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
fn ledger_verify_api_json(v: &LedgerVerify, path: &str) -> Value {
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
async fn ledger_verify(State(app): State<App>) -> impl IntoResponse {
    let v = verify_ledger_chain(app.ledger_path.as_str());
    (StatusCode::OK, Json(ledger_verify_api_json(&v, app.ledger_path.as_str())))
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

// ===========================================================================================
// SOURCE DE DÉTECTION CONFIGURABLE (plugin infra-agnostique) — substrat de la boucle purple.
//
// La console ne code plus « Plume » en dur. La SOURCE de détection (SIEM/IDS/pare-feu) est décrite
// par un objet JSON `{kind, endpoint?, auth?:{type,secret}, query?, mapping?}` rangé dans
// `settings.detection_source`. `kind` ∈ {plume, generic_http, crowdsec, fortigate_syslog, pfsense,
// opnsense, file_jsonl, elastic, exec, none} ; `auth.type` ∈ {none, basic, bearer, api_key_header,
// mtls}. Les kinds `plume`/`generic_http` (http) sont interrogés EN RUST (fetcher intégré ci-dessous) ;
// les kinds « messy » (et generic_http en https, pour TLS) sont DÉLÉGUÉS au collecteur Python
// (`forge.cli detections`). Dans TOUS les cas la sortie est normalisée en `[(mitre,count,first_ts)]`
// puis passée à `compute_purple_coverage` (jointure MITRE INCHANGÉE). Échec/mauvaise config =>
// FAIL-OPEN LISIBLE (source_reachable:false), jamais de detected/missed/MTTD inventés.
// ===========================================================================================

/// Résout la config de source de détection : `settings.detection_source` (VERBATIM si objet JSON
/// valide) sinon REPLI rétro-compat sur l'env legacy PLUME_URL/PLUME_TOKEN (implicitement
/// `{kind:plume, endpoint:PLUME_URL, auth:{type:basic,secret:PLUME_TOKEN}}`), sinon `{kind:none}`.
/// Le repli n'a lieu QUE si la clé settings est ABSENTE (une config explicite `{kind:none}` NE
/// retombe PAS sur l'env). Fonction pure vis-à-vis de la DB (lecture seule).
fn resolve_detection_source(db: &Connection) -> Value {
    if let Some(s) = settings_get(db, "detection_source") {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if v.is_object() {
                return v;
            }
        }
    }
    // repli env legacy : uniquement si settings n'a PAS de detection_source lisible.
    let url = std::env::var("PLUME_URL").unwrap_or_default().trim_end_matches('/').to_string();
    let token = std::env::var("PLUME_TOKEN").unwrap_or_default();
    if !url.is_empty() {
        return json!({"kind": "plume", "endpoint": url, "auth": {"type": "basic", "secret": token}});
    }
    json!({"kind": "none"})
}

/// `kind` de la source (défaut "none", trim).
fn ds_kind(cfg: &Value) -> String {
    cfg.get("kind").and_then(|v| v.as_str()).unwrap_or("none").trim().to_string()
}

/// `endpoint` de la source (URL http(s):// ou chemin fichier selon le kind ; défaut vide, trim).
fn ds_endpoint(cfg: &Value) -> String {
    cfg.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
}

/// Type d'auth déclaré (`auth.type`, avec tolérance à la forme plate `auth_type` écrite par le
/// wizard). Défaut "none". NE renvoie JAMAIS le secret — juste le NOM du schéma (pour le ledger/log).
fn ds_auth_type(cfg: &Value) -> String {
    cfg.get("auth").and_then(|a| a.get("type")).and_then(|v| v.as_str())
        .or_else(|| cfg.get("auth_type").and_then(|v| v.as_str()))
        .unwrap_or("none").trim().to_string()
}

/// Secret d'auth (`auth.secret`) — MANIÉ COMME UN SECRET DE SESSION : lu UNIQUEMENT pour construire
/// l'en-tête d'auth du fetch et pour la rédaction ; jamais renvoyé/journalisé/ledgerisé.
fn ds_secret(cfg: &Value) -> String {
    cfg.get("auth").and_then(|a| a.get("secret")).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// Remplace toute occurrence du secret par `[secret rédigé]` dans un message destiné à une réponse/au
/// log/au ledger. Garde-fou défense-en-profondeur (les messages d'erreur n'échoient normalement pas le
/// secret) ; no-op si le secret est vide ou trop court pour être remplacé sans risque de sur-rédaction.
fn redact_secret(msg: &str, secret: &str) -> String {
    if secret.len() < 4 {
        return msg.to_string();
    }
    msg.replace(secret, "[secret rédigé]")
}

/// Liste FERMÉE des `kind` de source de détection acceptés (parité avec le registre du collecteur Python
/// `forge.collectors` + les kinds interrogés en Rust). `none` désactive la mesure (fail-open lisible).
/// Sert de garde-fou d'entrée sur POST /api/detection/source (fail-closed : un kind inconnu est refusé,
/// jamais persisté) et alimente le sélecteur de l'UI admin/wizard.
const DETECTION_KINDS: &[&str] = &[
    "none", "plume", "generic_http", "crowdsec", "elastic", "opensearch",
    "fortigate_syslog", "pfsense", "opnsense", "file_jsonl", "exec",
];

fn is_known_detection_kind(kind: &str) -> bool {
    DETECTION_KINDS.contains(&kind)
}

/// Copie RÉDIGÉE d'une config de source : retire le secret d'auth (`auth.secret`) et tout `secret` posé
/// à plat. Utilisée par GET /api/detection/source et la réponse de POST — le SECRET n'est JAMAIS renvoyé
/// (manié comme un secret de session). Tout le reste (kind/endpoint/auth.type/query/mapping) est conservé
/// pour permettre l'édition côté admin sans jamais re-rendre le secret.
fn redact_detection_config(cfg: &Value) -> Value {
    let mut out = cfg.clone();
    if let Some(m) = out.as_object_mut() {
        m.remove("secret");
        if let Some(auth) = m.get_mut("auth").and_then(|a| a.as_object_mut()) {
            auth.remove("secret");
        }
    }
    out
}

/// Sémantique WRITE-ONLY du secret : si `keep_secret` et que la config entrante ne porte PAS de secret
/// non vide, réinjecte le secret STOCKÉ (config de détection effective courante) dans `auth.secret`.
/// Permet à l'admin d'éditer endpoint/mapping — ou de TESTER la source — SANS re-saisir le secret (jamais
/// rendu côté UI : affiché ••• une fois posé). No-op si aucun secret n'est déjà stocké, ou si l'appelant
/// fournit un nouveau secret non vide (celui-ci prime alors).
fn apply_kept_secret(app: &App, cfg: &Value, keep_secret: bool) -> Value {
    let mut out = cfg.clone();
    if keep_secret && ds_secret(cfg).is_empty() {
        let stored = ds_secret(&app.detection_config());
        if !stored.is_empty() {
            let atype = ds_auth_type(cfg);
            if let Some(m) = out.as_object_mut() {
                let auth = m.entry("auth").or_insert_with(|| json!({}));
                if !auth.is_object() {
                    *auth = json!({});
                }
                if let Some(am) = auth.as_object_mut() {
                    am.entry("type").or_insert_with(|| json!(atype));
                    am.insert("secret".into(), json!(stored));
                }
            }
        }
    }
    out
}

/// Schéma d'authentification HTTP du fetcher intégré. `mtls` n'est PAS ici (le client TCP brut ne fait
/// pas de TLS — un endpoint mTLS passe par un kind délégué au collecteur Python).
enum HttpAuth {
    None,
    Basic(String),                         // base64 de user:pass -> `Authorization: Basic ...`
    Bearer(String),                        // token -> `Authorization: Bearer ...`
    ApiKeyHeader { name: String, value: String }, // en-tête d'API arbitraire (ex: X-API-Key: ...)
}

/// Construit l'`HttpAuth` du fetcher intégré depuis la config source. `basic`/`bearer` prennent
/// `auth.secret` ; `api_key_header` prend `auth.header` (défaut `X-API-Key`) + `auth.secret`. `none`,
/// `mtls` ou un type inconnu => aucun en-tête (le TLS/mTLS relève d'un kind délégué au Python).
fn parse_http_auth(cfg: &Value) -> HttpAuth {
    let auth = cfg.get("auth");
    let atype = ds_auth_type(cfg);
    let secret = ds_secret(cfg);
    match atype.as_str() {
        "basic" => HttpAuth::Basic(secret),
        "bearer" => HttpAuth::Bearer(secret),
        "api_key_header" => {
            let name = auth.and_then(|a| a.get("header")).and_then(|v| v.as_str())
                .unwrap_or("X-API-Key").to_string();
            HttpAuth::ApiKeyHeader { name, value: secret }
        }
        _ => HttpAuth::None,
    }
}

/// GET HTTP/1.1 minimal et BLOQUANT (lancé via spawn_blocking) — pas de dépendance HTTP lourde.
/// Ne gère QUE `http://host[:port]/path` (le service bind en HTTP clair, derrière Traefik/forward-auth
/// en prod ; pour TLS, viser un endpoint interne http:// OU un kind délégué au collecteur Python).
/// `auth` porte le schéma d'authentification (none/basic/bearer/api_key_header). `allow_https` : si
/// faux (kind=plume, rétro-compat EXACTE) une URL https:// est refusée avec le message historique ;
/// si vrai (generic_http) une URL https:// est refusée avec un message d'aiguillage (TLS non géré
/// nativement) — le chemin generic_http+https est de toute façon délégué au Python en amont. Renvoie
/// le corps (string) en cas de 200, sinon Err. Timeout dur (connect + lecture).
fn http_get_blocking(url: &str, auth: &HttpAuth, timeout: Duration, allow_https: bool) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let rest = if let Some(r) = url.strip_prefix("http://") {
        r
    } else if url.strip_prefix("https://").is_some() {
        return Err(if allow_https {
            "HTTPS non géré nativement par le fetcher intégré — viser un endpoint http:// interne, \
             ou un kind délégué au collecteur Python (elastic/exec) pour le TLS".to_string()
        } else {
            "PLUME_URL doit commencer par http:// (TLS non géré côté console — utiliser un endpoint interne)".to_string()
        });
    } else {
        return Err("l'endpoint doit commencer par http:// (ou https:// pour un kind délégué)".to_string());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = authority.split(':').next().unwrap_or(authority);
    let port: u16 = authority.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(80);
    // résolution + connexion avec timeout (évite un blocage si la source est down).
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
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: forge-console-detection\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    // En-tête d'auth selon le schéma. Un secret/valeur vide => aucun en-tête (cas anonyme, ex.
    // SOC_PUBLIC_DEMO). Anti-injection d'en-tête : on refuse toute valeur portant CR/LF.
    let no_crlf = |s: &str| !s.contains('\r') && !s.contains('\n');
    match auth {
        HttpAuth::None => {}
        HttpAuth::Basic(b) if !b.is_empty() && no_crlf(b) => req.push_str(&format!("Authorization: Basic {b}\r\n")),
        HttpAuth::Bearer(t) if !t.is_empty() && no_crlf(t) => req.push_str(&format!("Authorization: Bearer {t}\r\n")),
        HttpAuth::ApiKeyHeader { name, value }
            if !name.is_empty() && !value.is_empty() && no_crlf(name) && no_crlf(value) =>
        {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        _ => {}
    }
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

/// Construit l'objet de FAIL-OPEN LISIBLE (source_reachable/plume_reachable:false) : compte les
/// techniques tirées (pour information) mais NE FABRIQUE PAS de detected/missed/MTTD. Réutilisé par
/// tous les chemins où la mesure n'a pas pu se faire (source absente/injoignable/illisible, lecture DB
/// échouée). `plume_reachable`/`plume_url` sont conservés (rétro-compat du SPA et du rapport qui les
/// lisent) et MIROITÉS en `source_reachable`/`source_url` (nommage neutre infra-agnostique). `url` ne
/// contient JAMAIS le secret (endpoint seul). `reason` a déjà été rédigé par l'appelant.
fn purple_fail_open(url: &str, fired: &[(String, Option<i64>)], reason: &str) -> Value {
    let n_fired = fired
        .iter()
        .filter(|(m, _)| !m.is_empty())
        .map(|(m, _)| m.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as i64;
    json!({
        "plume_reachable": false,
        "source_reachable": false,
        "plume_url": url,
        "source_url": url,
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

/// Accès à une valeur JSON par CHEMIN POINTÉ ("a.b.c") ; None si un segment manque. Un chemin vide
/// renvoie la valeur racine. Sert au `mapping` des sources generic_http (champ natif -> mitre/ts/count).
fn json_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        if seg.is_empty() {
            continue;
        }
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Valeur au chemin pointé rendue en String (string telle quelle, sinon repr scalaire, sinon vide).
fn json_path_str(v: &Value, path: &str) -> String {
    match json_path(v, path) {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.as_str().map(str::to_string).unwrap_or_default(),
        None => String::new(),
    }
}

/// Valeur au chemin pointé rendue en i64 (int, sinon f64 tronqué, sinon parse d'une string ; None si
/// absent/illisible).
fn json_path_i64(v: &Value, path: &str) -> Option<i64> {
    let n = json_path(v, path)?;
    n.as_i64()
        .or_else(|| n.as_f64().map(|f| f as i64))
        .or_else(|| n.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
}

/// Mapping IDENTITÉ de la réponse Plume `{detections:[{mitre,count,first_ts}]}` -> `[(mitre,count,ts)]`.
/// Réutilisé aussi pour la sortie NORMALISÉE du collecteur Python (même contrat de sortie).
fn parse_plume_detections(parsed: &Value) -> Vec<(String, i64, i64)> {
    let mut out = Vec::new();
    if let Some(arr) = parsed.get("detections").and_then(|v| v.as_array()) {
        for d in arr {
            let mitre = d.get("mitre").and_then(|v| v.as_str()).unwrap_or("");
            if mitre.is_empty() {
                continue;
            }
            let count = d.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            let first_ts = d.get("first_ts").and_then(|v| v.as_i64()).unwrap_or(0);
            out.push((mitre.to_string(), count, first_ts));
        }
    }
    out
}

/// Applique le `mapping` d'une source generic_http à une réponse arbitraire -> `[(mitre,count,ts)]`.
/// `mapping` : `{records?: "chemin.vers.tableau", mitre?: "champ", ts?: "champ", count?: "champ"}`.
/// - `records` localise le tableau d'enregistrements (défaut : tableau racine, sinon champ `detections`
///   / `results`) ;
/// - chaque enregistrement fournit `mitre` (défaut champ "mitre"), `ts` (défaut "first_ts"), et un
///   `count` OPTIONNEL (si absent chaque enregistrement compte 1) ;
/// - agrégation par mitre : count sommé, first_ts = min. Aucune fabrication : un tableau introuvable
///   ou vide -> Err / vec vide (l'appelant bascule alors en fail-open).
fn map_detections(parsed: &Value, mapping: Option<&Value>) -> Result<Vec<(String, i64, i64)>, String> {
    let default_map = json!({});
    let m = mapping.unwrap_or(&default_map);
    let records_path = m.get("records").and_then(|v| v.as_str()).unwrap_or("");
    let mitre_field = m.get("mitre").and_then(|v| v.as_str()).unwrap_or("mitre");
    let ts_field = m.get("ts").and_then(|v| v.as_str()).unwrap_or("first_ts");
    let count_field = m.get("count").and_then(|v| v.as_str());

    let arr: Vec<Value> = if !records_path.is_empty() {
        json_path(parsed, records_path)
            .and_then(|v| v.as_array().cloned())
            .ok_or_else(|| format!("aucun tableau de détections au chemin '{records_path}'"))?
    } else {
        parsed
            .as_array()
            .cloned()
            .or_else(|| parsed.get("detections").and_then(|v| v.as_array()).cloned())
            .or_else(|| parsed.get("results").and_then(|v| v.as_array()).cloned())
            .ok_or_else(|| "aucun tableau de détections (records/detections/results absents)".to_string())?
    };

    // agrégation par mitre : (count sommé, first_ts min).
    let mut agg: std::collections::BTreeMap<String, (i64, i64)> = std::collections::BTreeMap::new();
    for rec in &arr {
        let mitre = json_path_str(rec, mitre_field);
        if mitre.is_empty() {
            continue;
        }
        let ts = json_path_i64(rec, ts_field).unwrap_or(0);
        let c = match count_field {
            Some(cf) => json_path_i64(rec, cf).unwrap_or(1),
            None => 1,
        };
        let e = agg.entry(mitre).or_insert((0, ts));
        e.0 += c;
        if ts < e.1 {
            e.1 = ts;
        }
    }
    Ok(agg.into_iter().map(|(k, (c, t))| (k, c, t)).collect())
}

/// Construit l'URL d'une source generic_http : endpoint + `query` optionnelle (string, `{since}`
/// substitué), jointe par '?' si l'endpoint n'a pas de query-string, sinon '&'.
fn generic_http_url(endpoint: &str, query: Option<&Value>, since: i64) -> String {
    match query.and_then(|v| v.as_str()).filter(|q| !q.is_empty()) {
        Some(q) => {
            let q = q.replace("{since}", &since.to_string());
            let q = q.trim_start_matches(['?', '&']);
            let sep = if endpoint.contains('?') { '&' } else { '?' };
            format!("{endpoint}{sep}{q}")
        }
        None => endpoint.to_string(),
    }
}

/// Fetch + normalisation EN RUST d'une source http (`plume` ou `generic_http` en clair). `is_plume` :
/// URL = `{endpoint}/api/coverage/detections?since=N` + mapping IDENTITÉ + http-only (rétro-compat
/// EXACTE) ; sinon URL = endpoint + `query`, mapping configuré, https autorisé (aiguillé au Python en
/// amont). BLOQUANT (à lancer via spawn_blocking).
fn rust_http_collect(cfg: &Value, since: i64, is_plume: bool) -> Result<Vec<(String, i64, i64)>, String> {
    let endpoint = ds_endpoint(cfg);
    if endpoint.is_empty() {
        return Err("endpoint de la source de détection non configuré".to_string());
    }
    let auth = parse_http_auth(cfg);
    let timeout = Duration::from_secs(8);
    let url = if is_plume {
        format!("{}/api/coverage/detections?since={}", endpoint.trim_end_matches('/'), since)
    } else {
        generic_http_url(&endpoint, cfg.get("query"), since)
    };
    let body = http_get_blocking(&url, &auth, timeout, !is_plume)?;
    let parsed: Value = serde_json::from_str(body.trim())
        .map_err(|e| format!("réponse illisible (JSON invalide): {e}"))?;
    if is_plume {
        Ok(parse_plume_detections(&parsed))
    } else {
        map_detections(&parsed, cfg.get("mapping"))
    }
}

/// Délègue la collecte au COLLECTEUR PYTHON pour les kinds « messy » (crowdsec/fortigate_syslog/
/// pfsense/opnsense/file_jsonl/elastic/exec, et generic_http en https pour le TLS). Même patron de
/// spawn no-shell que populate_modules (`python3 -m forge.cli detections --since N --source ...`).
/// La config (AVEC secret) est passée par ENV `FORGE_DETECTION_SOURCE` (jamais en argv -> pas de fuite
/// via `ps`/cmdline, cf. le token console de run_create) ; l'argv ne porte que `--source env:...`. Le
/// collecteur émet `{detections:[{mitre,count,first_ts}]}` sur stdout. Toute erreur -> Err (fail-open),
/// le stderr éventuel étant RÉDIGÉ du secret avant de remonter.
async fn collect_via_python(app: &App, cfg: &Value, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    let py = app.python.as_str().to_string();
    let pkg_dir = app.pkg_dir.as_str().to_string();
    let source_json = cfg.to_string();
    let secret = ds_secret(cfg);
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new(&py)
            .args([
                "-m", "forge.cli", "detections",
                "--since", &since.to_string(),
                "--source", "env:FORGE_DETECTION_SOURCE",
            ])
            .current_dir(&pkg_dir)
            .env("FORGE_DETECTION_SOURCE", &source_json)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("collecteur Python injoignable: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = redact_secret(err.trim(), &secret);
            let err: String = err.chars().take(240).collect();
            return Err(format!("collecteur Python a échoué (code {:?}): {err}", out.status.code()));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let parsed: Value = serde_json::from_str(stdout.trim())
            .map_err(|e| format!("sortie du collecteur illisible (JSON invalide): {e}"))?;
        Ok(parse_plume_detections(&parsed))
    })
    .await
    .unwrap_or_else(|e| Err(format!("tâche collecteur interrompue: {e}")))
}

/// AIGUILLAGE central : collecte les détections de la source CONFIGURÉE (cache App) -> `[(mitre,count,
/// first_ts)]`. Voir `collect_detections_with` pour la logique de dispatch sur `kind`.
async fn collect_detections(app: &App, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    let cfg = app.detection_config();
    collect_detections_with(app, &cfg, since).await
}

/// Dispatch sur `kind` d'une config source DONNÉE (utilisé aussi par POST /api/detection/test pour
/// tester une config fournie sans la persister). `plume`/`generic_http`(http) -> fetch Rust ;
/// generic_http(https) + kinds messy -> collecteur Python. Résultat -> jointure MITRE INCHANGÉE.
async fn collect_detections_with(app: &App, cfg: &Value, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    match ds_kind(cfg).as_str() {
        "none" | "" => {
            Err("source de détection non configurée (kind=none) — couverture indisponible".to_string())
        }
        kind @ ("plume" | "generic_http") => {
            let is_plume = kind == "plume";
            // generic_http en https -> délégué au Python (TLS non géré par le fetcher intégré).
            if !is_plume && ds_endpoint(cfg).starts_with("https://") {
                return collect_via_python(app, cfg, since).await;
            }
            let cfg_owned = cfg.clone();
            tokio::task::spawn_blocking(move || rust_http_collect(&cfg_owned, since, is_plume))
                .await
                .unwrap_or_else(|e| Err(format!("tâche HTTP interrompue: {e}")))
        }
        "crowdsec" | "fortigate_syslog" | "pfsense" | "opnsense" | "file_jsonl" | "elastic" | "exec" => {
            collect_via_python(app, cfg, since).await
        }
        other => Err(format!("kind de source de détection inconnu: {other}")),
    }
}

/// Interroge la SOURCE DE DÉTECTION configurée et corrèle avec les techniques `fired` -> objet de
/// couverture complet. FAIL-OPEN LISIBLE à chaque étape qui peut échouer (source absente/injoignable/
/// illisible) : `source_reachable`/`plume_reachable:false` + raison RÉDIGÉE, JAMAIS de detected/missed/
/// MTTD inventés. La jointure MITRE (compute_purple_coverage) est INCHANGÉE quel que soit le `kind`.
/// Réutilisé par l'endpoint /api/purple/coverage (alias /api/detection/coverage) ET la section purple
/// du rapport de run. `endpoint`/`source_url` exposés pour la traçabilité NE contiennent jamais le secret.
async fn fetch_purple_coverage(app: &App, fired: Vec<(String, Option<i64>)>) -> Value {
    let cfg = app.detection_config();
    let disp = ds_endpoint(&cfg); // endpoint seul (jamais le secret) pour la traçabilité
    let kind = ds_kind(&cfg);
    // AUTONOME (standalone) vs source configurée : une source EST configurée si `kind` n'est ni none/vide
    // ni un kind http (plume/generic_http) sans endpoint (parité EXACTE avec le log de boot). Ce booléen
    // permet au SPA de distinguer « aucune source configurée — Forge en autonome » (état NORMAL, attendu)
    // de « source configurée mais INJOIGNABLE » (anomalie à signaler). Aucun des deux n'invente de métrique.
    let http_kind = kind == "plume" || kind == "generic_http";
    let source_configured = !(kind == "none" || kind.is_empty() || (http_kind && disp.is_empty()));
    // `since` = plus ancien tir red (borne la fenêtre côté source) ; 0 si aucun tir horodaté lisible.
    let since = fired.iter().filter_map(|(_, t)| *t).min().unwrap_or(0);
    match collect_detections(app, since).await {
        Ok(dets) => {
            let mut detections: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
            for (mitre, count, first_ts) in dets {
                if mitre.is_empty() {
                    continue;
                }
                // dernière occurrence prime (agrégée en amont) ; contrat identique à l'ancien parse.
                detections.insert(mitre, (count, first_ts));
            }
            // corrélation pure -> réponse. reachable:true (la mesure a bien eu lieu).
            let mut cov = compute_purple_coverage(&fired, &detections);
            if let Value::Object(ref mut m) = cov {
                m.insert("plume_reachable".into(), json!(true));
                m.insert("source_reachable".into(), json!(true));
                m.insert("plume_url".into(), json!(disp));
                m.insert("source_url".into(), json!(disp));
                m.insert("source_kind".into(), json!(kind));
                m.insert("source_configured".into(), json!(true));
            }
            cov
        }
        // fail-open lisible ; la raison est rédigée du secret (défense en profondeur). On y JOINT le
        // `kind` et `source_configured` pour que le SPA/rapport rende l'état AUTONOME (source absente,
        // normal) distinctement d'une source configurée mais injoignable (anomalie).
        Err(e) => {
            let mut fo = purple_fail_open(&disp, &fired, &redact_secret(&e, &ds_secret(&cfg)));
            if let Value::Object(ref mut m) = fo {
                m.insert("source_kind".into(), json!(kind));
                m.insert("source_configured".into(), json!(source_configured));
            }
            fo
        }
    }
}

/// GET /api/detection/coverage[?campaign=X] (alias rétro-compat /api/purple/coverage) — couverture de
/// DÉTECTION (purple-team défensif). Joint runrecord[fired=1] (techniques tirées en red-team Forge)
/// avec les détections de la SOURCE configurée (kind=plume/generic_http/crowdsec/…). Réponse :
///   {
///     "source_reachable": bool,        // (miroir rétro-compat: plume_reachable) false => FAIL-OPEN lisible
///     "source_configured": bool,       // false => AUCUNE source configurée (Forge AUTONOME/standalone) ;
///                                       //   true + source_reachable:false => source posée mais injoignable
///     "source_url": "...",             // (miroir: plume_url) endpoint pour traçabilité — JAMAIS le secret
///     "source_kind": "...",            // kind de la source (none en autonome)
///     "techniques_fired|detected|missed": i64,
///     "detection_rate": f64,           // [0,1]
///     "mttd_avg_secs"|"mttd_max_secs": f64|i64|null,
///     "detected": [ {mitre, fires, alert_count, first_detection_ts, fire_ts, mttd_secs} ],
///     "missed":   [ {mitre, fires, fire_ts} ],
///     ("error": "...")                 // présent UNIQUEMENT si source_reachable=false (raison lisible)
///   }
/// Si source_reachable=false : detected/missed=[], compteurs/MTTD nuls — jamais de faux détecté/raté.
async fn purple_coverage(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // côté RED : techniques tirées (fired=1) + horodatage du tir, filtrées par campaign optionnelle.
    let fired = read_fired_techniques(&app, q.get("campaign").map(|c| ("campaign", c.as_str())));
    (StatusCode::OK, Json(fetch_purple_coverage(&app, fired).await))
}

/// POST /api/detection/test — ADMIN (check_admin, fail-closed 403). Exécute collect_detections UNE
/// fois contre une config FOURNIE (`{detection_source:{...}}` ou l'objet config à plat dans le corps)
/// ou, à défaut, la config STOCKÉE. Renvoie `{reachable, count, sample_mitres, error?}` — le SECRET
/// n'est JAMAIS renvoyé. Ledgerise `console.detection.test` (actor + kind + endpoint + auth_type +
/// reachable + count ; JAMAIS le secret). LECTURE seule côté source (ne persiste pas la config testée).
async fn detection_test(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    // WRITE-ONLY : `keep_secret` permet de tester une config éditée SANS re-saisir le secret déjà posé
    // (le secret write-only n'est jamais rendu par GET). apply_kept_secret réinjecte alors le secret stocké.
    let keep = body.get("keep_secret").and_then(|v| v.as_bool()).unwrap_or(false);
    // config à tester : {detection_source:{...}} > objet-config à plat ({kind:...}) > config stockée.
    let cfg: Arc<Value> = if let Some(v) = body.get("detection_source").filter(|v| v.is_object()) {
        Arc::new(apply_kept_secret(&app, v, keep))
    } else if body.is_object() && body.get("kind").is_some() {
        Arc::new(apply_kept_secret(&app, &body, keep))
    } else {
        app.detection_config()
    };
    let secret = ds_secret(&cfg);
    let kind = ds_kind(&cfg);
    // since=0 : test « prends tout » (le but est de vérifier la joignabilité, pas une fenêtre précise).
    let result = collect_detections_with(&app, &cfg, 0).await;
    let (reachable, count, samples, error) = match result {
        Ok(dets) => {
            let count = dets.len() as i64;
            // échantillon de mitres DISTINCTS (max 8) — aide au diagnostic sans divulguer de secret.
            let mut seen = std::collections::BTreeSet::new();
            let mut samples: Vec<String> = Vec::new();
            for (m, _, _) in &dets {
                if seen.insert(m.clone()) {
                    samples.push(m.clone());
                }
                if samples.len() >= 8 {
                    break;
                }
            }
            (true, count, samples, None)
        }
        Err(e) => (false, 0i64, Vec::new(), Some(redact_secret(&e, &secret))),
    };
    // AUDIT : trace du test. JAMAIS le secret (endpoint + type d'auth seuls).
    append_console_ledger(&app, "console.detection.test", json!({
        "actor": actor,
        "kind": kind,
        "endpoint": ds_endpoint(&cfg),
        "auth_type": ds_auth_type(&cfg),
        "reachable": reachable,
        "count": count,
    }));
    let mut out = json!({
        "reachable": reachable,
        "count": count,
        "sample_mitres": samples,
    });
    if let (Value::Object(ref mut m), Some(e)) = (&mut out, error) {
        m.insert("error".into(), json!(e));
    }
    (StatusCode::OK, Json(out)).into_response()
}

/// GET /api/detection/source — ADMIN (check_admin, fail-closed 403). Renvoie la config de source de
/// détection EFFECTIVE (settings.detection_source sinon repli env legacy PLUME_URL/PLUME_TOKEN), le
/// SECRET RETIRÉ (jamais renvoyé — manié comme un secret de session), plus `secret_set` (un secret
/// est-il posé ?) et la liste FERMÉE des kinds. L'UI admin/wizard édite cette config ; le secret
/// write-only s'affiche ••• (secret_set) et n'est jamais re-rendu au client.
async fn detection_source_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let cfg = app.detection_config();
    let secret_set = !ds_secret(&cfg).is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "source": redact_detection_config(&cfg),
            "secret_set": secret_set,
            "kinds": DETECTION_KINDS,
        })),
    )
        .into_response()
}

/// POST /api/detection/source — ADMIN (check_admin, fail-closed 403). Persiste `settings.detection_source`
/// (config VERBATIM) puis recharge le cache (la couverture utilise immédiatement la nouvelle source).
/// Corps : `{detection_source:{...}}` OU l'objet-config à plat (`{kind,...}`), + `keep_secret?:bool`
/// (write-only : conserver le secret déjà posé sans le re-saisir). `kind` est validé contre la liste
/// FERMÉE (fail-closed, jamais persisté sinon). Ledgerise `console.detection.source.set` (actor + kind +
/// endpoint + auth_type — JAMAIS le secret). Réponse = config RÉDIGÉE + secret_set (le secret n'y est jamais).
async fn detection_source_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    // config entrante : {detection_source:{...}} > objet-config à plat ({kind:...}). Les clés de contrôle
    // (keep_secret) sont retirées de la config à plat pour ne pas polluer ce qui est persisté.
    let incoming: Value = if let Some(v) = body.get("detection_source").filter(|v| v.is_object()) {
        v.clone()
    } else if body.is_object() && body.get("kind").is_some() {
        let mut c = body.clone();
        if let Some(m) = c.as_object_mut() {
            m.remove("keep_secret");
        }
        c
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "bad_request", "why": "corps attendu : {detection_source:{kind,...}} ou {kind,...}"})),
        )
            .into_response();
    };
    let kind = ds_kind(&incoming);
    if !is_known_detection_kind(&kind) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "bad_kind", "why": format!("kind de source inconnu : {kind}")})),
        )
            .into_response();
    }
    // WRITE-ONLY : si keep_secret et aucun nouveau secret fourni, réinjecte le secret déjà posé.
    let keep = body.get("keep_secret").and_then(|v| v.as_bool()).unwrap_or(false);
    let cfg = apply_kept_secret(&app, &incoming, keep);
    {
        let db = app.db();
        if let Err(e) = settings_set(&db, "detection_source", &cfg.to_string()) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "settings_write_failed", "why": e})),
            )
                .into_response();
        }
    }
    // recharge le cache -> /api/detection/coverage bascule immédiatement sur la nouvelle source.
    app.reload_detection_source();
    // AUDIT : mutation d'administration attribuée + ledgerisée. JAMAIS le secret (endpoint + type seuls).
    append_console_ledger(&app, "console.detection.source.set", json!({
        "actor": actor,
        "kind": kind,
        "endpoint": ds_endpoint(&cfg),
        "auth_type": ds_auth_type(&cfg),
    }));
    let secret_set = !ds_secret(&cfg).is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "source": redact_detection_config(&cfg),
            "secret_set": secret_set,
            "saved": true,
        })),
    )
        .into_response()
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

// =====================================================================================
// SÉLECTION DE TECHNIQUES PAR-SCOPE (profil + toggles catégorie/technique) — « au scope retirer des
// tests automatiques des techniques/outils ». La console persiste l'INTENTION (settings
// `technique_selection`) ; le MOTEUR l'ENFORCE (forge.techniques.resolve_enabled_kinds — SOURCE UNIQUE :
// profil ∪ activations − désactivations, DÉRIVÉ de la table, sans câblage par-technique). GET
// /api/techniques rend le catalogue GROUPÉ PAR CATÉGORIE avec l'état activé du scope ; POST
// /api/techniques/selection définit la sélection (opérateur/admin, ledgerisé).
// =====================================================================================

/// Sélection par défaut : profil bug_bounty (liste qualifiante) + aucun toggle. C'est le défaut
/// documenté quand `settings.technique_selection` est absent/illisible (jamais de valeur inventée
/// au-delà de ce défaut). Forme : {profile, categories:{cat:bool}, techniques:{kind:bool}}.
fn default_technique_selection() -> Value {
    json!({"profile": "bug_bounty", "categories": {}, "techniques": {}})
}

/// Lit la sélection persistée (`settings.technique_selection`). Fail-soft : absente/illisible/non-objet
/// -> défaut. Ne verrouille que le mutex DB (ne pas appeler en tenant déjà `self.db()`).
fn technique_selection_value(app: &App) -> Value {
    let raw = { let db = app.db(); settings_get(&db, "technique_selection") };
    match raw.as_deref().map(serde_json::from_str::<Value>) {
        Some(Ok(v)) if v.is_object() => v,
        _ => default_technique_selection(),
    }
}

/// Valide/normalise une sélection POSTée : {profile?, categories?:{str:bool}, techniques?:{str:bool}}.
/// `profile` ∈ {bug_bounty,pentest,custom} (défaut bug_bounty). Les clés de toggle sont des noms bien
/// formés (grammaire [A-Za-z0-9._-], 1..64), les valeurs des booléens, la map bornée (≤256). Les clés
/// INCONNUES du registre sont TOLÉRÉES : le résolveur moteur les ignore (catégorie inconnue -> vide,
/// technique inconnue -> filtrée par ∩ technique_kinds) — jamais une capacité fabriquée. Fonction PURE.
fn validate_technique_selection(body: &Value) -> Result<Value, String> {
    if !body.is_object() {
        return Err("corps attendu : objet {profile?, categories?, techniques?}".into());
    }
    let profile = match body.get("profile") {
        None | Some(Value::Null) => "bug_bounty".to_string(),
        Some(Value::String(s)) => {
            if !matches!(s.as_str(), "bug_bounty" | "pentest" | "custom") {
                return Err(format!("profile '{s}' invalide (bug_bounty|pentest|custom)"));
            }
            s.clone()
        }
        Some(_) => return Err("profile doit être une chaîne".into()),
    };
    fn toggles(body: &Value, key: &str) -> Result<Value, String> {
        match body.get(key) {
            None | Some(Value::Null) => Ok(Value::Object(serde_json::Map::new())),
            Some(Value::Object(m)) => {
                if m.len() > 256 {
                    return Err(format!("{key} trop volumineux (>256 clés)"));
                }
                let mut o = serde_json::Map::new();
                for (k, v) in m {
                    if k.is_empty() || k.len() > 64
                        || !k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                    {
                        return Err(format!("{key} : clé '{k}' mal formée ([A-Za-z0-9._-], 1..64)"));
                    }
                    match v {
                        Value::Bool(b) => { o.insert(k.clone(), Value::Bool(*b)); }
                        _ => return Err(format!("{key} : la valeur de '{k}' doit être un booléen")),
                    }
                }
                Ok(Value::Object(o))
            }
            Some(_) => Err(format!("{key} doit être un objet {{clé: bool}}")),
        }
    }
    let mut out = serde_json::Map::new();
    out.insert("profile".into(), Value::String(profile));
    out.insert("categories".into(), toggles(body, "categories")?);
    out.insert("techniques".into(), toggles(body, "techniques")?);
    Ok(Value::Object(out))
}

/// Spawne `forge.cli techniques --json`, sélection injectée par env `FORGE_TECHNIQUE_SELECTION` (jamais
/// en argv — cohérent avec le passthrough sûr du reste). DÉRIVÉ du registre côté moteur (SOURCE UNIQUE :
/// groupement par catégorie + `enabled_for_current_scope` via resolve_enabled_kinds). Renvoie le
/// catalogue JSON parsé, ou une erreur lisible (moteur indisponible / JSON illisible).
fn spawn_techniques_catalog(app: &App, selection: &Value) -> Result<Value, String> {
    let out = std::process::Command::new(app.python.as_str())
        .args(["-m", "forge.cli", "techniques", "--json"])
        .current_dir(app.pkg_dir.as_str())
        .env("FORGE_TECHNIQUE_SELECTION", selection.to_string())
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn échoué: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "moteur techniques rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).chars().take(200).collect::<String>()
        ));
    }
    serde_json::from_slice::<Value>(&out.stdout).map_err(|e| format!("JSON illisible: {e}"))
}

/// GET /api/techniques — LE catalogue des techniques GROUPÉ PAR CATÉGORIE (vuln_class), reflétant l'état
/// ACTIVÉ pour la sélection par-scope PERSISTÉE (profil + toggles). Chaque entrée porte `kind`, `tools`,
/// `bug_bounty_eligible`, `pentest_only`, `enabled_for_current_scope`. Lecture (viewer) — la sélection
/// est visible de tous ; seule sa MUTATION est gouvernée (POST /api/techniques/selection). DÉRIVÉ du
/// registre côté moteur : un nouveau module @register apparaît AUTOMATIQUEMENT sous sa catégorie.
async fn techniques_catalog(State(app): State<App>) -> Response {
    let sel = technique_selection_value(&app);
    match spawn_techniques_catalog(&app, &sel) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        // fail-soft LISIBLE : le SPA affiche encore le sélecteur de profil même si le moteur est absent.
        Err(e) => (StatusCode::OK, Json(json!({
            "error": "techniques_unavailable", "why": e,
            "profile": sel.get("profile").cloned().unwrap_or(json!("bug_bounty")),
            "profiles": ["bug_bounty", "pentest", "custom"],
            "selection": sel, "enabled": [], "groups": {},
        }))).into_response(),
    }
}

/// POST /api/techniques/selection — définit la SÉLECTION de techniques par-scope (profil + toggles
/// catégorie/technique). OPÉRATEUR/ADMIN (check_operator, FAIL-CLOSED 403 sinon) + LEDGERISÉ
/// (`console.techniques.selection.set`, attribué à l'acteur individuel). Persiste
/// `settings.technique_selection` — l'intention est ensuite ENFORCÉE par le moteur à chaque run
/// (scope.json profile/techniques_enabled/categories_enabled -> resolve_enabled_kinds) : une technique
/// retirée n'est NI planifiée NI tirée (fail-closed), en plus du scope-guard.
async fn technique_selection_set(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    let sel = match validate_technique_selection(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_selection", "why": e}))).into_response(),
    };
    {
        let db = app.db();
        if let Err(e) = settings_set(&db, "technique_selection", &sel.to_string()) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "persist_failed", "why": e}))).into_response();
        }
    }
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.techniques.selection.set", json!({
        "actor": actor, "by": "operator", "selection": sel,
    }));
    (StatusCode::OK, Json(json!({"ok": true, "selection": sel}))).into_response()
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
async fn modules_refresh(State(app): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> impl IntoResponse {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j);
    }
    {
        let db = app.db();
        populate_modules(&db); // re-spawn `forge.cli modules --json` + UPSERT dans `module`
    }
    // relit le catalogue pour le renvoyer (transparence : l'opérateur voit l'état post-refresh —
    // l'intention `enabled`/`available_override` est PRÉSERVÉE par le re-probe, cf. populate_modules).
    let db = app.db();
    let mods = modules_catalog(&db);
    (StatusCode::OK, Json(json!({"refreshed": mods.len(), "modules": mods})))
}

/// GET /api/runs/:id/report — rend en markdown un rapport d'engagement pour CE run, à partir des
/// données stockées côté console (run_job + findings + roe_decision pour le run_id). Miroir Rust de
/// `forge.report.build_report` (synthèse, findings, transparence ROE). LECTURE (viewer).
/// 404 si le run_id est inconnu de run_job.
async fn run_report(State(app): State<App>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    // format : md (DÉFAUT — rétro-compat), html (livrable client brandé), pdf (si outil dispo).
    let format = q.get("format").map(|s| s.as_str()).unwrap_or("md");
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
    // annexe chaîne-de-custody : intégrité du ledger + attribution (started_by résolu du run).
    let started_by = job.get("started_by").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let custody = build_ledger_custody(&app, &started_by);

    match format {
        "html" => {
            let html = {
                let db = app.db();
                render_run_report_html(&db, &id, &job, Some(&purple), &custody)
            };
            ([("content-type", "text/html; charset=utf-8")], Html(html)).into_response()
        }
        "pdf" => {
            // PDF : depuis le HTML brandé, via un outil système SI présent (pas de dep lourde ajoutée).
            let html = {
                let db = app.db();
                render_run_report_html(&db, &id, &job, Some(&purple), &custody)
            };
            match render_pdf_from_html(&html).await {
                Some(bytes) => (
                    StatusCode::OK,
                    [
                        ("content-type", "application/pdf".to_string()),
                        ("content-disposition", format!("inline; filename=\"forge-report-{id}.pdf\"")),
                    ],
                    bytes,
                ).into_response(),
                None => (
                    StatusCode::NOT_IMPLEMENTED,
                    Json(json!({
                        "error": "pdf_unavailable",
                        "why": "aucun moteur PDF (wkhtmltopdf/weasyprint) détecté sur l'hôte",
                        "hint": "ouvrez ?format=html puis « Imprimer » → « Enregistrer au format PDF » (CSS @media print fourni), ou installez wkhtmltopdf/weasyprint pour activer ?format=pdf"
                    })),
                ).into_response(),
            }
        }
        _ => {
            // md (défaut) — rétro-compat stricte : même contenu qu'avant + annexe custody.
            let md = {
                let db = app.db();
                render_run_report_md(&db, &id, &job, Some(&purple), Some(&custody))
            };
            (StatusCode::OK, [("content-type", "text/markdown; charset=utf-8")], md).into_response()
        }
    }
}

/// Génère un PDF depuis le HTML brandé en s'appuyant sur un outil SYSTÈME s'il est présent
/// (wkhtmltopdf ou weasyprint) — AUCUNE dépendance lourde n'est ajoutée au binaire. Retourne None si
/// aucun moteur n'est installé (l'appelant documente alors l'impression navigateur). Le HTML est passé
/// par STDIN (wkhtmltopdf `- -`) ou par un fichier temporaire (weasyprint) ; sortie sur stdout/fichier.
async fn render_pdf_from_html(html: &str) -> Option<Vec<u8>> {
    use tokio::io::AsyncWriteExt;
    // 1) wkhtmltopdf : lit le HTML sur stdin (`-`), écrit le PDF sur stdout (`-`). Préféré (rendu CSS).
    if which_in_path("wkhtmltopdf") {
        let mut child = tokio::process::Command::new("wkhtmltopdf")
            .args(["--quiet", "--print-media-type", "-", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(html.as_bytes()).await;
            drop(stdin); // EOF -> wkhtmltopdf termine sa lecture
        }
        let out = child.wait_with_output().await.ok()?;
        if out.status.success() && !out.stdout.is_empty() {
            return Some(out.stdout);
        }
        return None;
    }
    // 2) weasyprint : HTML d'entrée par fichier temp, PDF en sortie sur stdout (`-`).
    if which_in_path("weasyprint") {
        let dir = std::env::temp_dir().join(format!("forge-report-{}", gen_token()));
        let _ = std::fs::create_dir_all(&dir);
        let in_path = dir.join("report.html");
        if std::fs::write(&in_path, html).is_err() {
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        let out = tokio::process::Command::new("weasyprint")
            .arg(&in_path)
            .arg("-") // stdout
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .ok();
        let _ = std::fs::remove_dir_all(&dir);
        let out = out?;
        if out.status.success() && !out.stdout.is_empty() {
            return Some(out.stdout);
        }
        return None;
    }
    None
}

/// Vrai si `bin` est trouvable dans le PATH (lookup pur, sans shell). Sert à n'exposer ?format=pdf
/// que lorsqu'un moteur PDF est réellement installé (sinon on documente l'impression navigateur).
fn which_in_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p = dir.join(bin);
                std::fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Un finding tel que rendu dans le rapport (md ou html). CWE / CVSS sont des champs DÉDIÉS,
/// séparés de `category` (fourre-tout) et `mitre` (ATT&CK).
struct FindingRow {
    title: String,
    target: String,
    severity: String,
    category: String,
    cwe: String,
    cvss_vector: String,
    cvss_score: f64,
    mitre: String,
    status: String,
    tool: String,
    evidence: String,
    poc: String,
    fix: String,
}

impl FindingRow {
    /// Affichage CVSS compact « score (vecteur) ». Vide si ni score ni vecteur (ex INFO).
    fn cvss_display(&self) -> String {
        if self.cvss_score <= 0.0 && self.cvss_vector.is_empty() {
            return String::new();
        }
        if self.cvss_vector.is_empty() {
            return format!("{:.1}", self.cvss_score);
        }
        format!("{:.1} ({})", self.cvss_score, self.cvss_vector)
    }
}

/// Lit les findings d'un run dans l'ordre d'affichage (récents d'abord), avec CWE/CVSS séparés.
/// Rétro-compat : si la colonne `cwe` est vide (base ancienne / finding ingéré avant ce lot), on
/// dérive le CWE depuis `category` ; idem CVSS dérivé de la sévérité si absent. Lecture only.
fn read_finding_rows(db: &Connection, run_id: &str) -> Vec<FindingRow> {
    let mut stmt = match db.prepare(
        "SELECT title,target,severity,category,mitre,status,tool,evidence,poc,fix,cwe,cvss_vector,cvss_score \
         FROM finding WHERE run_id=? ORDER BY id DESC",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map([run_id], |r| {
        let category = r.get::<_, Option<String>>(3)?.unwrap_or_default();
        let severity = r.get::<_, Option<String>>(2)?.unwrap_or_default();
        let mut cwe = r.get::<_, Option<String>>(10)?.unwrap_or_default();
        if cwe.is_empty() {
            cwe = extract_cwe(&category);
        }
        let mut cvss_vector = r.get::<_, Option<String>>(11)?.unwrap_or_default();
        let mut cvss_score = r.get::<_, Option<f64>>(12)?.unwrap_or(0.0);
        if cvss_vector.is_empty() && cvss_score <= 0.0 {
            let (v, s) = cvss_base_for_severity(&severity);
            cvss_vector = v.to_string();
            cvss_score = s;
        }
        Ok(FindingRow {
            title: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            target: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            severity,
            category,
            cwe,
            cvss_vector,
            cvss_score,
            mitre: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            status: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            tool: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            evidence: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            poc: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
            fix: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
        })
    })
    .map(|it| it.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Notes d'engagement d'une campagne (table `campaign.notes`) — contexte client (cadre, ROE, objet
/// de la mission) à brancher dans l'executive summary. '' si la campagne n'a pas de métadonnées.
fn campaign_notes(db: &Connection, name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    db.query_row(
        "SELECT notes FROM campaign WHERE name=? ORDER BY id DESC LIMIT 1",
        [name],
        |r| r.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
    .unwrap_or_default()
}

/// Annexe chaîne-de-custody : recalcule la chaîne SHA-256 du ledger (sans la clé) et retourne les
/// métadonnées d'audit (head, nb entrées, algo, validité, attribution actor du lot comptes). NE
/// vérifie PAS la signature (la console n'a pas la clé) — la vérif externe se fait via
/// `forge ledger verify --pubkey`. La clé publique éventuelle est lue via FORGE_CONSOLE_LEDGER_PUBKEY
/// (informative, jamais un secret).
struct LedgerCustody {
    path: String,
    entries: usize,
    head: String,
    alg: String,
    chain_ok: bool,
    why: String,
    pubkey: String,           // clé publique Ed25519 (hex) si exposée par l'opérateur, sinon ''
    actor: String,            // attribution = login source de vérité (started_by résolu) du run
    high_impact: bool,        // run armé haut-impact (opt-in honoré)
}

/// Re-vérifie la chaîne du ledger console (même algo que /api/ledger/verify) et assemble l'annexe
/// chaîne-de-custody pour le rapport. `started_by` = attribution du lot comptes (login résolu).
fn build_ledger_custody(app: &App, started_by: &str) -> LedgerCustody {
    const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let path = app.ledger_path.as_str().to_string();
    let pubkey = std::env::var("FORGE_CONSOLE_LEDGER_PUBKEY").unwrap_or_default();
    // attribution : `<login>` ou `<login>+high_impact` -> on sépare le login et le flag.
    let (actor, high_impact) = match started_by.strip_suffix("+high_impact") {
        Some(login) => (login.to_string(), true),
        None => (started_by.to_string(), false),
    };
    let entries = read_ledger_lines(&path);
    if entries.is_empty() {
        let exists = std::path::Path::new(&path).exists();
        return LedgerCustody {
            path, entries: 0, head: String::new(), alg: String::new(),
            chain_ok: exists, why: if exists { String::new() } else { "ledger absent".into() },
            pubkey, actor, high_impact,
        };
    }
    let mut prev = GENESIS.to_string();
    let mut head = GENESIS.to_string();
    let mut alg = String::new();
    let mut chain_ok = true;
    let mut why = String::new();
    for rec in &entries {
        let seq = rec.get("seq").cloned().unwrap_or(Value::Null);
        let ts = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let detail = rec.get("detail").cloned().unwrap_or(Value::Null);
        let stored_prev = rec.get("prev").and_then(|v| v.as_str()).unwrap_or("");
        let stored_hash = rec.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        alg = rec.get("alg").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if stored_prev != prev {
            chain_ok = false;
            why = "chaînage rompu (prev)".into();
            break;
        }
        let seq_str = match &seq { Value::Number(num) => num.to_string(), Value::Null => String::new(), other => other.to_string() };
        let preimage = format!("{prev}|{seq_str}|{ts}|{kind}|{}", canon_json(&detail));
        if sha_hex(&preimage) != stored_hash {
            chain_ok = false;
            why = "hash recalculé != hash stocké (entrée altérée)".into();
            break;
        }
        prev = stored_hash.to_string();
        head = stored_hash.to_string();
    }
    LedgerCustody {
        path, entries: entries.len(), head, alg, chain_ok, why, pubkey, actor, high_impact,
    }
}

const REPORT_SEVERITIES: &[&str] = &["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

/// Phrase EN PROSE des comptes par sévérité (résumé exécutif). « Aucun finding » si rien.
fn prose_counts(by_sev: &HashMap<String, i64>) -> String {
    let total: i64 = by_sev.values().sum();
    if total == 0 {
        return "Aucun finding n'a été retenu sur cet engagement.".into();
    }
    // ordre décroissant de gravité, en ne citant que les sévérités présentes.
    let parts: Vec<String> = REPORT_SEVERITIES.iter().rev()
        .filter_map(|s| {
            let n = by_sev.get(*s).copied().unwrap_or(0);
            if n > 0 { Some(format!("{n} {}", sev_word(s, n))) } else { None }
        })
        .collect();
    format!(
        "L'évaluation a retenu {total} finding{} : {}.",
        if total > 1 { "s" } else { "" },
        parts.join(", "),
    )
}

/// Libellé de sévérité en français accordé au nombre (pour la prose).
fn sev_word(sev: &str, n: i64) -> String {
    let base = match sev {
        "CRITICAL" => "critique",
        "HIGH" => "élevé",
        "MEDIUM" => "moyen",
        "LOW" => "faible",
        _ => "informatif",
    };
    if n > 1 { format!("{base}s") } else { base.to_string() }
}

/// Phrase top-risques : cite les titres des findings les plus graves (CRITICAL puis HIGH), max 3.
fn prose_top_risks(rows: &[FindingRow]) -> String {
    let mut ranked: Vec<&FindingRow> = rows.iter()
        .filter(|f| matches!(f.severity.to_ascii_uppercase().as_str(), "CRITICAL" | "HIGH"))
        .collect();
    ranked.sort_by_key(|f| match f.severity.to_ascii_uppercase().as_str() { "CRITICAL" => 0, _ => 1 });
    if ranked.is_empty() {
        return "Aucun risque haut ou critique n'a été identifié sur le périmètre testé.".into();
    }
    let top: Vec<String> = ranked.iter().take(3)
        .map(|f| format!("« {} » sur `{}`", f.title, f.target))
        .collect();
    format!("Les risques prioritaires à traiter sont : {}.", top.join(" ; "))
}

/// Phrase posture : lecture synthétique du niveau de risque résiduel.
fn prose_posture(by_sev: &HashMap<String, i64>) -> String {
    let crit = by_sev.get("CRITICAL").copied().unwrap_or(0);
    let high = by_sev.get("HIGH").copied().unwrap_or(0);
    let med = by_sev.get("MEDIUM").copied().unwrap_or(0);
    if crit > 0 {
        "Posture : EXPOSÉE — au moins une vulnérabilité critique permet un impact direct ; remédiation immédiate recommandée.".into()
    } else if high > 0 {
        "Posture : À RENFORCER — des vulnérabilités élevées sont exploitables ; planifier une remédiation rapide.".into()
    } else if med > 0 {
        "Posture : ACCEPTABLE SOUS RÉSERVE — risques modérés à corriger dans le cycle de durcissement courant.".into()
    } else {
        "Posture : SOLIDE — aucun risque élevé ou critique sur le périmètre testé ; maintenir la surveillance.".into()
    }
}

/// Rend le markdown du rapport d'un run depuis les données console (miroir de build_report Python) :
/// synthèse par sévérité, findings détaillés, section transparence ROE (FIRE/DRY_RUN/VETO/erreurs),
/// section PURPLE (couverture de détection SOC) quand `purple` est fourni, et annexe chaîne-de-custody
/// (head du ledger, nb entrées, algo, clé publique, attribution actor) quand `custody` est fourni.
/// Les compteurs proviennent de run_job ; le détail des findings/verdicts des tables finding/roe_decision.
fn render_run_report_md(db: &Connection, run_id: &str, job: &Value, purple: Option<&Value>, custody: Option<&LedgerCustody>) -> String {
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
    let finding_rows = read_finding_rows(db, run_id);
    for f in &finding_rows {
        *by_sev.entry(f.severity.clone()).or_insert(0) += 1;
    }

    // --- Executive summary (prose) : scope, fenêtre temporelle, comptes par sévérité, top risques,
    //     posture. Contexte d'engagement = Campaign.notes si renseigné. ---
    out.push("## Résumé exécutif".into());
    out.push(String::new());
    let notes = campaign_notes(db, campaign);
    if !notes.is_empty() {
        out.push(format!("**Contexte d'engagement.** {notes}"));
        out.push(String::new());
    }
    let targets_list: Vec<String> = job.get("targets").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let scope_phrase = if targets_list.is_empty() { "le périmètre planifié".to_string() } else { format!("le périmètre {}", targets_list.join(", ")) };
    let started = job.get("started").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
        .or_else(|| job.get("ts").and_then(|v| v.as_str())).unwrap_or("(début non daté)");
    let finished = job.get("finished").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("(en cours / non daté)");
    out.push(format!(
        "Cet engagement a couvert {scope_phrase}, sur la fenêtre du {started} au {finished}, \
         en mode `{}`.",
        job.get("mode").and_then(|v| v.as_str()).unwrap_or("propose"),
    ));
    out.push(prose_counts(&by_sev));
    out.push(prose_top_risks(&finding_rows));
    out.push(prose_posture(&by_sev));
    out.push(String::new());

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
    for f in &finding_rows {
        out.push(format!("### [{}] {} — `{}`", f.severity, f.title, f.target));
        // CWE et CVSS SÉPARÉS (distincts de la catégorie/ATT&CK).
        out.push(format!(
            "- **CWE** : {}  ·  **CVSS** : {}  ·  **ATT&CK** : {}",
            dash(&f.cwe), dash(&f.cvss_display()), dash(&f.mitre),
        ));
        out.push(format!("- **Catégorie** : {}  ·  **Statut** : {}  ·  **Outil** : {}", dash(&f.category), dash(&f.status), dash(&f.tool)));
        if !f.evidence.is_empty() {
            out.push(format!("- **Evidence** : {}", f.evidence));
        }
        if !f.poc.is_empty() {
            out.push(format!("- **PoC** : {}", f.poc));
        }
        if !f.fix.is_empty() {
            out.push(format!("- **Remediation** : {}", f.fix));
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

    // --- ANNEXE chaîne-de-custody : preuve d'intégrité de l'audit (ledger SHA-256) + attribution. ---
    if let Some(c) = custody {
        out.push("## Annexe — chaîne de custody".into());
        out.push(String::new());
        out.push(format!("- **Ledger** : `{}`", c.path));
        out.push(format!("- **Entrées** : {}", c.entries));
        out.push(format!("- **Algorithme** : {}", if c.alg.is_empty() { "—" } else { &c.alg }));
        out.push(format!("- **Head (dernier hash)** : `{}`", if c.head.is_empty() { "—" } else { &c.head }));
        let integrity = if c.chain_ok { "VALIDE (chaîne SHA-256 recalculée, chaînage cohérent)".to_string() }
            else { format!("ROMPUE — {}", if c.why.is_empty() { "intégrité non vérifiée".into() } else { c.why.clone() }) };
        out.push(format!("- **Intégrité** : {integrity}"));
        if !c.pubkey.is_empty() {
            out.push(format!("- **Clé publique (Ed25519)** : `{}`", c.pubkey));
        }
        // attribution du lot comptes : login source de vérité (started_by résolu).
        out.push(format!(
            "- **Attribution (acteur)** : `{}`{}",
            if c.actor.is_empty() { "—" } else { &c.actor },
            if c.high_impact { "  ·  opt-in HAUT-IMPACT honoré (run armé)" } else { "" },
        ));
        out.push(String::new());
        out.push("Vérification externe par un tiers, sans aucun secret (clé publique seule) :".into());
        out.push(String::new());
        let pk = if c.pubkey.is_empty() { "<clé_publique_hex>" } else { &c.pubkey };
        out.push(format!("```\nforge ledger verify --ledger {} --pubkey {pk}\n```", c.path));
        out.push(String::new());
    }

    out.join("\n")
}

/// Classe CSS de badge sévérité (couleurs Aurora) pour le rapport HTML.
fn sev_css_class(sev: &str) -> &'static str {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => "sev-crit",
        "HIGH" => "sev-high",
        "MEDIUM" => "sev-med",
        "LOW" => "sev-low",
        _ => "sev-info",
    }
}

/// LIVRABLE CLIENT — rapport d'engagement HTML BRANDÉ (thème Aurora GuatX/Forge + quetzal).
/// Document AUTONOME (CSS inlined, imprimable, `@media print`) : page de garde, sommaire, résumé
/// exécutif EN PROSE (scope, fenêtre, comptes par sévérité, top risques, posture, contexte
/// Campaign.notes), findings détaillés avec evidence/PoC/FIX + CWE/CVSS SÉPARÉS, transparence ROE,
/// couverture purple, et annexe chaîne-de-custody (head ledger, nb entrées, algo, clé publique,
/// commande `forge ledger verify --pubkey`, attribution actor). Tout texte dynamique est échappé HTML.
fn render_run_report_html(db: &Connection, run_id: &str, job: &Value, purple: Option<&Value>, custody: &LedgerCustody) -> String {
    let e = html_escape; // alias court
    let campaign = job.get("campaign").and_then(|v| v.as_str()).unwrap_or("");
    let mode = job.get("mode").and_then(|v| v.as_str()).unwrap_or("—");
    let status = job.get("status").and_then(|v| v.as_str()).unwrap_or("—");
    let started = job.get("started").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
        .or_else(|| job.get("ts").and_then(|v| v.as_str())).unwrap_or("—");
    let finished = job.get("finished").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—");
    let started_by = job.get("started_by").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—");
    let targets_list: Vec<String> = job.get("targets").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let finding_rows = read_finding_rows(db, run_id);
    let mut by_sev: HashMap<String, i64> = HashMap::new();
    for f in &finding_rows {
        *by_sev.entry(f.severity.clone()).or_insert(0) += 1;
    }
    let notes = campaign_notes(db, campaign);

    let mut h = String::with_capacity(16_384);
    h.push_str("<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    h.push_str(&format!("<title>Forge — rapport d'engagement {}</title>", e(run_id)));
    h.push_str(REPORT_CSS);
    h.push_str("</head><body>");

    // ----- barre d'actions (écran seulement) : impression / PDF -----
    h.push_str("<div class=\"toolbar noprint\">");
    h.push_str("<button type=\"button\" onclick=\"window.print()\">Imprimer / Enregistrer en PDF</button>");
    h.push_str("<a class=\"btn\" href=\"?format=pdf\">Télécharger PDF</a>");
    h.push_str("<a class=\"btn\" href=\"?format=md\">Markdown</a>");
    h.push_str("</div>");

    // ----- PAGE DE GARDE (quetzal + branding) -----
    h.push_str("<section class=\"cover\">");
    h.push_str("<img class=\"qz\" src=\"/quetzal.svg\" alt=\"\">");
    h.push_str("<div class=\"brand\">Guat<span class=\"x\">X</span> <span class=\"sub\">Forge</span></div>");
    h.push_str("<h1 class=\"cover-title\">Rapport d'engagement de sécurité</h1>");
    h.push_str(&format!("<div class=\"cover-camp\">{}</div>", e(if campaign.is_empty() { "(campagne sans nom)" } else { campaign })));
    h.push_str("<dl class=\"cover-meta\">");
    let cover_meta = [
        ("Run", run_id),
        ("Mode", mode),
        ("Statut", status),
        ("Fenêtre", &format!("{} → {}", started, finished)),
        ("Opérateur", started_by),
    ];
    for (k, v) in cover_meta {
        h.push_str(&format!("<dt>{}</dt><dd>{}</dd>", e(k), e(v)));
    }
    h.push_str("</dl>");
    h.push_str("<div class=\"cover-foot\">Document confidentiel — diffusion restreinte au commanditaire</div>");
    h.push_str("</section>");

    // ----- SOMMAIRE -----
    h.push_str("<nav class=\"toc\"><h2>Sommaire</h2><ol>");
    let mut toc = vec![
        ("exec", "Résumé exécutif"),
        ("synth", "Synthèse par sévérité"),
        ("findings", "Findings détaillés"),
        ("roe", "Couverture & transparence (ROE)"),
    ];
    if purple.map(|p| p.get("plume_reachable").and_then(|v| v.as_bool()).unwrap_or(false) || p.get("error").is_some()).unwrap_or(false) {
        toc.push(("purple", "Couverture détection (purple)"));
    }
    toc.push(("custody", "Annexe — chaîne de custody"));
    for (anchor, label) in &toc {
        h.push_str(&format!("<li><a href=\"#{}\">{}</a></li>", anchor, e(label)));
    }
    h.push_str("</ol></nav>");

    // ----- RÉSUMÉ EXÉCUTIF (prose) -----
    h.push_str("<section id=\"exec\" class=\"sec\"><h2>Résumé exécutif</h2>");
    if !notes.is_empty() {
        h.push_str(&format!("<p class=\"context\"><strong>Contexte d'engagement.</strong> {}</p>", e(&notes)));
    }
    let scope_phrase = if targets_list.is_empty() { "le périmètre planifié".to_string() }
        else { format!("le périmètre {}", e(&targets_list.join(", "))) };
    h.push_str(&format!(
        "<p>Cet engagement a couvert {scope_phrase}, sur la fenêtre du <strong>{}</strong> au <strong>{}</strong>, en mode <code>{}</code>.</p>",
        e(started), e(finished), e(mode),
    ));
    h.push_str(&format!("<p>{}</p>", e(&prose_counts(&by_sev))));
    h.push_str(&format!("<p>{}</p>", e(&prose_top_risks(&finding_rows))));
    let posture = prose_posture(&by_sev);
    let posture_cls = if posture.contains("EXPOSÉE") { "posture-bad" } else if posture.contains("RENFORCER") { "posture-warn" } else if posture.contains("ACCEPTABLE") { "posture-mid" } else { "posture-good" };
    h.push_str(&format!("<p class=\"posture {}\">{}</p>", posture_cls, e(&posture)));
    h.push_str("</section>");

    // ----- SYNTHÈSE par sévérité (cartes chiffrées) -----
    h.push_str("<section id=\"synth\" class=\"sec\"><h2>Synthèse par sévérité</h2><div class=\"sevgrid\">");
    for s in REPORT_SEVERITIES.iter().rev() {
        let n = by_sev.get(*s).copied().unwrap_or(0);
        h.push_str(&format!(
            "<div class=\"sevcard {}\"><div class=\"n\">{}</div><div class=\"l\">{}</div></div>",
            sev_css_class(s), n, e(s),
        ));
    }
    h.push_str("</div></section>");

    // ----- FINDINGS détaillés -----
    h.push_str("<section id=\"findings\" class=\"sec\"><h2>Findings détaillés</h2>");
    if finding_rows.is_empty() {
        h.push_str("<p class=\"muted\">Aucun finding retenu.</p>");
    }
    for f in &finding_rows {
        h.push_str("<article class=\"finding\">");
        h.push_str(&format!(
            "<h3><span class=\"sevbadge {}\">{}</span> {} <span class=\"tgt\">{}</span></h3>",
            sev_css_class(&f.severity), e(&f.severity), e(&f.title), e(&f.target),
        ));
        // taxonomie : CWE / CVSS / ATT&CK SÉPARÉS.
        h.push_str("<div class=\"taxo\">");
        h.push_str(&format!("<span class=\"chip\"><b>CWE</b> {}</span>", e(dash_or(&f.cwe))));
        h.push_str(&format!("<span class=\"chip\"><b>CVSS</b> {}</span>", e(dash_or(&f.cvss_display()))));
        h.push_str(&format!("<span class=\"chip\"><b>ATT&amp;CK</b> {}</span>", e(dash_or(&f.mitre))));
        h.push_str(&format!("<span class=\"chip\"><b>Catégorie</b> {}</span>", e(dash_or(&f.category))));
        h.push_str(&format!("<span class=\"chip\"><b>Statut</b> {}</span>", e(dash_or(&f.status))));
        h.push_str(&format!("<span class=\"chip\"><b>Outil</b> {}</span>", e(dash_or(&f.tool))));
        h.push_str("</div>");
        if !f.evidence.is_empty() {
            h.push_str(&format!("<div class=\"fld\"><div class=\"k\">Evidence</div><pre>{}</pre></div>", e(&f.evidence)));
        }
        if !f.poc.is_empty() {
            h.push_str(&format!("<div class=\"fld\"><div class=\"k\">PoC</div><pre>{}</pre></div>", e(&f.poc)));
        }
        // FIX (maintenant rempli) — mis en avant comme remédiation.
        if !f.fix.is_empty() {
            h.push_str(&format!("<div class=\"fld fix\"><div class=\"k\">Remédiation</div><div class=\"v\">{}</div></div>", e(&f.fix)));
        }
        h.push_str("</article>");
    }
    h.push_str("</section>");

    // ----- TRANSPARENCE ROE (anti-masquage) -----
    h.push_str("<section id=\"roe\" class=\"sec\"><h2>Couverture &amp; transparence (ROE / anti-masquage)</h2>");
    let geti = |k: &str| job.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    h.push_str("<div class=\"roegrid\">");
    for (lab, k) in [("Tirées (FIRE)", "fired"), ("Simulées (DRY_RUN)", "dry_run"), ("Refusées (VETO)", "vetoed"), ("Erreurs / skips", "errors")] {
        h.push_str(&format!("<div class=\"roebox\"><div class=\"n\">{}</div><div class=\"l\">{}</div></div>", geti(k), e(lab)));
    }
    h.push_str("</div>");
    // détail des verdicts non-FIRE.
    let verdicts = read_nonfire_verdicts(db, run_id);
    if !verdicts.is_empty() {
        h.push_str("<table class=\"vtab\"><thead><tr><th>Verdict</th><th>Kind</th><th>Cible</th><th>Raisons</th></tr></thead><tbody>");
        for (verdict, kind, target, reasons) in &verdicts {
            h.push_str(&format!(
                "<tr><td><span class=\"vbadge\">{}</span></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                e(verdict), e(kind), e(target), e(reasons),
            ));
        }
        h.push_str("</tbody></table>");
    }
    // classes jamais tentées + déférées budget.
    if let Some(gaps) = job.get("coverage_gaps").and_then(|g| g.as_object()).filter(|g| !g.is_empty()) {
        h.push_str("<h3>Classes jamais tentées</h3><ul>");
        for (tgt, miss) in gaps {
            let list = miss.as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_else(|| miss.to_string());
            h.push_str(&format!("<li><code>{}</code> : {}</li>", e(tgt), e(&list)));
        }
        h.push_str("</ul>");
    }
    if let Some(skipped) = job.get("skipped_budget").and_then(|s| s.as_array()).filter(|s| !s.is_empty()) {
        h.push_str("<h3>Déférées (budget)</h3><ul>");
        for a in skipped {
            h.push_str(&format!("<li>{}</li>", e(&cell_string(a))));
        }
        h.push_str("</ul>");
    }
    h.push_str("</section>");

    // ----- COUVERTURE PURPLE (si mesurée / fail-open lisible) -----
    if let Some(p) = purple {
        render_purple_section_html(&mut h, p);
    }

    // ----- ANNEXE chaîne-de-custody -----
    h.push_str("<section id=\"custody\" class=\"sec\"><h2>Annexe — chaîne de custody</h2>");
    h.push_str("<p class=\"muted\">Preuve d'intégrité de l'audit : chaîne de hachage SHA-256 du ledger d'engagement (chaque acte chaîné au précédent). L'attribution ci-dessous est la source de vérité du lot comptes (login résolu).</p>");
    h.push_str("<dl class=\"custody\">");
    let integrity = if custody.chain_ok { "VALIDE (chaîne SHA-256 recalculée, chaînage cohérent)".to_string() }
        else { format!("ROMPUE — {}", if custody.why.is_empty() { "intégrité non vérifiée".into() } else { custody.why.clone() }) };
    let actor_disp = if custody.actor.is_empty() { "—".to_string() }
        else if custody.high_impact { format!("{} (opt-in HAUT-IMPACT honoré — run armé)", custody.actor) }
        else { custody.actor.clone() };
    let mut custody_rows = vec![
        ("Ledger", custody.path.clone()),
        ("Entrées", custody.entries.to_string()),
        ("Algorithme", if custody.alg.is_empty() { "—".into() } else { custody.alg.clone() }),
        ("Head (dernier hash)", if custody.head.is_empty() { "—".into() } else { custody.head.clone() }),
        ("Intégrité", integrity),
        ("Attribution (acteur)", actor_disp),
    ];
    if !custody.pubkey.is_empty() {
        custody_rows.push(("Clé publique (Ed25519)", custody.pubkey.clone()));
    }
    for (k, v) in &custody_rows {
        h.push_str(&format!("<dt>{}</dt><dd><code>{}</code></dd>", e(k), e(v)));
    }
    h.push_str("</dl>");
    let pk = if custody.pubkey.is_empty() { "<clé_publique_hex>".to_string() } else { custody.pubkey.clone() };
    h.push_str("<p class=\"muted\">Vérification externe par un tiers, sans aucun secret (clé publique seule) :</p>");
    h.push_str(&format!("<pre class=\"cmd\">forge ledger verify --ledger {} --pubkey {}</pre>", e(&custody.path), e(&pk)));
    h.push_str("</section>");

    h.push_str("</body></html>");
    h
}

/// '—' si vide, sinon la chaîne telle quelle (pour l'affichage des champs taxonomie).
fn dash_or(s: &str) -> &str {
    if s.is_empty() { "—" } else { s }
}

/// Lit les verdicts non-FIRE (DRY_RUN/VETO) d'un run, raisons aplaties en une chaîne lisible.
fn read_nonfire_verdicts(db: &Connection, run_id: &str) -> Vec<(String, String, String, String)> {
    let mut stmt = match db.prepare(
        "SELECT verdict,kind,target,reasons FROM roe_decision WHERE run_id=? AND verdict<>'FIRE' ORDER BY id",
    ) { Ok(s) => s, Err(_) => return vec![] };
    stmt.query_map([run_id], |r| {
        let reasons_raw = r.get::<_, Option<String>>(3)?.unwrap_or_default();
        let reasons = serde_json::from_str::<Value>(&reasons_raw).ok()
            .and_then(|v| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>().join(" ; ")))
            .unwrap_or(reasons_raw);
        Ok((
            r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            reasons,
        ))
    })
    .map(|it| it.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Section HTML « Couverture détection (purple) » — miroir HTML de render_purple_section.
/// FAIL-OPEN LISIBLE : si Plume injoignable, on l'indique et on n'invente aucune couverture.
fn render_purple_section_html(h: &mut String, p: &Value) {
    let e = html_escape;
    h.push_str("<section id=\"purple\" class=\"sec\"><h2>Couverture détection (purple)</h2>");
    let reachable = p.get("plume_reachable").and_then(|v| v.as_bool()).unwrap_or(false);
    if !reachable {
        // AUTONOME (standalone) : aucune source configurée -> état NORMAL (Forge n'en DÉPEND pas), pas une panne.
        if p.get("source_configured").and_then(|v| v.as_bool()) == Some(false) {
            h.push_str("<p class=\"muted\">Aucune source de détection configurée — Forge fonctionne en autonome (standalone). \
Connectez une source (Plume / CrowdSec / FortiGate / Elastic / fichier…) pour activer la boucle purple. Aucune couverture inventée.</p></section>");
            return;
        }
        let why = p.get("error").and_then(|v| v.as_str()).unwrap_or("source de détection injoignable");
        h.push_str(&format!("<p class=\"muted\">Mesure indisponible (fail-open) : {}. Aucune couverture inventée.</p></section>", e(why)));
        return;
    }
    let fired = p.get("techniques_fired").and_then(|v| v.as_i64()).unwrap_or(0);
    let detected = p.get("techniques_detected").and_then(|v| v.as_i64()).unwrap_or(0);
    let missed = p.get("techniques_missed").and_then(|v| v.as_i64()).unwrap_or(0);
    let rate = p.get("detection_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let mttd_avg = p.get("mttd_avg_secs").and_then(|v| v.as_f64());
    let mttd_max = p.get("mttd_max_secs").and_then(|v| v.as_i64());
    h.push_str("<ul class=\"plist\">");
    h.push_str(&format!("<li><b>Techniques tirées (red)</b> : {}</li>", fired));
    h.push_str(&format!("<li><b>Détectées par le SOC (blue)</b> : {} · <b>Taux</b> : {:.0}%</li>", detected, rate * 100.0));
    h.push_str(&format!("<li><b>Trous de détection</b> : {}</li>", missed));
    h.push_str(&format!(
        "<li><b>MTTD moyen</b> : {} · <b>MTTD max</b> : {}</li>",
        mttd_avg.map(|m| format!("{m:.0}s")).unwrap_or_else(|| "—".into()),
        mttd_max.map(|m| format!("{m}s")).unwrap_or_else(|| "—".into()),
    ));
    h.push_str("</ul>");
    if let Some(arr) = p.get("missed").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) {
        h.push_str("<h3>Techniques NON détectées (trous SOC)</h3><ul>");
        for m in arr {
            let mitre = m.get("mitre").and_then(|v| v.as_str()).unwrap_or("?");
            let fires = m.get("fires").and_then(|v| v.as_i64()).unwrap_or(0);
            h.push_str(&format!("<li><code>{}</code> (tirée {}×) — aucune alerte SOC</li>", e(mitre), fires));
        }
        h.push_str("</ul>");
    }
    if let Some(arr) = p.get("detected").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) {
        h.push_str("<h3>Techniques détectées (avec MTTD)</h3><ul>");
        for d in arr {
            let mitre = d.get("mitre").and_then(|v| v.as_str()).unwrap_or("?");
            let alert_count = d.get("alert_count").and_then(|v| v.as_i64()).unwrap_or(0);
            let mttd = d.get("mttd_secs").and_then(|v| v.as_i64());
            h.push_str(&format!(
                "<li><code>{}</code> — {} alerte(s), MTTD {}</li>",
                e(mitre), alert_count, mttd.map(|m| format!("{m}s")).unwrap_or_else(|| "—".into()),
            ));
        }
        h.push_str("</ul>");
    }
    h.push_str("</section>");
}

/// CSS du rapport HTML brandé — thème Aurora (palette GuatX/Forge), inliné pour un document AUTONOME.
/// `@media print` : page de garde isolée, sauts de page propres, masquage de la barre d'actions,
/// couleurs forcées (print-color-adjust) pour que les badges/posture restent lisibles en PDF.
const REPORT_CSS: &str = "<style>\n\
:root{--bg:#070b13;--card:#0c1422;--card2:#0a111d;--bd:#16202e;--hd:#eaf2fb;--fg:#cdd9e6;--mut:#8aa0b4;\
--acc:#2dd4bf;--acc-ink:#04201c;--acc-bg:#2dd4bf1a;--b1:#7ce8c3;--b2:#ffd9a3;--b3:#ffb3ab;\
--crit:#ff6b6b;--high:#ffa94d;--med:#ffd43b;--low:#74c0fc;--info:#8aa0b4;\
--sans:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;--mono:'JetBrains Mono',ui-monospace,monospace}\n\
*{box-sizing:border-box}\n\
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.6;font-size:14px;\
max-width:920px;margin:0 auto;padding:0 28px 64px}\n\
body::before{content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.16;filter:blur(48px);\
background:radial-gradient(42vw 42vw at 6% -8%,var(--b1),transparent 62%),\
radial-gradient(38vw 38vw at 102% 10%,var(--b2),transparent 62%),\
radial-gradient(36vw 36vw at 44% 116%,var(--b3),transparent 62%)}\n\
h1,h2,h3{color:var(--hd);font-weight:700;line-height:1.25}\n\
h2{font-size:20px;margin:32px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--bd)}\n\
h3{font-size:15px;margin:18px 0 8px}\n\
code{font-family:var(--mono);font-size:.92em;background:var(--card2);border:1px solid var(--bd);border-radius:5px;padding:1px 5px;color:var(--acc)}\n\
pre{font-family:var(--mono);font-size:12px;background:var(--card2);border:1px solid var(--bd);border-radius:8px;padding:10px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;color:var(--fg)}\n\
.muted{color:var(--mut)}\n\
.toolbar{display:flex;gap:10px;padding:16px 0;position:sticky;top:0;z-index:9}\n\
.toolbar button,.toolbar .btn{font-family:var(--sans);font-size:13px;background:var(--acc);color:var(--acc-ink);\
border:0;border-radius:9px;padding:8px 16px;cursor:pointer;font-weight:700;text-decoration:none}\n\
.toolbar .btn{background:var(--card);color:var(--fg);border:1px solid var(--bd);font-weight:500}\n\
.cover{min-height:88vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:40px 0}\n\
.cover .qz{width:128px;height:128px;filter:drop-shadow(0 6px 24px rgba(45,212,191,.25))}\n\
.cover .brand{font-size:34px;font-weight:800;letter-spacing:-.02em;margin-top:14px;color:var(--hd)}\n\
.cover .brand .x{color:var(--acc)}\n\
.cover .brand .sub{font-size:18px;font-weight:600;color:var(--mut);margin-left:6px}\n\
.cover-title{font-size:30px;margin:24px 0 6px}\n\
.cover-camp{font-size:18px;color:var(--acc);font-weight:600;margin-bottom:26px}\n\
.cover-meta{display:grid;grid-template-columns:auto auto;gap:5px 18px;font-size:14px;margin:0 auto;text-align:left}\n\
.cover-meta dt{color:var(--mut);font-weight:600}.cover-meta dd{margin:0;color:var(--fg);font-family:var(--mono);font-size:13px}\n\
.cover-foot{margin-top:34px;font-size:12px;color:var(--mut);letter-spacing:.04em;text-transform:uppercase}\n\
.toc{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px 22px;margin:28px 0}\n\
.toc h2{border:0;margin:0 0 6px;font-size:16px}\n\
.toc ol{margin:0;padding-left:20px}.toc a{color:var(--fg);text-decoration:none}.toc a:hover{color:var(--acc)}\n\
.sec{margin-top:8px}\n\
.context{background:var(--acc-bg);border-left:3px solid var(--acc);border-radius:0 8px 8px 0;padding:10px 14px}\n\
.posture{font-weight:700;border-radius:8px;padding:11px 14px;margin-top:14px}\n\
.posture-bad{background:rgba(255,107,107,.14);border:1px solid var(--crit);color:var(--crit)}\n\
.posture-warn{background:rgba(255,169,77,.14);border:1px solid var(--high);color:var(--high)}\n\
.posture-mid{background:rgba(255,212,59,.12);border:1px solid var(--med);color:var(--med)}\n\
.posture-good{background:var(--acc-bg);border:1px solid var(--acc);color:var(--acc)}\n\
.sevgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}\n\
.sevcard{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 8px;text-align:center}\n\
.sevcard .n{font-size:26px;font-weight:800;line-height:1}.sevcard .l{font-size:11px;color:var(--mut);margin-top:5px;text-transform:uppercase;letter-spacing:.05em}\n\
.sevcard.sev-crit{border-color:var(--crit)}.sevcard.sev-crit .n{color:var(--crit)}\n\
.sevcard.sev-high{border-color:var(--high)}.sevcard.sev-high .n{color:var(--high)}\n\
.sevcard.sev-med{border-color:var(--med)}.sevcard.sev-med .n{color:var(--med)}\n\
.sevcard.sev-low{border-color:var(--low)}.sevcard.sev-low .n{color:var(--low)}\n\
.finding{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px 18px;margin:14px 0;break-inside:avoid}\n\
.finding h3{margin:0 0 10px;display:flex;align-items:center;gap:9px;flex-wrap:wrap}\n\
.finding .tgt{font-family:var(--mono);font-size:12px;color:var(--mut);font-weight:500}\n\
.sevbadge{font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.04em;padding:3px 9px;border-radius:20px;text-transform:uppercase}\n\
.sevbadge.sev-crit{background:var(--crit);color:#1a0606}.sevbadge.sev-high{background:var(--high);color:#241201}\n\
.sevbadge.sev-med{background:var(--med);color:#241f01}.sevbadge.sev-low{background:var(--low);color:#031424}.sevbadge.sev-info{background:var(--info);color:#06101a}\n\
.taxo{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:10px}\n\
.chip{font-size:12px;background:var(--card2);border:1px solid var(--bd);border-radius:7px;padding:3px 9px;color:var(--fg)}\n\
.chip b{color:var(--mut);font-weight:600;margin-right:4px;font-size:11px;text-transform:uppercase;letter-spacing:.03em}\n\
.fld{margin:9px 0}.fld .k{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;font-weight:700;margin-bottom:3px}\n\
.fld.fix .v{background:var(--acc-bg);border:1px solid color-mix(in srgb,var(--acc) 30%,transparent);border-radius:8px;padding:9px 12px;color:var(--hd)}\n\
.roegrid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}\n\
.roebox{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px;text-align:center}\n\
.roebox .n{font-size:22px;font-weight:800;color:var(--hd)}.roebox .l{font-size:11px;color:var(--mut);margin-top:4px}\n\
.vtab,.custody dl{width:100%}\n\
.vtab{border-collapse:collapse;font-size:13px;margin:8px 0}\n\
.vtab th,.vtab td{border:1px solid var(--bd);padding:6px 10px;text-align:left;vertical-align:top}\n\
.vtab th{background:var(--card2);color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em}\n\
.vbadge{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--high)}\n\
.plist{margin:6px 0;padding-left:20px}.plist b{color:var(--mut);font-weight:600}\n\
dl.custody{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px}\n\
dl.custody dt{color:var(--mut);font-weight:600}dl.custody dd{margin:0;word-break:break-all}\n\
pre.cmd{border-color:var(--acc);color:var(--acc)}\n\
@media print{\n\
@page{margin:16mm}\n\
:root,body{background:#fff!important;color:#1a2330!important}\n\
*{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}\n\
body{max-width:none;padding:0}body::before{display:none}\n\
.noprint,.toolbar{display:none!important}\n\
.cover{min-height:auto;page-break-after:always;padding:18mm 0}\n\
.cover .brand,.cover-title,h1,h2,h3{color:#0c1a16!important}\n\
.toc{page-break-after:always}\n\
.sec,.finding{break-inside:avoid}\n\
h2{page-break-after:avoid}\n\
.finding,.sevcard,.roebox,.toc,.context,.posture,pre,.vtab th{background:#f6f8f7!important}\n\
code,.chip{background:#eef2f0!important;color:#0a6b56!important}\n\
.posture-good,pre.cmd{color:#0a6b56!important}\n\
}\n\
</style>";

/// Section markdown « Couverture détection (purple) » du rapport : detected / missed / MTTD.
/// FAIL-OPEN LISIBLE : si `plume_reachable=false`, on l'indique explicitement et on n'affiche
/// AUCUN détecté/raté (cohérent avec l'endpoint — un SOC muet n'est jamais « tout détecté »).
fn render_purple_section(out: &mut Vec<String>, p: &Value) {
    out.push("## Couverture détection (purple)".into());
    out.push(String::new());
    let reachable = p.get("plume_reachable").and_then(|v| v.as_bool()).unwrap_or(false);
    if !reachable {
        // AUTONOME (standalone) : aucune source de détection configurée -> état NORMAL et attendu (Forge
        // ne DÉPEND d'aucune source ; Plume/SIEM/IDS ne sont qu'un enrichissement optionnel), PAS une anomalie.
        if p.get("source_configured").and_then(|v| v.as_bool()) == Some(false) {
            out.push("_Aucune source de détection configurée — Forge fonctionne en autonome (standalone). \
Connectez une source (Plume / CrowdSec / FortiGate / Elastic / fichier…) pour activer la boucle purple. \
Aucune couverture n'est inventée._".into());
            out.push(String::new());
            return;
        }
        let why = p.get("error").and_then(|v| v.as_str()).unwrap_or("source de détection injoignable");
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
///   exploit est levé (validate_modules) et le scope du run écrit allow_exploit/destructive=true ;
///   l'autorisation est journalisée au ledger. Hors opt-in : comportement actuel inchangé.
async fn run_create(State(app): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    // (1) rôle opérateur fail-closed (+ contrainte source-CIDR si configurée : cf. check_operator)
    if !check_operator(&app, &headers, Some(peer.ip())) {
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
    // --auto-pentest : MODE PENTEST AUTOMATISÉ — balaie TOUTES les techniques ACTIVÉES du scope à
    // travers la surface découverte (recon -> chaînage -> oracles), gouverné À L'IDENTIQUE d'un run
    // normal (scope-guard, plancher exploit, ledger). Ne CHANGE aucun garde-fou : il ne fait qu'élargir
    // le PLAN à l'ensemble effectif du scope (le moteur le re-filtre et le ROE le gate). Défaut : false.
    let auto_pentest = body.get("auto_pentest").and_then(|v| v.as_bool()).unwrap_or(false);
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
    // GOUVERNANCE CONNECTEUR — ENFORCEMENT AU TIR : la liste des connecteurs DÉSACTIVÉS par l'opérateur
    // (enabled=0 / available_override=0) est injectée dans le scope.json du run. Le moteur la lit
    // (roe.Scope.disabled_modules) et SKIP ces kinds EXACTEMENT comme un outil absent — y compris les
    // modules choisis par le PLANNER (au-delà de `--modules`). C'est le complément indispensable au filtre
    // `--modules` ci-dessous : ensemble, ils garantissent qu'un connecteur désactivé ne tire jamais.
    let disabled_modules = operator_disabled_modules(&app);
    // SÉLECTION DE TECHNIQUES PAR-SCOPE — l'intention persistée (profil + toggles catégorie/technique)
    // est injectée dans le scope.json du run. Le moteur en RÉSOUT l'ensemble effectif
    // (resolve_enabled_kinds) et l'ENFORCE : une technique hors-profil/désactivée n'est NI planifiée NI
    // tirée (fail-closed), en plus de la gouvernance connecteur et du scope-guard. Défaut : profil
    // bug_bounty (liste qualifiante). N'altère AUCUN garde-fou de capacité (allow_* restent dictés par
    // l'opt-in haut-impact ci-dessus). Une entrée de run explicite `profile`/`categories_enabled`/
    // `techniques_enabled` dans le corps override la sélection persistée (sinon : la persistée).
    let selection = match body.get("technique_selection") {
        Some(v) if v.is_object() => validate_technique_selection(v).unwrap_or_else(|_| technique_selection_value(&app)),
        _ => technique_selection_value(&app),
    };
    let sel_profile = selection.get("profile").cloned().unwrap_or(json!("bug_bounty"));
    let sel_categories = selection.get("categories").cloned().unwrap_or(json!({}));
    let sel_techniques = selection.get("techniques").cloned().unwrap_or(json!({}));
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
        "disabled_modules": disabled_modules.clone(),
        // sélection de techniques par-scope (enforcée par le moteur : profil ∪ activations − désactivations).
        "profile": sel_profile.clone(),
        "categories_enabled": sel_categories.clone(),
        "techniques_enabled": sel_techniques.clone(),
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
    // --auto-pentest : balaie l'ensemble EFFECTIF de techniques du scope (profil + toggles). Gouverné à
    // l'identique (le scope écrit force allow_* selon l'opt-in ; le ROE gate chaque action).
    if auto_pentest { argv.push("--auto-pentest".into()); }
    // sélection de modules de l'UI -> --modules kind1,kind2 : RESTREINT le plan du moteur aux
    // kinds demandés (déjà validés : ⊆ kinds connus, web_allowed=1, ni exploit ni destructif).
    // Vide -> flag omis -> le moteur garde le plan complet du cerveau (comportement inchangé).
    // Les kinds passent la grammaire validate_modules (kind bien formé) : pas d'injection d'argv
    // (argv FIXE, aucun shell), et la gate ROE reste seule juge des capacités.
    // GOUVERNANCE CONNECTEUR — filtre au spawn : la liste passée EXCLUT tout connecteur désactivé par
    // l'opérateur (défense en profondeur ; validate_modules l'a déjà refusé, mais un désactivé n'atteint
    // JAMAIS l'argv). NB : on ne passe le flag que si la liste DEMANDÉE était non vide — une liste vidée
    // par le filtre resterait vide et NE retombe PAS en « plan complet » (validate_modules ayant refusé
    // toute demande contenant un désactivé, ce cas ne se présente pas ; le scope.json disabled_modules
    // couvre de toute façon le plan complet du planner).
    let spawn_modules = filter_enabled_modules(&app, &requested_modules);
    if !spawn_modules.is_empty() {
        argv.push("--modules".into());
        argv.push(spawn_modules.join(","));
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

    // run_job 'running' + provenance opérateur. ATTRIBUTION : on résout l'IDENTITÉ individuelle depuis
    // la session (login réel) si présente ; sinon repli rétro-compat sur 'operator' (compte bootstrap
    // env-hash ou dev-open). Le started_by encode `<login>` et, pour un run armé, `<login>+high_impact`
    // -> tout run haut-impact reste traçable au COMPTE qui l'a déclenché, sans nouvelle colonne.
    let actor = attribution_login(&app, &headers);
    let started_by = if high_impact { format!("{actor}+high_impact") } else { actor.clone() };
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
            "run_id": run_id, "campaign": campaign, "actor": actor, "by": "operator",
            "arm": arm, "reason": reason,
            "exploit_modules_authorized": hi_modules,
            "requested_modules": requested_modules,
            "allow_exploit": true, "allow_destructive": true,
            "note": "opt-in haut-impact GOUVERNÉ honoré (operator+arm+reason) ; scope-guard moteur inchangé (hors-scope = VETO)"
        }));
    }
    append_console_ledger(&app, "console.run.start", json!({
        "run_id": run_id, "campaign": campaign, "mode": mode, "actor": actor, "by": "operator",
        "targets": body.get("targets").cloned().unwrap_or(json!([])), "modules": requested_modules,
        "module_params": Value::Object(module_params.clone()),
        // gouvernance connecteur : connecteurs désactivés (skippés au tir, y compris plan planner).
        "disabled_modules": disabled_modules,
        // sélection de techniques par-scope enforcée par le moteur + mode pentest automatisé.
        "technique_selection": selection,
        "auto_pentest": auto_pentest,
        "reason": reason, "arm_requested": arm,
        "high_impact": high_impact,
        "exploit_floor": if high_impact { "lifted via governed high-impact opt-in (allow_exploit=true allow_destructive=true)" } else { "forced allow_exploit=false allow_destructive=false" }
    }));

    state.current = Some(RunHandle { run_id: run_id.clone(), pgid });
    let _ = app.events.send(RunEvent { run_id: run_id.clone(), kind: "status".into(), payload: json!({"status": "running"}) });
    drop(state); // libère le verrou FIFO avant de détacher le superviseur

    // superviseur : pompe stdout/stderr -> run_log + SSE ; watchdog timeout ; finalisation atomique.
    spawn_supervisor(app.clone(), child, run_id.clone(), run_dir);

    (StatusCode::ACCEPTED, Json(json!({"run_id": run_id, "status": "running", "campaign": campaign, "mode": mode, "high_impact": high_impact, "auto_pentest": auto_pentest})))
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
            "SELECT exploit,destructive,web_allowed,enabled,available_override FROM module WHERE kind=?",
            [m],
            |r| Ok((
                r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)? != 0, r.get::<_, Option<i64>>(4)?.map(|v| v != 0),
            )),
        );
        match row {
            Ok((exploit, destructive, web_allowed, enabled, available_override)) => {
                // GOUVERNANCE CONNECTEUR (fail-closed) : un module DÉSACTIVÉ par l'opérateur (enabled=0
                // ou available_override=0) n'est JAMAIS lançable depuis le web — MÊME sous opt-in
                // haut-impact. Désactiver un connecteur = le désinstaller opérationnellement, un cran
                // AU-DESSUS du plancher exploit : vérifié AVANT le bypass high-impact. (Un binaire
                // simplement absent, sans intention opérateur, reste accepté puis SKIP par le moteur.)
                if module_operator_disabled(enabled, available_override) {
                    return Err((StatusCode::BAD_REQUEST, Json(json!({
                        "error": "module_disabled",
                        "why": format!("module '{m}' désactivé (gouvernance connecteur) — non lançable, même armé")
                    }))));
                }
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
                "SELECT exploit,destructive,enabled,available_override FROM module WHERE kind=?",
                [m.as_str()],
                |r| Ok((
                    r.get::<_, i64>(0)?, r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)? != 0, r.get::<_, Option<i64>>(3)?.map(|v| v != 0),
                )),
            )
            // haut-impact ET effectivement activable : un connecteur exploit/destructif DÉSACTIVÉ par
            // l'opérateur ne sera pas tiré -> il ne doit pas figurer parmi les capacités « débloquées »
            // dans l'audit (ledger/run_job). Consulte `enabled`/`available_override`.
            .map(|(e, d, en, ov)| (e != 0 || d != 0) && !module_operator_disabled(en, ov))
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
async fn run_cancel(State(app): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Path(id): Path<String>) -> impl IntoResponse {
    if !check_operator(&app, &headers, Some(peer.ip())) {
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
    let actor = attribution_login(&app, &headers);
    push_run_log(&app, &id, "system", &format!("cancel demandé par '{actor}' — kill group"));
    append_console_ledger(&app, "console.run.cancel", json!({"run_id": id, "actor": actor, "by": "operator"}));
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

/// `forge-console useradd <login> <role> [--pass <pw>]` — provisionne un compte individuel.
/// Le mot de passe est lu sur STDIN (recommandé : pas de fuite argv) ; `--pass` le fournit en argv
/// (scripting). Calcule le hash argon2id et l'écrit dans `users` (upsert par login). Ouvre la base en
/// ÉCRITURE (mêmes PRAGMA que le boot) et garantit le schéma (execute_batch) avant l'insertion — la
/// sous-commande peut donc créer le 1er compte sur une base neuve. Codes : 0 OK, 2 erreur d'usage/IO.
fn run_useradd_cli(args: &[String]) -> i32 {
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let (login, role) = match (positional.first(), positional.get(1)) {
        (Some(l), Some(r)) => (l.as_str(), r.as_str()),
        _ => {
            eprintln!("usage: forge-console useradd <login> <role> [--pass <password>]   (role: viewer|operator|admin)");
            return 2;
        }
    };
    if let Err(e) = validate_login(login) {
        eprintln!("[forge-console] useradd: login invalide: {e}");
        return 2;
    }
    if let Err(e) = validate_role(role) {
        eprintln!("[forge-console] useradd: {e}");
        return 2;
    }
    // mot de passe : --pass (argv, scripting) sinon lecture sur STDIN (pas de fuite via ps).
    let pw = match cli_opt(args, "pass") {
        Some(p) => p,
        None => {
            eprintln!("[forge-console] useradd: entre le mot de passe (STDIN) :");
            use std::io::Read;
            let mut s = String::new();
            if std::io::stdin().read_to_string(&mut s).is_err() {
                eprintln!("[forge-console] useradd: lecture STDIN impossible");
                return 2;
            }
            s.trim_end_matches(['\n', '\r']).to_string()
        }
    };
    if pw.is_empty() {
        eprintln!("[forge-console] useradd: mot de passe vide refusé");
        return 2;
    }
    let db_path = cli_db_path();
    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[forge-console] useradd: ouverture de '{db_path}' impossible: {e}");
            return 2;
        }
    };
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    // garantit le schéma (table users incluse) — permet de créer le 1er compte sur une base neuve.
    if conn.execute_batch(SCHEMA).is_err() {
        eprintln!("[forge-console] useradd: initialisation du schéma impossible");
        return 2;
    }
    let hash = hash_pw(&pw);
    match upsert_user(&conn, login, role, &hash) {
        Ok(role) => {
            println!("[forge-console] compte '{login}' (role={role}) provisionné dans {db_path}");
            0
        }
        Err(e) => {
            eprintln!("[forge-console] useradd: {e}");
            2
        }
    }
}

// ===========================================================================================
// `forge-console seed-demo` — amorce la base SQLite avec l'ENGAGEMENT DE RÉFÉRENCE fourni
// (examples/reference-engagement/), pour qu'une console fraîche affiche IMMÉDIATEMENT des
// Findings / Coverage / Purple / Runs peuplés, HORS-LIGNE et sans réseau. Voie d'ingestion
// LOCALE (écrit directement dans SQLite, PAS via /api/ingest) — réutilise la MÊME dérivation
// CWE/CVSS que le handler ingest pour un résultat identique. Idempotent : purge d'abord les
// lignes de la campagne démo, puis réinsère (rejouer `seed-demo` ne duplique rien et ne touche
// AUCUNE autre campagne). Données 100 % synthétiques (TLD .example réservé) — jamais une cible réelle.
// ===========================================================================================

/// Campagne par défaut de l'engagement de référence (surchargée via `--campaign`).
const SEED_DEMO_CAMPAIGN: &str = "acme-lab";
/// run_id fixe du run synthétique de la démo (idempotence : rejouer écrase au lieu de dupliquer).
const SEED_DEMO_RUN_ID: &str = "seed-demo-acme-lab";

/// Lit un fichier JSONL en `Vec<Value>` (ignore lignes vides / commentaires `#`). `required=false`
/// -> fichier absent = liste vide (pas une erreur). Erreur lisible si une ligne n'est pas du JSON.
fn read_jsonl(path: &std::path::Path, required: bool) -> Result<Vec<Value>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            if !required && e.kind() == std::io::ErrorKind::NotFound {
                return Ok(vec![]);
            }
            return Err(format!("lecture de '{}' impossible: {e}", path.display()));
        }
    };
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => out.push(v),
            Err(e) => return Err(format!("{}:{}: JSON invalide: {e}", path.display(), i + 1)),
        }
    }
    Ok(out)
}

/// Résout le dossier de l'engagement de référence indépendamment du cwd (make lance depuis la
/// racine ; un humain peut lancer depuis console/). Ordre : `--dir` explicite, cwd/examples,
/// FORGE_PKG_DIR, ../examples, puis relatif au binaire (target/release -> racine du repo).
/// Le 1er candidat contenant `findings.jsonl` gagne ; sinon on renvoie le chemin par défaut tel quel
/// (l'appelant émettra une erreur de lecture lisible).
fn resolve_seed_dir(explicit: Option<&str>) -> std::path::PathBuf {
    let rel = std::path::Path::new("examples").join("reference-engagement");
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(d) = explicit {
        candidates.push(std::path::PathBuf::from(d));
    }
    candidates.push(rel.clone());
    if let Ok(pkg) = std::env::var("FORGE_PKG_DIR") {
        candidates.push(std::path::PathBuf::from(pkg).join(&rel));
    }
    candidates.push(std::path::Path::new("..").join(&rel));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // target/release/forge-console -> release -> target -> console -> racine du repo
            candidates.push(dir.join("..").join("..").join("..").join(&rel));
        }
    }
    for c in &candidates {
        if c.join("findings.jsonl").is_file() {
            return c.clone();
        }
    }
    // repli : 1er candidat (défaut) — l'appelant échouera proprement à la lecture.
    candidates.into_iter().next().unwrap_or(rel)
}

/// `forge-console seed-demo [--dir <path>] [--campaign <name>]` — amorce la base avec l'engagement
/// de référence fourni. Codes : 0 OK, 2 erreur (dossier/JSON/IO). Écrit directement dans SQLite.
fn run_seed_demo_cli(args: &[String]) -> i32 {
    let campaign = cli_opt(args, "campaign").unwrap_or_else(|| SEED_DEMO_CAMPAIGN.to_string());
    let dir = resolve_seed_dir(cli_opt(args, "dir").as_deref());
    let findings = match read_jsonl(&dir.join("findings.jsonl"), true) {
        Ok(v) => v,
        Err(e) => { eprintln!("[forge-console] seed-demo: {e}"); return 2; }
    };
    let runrecords = match read_jsonl(&dir.join("runrecords.jsonl"), true) {
        Ok(v) => v,
        Err(e) => { eprintln!("[forge-console] seed-demo: {e}"); return 2; }
    };
    let roe = match read_jsonl(&dir.join("roe_decisions.jsonl"), false) {
        Ok(v) => v,
        Err(e) => { eprintln!("[forge-console] seed-demo: {e}"); return 2; }
    };

    let db_path = cli_db_path();
    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => { eprintln!("[forge-console] seed-demo: ouverture de '{db_path}' impossible: {e}"); return 2; }
    };
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    if conn.execute_batch(SCHEMA).is_err() {
        eprintln!("[forge-console] seed-demo: initialisation du schéma impossible");
        return 2;
    }
    migrate(&conn); // colonnes additives (run_id, cwe/cvss, run_job C2) — requises par les INSERT ci-dessous

    // IDEMPOTENCE : purge UNIQUEMENT la campagne démo (+ son run) avant de réinsérer. N'affecte
    // aucune autre campagne réelle stockée dans la même base.
    let _ = conn.execute("DELETE FROM finding WHERE campaign=?", rusqlite::params![campaign]);
    let _ = conn.execute("DELETE FROM runrecord WHERE campaign=?", rusqlite::params![campaign]);
    let _ = conn.execute("DELETE FROM roe_decision WHERE campaign=?", rusqlite::params![campaign]);
    let _ = conn.execute("DELETE FROM run_job WHERE run_id=?", rusqlite::params![SEED_DEMO_RUN_ID]);

    // --- findings : MÊME dérivation CWE/CVSS que le handler /api/ingest (résultat identique) ---
    let mut nf = 0i64;
    for f in &findings {
        let cwe = {
            let c = gs(f, "cwe");
            if c.is_empty() { extract_cwe(&gs(f, "category")) } else { c }
        };
        let (mut cvss_vec, mut cvss_score) =
            (gs(f, "cvss_vector"), f.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0));
        if cvss_vec.is_empty() && cvss_score == 0.0 {
            let (v, s) = cvss_base_for_severity(&gs(f, "severity"));
            cvss_vec = v.to_string();
            cvss_score = s;
        }
        if let Ok(n) = conn.execute(
            "INSERT OR IGNORE INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rusqlite::params![gs(f,"ts"), campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                gs(f,"fix"), SEED_DEMO_RUN_ID, cwe, cvss_vec, cvss_score],
        ) { nf += n as i64; }
    }

    // --- run-records (fires ATT&CK) : alimentent /api/coverage ET la corrélation purple ---
    let (mut nr, mut fired_cnt) = (0i64, 0i64);
    let mut targets: Vec<String> = Vec::new();
    let mut modules: Vec<String> = Vec::new();
    for rr in &runrecords {
        let fired = if rr.get("fired").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
        let (tgt, kind) = (gs(rr, "target"), gs(rr, "kind"));
        if !tgt.is_empty() && !targets.contains(&tgt) { targets.push(tgt.clone()); }
        if !kind.is_empty() && !modules.contains(&kind) { modules.push(kind.clone()); }
        if let Ok(n) = conn.execute(
            "INSERT INTO runrecord(ts,campaign,target,kind,mitre,fired,detail,run_id) VALUES(?,?,?,?,?,?,?,?)",
            rusqlite::params![gs(rr,"ts"), campaign, tgt, kind, gs(rr,"mitre"), fired, gs(rr,"detail"), SEED_DEMO_RUN_ID],
        ) { nr += n as i64; fired_cnt += fired as i64; }
    }

    // --- décisions ROE (transparence anti-masquage : FIRE / VETO / DRY_RUN) -> /api/roe ---
    let (mut nd, mut vetoed_cnt, mut dry_run_cnt) = (0i64, 0i64, 0i64);
    for d in &roe {
        let verdict = gs(d, "verdict");
        match verdict.as_str() {
            "VETO" => vetoed_cnt += 1,
            "DRY_RUN" => dry_run_cnt += 1,
            _ => {}
        }
        let ex = if d.get("exploit").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
        let de = if d.get("destructive").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 };
        let reasons = d.get("reasons").map(|r| r.to_string()).unwrap_or_else(|| "[]".into());
        if let Ok(n) = conn.execute(
            "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons)
             VALUES(?,?,?,?,?,?,?,?,?,?)",
            rusqlite::params![gs(d,"ts"), campaign, SEED_DEMO_RUN_ID, gs(d,"action_id"), gs(d,"target"),
                gs(d,"kind"), verdict, ex, de, reasons],
        ) { nd += n as i64; }
    }

    // --- un run_job récapitulatif : alimente l'onglet Runs (compteurs cohérents avec ci-dessus) ---
    let targets_json = serde_json::to_string(&targets).unwrap_or_else(|_| "[]".into());
    let modules_json = serde_json::to_string(&modules).unwrap_or_else(|_| "[]".into());
    // lacune de couverture volontaire (defer != delete) : classe jamais tentée + action déférée budget.
    let coverage_gaps = "{\"shop.lab.example\":[\"injection.sqli\"]}";
    let skipped_budget = "[{\"kind\":\"web.xss\",\"target\":\"shop.lab.example\",\"cls\":\"xss\"}]";
    let _ = conn.execute(
        "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps,started_by,reason,targets,modules,started,finished,exit_code)
         VALUES(?,?,datetime('now'),'done','grey',?,?,?,0,?,?,'seed-demo','bundled reference engagement (synthetic lab — examples/reference-engagement)',?,?,datetime('now'),datetime('now'),0)",
        rusqlite::params![SEED_DEMO_RUN_ID, campaign, fired_cnt, dry_run_cnt, vetoed_cnt,
            skipped_budget, coverage_gaps, targets_json, modules_json],
    );

    println!("[forge-console] seed-demo : engagement de référence chargé depuis {}", dir.display());
    println!("[forge-console] base={db_path}  campagne='{campaign}'  run_id={SEED_DEMO_RUN_ID}");
    println!("[forge-console] findings={nf}  run-records={nr} (fired={fired_cnt})  roe={nd} (veto={vetoed_cnt}, dry_run={dry_run_cnt})");
    println!("[forge-console] Findings / Coverage / Runs peuplés. Pour l'onglet Purple : lance tools/mock_plume.py + PLUME_URL (voir `make demo-purple`).");
    0
}

// ===========================================================================================
// MIGRATION DE DONNÉES — importe un install Forge EXISTANT (non-Docker) vers un install
// Docker/autre. Trois volets couplés qui doivent voyager ENSEMBLE pour rester audités :
//   1) la base SQLite (findings/runs/roe/users/settings) — copie COHÉRENTE via VACUUM INTO
//      (source ouverte READ-ONLY, jamais mutée) ou export CHIFFRÉ (SQLCipher, feature opt-in) ;
//   2) le ledger JSONL d'engagement (chaîne SHA-256 tamper-evident) ;
//   3) la clé de signature sibling `.ed25519` (0600) — SANS elle, les entrées signées du ledger
//      deviennent invérifiables (la chaîne perd sa non-répudiation). La clé DOIT suivre le ledger.
// La cible reçoit ensuite SCHEMA + migrate() : une base plus ANCIENNE est upgradée EN PLACE.
// ZÉRO défaut caché : chaque chemin est explicite (pas d'IP/host/clé codés en dur). La migration
// est elle-même TRACÉE au ledger cible (kind `console.migrate`, chaîne SHA-256 continue).
// ===========================================================================================

/// Options d'une migration (partagées par la sous-commande CLI et POST /api/setup/migrate).
struct MigrateOpts {
    from: String,            // source : un DOSSIER (install) ou un FICHIER .db
    to: String,              // base cible
    ledger: Option<String>,  // ledger cible (défaut : sibling engagement.jsonl de `to`)
    verify: bool,            // recompute la chaîne SHA-256 du ledger source, ABORT sur rupture
    encrypt: bool,           // cible chiffrée SQLCipher (exige la feature `encryption`)
    key_env: Option<String>, // nom de la variable d'ENV portant la clé (JAMAIS la clé en argv)
    actor: String,           // attribution ledger ("cli:migrate" | "api:setup/migrate")
}

/// Résout (source_db, source_ledger) depuis `--from`. Un DOSSIER -> {dir}/forge-console.db +
/// {dir}/engagement.jsonl (convention d'install). Un FICHIER -> le fichier .db + son sibling
/// engagement.jsonl (même dossier). Aucune invention : si le ledger n'existe pas, la copie le note.
fn resolve_migrate_source(from: &str) -> (String, String) {
    let p = std::path::Path::new(from);
    if p.is_dir() {
        let db = p.join("forge-console.db");
        let led = p.join("engagement.jsonl");
        (db.to_string_lossy().into_owned(), led.to_string_lossy().into_owned())
    } else {
        let led = p.parent().unwrap_or_else(|| std::path::Path::new("."))
            .join("engagement.jsonl");
        (from.to_string(), led.to_string_lossy().into_owned())
    }
}

/// Chemin ledger par défaut à côté d'une base : {dir(to)}/engagement.jsonl.
fn default_sibling_ledger(to: &str) -> String {
    std::path::Path::new(to)
        .parent()
        .map(|p| p.join("engagement.jsonl"))
        .unwrap_or_else(|| std::path::PathBuf::from("engagement.jsonl"))
        .to_string_lossy()
        .into_owned()
}

// ===========================================================================================
// GARDE-FOU MIGRATION VIA API (POST /api/setup/migrate) — cet endpoint est joignable NON-AUTHENTIFIÉ
// pendant la fenêtre de setup (avant le 1er provisioning). Sans garde, `from`/`to`/`ledger` sont des
// chemins serveur ARBITRAIRES -> primitive d'écriture/suppression de fichier non-auth (traversal `..`,
// chemins absolus). DEUX couches défendent cette frontière API (la voie CLI, invocation locale de
// confiance, reste INCHANGÉE et non restreinte) :
//   COUCHE 1 — opt-in `FORGE_ALLOW_API_MIGRATE` (défaut OFF = CLI-seule) : sans le flag, l'endpoint
//              REFUSE avant toute I/O -> la primitive disparaît du déploiement par défaut.
//   COUCHE 2 — quand le flag est actif, confinement anti-traversal des chemins sous une racine
//              allowlistée (racine de données console), avec refus d'écraser une cible hors racine.
// ===========================================================================================

/// Lit un flag booléen d'ENV : `1`/`true`/`yes`/`on` (insensible à la casse) => true ; absent, vide,
/// ou toute autre valeur => false. FAIL-CLOSED : un flag mal orthographié n'active RIEN.
fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false)
}

/// Racine autorisée pour l'import/export via API (allowlist anti-traversal). Par défaut : le DOSSIER
/// parent de la base console ($FORGE_CONSOLE_DB — la racine de données), surchargeable explicitement
/// par $FORGE_CONSOLE_IMPORT_DIR (dossier de staging dédié). Un chemin de base relatif sans parent
/// (défaut `forge-console.db`) => `.` (cwd de la console). N'affecte QUE la frontière API.
fn api_migrate_base_dir() -> std::path::PathBuf {
    if let Some(d) = std::env::var("FORGE_CONSOLE_IMPORT_DIR").ok().filter(|s| !s.is_empty()) {
        return std::path::PathBuf::from(d);
    }
    let db = std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge-console.db".to_string());
    std::path::Path::new(&db)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Confine UN chemin d'import/export (frontière API) sous `base_canon` (déjà canonicalisé). Étapes :
///   1) rejet de tout composant `..` (traversal explicite) AVANT toute résolution ;
///   2) résolution : si la cible existe, canonicalise le chemin COMPLET ; sinon (to/ledger neufs)
///      canonicalise le DOSSIER PARENT (qui doit exister) puis rejoint le nom de fichier ;
///   3) confinement : le chemin résolu DOIT être SOUS `base_canon` (comparaison par composants).
///
/// `must_exist` : la source (`from`) doit exister ; une cible préexistante HORS base est REFUSÉE
/// (jamais d'écrasement/suppression hors racine). N'est appelée QUE sur la voie API (jamais la CLI).
fn validate_api_migrate_path(
    base_canon: &std::path::Path,
    raw: &str,
    label: &str,
    must_exist: bool,
) -> Result<(), String> {
    if raw.is_empty() {
        return Err(format!("chemin `{label}` vide"));
    }
    let p = std::path::Path::new(raw);
    // 1) refus de tout composant `..` (traversal) — avant même de toucher le disque.
    if p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(format!("chemin `{label}` refusé : composant `..` interdit ({raw})"));
    }
    // 2) résolution en chemin absolu réel.
    let resolved = if p.exists() {
        // existe (source, OU cible préexistante) : canonicalise le chemin complet.
        p.canonicalize()
            .map_err(|e| format!("canonicalisation de `{label}` ({raw}) impossible: {e}"))?
    } else {
        if must_exist {
            return Err(format!("source `{label}` introuvable: {raw}"));
        }
        // cible neuve : le PARENT doit exister et être sous la base ; on rejoint ensuite le nom.
        let parent = p
            .parent()
            .filter(|pp| !pp.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let parent_canon = parent
            .canonicalize()
            .map_err(|e| format!("dossier parent de `{label}` ({raw}) inexistant/illisible: {e}"))?;
        let name = p
            .file_name()
            .ok_or_else(|| format!("chemin `{label}` sans nom de fichier: {raw}"))?;
        parent_canon.join(name)
    };
    // 3) confinement sous la racine allowlistée (starts_with = comparaison PAR COMPOSANTS, pas de
    //    faux-positif "/a/bc".starts_with("/a/b")). Une cible préexistante hors base tombe ici => refus.
    if !resolved.starts_with(base_canon) {
        return Err(format!(
            "chemin `{label}` hors de la racine autorisée : {} n'est pas sous {}",
            resolved.display(),
            base_canon.display()
        ));
    }
    Ok(())
}

/// Valide `from`/`to`/`ledger` de la migration API contre la racine allowlistée ($FORGE_CONSOLE_IMPORT_DIR
/// ou la racine de données console). Résout+canonicalise la base UNE fois, puis délègue par chemin.
/// N'est appelée QUE depuis `setup_migrate` (jamais la CLI). Err(why) => la requête est refusée (403).
fn validate_api_migrate_paths(from: &str, to: &str, ledger: Option<&str>) -> Result<(), String> {
    let base = api_migrate_base_dir();
    let base_canon = base.canonicalize().map_err(|e| {
        format!(
            "racine d'import autorisée introuvable/illisible ({}): {e} — créer le dossier ou poser FORGE_CONSOLE_IMPORT_DIR",
            base.display()
        )
    })?;
    validate_api_migrate_path(&base_canon, from, "from", true)?;
    validate_api_migrate_path(&base_canon, to, "to", false)?;
    if let Some(l) = ledger {
        validate_api_migrate_path(&base_canon, l, "ledger", false)?;
    }
    Ok(())
}

/// Append UNE entrée au ledger JSONL à `path`, en (re)lisant le head depuis le disque (chaîne
/// SHA-256, alg "sha256-console", sig ""). AUTONOME (pas d'App/cache) — pour la migration one-shot :
/// une seule entrée, pas de contention. Miroir strict de append_console_ledger côté pré-image, donc
/// /api/ledger/verify recompute la chaîne SANS rupture. Renvoie le hash de la nouvelle entrée.
fn ledger_append_standalone(path: &str, kind: &str, detail: &Value) -> Result<String, String> {
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
    let seq = seq + 1;
    let ts = format!("@{}", chrono_now_compact());
    let preimage = format!("{prev}|{seq}|{ts}|{kind}|{}", canon_json(detail));
    let hash = sha_hex(&preimage);
    let rec = json!({
        "seq": seq, "ts": ts, "kind": kind, "detail": detail,
        "prev": prev, "hash": hash, "alg": "sha256-console", "sig": ""
    });
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() { let _ = std::fs::create_dir_all(parent); }
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)
        .map_err(|e| format!("ouverture ledger cible '{path}' impossible: {e}"))?;
    writeln!(f, "{}", canon_json(&rec)).map_err(|e| format!("écriture ledger cible échouée: {e}"))?;
    Ok(hash)
}

/// plaintext -> plaintext : `VACUUM INTO` (copie COHÉRENTE, fonctionne sur une source READ-ONLY).
/// La cible NE DOIT PAS préexister (VACUUM INTO refuse d'écraser) -> on retire cible + sidecars WAL/SHM
/// d'abord. Renvoie `encrypted=false`.
fn migrate_copy_plaintext(src: &Connection, target: &str) -> Result<bool, String> {
    if std::path::Path::new(target).exists() {
        std::fs::remove_file(target)
            .map_err(|e| format!("cible '{target}' déjà présente et non supprimable: {e}"))?;
    }
    let _ = std::fs::remove_file(format!("{target}-wal"));
    let _ = std::fs::remove_file(format!("{target}-shm"));
    if let Some(parent) = std::path::Path::new(target).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("création du dossier cible échouée: {e}"))?;
        }
    }
    // paramètre lié (le chemin cible n'est pas inliné dans le SQL).
    src.execute("VACUUM INTO ?1", [target])
        .map_err(|e| format!("VACUUM INTO '{target}' échoué: {e}"))?;
    Ok(false)
}

/// Résout la clé de chiffrement depuis la variable d'ENV nommée par `--key-env`. JAMAIS la clé en argv
/// (fuite via ps/historique). None si le nom est absent ou la variable vide. Gated : n'existe que dans
/// le build chiffré (dans le build par défaut, aucun code ne la référence).
#[cfg(feature = "encryption")]
fn resolve_key(key_env: Option<&str>) -> Option<String> {
    let name = key_env?;
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// plaintext -> CHIFFRÉ : attache une base cible chiffrée (PRAGMA KEY) et exporte via
/// sqlcipher_export(). Compilé UNIQUEMENT avec la feature `encryption`.
#[cfg(feature = "encryption")]
fn migrate_copy_encrypted(src: &Connection, target: &str, key_env: Option<&str>) -> Result<bool, String> {
    let key = resolve_key(key_env)
        .ok_or_else(|| "clé de chiffrement absente (--key-env non résolu / variable d'ENV vide)".to_string())?;
    if std::path::Path::new(target).exists() {
        std::fs::remove_file(target).map_err(|e| format!("cible '{target}' non supprimable: {e}"))?;
    }
    let _ = std::fs::remove_file(format!("{target}-wal"));
    let _ = std::fs::remove_file(format!("{target}-shm"));
    if let Some(parent) = std::path::Path::new(target).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("création du dossier cible échouée: {e}"))?;
        }
    }
    src.execute("ATTACH DATABASE ?1 AS encrypted KEY ?2", rusqlite::params![target, key])
        .map_err(|e| format!("ATTACH de la cible chiffrée échoué: {e}"))?;
    let export = src.query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()));
    let _ = src.execute("DETACH DATABASE encrypted", []);
    export.map_err(|e| format!("sqlcipher_export('encrypted') échoué: {e}"))?;
    Ok(true)
}

/// Build PAR DÉFAUT (sans `encryption`) : le chiffrement au repos n'est PAS compilé -> erreur CLAIRE
/// (recompiler avec `--features encryption`). Aucune dépendance SQLCipher n'est tirée par ce chemin.
#[cfg(not(feature = "encryption"))]
fn migrate_copy_encrypted(_src: &Connection, _target: &str, _key_env: Option<&str>) -> Result<bool, String> {
    Err("chiffrement au repos NON compilé dans ce build — recompiler avec `--features encryption` (SQLCipher)".to_string())
}

/// Copie le ledger JSONL source + sa clé de signature sibling `.ed25519` (et le repli HMAC `.key`)
/// dans le dossier ledger CIBLE, en PRÉSERVANT le mode 0600 de la ou des clés (la clé DOIT voyager
/// avec le ledger, sinon la chaîne signée devient invérifiable). Renvoie (ledger_copié, ed25519_copiée).
/// Ledger source absent -> ne copie rien (Ok(false,false)) : un install neuf n'a pas d'engagement.
fn copy_ledger_and_key(src_ledger: &str, target_ledger: &str) -> Result<(bool, bool), String> {
    if !std::path::Path::new(src_ledger).exists() {
        return Ok((false, false));
    }
    if std::path::Path::new(src_ledger) == std::path::Path::new(target_ledger) {
        // source == cible (upgrade en place du même dossier) : rien à copier, la clé est déjà là.
        let has_key = std::path::Path::new(&format!("{src_ledger}.ed25519")).exists();
        return Ok((true, has_key));
    }
    if let Some(parent) = std::path::Path::new(target_ledger).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("création du dossier ledger cible échouée: {e}"))?;
        }
    }
    std::fs::copy(src_ledger, target_ledger)
        .map_err(|e| format!("copie du ledger '{src_ledger}' -> '{target_ledger}' échouée: {e}"))?;
    let mut ed_copied = false;
    // clé(s) de signature sibling : <ledger>.ed25519 (Ed25519, non-répudiation) + <ledger>.key (repli HMAC).
    for ext in [".ed25519", ".key"] {
        let src_key = format!("{src_ledger}{ext}");
        if std::path::Path::new(&src_key).exists() {
            let dst_key = format!("{target_ledger}{ext}");
            std::fs::copy(&src_key, &dst_key)
                .map_err(|e| format!("copie de la clé '{src_key}' -> '{dst_key}' échouée: {e}"))?;
            // PRÉSERVE 0600 explicitement (secret de signature — jamais lisible par autrui).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dst_key, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("chmod 0600 de '{dst_key}' échoué: {e}"))?;
            }
            if ext == ".ed25519" { ed_copied = true; }
        }
    }
    Ok((true, ed_copied))
}

/// Exécute une migration complète. Étapes : (1) ouvre la source READ-ONLY (jamais mutée) ; (2) si
/// `verify`, recompute la chaîne SHA-256 du ledger source et ABORT sur une rupture réelle ; (3) copie
/// la base (VACUUM INTO plaintext | sqlcipher_export chiffré) ; (4) SCHEMA + migrate() sur la cible
/// (upgrade en place) ; (5) copie ledger + clé `.ed25519` (0600) dans le dossier ledger cible ;
/// (6) trace `console.migrate` au ledger cible (chaîne SHA-256 continue). Renvoie un rapport JSON.
fn run_migration(opts: &MigrateOpts) -> Result<Value, String> {
    let (src_db, src_ledger) = resolve_migrate_source(&opts.from);
    if !std::path::Path::new(&src_db).exists() {
        return Err(format!("base source introuvable: {src_db}"));
    }
    // (1) source en LECTURE SEULE — l'install existant n'est JAMAIS modifié par la migration.
    let src = Connection::open_with_flags(
        &src_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("ouverture read-only de '{src_db}' impossible: {e}"))?;
    let _ = src.busy_timeout(std::time::Duration::from_secs(5));

    // (2) --verify : recompute la chaîne du ledger source. ABORT AVANT toute écriture cible si une
    // rupture RÉELLE est détectée (le fichier existe mais la chaîne est cassée). Un ledger ABSENT
    // n'est pas une rupture (install neuf) -> on continue (rien à copier).
    let verify_report = if opts.verify {
        let v = verify_ledger_chain(&src_ledger);
        if v.exists && !v.ok {
            return Err(format!(
                "ledger source rompu (seq={}) : {} — migration AVORTÉE (aucune écriture)",
                v.broken, v.why.clone().unwrap_or_default()
            ));
        }
        Some(ledger_verify_api_json(&v, &src_ledger))
    } else {
        None
    };

    // (3) copie de la base.
    let encrypted = if opts.encrypt {
        migrate_copy_encrypted(&src, &opts.to, opts.key_env.as_deref())?
    } else {
        migrate_copy_plaintext(&src, &opts.to)?
    };
    drop(src); // libère la connexion read-only avant d'ouvrir la cible en écriture.

    // (4) SCHEMA + migrate() sur la cible : une base plus ANCIENNE est upgradée EN PLACE.
    {
        let dst = Connection::open(&opts.to)
            .map_err(|e| format!("ouverture de la cible '{}' impossible: {e}", opts.to))?;
        // cible chiffrée : PRAGMA key AVANT tout statement (sinon SQLCipher lit une base illisible).
        #[cfg(feature = "encryption")]
        if opts.encrypt {
            if let Some(k) = resolve_key(opts.key_env.as_deref()) {
                let _ = dst.pragma_update(None, "key", &k);
            }
        }
        let _ = dst.busy_timeout(std::time::Duration::from_secs(5));
        dst.execute_batch(SCHEMA).map_err(|e| format!("SCHEMA sur la cible échoué: {e}"))?;
        migrate(&dst);
    }

    // (5) copie du ledger + de la clé de signature .ed25519 (0600) dans le dossier ledger cible.
    let target_ledger = opts.ledger.clone().unwrap_or_else(|| default_sibling_ledger(&opts.to));
    let (ledger_copied, key_copied) = copy_ledger_and_key(&src_ledger, &target_ledger)?;

    // (6) trace la migration au ledger CIBLE (mutation ledgerisée, chaîne SHA-256 continue). JAMAIS
    // la clé/le secret — seulement les chemins + booléens. Best-effort : une erreur d'écriture du
    // ledger ne défait pas la copie DB déjà réalisée (la migration reste utilisable).
    let detail = json!({
        "actor": opts.actor, "from": opts.from, "source_db": src_db, "target_db": opts.to,
        "encrypted": encrypted, "verified": opts.verify,
        "ledger_copied": ledger_copied, "key_copied": key_copied,
    });
    let migrate_hash = ledger_append_standalone(&target_ledger, "console.migrate", &detail).ok();

    Ok(json!({
        "ok": true,
        "source_db": src_db,
        "target_db": opts.to,
        "target_ledger": target_ledger,
        "encrypted": encrypted,
        "ledger_copied": ledger_copied,
        "key_copied": key_copied,
        "migrate_ledger_hash": migrate_hash,
        "verify": verify_report,
    }))
}

/// Applique la clé SQLCipher AU REPOS au BOOT si `FORGE_DB_KEY` est posé. `PRAGMA key` DOIT précéder
/// toute autre requête sur la connexion (contrat SQLCipher). Compilé UNIQUEMENT avec `encryption` :
/// dans le build par défaut, ce hook n'existe pas et la base reste en clair (inchangé).
#[cfg(feature = "encryption")]
fn apply_db_key_on_boot(conn: &Connection) {
    if let Ok(key) = std::env::var("FORGE_DB_KEY") {
        if !key.is_empty() {
            // la clé est passée telle quelle -> SQLCipher en dérive la clé de chiffrement (KDF).
            let _ = conn.pragma_update(None, "key", &key);
        }
    }
}

/// `forge-console migrate --from <dir|db> --to <db> [--ledger <path>] [--verify]
///                        [--encrypt --key-env <ENVVAR>]`
/// Migre un install Forge existant vers une base cible. UX PRIMAIRE (documentée) : lancée dans un
/// conteneur one-shot au 1er déploiement Docker. Codes : 0 OK, 1 échec migration/vérif, 2 usage.
fn run_migrate_cli(args: &[String]) -> i32 {
    let from = match cli_opt(args, "from") {
        Some(f) if !f.is_empty() => f,
        _ => {
            eprintln!("usage: forge-console migrate --from <dir|db> --to <db> [--ledger <path>] [--verify] [--encrypt --key-env <ENVVAR>]");
            return 2;
        }
    };
    let to = match cli_opt(args, "to") {
        Some(t) if !t.is_empty() => t,
        _ => {
            eprintln!("[forge-console] migrate: --to <db> requis");
            return 2;
        }
    };
    let encrypt = cli_flag(args, "encrypt");
    let key_env = cli_opt(args, "key-env");
    if encrypt && !cfg!(feature = "encryption") {
        eprintln!("[forge-console] migrate: --encrypt demandé mais ce build n'inclut PAS le chiffrement au repos (recompiler avec `--features encryption`)");
        return 2;
    }
    if encrypt && key_env.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
        eprintln!("[forge-console] migrate: --encrypt exige --key-env <ENVVAR> (nom de la variable d'ENV portant la clé)");
        return 2;
    }
    let opts = MigrateOpts {
        from,
        to,
        ledger: cli_opt(args, "ledger"),
        verify: cli_flag(args, "verify"),
        encrypt,
        key_env,
        actor: "cli:migrate".to_string(),
    };
    match run_migration(&opts) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into()));
            if let Some(v) = report.get("verify").filter(|v| !v.is_null()) {
                println!(
                    "[forge-console] migrate: ledger source vérifié — ok={}, entries={}",
                    v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
                    v.get("entries").and_then(|x| x.as_u64()).unwrap_or(0)
                );
            }
            println!(
                "[forge-console] migrate: OK — {} -> {} (ledger cible: {})",
                report.get("source_db").and_then(|x| x.as_str()).unwrap_or(""),
                opts.to,
                report.get("target_ledger").and_then(|x| x.as_str()).unwrap_or("")
            );
            0
        }
        Err(e) => {
            eprintln!("[forge-console] migrate: {e}");
            1
        }
    }
}

// ===========================================================================================
// SAUVEGARDE / RESTAURATION CHIFFRÉE — `forge-console backup` / `forge-console restore`.
//
// Une archive de sauvegarde regroupe TROIS actifs sensibles couplés (mêmes trois que la migration) :
//   1) un snapshot COHÉRENT de la base SQLite (VACUUM INTO — copie défragmentée d'une source READ-ONLY) ;
//   2) le ledger JSONL d'engagement (chaîne SHA-256 tamper-evident) ;
//   3) la clé de signature `.ed25519` (0600) — SANS elle, la chaîne signée devient invérifiable.
// La clé privée de signature ET la base voyagent DANS l'archive -> l'archive est TOUJOURS chiffrée :
// il n'existe AUCUN chemin de sortie en clair. Une passphrase est OBLIGATOIRE (fail-closed si absente).
//
// CRYPTO (pur Rust, aucune dép C) :
//   passphrase --argon2id(salt 16o aléatoire)--> clé 32o --XChaCha20-Poly1305(nonce 24o aléatoire)-->
//   ciphertext authentifié. L'en-tête (magic|version|params argon2|salt|nonce) est écrit EN CLAIR
//   devant le ciphertext ET lié comme DONNÉE ASSOCIÉE (AAD) de l'AEAD : altérer l'en-tête OU le corps
//   fait échouer le tag Poly1305. La passphrase / la clé dérivée ne sont JAMAIS stockées/loggées/ledgerisées.
//
// INTÉGRITÉ : la chaîne du ledger est vérifiée AVANT le backup (abort sur rupture) et APRÈS le restore ;
// chaque fichier porte son sha256 dans `manifest.json`, re-vérifié au restore. Le restore REFUSE
// d'écraser un install non vide sans `--force`. Chaque backup/restore est TRACÉ au ledger (métadonnées
// seules — jamais la passphrase/clé). Voie CLI = invocation locale de confiance (admin-gated par l'accès hôte).
// ===========================================================================================

const BACKUP_MAGIC: &[u8; 8] = b"FORGEBK1"; // repère de format (8 octets) — "FORGE backup v1"
const BACKUP_VERSION: u8 = 1; // version du format d'en-tête/archive
const BACKUP_SCHEMA_VERSION: u64 = 1; // version du schéma du manifest.json (contenu logique)
const BACKUP_KEY_LEN: usize = 32; // clé AEAD dérivée (XChaCha20-Poly1305 exige 32 octets)
const BACKUP_SALT_LEN: usize = 16; // sel argon2id (aléatoire par archive)
const BACKUP_NONCE_LEN: usize = 24; // nonce XChaCha20 (24 octets — grande marge anti-collision)
// noms d'entrée canoniques dans l'archive tar.
const BACKUP_ENTRY_MANIFEST: &str = "manifest.json";
const BACKUP_ENTRY_DB: &str = "db.sqlite";
const BACKUP_ENTRY_LEDGER: &str = "engagement.jsonl";
const BACKUP_ENTRY_KEY: &str = "signing.ed25519";

/// sha256 hex d'un buffer d'octets (les fichiers de l'archive ne sont pas forcément UTF-8 -> on ne
/// peut pas réutiliser sha_hex(&str)). Réutilise le même hex(...) que le reste de la console.
fn sha256_hex_bytes(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex(&h.finalize())
}

/// Valide les paramètres argon2id (m/t/p) issus d'un EN-TÊTE — qui est MALLÉABLE avant authentification
/// (la clé dérive AVANT la vérif du tag AEAD -> impossible d'authentifier les params d'abord). Bornes
/// délibérément CONSERVATRICES, bien en-deçà des limites u32 : un en-tête corrompu/malveillant produit
/// alors une Err PROPRE au lieu d'un panic (multiply-overflow en debug) ou d'une allocation démesurée
/// (release) — pas de DoS. Nos archives n'écrivent QUE les params argon2 par défaut (petits), donc une
/// archive légitime passe toujours.
fn backup_validate_kdf_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<(), String> {
    if !(8..=4_194_304).contains(&m_cost) {
        return Err(format!("m_cost argon2 hors bornes sûres: {m_cost}"));
    }
    if !(1..=16_384).contains(&t_cost) {
        return Err(format!("t_cost argon2 hors bornes sûres: {t_cost}"));
    }
    if !(1..=16_777_215).contains(&p_cost) {
        return Err(format!("p_cost argon2 hors bornes sûres: {p_cost}"));
    }
    Ok(())
}

/// Dérive une clé AEAD 32o depuis une passphrase + un sel, avec argon2id (Algorithme id, v0x13) aux
/// paramètres passés (m/t/p) — DÉTERMINISTE : mêmes (passphrase, sel, params) -> même clé (indispensable
/// pour re-dériver au restore). PUR : aucune I/O, aucun log. La clé n'est jamais renvoyée à l'appelant
/// au-delà du buffer 32o (jamais ledgerisée/loggée).
fn backup_derive_key(passphrase: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<[u8; BACKUP_KEY_LEN], String> {
    backup_validate_kdf_params(m_cost, t_cost, p_cost)?; // évite panic/DoS sur params d'en-tête malléables
    let params = Params::new(m_cost, t_cost, p_cost, Some(BACKUP_KEY_LEN))
        .map_err(|e| format!("paramètres argon2 invalides: {e}"))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; BACKUP_KEY_LEN];
    a.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("dérivation argon2id échouée: {e}"))?;
    Ok(key)
}

/// Sérialise l'en-tête d'archive EN CLAIR (auto-descriptif, lié comme AAD de l'AEAD) :
///   magic(8) | version(1) | m_cost(4 LE) | t_cost(4 LE) | p_cost(4 LE) | salt_len(1) | salt | nonce_len(1) | nonce
fn backup_build_header(m_cost: u32, t_cost: u32, p_cost: u32, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(8 + 1 + 12 + 1 + salt.len() + 1 + nonce.len());
    h.extend_from_slice(BACKUP_MAGIC);
    h.push(BACKUP_VERSION);
    h.extend_from_slice(&m_cost.to_le_bytes());
    h.extend_from_slice(&t_cost.to_le_bytes());
    h.extend_from_slice(&p_cost.to_le_bytes());
    h.push(salt.len() as u8);
    h.extend_from_slice(salt);
    h.push(nonce.len() as u8);
    h.extend_from_slice(nonce);
    h
}

/// Params argon2id extraits d'un en-tête + longueur totale de l'en-tête (offset du ciphertext).
struct BackupHeader {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: [u8; BACKUP_SALT_LEN],
    nonce: [u8; BACKUP_NONCE_LEN],
    header_len: usize,
}

/// Parse+valide l'en-tête en tête d'archive. Rejette un magic/version inconnus et tout troncage.
/// N'effectue AUCUN déchiffrement (juste la structure) — l'authenticité est prouvée par le tag AEAD.
fn backup_parse_header(archive: &[u8]) -> Result<BackupHeader, String> {
    if archive.len() < 8 || &archive[0..8] != BACKUP_MAGIC {
        return Err("magic invalide — ce fichier n'est pas une archive Forge backup".to_string());
    }
    let mut o = 8usize;
    let ver = *archive.get(o).ok_or_else(|| "en-tête tronqué (version)".to_string())?;
    o += 1;
    if ver != BACKUP_VERSION {
        return Err(format!("version d'archive non supportée: {ver} (attendu {BACKUP_VERSION})"));
    }
    let rd_u32 = |a: &[u8], off: usize| -> Result<u32, String> {
        let s = a.get(off..off + 4).ok_or_else(|| "en-tête tronqué (paramètres argon2)".to_string())?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    let m_cost = rd_u32(archive, o)?; o += 4;
    let t_cost = rd_u32(archive, o)?; o += 4;
    let p_cost = rd_u32(archive, o)?; o += 4;
    let salt_len = *archive.get(o).ok_or_else(|| "en-tête tronqué (salt_len)".to_string())? as usize;
    o += 1;
    if salt_len != BACKUP_SALT_LEN {
        return Err(format!("longueur de sel inattendue: {salt_len} (attendu {BACKUP_SALT_LEN})"));
    }
    let salt_slice = archive.get(o..o + salt_len).ok_or_else(|| "en-tête tronqué (sel)".to_string())?;
    let mut salt = [0u8; BACKUP_SALT_LEN];
    salt.copy_from_slice(salt_slice);
    o += salt_len;
    let nonce_len = *archive.get(o).ok_or_else(|| "en-tête tronqué (nonce_len)".to_string())? as usize;
    o += 1;
    if nonce_len != BACKUP_NONCE_LEN {
        return Err(format!("longueur de nonce inattendue: {nonce_len} (attendu {BACKUP_NONCE_LEN})"));
    }
    let nonce_slice = archive.get(o..o + nonce_len).ok_or_else(|| "en-tête tronqué (nonce)".to_string())?;
    let mut nonce = [0u8; BACKUP_NONCE_LEN];
    nonce.copy_from_slice(nonce_slice);
    o += nonce_len;
    Ok(BackupHeader { m_cost, t_cost, p_cost, salt, nonce, header_len: o })
}

/// Chiffre `plaintext` (l'archive tar) : génère sel+nonce CSPRNG, dérive la clé argon2id, chiffre en
/// XChaCha20-Poly1305 avec l'en-tête lié en AAD. Renvoie header || ciphertext‖tag. Passphrase vide
/// REFUSÉE (fail-closed). Il n'existe PAS de variante non chiffrée.
fn backup_encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    if passphrase.is_empty() {
        return Err("passphrase vide — refus de chiffrer (fail-closed)".to_string());
    }
    // paramètres argon2 par DÉFAUT du crate (auto-descriptifs dans l'en-tête -> re-dérivables au restore).
    let dp = Params::default();
    let (m_cost, t_cost, p_cost) = (dp.m_cost(), dp.t_cost(), dp.p_cost());
    let mut salt = [0u8; BACKUP_SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| format!("CSPRNG (sel) indisponible: {e}"))?;
    let mut nonce = [0u8; BACKUP_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("CSPRNG (nonce) indisponible: {e}"))?;
    let mut key = backup_derive_key(passphrase, &salt, m_cost, t_cost, p_cost)?;
    let header = backup_build_header(m_cost, t_cost, p_cost, &salt, &nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("clé AEAD invalide: {e}"))?;
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &header })
        .map_err(|_| "chiffrement AEAD échoué".to_string())?;
    // hygiène : efface la clé dérivée du stack dès qu'elle n'est plus nécessaire (le cipher en détient
    // sa propre copie interne, zeroizée à son Drop). La clé n'a JAMAIS quitté ce périmètre.
    for b in key.iter_mut() { *b = 0; }
    let mut out = header;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Déchiffre une archive produite par backup_encrypt. Parse l'en-tête, re-dérive la clé, vérifie le tag
/// AEAD (en-tête en AAD). Une MAUVAISE passphrase OU un octet altéré (en-tête ou corps) => Err propre
/// (tag Poly1305 invalide) — l'appelant n'écrit alors RIEN. Passphrase vide REFUSÉE (fail-closed).
fn backup_decrypt(archive: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    if passphrase.is_empty() {
        return Err("passphrase vide — refus de déchiffrer (fail-closed)".to_string());
    }
    let hdr = backup_parse_header(archive)?;
    let header = &archive[..hdr.header_len];
    let ct = &archive[hdr.header_len..];
    let mut key = backup_derive_key(passphrase, &hdr.salt, hdr.m_cost, hdr.t_cost, hdr.p_cost)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("clé AEAD invalide: {e}"))?;
    let pt = cipher
        .decrypt(XNonce::from_slice(&hdr.nonce), Payload { msg: ct, aad: header })
        .map_err(|_| "déchiffrement AEAD échoué — mauvaise passphrase ou archive altérée (tag invalide)".to_string());
    for b in key.iter_mut() { *b = 0; }
    pt
}

/// Construit une archive tar (pur Rust) à partir d'entrées (nom, octets) — mode 0600, mtime 0 (sortie
/// déterministe). L'ordre des entrées est préservé. Renvoie les octets tar bruts (avant chiffrement).
fn backup_build_tar(files: &[(&str, &[u8])]) -> Result<Vec<u8>, String> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o600);
        header.set_mtime(0);
        // append_data pose le chemin PUIS recalcule le checksum de l'en-tête tar (cksum interne).
        builder
            .append_data(&mut header, name, *data)
            .map_err(|e| format!("écriture de l'entrée tar '{name}' échouée: {e}"))?;
    }
    builder.into_inner().map_err(|e| format!("finalisation de l'archive tar échouée: {e}"))
}

/// Extrait toutes les entrées d'une archive tar en mémoire (nom -> octets). Aucune écriture disque.
fn backup_extract_tar(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    use std::io::Read;
    let mut ar = tar::Archive::new(std::io::Cursor::new(bytes));
    let mut out = Vec::new();
    let iter = ar.entries().map_err(|e| format!("lecture de l'archive tar impossible: {e}"))?;
    for entry in iter {
        let mut e = entry.map_err(|e| format!("entrée tar illisible: {e}"))?;
        let path = e
            .path()
            .map_err(|e| format!("chemin d'entrée tar illisible: {e}"))?
            .to_string_lossy()
            .into_owned();
        let mut buf = Vec::new();
        e.read_to_end(&mut buf).map_err(|e| format!("lecture du contenu tar '{path}' échouée: {e}"))?;
        out.push((path, buf));
    }
    Ok(out)
}

/// Assemble le PLAINTEXT de l'archive (tar) : manifest.json (schéma+timestamp optionnel+sha256 par
/// fichier) EN PREMIER, puis db.sqlite (toujours), puis engagement.jsonl et signing.ed25519 s'ils
/// existent. `ts` = timestamp passé-en-argument ou OMIS (jamais inventé). Renvoie les octets tar.
fn backup_build_archive(
    db_snapshot: &[u8],
    ledger: Option<&[u8]>,
    key: Option<&[u8]>,
    ts: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut files_meta = serde_json::Map::new();
    // db toujours présent.
    files_meta.insert(
        BACKUP_ENTRY_DB.to_string(),
        json!({"sha256": sha256_hex_bytes(db_snapshot), "size": db_snapshot.len()}),
    );
    if let Some(l) = ledger {
        files_meta.insert(
            BACKUP_ENTRY_LEDGER.to_string(),
            json!({"sha256": sha256_hex_bytes(l), "size": l.len()}),
        );
    }
    if let Some(k) = key {
        files_meta.insert(
            BACKUP_ENTRY_KEY.to_string(),
            json!({"sha256": sha256_hex_bytes(k), "size": k.len()}),
        );
    }
    let mut manifest = json!({
        "kind": "forge-console-backup",
        "schema": BACKUP_SCHEMA_VERSION,
        "cipher": "xchacha20poly1305",
        "kdf": "argon2id",
        "files": Value::Object(files_meta),
    });
    if let Some(t) = ts {
        manifest["created_at"] = json!(t);
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("sérialisation du manifest échouée: {e}"))?;

    let mut entries: Vec<(&str, &[u8])> = vec![
        (BACKUP_ENTRY_MANIFEST, manifest_bytes.as_slice()),
        (BACKUP_ENTRY_DB, db_snapshot),
    ];
    if let Some(l) = ledger { entries.push((BACKUP_ENTRY_LEDGER, l)); }
    if let Some(k) = key { entries.push((BACKUP_ENTRY_KEY, k)); }
    backup_build_tar(&entries)
}

/// Écrit `data` à `path` de façon quasi-atomique : écrit un fichier temporaire sibling puis rename().
/// Crée le dossier parent si nécessaire. `mode` (unix) appliqué au fichier final (ex: 0600 pour la clé).
fn backup_write_atomic(path: &str, data: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("création du dossier de '{path}' échouée: {e}"))?;
        }
    }
    let tmp = format!("{path}.forge-tmp-{}", std::process::id());
    std::fs::write(&tmp, data).map_err(|e| format!("écriture de '{tmp}' échouée: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {mode:o} de '{tmp}' échoué: {e}"))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("renommage de '{tmp}' -> '{path}' échoué: {e}")
    })?;
    Ok(())
}

/// Vrai si un fichier existe ET est non vide (taille > 0). Sert la garde anti-écrasement du restore.
fn path_exists_nonempty(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_file() && m.len() > 0).unwrap_or(false)
}

/// Options d'une sauvegarde (partagées CLI/coeur).
struct BackupOpts {
    out: String,             // chemin de l'archive chiffrée à écrire
    passphrase: String,      // passphrase EN CLAIR (déjà lue depuis l'ENV — jamais depuis argv)
    db: String,              // base source
    ledger: Option<String>,  // ledger source (défaut : sibling engagement.jsonl de `db`)
    ts: Option<String>,      // timestamp du manifest (ou OMIS)
    actor: String,           // attribution ledger ("cli:backup")
}

/// CŒUR d'une sauvegarde, SANS la trace ledger finale. Étapes : (a) VÉRIFIE la chaîne du ledger —
/// ABORT sur rupture ; (b) snapshot COHÉRENT de la base (VACUUM INTO, source READ-ONLY) ; (c) archive
/// tar {manifest, db, ledger, clé} ; (d) CHIFFRE (argon2id + XChaCha20-Poly1305) -> écrit l'archive.
/// Renvoie `(rapport, detail_a_tracer)` : le `detail` est ce que l'appelant DOIT ledgeriser
/// (`console.backup`, métadonnées SEULES — JAMAIS la passphrase/clé). Séparer la trace permet à
/// l'appelant LIVE (serveur) de la router via `append_console_ledger` (verrou + cache du head) plutôt
/// que `ledger_append_standalone`, ce qui éviterait de DÉSYNCHRONISER le cache du head ledger de l'App.
/// La voie CLI (offline) réutilise `run_backup` (ci-dessous) qui trace en standalone.
fn run_backup_core(opts: &BackupOpts) -> Result<(Value, Value), String> {
    if opts.passphrase.is_empty() {
        return Err("passphrase absente — une passphrase est OBLIGATOIRE (fail-closed)".to_string());
    }
    if !std::path::Path::new(&opts.db).exists() {
        return Err(format!("base source introuvable: {}", opts.db));
    }
    let ledger_path = opts.ledger.clone().unwrap_or_else(|| default_sibling_ledger(&opts.db));

    // (a) VÉRIF chaîne ledger AVANT tout — un ledger présent mais rompu AVORTE (aucune archive écrite).
    // Un ledger ABSENT n'est pas une rupture (install neuf, rien à inclure) -> on continue.
    let v = verify_ledger_chain(&ledger_path);
    if v.exists && !v.ok {
        return Err(format!(
            "ledger rompu (seq={}) : {} — backup AVORTÉ (aucune archive écrite)",
            v.broken,
            v.why.clone().unwrap_or_default()
        ));
    }

    // (b) snapshot COHÉRENT de la base via VACUUM INTO (réutilise la primitive de migration) dans un
    // fichier temporaire sibling de l'archive, lu en mémoire puis supprimé.
    let snap = format!("{}.forge-snap-{}", opts.out, std::process::id());
    {
        let src = Connection::open_with_flags(
            &opts.db,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| format!("ouverture read-only de '{}' impossible: {e}", opts.db))?;
        let _ = src.busy_timeout(std::time::Duration::from_secs(5));
        migrate_copy_plaintext(&src, &snap)?; // VACUUM INTO (source jamais mutée)
    }
    let db_snapshot = std::fs::read(&snap).map_err(|e| format!("lecture du snapshot '{snap}' échouée: {e}"));
    // nettoyage du temporaire quel que soit le résultat de lecture.
    let _ = std::fs::remove_file(&snap);
    let _ = std::fs::remove_file(format!("{snap}-wal"));
    let _ = std::fs::remove_file(format!("{snap}-shm"));
    let db_snapshot = db_snapshot?;

    // (c) lit ledger + clé de signature (verbatim) s'ils existent.
    let ledger_bytes = if std::path::Path::new(&ledger_path).exists() {
        Some(std::fs::read(&ledger_path).map_err(|e| format!("lecture du ledger '{ledger_path}' échouée: {e}"))?)
    } else {
        None
    };
    let key_path = format!("{ledger_path}.ed25519");
    let key_bytes = if std::path::Path::new(&key_path).exists() {
        Some(std::fs::read(&key_path).map_err(|e| format!("lecture de la clé '{key_path}' échouée: {e}"))?)
    } else {
        None
    };

    let plaintext = backup_build_archive(
        &db_snapshot,
        ledger_bytes.as_deref(),
        key_bytes.as_deref(),
        opts.ts.as_deref(),
    )?;

    // (d) CHIFFREMENT OBLIGATOIRE (aucun chemin en clair) puis écriture atomique de l'archive.
    let sealed = backup_encrypt(&plaintext, &opts.passphrase)?;
    backup_write_atomic(&opts.out, &sealed, 0o600)?;

    // `detail` à TRACER par l'appelant (métadonnées SEULES — jamais passphrase/clé). L'archive reflète
    // l'état AVANT cette entrée (point-in-time propre : le fichier ledger est lu plus haut, avant tout
    // append). `archive_sha256` = empreinte de l'archive scellée (traçabilité offsite).
    let detail = json!({
        "actor": opts.actor,
        "db": opts.db,
        "ledger": ledger_path,
        "out": opts.out,
        "db_sha256": sha256_hex_bytes(&db_snapshot),
        "archive_bytes": sealed.len(),
        "archive_sha256": sha256_hex_bytes(&sealed),
        "included": {"db": true, "ledger": ledger_bytes.is_some(), "key": key_bytes.is_some()},
        "encrypted": true,
        "cipher": "xchacha20poly1305",
        "kdf": "argon2id",
    });

    let report = json!({
        "ok": true,
        "out": opts.out,
        "db": opts.db,
        "ledger": ledger_path,
        "archive_bytes": sealed.len(),
        "archive_sha256": sha256_hex_bytes(&sealed),
        "db_sha256": sha256_hex_bytes(&db_snapshot),
        "included_ledger": ledger_bytes.is_some(),
        "included_key": key_bytes.is_some(),
        "encrypted": true,
    });
    Ok((report, detail))
}

/// Sauvegarde CLI/offline : exécute `run_backup_core` PUIS trace `console.backup` au ledger via
/// `ledger_append_standalone` (relit le head à froid — pas d'App live à désynchroniser). Renvoie le
/// rapport enrichi de `backup_ledger_hash`. Comportement historique préservé (voie CLI de confiance).
fn run_backup(opts: &BackupOpts) -> Result<Value, String> {
    let (mut report, detail) = run_backup_core(opts)?;
    let ledger_path = report.get("ledger").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let backup_hash = if !ledger_path.is_empty() {
        ledger_append_standalone(&ledger_path, "console.backup", &detail).ok()
    } else {
        None
    };
    report["backup_ledger_hash"] = json!(backup_hash);
    Ok(report)
}

/// Options d'une restauration (partagées CLI/coeur).
struct RestoreOpts {
    input: String,           // archive chiffrée à lire
    passphrase: String,      // passphrase EN CLAIR (déjà lue depuis l'ENV)
    to: Option<String>,      // base cible (défaut : FORGE_CONSOLE_DB / forge-console.db)
    ledger: Option<String>,  // ledger cible (défaut : sibling engagement.jsonl de la base)
    force: bool,             // autorise l'écrasement d'un install existant NON VIDE
    actor: String,           // attribution ledger ("cli:restore")
}

/// Exécute une restauration. Étapes : (1) DÉCHIFFRE (mauvaise passphrase / archive altérée => Err propre,
/// RIEN écrit) ; (2) extrait le tar ; (3) VÉRIFIE le sha256 de chaque fichier du manifest ; (4) re-VÉRIFIE
/// la chaîne du ledger extrait ; (5) REFUSE d'écraser un install non vide sans `--force` ; (6) place
/// db/ledger/clé (clé en 0600) verbatim ; (7) re-vérifie la chaîne APRÈS placement ; trace `console.restore`
/// (métadonnées seules). La clé voyage TOUJOURS à côté du ledger.
fn run_restore(opts: &RestoreOpts) -> Result<Value, String> {
    if opts.passphrase.is_empty() {
        return Err("passphrase absente — une passphrase est OBLIGATOIRE (fail-closed)".to_string());
    }
    let archive = std::fs::read(&opts.input)
        .map_err(|e| format!("lecture de l'archive '{}' impossible: {e}", opts.input))?;

    // (1) DÉCHIFFREMENT — échec (passphrase/altération) AVANT toute écriture disque => rien n'est touché.
    let plaintext = backup_decrypt(&archive, &opts.passphrase)?;
    // (2) extraction en mémoire (aucune écriture cible pour l'instant).
    let entries = backup_extract_tar(&plaintext)?;
    let get = |name: &str| entries.iter().find(|(n, _)| n == name).map(|(_, b)| b.as_slice());

    // (3) manifest + vérif sha256 de CHAQUE fichier listé.
    let manifest_bytes = get(BACKUP_ENTRY_MANIFEST)
        .ok_or_else(|| "manifest.json absent de l'archive".to_string())?;
    let manifest: Value = serde_json::from_slice(manifest_bytes)
        .map_err(|e| format!("manifest.json illisible: {e}"))?;
    let files = manifest
        .get("files")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "manifest.json : section `files` absente ou invalide".to_string())?;
    for (fname, meta) in files {
        let expected = meta
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("manifest : sha256 manquant pour '{fname}'"))?;
        let data = get(fname)
            .ok_or_else(|| format!("fichier '{fname}' listé au manifest mais ABSENT de l'archive"))?;
        let actual = sha256_hex_bytes(data);
        if actual != expected {
            return Err(format!(
                "sha256 mismatch pour '{fname}' — archive altérée (attendu {expected}, calculé {actual})"
            ));
        }
    }

    let db_data = get(BACKUP_ENTRY_DB).ok_or_else(|| "db.sqlite absent de l'archive".to_string())?;
    let ledger_data = get(BACKUP_ENTRY_LEDGER);
    let key_data = get(BACKUP_ENTRY_KEY);

    // destinations.
    let db_dst = opts.to.clone().unwrap_or_else(cli_db_path);
    let ledger_dst = opts.ledger.clone().unwrap_or_else(|| default_sibling_ledger(&db_dst));
    let key_dst = format!("{ledger_dst}.ed25519");

    // (4) re-VÉRIF de la chaîne du ledger EXTRAIT (intégrité) — via un temporaire, AVANT tout placement.
    if let Some(l) = ledger_data {
        let tmpv = format!("{ledger_dst}.forge-verify-{}", std::process::id());
        std::fs::write(&tmpv, l).map_err(|e| format!("écriture temp de vérif ledger échouée: {e}"))?;
        let vext = verify_ledger_chain(&tmpv);
        let _ = std::fs::remove_file(&tmpv);
        if vext.exists && !vext.ok {
            return Err(format!(
                "ledger de l'archive rompu (seq={}) : {} — restore AVORTÉ (rien écrit)",
                vext.broken,
                vext.why.clone().unwrap_or_default()
            ));
        }
    }

    // (5) GARDE anti-écrasement : une base OU un ledger cible NON VIDE bloque sans `--force`.
    if !opts.force && (path_exists_nonempty(&db_dst) || path_exists_nonempty(&ledger_dst)) {
        return Err(format!(
            "install existant NON VIDE ({db_dst} / {ledger_dst}) — restore REFUSÉ sans --force (aucune écriture)"
        ));
    }

    // (6) placement verbatim. DB : purge des sidecars WAL/SHM potentiellement périmés avant d'écrire.
    let _ = std::fs::remove_file(format!("{db_dst}-wal"));
    let _ = std::fs::remove_file(format!("{db_dst}-shm"));
    backup_write_atomic(&db_dst, db_data, 0o600)?;
    if let Some(l) = ledger_data {
        backup_write_atomic(&ledger_dst, l, 0o644)?;
    }
    // la clé DOIT voyager avec le ledger — placée en 0600 (secret de signature).
    if let Some(k) = key_data {
        backup_write_atomic(&key_dst, k, 0o600)?;
    }

    // (7) re-VÉRIF de la chaîne APRÈS placement (intégrité restaurée), PUIS trace `console.restore`.
    let restore_hash = if ledger_data.is_some() {
        let vplaced = verify_ledger_chain(&ledger_dst);
        if vplaced.exists && !vplaced.ok {
            return Err(format!(
                "ledger restauré invérifiable après placement (seq={}) : {}",
                vplaced.broken,
                vplaced.why.clone().unwrap_or_default()
            ));
        }
        // TRACE (métadonnées SEULES — jamais passphrase/clé) : continue la chaîne du ledger restauré.
        let detail = json!({
            "actor": opts.actor,
            "input": opts.input,
            "db": db_dst,
            "ledger": ledger_dst,
            "forced": opts.force,
            "restored": {"db": true, "ledger": ledger_data.is_some(), "key": key_data.is_some()},
        });
        ledger_append_standalone(&ledger_dst, "console.restore", &detail).ok()
    } else {
        None
    };

    Ok(json!({
        "ok": true,
        "input": opts.input,
        "db": db_dst,
        "ledger": ledger_dst,
        "restored_ledger": ledger_data.is_some(),
        "restored_key": key_data.is_some(),
        "forced": opts.force,
        "restore_ledger_hash": restore_hash,
    }))
}

/// Lit une passphrase depuis la variable d'ENV nommée (JAMAIS depuis argv/STDIN echo). Vide/absente =>
/// None (l'appelant échoue fail-closed). La valeur n'est jamais imprimée/loggée.
fn read_passphrase_env(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|v| !v.is_empty())
}

/// `forge-console backup --out <archive> --passphrase-env <ENVVAR> [--db <path>] [--ledger <path>]`
/// Sauvegarde CHIFFRÉE (obligatoire) de la base + ledger + clé. Codes : 0 OK, 1 échec, 2 usage.
fn run_backup_cli(args: &[String]) -> i32 {
    let out = match cli_opt(args, "out") {
        Some(o) if !o.is_empty() => o,
        _ => {
            eprintln!("usage: forge-console backup --out <archive> --passphrase-env <ENVVAR> [--db <path>] [--ledger <path>]");
            return 2;
        }
    };
    let pass_env = match cli_opt(args, "passphrase-env") {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("[forge-console] backup: --passphrase-env <ENVVAR> requis (la passphrase est lue depuis cette variable d'ENV, jamais en argv)");
            return 2;
        }
    };
    let passphrase = match read_passphrase_env(&pass_env) {
        Some(p) => p,
        None => {
            eprintln!("[forge-console] backup: passphrase absente — la variable d'ENV '{pass_env}' est vide ou non définie (fail-closed)");
            return 2;
        }
    };
    let db = cli_opt(args, "db").filter(|s| !s.is_empty()).unwrap_or_else(cli_db_path);
    let opts = BackupOpts {
        out,
        passphrase,
        db,
        ledger: cli_opt(args, "ledger").filter(|s| !s.is_empty()),
        ts: Some(format!("@{}", chrono_now_compact())),
        actor: "cli:backup".to_string(),
    };
    match run_backup(&opts) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into()));
            println!(
                "[forge-console] backup: OK — archive chiffrée écrite ({} octets) : {}",
                report.get("archive_bytes").and_then(|x| x.as_u64()).unwrap_or(0),
                opts.out
            );
            0
        }
        Err(e) => {
            eprintln!("[forge-console] backup: {e}");
            1
        }
    }
}

/// `forge-console restore --in <archive> --passphrase-env <ENVVAR> [--to <db>] [--ledger <path>] [--force]`
/// Restauration CHIFFRÉE (déchiffre, vérifie sha256+ledger, place db/ledger/clé). Codes : 0 OK, 1 échec, 2 usage.
fn run_restore_cli(args: &[String]) -> i32 {
    let input = match cli_opt(args, "in") {
        Some(i) if !i.is_empty() => i,
        _ => {
            eprintln!("usage: forge-console restore --in <archive> --passphrase-env <ENVVAR> [--to <db>] [--ledger <path>] [--force]");
            return 2;
        }
    };
    let pass_env = match cli_opt(args, "passphrase-env") {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("[forge-console] restore: --passphrase-env <ENVVAR> requis (passphrase lue depuis l'ENV, jamais en argv)");
            return 2;
        }
    };
    let passphrase = match read_passphrase_env(&pass_env) {
        Some(p) => p,
        None => {
            eprintln!("[forge-console] restore: passphrase absente — la variable d'ENV '{pass_env}' est vide ou non définie (fail-closed)");
            return 2;
        }
    };
    let opts = RestoreOpts {
        input,
        passphrase,
        to: cli_opt(args, "to").filter(|s| !s.is_empty()),
        ledger: cli_opt(args, "ledger").filter(|s| !s.is_empty()),
        force: cli_flag(args, "force"),
        actor: "cli:restore".to_string(),
    };
    match run_restore(&opts) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into()));
            println!(
                "[forge-console] restore: OK — {} -> base {} (ledger {})",
                opts.input,
                report.get("db").and_then(|x| x.as_str()).unwrap_or(""),
                report.get("ledger").and_then(|x| x.as_str()).unwrap_or("")
            );
            0
        }
        Err(e) => {
            eprintln!("[forge-console] restore: {e}");
            1
        }
    }
}

// ===========================================================================================
// API SAUVEGARDE / RESTAURATION / POLITIQUE (admin-gated) — expose le moteur backup au-dessus de
// l'API + la programmation/offsite. Invariants PRÉSERVÉS : l'archive est TOUJOURS chiffrée (aucun
// chemin en clair) ; la passphrase est transitoire (JAMAIS stockée/loggée/ledgerisée) ; la chaîne du
// ledger est vérifiée AVANT backup / à la validation de restore ; le restore refuse d'écraser sans
// confirmation ; chaque action est réservée admin (check_admin, 403) et ledgerisée (métadonnées seules).
// ===========================================================================================

/// Nom canonique d'archive de backup (préfixe + epoch compact). Pas de secret, déterministe par instant.
fn backup_archive_name() -> String {
    format!("forge-backup-{}.forge", chrono_now_compact())
}

/// Suffixe unique pour un fichier TEMPORAIRE (pid + nanos) — évite toute collision entre deux backups /
/// restores concurrents la même seconde. Sans valeur sémantique (jamais persisté/ledgerisé).
fn tmp_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", std::process::id(), nanos)
}

/// Kinds d'offsite FERMÉS (fail-closed : tout autre kind est rejeté avant persistance).
const OFFSITE_KINDS: [&str; 3] = ["none", "local_dir", "exec"];

/// Rédige une politique de backup pour un GET : neutralise TOUTE valeur potentiellement secrète
/// (clé matchant pass/secret/token/password/cred/key) SAUF les noms de variables d'ENV (`*_env`, qui
/// ne sont que des NOMS, pas des secrets). Récursif (couvre `offsite`). Garantit qu'un GET ne renvoie
/// JAMAIS un secret même si un admin a collé par erreur un secret en clair dans la politique.
fn redact_backup_policy(v: &Value) -> Value {
    fn key_is_secretish(k: &str) -> bool {
        if k.ends_with("_env") { return false; } // NOM d'ENV -> jamais un secret
        let lk = k.to_ascii_lowercase();
        ["pass", "secret", "token", "password", "cred", "key"].iter().any(|n| lk.contains(n))
    }
    match v {
        Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, val) in m {
                if key_is_secretish(k) {
                    out.insert(k.clone(), json!("***REDACTED***"));
                } else {
                    out.insert(k.clone(), redact_backup_policy(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(redact_backup_policy).collect()),
        other => other.clone(),
    }
}

/// Politique par défaut quand `settings.backup_policy` est ABSENTE : rien de programmé, aucun offsite.
/// Rien de codé en dur ailleurs — sans politique, le runner ne fait AUCUNE sauvegarde.
fn backup_policy_default() -> Value {
    json!({"enabled": false, "offsite": {"kind": "none"}})
}

/// Lit `settings.backup_policy` (objet JSON) ; défaut si absente/illisible. Ne renvoie jamais d'erreur
/// (fail-soft en lecture — l'appelant obtient la politique par défaut, jamais une valeur inventée).
fn load_backup_policy(db: &Connection) -> Value {
    settings_get(db, "backup_policy")
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(backup_policy_default)
}

/// Valide une politique entrante (fail-closed sur les champs structurants). Retourne la politique
/// NETTOYÉE à persister (tout `passphrase` en clair est RETIRÉ — on ne stocke JAMAIS le secret ; seul
/// `passphrase_env` (un NOM d'ENV) est conservé). Erreur -> l'appelant renvoie 400 sans rien écrire.
fn validate_backup_policy(incoming: &Value) -> Result<Value, String> {
    let obj = incoming.as_object().ok_or_else(|| "politique attendue : objet JSON".to_string())?;
    let mut clean = obj.clone();
    // JAMAIS de secret en clair persisté : on retire tout `passphrase` littéral (seul `passphrase_env` reste).
    clean.remove("passphrase");
    let enabled = clean.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    if enabled {
        let interval = clean.get("interval_secs").and_then(|v| v.as_u64()).unwrap_or(0);
        if interval == 0 {
            return Err("interval_secs > 0 requis quand enabled=true".to_string());
        }
        let pe = clean.get("passphrase_env").and_then(|v| v.as_str()).unwrap_or("");
        if pe.is_empty() {
            return Err("passphrase_env requis quand enabled=true (nom de la variable d'ENV portant la passphrase — jamais la passphrase elle-même)".to_string());
        }
    }
    // offsite (kind fermé + forme par kind).
    let offsite = clean.get("offsite").cloned().unwrap_or_else(|| json!({"kind": "none"}));
    let ok = offsite.as_object().ok_or_else(|| "offsite attendu : objet {kind,...}".to_string())?;
    let kind = ok.get("kind").and_then(|v| v.as_str()).unwrap_or("none");
    if !OFFSITE_KINDS.contains(&kind) {
        return Err(format!("offsite.kind inconnu: {kind} (attendu: none|local_dir|exec)"));
    }
    if kind == "local_dir" {
        let dir = ok.get("dir").and_then(|v| v.as_str()).unwrap_or("");
        if dir.is_empty() {
            return Err("offsite local_dir : champ `dir` requis".to_string());
        }
    }
    if kind == "exec" {
        let program = ok.get("program").and_then(|v| v.as_str()).unwrap_or("");
        if program.is_empty() {
            return Err("offsite exec : champ `program` (chemin absolu) requis".to_string());
        }
        if !std::path::Path::new(program).is_absolute() {
            return Err("offsite exec : `program` doit être un chemin ABSOLU (pas de résolution PATH/shell)".to_string());
        }
        if let Some(a) = ok.get("args") {
            if !a.is_array() {
                return Err("offsite exec : `args` doit être un tableau d'arguments (argv fixe, aucun shell)".to_string());
            }
        }
    }
    Ok(Value::Object(clean))
}

/// Inspecte une archive de backup SANS rien écrire sur une cible : (1) DÉCHIFFRE (mauvaise passphrase /
/// altération => Err propre, tag AEAD) ; (2) extrait le tar en mémoire ; (3) re-vérifie le sha256 de
/// chaque fichier du manifest ; (4) vérifie la chaîne du ledger extrait via un fichier TEMPORAIRE
/// (supprimé aussitôt). Renvoie un rapport de validation (aucun secret). Sert le chemin de restore
/// « valider + rapporter » (par défaut, non destructif).
fn backup_inspect(archive: &[u8], passphrase: &str) -> Result<Value, String> {
    if passphrase.is_empty() {
        return Err("passphrase absente — une passphrase est OBLIGATOIRE (fail-closed)".to_string());
    }
    let plaintext = backup_decrypt(archive, passphrase)?;
    let entries = backup_extract_tar(&plaintext)?;
    let get = |name: &str| entries.iter().find(|(n, _)| n == name).map(|(_, b)| b.as_slice());

    let manifest_bytes = get(BACKUP_ENTRY_MANIFEST)
        .ok_or_else(|| "manifest.json absent de l'archive".to_string())?;
    let manifest: Value = serde_json::from_slice(manifest_bytes)
        .map_err(|e| format!("manifest.json illisible: {e}"))?;
    let files = manifest
        .get("files")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "manifest.json : section `files` absente ou invalide".to_string())?;
    let mut files_report = Vec::new();
    for (fname, meta) in files {
        let expected = meta.get("sha256").and_then(|v| v.as_str())
            .ok_or_else(|| format!("manifest : sha256 manquant pour '{fname}'"))?;
        let data = get(fname)
            .ok_or_else(|| format!("fichier '{fname}' listé au manifest mais ABSENT de l'archive"))?;
        let actual = sha256_hex_bytes(data);
        if actual != expected {
            return Err(format!(
                "sha256 mismatch pour '{fname}' — archive altérée (attendu {expected}, calculé {actual})"
            ));
        }
        files_report.push(json!({"name": fname, "size": data.len(), "sha256": actual}));
    }

    // vérif de la chaîne du ledger extrait, sur un temporaire (aucune cible touchée).
    let mut ledger_ok = true;
    let mut ledger_entries = 0i64;
    if let Some(l) = get(BACKUP_ENTRY_LEDGER) {
        let tmpv = format!("{}/forge-inspect-{}.jsonl",
            std::env::temp_dir().to_string_lossy(), tmp_nonce());
        std::fs::write(&tmpv, l).map_err(|e| format!("écriture temp de vérif ledger échouée: {e}"))?;
        let v = verify_ledger_chain(&tmpv);
        ledger_entries = read_ledger_lines(&tmpv).len() as i64;
        let _ = std::fs::remove_file(&tmpv);
        if v.exists && !v.ok {
            return Err(format!(
                "ledger de l'archive rompu (seq={}) : {}",
                v.broken, v.why.clone().unwrap_or_default()
            ));
        }
        ledger_ok = v.ok || !v.exists;
    }

    Ok(json!({
        "ok": true,
        "manifest": {
            "schema": manifest.get("schema").cloned().unwrap_or(Value::Null),
            "created_at": manifest.get("created_at").cloned().unwrap_or(Value::Null),
            "cipher": manifest.get("cipher").cloned().unwrap_or(Value::Null),
            "kdf": manifest.get("kdf").cloned().unwrap_or(Value::Null),
        },
        "files": files_report,
        "has_db": get(BACKUP_ENTRY_DB).is_some(),
        "has_ledger": get(BACKUP_ENTRY_LEDGER).is_some(),
        "has_key": get(BACKUP_ENTRY_KEY).is_some(),
        "ledger_ok": ledger_ok,
        "ledger_entries": ledger_entries,
    }))
}

/// POST /api/backup — ADMIN (check_admin, 403 sinon), LEDGERISÉ. Corps `{passphrase}` : la passphrase
/// est utilisée UNE FOIS (dérivation argon2id) puis abandonnée — JAMAIS stockée/loggée/ledgerisée.
/// Exécute le moteur de backup (chaîne ledger vérifiée AVANT ; archive TOUJOURS chiffrée) et RENVOIE
/// l'archive chiffrée en téléchargement (Content-Disposition). La trace ledger `console.backup` ne
/// contient QUE : acteur + (ts implicite) + taille + sha256 de l'archive (+ sha db). Jamais la passphrase.
async fn api_backup(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let passphrase = body.get("passphrase").and_then(|v| v.as_str()).unwrap_or("");
    if passphrase.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "passphrase_required", "why": "une passphrase est OBLIGATOIRE (fail-closed) — l'archive est toujours chiffrée"})),
        ).into_response();
    }
    // archive écrite dans un temporaire (0600) puis relue et supprimée ; jamais persistée côté serveur.
    let out = format!("{}/{}.tmp-{}", std::env::temp_dir().to_string_lossy(), backup_archive_name(), tmp_nonce());
    let opts = BackupOpts {
        out: out.clone(),
        passphrase: passphrase.to_string(),
        db: (*app.db_path).clone(),
        ledger: Some((*app.ledger_path).clone()),
        ts: Some(format!("@{}", chrono_now_compact())),
        actor: actor.clone(),
    };
    // run_backup_core NE trace PAS le ledger (on le fait ci-dessous via append_console_ledger, qui tient
    // le verrou + met à jour le cache du head -> aucune désynchronisation de la chaîne live).
    let (report, _cli_detail) = match run_backup_core(&opts) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&out);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "backup_failed", "why": e}))).into_response();
        }
    };
    let sealed = match std::fs::read(&out) {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_file(&out);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "backup_read_failed", "why": e.to_string()}))).into_response();
        }
    };
    let _ = std::fs::remove_file(&out); // le serveur ne conserve JAMAIS l'archive
    // AUDIT : métadonnées SEULES (acteur + taille + sha256), JAMAIS la passphrase ni la clé.
    append_console_ledger(&app, "console.backup", json!({
        "actor": actor,
        "archive_bytes": sealed.len(),
        "archive_sha256": sha256_hex_bytes(&sealed),
        "db_sha256": report.get("db_sha256").cloned().unwrap_or(Value::Null),
        "included": {
            "db": true,
            "ledger": report.get("included_ledger").cloned().unwrap_or(json!(false)),
            "key": report.get("included_key").cloned().unwrap_or(json!(false)),
        },
        "encrypted": true,
        "via": "api",
    }));
    let filename = backup_archive_name();
    (
        StatusCode::OK,
        [
            ("content-type", "application/octet-stream".to_string()),
            ("content-disposition", format!("attachment; filename=\"{filename}\"")),
            ("x-forge-archive-sha256", sha256_hex_bytes(&sealed)),
        ],
        sealed,
    ).into_response()
}

/// POST /api/restore — ADMIN (check_admin, 403 sinon), LEDGERISÉ. Corps JSON :
///   `{archive_b64, passphrase, apply?:bool, confirm?:bool}`.
/// La passphrase est transitoire (jamais stockée/loggée/ledgerisée). PAR DÉFAUT (apply absent/false) :
/// VALIDER + VÉRIFIER l'archive (déchiffrement AEAD, sha256 du manifest, chaîne ledger) et RAPPORTER —
/// AUCUNE écriture. Trace `console.restore.validate` (métadonnées). Un SWAP en place (apply=true) exige
/// une CONFIRMATION explicite (`confirm=true`) : il remplace db+ledger+clé (garde anti-écrasement via
/// --force implicite sous confirm) et REQUIERT UN REDÉMARRAGE de la console (la connexion SQLite vivante
/// tient encore l'ancien fichier). Mauvaise passphrase / archive altérée => échec propre, RIEN écrit.
async fn api_restore(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let passphrase = body.get("passphrase").and_then(|v| v.as_str()).unwrap_or("");
    if passphrase.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "passphrase_required", "why": "une passphrase est OBLIGATOIRE (fail-closed)"})),
        ).into_response();
    }
    let b64 = body.get("archive_b64").and_then(|v| v.as_str()).unwrap_or("");
    if b64.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "archive_required", "why": "champ `archive_b64` (archive chiffrée base64) requis"})),
        ).into_response();
    }
    let archive = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_base64", "why": "archive_b64 n'est pas du base64 valide"}))).into_response(),
    };

    // (1) VALIDATION non destructive systématique (déchiffre + vérifie sha256 + chaîne ledger).
    let inspect = match backup_inspect(&archive, passphrase) {
        Ok(v) => v,
        Err(e) => {
            // échec de validation (mauvaise passphrase / archive altérée) — trace SANS secret, 422.
            append_console_ledger(&app, "console.restore.validate", json!({
                "actor": actor, "archive_bytes": archive.len(), "ok": false, "via": "api",
            }));
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": "archive_invalid", "why": e}))).into_response();
        }
    };

    let apply = body.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
    if !apply {
        // chemin SÛR par défaut : rapporter la validation, ne RIEN écrire.
        append_console_ledger(&app, "console.restore.validate", json!({
            "actor": actor,
            "archive_bytes": archive.len(),
            "archive_sha256": sha256_hex_bytes(&archive),
            "ok": true,
            "via": "api",
        }));
        return (StatusCode::OK, Json(json!({
            "ok": true,
            "applied": false,
            "validated": inspect,
            "note": "archive VALIDÉE (déchiffrable, sha256 conformes, chaîne ledger intègre). Aucune écriture. Pour APPLIQUER le swap en place, relancez avec apply=true ET confirm=true — un REDÉMARRAGE de la console sera requis.",
        }))).into_response();
    }

    // (2) APPLY : swap en place — CONFIRMATION explicite OBLIGATOIRE.
    let confirm = body.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
    if !confirm {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "confirmation_required",
            "why": "apply=true exige confirm=true (confirmation explicite) — le swap remplace la base/ledger/clé en place et REQUIERT un redémarrage",
        }))).into_response();
    }
    // écrit l'archive dans un temporaire (run_restore lit un chemin), puis restaure vers la base/ledger LIVE.
    // `force=true` : la confirmation explicite vaut autorisation d'écraser l'install existant (non vide).
    let tmp = format!("{}/forge-restore-{}.forge", std::env::temp_dir().to_string_lossy(), tmp_nonce());
    if let Err(e) = std::fs::write(&tmp, &archive) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "restore_stage_failed", "why": e.to_string()}))).into_response();
    }
    let ropts = RestoreOpts {
        input: tmp.clone(),
        passphrase: passphrase.to_string(),
        to: Some((*app.db_path).clone()),
        ledger: Some((*app.ledger_path).clone()),
        force: true,
        actor: actor.clone(),
    };
    let result = run_restore(&ropts);
    let _ = std::fs::remove_file(&tmp);
    match result {
        Ok(mut report) => {
            // run_restore a remplacé le fichier ledger LIVE par celui de l'archive (avec sa propre trace
            // `console.restore`). Le cache du head de l'App est désormais périmé -> on l'invalide pour que
            // tout append ultérieur (avant le redémarrage requis) relise le head à froid (chaîne intacte).
            app.invalidate_ledger_head();
            if let Some(o) = report.as_object_mut() {
                o.insert("applied".to_string(), json!(true));
                o.insert("restart_required".to_string(), json!(true));
                o.insert("maintenance".to_string(), json!("Base/ledger/clé restaurés SUR PLACE. La connexion SQLite vivante tient encore l'ancien fichier : REDÉMARREZ la console (docker restart / systemctl restart) pour charger l'état restauré."));
            }
            (StatusCode::OK, Json(report)).into_response()
        }
        Err(e) => {
            // ex. install non vide sans force (ne devrait pas arriver ici, force=true) OU intégrité.
            let code = if e.contains("REFUSÉ") { StatusCode::CONFLICT } else { StatusCode::UNPROCESSABLE_ENTITY };
            (code, Json(json!({"error": "restore_failed", "why": e}))).into_response()
        }
    }
}

/// GET /api/backup/policy — ADMIN (403 sinon). Renvoie la politique de sauvegarde RÉDIGÉE (aucun secret ;
/// `passphrase_env` = NOM d'ENV, conservé), la liste FERMÉE des kinds d'offsite, et l'horodatage de la
/// dernière exécution programmée (`last_run`, métadonnée). Sans politique -> défaut (rien de programmé).
async fn api_backup_policy_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let (policy, last_run) = {
        let db = app.db();
        (load_backup_policy(&db), settings_get(&db, "backup_last_run"))
    };
    (StatusCode::OK, Json(json!({
        "policy": redact_backup_policy(&policy),
        "offsite_kinds": OFFSITE_KINDS,
        "last_run": last_run,
        "configured": settings_get(&app.db(), "backup_policy").is_some(),
    }))).into_response()
}

/// POST /api/backup/policy — ADMIN (403 sinon), LEDGERISÉ. Corps : la politique (à plat) OU `{policy:{...}}`.
/// Valide (kinds fermés, interval/passphrase_env requis si enabled), RETIRE tout `passphrase` en clair
/// (jamais de secret persisté), persiste `settings.backup_policy`, trace `console.backup.policy.set`
/// (métadonnées : enabled/interval/offsite_kind/passphrase_env — jamais un secret). Renvoie la politique rédigée.
async fn api_backup_policy_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let incoming = if let Some(p) = body.get("policy").filter(|v| v.is_object()) {
        p.clone()
    } else if body.is_object() {
        body.clone()
    } else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "corps attendu : {policy:{...}} ou l'objet politique à plat"}))).into_response();
    };
    let clean = match validate_backup_policy(&incoming) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_policy", "why": e}))).into_response(),
    };
    {
        let db = app.db();
        if let Err(e) = settings_set(&db, "backup_policy", &clean.to_string()) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "settings_write_failed", "why": e}))).into_response();
        }
    }
    let offsite_kind = clean.get("offsite").and_then(|o| o.get("kind")).and_then(|v| v.as_str()).unwrap_or("none").to_string();
    append_console_ledger(&app, "console.backup.policy.set", json!({
        "actor": actor,
        "enabled": clean.get("enabled").cloned().unwrap_or(json!(false)),
        "interval_secs": clean.get("interval_secs").cloned().unwrap_or(Value::Null),
        "retention": clean.get("retention").cloned().unwrap_or(Value::Null),
        "offsite_kind": offsite_kind,
        "passphrase_env": clean.get("passphrase_env").cloned().unwrap_or(Value::Null),
    }));
    (StatusCode::OK, Json(json!({"ok": true, "saved": true, "policy": redact_backup_policy(&clean)}))).into_response()
}

// --- Runner programmé (offsite) — tâche périodique fail-open, ne crashe JAMAIS la console. -----------

/// Expédie l'archive `archive_path` vers la destination offsite. `none` -> no-op. `local_dir` -> copie
/// dans `dir` (créé si besoin). `exec` -> lance un argv FIXE (aucun shell) avec timeout ; le token
/// littéral `{archive}` dans `program`/`args` est remplacé par le chemin de l'archive. Aucun secret n'est
/// journalisé (kind + statut seuls). Renvoie un rapport (jamais d'argv complet si secretish — l'admin
/// est responsable de ne pas mettre de secret inline ; préférer des creds via l'ENV du process/rclone.conf).
fn ship_offsite(offsite: &Value, archive_path: &str) -> Result<Value, String> {
    let kind = offsite.get("kind").and_then(|v| v.as_str()).unwrap_or("none");
    match kind {
        "none" => Ok(json!({"shipped": false, "kind": "none"})),
        "local_dir" => {
            let dir = offsite.get("dir").and_then(|v| v.as_str()).unwrap_or("");
            if dir.is_empty() {
                return Err("offsite local_dir : `dir` requis".to_string());
            }
            std::fs::create_dir_all(dir).map_err(|e| format!("création de '{dir}' échouée: {e}"))?;
            let base = std::path::Path::new(archive_path).file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(backup_archive_name);
            let dst = std::path::Path::new(dir).join(&base);
            std::fs::copy(archive_path, &dst).map_err(|e| format!("copie offsite échouée: {e}"))?;
            Ok(json!({"shipped": true, "kind": "local_dir", "dest": dst.to_string_lossy()}))
        }
        "exec" => {
            let program = offsite.get("program").and_then(|v| v.as_str()).unwrap_or("");
            if program.is_empty() {
                return Err("offsite exec : `program` requis".to_string());
            }
            let timeout = offsite.get("timeout_secs").and_then(|v| v.as_u64()).filter(|&n| n > 0).unwrap_or(120);
            let subst = |s: &str| s.replace("{archive}", archive_path);
            let program = subst(program);
            let args: Vec<String> = offsite.get("args").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).map(subst).collect())
                .unwrap_or_default();
            // AUCUN shell : argv fixe. status + timeout, jamais d'interprétation de métacaractères.
            run_offsite_exec(&program, &args, timeout)
        }
        other => Err(format!("offsite.kind inconnu: {other}")),
    }
}

/// Lance un binaire (chemin explicite) avec un argv FIXE (aucun shell) et un timeout dur. Tue le
/// process au dépassement. Renvoie {shipped, kind:"exec", code} (code de sortie) ; erreur si le spawn
/// échoue ou si le process sort en échec/timeout. Blocage borné -> appelé depuis spawn_blocking.
fn run_offsite_exec(program: &str, args: &[String], timeout_secs: u64) -> Result<Value, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("offsite exec: lancement de '{program}' impossible: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(json!({"shipped": true, "kind": "exec", "code": status.code()}));
                }
                return Err(format!("offsite exec: '{program}' a échoué (code={:?})", status.code()));
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("offsite exec: '{program}' dépassé le timeout ({timeout_secs}s) — process tué"));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => return Err(format!("offsite exec: attente de '{program}' échouée: {e}")),
        }
    }
}

/// Applique la rétention : conserve les `keep` archives `forge-backup-*.forge` les plus récentes de
/// `dir`, supprime le reste. `keep=0` -> aucune purge (rétention illimitée). Best-effort (erreurs ignorées).
fn apply_backup_retention(dir: &str, keep: usize) {
    if keep == 0 {
        return;
    }
    let mut archives: Vec<(std::time::SystemTime, std::path::PathBuf)> = std::fs::read_dir(dir)
        .map(|it| it.filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with("forge-backup-") && n.ends_with(".forge")
            })
            .filter_map(|e| e.metadata().and_then(|m| m.modified()).ok().map(|t| (t, e.path())))
            .collect())
        .unwrap_or_default();
    if archives.len() <= keep {
        return;
    }
    archives.sort_by_key(|b| std::cmp::Reverse(b.0)); // plus récent d'abord
    for (_, path) in archives.into_iter().skip(keep) {
        let _ = std::fs::remove_file(path);
    }
}

/// Exécute UNE sauvegarde programmée selon `settings.backup_policy` : lit la passphrase depuis la
/// variable d'ENV NOMMÉE par la politique (JAMAIS depuis settings en clair) ; crée une archive chiffrée
/// dans le staging ; applique la rétention ; expédie offsite ; trace chaque étape au ledger (métadonnées).
/// Fail-closed sur passphrase absente. Renvoie un rapport ou une erreur (l'appelant ledgerise l'échec).
/// Fonction BLOQUANTE (argon2 + I/O) -> à invoquer via spawn_blocking depuis le runner async.
fn run_scheduled_backup(app: &App) -> Result<Value, String> {
    let policy = { let db = app.db(); load_backup_policy(&db) };
    if !policy.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Ok(json!({"skipped": true, "reason": "policy_disabled"}));
    }
    let pass_env = policy.get("passphrase_env").and_then(|v| v.as_str()).unwrap_or("");
    if pass_env.is_empty() {
        return Err("passphrase_env absent de la politique (fail-closed)".to_string());
    }
    let passphrase = read_passphrase_env(pass_env)
        .ok_or_else(|| format!("passphrase absente — la variable d'ENV '{pass_env}' est vide/non définie (fail-closed)"))?;

    // staging : `staging_dir` de la politique, sinon un dossier `backups/` sibling de la base.
    let staging = policy.get("staging_dir").and_then(|v| v.as_str()).map(|s| s.to_string())
        .unwrap_or_else(|| {
            std::path::Path::new(app.db_path.as_str()).parent()
                .map(|p| p.join("backups").to_string_lossy().into_owned())
                .unwrap_or_else(|| "backups".to_string())
        });
    std::fs::create_dir_all(&staging).map_err(|e| format!("création du staging '{staging}' échouée: {e}"))?;
    let out = std::path::Path::new(&staging).join(backup_archive_name()).to_string_lossy().into_owned();

    let opts = BackupOpts {
        out: out.clone(),
        passphrase,
        db: (*app.db_path).clone(),
        ledger: Some((*app.ledger_path).clone()),
        ts: Some(format!("@{}", chrono_now_compact())),
        actor: "scheduler".to_string(),
    };
    let (report, _detail) = run_backup_core(&opts)?;
    let sealed_len = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    let archive_sha = std::fs::read(&out).map(|b| sha256_hex_bytes(&b)).unwrap_or_default();

    // AUDIT (métadonnées) — via append_console_ledger (verrou + cache head, pas de désync).
    append_console_ledger(app, "console.backup.scheduled", json!({
        "actor": "scheduler",
        "out": out,
        "archive_bytes": sealed_len,
        "archive_sha256": archive_sha,
        "db_sha256": report.get("db_sha256").cloned().unwrap_or(Value::Null),
        "encrypted": true,
    }));

    // rétention locale (conserve les N plus récentes).
    let keep = policy.get("retention").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    apply_backup_retention(&staging, keep);

    // offsite : expédie l'archive ; ledgerise le résultat (kind + statut, jamais de secret).
    let offsite = policy.get("offsite").cloned().unwrap_or_else(|| json!({"kind": "none"}));
    let offsite_kind = offsite.get("kind").and_then(|v| v.as_str()).unwrap_or("none").to_string();
    let offsite_res = ship_offsite(&offsite, &out);
    match &offsite_res {
        Ok(r) => append_console_ledger(app, "console.backup.offsite", json!({
            "actor": "scheduler", "kind": offsite_kind, "ok": true,
            "shipped": r.get("shipped").cloned().unwrap_or(json!(false)),
        })),
        Err(e) => append_console_ledger(app, "console.backup.offsite", json!({
            "actor": "scheduler", "kind": offsite_kind, "ok": false, "why": e,
        })),
    }

    Ok(json!({
        "ok": true,
        "out": out,
        "archive_bytes": sealed_len,
        "archive_sha256": archive_sha,
        "offsite": offsite_res.unwrap_or_else(|e| json!({"shipped": false, "error": e})),
    }))
}

/// Vrai si une sauvegarde programmée est DUE : politique activée + `interval_secs` écoulé depuis
/// `settings.backup_last_run` (0/absent -> due immédiatement). Lecture seule (aucun effet de bord).
fn scheduled_backup_due(db: &Connection) -> bool {
    let policy = load_backup_policy(db);
    if !policy.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
        return false;
    }
    let interval = policy.get("interval_secs").and_then(|v| v.as_u64()).unwrap_or(0);
    if interval == 0 {
        return false;
    }
    let now: u64 = chrono_now_compact().parse().unwrap_or(0);
    let last: u64 = settings_get(db, "backup_last_run").and_then(|s| s.parse().ok()).unwrap_or(0);
    now.saturating_sub(last) >= interval
}

/// Runner périodique EN CONSOLE : à chaque tick, si une politique est DUE, exécute une sauvegarde
/// programmée (via spawn_blocking — argon2 hors runtime async), met à jour `backup_last_run`, et
/// ledgerise. FAIL-OPEN : un échec de backup/offsite est loggé + ledgerisé (`console.backup.error`) mais
/// ne fait JAMAIS crasher la console (un panic de la tâche bloquante est capté par le JoinHandle). Sans
/// politique/activation, ne fait rien (aucune sauvegarde codée en dur). Tick réglable (FORGE_BACKUP_TICK_SECS).
async fn backup_scheduler_loop(app: App) {
    let tick = std::env::var("FORGE_BACKUP_TICK_SECS").ok()
        .and_then(|s| s.parse::<u64>().ok()).filter(|&n| n > 0).unwrap_or(60);
    loop {
        tokio::time::sleep(Duration::from_secs(tick)).await;
        let due = { let db = app.db(); scheduled_backup_due(&db) };
        if !due {
            continue;
        }
        let app2 = app.clone();
        let res = tokio::task::spawn_blocking(move || run_scheduled_backup(&app2)).await;
        // marque la tentative (succès OU échec) pour ne pas boucler serré ; prochaine tentative après interval.
        {
            let db = app.db();
            let _ = settings_set(&db, "backup_last_run", &chrono_now_compact());
        }
        match res {
            Ok(Ok(v)) => {
                println!("[forge-console] backup programmé OK — {} octets (offsite: {})",
                    v.get("archive_bytes").and_then(|x| x.as_u64()).unwrap_or(0),
                    v.get("offsite").and_then(|o| o.get("kind")).and_then(|x| x.as_str())
                        .or_else(|| v.get("offsite").and_then(|o| o.get("shipped")).map(|_| "done")).unwrap_or("none"));
            }
            Ok(Err(e)) => {
                eprintln!("[forge-console] backup programmé ÉCHEC (fail-open, console intacte): {e}");
                append_console_ledger(&app, "console.backup.error", json!({"actor": "scheduler", "why": e}));
            }
            Err(join_err) => {
                eprintln!("[forge-console] backup programmé : tâche interrompue (fail-open): {join_err}");
                append_console_ledger(&app, "console.backup.error", json!({"actor": "scheduler", "why": "tâche de backup interrompue"}));
            }
        }
    }
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

/// Sous-commande LECTURE SEULE, NON INTERACTIVE et RAPIDE : `forge-console ledger verify [--ledger <path>]
/// [--json]`. Recompute la chaîne SHA-256 (prev|seq|ts|kind|canon(detail)) du ledger JSONL et VÉRIFIE
/// chaque hash + le chaînage `prev` — MÊME algorithme que GET /api/ledger/verify et `migrate --verify`
/// (verify_ledger_chain, source de vérité unique). Ne démarre AUCUN serveur, n'ouvre AUCUNE base SQLite,
/// ne lit AUCUN STDIN : pure lecture du fichier -> exit immédiat (jamais de blocage). La vérif de
/// SIGNATURE (Ed25519/HMAC) reste côté `forge ledger verify --pubkey` (Python) : la console n'a pas la
/// clé privée -> `sig_checked:false`. Chemin résolu : `--ledger` sinon $FORGE_CONSOLE_LEDGER sinon défaut
/// `engagement.jsonl` (parité boot). Codes de sortie : 0 = chaîne intègre (ou fichier présent mais vide) ;
/// 1 = rupture/altération détectée OU ledger absent ; 2 = erreur d'usage (sous-commande absente/inconnue).
fn run_ledger_cli(args: &[String]) -> i32 {
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

/// Construit le routeur axum complet : routes PUBLIQUES (hors auth_guard : /health, /api/login, wizard
/// de 1er déploiement /api/setup*) + routes PROTÉGÉES (derrière auth_guard) + fallback ServeDir, le
/// tout sous host_guard (anti-rebinding). Extrait de main() pour être exercé TEL QUEL par les tests
/// d'intégration (parité stricte du câblage : ce qui est gaté en prod l'est en test). `app` est déplacé
/// dans le routeur (with_state) ; le ConnectInfo est branché au moment du `serve`, pas ici.
fn build_router(app: App, web_dir: &str) -> Router {
    // routes protégées par auth_guard ; ServeDir sert les assets statiques (style.css/app.js/quetzal.svg/
    // favicon.svg/fonts/…) en fallback pour toute route non-API non matchée — l'index `/` reste rendu
    // par include_str!.
    let protected = Router::new()
        .route("/", get(index))
        .route("/api/whoami", get(whoami))
        .route("/api/ingest", post(ingest))
        .route("/api/findings", get(findings))
        .route("/api/findings/:id", get(finding_detail))
        .route("/api/runrecords", get(runrecords))
        .route("/api/coverage", get(coverage))
        // Couverture de détection : nom canonique + alias rétro-compat /api/purple/coverage (le SPA
        // interroge encore /purple/coverage — l'alias garantit qu'il ne casse pas).
        .route("/api/detection/coverage", get(purple_coverage))
        .route("/api/purple/coverage", get(purple_coverage))
        // Test admin d'une source de détection (config fournie ou stockée) — ne renvoie jamais le secret.
        .route("/api/detection/test", post(detection_test))
        // Config admin de la SOURCE de détection : GET (secret RETIRÉ) + POST (persiste settings.detection_source,
        // recharge le cache, ledgerise ; write-only sur le secret). Réservé admin (check_admin, 403 sinon).
        .route("/api/detection/source", get(detection_source_get).post(detection_source_set))
        .route("/api/modules", get(modules))
        .route("/api/modules/refresh", post(modules_refresh))
        // SÉLECTION DE TECHNIQUES PAR-SCOPE — catalogue groupé par catégorie (lecture) + mutation
        // gouvernée (opérateur/admin, ledgerisée) de la sélection (profil + toggles catégorie/technique).
        .route("/api/techniques", get(techniques_catalog))
        .route("/api/techniques/selection", post(technique_selection_set))
        // GOUVERNANCE CONNECTEUR (#4) : écriture réservée admin (check_admin, fail-closed 403), attribuée +
        // ledgerisée. Le segment statique `refresh` prime sur le paramètre `:kind` (matchit). Disabling
        // un connecteur l'empêche RÉELLEMENT de tirer (enforcement au spawn, cf. run_create).
        .route("/api/modules/:kind", post(module_governance))
        .route("/api/campaigns", get(campaigns))
        .route("/api/roe", get(roe))
        // --- ADMINISTRATION comptes (#4) : réservé admin (check_admin, fail-closed 403 sinon). Chaque
        //     mutation est attribuée à l'admin acteur + ledgerisée ; GET ne renvoie jamais pass_hash ;
        //     recompute_auth_required après chaque mutation (gate DB-state) ; dernier admin protégé.
        .route("/api/users", get(users_list).post(users_create))
        .route("/api/users/:login", post(users_update).delete(users_delete))
        // --- SAUVEGARDE / RESTAURATION CHIFFRÉES (admin, ledgerisées). L'archive est TOUJOURS chiffrée ;
        //     la passphrase (corps) est transitoire (jamais stockée/loggée/ledgerisée). Le restore VALIDE
        //     par défaut (non destructif) ; un swap en place exige apply=true+confirm=true (redémarrage
        //     requis). La politique (schedule/rétention/offsite) pilote le runner programmé ; GET rédige
        //     tout secret. DefaultBodyLimit relevé sur /api/restore (archive base64 volumineuse possible).
        .route("/api/backup", post(api_backup))
        .route("/api/restore", post(api_restore).layer(DefaultBodyLimit::max(512 * 1024 * 1024)))
        .route("/api/backup/policy", get(api_backup_policy_get).post(api_backup_policy_set))
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
        .fallback_service(ServeDir::new(web_dir))
        .route_layer(middleware::from_fn_with_state(app.clone(), auth_guard));
    Router::new()
        // /health : sonde ouverte (hors auth_guard). JSON {status, version} — `version` provient
        // du fichier VERSION (source unique). `forge doctor --purple` ne teste que le code HTTP 200.
        .route("/health", get(|| async { Json(json!({"status": "ok", "version": forge_version()})) }))
        // /api/login HORS auth_guard (sinon impossible de se connecter quand pass_hash est posé) ;
        // reste sous host_guard (anti-rebinding). Pose une session individuelle (cookie + bearer).
        .route("/api/login", post(login))
        // WIZARD 1er DÉPLOIEMENT — PUBLIC (hors auth_guard) : sonde d'état + provision AUTO-DÉSACTIVANTE
        // (409 une fois provisionné). Sous host_guard comme tout le reste. Le SPA sonde /api/setup/state
        // au boot pour afficher le wizard sur un fresh install ; POST /api/setup crée le 1er admin.
        .route("/api/setup/state", get(setup_state))
        .route("/api/setup", post(setup_provision))
        // IMPORT DE DONNÉES (pré-provision) : migre un install existant vers cette base + ledger.
        // PUBLIC mais 409 une fois provisionné (comme /api/setup). UX primaire = CLI `migrate`.
        .route("/api/setup/migrate", post(setup_migrate))
        .merge(protected)
        .layer(middleware::from_fn_with_state(app.clone(), host_guard))
        .with_state(app)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // sous-commandes de provisioning de hash argon2id :
    //   forge-console hashpw <password>           -> hash du viewer (FORGE_CONSOLE_PASS_HASH)
    //   forge-console hashpw-operator <password>  -> hash du rôle OPÉRATEUR C2 (FORGE_CONSOLE_OPERATOR_HASH)
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        // --version / -V : imprime la version unique (fichier VERSION, include_str! à la compile).
        Some("--version") | Some("-V") => {
            println!("forge-console {}", forge_version());
            return;
        }
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
        // Provisioning d'un COMPTE INDIVIDUEL : forge-console useradd <login> <role> [--pass <pw>]
        //   role ∈ {viewer|operator|admin}. Le mot de passe est lu sur STDIN par défaut (jamais en
        //   argv -> pas de fuite via ps/cmdline) ; `--pass <pw>` est toléré pour le scripting. Le hash
        //   argon2id est calculé ici et stocké dans `users` (idempotent par login : upsert + réactive).
        Some("useradd") => {
            std::process::exit(run_useradd_cli(&args[2..]));
        }
        // AMORÇAGE DÉMO : forge-console seed-demo [--dir <path>] [--campaign <name>]
        //   Charge l'engagement de référence synthétique (examples/reference-engagement/) DIRECTEMENT
        //   dans la base SQLite (hors-ligne, sans réseau, sans /api/ingest) pour qu'une console fraîche
        //   affiche immédiatement Findings/Coverage/Purple/Runs. Idempotent (purge la campagne démo).
        Some("seed-demo") => {
            std::process::exit(run_seed_demo_cli(&args[2..]));
        }
        // MIGRATION DE DONNÉES : forge-console migrate --from <dir|db> --to <db> [--ledger <path>]
        //   [--verify] [--encrypt --key-env <ENVVAR>]. Importe un install Forge existant (non-Docker)
        //   vers une base cible (Docker/autre) : copie DB (VACUUM INTO / SQLCipher), ledger + clé
        //   .ed25519 (0600), puis SCHEMA + migrate() sur la cible. UX primaire = conteneur one-shot.
        Some("migrate") => {
            std::process::exit(run_migrate_cli(&args[2..]));
        }
        // SAUVEGARDE CHIFFRÉE : forge-console backup --out <archive> --passphrase-env <ENVVAR>
        //   [--db <path>] [--ledger <path>]. Archive TOUJOURS chiffrée (argon2id + XChaCha20-Poly1305)
        //   regroupant snapshot DB (VACUUM INTO) + ledger + clé .ed25519 + manifest.json. Passphrase
        //   lue UNIQUEMENT depuis l'ENV (jamais argv). Chaîne ledger vérifiée avant, backup tracé.
        Some("backup") => {
            std::process::exit(run_backup_cli(&args[2..]));
        }
        // RESTAURATION CHIFFRÉE : forge-console restore --in <archive> --passphrase-env <ENVVAR>
        //   [--to <db>] [--ledger <path>] [--force]. Déchiffre (mauvaise passphrase/altération => rien
        //   écrit), vérifie les sha256 du manifest + la chaîne ledger, refuse d'écraser un install non
        //   vide sans --force, place db/ledger/clé (.ed25519 = 0600). Restore tracé au ledger.
        Some("restore") => {
            std::process::exit(run_restore_cli(&args[2..]));
        }
        // VÉRIF LEDGER (lecture seule, NON INTERACTIVE, RAPIDE) : forge-console ledger verify
        //   [--ledger <path>] [--json]. Recompute la chaîne SHA-256 du ledger JSONL et exit immédiat
        //   (0 intègre / 1 rompu-absent / 2 usage). NE démarre PAS le serveur, n'ouvre PAS la base,
        //   ne lit PAS STDIN. La vérif de signature reste côté `forge ledger verify --pubkey` (Python).
        Some("ledger") => {
            std::process::exit(run_ledger_cli(&args[2..]));
        }
        _ => {}
    }

    let db_path = std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge-console.db".to_string());
    let conn = Connection::open(&db_path).expect("open db");
    // CHIFFREMENT AU REPOS (opt-in, feature `encryption`) : si FORGE_DB_KEY est posé, `PRAGMA key`
    // DOIT précéder TOUTE autre requête (sinon SQLCipher lit une base illisible). Dans le build par
    // défaut (feature off), ce hook n'est pas compilé -> base en clair, comportement inchangé.
    #[cfg(feature = "encryption")]
    apply_db_key_on_boot(&conn);
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
    // DÉTECTION (mesure de couverture, purple) : la SOURCE est configurable (settings.detection_source),
    // avec repli rétro-compat sur l'env legacy PLUME_URL/PLUME_TOKEN. Le cache est chargé JUSTE APRÈS la
    // construction de l'App (reload_detection_source, qui lit la table settings + l'env). Source absente
    // => /api/detection/coverage (alias /api/purple/coverage) répond en FAIL-OPEN LISIBLE.
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
    // ÉTAT DB de la gate d'auth : un compte activé en base engage la gate MÊME sans hash env (ferme le
    // trou dev-open historique). On le calcule ici sur `conn` (avant son déplacement dans App) pour un
    // log fidèle ; App.recompute_auth_required() recalcule ensuite le cache faisant autorité.
    let has_enabled_user: bool =
        conn.query_row("SELECT 1 FROM users WHERE disabled=0 LIMIT 1", [], |_| Ok(())).is_ok();
    if pass_hash.is_empty() && !has_enabled_user {
        println!("[forge-console] AUTH OFF (dev localhost) — ni FORGE_CONSOLE_PASS_HASH ni compte activé en base. `forge-console useradd <login> admin` (ou pose le hash env) pour engager la gate.");
    } else if pass_hash.is_empty() {
        println!("[forge-console] auth ON (état DB) — gate engagée par au moins un compte activé (table users) ; connexion via POST /api/login (session individuelle) ; hash env absent");
    } else {
        println!("[forge-console] auth ON — user={user}, lectures protégées (Basic), écritures par token (comptes individuels via POST /api/login également acceptés)");
    }
    if operator_hash.is_empty() {
        println!("[forge-console] C2 FAIL-CLOSED — rôle opérateur NON provisionné (FORGE_CONSOLE_OPERATOR_HASH absent) : /api/run* renverra 403. `forge-console hashpw-operator '...'` pour l'activer.");
    } else {
        println!("[forge-console] C2 armé — rôle opérateur via en-tête X-Forge-Operator ; cibles ⊆ scope serveur ({} entrée(s)) ; exploit/destructif possibles UNIQUEMENT via opt-in haut-impact gouverné (allow_high_impact + arm + reason, journalisé au ledger) ; scope-guard moteur inchangé (hors-scope = VETO) ; watchdog={run_timeout_secs}s", scope_in.len());
    }

    // (log DÉTECTION déplacé après la construction de l'App + reload_detection_source — la source
    //  n'est connue qu'une fois le cache chargé depuis settings/env.)

    // [SÉCURITÉ XFF] Garde-fou/migration du réglage `trusted_proxy` : il doit désormais contenir le/les
    // CIDR(s) du proxy amont (Traefik/cluster, egress Cloudflare…). Une valeur héritée « truthy » non-CIDR
    // (ex. "1"/"true") ne produit AUCUN CIDR valide -> on n'accorde foi à AUCUN X-Forwarded-For (repli
    // fail-closed sur le pair TCP). On alerte l'opérateur pour qu'il reconfigure explicitement.
    match settings_get(&conn, "trusted_proxy") {
        Some(raw) if !raw.trim().is_empty() && parse_trusted_proxy_cidrs(&raw).is_empty() => {
            eprintln!("[forge-console] WARN trusted_proxy={raw:?} n'est PAS un CIDR valide — X-Forwarded-For sera IGNORÉ (repli fail-closed sur le pair TCP). Reconfigure `trusted_proxy` sur le(s) CIDR(s) du proxy amont réel (ex. le CIDR Traefik/cluster ou l'egress Cloudflare), sinon la politique opérateur source-CIDR verra l'IP du proxy et jamais celle du client.");
        }
        Some(raw) if !raw.trim().is_empty() => {
            println!("[forge-console] trusted_proxy: X-Forwarded-For honoré UNIQUEMENT si le pair TCP appartient à {:?}", parse_trusted_proxy_cidrs(&raw));
        }
        _ => {}
    }

    let (events, _) = broadcast::channel::<RunEvent>(1024);
    let app = App {
        db: Arc::new(Mutex::new(conn)),
        db_path: Arc::new(db_path.clone()),
        token_sha: Arc::new(sha_hex(&token)),
        token_raw: Arc::new(token.clone()),
        user: Arc::new(user),
        pass_hash: Arc::new(pass_hash),
        auth_required: Arc::new(AtomicBool::new(false)), // recalculé juste après (recompute_auth_required)
        operator_hash: Arc::new(operator_hash),
        allowed_hosts: Arc::new(allowed),
        ledger_path: Arc::new(ledger_path),
        pkg_dir: Arc::new(pkg_dir),
        python: Arc::new(python),
        scope_in: Arc::new(scope_in),
        scope_mode: Arc::new(scope_mode),
        // cache provisoire (kind=none) ; rechargé depuis settings/env juste après (reload_detection_source).
        detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
        run_timeout_secs,
        run_state: Arc::new(AsyncMutex::new(RunState { current: None })),
        events,
        ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
    };
    // Cache faisant autorité de la gate d'auth : engagée si hash env OU compte activé en base. À
    // recalculer aussi après toute mutation de comptes (routes d'administration à venir).
    app.recompute_auth_required();
    // Cache de la SOURCE DE DÉTECTION : settings.detection_source (verbatim) sinon repli env legacy
    // PLUME_URL/PLUME_TOKEN (kind=plume) sinon kind=none. Recalculé après chaque mutation (wizard).
    app.reload_detection_source();
    {
        let cfg = app.detection_config();
        let kind = ds_kind(&cfg);
        let endpoint = ds_endpoint(&cfg);
        let http_kind = kind == "plume" || kind == "generic_http";
        if kind == "none" || kind.is_empty() || (http_kind && endpoint.is_empty()) {
            println!("[forge-console] DÉTECTION OFF — aucune source configurée : /api/detection/coverage (alias /api/purple/coverage) répondra en fail-open lisible (source_reachable:false). Configure `settings.detection_source` (wizard) ou pose PLUME_URL/PLUME_TOKEN (rétro-compat kind=plume).");
        } else {
            // JAMAIS le secret dans le log — kind + endpoint + type d'auth seuls.
            println!("[forge-console] DÉTECTION armée — kind={kind} endpoint={endpoint} auth={} ; LECTURE seule, joint runrecord[fired] (red) vs détections de la source (blue).",
                ds_auth_type(&cfg));
        }
    }

    // RUNNER DE SAUVEGARDE PROGRAMMÉE (fail-open) : tâche périodique qui, SI une politique
    // `settings.backup_policy` existe et est DUE, crée une archive chiffrée et l'expédie offsite en
    // ledgerisant chaque exécution. Sans politique -> ne fait rien (aucune sauvegarde codée en dur). Un
    // échec logge + ledgerise mais ne fait JAMAIS crasher la console. Cloné AVANT que build_router ne
    // déplace `app` (with_state).
    tokio::spawn(backup_scheduler_loop(app.clone()));

    // Câblage du routeur extrait dans build_router (parité stricte prod/test : ce qui est gaté ici
    // l'est aussi dans les tests d'intégration). ConnectInfo est branché au serve pour que les
    // handlers C2 (run/cancel/refresh) reçoivent l'IP du pair (contrainte source-CIDR opérateur).
    let router = build_router(app, &web_dir);

    let addr = std::env::var("FORGE_CONSOLE_ADDR").unwrap_or_else(|_| "127.0.0.1:7100".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("[forge-console] http://{addr}");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("serve");
}

// =====================================================================================
// Tests de régression des correctifs de sûreté/sécurité (durcissement audit).
// =====================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Verrou global sérialisant les tests qui LISENT/ÉCRIVENT des variables d'ENV partagées
    /// (FORGE_ALLOW_API_MIGRATE / FORGE_CONSOLE_IMPORT_DIR) — l'ENV du process est global, donc ces
    /// tests ne doivent pas courir en parallèle. Empoisonnement ignoré (into_inner) : un panic
    /// antérieur ne doit pas bloquer les suivants.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

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
            auth_required: Arc::new(AtomicBool::new(false)),
            operator_hash: Arc::new(String::new()),
            allowed_hosts: Arc::new(vec!["localhost".into()]),
            ledger_path: Arc::new(ledger_path.to_string()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
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

    /// Construit un HeaderMap avec un Authorization: Bearer <tok> (utilisé pour simuler une session).
    fn bearer_headers(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {tok}").parse().unwrap());
        h
    }

    /// Construit un HeaderMap avec un X-Forge-Operator (repli bootstrap env-hash).
    fn operator_headers(pw: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forge-operator", pw.parse().unwrap());
        h
    }

    /// [#6 comptes] validate_login / validate_role : grammaire stricte, rôles fermés (fail-closed).
    #[test]
    fn user_login_and_role_validation() {
        assert!(validate_login("alice").is_ok());
        assert!(validate_login("a.b_c-1").is_ok());
        assert!(validate_login("").is_err(), "login vide refusé");
        assert!(validate_login("-x").is_err(), "login débutant par '-' refusé (anti-flag)");
        assert!(validate_login("a b").is_err(), "espace refusé");
        assert!(validate_login("évil").is_err(), "non-ASCII refusé");
        assert!(validate_role("viewer").is_ok());
        assert!(validate_role("operator").is_ok());
        assert!(validate_role("admin").is_ok());
        assert!(validate_role("root").is_err(), "rôle inconnu refusé");
        assert!(validate_role("").is_err());
    }

    /// [#6 comptes] upsert_user -> session -> resolve_session_identity : un compte individuel en
    /// session est résolu (login/rôle réels), is_operator suit le rôle.
    #[test]
    fn session_resolves_individual_identity() {
        let path = tmp_path("forge-test-users-resolve");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "carol", "operator", &hash_pw("pw")).unwrap();
        }
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='carol'", [], |r| r.get(0)).unwrap() };
        let (tok, _exp) = create_session(&app, uid);
        let id = resolve_session_identity(&app, &bearer_headers(&tok)).expect("session valide -> identité");
        assert_eq!(id.login, "carol");
        assert_eq!(id.role, "operator");
        assert!(id.is_operator, "operator -> is_operator");
        assert!(id.via_session, "via_session=true pour un compte individuel");
        // token inconnu -> pas d'identité.
        assert!(resolve_session_identity(&app, &bearer_headers("deadbeef")).is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 comptes] disabled / expiration : un compte désactivé et une session expirée sont refusés
    /// (fail-closed), et la session expirée est purgée.
    #[test]
    fn session_disabled_and_expired_are_rejected() {
        let path = tmp_path("forge-test-users-disabled");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "dave", "viewer", &hash_pw("pw")).unwrap();
        }
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='dave'", [], |r| r.get(0)).unwrap() };
        let (tok, _) = create_session(&app, uid);
        // désactivation -> refus immédiat même session valide.
        { let db = app.db(); db.execute("UPDATE users SET disabled=1 WHERE id=?", [uid]).unwrap(); }
        assert!(resolve_session_identity(&app, &bearer_headers(&tok)).is_none(), "compte désactivé refusé");
        // réactive + force une session expirée -> refus + purge.
        { let db = app.db(); db.execute("UPDATE users SET disabled=0 WHERE id=?", [uid]).unwrap(); }
        let token_sha = sha_hex(&tok);
        { let db = app.db(); db.execute("UPDATE session SET expires=1 WHERE token_sha=?", [&token_sha]).unwrap(); }
        assert!(resolve_session_identity(&app, &bearer_headers(&tok)).is_none(), "session expirée refusée");
        let purged: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM session WHERE token_sha=?", [&token_sha], |r| r.get(0)).unwrap() };
        assert_eq!(purged, 0, "session expirée purgée");
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 RÉTRO-COMPAT] check_operator : repli bootstrap par hash env quand AUCUNE session n'est
    /// présentée — la console live (hash via env) continue de fonctionner.
    #[test]
    fn check_operator_falls_back_to_env_hash() {
        let path = tmp_path("forge-test-op-env");
        let mut app = test_app(&path);
        app.operator_hash = Arc::new(hash_pw("s3cr3t"));
        assert!(check_operator(&app, &operator_headers("s3cr3t"), None), "bonne preuve env -> opérateur");
        assert!(!check_operator(&app, &operator_headers("wrong"), None), "mauvaise preuve env -> refus");
        assert!(!check_operator(&app, &HeaderMap::new(), None), "aucune preuve -> refus (fail-closed)");
        // attribution sans session -> 'bootstrap' (compte env-hash).
        assert_eq!(attribution_login(&app, &operator_headers("s3cr3t")), "bootstrap");
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 sécurité] check_operator : une session VIEWER ne passe JAMAIS le C2, même si un hash env
    /// opérateur est présent (un viewer authentifié ne doit pas escalader via le secret partagé).
    /// Une session OPERATOR passe, et l'attribution porte le login individuel.
    #[test]
    fn session_viewer_cannot_arm_operator_can() {
        let path = tmp_path("forge-test-op-session");
        let mut app = test_app(&path);
        app.operator_hash = Arc::new(hash_pw("s3cr3t")); // hash env présent (ne doit pas sauver le viewer)
        {
            let db = app.db();
            upsert_user(&db, "viewy", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oppy", "operator", &hash_pw("pw")).unwrap();
        }
        let (vid, oid): (i64, i64) = {
            let db = app.db();
            (db.query_row("SELECT id FROM users WHERE login='viewy'", [], |r| r.get(0)).unwrap(),
             db.query_row("SELECT id FROM users WHERE login='oppy'", [], |r| r.get(0)).unwrap())
        };
        let (vtok, _) = create_session(&app, vid);
        let (otok, _) = create_session(&app, oid);
        assert!(!check_operator(&app, &bearer_headers(&vtok), None), "session viewer NE PASSE PAS le C2");
        assert!(check_operator(&app, &bearer_headers(&otok), None), "session operator passe le C2");
        assert_eq!(attribution_login(&app, &bearer_headers(&otok)), "oppy", "attribution = login individuel");
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 RÉTRO-COMPAT] attribution_login : sans aucune identité (dev-open, ni session ni hash env),
    /// retombe sur le littéral historique 'operator' (comportement existant préservé).
    #[test]
    fn attribution_defaults_to_operator_when_no_identity() {
        let path = tmp_path("forge-test-attr-default");
        let app = test_app(&path); // operator_hash vide
        assert_eq!(attribution_login(&app, &HeaderMap::new()), "operator");
        let _ = std::fs::remove_file(&path);
    }

    /// [SEC gate DB-state] auth_guard s'engage sur l'ÉTAT DB, pas seulement sur le hash env. Fresh
    /// install : hash env VIDE (pass_hash="") mais un compte ACTIVÉ présent -> gate engagée -> une
    /// requête sans preuve est REFUSÉE (le middleware répond alors 401, le SPA montre le login).
    /// Une session valide de ce compte passe. Ferme le trou dev-open « comptes en base, env vide ».
    #[test]
    fn auth_gate_engages_on_enabled_user_without_env_hash() {
        let path = tmp_path("forge-test-auth-gate");
        let app = test_app(&path); // pass_hash vide (dev), aucun compte au départ
        // 1) sans hash env ni compte -> dev-open : la gate est désengagée, tout passe.
        app.recompute_auth_required();
        assert!(!app.auth_required(), "sans hash env ni compte activé -> dev-open (gate désengagée)");
        assert!(auth_guard_allows(&app, &HeaderMap::new()), "dev-open : requête anonyme passe");
        // 2) un compte ACTIVÉ est provisionné en base -> après recompute, la gate DOIT s'engager,
        //    MÊME si le hash env reste vide (c'est exactement le trou historique qu'on ferme).
        {
            let db = app.db();
            upsert_user(&db, "erin", "viewer", &hash_pw("pw")).unwrap();
        }
        app.recompute_auth_required();
        assert!(app.auth_required(), "un compte activé engage la gate même sans hash env");
        assert!(!auth_guard_allows(&app, &HeaderMap::new()),
            "gate engagée : requête anonyme REFUSÉE -> le middleware renvoie 401");
        // 3) une session valide de ce compte passe la gate ; un token inconnu ne passe pas.
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='erin'", [], |r| r.get(0)).unwrap() };
        let (tok, _) = create_session(&app, uid);
        assert!(auth_guard_allows(&app, &bearer_headers(&tok)), "session individuelle valide passe la gate");
        assert!(!auth_guard_allows(&app, &bearer_headers("deadbeef")), "session inconnue -> refus (401)");
        // 4) contrapositive de la règle : désactiver l'UNIQUE compte, hash env toujours vide -> plus
        //    aucun compte activé -> la gate se désengage (règle « engage si hash OU compte activé »).
        { let db = app.db(); db.execute("UPDATE users SET disabled=1 WHERE id=?", [uid]).unwrap(); }
        app.recompute_auth_required();
        assert!(!app.auth_required(), "dernier compte activé désactivé + hash env vide -> gate désengagée");
        let _ = std::fs::remove_file(&path);
    }

    /// [SEC gate DB-state] un hash env posé engage la gate à lui seul (rétro-compat) : même sans aucun
    /// compte en base, auth_required=true et une requête anonyme est refusée.
    #[test]
    fn auth_gate_engages_on_env_hash_alone() {
        let path = tmp_path("forge-test-auth-gate-env");
        let mut app = test_app(&path);
        app.pass_hash = Arc::new(hash_pw("viewerpw")); // hash env posé, aucun compte en base
        app.recompute_auth_required();
        assert!(app.auth_required(), "hash env posé -> gate engagée même sans compte");
        assert!(!auth_guard_allows(&app, &HeaderMap::new()), "gate engagée : anonyme refusé (401)");
        // Basic viewer avec le bon mdp passe (rétro-compat viewer par hash env).
        let mut h = HeaderMap::new();
        let b64 = base64::engine::general_purpose::STANDARD.encode("forge:viewerpw");
        h.insert("authorization", format!("Basic {b64}").parse().unwrap());
        assert!(auth_guard_allows(&app, &h), "Basic viewer (hash env) passe la gate");
        let _ = std::fs::remove_file(&path);
    }

    /// [SEC admin] check_admin : FAIL-CLOSED, session ADMIN uniquement. Un viewer et un operator sont
    /// REFUSÉS ; un admin est autorisé. PAS de repli hash env (contrairement à operator) : une preuve
    /// X-Forge-Operator seule ne confère JAMAIS l'admin (attribution individuelle obligatoire).
    #[test]
    fn check_admin_requires_admin_session_no_env_fallback() {
        let path = tmp_path("forge-test-admin");
        let mut app = test_app(&path);
        app.operator_hash = Arc::new(hash_pw("s3cr3t")); // hash env opérateur présent -> ne doit PAS conférer l'admin
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let sid = |login: &str, app: &App| -> i64 {
            let db = app.db();
            db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
        };
        let (vtok, _) = create_session(&app, sid("vv", &app));
        let (otok, _) = create_session(&app, sid("oo", &app));
        let (atok, _) = create_session(&app, sid("aa", &app));
        assert!(!check_admin(&app, &bearer_headers(&vtok)), "viewer refusé (fail-closed)");
        assert!(!check_admin(&app, &bearer_headers(&otok)), "operator refusé (admin != operator)");
        assert!(check_admin(&app, &bearer_headers(&atok)), "admin autorisé");
        assert!(!check_admin(&app, &operator_headers("s3cr3t")), "hash env opérateur NE confère PAS l'admin (pas de repli)");
        assert!(!check_admin(&app, &HeaderMap::new()), "aucune preuve -> refus (fail-closed)");
        let _ = std::fs::remove_file(&path);
    }

    /// Récupère l'id d'un compte par login (helper de test).
    fn uid_of(app: &App, login: &str) -> i64 {
        let db = app.db();
        db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
    }
    /// Compte les sessions d'un user_id (helper de test).
    fn session_count(app: &App, uid: i64) -> i64 {
        let db = app.db();
        db.query_row("SELECT COUNT(*) FROM session WHERE user_id=?", [uid], |r| r.get(0)).unwrap()
    }

    /// [ADMIN #4] admin_create_user + admin_list_users : création, vue publique SANS pass_hash, ledger
    /// de création SANS mot de passe/hash, attribution à l'acteur, doublon de login -> 409.
    #[test]
    fn admin_create_lists_and_never_leaks_pass_hash() {
        let path = tmp_path("forge-test-admin-create");
        let app = test_app(&path);
        let out = admin_create_user(&app, "aa", &json!({"login": "newbie", "role": "viewer", "password": "s3cretPW"}))
            .expect("création OK");
        assert_eq!(out["login"], "newbie");
        assert_eq!(out["role"], "viewer");
        assert_eq!(out["disabled"], false);
        assert!(out.get("pass_hash").is_none(), "la réponse de création ne contient jamais pass_hash");
        // liste : champs attendus, pass_hash structurellement absent.
        let users = admin_list_users(&app);
        let u = users.iter().find(|u| u["login"] == "newbie").expect("compte listé");
        assert!(u.get("pass_hash").is_none(), "la liste ne renvoie JAMAIS pass_hash");
        assert_eq!(u["role"], "viewer");
        assert_eq!(u["disabled"], false);
        // ledger : entrée create, attribuée, SANS le mot de passe ni le hash argon2.
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.admin.user.create");
        assert_eq!(last["detail"]["actor"], "aa");
        assert_eq!(last["detail"]["login"], "newbie");
        let ser = canon_json(last).to_lowercase();
        assert!(!ser.contains("s3cretpw"), "le mot de passe ne DOIT jamais entrer dans le ledger");
        assert!(!ser.contains("argon2"), "le hash ne DOIT jamais entrer dans le ledger");
        // le compte est réellement provisionné avec un hash vérifiable (mais jamais exposé).
        let ph: String = { let db = app.db(); db.query_row("SELECT pass_hash FROM users WHERE login='newbie'", [], |r| r.get(0)).unwrap() };
        assert!(verify_pw("s3cretPW", &ph), "mot de passe créé vérifiable côté DB");
        // doublon de login -> 409 (l'édition sert à modifier).
        let dup = admin_create_user(&app, "aa", &json!({"login": "newbie", "role": "admin", "password": "x"}));
        assert_eq!(dup.unwrap_err().0, StatusCode::CONFLICT, "login déjà pris -> 409");
        // login/rôle invalides -> 400.
        assert_eq!(admin_create_user(&app, "aa", &json!({"login": "-bad", "role": "viewer", "password": "x"})).unwrap_err().0, StatusCode::BAD_REQUEST);
        assert_eq!(admin_create_user(&app, "aa", &json!({"login": "ok", "role": "root", "password": "x"})).unwrap_err().0, StatusCode::BAD_REQUEST);
        assert_eq!(admin_create_user(&app, "aa", &json!({"login": "ok", "role": "viewer", "password": ""})).unwrap_err().0, StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] admin_update_user : la DÉSACTIVATION purge les sessions du compte + ledgerise (actor,
    /// sessions_purged). La RÉTROGRADATION purge aussi. Le RESET de mot de passe purge et n'expose rien.
    #[test]
    fn admin_update_disable_downgrade_reset_purge_sessions_and_ledger() {
        let path = tmp_path("forge-test-admin-update");
        let app = test_app(&path);
        admin_create_user(&app, "boot", &json!({"login": "root", "role": "admin", "password": "pw"})).unwrap();
        admin_create_user(&app, "root", &json!({"login": "bob", "role": "operator", "password": "pw"})).unwrap();
        let bob = uid_of(&app, "bob");
        let (btok, _) = create_session(&app, bob);
        assert!(resolve_session_identity(&app, &bearer_headers(&btok)).is_some(), "session bob valide au départ");
        // DÉSACTIVATION -> purge des sessions + ledger.
        let out = admin_update_user(&app, "root", "bob", &json!({"disabled": true})).unwrap();
        assert_eq!(out["disabled"], true);
        assert_eq!(out["sessions_purged"], true);
        assert_eq!(session_count(&app, bob), 0, "les sessions du compte désactivé sont purgées");
        assert!(resolve_session_identity(&app, &bearer_headers(&btok)).is_none(), "session révoquée");
        let last = read_ledger_lines(&path).pop().unwrap();
        assert_eq!(last["kind"], "console.admin.user.update");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["sessions_purged"], true);
        // RÉTROGRADATION admin->viewer purge (créer un 2e admin d'abord pour ne pas heurter le garde-fou).
        admin_create_user(&app, "root", &json!({"login": "admin2", "role": "admin", "password": "pw"})).unwrap();
        let a2 = uid_of(&app, "admin2");
        let (a2tok, _) = create_session(&app, a2);
        let out = admin_update_user(&app, "root", "admin2", &json!({"role": "viewer"})).unwrap();
        assert_eq!(out["role"], "viewer");
        assert_eq!(out["sessions_purged"], true, "la rétrogradation purge les sessions");
        assert!(resolve_session_identity(&app, &bearer_headers(&a2tok)).is_none(), "session purgée après rétrogradation");
        // RESET de mot de passe : purge + nouveau mot de passe effectif + rien de sensible au ledger.
        let root_id = uid_of(&app, "root");
        let (rtok, _) = create_session(&app, root_id);
        let out = admin_update_user(&app, "root", "root", &json!({"password": "brandNEW"})).unwrap();
        assert_eq!(out["password_reset"], true);
        assert_eq!(out["sessions_purged"], true, "un reset de mot de passe purge les sessions");
        assert!(resolve_session_identity(&app, &bearer_headers(&rtok)).is_none(), "ancienne session invalidée par le reset");
        let ph: String = { let db = app.db(); db.query_row("SELECT pass_hash FROM users WHERE login='root'", [], |r| r.get(0)).unwrap() };
        assert!(verify_pw("brandNEW", &ph) && !verify_pw("pw", &ph), "nouveau mot de passe effectif, ancien invalidé");
        let ser = canon_json(&read_ledger_lines(&path).pop().unwrap()).to_lowercase();
        assert!(!ser.contains("brandnew"), "aucun mot de passe dans le ledger (reset)");
        // corps vide -> 400 (aucun changement).
        assert_eq!(admin_update_user(&app, "root", "root", &json!({})).unwrap_err().0, StatusCode::BAD_REQUEST);
        // cible inexistante -> 404.
        assert_eq!(admin_update_user(&app, "root", "ghost", &json!({"role": "viewer"})).unwrap_err().0, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] garde-fou DERNIER ADMIN (fail-closed 409) : impossible de désactiver, rétrograder ou
    /// supprimer le seul admin activé ; possible dès qu'il en existe un second. Un refus 409 NE
    /// ledgerise PAS. La suppression réussie purge les sessions et ledgerise (actor).
    #[test]
    fn admin_last_admin_is_protected_on_disable_downgrade_delete() {
        let path = tmp_path("forge-test-admin-last");
        let app = test_app(&path);
        admin_create_user(&app, "boot", &json!({"login": "root", "role": "admin", "password": "pw"})).unwrap();
        let root_id = uid_of(&app, "root");
        let (rtok, _) = create_session(&app, root_id);
        // seul admin activé : désactivation / rétrogradation / suppression -> 409, SANS ledgeriser.
        let before = read_ledger_lines(&path).len();
        assert_eq!(admin_update_user(&app, "root", "root", &json!({"disabled": true})).unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(admin_update_user(&app, "root", "root", &json!({"role": "viewer"})).unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(admin_delete_user(&app, "root", "root").unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(read_ledger_lines(&path).len(), before, "un refus 409 ne ledgerise pas");
        assert!(resolve_session_identity(&app, &bearer_headers(&rtok)).is_some(), "root intact -> sa session survit");
        // 2e admin -> la suppression du 1er devient possible (purge ses sessions + ledger delete).
        admin_create_user(&app, "root", &json!({"login": "root2", "role": "admin", "password": "pw"})).unwrap();
        let del = admin_delete_user(&app, "root2", "root").expect("avec 2 admins, suppression permise");
        assert_eq!(del["deleted"], "root");
        assert_eq!(session_count(&app, root_id), 0, "sessions du compte supprimé purgées");
        let last = read_ledger_lines(&path).pop().unwrap();
        assert_eq!(last["kind"], "console.admin.user.delete");
        assert_eq!(last["detail"]["actor"], "root2");
        assert_eq!(last["detail"]["login"], "root");
        // il ne reste que root2 (seul admin) -> re-bloqué.
        assert_eq!(admin_delete_user(&app, "root2", "root2").unwrap_err().0, StatusCode::CONFLICT);
        // un NON-admin peut être supprimé même seul de son rôle ; inexistant -> 404.
        admin_create_user(&app, "root2", &json!({"login": "viewy", "role": "viewer", "password": "pw"})).unwrap();
        assert!(admin_delete_user(&app, "root2", "viewy").is_ok());
        assert_eq!(admin_delete_user(&app, "root2", "ghost").unwrap_err().0, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] gate des ROUTES : viewer et operator (et l'anonyme) reçoivent 403 sur /api/users
    /// (list/create/update/delete) ; l'admin passe. Vérifie les handlers HTTP réels (check_admin).
    #[tokio::test]
    async fn users_routes_are_admin_only_403() {
        let path = tmp_path("forge-test-users-403");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        app.recompute_auth_required();
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));
        let (atok, _) = create_session(&app, uid_of(&app, "aa"));
        // GET : viewer/operator/anonyme -> 403 ; admin -> 200.
        assert_eq!(users_list(State(app.clone()), bearer_headers(&vtok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(users_list(State(app.clone()), bearer_headers(&otok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(users_list(State(app.clone()), HeaderMap::new()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(users_list(State(app.clone()), bearer_headers(&atok)).await.status(), StatusCode::OK);
        // POST create : operator -> 403 (et le compte n'est PAS créé) ; admin -> 200.
        let body = || Json(json!({"login": "mallory", "role": "viewer", "password": "pw"}));
        assert_eq!(users_create(State(app.clone()), bearer_headers(&otok), body()).await.status(), StatusCode::FORBIDDEN);
        assert!(!admin_list_users(&app).iter().any(|u| u["login"] == "mallory"), "un create refusé (403) ne provisionne rien");
        assert_eq!(users_create(State(app.clone()), bearer_headers(&atok), body()).await.status(), StatusCode::OK);
        // POST update + DELETE : viewer -> 403.
        assert_eq!(
            users_update(State(app.clone()), bearer_headers(&vtok), Path("mallory".into()), Json(json!({"role": "operator"}))).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            users_delete(State(app.clone()), bearer_headers(&vtok), Path("mallory".into())).await.status(),
            StatusCode::FORBIDDEN
        );
        let _ = std::fs::remove_file(&path);
    }

    /// [SUBSTRAT settings] settings_get/settings_set : round-trip d'une clé, upsert (pas de doublon),
    /// horodatage `updated` renseigné, clé absente -> None.
    #[test]
    fn settings_get_set_round_trip() {
        let path = tmp_path("forge-test-settings");
        let app = test_app(&path);
        let db = app.db();
        assert!(settings_get(&db, "operator_policy").is_none(), "clé absente -> None (aucune valeur inventée)");
        settings_set(&db, "operator_policy", "{\"arm_required\":true}").unwrap();
        assert_eq!(settings_get(&db, "operator_policy").as_deref(), Some("{\"arm_required\":true}"),
            "la valeur écrite est relue à l'identique (round-trip)");
        let updated: String = db.query_row("SELECT updated FROM settings WHERE key='operator_policy'", [], |r| r.get(0)).unwrap();
        assert!(!updated.is_empty(), "horodatage `updated` renseigné à l'écriture");
        // upsert : re-écrire la MÊME clé remplace la valeur sans créer de doublon (PRIMARY KEY).
        settings_set(&db, "operator_policy", "{\"arm_required\":false}").unwrap();
        assert_eq!(settings_get(&db, "operator_policy").as_deref(), Some("{\"arm_required\":false}"), "valeur mise à jour");
        let count: i64 = db.query_row("SELECT COUNT(*) FROM settings WHERE key='operator_policy'", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "PRIMARY KEY -> une seule ligne par clé (upsert, pas d'insertion doublon)");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------------------------------------
    // WIZARD 1er DÉPLOIEMENT + politique opérateur source-CIDR
    // ---------------------------------------------------------------------------------------------

    /// Client HTTP brut minimal (aucune dép externe) : envoie `req` et lit toute la réponse jusqu'à EOF
    /// (le serveur ferme la connexion sur `Connection: close`). Suffisant pour tester le câblage réel.
    async fn http_raw(addr: SocketAddr, req: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        s.write_all(req.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.expect("read");
        String::from_utf8_lossy(&buf).into_owned()
    }
    fn get_req(path: &str, extra: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\r\n")
    }
    fn post_req(path: &str, body: &str, extra: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
    }
    fn parse_status(resp: &str) -> u16 {
        resp.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }
    fn body_of(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }
    fn cookie_token(resp: &str) -> Option<String> {
        let head = resp.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(resp);
        let idx = head.find("forge_session=")?;
        let rest = &head[idx + "forge_session=".len()..];
        let end = rest.find(';').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }

    /// [SETUP wizard] Flux END-TO-END sur le VRAI routeur (build_router) : fresh -> needs_setup ;
    /// POST /api/setup crée l'admin, pose le cookie, bascule provisioned ; 2e POST -> 409 ;
    /// detection_source + operator_policy atterrissent dans settings ; /api/setup* restent joignables
    /// SANS auth tandis qu'une route protégée (/api/whoami) passe à 401 une fois la gate engagée.
    #[tokio::test]
    async fn setup_wizard_live_end_to_end() {
        let ledger = tmp_path("forge-test-setup-ledger");
        let app = test_app(&ledger);
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // 1) fresh install -> needs_setup:true, sqlcipher:false (build par défaut), joignable SANS auth.
        let r = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert_eq!(parse_status(&r), 200, "setup/state public: {r}");
        assert!(body_of(&r).contains("\"needs_setup\":true"), "fresh -> needs_setup:true : {}", body_of(&r));
        assert!(body_of(&r).contains("\"provisioned\":false"));
        assert!(body_of(&r).contains("\"sqlcipher\":false"), "build par défaut -> sqlcipher:false");

        // 2) POST /api/setup SANS auth -> 200 + cookie posé + settings persistés.
        let setup_body = json!({
            "admin_login": "root",
            "admin_password": "hunter2pw",
            "session_ttl": 1800,
            "operator_policy": {"require_reason": true, "source_cidrs": ["10.0.0.0/24"], "high_impact_approval": false},
            "detection_source": {"kind": "plume", "endpoint": "http://soc.local:8080", "auth_type": "basic"}
        })
        .to_string();
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 200, "provision -> 200 : {r}");
        assert!(body_of(&r).contains("\"provisioned\":true"));
        let tok = cookie_token(&r).expect("cookie forge_session posé par le provisioning");
        assert!(!tok.is_empty());

        // 3) l'état bascule : provisioned:true / needs_setup:false.
        let r = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert!(body_of(&r).contains("\"needs_setup\":false"), "après provision -> needs_setup:false");
        assert!(body_of(&r).contains("\"provisioned\":true"));

        // 4) SECONDE provision -> 409 (route auto-désactivante).
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 409, "2e provision -> 409 : {r}");

        // 5) detection_source + operator_policy (+ session_ttl) atterrissent VERBATIM dans settings.
        {
            let db = app.db();
            assert!(settings_get(&db, "operator_policy").unwrap().contains("10.0.0.0/24"), "operator_policy stocké");
            assert!(settings_get(&db, "detection_source").unwrap().contains("plume"), "detection_source stocké");
            assert_eq!(settings_get(&db, "session_ttl").as_deref(), Some("1800"), "session_ttl stocké");
        }
        assert!(app.any_enabled_admin(), "un admin activé existe après provision");

        // 6) la gate d'auth est désormais engagée : /api/whoami SANS auth -> 401 ; AVEC session -> 200.
        let r = http_raw(addr, &get_req("/api/whoami", "")).await;
        assert_eq!(parse_status(&r), 401, "route protégée sans auth, gate engagée -> 401 : {r}");
        let r = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "route protégée avec session -> 200 : {r}");
        assert!(body_of(&r).contains("\"login\":\"root\""), "session = nouvel admin root : {}", body_of(&r));

        // 7) /api/setup/state RESTE joignable sans auth même gate engagée (hors auth_guard).
        let r = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert_eq!(parse_status(&r), 200, "setup/state toujours public une fois provisionné");

        // ledger : entrée de provision attribuée à root, JAMAIS le mot de passe/hash.
        let last = read_ledger_lines(&ledger).pop().expect("ledger provision");
        assert_eq!(last["kind"], "console.setup.provision");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["operator_policy_set"], true);
        assert_eq!(last["detail"]["detection_source_set"], true);
        let ser = canon_json(&last).to_lowercase();
        assert!(!ser.contains("hunter2pw"), "le mot de passe ne DOIT jamais entrer dans le ledger");
        assert!(!ser.contains("argon2"), "le hash ne DOIT jamais entrer dans le ledger");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [SETUP migrate] POST /api/setup/migrate : PUBLIC en pré-provision (exécute la migration + rend
    /// le rapport verify), puis AUTO-DÉSACTIVANTE (409) dès qu'un admin activé existe. Chemin plaintext
    /// (aucun sqlcipher requis).
    // env_lock() sérialise l'ENV process-global entre threads de test ; le garder à travers l'await
    // de setup_migrate est VOULU (l'ENV doit rester stable pendant l'appel awaité). Runtime de test
    // current_thread => aucun risque de blocage de l'exécuteur.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn setup_migrate_public_pre_provision_then_409_once_provisioned() {
        // COUCHE 1+2 activées : flag opt-in ON + racine d'import = temp_dir (où vivent from/to/ledger)
        // -> l'endpoint accepte l'import pré-provision. (Le verrou sérialise vs le test flag-OFF.)
        let _g = env_lock();
        std::env::set_var("FORGE_ALLOW_API_MIGRATE", "1");
        std::env::set_var("FORGE_CONSOLE_IMPORT_DIR", std::env::temp_dir().to_string_lossy().to_string());

        // source sur disque : base ANCIENNE + ledger intact.
        let src_dir = tmp_dir("forge-mig-http-src");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        ledger_append_standalone(&src_ledger, "engagement.start", &json!({"a": 1})).unwrap();

        let led = tmp_path("forge-test-setup-migrate-ledger");
        let app = test_app(&led);
        let to = tmp_path("forge-mig-http-to.db");
        let target_ledger = tmp_path("forge-mig-http-to.jsonl");
        let body = json!({"from": src_dir, "to": to, "ledger": target_ledger, "verify": true});

        // 1) PRÉ-PROVISION : route publique -> exécute la migration -> 200 + cible écrite.
        let r = setup_migrate(State(app.clone()), Json(body.clone())).await;
        assert_eq!(r.status(), StatusCode::OK, "pré-provision -> 200");
        assert!(std::path::Path::new(&to).exists(), "migration exécutée (cible écrite)");

        // 2) provisionne un admin -> la route se ferme (409), sans relancer de migration.
        {
            let db = app.db();
            upsert_user(&db, "root", "admin", &hash_pw("pw123456")).unwrap();
        }
        app.recompute_auth_required();
        assert!(app.provisioned(), "un admin activé -> provisionné");
        let r = setup_migrate(State(app.clone()), Json(body)).await;
        assert_eq!(r.status(), StatusCode::CONFLICT, "une fois provisionné -> 409");

        std::env::remove_var("FORGE_ALLOW_API_MIGRATE");
        std::env::remove_var("FORGE_CONSOLE_IMPORT_DIR");
        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&led);
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::remove_file(&target_ledger);
        let _ = std::fs::remove_file(format!("{target_ledger}.ed25519"));
    }

    /// [SETUP migrate — COUCHE 1] Défaut OFF : sans FORGE_ALLOW_API_MIGRATE, l'endpoint REFUSE (403)
    /// AVANT toute I/O — la primitive d'écriture/suppression de fichier non-auth n'existe pas dans le
    /// déploiement par défaut. Preuve : la cible n'est JAMAIS écrite malgré une source valide.
    // env_lock() sérialise l'ENV process-global entre threads de test ; le garder à travers l'await
    // de setup_migrate est VOULU (l'ENV doit rester stable pendant l'appel awaité). Runtime de test
    // current_thread => aucun risque de blocage de l'exécuteur.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn setup_migrate_api_disabled_by_default_no_file_op() {
        let _g = env_lock();
        std::env::remove_var("FORGE_ALLOW_API_MIGRATE");

        let src_dir = tmp_dir("forge-mig-flagoff-src");
        seed_old_source_db(&format!("{src_dir}/forge-console.db"));
        let led = tmp_path("forge-mig-flagoff-led");
        let app = test_app(&led); // non provisionnée -> la fenêtre de setup est ouverte.
        assert!(!app.provisioned(), "console non provisionnée (fenêtre setup ouverte)");
        let to = tmp_path("forge-mig-flagoff-to.db");
        let body = json!({"from": src_dir, "to": to});

        let r = setup_migrate(State(app.clone()), Json(body)).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "flag OFF -> 403 (migration API désactivée)");
        assert!(!std::path::Path::new(&to).exists(), "AUCUN fichier écrit quand la migration API est OFF");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&led);
    }

    /// [SETUP migrate — COUCHE 2] Validation de chemin (flag ON) : (c) cible/ source SOUS la base
    /// acceptées ; (b) traversal `..` + absolu hors base rejetés ; (d) cible PRÉEXISTANTE hors base
    /// refusée SANS y toucher. Teste le helper directement (base injectée) -> aucune course d'ENV.
    #[test]
    fn api_migrate_path_validation_confines_to_base() {
        let base = tmp_dir("forge-mig-base");
        let base_canon = std::path::Path::new(&base).canonicalize().expect("canon base");

        // (c) cible neuve VALIDE sous la base (parent = base existe, fichier absent) -> acceptée.
        let ok_to = format!("{base}/staging.db");
        assert!(validate_api_migrate_path(&base_canon, &ok_to, "to", false).is_ok(),
            "cible neuve sous la base -> acceptée");
        // source existante VALIDE sous la base -> acceptée (must_exist).
        let src = format!("{base}/src.db");
        std::fs::write(&src, b"x").unwrap();
        assert!(validate_api_migrate_path(&base_canon, &src, "from", true).is_ok(),
            "source existante sous la base -> acceptée");

        // (b) traversal `..` -> rejeté AVANT toute résolution.
        let trav = format!("{base}/../etc/evil");
        assert!(validate_api_migrate_path(&base_canon, &trav, "to", false).is_err(),
            "composant `..` -> rejeté");
        // (b bis) chemin ABSOLU hors base -> rejeté.
        assert!(validate_api_migrate_path(&base_canon, "/etc/passwd", "from", true).is_err(),
            "absolu hors base -> rejeté");
        // source inexistante -> rejetée (introuvable), jamais silencieusement acceptée.
        assert!(validate_api_migrate_path(&base_canon, &format!("{base}/nope.db"), "from", true).is_err(),
            "source introuvable -> rejetée");

        // (d) cible PRÉEXISTANTE hors base -> refus d'écrasement, fichier intact.
        let outside_dir = tmp_dir("forge-mig-outside");
        let victim = format!("{outside_dir}/victim.db");
        std::fs::write(&victim, b"precious").unwrap();
        assert!(validate_api_migrate_path(&base_canon, &victim, "to", false).is_err(),
            "cible préexistante HORS base -> refusée (pas d'écrasement)");
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious", "la cible hors base reste intacte");

        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside_dir);
    }

    /// [SETUP wizard] Validation d'entrée + auto-désactivation par HASH ENV : login invalide -> 400,
    /// mot de passe vide -> 400 ; une install avec un hash d'amorçage env est déjà provisionnée -> 409
    /// (pas de nouvelle provision anonyme), même sans compte en base.
    #[tokio::test]
    async fn setup_provision_validates_and_self_disables_on_env_hash() {
        let path = tmp_path("forge-test-setup-validate");
        // login invalide -> 400
        {
            let app = test_app(&path);
            let r = setup_provision(State(app.clone()), Json(json!({"admin_login": "-bad", "admin_password": "x"}))).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "login invalide -> 400");
            // mot de passe vide -> 400
            let r = setup_provision(State(app.clone()), Json(json!({"admin_login": "ok", "admin_password": ""}))).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "mot de passe vide -> 400");
            assert!(!app.any_enabled_admin(), "aucun refus 400 ne provisionne quoi que ce soit");
        }
        // hash env d'amorçage posé -> provisioned d'emblée -> 409.
        {
            let mut app = test_app(&path);
            app.pass_hash = Arc::new(hash_pw("bootstrap"));
            app.recompute_auth_required();
            assert!(app.provisioned(), "hash env -> déjà provisionné");
            let r = setup_provision(State(app.clone()), Json(json!({"admin_login": "root", "admin_password": "x"}))).await;
            assert_eq!(r.status(), StatusCode::CONFLICT, "hash env d'amorçage -> /api/setup fermée (409)");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// [OPÉRATEUR source-CIDR] ip_in_cidr : appartenance v4/v6, IP exacte, /0, familles hétérogènes,
    /// et rejet fail-closed des entrées malformées (préfixe non numérique / hors borne, réseau invalide).
    #[test]
    fn ip_in_cidr_membership_and_fail_closed() {
        let v4 = "10.0.0.5".parse::<IpAddr>().unwrap();
        assert!(ip_in_cidr(&v4, "10.0.0.0/24"));
        assert!(ip_in_cidr(&v4, "10.0.0.0/8"));
        assert!(!ip_in_cidr(&v4, "10.0.1.0/24"));
        assert!(ip_in_cidr(&v4, "10.0.0.5"), "sans '/' -> comparaison exacte");
        assert!(!ip_in_cidr(&v4, "10.0.0.6"));
        assert!(ip_in_cidr(&v4, "0.0.0.0/0"), "/0 -> tout l'espace v4");
        assert!(!ip_in_cidr(&v4, "garbage"), "réseau invalide -> false");
        assert!(!ip_in_cidr(&v4, "10.0.0.0/33"), "préfixe hors borne -> false");
        assert!(!ip_in_cidr(&v4, "10.0.0.0/x"), "préfixe non numérique -> false");
        let v6 = "2001:db8::5".parse::<IpAddr>().unwrap();
        assert!(ip_in_cidr(&v6, "2001:db8::/32"));
        assert!(!ip_in_cidr(&v6, "2001:dead::/32"));
        assert!(!ip_in_cidr(&v4, "2001:db8::/32"), "v4 vs réseau v6 -> false");
        assert!(!ip_in_cidr(&v6, "10.0.0.0/8"), "v6 vs réseau v4 -> false");
    }

    /// [OPÉRATEUR source-CIDR] check_operator : la contrainte source ne s'applique QUE si configurée.
    /// Non configurée -> toute IP passe (défaut = none). Configurée -> hors-allowlist REFUSÉ, dans
    /// l'allowlist AUTORISÉ, IP indéterminée REFUSÉE (fail-closed). trusted_proxy (CIDR du proxy) ->
    /// honore le dernier hop XFF UNIQUEMENT si le pair TCP EST ce proxy ; un client direct (pair hors
    /// CIDR) qui forge un XFF est IGNORÉ (repli sur le pair) ; valeur héritée "1" -> aucun proxy de
    /// confiance. Un viewer ne passe jamais.
    #[tokio::test]
    async fn operator_source_cidr_enforced_only_when_configured() {
        let path = tmp_path("forge-test-op-cidr");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "op", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
        }
        let (otok, _) = create_session(&app, uid_of(&app, "op"));
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let h = bearer_headers(&otok);
        let ip_ok = "10.0.0.5".parse::<IpAddr>().unwrap();
        let ip_bad = "192.168.1.9".parse::<IpAddr>().unwrap();

        // (a) AUCUNE politique -> toute IP passe (défaut = none), y compris IP indéterminée.
        assert!(check_operator(&app, &h, Some(ip_ok)));
        assert!(check_operator(&app, &h, Some(ip_bad)), "sans politique, IP hors 'futur allowlist' passe");
        assert!(check_operator(&app, &h, None), "sans politique, IP indéterminée passe");

        // (b) politique source_cidrs configurée -> restriction fail-closed.
        {
            let db = app.db();
            settings_set(&db, "operator_policy", "{\"source_cidrs\":[\"10.0.0.0/24\"]}").unwrap();
        }
        assert!(check_operator(&app, &h, Some(ip_ok)), "IP dans le CIDR -> autorisée");
        assert!(!check_operator(&app, &h, Some(ip_bad)), "IP hors CIDR -> refusée (fail-closed)");
        assert!(!check_operator(&app, &h, None), "politique active + IP indéterminée -> refus");

        // (c) AUCUN trusted_proxy configuré -> X-Forwarded-For IGNORÉ (on prend le pair). Pair hors
        //     CIDR -> refus, même si le XFF prétend une IP autorisée.
        let mut hx = bearer_headers(&otok);
        hx.insert("x-forwarded-for", "10.0.0.5".parse().unwrap());
        assert!(!check_operator(&app, &hx, Some(ip_bad)), "sans trusted_proxy -> XFF ignoré, pair hors CIDR -> refus");

        // (d) [RÉTRO-COMPAT] valeur héritée "1" (truthy non-CIDR) -> traitée comme AUCUN proxy de
        //     confiance -> XFF ignoré, repli fail-closed sur le pair. Ne vaut JAMAIS « fais confiance à
        //     tout XFF » (ce qui rouvrirait le contournement).
        {
            let db = app.db();
            settings_set(&db, "trusted_proxy", "1").unwrap();
        }
        let mut hlegacy = bearer_headers(&otok);
        hlegacy.insert("x-forwarded-for", "203.0.113.7, 10.0.0.5".parse().unwrap());
        assert!(!check_operator(&app, &hlegacy, Some(ip_bad)),
            "trusted_proxy='1' (héritée) -> aucun proxy de confiance -> XFF ignoré, pair hors CIDR -> refus");

        // On configure désormais trusted_proxy = le CIDR RÉEL du proxy amont.
        {
            let db = app.db();
            settings_set(&db, "trusted_proxy", "172.16.0.0/12").unwrap();
        }
        let proxy_ip = "172.16.0.9".parse::<IpAddr>().unwrap(); // pair ∈ trusted_proxy CIDR

        // (e) [RÉGRESSION anti-contournement] client DIRECT (pair hors trusted_proxy CIDR) qui FORGE un
        //     X-Forwarded-For revendiquant une IP de l'allowlist -> XFF IGNORÉ (le pair n'est pas le
        //     proxy) -> repli sur le pair (ip_bad) -> REFUSÉ. Fermeture du bypass XFF spoofé.
        let mut hspoof = bearer_headers(&otok);
        hspoof.insert("x-forwarded-for", "10.0.0.5".parse().unwrap());
        assert!(!check_operator(&app, &hspoof, Some(ip_bad)),
            "client direct + XFF spoofé prétendant une IP autorisée -> XFF ignoré, repli sur pair -> REFUSÉ (bypass fermé)");

        // (f) requête RÉELLEMENT relayée : le pair TCP EST le proxy de confiance (∈ CIDR) et le dernier
        //     hop XFF est dans l'allowlist opérateur -> honoré -> AUTORISÉ (le pair-proxy n'est PAS dans
        //     l'allowlist, ce qui prouve que c'est bien le XFF qui décide).
        let mut hp = bearer_headers(&otok);
        hp.insert("x-forwarded-for", "203.0.113.7, 10.0.0.5".parse().unwrap());
        assert!(check_operator(&app, &hp, Some(proxy_ip)),
            "pair = proxy de confiance + dernier hop XFF dans le CIDR -> autorisé");

        // (f-bis) même proxy de confiance mais dernier hop XFF hors allowlist -> refusé (fail-closed sur
        //     l'IP réelle du client telle que déclarée par le proxy).
        let mut hp2 = bearer_headers(&otok);
        hp2.insert("x-forwarded-for", "203.0.113.7, 192.168.1.9".parse().unwrap());
        assert!(!check_operator(&app, &hp2, Some(proxy_ip)),
            "pair = proxy de confiance mais dernier hop XFF hors CIDR -> refusé");

        // (g) un viewer ne passe JAMAIS, quelle que soit l'IP/politique.
        assert!(!check_operator(&app, &bearer_headers(&vtok), Some(ip_ok)), "viewer refusé indépendamment de la politique source");
        let _ = std::fs::remove_file(&path);
    }

    /// [SÉCURITÉ XFF] parse_trusted_proxy_cidrs : tableau JSON / CSV / CIDR unique -> liste ; valeurs
    /// héritées truthy non-CIDR ("1"/"true"), vide, ou déchet -> liste VIDE (aucun proxy de confiance).
    /// effective_client_ip : XFF honoré SEULEMENT si le pair ∈ un trusted_proxy CIDR ; sinon IGNORÉ
    /// (repli fail-closed sur le pair, ou None si pair inconnu).
    #[test]
    fn trusted_proxy_cidr_parse_and_effective_ip_fail_closed() {
        // parse : formats acceptés
        assert_eq!(parse_trusted_proxy_cidrs("10.0.0.0/24"), vec!["10.0.0.0/24".to_string()]);
        assert_eq!(parse_trusted_proxy_cidrs("[\"10.0.0.0/24\",\"172.16.0.0/12\"]"),
                   vec!["10.0.0.0/24".to_string(), "172.16.0.0/12".to_string()]);
        assert_eq!(parse_trusted_proxy_cidrs("10.0.0.0/24, 172.16.0.0/12"),
                   vec!["10.0.0.0/24".to_string(), "172.16.0.0/12".to_string()]);
        assert_eq!(parse_trusted_proxy_cidrs("203.0.113.4"), vec!["203.0.113.4".to_string()], "IP nue -> match exact");
        // parse : héritées / invalides -> vide (fail-closed, jamais « trust all »)
        assert!(parse_trusted_proxy_cidrs("1").is_empty(), "'1' hérité -> aucun proxy de confiance");
        assert!(parse_trusted_proxy_cidrs("true").is_empty(), "'true' hérité -> aucun proxy de confiance");
        assert!(parse_trusted_proxy_cidrs("").is_empty());
        assert!(parse_trusted_proxy_cidrs("garbage").is_empty());
        assert!(parse_trusted_proxy_cidrs("10.0.0.0/33").is_empty(), "préfixe hors borne -> écarté");

        let cidrs = vec!["172.16.0.0/12".to_string()];
        let proxy = "172.16.0.9".parse::<IpAddr>().unwrap();
        let direct = "192.168.1.9".parse::<IpAddr>().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.5".parse().unwrap());

        // pair = proxy de confiance -> dernier hop XFF honoré
        assert_eq!(effective_client_ip(Some(proxy), &h, &cidrs), Some("10.0.0.5".parse().unwrap()));
        // pair = client direct (hors CIDR) -> XFF IGNORÉ, repli sur le pair
        assert_eq!(effective_client_ip(Some(direct), &h, &cidrs), Some(direct));
        // aucun trusted_proxy -> XFF ignoré, repli sur le pair
        assert_eq!(effective_client_ip(Some(proxy), &h, &[]), Some(proxy));
        // pair inconnu -> None (fail-closed), jamais l'XFF
        assert_eq!(effective_client_ip(None, &h, &cidrs), None);
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

    /// [WebUI] L'aide in-app est présente et accessible : bouton « ? » persistant (annoncé comme
    /// dialog) + indices de champ inline sur le wizard config-heavy dans l'index compilé, et le front
    /// définit le centre d'aide (openHelp + registre HELP_TOPICS + rubrique gouvernance/modèle de
    /// sûreté) avec la modale role=dialog/aria-modal et les indices des formulaires config-heavy.
    /// Garde-fou anti-régression : ces marqueurs ne doivent pas disparaître silencieusement.
    #[test]
    fn webui_help_affordance_and_registry_present() {
        let index = include_str!("../web/index.html");
        assert!(index.contains("id=\"help\""), "bouton d'aide manquant dans l'en-tête");
        assert!(index.contains("aria-haspopup=\"dialog\""), "affordance d'aide non annoncée comme dialog");
        assert!(index.contains("class=\"fhint\""), "indices de champ (.fhint) absents du wizard de 1er déploiement");

        let app = include_str!("../web/app.js");
        assert!(app.contains("function openHelp("), "openHelp() absent du front");
        assert!(app.contains("HELP_TOPICS"), "registre d'aide HELP_TOPICS absent");
        assert!(app.contains("'governance'"), "rubrique « Comment Forge fonctionne » (gouvernance) absente");
        assert!(app.contains("'aria-modal'"), "la modale d'aide n'est pas marquée aria-modal");
        assert!(app.contains("'dialog'"), "la modale d'aide n'a pas role=dialog");
        assert!(app.contains("modal-fhint"), "indices de champ des modales (users/backup) absents");
        assert!(app.contains("det-fhint"), "indices de champ de la source de détection absents");
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

    // =========================================================================================
    // MIGRATION DE DONNÉES — chemin PLAINTEXT (aucun sqlcipher requis : ces tests tournent dans la
    // suite PAR DÉFAUT). Le chemin CHIFFRÉ est gardé derrière `#[cfg(feature="encryption")]` plus bas
    // (skip quand non compilé) pour ne JAMAIS faire dépendre la suite par défaut de SQLCipher/openssl.
    // =========================================================================================

    /// Crée un dossier temporaire unique.
    fn tmp_dir(name: &str) -> String {
        let d = tmp_path(name);
        std::fs::create_dir_all(&d).expect("mkdir tmp");
        d
    }

    /// Sème une base SOURCE au schéma ANCIEN : `finding` SANS les colonnes additives (cwe/run_id/…),
    /// et PAS de table settings/users. La migration doit l'upgrader EN PLACE (SCHEMA + migrate()).
    fn seed_old_source_db(path: &str) {
        let c = Connection::open(path).expect("open src db");
        c.execute_batch(
            "CREATE TABLE finding(id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, title TEXT,
                severity TEXT, category TEXT, mitre TEXT, status TEXT, evidence TEXT, tool TEXT, poc TEXT);",
        )
        .expect("old schema");
        c.execute(
            "INSERT INTO finding(id,title,target,campaign) VALUES(1,'old-finding','h.example','c1')",
            [],
        )
        .expect("insert old row");
    }

    /// [MIGRATION plaintext] copie COHÉRENTE (VACUUM INTO) + upgrade EN PLACE : la cible reçoit les
    /// colonnes additives (cwe) et les tables neuves (settings) via SCHEMA+migrate(), la donnée
    /// source survit, le ledger + la clé voyagent, et le ledger cible reste VÉRIFIABLE (chaîne
    /// SHA-256 continue avec l'entrée `console.migrate`).
    #[test]
    fn migrate_plaintext_copies_and_upgrades_schema() {
        let src_dir = tmp_dir("forge-mig-src");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        // ledger source (2 entrées chaînées) + clé de signature .ed25519.
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        ledger_append_standalone(&src_ledger, "engagement.start", &json!({"a": 1})).unwrap();
        ledger_append_standalone(&src_ledger, "action.recon", &json!({"a": 2})).unwrap();
        std::fs::write(format!("{src_ledger}.ed25519"), b"fake-ed25519-key-32-bytes-xxxxxx").unwrap();

        let to = tmp_path("forge-mig-to.db");
        let target_ledger = tmp_path("forge-mig-to.jsonl");
        let opts = MigrateOpts {
            from: src_dir.clone(),
            to: to.clone(),
            ledger: Some(target_ledger.clone()),
            verify: true,
            encrypt: false,
            key_env: None,
            actor: "test".to_string(),
        };
        let report = run_migration(&opts).expect("migration doit réussir");
        assert_eq!(report["ok"], true);
        assert_eq!(report["encrypted"], false, "build par défaut -> copie en clair");
        assert_eq!(report["verify"]["ok"], true, "ledger source intact -> verify ok");

        // 1) schéma UPGRADÉ en place : colonne additive `cwe` présente, donnée source préservée.
        let dst = Connection::open(&to).expect("open target");
        let cwe: String = dst
            .query_row("SELECT cwe FROM finding WHERE id=1", [], |r| r.get(0))
            .expect("colonne cwe ajoutée par migrate()");
        assert_eq!(cwe, "", "cwe = DEFAULT '' sur une ligne migrée");
        let title: String = dst.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding", "la donnée source survit à la copie");
        // 2) table neuve `settings` créée par SCHEMA sur la cible (absente de la source ancienne).
        let n: i64 = dst.query_row("SELECT count(*) FROM settings", [], |r| r.get(0)).expect("table settings créée");
        assert_eq!(n, 0);

        // 3) ledger + clé copiés ; ledger cible VÉRIFIABLE (2 source + 1 console.migrate = 3, intègre).
        assert_eq!(report["ledger_copied"], true);
        assert_eq!(report["key_copied"], true);
        assert!(std::path::Path::new(&format!("{target_ledger}.ed25519")).exists(), "clé .ed25519 copiée");
        let v = verify_ledger_chain(&target_ledger);
        assert!(v.ok, "ledger cible doit rester intègre après l'append console.migrate");
        assert_eq!(v.entries, 3, "2 entrées source + 1 entrée de migration");
        let last = read_ledger_lines(&target_ledger).pop().unwrap();
        assert_eq!(last["kind"], "console.migrate", "la migration est tracée au ledger cible");
        assert_eq!(last["detail"]["encrypted"], false);

        drop(dst);
        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::remove_file(&target_ledger);
        let _ = std::fs::remove_file(format!("{target_ledger}.ed25519"));
    }

    /// [MIGRATION --verify] passe sur un ledger INTACT et ABORTE (aucune écriture cible) sur un ledger
    /// ALTÉRÉ (une entrée tamperée casse le recompute de hash).
    #[test]
    fn migrate_verify_passes_intact_aborts_on_tamper() {
        // --- cas INTACT : verify ok, migration réussit. ---
        let src_dir = tmp_dir("forge-mig-verify-ok");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        for i in 0..4 {
            ledger_append_standalone(&src_ledger, "console.test", &json!({"i": i, "msg": "événement"})).unwrap();
        }
        let to_ok = tmp_path("forge-mig-verify-ok-to.db");
        let led_ok = tmp_path("forge-mig-verify-ok-to.jsonl");
        let ok_opts = MigrateOpts {
            from: src_dir.clone(), to: to_ok.clone(), ledger: Some(led_ok.clone()),
            verify: true, encrypt: false, key_env: None, actor: "test".to_string(),
        };
        let r = run_migration(&ok_opts).expect("ledger intact -> migration réussit");
        assert_eq!(r["verify"]["ok"], true);
        assert!(std::path::Path::new(&to_ok).exists(), "cible écrite quand le ledger est intact");

        // --- cas ALTÉRÉ : on tampere une entrée -> verify échoue -> ABORT avant toute écriture. ---
        let src_dir2 = tmp_dir("forge-mig-verify-tamper");
        let src_db2 = format!("{src_dir2}/forge-console.db");
        seed_old_source_db(&src_db2);
        let src_ledger2 = format!("{src_dir2}/engagement.jsonl");
        for i in 0..4 {
            ledger_append_standalone(&src_ledger2, "console.test", &json!({"i": i, "msg": "événement"})).unwrap();
        }
        // altère le CONTENU d'une entrée sans recalculer son hash -> "hash recalculé != stocké".
        let tampered = std::fs::read_to_string(&src_ledger2).unwrap().replacen("événement", "ALTÉRÉ", 1);
        std::fs::write(&src_ledger2, tampered).unwrap();
        // pré-condition : la vérif détecte bien la rupture.
        let vchk = verify_ledger_chain(&src_ledger2);
        assert!(!vchk.ok && vchk.exists, "le ledger tamperé doit être détecté comme rompu");

        let to_bad = tmp_path("forge-mig-verify-tamper-to.db");
        let bad_opts = MigrateOpts {
            from: src_dir2.clone(), to: to_bad.clone(), ledger: Some(tmp_path("forge-mig-tamper-to.jsonl")),
            verify: true, encrypt: false, key_env: None, actor: "test".to_string(),
        };
        let err = run_migration(&bad_opts).expect_err("ledger rompu -> migration AVORTÉE");
        assert!(err.contains("AVORTÉE"), "message d'abort explicite: {err}");
        assert!(!std::path::Path::new(&to_bad).exists(), "AUCUNE écriture cible sur abort (verify avant copie)");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&src_dir2);
        let _ = std::fs::remove_file(&to_ok);
        let _ = std::fs::remove_file(&led_ok);
        let _ = std::fs::remove_file(format!("{led_ok}.ed25519"));
    }

    /// [MIGRATION clé] la clé de signature `.ed25519` voyage AVEC le ledger, en mode 0600 FORCÉ
    /// (même si la source est plus permissive) — sinon la chaîne signée devient invérifiable.
    #[cfg(unix)]
    #[test]
    fn migrate_copies_ed25519_key_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let src_dir = tmp_dir("forge-mig-key");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        ledger_append_standalone(&src_ledger, "engagement.start", &json!({"a": 1})).unwrap();
        // clé source DÉLIBÉRÉMENT en 0644 -> prouve que la copie FORCE 0600 (pas un simple héritage).
        let src_key = format!("{src_ledger}.ed25519");
        std::fs::write(&src_key, b"raw-ed25519-private-key-32-bytes").unwrap();
        std::fs::set_permissions(&src_key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let to = tmp_path("forge-mig-key-to.db");
        let target_ledger = tmp_path("forge-mig-key-to.jsonl");
        let opts = MigrateOpts {
            from: src_dir.clone(), to: to.clone(), ledger: Some(target_ledger.clone()),
            verify: false, encrypt: false, key_env: None, actor: "test".to_string(),
        };
        run_migration(&opts).expect("migration ok");

        let dst_key = format!("{target_ledger}.ed25519");
        assert!(std::path::Path::new(&dst_key).exists(), "clé .ed25519 copiée dans le dossier ledger cible");
        let mode = std::fs::metadata(&dst_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "la clé doit être 0600 (secret de signature)");
        // contenu identique (la clé est le même secret).
        assert_eq!(std::fs::read(&dst_key).unwrap(), b"raw-ed25519-private-key-32-bytes");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::remove_file(&target_ledger);
        let _ = std::fs::remove_file(&dst_key);
    }

    /// [MIGRATION chiffrement — build par défaut] `--encrypt` sans la feature `encryption` renvoie une
    /// ERREUR CLAIRE (jamais un faux succès en clair). Ce test n'existe QUE dans le build par défaut.
    #[cfg(not(feature = "encryption"))]
    #[test]
    fn migrate_encrypt_without_feature_errors_clearly() {
        let src_dir = tmp_dir("forge-mig-noenc");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let opts = MigrateOpts {
            from: src_dir.clone(), to: tmp_path("forge-mig-noenc-to.db"), ledger: None,
            verify: false, encrypt: true, key_env: Some("FORGE_TEST_KEY".to_string()), actor: "test".to_string(),
        };
        let err = run_migration(&opts).expect_err("encrypt sans feature -> erreur");
        assert!(err.contains("NON compilé") || err.contains("features encryption"),
            "message doit dire que le chiffrement n'est pas compilé: {err}");
        let _ = std::fs::remove_dir_all(&src_dir);
    }

    /// [MIGRATION chiffrement — build chiffré] plaintext -> SQLCipher -> relecture avec la clé. GARDÉ
    /// derrière `#[cfg(feature="encryption")]` : SKIP (non compilé) dans la suite par défaut, pour ne
    /// PAS faire dépendre celle-ci de SQLCipher/openssl. Exécuté seulement via `--features encryption`.
    #[cfg(feature = "encryption")]
    #[test]
    fn migrate_encrypted_roundtrip_reads_back_with_key() {
        let src_dir = tmp_dir("forge-mig-enc");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let to = tmp_path("forge-mig-enc-to.db");
        std::env::set_var("FORGE_TEST_ENC_KEY", "correct horse battery staple");
        let opts = MigrateOpts {
            from: src_dir.clone(), to: to.clone(), ledger: Some(tmp_path("forge-mig-enc-to.jsonl")),
            verify: false, encrypt: true, key_env: Some("FORGE_TEST_ENC_KEY".to_string()), actor: "test".to_string(),
        };
        let report = run_migration(&opts).expect("migration chiffrée doit réussir");
        assert_eq!(report["encrypted"], true);

        // relecture AVEC la bonne clé -> lisible ; la donnée source a survécu.
        let dst = Connection::open(&to).unwrap();
        dst.pragma_update(None, "key", "correct horse battery staple").unwrap();
        let title: String = dst.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding");

        // relecture SANS clé -> illisible (preuve que la base est bien chiffrée au repos).
        let bad = Connection::open(&to).unwrap();
        assert!(bad.query_row("SELECT count(*) FROM finding", [], |r| r.get::<_, i64>(0)).is_err(),
            "sans PRAGMA key, une base chiffrée est illisible");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&to);
    }

    // ---------------------------------------------------------------------------------------
    // SAUVEGARDE / RESTAURATION CHIFFRÉE (backup / restore)
    // ---------------------------------------------------------------------------------------

    /// Sème une source d'engagement complète : base (schéma ancien, 1 finding), ledger chaîné à
    /// `entries` entrées, et une clé de signature `.ed25519`. Renvoie (db, ledger, key).
    fn seed_backup_source(dir: &str, entries: usize) -> (String, String, String) {
        let db = format!("{dir}/forge-console.db");
        seed_old_source_db(&db);
        let ledger = format!("{dir}/engagement.jsonl");
        for i in 0..entries {
            ledger_append_standalone(&ledger, "engagement.step", &json!({"i": i, "msg": "événement"})).unwrap();
        }
        let key = format!("{ledger}.ed25519");
        std::fs::write(&key, b"raw-ed25519-signing-key-32-bytes").unwrap();
        (db, ledger, key)
    }

    /// [BACKUP crypto] round-trip byte-for-byte : la base (snapshot), le ledger et la clé sortent de
    /// l'archive IDENTIQUES à ce qui y est entré. Le restore place la DB et la clé VERBATIM, et
    /// reproduit le ledger d'origine à l'octet près (puis y ajoute une entrée `console.restore` de
    /// traçabilité). La donnée SQLite survit (contenu relisible).
    #[test]
    fn backup_restore_roundtrips_db_ledger_key_byte_for_byte() {
        let src_dir = tmp_dir("forge-bk-rt-src");
        let (src_db, src_ledger, src_key) = seed_backup_source(&src_dir, 2);
        // capture l'état AVANT le backup (le backup appendra `console.backup` à la SOURCE après coup).
        let orig_ledger = std::fs::read(&src_ledger).unwrap();
        let orig_key = std::fs::read(&src_key).unwrap();

        let out = tmp_path("forge-bk-rt.age");
        let pass = "correct horse battery staple";
        let bopts = BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db.clone(),
            ledger: Some(src_ledger.clone()), ts: Some("@1234".to_string()), actor: "test".to_string(),
        };
        let brep = run_backup(&bopts).expect("backup doit réussir");
        assert_eq!(brep["encrypted"], true, "l'archive est TOUJOURS chiffrée");
        assert_eq!(brep["included_ledger"], true);
        assert_eq!(brep["included_key"], true);
        assert!(std::path::Path::new(&out).exists(), "archive écrite");

        // l'archive ne commence PAS par les octets d'un tar en clair (magic FORGE + chiffré).
        let raw = std::fs::read(&out).unwrap();
        assert_eq!(&raw[0..8], BACKUP_MAGIC, "en-tête FORGEBK1");
        // fidélité au niveau ARCHIVE : déchiffre + extrait -> db/ledger/clé égaux aux sources (octet-près).
        let pt = backup_decrypt(&raw, pass).expect("déchiffrement ok");
        let entries = backup_extract_tar(&pt).unwrap();
        let ar_get = |n: &str| entries.iter().find(|(x, _)| x == n).map(|(_, b)| b.clone()).unwrap();
        let ar_db = ar_get(BACKUP_ENTRY_DB);
        let ar_ledger = ar_get(BACKUP_ENTRY_LEDGER);
        let ar_key = ar_get(BACKUP_ENTRY_KEY);
        assert_eq!(ar_ledger, orig_ledger, "ledger archivé == ledger source (byte-for-byte)");
        assert_eq!(ar_key, orig_key, "clé archivée == clé source (byte-for-byte)");
        // manifest présent, sha256 par fichier cohérents.
        let manifest: Value = serde_json::from_slice(&ar_get(BACKUP_ENTRY_MANIFEST)).unwrap();
        assert_eq!(manifest["schema"], BACKUP_SCHEMA_VERSION);
        assert_eq!(manifest["created_at"], "@1234", "timestamp passé-en-argument conservé");
        assert_eq!(manifest["files"]["db.sqlite"]["sha256"], sha256_hex_bytes(&ar_db));

        // restore dans un dossier NEUF (aucun écrasement).
        let to_dir = tmp_dir("forge-bk-rt-to");
        let to_db = format!("{to_dir}/forge-console.db");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        let ropts = RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: false, actor: "test".to_string(),
        };
        let rrep = run_restore(&ropts).expect("restore doit réussir");
        assert_eq!(rrep["restored_key"], true);

        // DB placée VERBATIM == db archivée (byte-for-byte) + contenu SQLite relisible.
        assert_eq!(std::fs::read(&to_db).unwrap(), ar_db, "DB restaurée == snapshot archivé (byte-for-byte)");
        let dst = Connection::open(&to_db).unwrap();
        let title: String = dst.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding", "la donnée SQLite survit au round-trip");
        drop(dst);

        // clé restaurée == clé source (byte-for-byte). La clé voyage AVEC le ledger.
        let to_key = format!("{to_ledger}.ed25519");
        assert!(std::path::Path::new(&to_key).exists(), "clé .ed25519 restaurée à côté du ledger");
        assert_eq!(std::fs::read(&to_key).unwrap(), orig_key, "clé restaurée == source (byte-for-byte)");

        // ledger : les 2 entrées d'origine sont reproduites À L'OCTET PRÈS en préfixe ; une entrée
        // `console.restore` de traçabilité est ajoutée ; la chaîne reste intègre.
        let restored_ledger = std::fs::read(&to_ledger).unwrap();
        assert!(restored_ledger.starts_with(&orig_ledger), "préfixe ledger == source (byte-for-byte)");
        let lines = read_ledger_lines(&to_ledger);
        assert_eq!(lines.len(), 3, "2 entrées source + 1 console.restore");
        assert_eq!(lines[2]["kind"], "console.restore", "restore tracé au ledger (métadonnées)");
        let vfin = verify_ledger_chain(&to_ledger);
        assert!(vfin.ok, "chaîne du ledger restauré + trace reste vérifiable");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP crypto] une MAUVAISE passphrase échoue proprement (tag AEAD) et n'écrit RIEN sur disque.
    #[test]
    fn backup_wrong_passphrase_fails_and_writes_nothing() {
        let src_dir = tmp_dir("forge-bk-wp-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-wp.age");
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: "the-right-one".to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");

        // déchiffrement direct avec la mauvaise passphrase -> Err (jamais de plaintext).
        let raw = std::fs::read(&out).unwrap();
        assert!(backup_decrypt(&raw, "the-WRONG-one").is_err(), "mauvaise passphrase -> tag AEAD invalide");
        assert!(backup_decrypt(&raw, "the-right-one").is_ok(), "bonne passphrase -> ok (sanity)");

        // restore complet avec mauvaise passphrase : Err ET aucune écriture cible.
        let to_dir = tmp_dir("forge-bk-wp-to");
        let to_db = format!("{to_dir}/db.sqlite");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        let err = run_restore(&RestoreOpts {
            input: out.clone(), passphrase: "the-WRONG-one".to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: true, actor: "test".to_string(),
        }).expect_err("mauvaise passphrase -> restore échoue");
        assert!(err.contains("AEAD") || err.contains("passphrase"), "erreur claire: {err}");
        assert!(!std::path::Path::new(&to_db).exists(), "RIEN écrit (db) sur mauvaise passphrase");
        assert!(!std::path::Path::new(&to_ledger).exists(), "RIEN écrit (ledger) sur mauvaise passphrase");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP crypto] un octet retourné dans l'archive (corps OU en-tête lié en AAD) casse le tag
    /// Poly1305 -> déchiffrement refusé, restore échoue et n'écrit rien.
    #[test]
    fn backup_flipped_byte_fails_aead_tag() {
        let src_dir = tmp_dir("forge-bk-flip-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-flip.age");
        let pass = "passphrase-forte-123";
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");
        let raw = std::fs::read(&out).unwrap();
        let hdr = backup_parse_header(&raw).unwrap();

        // 1) octet retourné dans le CIPHERTEXT.
        let mut t1 = raw.clone();
        let idx = hdr.header_len + 4; // dans le corps chiffré
        t1[idx] ^= 0xFF;
        assert!(backup_decrypt(&t1, pass).is_err(), "corps altéré -> tag AEAD invalide");

        // 2) octet retourné dans le SEL (en-tête, lié en AAD) : la clé dérivée diffère ET l'AAD change
        //    -> le tag AEAD échoue. Le sel occupe les octets 22..38 (après magic|ver|m|t|p|salt_len).
        let mut t2 = raw.clone();
        t2[25] ^= 0xFF; // à l'intérieur de la zone sel
        assert!(backup_decrypt(&t2, pass).is_err(), "sel altéré -> clé/AAD différents -> tag AEAD invalide");

        // 2b) octet retourné dans les PARAMS argon2 (en-tête, malléable AVANT authentification) : rejet
        //     PROPRE (Err, jamais de panic/DoS) grâce à la validation des bornes de la KDF.
        let mut t2b = raw.clone();
        t2b[12] ^= 0xFF; // octet de poids fort de m_cost -> valeur absurde
        assert!(backup_decrypt(&t2b, pass).is_err(), "params argon2 corrompus -> Err propre (pas de panic)");

        // 3) restore sur archive altérée : Err + aucune écriture.
        let tampered = tmp_path("forge-bk-flip-tampered.age");
        std::fs::write(&tampered, &t1).unwrap();
        let to_dir = tmp_dir("forge-bk-flip-to");
        let to_db = format!("{to_dir}/db.sqlite");
        let err = run_restore(&RestoreOpts {
            input: tampered.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(format!("{to_dir}/engagement.jsonl")), force: true, actor: "test".to_string(),
        }).expect_err("archive altérée -> restore échoue");
        assert!(err.contains("AEAD") || err.contains("altérée"), "erreur claire: {err}");
        assert!(!std::path::Path::new(&to_db).exists(), "RIEN écrit sur archive altérée");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
        let _ = std::fs::remove_file(&tampered);
    }

    /// [BACKUP intégrité] le manifest re-vérifie le sha256 de chaque fichier : un sha falsifié (même
    /// dans un plaintext par ailleurs bien chiffré) fait ÉCHOUER le restore sans rien placer.
    #[test]
    fn restore_rejects_manifest_sha_mismatch() {
        let db = b"fausse-base-sqlite-pour-le-test".to_vec();
        // manifest annonçant un sha256 VOLONTAIREMENT faux pour db.sqlite.
        let bad_manifest = json!({
            "kind": "forge-console-backup", "schema": BACKUP_SCHEMA_VERSION,
            "files": {"db.sqlite": {"sha256": "0".repeat(64), "size": db.len()}}
        });
        let mb = serde_json::to_vec_pretty(&bad_manifest).unwrap();
        let tar = backup_build_tar(&[(BACKUP_ENTRY_MANIFEST, &mb), (BACKUP_ENTRY_DB, &db)]).unwrap();
        let sealed = backup_encrypt(&tar, "pw").unwrap(); // bien chiffré : l'AEAD passera.
        let arch = tmp_path("forge-bk-shamism.age");
        std::fs::write(&arch, &sealed).unwrap();

        let to_dir = tmp_dir("forge-bk-shamism-to");
        let to_db = format!("{to_dir}/db.sqlite");
        let err = run_restore(&RestoreOpts {
            input: arch.clone(), passphrase: "pw".to_string(), to: Some(to_db.clone()),
            ledger: Some(format!("{to_dir}/engagement.jsonl")), force: true, actor: "test".to_string(),
        }).expect_err("sha256 falsifié -> restore refusé");
        assert!(err.contains("sha256 mismatch"), "erreur d'intégrité manifest: {err}");
        assert!(!std::path::Path::new(&to_db).exists(), "aucun placement quand le manifest est incohérent");

        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&arch);
    }

    /// [BACKUP garde] le restore REFUSE d'écraser un install existant NON VIDE sans `--force`, puis
    /// l'écrase quand `--force` est fourni.
    #[test]
    fn restore_without_force_refuses_to_clobber() {
        let src_dir = tmp_dir("forge-bk-clob-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-clob.age");
        let pass = "pw-clobber";
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");

        // install cible PRÉ-EXISTANT et NON VIDE.
        let to_dir = tmp_dir("forge-bk-clob-to");
        let to_db = format!("{to_dir}/forge-console.db");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        let sentinel = b"NE-PAS-ECRASER-existant".to_vec();
        std::fs::write(&to_db, &sentinel).unwrap();

        // sans --force -> REFUS, et la donnée existante est INTACTE.
        let err = run_restore(&RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: false, actor: "test".to_string(),
        }).expect_err("clobber refusé sans --force");
        assert!(err.contains("force") || err.contains("REFUSÉ"), "message anti-clobber: {err}");
        assert_eq!(std::fs::read(&to_db).unwrap(), sentinel, "install existant NON écrasé");

        // avec --force -> écrase.
        run_restore(&RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: true, actor: "test".to_string(),
        }).expect("--force autorise l'écrasement");
        assert_ne!(std::fs::read(&to_db).unwrap(), sentinel, "install écrasé avec --force");
        let dst = Connection::open(&to_db).unwrap();
        let n: i64 = dst.query_row("SELECT count(*) FROM finding", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "la base restaurée contient le finding source");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP perms] la clé `.ed25519` restaurée est en 0600 — MÊME si la clé source est plus
    /// permissive (0644). La clé de signature reste un secret non-lisible par autrui.
    #[cfg(unix)]
    #[test]
    fn restored_ed25519_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let src_dir = tmp_dir("forge-bk-perm-src");
        let (src_db, src_ledger, src_key) = seed_backup_source(&src_dir, 2);
        // clé source DÉLIBÉRÉMENT 0644 -> prouve que le restore FORCE 0600.
        std::fs::set_permissions(&src_key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let out = tmp_path("forge-bk-perm.age");
        let pass = "pw-perm";
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");

        let to_dir = tmp_dir("forge-bk-perm-to");
        let to_db = format!("{to_dir}/forge-console.db");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        run_restore(&RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db),
            ledger: Some(to_ledger.clone()), force: false, actor: "test".to_string(),
        }).expect("restore ok");
        let to_key = format!("{to_ledger}.ed25519");
        let mode = std::fs::metadata(&to_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "clé de signature restaurée en 0600");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP intégrité] un ledger source à la chaîne ROMPUE fait AVORTER le backup AVANT toute
    /// écriture d'archive.
    #[test]
    fn backup_aborts_on_tampered_ledger_chain() {
        let src_dir = tmp_dir("forge-bk-tamper-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 4);
        // altère le CONTENU d'une entrée sans recalculer son hash -> "hash recalculé != stocké".
        let tampered = std::fs::read_to_string(&src_ledger).unwrap().replacen("événement", "ALTÉRÉ", 1);
        std::fs::write(&src_ledger, tampered).unwrap();
        assert!(!verify_ledger_chain(&src_ledger).ok, "pré-condition : ledger détecté rompu");

        let out = tmp_path("forge-bk-tamper.age");
        let err = run_backup(&BackupOpts {
            out: out.clone(), passphrase: "pw".to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect_err("ledger rompu -> backup AVORTÉ");
        assert!(err.contains("AVORTÉ"), "message d'abort explicite: {err}");
        assert!(!std::path::Path::new(&out).exists(), "AUCUNE archive écrite sur abort");

        let _ = std::fs::remove_dir_all(&src_dir);
    }

    /// [BACKUP crypto] la KDF argon2id est déterministe (mêmes passphrase+sel+params -> même clé) mais
    /// sensible à la passphrase, et deux archives du MÊME plaintext diffèrent (sel+nonce aléatoires).
    #[test]
    fn backup_kdf_deterministic_and_archives_use_fresh_salt_nonce() {
        let salt = [7u8; BACKUP_SALT_LEN];
        let dp = Params::default();
        let k1 = backup_derive_key("pw", &salt, dp.m_cost(), dp.t_cost(), dp.p_cost()).unwrap();
        let k2 = backup_derive_key("pw", &salt, dp.m_cost(), dp.t_cost(), dp.p_cost()).unwrap();
        let k3 = backup_derive_key("other", &salt, dp.m_cost(), dp.t_cost(), dp.p_cost()).unwrap();
        assert_eq!(k1, k2, "KDF déterministe (re-dérivable au restore)");
        assert_ne!(k1, k3, "passphrase différente -> clé différente");
        assert_ne!(k1, [0u8; BACKUP_KEY_LEN], "clé non tous-zeros");

        let pt = b"payload identique".to_vec();
        let a = backup_encrypt(&pt, "pw").unwrap();
        let b = backup_encrypt(&pt, "pw").unwrap();
        assert_ne!(a, b, "sel+nonce aléatoires -> chiffrés distincts pour un même plaintext");
        assert_eq!(backup_decrypt(&a, "pw").unwrap(), pt, "round-trip AEAD (a)");
        assert_eq!(backup_decrypt(&b, "pw").unwrap(), pt, "round-trip AEAD (b)");
        assert!(backup_encrypt(&pt, "").is_err(), "passphrase vide REFUSÉE (fail-closed)");
        assert!(backup_decrypt(&a, "").is_err(), "passphrase vide REFUSÉE au déchiffrement");
    }

    // ---------------------------------------------------------------------------------------------
    // API SAUVEGARDE / RESTAURATION / POLITIQUE (admin-gated) + runner programmé
    // ---------------------------------------------------------------------------------------------

    /// Consomme une Response axum et parse son corps JSON (helper de test).
    async fn resp_json(r: Response) -> Value {
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&b).unwrap_or(Value::Null)
    }

    /// App de test dont `db_path`/`ledger_path` pointent sur des fichiers RÉELS (le moteur backup ouvre
    /// la base sur disque en read-only + VACUUM INTO). Sème un admin, une base au SCHEMA courant, un
    /// ledger chaîné (1 entrée) et une clé .ed25519. Renvoie (app, db_path, ledger_path, admin_token).
    fn test_app_disk(dir: &str) -> (App, String, String, String) {
        let db_path = format!("{dir}/forge-console.db");
        let ledger = format!("{dir}/engagement.jsonl");
        let conn = Connection::open(&db_path).expect("open disk db");
        conn.execute_batch(SCHEMA).expect("schema");
        migrate(&conn);
        upsert_user(&conn, "adm", "admin", &hash_pw("pw")).unwrap();
        upsert_user(&conn, "viw", "viewer", &hash_pw("pw")).unwrap();
        upsert_user(&conn, "opr", "operator", &hash_pw("pw")).unwrap();
        ledger_append_standalone(&ledger, "engagement.start", &json!({"a": 1})).unwrap();
        std::fs::write(format!("{ledger}.ed25519"), b"raw-ed25519-signing-key-32-bytes!").unwrap();
        let (events, _) = broadcast::channel::<RunEvent>(64);
        let app = App {
            db: Arc::new(Mutex::new(conn)),
            db_path: Arc::new(db_path.clone()),
            token_sha: Arc::new(sha_hex("t")),
            token_raw: Arc::new("t".into()),
            user: Arc::new("forge".into()),
            pass_hash: Arc::new(String::new()),
            auth_required: Arc::new(AtomicBool::new(true)),
            operator_hash: Arc::new(String::new()),
            allowed_hosts: Arc::new(vec!["localhost".into()]),
            ledger_path: Arc::new(ledger.clone()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(RunState { current: None })),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        };
        let (atok, _) = create_session(&app, uid_of(&app, "adm"));
        (app, db_path, ledger, atok)
    }

    /// [BACKUP API gate] /api/backup, /api/restore, /api/backup/policy sont ADMIN-ONLY : viewer,
    /// operator et l'anonyme reçoivent 403 ; l'admin passe. Vérifie les handlers HTTP réels (check_admin).
    #[tokio::test]
    async fn backup_restore_policy_routes_are_admin_only_403() {
        let dir = tmp_dir("forge-bkapi-403");
        let (app, _db, _led, atok) = test_app_disk(&dir);
        let (vtok, _) = create_session(&app, uid_of(&app, "viw"));
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));
        let pbody = || Json(json!({"passphrase": "correct horse battery staple"}));

        // POST /api/backup : viewer/operator/anonyme -> 403.
        assert_eq!(api_backup(State(app.clone()), bearer_headers(&vtok), pbody()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup(State(app.clone()), bearer_headers(&otok), pbody()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup(State(app.clone()), HeaderMap::new(), pbody()).await.status(), StatusCode::FORBIDDEN);
        // admin -> 200 (téléchargement de l'archive chiffrée).
        assert_eq!(api_backup(State(app.clone()), bearer_headers(&atok), pbody()).await.status(), StatusCode::OK);

        // POST /api/restore : viewer/operator -> 403.
        let rbody = || Json(json!({"archive_b64": "AA==", "passphrase": "x"}));
        assert_eq!(api_restore(State(app.clone()), bearer_headers(&vtok), rbody()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_restore(State(app.clone()), bearer_headers(&otok), rbody()).await.status(), StatusCode::FORBIDDEN);

        // GET/POST /api/backup/policy : viewer/operator -> 403 ; admin -> 200.
        assert_eq!(api_backup_policy_get(State(app.clone()), bearer_headers(&vtok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup_policy_get(State(app.clone()), bearer_headers(&otok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup_policy_get(State(app.clone()), bearer_headers(&atok)).await.status(), StatusCode::OK);
        assert_eq!(
            api_backup_policy_set(State(app.clone()), bearer_headers(&vtok), Json(json!({"enabled": false}))).await.status(),
            StatusCode::FORBIDDEN
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [BACKUP API] POST /api/backup : passphrase manquante -> 400 (fail-closed) ; avec passphrase ->
    /// 200 + corps = archive CHIFFRÉE (magic FORGEBK1, déchiffrable) ; l'entrée ledger `console.backup`
    /// est écrite MAIS la passphrase n'apparaît JAMAIS dans le fichier ledger.
    #[tokio::test]
    async fn api_backup_downloads_encrypted_archive_and_never_ledgers_passphrase() {
        let dir = tmp_dir("forge-bkapi-dl");
        let (app, _db, ledger, atok) = test_app_disk(&dir);
        let secret_pass = "s3cr3t-passphrase-do-not-log-42";

        // passphrase absente -> 400.
        let r = api_backup(State(app.clone()), bearer_headers(&atok), Json(json!({}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "passphrase absente -> 400 fail-closed");

        // avec passphrase -> 200 + archive chiffrée téléchargeable.
        let r = api_backup(State(app.clone()), bearer_headers(&atok), Json(json!({"passphrase": secret_pass}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let disp = r.headers().get("content-disposition").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(disp.contains("attachment") && disp.contains("forge-backup-"), "Content-Disposition de téléchargement: {disp}");
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[0..8], BACKUP_MAGIC, "corps = archive chiffrée (magic FORGEBK1)");
        assert!(backup_decrypt(&body, secret_pass).is_ok(), "archive déchiffrable avec la bonne passphrase");
        assert!(backup_decrypt(&body, "mauvaise").is_err(), "mauvaise passphrase -> tag AEAD invalide");

        // le ledger contient `console.backup` MAIS jamais la passphrase.
        let ledger_txt = std::fs::read_to_string(&ledger).unwrap();
        assert!(ledger_txt.contains("console.backup"), "l'action backup est ledgerisée");
        assert!(!ledger_txt.contains(secret_pass), "la passphrase n'apparaît JAMAIS dans le ledger");
        assert!(verify_ledger_chain(&ledger).ok, "chaîne du ledger intacte après backup via API");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [RESTORE API] chemins de sûreté : (a) validation par défaut (apply absent) NE réécrit RIEN et
    /// répond applied:false ; (b) apply=true SANS confirm -> 400 (confirmation requise), rien écrit ;
    /// (c) mauvaise passphrase -> 422 propre + ledger `console.restore.validate` ok:false SANS la
    /// passphrase ; (d) apply=true+confirm=true -> swap effectué, restart_required:true.
    #[tokio::test]
    async fn api_restore_validate_default_confirm_required_and_apply() {
        let src_dir = tmp_dir("forge-rsapi-src");
        let (app, db_path, ledger, atok) = test_app_disk(&src_dir);
        let secret_pass = "restore-pass-never-logged-99";

        // fabrique une VRAIE archive chiffrée à partir de la source disque.
        let arch = tmp_path("forge-rsapi.forge");
        run_backup(&BackupOpts {
            out: arch.clone(), passphrase: secret_pass.to_string(), db: db_path.clone(),
            ledger: Some(ledger.clone()), ts: Some("@1000".into()), actor: "test".into(),
        }).expect("backup source");
        let archive_b64 = base64::engine::general_purpose::STANDARD.encode(std::fs::read(&arch).unwrap());

        // (a) validation par défaut : 200 applied:false, aucune écriture destructive.
        let db_before = std::fs::read(&db_path).unwrap();
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": secret_pass}))).await;
        assert_eq!(r.status(), StatusCode::OK, "validation par défaut -> 200");
        let j = resp_json(r).await;
        assert_eq!(j["applied"], false, "validation par défaut n'applique RIEN");
        assert_eq!(j["validated"]["ok"], true, "archive validée");
        assert_eq!(std::fs::read(&db_path).unwrap(), db_before, "base LIVE inchangée par la validation");

        // (b) apply sans confirm -> 400.
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": secret_pass, "apply": true}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "apply sans confirm -> 400");
        assert_eq!(std::fs::read(&db_path).unwrap(), db_before, "base LIVE inchangée sans confirm");

        // (c) mauvaise passphrase -> 422 + trace validate ok:false, jamais la passphrase.
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": "WRONG"}))).await;
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY, "mauvaise passphrase -> 422");
        let ledger_txt = std::fs::read_to_string(&ledger).unwrap();
        assert!(ledger_txt.contains("console.restore.validate"), "tentative de restore ledgerisée");
        assert!(!ledger_txt.contains(secret_pass), "la passphrase n'apparaît JAMAIS dans le ledger");
        assert!(!ledger_txt.contains("WRONG"), "la passphrase (même erronée) n'est jamais ledgerisée");

        // (d) apply=true+confirm=true -> swap effectué, redémarrage requis annoncé.
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": secret_pass, "apply": true, "confirm": true}))).await;
        assert_eq!(r.status(), StatusCode::OK, "apply+confirm -> 200");
        let j = resp_json(r).await;
        assert_eq!(j["applied"], true, "swap appliqué");
        assert_eq!(j["restart_required"], true, "redémarrage requis annoncé (base live tenue par la connexion)");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&arch);
    }

    /// [POLICY API] round-trip d'une politique (schedule/rétention/offsite) + RÉDACTION : un GET ne
    /// renvoie JAMAIS un secret (champ secretish rédigé), mais conserve `passphrase_env` (un NOM d'ENV).
    #[tokio::test]
    async fn backup_policy_round_trips_and_get_redacts_secrets() {
        let dir = tmp_dir("forge-pol-rt");
        let (app, _db, _led, atok) = test_app_disk(&dir);

        // POST : politique complète, avec un secret inline dans offsite exec (doit être rédigé au GET).
        let policy = json!({
            "enabled": true,
            "interval_secs": 3600,
            "retention": 7,
            "passphrase_env": "FORGE_BACKUP_PASSPHRASE",
            "staging_dir": format!("{dir}/staging"),
            "offsite": {"kind": "exec", "program": "/usr/bin/rclone",
                        "args": ["copy", "{archive}", "remote:forge/"], "token": "SUPER-SECRET-TOKEN"}
        });
        let r = api_backup_policy_set(State(app.clone()), bearer_headers(&atok), Json(policy)).await;
        assert_eq!(r.status(), StatusCode::OK, "politique valide enregistrée");

        // GET : round-trip des champs non-secrets + rédaction du secret.
        let r = api_backup_policy_get(State(app.clone()), bearer_headers(&atok)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let j = resp_json(r).await;
        let p = &j["policy"];
        assert_eq!(p["enabled"], true);
        assert_eq!(p["interval_secs"], 3600);
        assert_eq!(p["retention"], 7);
        assert_eq!(p["passphrase_env"], "FORGE_BACKUP_PASSPHRASE", "le NOM d'ENV n'est PAS un secret -> conservé");
        assert_eq!(p["offsite"]["kind"], "exec");
        assert_eq!(p["offsite"]["program"], "/usr/bin/rclone");
        assert_eq!(p["offsite"]["token"], "***REDACTED***", "tout champ secretish est RÉDIGÉ au GET");
        assert_eq!(j["configured"], true);

        // la valeur PERSISTÉE ne contient jamais de `passphrase` en clair (seul passphrase_env).
        let stored = { let db = app.db(); settings_get(&db, "backup_policy").unwrap() };
        assert!(!stored.contains("\"passphrase\""), "aucun `passphrase` en clair persisté");
        assert!(stored.contains("FORGE_BACKUP_PASSPHRASE"), "passphrase_env persisté");

        // politique invalide : enabled sans interval -> 400, rien n'est écrasé.
        let r = api_backup_policy_set(State(app.clone()), bearer_headers(&atok),
            Json(json!({"enabled": true, "passphrase_env": "X"}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "enabled sans interval -> 400");
        // offsite kind inconnu -> 400.
        let r = api_backup_policy_set(State(app.clone()), bearer_headers(&atok),
            Json(json!({"enabled": false, "offsite": {"kind": "ftp"}}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "offsite kind hors none/local_dir/exec -> 400");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [POLICY] validate_backup_policy : fail-closed (interval/passphrase_env requis si enabled ;
    /// exec program absolu). redact_backup_policy : rédige un secret, conserve `*_env`.
    #[test]
    fn backup_policy_validation_and_redaction_units() {
        // enabled sans interval -> Err.
        assert!(validate_backup_policy(&json!({"enabled": true, "passphrase_env": "P"})).is_err());
        // enabled sans passphrase_env -> Err.
        assert!(validate_backup_policy(&json!({"enabled": true, "interval_secs": 60})).is_err());
        // exec program relatif -> Err (pas de résolution PATH).
        assert!(validate_backup_policy(&json!({"enabled": false, "offsite": {"kind": "exec", "program": "rclone"}})).is_err());
        // valide : disabled + offsite none.
        assert!(validate_backup_policy(&json!({"enabled": false, "offsite": {"kind": "none"}})).is_ok());
        // le `passphrase` en clair est RETIRÉ à la persistance.
        let clean = validate_backup_policy(&json!({"enabled": false, "passphrase": "LEAK"})).unwrap();
        assert!(clean.get("passphrase").is_none(), "passphrase en clair jamais persistée");
        // rédaction.
        let red = redact_backup_policy(&json!({"passphrase_env": "P", "secret": "S", "offsite": {"token": "T", "kind": "exec"}}));
        assert_eq!(red["passphrase_env"], "P", "NOM d'ENV conservé");
        assert_eq!(red["secret"], "***REDACTED***");
        assert_eq!(red["offsite"]["token"], "***REDACTED***", "rédaction récursive");
        assert_eq!(red["offsite"]["kind"], "exec", "champ non-secret conservé");
    }

    /// [SCHEDULER] run_scheduled_backup : avec une politique activée + une passphrase via ENV + un offsite
    /// local_dir, crée une archive CHIFFRÉE dans le staging, la copie offsite, ledgerise (scheduled +
    /// offsite) et NE FUITE JAMAIS la passphrase. Passphrase ENV absente -> Err (fail-closed, pas de
    /// crash). Politique désactivée -> skip.
    #[test]
    fn scheduled_backup_encrypts_ships_local_dir_and_never_leaks_passphrase() {
        let _g = env_lock(); // ENV process-global
        let dir = tmp_dir("forge-sched");
        let (app, _db, ledger, _atok) = test_app_disk(&dir);
        let staging = format!("{dir}/staging");
        let offsite_dir = format!("{dir}/offsite");
        let pass_env = "FORGE_TEST_SCHED_PASS";
        let secret_pass = "scheduled-pass-shh-77";

        {
            let db = app.db();
            settings_set(&db, "backup_policy", &json!({
                "enabled": true, "interval_secs": 1, "retention": 2,
                "passphrase_env": pass_env, "staging_dir": staging,
                "offsite": {"kind": "local_dir", "dir": offsite_dir}
            }).to_string()).unwrap();
        }

        // (a) passphrase ENV absente -> Err (fail-closed), aucune archive, pas de crash.
        std::env::remove_var(pass_env);
        assert!(run_scheduled_backup(&app).is_err(), "passphrase ENV absente -> fail-closed");

        // (b) passphrase ENV posée -> backup + offsite.
        std::env::set_var(pass_env, secret_pass);
        let rep = run_scheduled_backup(&app).expect("backup programmé réussit");
        std::env::remove_var(pass_env);
        assert_eq!(rep["ok"], true);

        // une archive chiffrée dans le staging (magic + déchiffrable).
        let staged: Vec<_> = std::fs::read_dir(&staging).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".forge")).collect();
        assert_eq!(staged.len(), 1, "une archive dans le staging");
        let raw = std::fs::read(staged[0].path()).unwrap();
        assert_eq!(&raw[0..8], BACKUP_MAGIC, "archive chiffrée");
        assert!(backup_decrypt(&raw, secret_pass).is_ok(), "déchiffrable avec la passphrase ENV");

        // l'archive a été copiée offsite (local_dir).
        let shipped: Vec<_> = std::fs::read_dir(&offsite_dir).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".forge")).collect();
        assert_eq!(shipped.len(), 1, "archive expédiée dans l'offsite local_dir");

        // ledger : entrées scheduled + offsite, jamais la passphrase.
        let ltxt = std::fs::read_to_string(&ledger).unwrap();
        assert!(ltxt.contains("console.backup.scheduled"), "backup programmé ledgerisé");
        assert!(ltxt.contains("console.backup.offsite"), "expédition offsite ledgerisée");
        assert!(!ltxt.contains(secret_pass), "la passphrase n'apparaît JAMAIS dans le ledger");
        assert!(verify_ledger_chain(&ledger).ok, "chaîne du ledger intacte");

        // (c) politique désactivée -> skip (aucune erreur).
        { let db = app.db(); settings_set(&db, "backup_policy", &json!({"enabled": false}).to_string()).unwrap(); }
        let rep = run_scheduled_backup(&app).expect("désactivée -> Ok");
        assert_eq!(rep["skipped"], true, "politique désactivée -> skip");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [SCHEDULER] scheduled_backup_due : dû si activé + interval écoulé depuis backup_last_run ;
    /// jamais dû si désactivé ou interval=0. Rétention : conserve les N plus récentes.
    #[test]
    fn scheduled_due_gate_and_retention() {
        let dir = tmp_dir("forge-sched-due");
        let (app, _db, _led, _atok) = test_app_disk(&dir);
        {
            let db = app.db();
            assert!(!scheduled_backup_due(&db), "aucune politique -> pas dû");
            settings_set(&db, "backup_policy", &json!({"enabled": true, "interval_secs": 3600, "passphrase_env": "P"}).to_string()).unwrap();
            settings_set(&db, "backup_last_run", &chrono_now_compact()).unwrap();
            assert!(!scheduled_backup_due(&db), "dernière exécution à l'instant -> pas encore dû");
            settings_set(&db, "backup_last_run", "0").unwrap();
            assert!(scheduled_backup_due(&db), "last_run très ancien -> dû");
            settings_set(&db, "backup_policy", &json!({"enabled": false}).to_string()).unwrap();
            assert!(!scheduled_backup_due(&db), "désactivé -> jamais dû");
        }
        // rétention : 4 archives, keep=2 -> 2 restent.
        let ret = format!("{dir}/ret");
        std::fs::create_dir_all(&ret).unwrap();
        for i in 0..4 {
            std::fs::write(format!("{ret}/forge-backup-{i}.forge"), format!("a{i}")).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(15)); // mtimes distinctes
        }
        apply_backup_retention(&ret, 2);
        let left = std::fs::read_dir(&ret).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".forge")).count();
        assert_eq!(left, 2, "rétention conserve exactement les 2 plus récentes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [OFFSITE exec] ship_offsite exec : argv fixe (aucun shell), token `{archive}` substitué ; un
    /// programme qui sort en échec -> Err ; un timeout tue le process (Err). Le succès renvoie shipped:true.
    #[test]
    fn offsite_exec_no_shell_success_failure_and_timeout() {
        let dir = tmp_dir("forge-offx");
        let arch = format!("{dir}/a.forge");
        std::fs::write(&arch, b"payload").unwrap();
        // succès : /bin/cp {archive} -> {dir}/copied.forge (argv fixe, aucun shell).
        let dst = format!("{dir}/copied.forge");
        let r = ship_offsite(&json!({"kind": "exec", "program": "/bin/cp", "args": ["{archive}", dst]}), &arch);
        assert!(r.is_ok(), "cp argv fixe -> succès: {r:?}");
        assert!(std::path::Path::new(&dst).exists(), "token archive substitué -> fichier copié");
        // échec : /bin/false -> code != 0 -> Err.
        assert!(ship_offsite(&json!({"kind": "exec", "program": "/bin/false", "args": []}), &arch).is_err(),
            "exit code != 0 -> Err");
        // timeout : /bin/sleep 5 avec timeout_secs=1 -> Err (process tué).
        let r = ship_offsite(&json!({"kind": "exec", "program": "/bin/sleep", "args": ["5"], "timeout_secs": 1}), &arch);
        assert!(r.is_err() && r.unwrap_err().contains("timeout"), "dépassement -> tué + Err");
        // none -> no-op.
        assert_eq!(ship_offsite(&json!({"kind": "none"}), &arch).unwrap()["shipped"], false);
        let _ = std::fs::remove_dir_all(&dir);
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
        let md = render_run_report_md(&db, "run-1", &job, None, None);
        assert!(md.contains("# Forge — rapport d'engagement (`run-1`)"), "titre avec run_id");
        assert!(md.contains("| HIGH | 1 |"), "synthèse sévérité HIGH=1");
        assert!(md.contains("### [HIGH] IDOR exposé — `api.example.com`"), "finding détaillé rendu");
        assert!(md.contains("**Refusées (VETO"), "section transparence ROE présente");
        assert!(md.contains("`VETO` `exploit.rce` → `api.example.com` : capacité non autorisée"), "verdict VETO détaillé avec raison");
        assert!(md.contains("**Simulées (DRY_RUN)** : 2"), "compteur dry_run depuis run_job");
        // [LOT REPORTING] CWE/CVSS séparés : le finding n'a pas de colonne cwe/cvss -> dérivés
        // (CWE depuis category vide => '—' ; CVSS depuis sévérité HIGH).
        assert!(md.contains("## Résumé exécutif"), "executive summary présent");
        assert!(md.contains("Posture :"), "phrase posture présente");
        assert!(md.contains("**CWE**") && md.contains("**CVSS**"), "CWE et CVSS rendus séparément");
        assert!(md.contains("7.5"), "CVSS de base dérivé de la sévérité HIGH");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    /// [LOT REPORTING] extract_cwe : extrait un CWE canonique de formes variées, '' si absent.
    #[test]
    fn extract_cwe_variants() {
        assert_eq!(extract_cwe("CWE-639"), "CWE-639");
        assert_eq!(extract_cwe("cwe_862"), "CWE-862");
        assert_eq!(extract_cwe("CWE 918"), "CWE-918");
        assert_eq!(extract_cwe("access_control.CWE-284 (idor)"), "CWE-284");
        assert_eq!(extract_cwe("access_control"), "", "pas de CWE -> vide");
        assert_eq!(extract_cwe(""), "");
    }

    /// [LOT REPORTING] cvss_base_for_severity : (vecteur,score) par bande ; INFO/inconnu -> ('',0).
    #[test]
    fn cvss_base_by_severity() {
        assert_eq!(cvss_base_for_severity("CRITICAL").1, 9.8);
        assert_eq!(cvss_base_for_severity("high").1, 7.5, "casse insensible");
        assert_eq!(cvss_base_for_severity("MEDIUM").1, 5.3);
        assert_eq!(cvss_base_for_severity("LOW").1, 3.1);
        assert_eq!(cvss_base_for_severity("INFO"), ("", 0.0), "INFO -> pas de CVSS inventé");
        assert!(cvss_base_for_severity("CRITICAL").0.starts_with("CVSS:3.1/"));
    }

    /// [LOT REPORTING] html_escape : neutralise les métacaractères HTML (anti-injection rapport).
    #[test]
    fn html_escape_neutralizes() {
        assert_eq!(html_escape("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
        assert_eq!(html_escape("a&b \"q\" 'x'"), "a&amp;b &quot;q&quot; &#39;x&#39;");
        assert_eq!(html_escape("texte normal"), "texte normal");
    }

    /// [LOT REPORTING] render_run_report_html : document brandé autonome — page de garde GuatX/Forge
    /// + quetzal, sommaire, résumé exécutif EN PROSE (Campaign.notes), findings avec CWE/CVSS SÉPARÉS
    /// + FIX, CSS print, annexe chaîne-de-custody (head ledger, attribution, commande verify --pubkey).
    ///
    /// Le contenu hostile est échappé (anti-injection).
    #[test]
    fn run_report_html_branded_deliverable() {
        let path = tmp_path("forge-test-html");
        let app = test_app(&path);
        {
            let db = app.db();
            migrate(&db);
            db.execute("INSERT INTO campaign(name,started,notes) VALUES('c','t','Pentest grey-box autorisé du périmètre client.')", []).unwrap();
            // finding AVEC cwe/cvss explicites + un titre hostile (doit être échappé).
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,cwe,cvss_vector,cvss_score,mitre,status,evidence,poc,fix,tool,run_id)
                 VALUES('t','c','api.example.com','<b>IDOR</b>','HIGH','access_control','CWE-639','CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',8.1,'T1190','confirmé','dump user 42','curl -H ...','Contrôle ownership serveur','idor','run-1')",
                [],
            ).unwrap();
            db.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,started_by,targets,started,finished)
                 VALUES('run-1','c',datetime('now'),'done','propose',1,0,0,0,'alice+high_impact','[\"api.example.com\"]','2026-06-01T10:00:00Z','2026-06-01T12:00:00Z')",
                [],
            ).unwrap();
        }
        // ledger non vide -> annexe custody avec head + intégrité VALIDE.
        append_console_ledger(&app, "console.run.start", json!({"run_id":"run-1","actor":"alice","by":"operator"}));
        let db = app.db();
        let job = db.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), ["run-1"], run_job_json).unwrap();
        drop(db);
        let custody = build_ledger_custody(&app, "alice+high_impact");
        let db = app.db();
        let html = render_run_report_html(&db, "run-1", &job, None, &custody);
        // structure & branding
        assert!(html.starts_with("<!doctype html>"), "document HTML autonome");
        assert!(html.contains("Guat<span class=\"x\">X</span>"), "branding GuatX");
        assert!(html.contains("/quetzal.svg"), "quetzal sur la page de garde");
        assert!(html.contains("@media print"), "CSS print fourni");
        assert!(html.contains("class=\"toc\""), "sommaire présent");
        // executive summary en prose + contexte Campaign.notes
        assert!(html.contains("Résumé exécutif"), "section résumé exécutif");
        assert!(html.contains("Pentest grey-box autorisé"), "Campaign.notes branchées dans le contexte");
        assert!(html.contains("posture"), "posture rendue");
        // CWE/CVSS SÉPARÉS + FIX
        assert!(html.contains("CWE</b> CWE-639"), "CWE rendu séparément");
        assert!(html.contains("8.1"), "CVSS score rendu");
        assert!(html.contains("Remédiation") && html.contains("Contrôle ownership serveur"), "FIX rendu");
        // anti-injection : le titre hostile est échappé, pas exécutable
        assert!(html.contains("&lt;b&gt;IDOR&lt;/b&gt;"), "titre hostile échappé");
        assert!(!html.contains("<b>IDOR</b>"), "pas de balise hostile brute");
        // annexe chaîne-de-custody
        assert!(html.contains("Annexe — chaîne de custody"), "annexe custody");
        assert!(html.contains("forge ledger verify --ledger") && html.contains("--pubkey"), "commande de vérif externe");
        assert!(html.contains("VALIDE"), "intégrité de la chaîne recalculée");
        assert!(html.contains("alice") && html.contains("HAUT-IMPACT"), "attribution actor + opt-in haut-impact");
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

    /// [purple http] http_get_blocking : pour kind=plume (allow_https=false) une URL https:// est
    /// rejetée (TLS non géré, rétro-compat EXACTE) avec un message lisible mentionnant http://.
    #[test]
    fn http_get_blocking_rejects_non_http() {
        let e = http_get_blocking(
            "https://plume:7000/api/coverage/detections",
            &HttpAuth::None,
            Duration::from_millis(50),
            false, // allow_https=false (chemin plume)
        );
        assert!(e.is_err(), "https non géré (plume) -> Err");
        assert!(e.unwrap_err().contains("http://"), "message lisible mentionnant http://");
    }

    // =============================================================================================
    // SOURCE DE DÉTECTION CONFIGURABLE (plugin) — refactor infra-agnostique de la boucle purple.
    // =============================================================================================

    /// Écrit la config de source de détection dans le cache de l'App (utilitaire de test).
    fn set_detection_source(app: &App, cfg: Value) {
        *app.detection_source.write().unwrap() = Arc::new(cfg);
    }

    /// Serveur HTTP mock (UNE connexion) : renvoie `body` en 200 et retourne la requête reçue (ligne +
    /// en-têtes) pour inspection (ex. vérifier l'en-tête d'auth). Bind éphémère 127.0.0.1:0.
    async fn mock_http_once(body: String) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.expect("accept mock");
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
            req // le drop de `sock` en fin de tâche ferme la connexion (EOF côté client)
        });
        (addr, handle)
    }

    /// [détection RÉTRO-COMPAT] resolve_detection_source : sans settings, l'env legacy PLUME_URL/
    /// PLUME_TOKEN produit `{kind:plume, endpoint, auth:{type:basic,secret}}` ; une config `settings`
    /// PRIME sur l'env (la clé settings verbatim gagne). Ces deux branches figent le repli rétro-compat.
    #[test]
    fn resolve_detection_source_env_fallback_and_settings_precedence() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        // env posé, settings vide -> repli plume implicite.
        std::env::set_var("PLUME_URL", "http://soc.internal:7000/");
        std::env::set_var("PLUME_TOKEN", "dXNlcjpwYXNz");
        let v = resolve_detection_source(&conn);
        std::env::remove_var("PLUME_URL");
        std::env::remove_var("PLUME_TOKEN");
        assert_eq!(ds_kind(&v), "plume", "repli env -> kind plume");
        assert_eq!(ds_endpoint(&v), "http://soc.internal:7000", "endpoint = PLUME_URL (slash final retiré)");
        assert_eq!(ds_auth_type(&v), "basic");
        assert_eq!(ds_secret(&v), "dXNlcjpwYXNz", "auth.secret = PLUME_TOKEN");
        // settings présent -> gagne, MÊME si l'env est posé.
        std::env::set_var("PLUME_URL", "http://ignore-me:1");
        settings_set(&conn, "detection_source",
            "{\"kind\":\"generic_http\",\"endpoint\":\"http://siem:9200\",\"auth\":{\"type\":\"bearer\",\"secret\":\"abc\"}}").unwrap();
        let v2 = resolve_detection_source(&conn);
        std::env::remove_var("PLUME_URL");
        assert_eq!(ds_kind(&v2), "generic_http", "settings prime sur l'env");
        assert_eq!(ds_endpoint(&v2), "http://siem:9200");
    }

    /// [détection RÉTRO-COMPAT bout-en-bout] une source `kind=plume` (endpoint = mock renvoyant le
    /// contrat historique `{detections:[{mitre,count,first_ts}]}`) produit EXACTEMENT la même couverture
    /// que l'ancien chemin Plume : mapping IDENTITÉ, mêmes detected/missed/MTTD que compute_purple_coverage.
    #[tokio::test]
    async fn plume_source_yields_same_coverage_backcompat() {
        let app = test_app(&tmp_path("det-plume-ledger"));
        let body = r#"{"detections":[{"mitre":"T1110","count":3,"first_ts":1042},{"mitre":"T1190","count":1,"first_ts":1990}]}"#;
        let (addr, handle) = mock_http_once(body.to_string()).await;
        set_detection_source(&app, json!({
            "kind": "plume",
            "endpoint": format!("http://{addr}"),
            "auth": {"type": "basic", "secret": "dXNlcjpwYXNz"}
        }));
        let fired = vec![
            ("T1110".to_string(), Some(1000)),
            ("T1190".to_string(), Some(2000)),
            ("T1046".to_string(), Some(3000)),
        ];
        let cov = fetch_purple_coverage(&app, fired).await;
        let req = handle.await.unwrap();
        // le chemin plume envoie GET /api/coverage/detections?since=... + Basic (rétro-compat exacte).
        assert!(req.contains("GET /api/coverage/detections?since=1000"), "chemin/param plume: {req}");
        assert!(req.contains("Authorization: Basic dXNlcjpwYXNz"), "auth Basic transmise: {req}");
        assert_eq!(cov["plume_reachable"], json!(true), "rétro-compat: plume_reachable conservé");
        assert_eq!(cov["source_reachable"], json!(true), "miroir neutre présent");
        assert_eq!(cov["source_kind"], json!("plume"));
        assert_eq!(cov["techniques_detected"], json!(2));
        assert_eq!(cov["techniques_missed"], json!(1));
        let t1110 = cov["detected"].as_array().unwrap().iter().find(|d| d["mitre"] == json!("T1110")).unwrap();
        assert_eq!(t1110["mttd_secs"], json!(42), "MTTD identique à l'ancien calcul");
        assert_eq!(t1110["alert_count"], json!(3));
    }

    /// [détection generic_http + bearer + mapping] une source `generic_http` avec auth bearer est
    /// interrogée (en-tête `Authorization: Bearer …` transmis) et la réponse aux CHAMPS NATIFS
    /// (results/tech/seen/ts) est remappée puis corrélée — même jointure MITRE que plume.
    #[tokio::test]
    async fn generic_http_bearer_fetched_and_mapped() {
        let app = test_app(&tmp_path("det-generic-ledger"));
        let body = r#"{"results":[{"tech":"T1110","seen":3,"ts":1042},{"tech":"T1190","seen":1,"ts":1990}]}"#;
        let (addr, handle) = mock_http_once(body.to_string()).await;
        set_detection_source(&app, json!({
            "kind": "generic_http",
            "endpoint": format!("http://{addr}/api/alerts"),
            "auth": {"type": "bearer", "secret": "tok-abc-123"},
            "mapping": {"records": "results", "mitre": "tech", "count": "seen", "ts": "ts"}
        }));
        let fired = vec![
            ("T1110".to_string(), Some(1000)),
            ("T1190".to_string(), Some(2000)),
            ("T1046".to_string(), Some(3000)),
        ];
        let cov = fetch_purple_coverage(&app, fired).await;
        let req = handle.await.unwrap();
        assert!(req.contains("GET /api/alerts "), "endpoint generic respecté: {req}");
        assert!(req.contains("Authorization: Bearer tok-abc-123"), "bearer transmis: {req}");
        assert_eq!(cov["source_reachable"], json!(true));
        assert_eq!(cov["source_kind"], json!("generic_http"));
        assert_eq!(cov["techniques_detected"], json!(2), "T1110+T1190 remappés et détectés");
        assert_eq!(cov["techniques_missed"], json!(1), "T1046 = trou");
        let t1110 = cov["detected"].as_array().unwrap().iter().find(|d| d["mitre"] == json!("T1110")).unwrap();
        assert_eq!(t1110["alert_count"], json!(3), "count natif `seen` remappé");
        assert_eq!(t1110["mttd_secs"], json!(42));
    }

    /// [détection FAIL-OPEN LISIBLE] une source injoignable (port fermé) => source_reachable:false SANS
    /// aucun detected/missed inventé ; une config kind=none => idem. Le secret n'apparaît nulle part.
    #[tokio::test]
    async fn unreachable_source_fails_open_readable() {
        let app = test_app(&tmp_path("det-unreach-ledger"));
        set_detection_source(&app, json!({
            "kind": "generic_http",
            "endpoint": "http://127.0.0.1:1/x", // port 1 -> connexion refusée
            "auth": {"type": "bearer", "secret": "MUST-NOT-LEAK-XYZ"}
        }));
        let fired = vec![("T1110".to_string(), Some(1000)), ("T1046".to_string(), Some(2000))];
        let cov = fetch_purple_coverage(&app, fired).await;
        assert_eq!(cov["source_reachable"], json!(false), "injoignable -> fail-open lisible");
        assert_eq!(cov["plume_reachable"], json!(false), "miroir rétro-compat");
        assert_eq!(cov["techniques_detected"], json!(0), "rien détecté inventé");
        assert_eq!(cov["techniques_missed"], json!(0), "rien classé missed (mesure impossible)");
        assert!(cov["detected"].as_array().unwrap().is_empty());
        assert!(cov["missed"].as_array().unwrap().is_empty());
        assert!(cov.get("error").is_some(), "raison lisible présente");
        let ser = serde_json::to_string(&cov).unwrap();
        assert!(!ser.contains("MUST-NOT-LEAK-XYZ"), "le secret ne DOIT jamais apparaître dans la réponse");

        // config kind=none -> même fail-open lisible.
        set_detection_source(&app, json!({"kind": "none"}));
        let cov2 = fetch_purple_coverage(&app, vec![("T1110".to_string(), Some(1))]).await;
        assert_eq!(cov2["source_reachable"], json!(false));
        assert_eq!(cov2["techniques_detected"], json!(0));
        assert!(cov2["detected"].as_array().unwrap().is_empty());
    }

    /// [détection /api/detection/test] ADMIN uniquement (sans session -> refus), n'expose JAMAIS le
    /// secret dans la réponse ni le ledger, et renvoie {reachable,count,sample_mitres,error?}. Flux réel
    /// via build_router (parité prod/test) : provision admin -> cookie -> POST test.
    #[tokio::test]
    async fn detection_test_admin_only_and_never_leaks_secret() {
        let ledger = tmp_path("det-test-ledger");
        let app = test_app(&ledger);
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // provision d'un admin -> cookie de session admin.
        let setup_body = json!({"admin_login": "root", "admin_password": "hunter2pw"}).to_string();
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 200, "provision: {r}");
        let tok = cookie_token(&r).expect("cookie admin");

        let secret = "DETECT-SECRET-NEVER-LEAK-9999";
        let test_body = json!({"detection_source": {
            "kind": "generic_http",
            "endpoint": "http://127.0.0.1:1/x",   // injoignable -> reachable:false
            "auth": {"type": "bearer", "secret": secret}
        }}).to_string();

        // 1) SANS session -> refusé (gate engagée : 401/403, jamais 200).
        let r = http_raw(addr, &post_req("/api/detection/test", &test_body, "")).await;
        assert_ne!(parse_status(&r), 200, "sans admin -> pas 200 : {r}");

        // 2) AVEC session admin -> 200 + reachable:false + secret ABSENT de la réponse.
        let r = http_raw(addr, &post_req("/api/detection/test", &test_body,
            &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "admin -> 200 : {r}");
        let b = body_of(&r);
        assert!(b.contains("\"reachable\":false"), "source injoignable -> reachable:false : {b}");
        assert!(b.contains("\"count\":0"));
        assert!(!b.contains(secret), "le secret ne DOIT jamais être renvoyé : {b}");

        // 3) le ledger trace le test SANS le secret (endpoint + type d'auth seuls).
        let last = read_ledger_lines(&ledger).pop().expect("ledger detection.test");
        assert_eq!(last["kind"], "console.detection.test");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["kind"], "generic_http");
        assert_eq!(last["detail"]["auth_type"], "bearer");
        let ser = canon_json(&last);
        assert!(!ser.contains(secret), "le secret ne DOIT jamais entrer dans le ledger : {ser}");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [détection GET /api/detection/source] ADMIN uniquement (sans session -> refus) et RÉDACTION du
    /// secret : la config effective est renvoyée SANS `auth.secret`, avec `secret_set:true` et l'endpoint
    /// (non secret) conservé. Flux réel via build_router (provision admin -> cookie -> GET).
    #[tokio::test]
    async fn detection_source_get_redacts_secret_and_admin_gated() {
        let ledger = tmp_path("det-src-get-ledger");
        let app = test_app(&ledger);
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // provision d'un admin AVEC une source de détection portant un secret.
        let secret = "GET-REDACT-SECRET-7777";
        let setup_body = json!({
            "admin_login": "root", "admin_password": "hunter2pw",
            "detection_source": {"kind": "generic_http", "endpoint": "http://soc.local:9/x",
                                 "auth": {"type": "bearer", "secret": secret}}
        }).to_string();
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 200, "provision: {r}");
        let tok = cookie_token(&r).expect("cookie admin");

        // 1) GET SANS session -> refusé (gate engagée : jamais 200).
        let r = http_raw(addr, &get_req("/api/detection/source", "")).await;
        assert_ne!(parse_status(&r), 200, "GET sans admin -> refus : {r}");

        // 2) GET AVEC session admin -> 200 + secret ABSENT + secret_set:true + endpoint (non secret) présent.
        let r = http_raw(addr, &get_req("/api/detection/source", &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "admin -> 200 : {r}");
        let b = body_of(&r);
        assert!(!b.contains(secret), "le secret ne DOIT jamais être renvoyé par GET : {b}");
        assert!(b.contains("\"secret_set\":true"), "secret_set:true attendu : {b}");
        assert!(b.contains("generic_http"), "kind conservé : {b}");
        assert!(b.contains("soc.local"), "endpoint (non secret) conservé pour l'édition : {b}");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [détection POST /api/detection/source] ADMIN uniquement (sans session -> refus, rien persisté) ;
    /// une sauvegarde admin est LEDGERISÉE (console.detection.source.set, sans le secret) et persiste
    /// `settings.detection_source` VERBATIM ; write-only : `keep_secret` conserve le secret déjà posé
    /// sans le re-saisir, et le secret n'apparaît JAMAIS dans une réponse ni le ledger.
    #[tokio::test]
    async fn detection_source_set_admin_gated_ledgered_and_write_only_secret() {
        let ledger = tmp_path("det-src-set-ledger");
        let app = test_app(&ledger);
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // provision d'un admin SANS source de détection -> cookie admin.
        let setup_body = json!({"admin_login": "root", "admin_password": "hunter2pw"}).to_string();
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 200, "provision: {r}");
        let tok = cookie_token(&r).expect("cookie admin");

        let secret = "SET-SECRET-NEVER-LEAK-4242";
        let cfg = json!({"detection_source": {"kind": "generic_http", "endpoint": "http://soc.local:9/x",
                        "auth": {"type": "bearer", "secret": secret}}}).to_string();

        // 1) POST SANS session -> refusé + RIEN persisté (fail-closed avant toute écriture).
        let r = http_raw(addr, &post_req("/api/detection/source", &cfg, "")).await;
        assert_ne!(parse_status(&r), 200, "POST sans admin -> refus : {r}");
        {
            let db = app.db();
            assert!(settings_get(&db, "detection_source").is_none(), "aucune écriture sans session admin");
        }

        // 2) POST AVEC session admin -> 200 + settings persistés VERBATIM + ledger source.set (sans secret).
        let r = http_raw(addr, &post_req("/api/detection/source", &cfg, &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "admin -> 200 : {r}");
        let b = body_of(&r);
        assert!(!b.contains(secret), "la réponse de sauvegarde ne DOIT jamais contenir le secret : {b}");
        assert!(b.contains("\"saved\":true"));
        {
            let db = app.db();
            let stored = settings_get(&db, "detection_source").expect("detection_source persisté");
            assert!(stored.contains("generic_http"), "config persistée");
            assert!(stored.contains(secret), "secret persisté verbatim côté serveur (jamais renvoyé)");
        }
        let last = read_ledger_lines(&ledger).pop().expect("ledger source.set");
        assert_eq!(last["kind"], "console.detection.source.set");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["kind"], "generic_http");
        assert_eq!(last["detail"]["auth_type"], "bearer");
        let ser = canon_json(&last);
        assert!(!ser.contains(secret), "le secret ne DOIT jamais entrer dans le ledger : {ser}");

        // 3) WRITE-ONLY : POST keep_secret SANS secret (endpoint modifié) -> le secret déjà posé est CONSERVÉ.
        let cfg2 = json!({"keep_secret": true, "detection_source": {"kind": "generic_http",
                         "endpoint": "http://soc.local:9/y", "auth": {"type": "bearer"}}}).to_string();
        let r = http_raw(addr, &post_req("/api/detection/source", &cfg2, &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "keep_secret -> 200 : {r}");
        {
            let db = app.db();
            let stored = settings_get(&db, "detection_source").expect("detection_source persisté");
            assert!(stored.contains("soc.local:9/y"), "endpoint mis à jour");
            assert!(stored.contains(secret), "secret conservé via keep_secret (write-only) : {stored}");
        }
        // 4) GET ne renvoie JAMAIS le secret, même après le round-trip keep_secret.
        let r = http_raw(addr, &get_req("/api/detection/source", &format!("Cookie: forge_session={tok}\r\n"))).await;
        let b = body_of(&r);
        assert!(!b.contains(secret), "GET post-keep_secret : secret toujours rédigé : {b}");
        assert!(b.contains("\"secret_set\":true"));
        let _ = std::fs::remove_file(&ledger);
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
        assert!(!high_impact_gate(false, true, true, "raison").unwrap());
        assert!(!high_impact_gate(false, false, false, "").unwrap(),
            "opt-in absent prime : aucune erreur même sans arm/reason");
        // opt-in demandé + 3 conditions réunies -> Ok(true).
        assert!(high_impact_gate(true, true, true, "test autorisé par l'opérateur").unwrap());
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

    // =================================================================================================
    // GOUVERNANCE CONNECTEUR (#4) — enabled / available_override : intention opérateur + enforcement.
    // =================================================================================================

    /// [connecteur] module_operator_disabled / module_effectively_available (fonctions PURES) :
    /// désactivé ssi enabled=0 OU override=Some(false) ; un binaire simplement absent (probed=0, sans
    /// override) N'EST PAS une désactivation opérateur. effective = enabled AND (override ?? probed).
    #[test]
    fn module_governance_pure_predicates() {
        // enabled + rien -> suit la sonde.
        assert!(!module_operator_disabled(true, None), "enabled sans override -> pas désactivé opérateur");
        assert!(module_effectively_available(true, None, true), "enabled + sonde OK -> effectif");
        assert!(!module_effectively_available(true, None, false), "enabled + sonde KO -> non effectif (sonde)");
        // enabled=0 -> désactivé opérateur, jamais effectif (même sonde OK).
        assert!(module_operator_disabled(false, None), "enabled=0 -> désactivé");
        assert!(!module_effectively_available(false, None, true), "enabled=0 prime sur une sonde positive");
        // override=Some(false) -> désactivé opérateur MÊME si la sonde est positive (binaire présent).
        assert!(module_operator_disabled(true, Some(false)), "override=false -> désactivé opérateur");
        assert!(!module_effectively_available(true, Some(false), true), "override=false masque un binaire présent");
        // override=Some(true) -> PAS une désactivation ; effectif même sonde négative.
        assert!(!module_operator_disabled(true, Some(true)), "override=true -> pas désactivé");
        assert!(module_effectively_available(true, Some(true), false), "override=true force la disponibilité");
    }

    /// [connecteur --modules filter] filter_enabled_modules + operator_disabled_modules : un connecteur
    /// DÉSACTIVÉ (enabled=0) OU masqué par override=0 est RETIRÉ de la liste `--modules` passée au moteur
    /// au spawn, ET figure dans l'ensemble injecté au scope.json. Un binaire absent (probed=0, sans
    /// override) N'est PAS considéré « désactivé opérateur » (le moteur le SKIP via sa propre sonde).
    #[test]
    fn module_governance_filter_and_disabled_set() {
        let path = tmp_path("forge-test-modfilter");
        let app = test_app(&path);
        seed_modules(&app); // recon.httpx (enabled=1, dispo), exploit.rce (enabled=1, dispo)
        {
            let db = app.db();
            // recon.disabled : présent (available=1) mais DÉSACTIVÉ par l'opérateur (enabled=0).
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled) \
                        VALUES('recon.disabled',0,0,1,'','recon',1,0)", []).unwrap();
            // recon.masked : ENABLED mais override=0 -> masqué malgré un binaire présent.
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled,available_override) \
                        VALUES('recon.masked',0,0,1,'','recon',1,1,0)", []).unwrap();
            // recon.absent : ENABLED, pas d'override, binaire ABSENT (available=0) -> PAS désactivé opérateur.
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled) \
                        VALUES('recon.absent',0,0,0,'','recon',1,1)", []).unwrap();
        }
        let disabled = operator_disabled_modules(&app);
        assert!(disabled.contains(&"recon.disabled".to_string()), "enabled=0 -> dans le set désactivé");
        assert!(disabled.contains(&"recon.masked".to_string()), "override=0 -> dans le set désactivé");
        assert!(!disabled.contains(&"recon.absent".to_string()), "binaire absent (sans override) -> PAS désactivé opérateur");
        assert!(!disabled.contains(&"recon.httpx".to_string()), "connecteur actif -> hors set");
        // filtre --modules : les désactivés SONT retirés, les actifs et l'absent (géré par la sonde) restent.
        let filtered = filter_enabled_modules(&app,
            &["recon.httpx".into(), "recon.disabled".into(), "recon.masked".into(), "recon.absent".into()]);
        assert_eq!(filtered, vec!["recon.httpx".to_string(), "recon.absent".to_string()],
            "le filtre spawn retire recon.disabled + recon.masked, conserve httpx + absent");
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur validate] validate_modules CONSULTE enabled/override : un connecteur désactivé est
    /// refusé (400 module_disabled) — MÊME sous opt-in haut-impact (désinstaller un connecteur est au
    /// -dessus du plancher exploit). Un module actif reste accepté. Un binaire absent (sans override)
    /// N'est PAS refusé (comportement inchangé : accepté puis SKIP par le moteur).
    #[test]
    fn validate_modules_rejects_operator_disabled() {
        let path = tmp_path("forge-test-vmods-disabled");
        let app = test_app(&path);
        seed_modules(&app);
        {
            let db = app.db();
            db.execute("UPDATE module SET enabled=0 WHERE kind='recon.httpx'", []).unwrap(); // désactive
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled) \
                        VALUES('recon.absent',0,0,0,'','recon',1,1)", []).unwrap();           // absent mais actif
        }
        // désactivé -> 400 module_disabled (sans opt-in).
        let err = validate_modules(&app, &["recon.httpx".into()], false).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.0["error"], "module_disabled", "connecteur désactivé refusé");
        // désactivé -> 400 module_disabled MÊME sous opt-in haut-impact (au-dessus du plancher exploit).
        let err = validate_modules(&app, &["recon.httpx".into()], true).unwrap_err();
        assert_eq!(err.1.0["error"], "module_disabled", "désactivé refusé même armé (gouvernance > plancher)");
        // réactive -> OK ; binaire absent (actif) -> accepté (skip côté moteur, pas un refus web).
        { let db = app.db(); db.execute("UPDATE module SET enabled=1 WHERE kind='recon.httpx'", []).unwrap(); }
        assert!(validate_modules(&app, &["recon.httpx".into()], false).is_ok(), "réactivé -> accepté");
        assert!(validate_modules(&app, &["recon.absent".into()], false).is_ok(),
            "binaire absent sans intention opérateur -> accepté (SKIP moteur), pas 400");
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur no-clobber] upsert_probed_module (chemin populate_modules) : un DISABLE manuel
    /// (enabled=0 + available_override=0 + web_allowed=0) SURVIT à un re-probe qui met à jour les
    /// champs sondés (exploit/available/mitre/descr). Régression : le refresh ne doit JAMAIS écraser
    /// l'intention opérateur.
    #[test]
    fn refresh_does_not_clobber_manual_disable() {
        let path = tmp_path("forge-test-noclobber");
        let app = test_app(&path);
        {
            let db = app.db();
            // 1er probe : module recon dispo.
            upsert_probed_module(&db, "recon.httpx", false, false, true, "", "recon httpx");
            // l'admin DÉSACTIVE le connecteur + masque + retire du web (intention opérateur).
            db.execute("UPDATE module SET enabled=0, available_override=0, web_allowed=0 WHERE kind='recon.httpx'", []).unwrap();
            // re-probe (nouvelle version : gagne une capacité exploit, sonde toujours dispo, descr changée).
            upsert_probed_module(&db, "recon.httpx", true, false, true, "T1190", "recon httpx v2");
            let (enabled, ov, web, exploit, descr): (i64, Option<i64>, i64, i64, String) = db.query_row(
                "SELECT enabled, available_override, web_allowed, exploit, descr FROM module WHERE kind='recon.httpx'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap();
            // INTENTION OPÉRATEUR préservée :
            assert_eq!(enabled, 0, "enabled=0 préservé au re-probe (no-clobber)");
            assert_eq!(ov, Some(0), "available_override=0 préservé au re-probe");
            assert_eq!(web, 0, "web_allowed préservé au re-probe (intention opérateur)");
            // champs SONDÉS mis à jour :
            assert_eq!(exploit, 1, "champ sondé exploit MIS À JOUR par le re-probe");
            assert_eq!(descr, "recon httpx v2", "champ sondé descr MIS À JOUR par le re-probe");
        }
        // un NOUVEAU module hérite des DEFAULT enabled=1 / override=NULL.
        {
            let db = app.db();
            upsert_probed_module(&db, "recon.new", false, false, true, "", "neuf");
            let (enabled, ov): (i64, Option<i64>) = db.query_row(
                "SELECT enabled, available_override FROM module WHERE kind='recon.new'", [],
                |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert_eq!(enabled, 1, "nouveau module -> enabled par défaut");
            assert_eq!(ov, None, "nouveau module -> pas d'override par défaut (suit la sonde)");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur endpoint] module_governance : ADMIN-GATED (viewer -> 403 sans aucune mutation) +
    /// LEDGERISÉ (une mutation admin écrit `console.admin.module.set` attribuée à l'acteur). Preuve que
    /// l'endpoint est la contrepartie écriture gouvernée de GET /api/modules.
    #[tokio::test]
    async fn module_governance_endpoint_admin_gated_and_ledgered() {
        let path = tmp_path("forge-test-modgov");
        let app = test_app(&path);
        seed_modules(&app);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (atok, _) = create_session(&app, uid_of(&app, "aa"));

        // viewer -> 403 (fail-closed) ET aucune mutation (le connecteur reste enabled=1).
        let resp = module_governance(
            State(app.clone()), bearer_headers(&vtok), Path("recon.httpx".into()),
            Json(json!({"enabled": false}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "non-admin refusé (fail-closed)");
        let en: i64 = { let db = app.db(); db.query_row("SELECT enabled FROM module WHERE kind='recon.httpx'", [], |r| r.get(0)).unwrap() };
        assert_eq!(en, 1, "un refus 403 ne DOIT rien muter");

        // admin -> 200 + mutation persistée + entrée ledger attribuée.
        let resp = module_governance(
            State(app.clone()), bearer_headers(&atok), Path("recon.httpx".into()),
            Json(json!({"enabled": false, "available_override": true}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "admin autorisé");
        let (en, ov): (i64, Option<i64>) = { let db = app.db(); db.query_row(
            "SELECT enabled, available_override FROM module WHERE kind='recon.httpx'", [],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!(en, 0, "admin a désactivé le connecteur");
        assert_eq!(ov, Some(1), "admin a posé available_override=true");
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.admin.module.set", "mutation ledgerisée");
        assert_eq!(last["detail"]["actor"], "aa", "attribuée à l'admin acteur");
        assert_eq!(last["detail"]["kind"], "recon.httpx");
        assert_eq!(last["detail"]["enabled"], false);

        // kind inconnu -> 404 (pas de module fantôme créé depuis l'admin).
        let resp = module_governance(
            State(app.clone()), bearer_headers(&atok), Path("recon.ghost".into()),
            Json(json!({"enabled": false}))).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "connecteur inconnu -> 404");
        // corps sans aucun champ -> 400 (aucun changement).
        let resp = module_governance(
            State(app.clone()), bearer_headers(&atok), Path("recon.httpx".into()),
            Json(json!({}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "aucun changement -> 400");
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur routeur] le param `/api/modules/:kind` coexiste avec le statique
    /// `/api/modules/refresh` (matchit : le statique prime). Construire ce sous-routeur ne doit PAS
    /// paniquer — garde-fou contre un conflit de routes introduit par la gouvernance connecteur.
    #[test]
    fn module_routes_do_not_conflict() {
        let _r: Router<App> = Router::new()
            .route("/api/modules", get(modules))
            .route("/api/modules/refresh", post(modules_refresh))
            .route("/api/modules/:kind", post(module_governance));
    }

    // =============================================================================================
    // SÉLECTION DE TECHNIQUES PAR-SCOPE (profil + toggles catégorie/technique) — validation, persistance,
    // catalogue groupé par catégorie (spawn moteur), endpoint gouverné (opérateur/admin) + ledgerisé.
    // =============================================================================================

    fn conn_info() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:5555".parse().unwrap())
    }

    /// Aplati {groups:{cat:[{kind,enabled_for_current_scope}]}} en une map kind -> activé.
    fn flatten_enabled(body: &Value) -> std::collections::HashMap<String, bool> {
        let mut m = std::collections::HashMap::new();
        if let Some(groups) = body.get("groups").and_then(|g| g.as_object()) {
            for rows in groups.values() {
                for r in rows.as_array().into_iter().flatten() {
                    if let (Some(k), Some(e)) = (
                        r.get("kind").and_then(|v| v.as_str()),
                        r.get("enabled_for_current_scope").and_then(|v| v.as_bool()),
                    ) {
                        m.insert(k.to_string(), e);
                    }
                }
            }
        }
        m
    }

    /// [sélection pure] validate_technique_selection : profils fermés, toggles typés bool + clés bien
    /// formées, défauts, clés INCONNUES tolérées (le résolveur moteur les ignore — pas de capacité forgée).
    #[test]
    fn validate_technique_selection_grammar_and_defaults() {
        // corps vide -> défaut profil bug_bounty + toggles vides.
        let v = validate_technique_selection(&json!({})).unwrap();
        assert_eq!(v["profile"], "bug_bounty");
        assert_eq!(v["categories"], json!({}));
        assert_eq!(v["techniques"], json!({}));
        // profils FERMÉS.
        for p in ["bug_bounty", "pentest", "custom"] {
            assert_eq!(validate_technique_selection(&json!({"profile": p})).unwrap()["profile"], p);
        }
        assert!(validate_technique_selection(&json!({"profile": "root"})).is_err(), "profil inconnu refusé");
        // toggles : bool requis, clé bien formée ; clé inconnue TOLÉRÉE (résolveur moteur l'ignore).
        let v = validate_technique_selection(&json!({"categories": {"SQLi": false}, "techniques": {"rce.probe": true}})).unwrap();
        assert_eq!(v["categories"]["SQLi"], false);
        assert_eq!(v["techniques"]["rce.probe"], true);
        assert!(validate_technique_selection(&json!({"categories": {"SQLi": "no"}})).is_err(), "valeur non-bool refusée");
        assert!(validate_technique_selection(&json!({"categories": {"bad key": true}})).is_err(), "clé mal formée refusée");
        assert!(validate_technique_selection(&json!({"techniques": []})).is_err(), "techniques doit être un objet");
    }

    /// [sélection persistance] technique_selection_value : défaut bug_bounty si absent ; round-trip après
    /// settings_set ; valeur illisible -> défaut (fail-soft, jamais de valeur inventée).
    #[test]
    fn technique_selection_value_default_and_round_trip() {
        let path = tmp_path("forge-test-techsel");
        let app = test_app(&path);
        assert_eq!(technique_selection_value(&app)["profile"], "bug_bounty", "absent -> défaut bug_bounty");
        {
            let db = app.db();
            settings_set(&db, "technique_selection",
                &json!({"profile":"pentest","categories":{"SQLi":false},"techniques":{}}).to_string()).unwrap();
        }
        let v = technique_selection_value(&app);
        assert_eq!(v["profile"], "pentest");
        assert_eq!(v["categories"]["SQLi"], false);
        { let db = app.db(); settings_set(&db, "technique_selection", "pas du json").unwrap(); }
        assert_eq!(technique_selection_value(&app)["profile"], "bug_bounty", "illisible -> défaut (fail-soft)");
        let _ = std::fs::remove_file(&path);
    }

    /// [sélection endpoint] POST /api/techniques/selection : OPÉRATEUR/ADMIN-gated (viewer -> 403 SANS
    /// mutation) + LEDGERISÉ (`console.techniques.selection.set` attribuée à l'acteur) + persisté.
    #[tokio::test]
    async fn technique_selection_endpoint_operator_gated_and_ledgered() {
        let path = tmp_path("forge-test-techsel-ep");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));

        // viewer -> 403 (fail-closed) ET aucune persistance.
        let resp = technique_selection_set(State(app.clone()), conn_info(), bearer_headers(&vtok),
            Json(json!({"profile": "pentest"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer refusé (fail-closed)");
        { let db = app.db(); assert!(settings_get(&db, "technique_selection").is_none(), "un refus ne persiste rien"); }

        // operator -> 200 + persistance + ledger attribué.
        let resp = technique_selection_set(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(json!({"profile": "pentest", "categories": {"SQLi": false}}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "operator autorisé");
        let stored = { let db = app.db(); settings_get(&db, "technique_selection").unwrap() };
        let sv: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(sv["profile"], "pentest");
        assert_eq!(sv["categories"]["SQLi"], false);
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.techniques.selection.set", "mutation ledgerisée");
        assert_eq!(last["detail"]["actor"], "oo", "attribuée à l'acteur opérateur");
        assert_eq!(last["detail"]["selection"]["profile"], "pentest");

        // profil invalide -> 400.
        let resp = technique_selection_set(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(json!({"profile": "root"}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "profil invalide -> 400");
        let _ = std::fs::remove_file(&path);
    }

    /// [catalogue] GET /api/techniques : spawne le moteur, GROUPE par catégorie et reflète l'état activé
    /// du scope. Défaut (bug_bounty) : rce.probe désactivé, sqli.probe activé. Une sélection persistée
    /// (pentest) réactive rce.probe. DÉRIVÉ du registre (SOURCE UNIQUE) — nécessite python3 + forge (..).
    #[tokio::test]
    async fn techniques_catalog_groups_by_category_and_reflects_scope() {
        let path = tmp_path("forge-test-techcat");
        let app = test_app(&path);
        // défaut (aucune sélection persistée -> bug_bounty).
        let resp = techniques_catalog(State(app.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp_json(resp).await;
        assert!(body.get("error").is_none(), "catalogue indisponible (spawn moteur): {body:?}");
        assert_eq!(body["profile"], "bug_bounty");
        let groups = body["groups"].as_object().expect("groups objet");
        assert!(groups.contains_key("SQLi") && groups.contains_key("IDOR"), "groupé par catégorie (SQLi/IDOR)");
        let state = flatten_enabled(&body);
        assert_eq!(state.get("rce.probe"), Some(&false), "rce.probe pentest-only -> désactivé en bug_bounty");
        assert_eq!(state.get("sqli.probe"), Some(&true), "sqli.probe bug_bounty -> activé");
        // chaque ligne porte tools + éligibilité.
        let sqli = groups["SQLi"].as_array().unwrap().iter().find(|r| r["kind"] == "sqli.probe").unwrap();
        assert!(sqli.get("tools").is_some() && sqli.get("bug_bounty_eligible").is_some(),
            "chaque technique porte tools + éligibilité BB");

        // sélection persistée pentest -> rce.probe activé (reflète le scope courant).
        {
            let db = app.db();
            settings_set(&db, "technique_selection",
                &json!({"profile":"pentest","categories":{},"techniques":{}}).to_string()).unwrap();
        }
        let resp = techniques_catalog(State(app.clone())).await;
        let body = resp_json(resp).await;
        assert_eq!(body["profile"], "pentest");
        assert_eq!(flatten_enabled(&body).get("rce.probe"), Some(&true), "pentest -> rce.probe activé");
        let _ = std::fs::remove_file(&path);
    }

    // =============================================================================================
    // AUTONOMIE (STANDALONE) — Forge ne DÉPEND JAMAIS de Plume / d'une source de détection.
    // Plume (et tout SIEM/IDS) n'est qu'un enrichissement OPTIONNEL de la boucle purple.
    // =============================================================================================

    /// [STANDALONE] Sans réglage `settings.detection_source` NI env PLUME_URL/PLUME_TOKEN, la source
    /// résolue au boot est `{kind:none}` : la console démarre en AUTONOME, aucune dépendance Plume.
    /// (Défense en profondeur : on RETIRE explicitement l'env legacy pour prouver l'absence de repli.)
    #[test]
    fn standalone_default_detection_source_is_none_without_plume_env() {
        let _g = env_lock();
        std::env::remove_var("PLUME_URL");
        std::env::remove_var("PLUME_TOKEN");
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let v = resolve_detection_source(&conn);
        assert_eq!(ds_kind(&v), "none", "aucune source ni env -> kind none (Forge autonome, pas de Plume requis)");
        assert!(ds_endpoint(&v).is_empty(), "aucun endpoint inventé en autonome");
        assert!(ds_secret(&v).is_empty(), "aucun secret en autonome");
    }

    /// [STANDALONE] fetch_purple_coverage sans source configurée (kind=none) : FAIL-OPEN LISIBLE et
    /// EXPLICITEMENT AUTONOME — `source_reachable:false`, `source_configured:false`, `source_kind:"none"`,
    /// AUCUNE métrique fabriquée (detected/missed vides, taux/MTTD nuls), et `techniques_fired` reste
    /// informatif. C'est un état NORMAL (pas une erreur) : la boucle purple est simplement OFF.
    #[tokio::test]
    async fn fetch_purple_coverage_standalone_invents_nothing() {
        let app = test_app(&tmp_path("standalone-cov-ledger"));
        // cache par défaut = {kind:none} (test_app). On l'affirme pour la lisibilité du test.
        set_detection_source(&app, json!({"kind": "none"}));
        let fired = vec![
            ("T1110".to_string(), Some(1000)),
            ("T1110".to_string(), Some(1100)),
            ("T1046".to_string(), Some(2000)),
            ("".to_string(), None),
        ];
        let cov = fetch_purple_coverage(&app, fired).await;
        assert_eq!(cov["source_reachable"], json!(false), "autonome -> non joignable (fail-open)");
        assert_eq!(cov["plume_reachable"], json!(false), "miroir rétro-compat");
        assert_eq!(cov["source_configured"], json!(false), "AUCUNE source configurée -> standalone");
        assert_eq!(cov["source_kind"], json!("none"));
        assert_eq!(cov["techniques_detected"], json!(0), "rien de détecté fabriqué");
        assert_eq!(cov["techniques_missed"], json!(0), "rien classé raté quand la mesure est impossible");
        assert_eq!(cov["detection_rate"], json!(0.0));
        assert_eq!(cov["mttd_avg_secs"], Value::Null);
        assert_eq!(cov["mttd_max_secs"], Value::Null);
        assert!(cov["detected"].as_array().unwrap().is_empty());
        assert!(cov["missed"].as_array().unwrap().is_empty());
        assert_eq!(cov["techniques_fired"], json!(2), "info offensive conservée (T1110+T1046 distinctes)");
        assert!(cov["error"].as_str().unwrap_or("").contains("non configurée"), "raison lisible");
    }

    /// [STANDALONE] Une source POSÉE mais INJOIGNABLE se distingue de l'autonome : `source_configured:true`
    /// + `source_reachable:false`. Le SPA peut ainsi afficher une ANOMALIE (source injoignable) là, et un
    /// état NEUTRE (autonome) quand aucune source n'est configurée — sans jamais bloquer l'UI.
    #[tokio::test]
    async fn fetch_purple_coverage_configured_but_unreachable_is_distinct() {
        let app = test_app(&tmp_path("unreachable-cov-ledger"));
        // endpoint bidon fermé -> injoignable, mais une source EST bien configurée.
        set_detection_source(&app, json!({
            "kind": "plume", "endpoint": "http://127.0.0.1:1", "auth": {"type": "basic", "secret": "dXNlcjpwYXNz"}
        }));
        let cov = fetch_purple_coverage(&app, vec![("T1110".to_string(), Some(1))]).await;
        assert_eq!(cov["source_reachable"], json!(false), "endpoint fermé -> injoignable");
        assert_eq!(cov["source_configured"], json!(true), "une source EST configurée (pas autonome)");
        assert_eq!(cov["source_kind"], json!("plume"));
        assert!(cov["detected"].as_array().unwrap().is_empty(), "aucune couverture inventée même configurée");
    }

    /// [STANDALONE bout-en-bout] Sur le VRAI routeur (build_router), SANS aucune source de détection :
    /// /health répond 200 et /api/purple/coverage (+ alias /api/detection/coverage) répond 200 en état
    /// AUTONOME (source_reachable:false, source_configured:false) — l'endpoint ne renvoie JAMAIS d'erreur
    /// qui bloquerait l'UI. Prouve que la console BOOTE et sert la vue purple sans Plume.
    #[tokio::test]
    async fn standalone_boot_serves_health_and_coverage_without_plume() {
        let app = test_app(&tmp_path("standalone-boot-ledger")); // détection par défaut = {kind:none}
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // /health : la console est up (aucun PLUME_URL requis pour démarrer).
        let r = http_raw(addr, &get_req("/health", "")).await;
        assert_eq!(parse_status(&r), 200, "/health up en autonome : {r}");
        assert!(body_of(&r).contains("\"status\":\"ok\""));

        // /api/purple/coverage : 200 + état AUTONOME lisible (jamais une 5xx/erreur bloquante).
        let r = http_raw(addr, &get_req("/api/purple/coverage", "")).await;
        assert_eq!(parse_status(&r), 200, "coverage 200 en autonome (pas d'erreur bloquante) : {r}");
        let b = body_of(&r);
        assert!(b.contains("\"source_reachable\":false"), "autonome -> source_reachable:false : {b}");
        assert!(b.contains("\"source_configured\":false"), "autonome -> source_configured:false : {b}");
        assert!(!b.contains("\"techniques_detected\":1"), "aucune détection fabriquée en autonome");

        // alias canonique /api/detection/coverage : même contrat 200 autonome.
        let r2 = http_raw(addr, &get_req("/api/detection/coverage", "")).await;
        assert_eq!(parse_status(&r2), 200, "alias /api/detection/coverage 200 en autonome : {r2}");
    }

    // =============================================================================================
    // LEDGER VERIFY CLI — lecture seule, NON INTERACTIVE, RAPIDE (ne démarre PAS le serveur).
    // Régression : `forge-console ledger verify` retombait sur le boot serveur et PENDAIT.
    // =============================================================================================

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

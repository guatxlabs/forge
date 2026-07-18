// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — ÉTAT PARTAGÉ (`App`) + son substrat d'app couplé. Regroupe la struct d'état `App`
//! (+ son `impl` : `db()`/`store()`/`recompute_auth_required()`/`reload_detection_source()`/
//! `detection_config()`/`invalidate_ledger_head()`/`provisioned()` …), les structs de run vivant
//! (`RunState`/`RunHandle`/`RunEvent`), le head du ledger console (`LedgerHead`), l'objet `Engagement`
//! (+ `load_engagement`/`scope_json_list`), la gouvernance de connecteur runtime
//! (`module_operator_disabled`/`module_effectively_available`), la résolution des assets web/scope serveur
//! (`resolve_web_dir`/`load_server_scope`), les accès `settings_get`/`settings_set`/`now_epoch`/comptes
//! (`upsert_user`) et les helpers de run-report (`run_report`/`engagement_ledger_for_run`/
//! `append_run_ledger_path`/`chrono_now_compact`).
//!
//! DEUX clusters cohésifs ont été EXTRAITS de ce fichier (PURE MOVE, byte-identique au tir). Le cluster
//! `crate::schema` porte le `SCHEMA`/`PG_SCHEMA` + `migrate()`/`ensure_default_*`/`populate_modules`/
//! `advance_pg_identity_sequences*` (DDL + seeding). Le cluster `crate::detection` porte le sous-système
//! DÉTECTION / purple-coverage (`resolve_detection_source*`/`collect_detections*`/`fetch_purple_coverage`/
//! `purple_coverage`/`detection_*`). Les deux restent joignables INCHANGÉS via leur ré-export racine
//! (`crate::migrate`/`crate::fetch_purple_coverage` …), consommés ici par `reload_detection_source`/
//! `run_report`.
//!
//! Ré-exporté `pub(crate)` à la racine de crate (`pub(crate) use crate::state::*;`) pour que le
//! `build_router`/`main` de main.rs, TOUS les modules frères (`crate::App`/`crate::settings_get`/
//! `crate::now_epoch`/`crate::resolve_web_dir` …) ET le bloc de tests inline (`super::*`) résolvent ces
//! items INCHANGÉS. Tous les `#[cfg(...)]` préservés VERBATIM (build community par défaut byte-identique).
use crate::*;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, Mutex as AsyncMutex};

// Version produit — SOURCE DE VÉRITÉ UNIQUE : le fichier `VERSION` à la racine du repo, lu à la
// COMPILATION (`include_str!`). Le même fichier alimente le moteur Python (forge/__init__.py) et
// est vérifié en dérive par la CI (`make check-version`). `CARGO_MANIFEST_DIR` = `console/`, donc
// `../VERSION` = la racine. Un `\n` de fin est possible -> trim au point d'usage (forge_version()).
pub(crate) const FORGE_VERSION_RAW: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../VERSION"));

/// Version nettoyée (sans espaces/newline de fin), réutilisable partout (CLI `--version`,
/// JSON `/health`, pied de page de l'UI web). Reste `&'static` (sous-tranche de la const).
pub(crate) fn forge_version() -> &'static str {
    FORGE_VERSION_RAW.trim()
}


/// ENGAGEMENT résolu (vue en mémoire d'une ligne `engagement`) : le scope in/out DÉCODÉ depuis
/// `scope_json`, le `mode` effectif et le `ledger_path` DÉDIÉ. C'est CET objet (jamais les App globals)
/// que le run flow consomme : scope-guard = `scope_in`/`scope_out` de l'engagement (fail-closed),
/// journalisation dans `ledger_path` de l'engagement. Isolation : un run pour l'engagement A ne voit
/// que le scope de A.
#[derive(Clone, Debug)]
pub(crate) struct Engagement {
    pub(crate) id: i64,
    pub(crate) mode: String,
    pub(crate) scope_in: Vec<String>,
    pub(crate) scope_out: Vec<String>,
    pub(crate) ledger_path: String,
    /// POLITIQUE RÉSEAU (privé/LAN/loopback) — opt-in PAR ENGAGEMENT (colonne `engagement.allow_private`).
    /// Défaut FALSE (fail-closed). Une des DEUX portes cumulatives : effectif = master global AND ceci
    /// (calculé dans run_create). Isolation : activer sur l'engagement A n'affecte JAMAIS un autre engagement.
    pub(crate) allow_private: bool,
    /// CONTEXTE D'AUTHENTIFICATION PAR-ENGAGEMENT (R5b) — bloc OPTIONNEL `auth` {accounts, idor_targets}
    /// décodé DEPUIS `scope_json` (validé/canonicalisé par `validate_engagement_scope`). `None` si absent
    /// (=> le run flow N'ÉMET aucun champ `auth` dans le scope.json du moteur => no-op byte-identique). Le
    /// moteur (`session.AuthContext.from_scope`) le lit pour alimenter les oracles IDOR (R5) et ATO (R5b)
    /// en cross-compte. SECRET : porte le matériel d'auth de l'opérateur — jamais journalisé (le moteur le
    /// rédige dans les findings/ledger) ; ne transite que par le scope.json du run (fichier temp local).
    pub(crate) auth: Option<Value>,
}

/// Extrait la liste de chaînes d'un champ tableau d'un scope_json (in_scope/out_scope). Absent/mal
/// formé => vide (fail-closed pour in_scope : un engagement sans in_scope ne lance rien).
pub(crate) fn scope_json_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// Charge un engagement par id : décode `scope_json` (in/out scope) et le `mode` (le `mode` du
/// scope_json prime sur la colonne `mode` s'il est présent — le scope reste la source autoritaire du
/// périmètre). None si l'id n'existe pas. Pure lecture (aucune écriture).
pub(crate) fn load_engagement(store: &crate::store::Store, id: i64) -> Option<Engagement> {
    // allow_private : colonne INTEGER (0/1) ; défaut 0 fail-closed si NULL/illisible (rétro-compat).
    let (mode_col, scope_json, ledger_path, allow_private): (String, String, String, i64) = store
        .query_row(
            "SELECT mode, scope_json, ledger_path, allow_private FROM engagement WHERE id=?",
            &crate::sql_params![id],
            |r| Ok((r.get_str(0)?, r.get_str(1)?, r.get_str(2)?, r.get_opt_i64(3)?.unwrap_or(0))),
        )
        .ok()?;
    let v: Value = serde_json::from_str(&scope_json).unwrap_or_else(|_| json!({}));
    let mode = v
        .get("mode")
        .and_then(|m| m.as_str())
        .map(String::from)
        .unwrap_or(mode_col);
    // CONTEXTE AUTH PAR-ENGAGEMENT (R5b) : le bloc `auth` déjà VALIDÉ/canonicalisé au moment de l'écriture
    // (validate_engagement_scope) est décodé tel quel. Un objet non-vide => Some ; absent/non-objet => None
    // (=> le run flow n'émet aucun `auth` => byte-identique). On ne re-valide PAS ici (source déjà de confiance).
    let auth = match v.get("auth") {
        Some(a) if a.is_object() => Some(a.clone()),
        _ => None,
    };
    Some(Engagement {
        id,
        mode,
        scope_in: scope_json_list(&v, "in_scope"),
        scope_out: scope_json_list(&v, "out_scope"),
        ledger_path,
        allow_private: allow_private != 0,
        auth,
    })
}

/// MASTER SWITCH GLOBAL de la politique réseau (`settings.network.allow_private`). Défaut FALSE
/// (FAIL-CLOSED) : sur une instance fraîche, AUCUN engagement ne peut scanner de cible privée/LAN/loopback.
/// Lu à CHAQUE run (aucun cache) => une bascule admin prend effet IMMÉDIATEMENT, sans redémarrage. C'est
/// le « gros bouton rouge » instance-wide : OFF ⇒ le scan privé est impossible partout, indépendamment de
/// l'opt-in per-engagement. Absent/illisible => False. Truthy = on|1|true|yes (miroir des flags entreprise).
pub(crate) fn network_allow_private(store: &crate::store::Store) -> bool {
    matches!(
        settings_get_store(store, "network.allow_private").as_deref(),
        Some("on") | Some("1") | Some("true") | Some("yes")
    )
}


/// INTENTION OPÉRATEUR de désactiver un connecteur (gouvernance, indépendante de la sonde host) :
/// vrai si `enabled=0` OU `available_override=Some(false)` (override explicite « indisponible »). Un
/// simple binaire absent (probed=0, sans override) N'EST PAS une désactivation opérateur — le moteur
/// le SKIP déjà via sa propre sonde. C'est CE set qu'on refuse dans validate_modules et qu'on injecte
/// dans scope.json `disabled_modules` (pour que le moteur SKIP même un outil PRÉSENT que l'opérateur a
/// désactivé). Fonction PURE (testable, aucun I/O).
pub(crate) fn module_operator_disabled(enabled: bool, available_override: Option<bool>) -> bool {
    !enabled || available_override == Some(false)
}

/// Disponibilité EFFECTIVE d'un connecteur = `enabled AND (available_override ?? probed_available)`.
/// Exposée au front (badge « effectif ») et cohérente avec module_operator_disabled : effective=false
/// dès que l'opérateur désactive (enabled=0 / override=0) OU que la sonde host est négative sans override.
/// Fonction PURE (testable, aucun I/O).
pub(crate) fn module_effectively_available(enabled: bool, available_override: Option<bool>, probed_available: bool) -> bool {
    enabled && available_override.unwrap_or(probed_available)
}

/// Résout le répertoire des assets web statiques (style.css/app.js/fonts/…) de façon robuste,
/// indépendamment du cwd — sans ça, le défaut relatif `"web"` est servi en 0 octet quand la console
/// est lancée hors `console/` (seul index.html survit via include_str!). Ordre de priorité :
///   1) $FORGE_CONSOLE_WEB s'il est posé (override explicite de l'opérateur) ;
///   2) <dir-du-binaire>/web et <dir-du-binaire>/../web (cas `./target/{debug,release}/forge`
///      lancé de n'importe où : les assets sont copiés/symlinkés à côté, ou restent dans console/web) ;
///   3) $FORGE_PKG_DIR/console/web puis ./console/web puis ./web (cas lancé depuis console/ ou la racine) ;
///   4) repli `"web"` (comportement historique, lancé depuis console/).
pub(crate) fn resolve_web_dir() -> String {
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
            // ./console/target/{debug,release}/forge -> remonter au crate console/, puis web/
            // (target/release -> target -> console -> console/web)
            candidates.push(dir.join("..").join("..").join("web"));
            // tolérance si le binaire est une marche plus haut (target/forge)
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
pub(crate) fn load_server_scope(pkg_dir: &str) -> (Vec<String>, String) {
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
            eprintln!("[forge] scope serveur introuvable ({path}) — C2 fail-closed (aucune cible lançable)");
            (vec![], "grey".to_string())
        }
    }
}


/// Évènement SSE diffusé pendant un run (lignes stdout/stderr du moteur + transitions de statut).
#[derive(Clone)]
pub(crate) struct RunEvent {
    pub(crate) run_id: String,
    pub(crate) kind: String, // "log" | "status"
    pub(crate) payload: Value,
}

/// État partagé des runs vivants (C2-light gouverné) — ISOLATION PAR ENGAGEMENT.
/// `current` mappe `engagement_id -> RunHandle` du run VIVANT de CET engagement. Conséquences :
///   - CONCURRENCE INTER-ENGAGEMENT : plusieurs engagements peuvent avoir un run vivant EN MÊME TEMPS
///     (clés distinctes) — démarrer un run pour B pendant qu'un run de A est vivant ne renvoie JAMAIS
///     409 (aucun 409 croisé) ;
///   - FIFO PAR ENGAGEMENT : au plus UN run vivant par engagement — un 2e /api/run sur le MÊME
///     engagement est refusé 409 (refus immédiat, pas de file), jamais sur un autre.
///
/// Le verrou async dans /api/run sérialise la réservation (check `contains_key` -> insert) : la clé
/// étant l'engagement_id, un run n'inspecte ni ne retire JAMAIS le slot d'un autre engagement
/// (isolation par construction). Le `broadcast::Sender` SSE vit hors de ce verrou (clone lock-free dans
/// App.events) pour que les pompes stdout puissent diffuser sans le prendre.
pub(crate) struct RunState {
    pub(crate) current: HashMap<i64, RunHandle>, // engagement_id -> run vivant DE CET engagement (au plus 1)
}

/// Slot d'un run vivant, rangé sous la clé `engagement_id` de `RunState.current`. `run_id` est
/// GLOBAL-unique (traçable, sert de garde anti-course à la libération) ; `pgid` = groupe de process
/// (setsid) pour cancel/watchdog (killpg de tout le sous-arbre).
pub(crate) struct RunHandle {
    pub(crate) run_id: String,
    pub(crate) pgid: i32, // group de process (setsid) -> kill group pour cancel/watchdog
}

#[derive(Clone)]
pub(crate) struct App {
    pub(crate) db: Arc<Mutex<Connection>>,
    pub(crate) db_path: Arc<String>,
    // ENTERPRISE STORE (Postgres, feature `store-postgres`) — POOL de N clients partagé. `store()`
    // CHECKOUT un client libre par Store (tenu pour la vie du Store, rendu au drop) : les opérateurs
    // concurrents tombent sur des slots DIFFÉRENTS -> pas de sérialisation sur un unique client. L'id
    // d'insertion ne dépend plus de la session (`execute_returning_id` -> `RETURNING id` en UN
    // statement), donc n'importe quel client poolé est correct. `Some` UNIQUEMENT si
    // FORGE_ENTERPRISE_STORE=postgres + FORGE_DB_URL et feature compilée ; sinon `None` -> `store()`
    // retombe sur SQLite (build community inchangé). Le champ n'existe QUE sous la feature (struct
    // byte-identique quand OFF). Stage 4 HA : `PgPool` bundle les clients + le DSN (`url`) pour RE-ÉTABLIR
    // un client cassé dans son slot après une coupure — cf. `Store::postgres_reconnectable` /
    // `pg_run_read` (reads: reconnect+retry) / `pg_run_write` (writes/tx: reconnect-for-next-op, no retry).
    #[cfg(feature = "store-postgres")]
    pub(crate) pg: Option<Arc<crate::store::PgPool>>,
    // HA (#10 Wave A — foundation). All THREE fields are PG-only (feature-gated) : HA is only ever engaged
    // on a Postgres store, so the DEFAULT/community build compiles NONE of them (struct byte-identical, like
    // `pg`). Read once at boot (main.rs), then INERT this wave — no consumer gates on leadership yet.
    //   `ha`          = the once-at-boot evaluation of `flags::env_truthy("FORGE_HA") && pg.is_some()` (see
    //                   `ha::ha_enabled`). FAIL-CLOSED at boot if FORGE_HA is truthy on a non-Postgres store.
    //   `instance_id` = this process's identity (FORGE_INSTANCE_ID | hostname | gen_token) — the lease holder key.
    //   `is_leader`   = current lease-held state, refreshed by the heartbeat ticker (ha::heartbeat_loop); read
    //                   by /health. When `ha` is false (single instance) `ha::is_leader` short-circuits to true.
    #[cfg(feature = "store-postgres")]
    pub(crate) ha: bool,
    #[cfg(feature = "store-postgres")]
    pub(crate) instance_id: Arc<String>,
    #[cfg(feature = "store-postgres")]
    pub(crate) is_leader: Arc<AtomicBool>,
    pub(crate) token_sha: Arc<String>,
    pub(crate) token_raw: Arc<String>,          // token bearer EN CLAIR — passé au moteur spawné pour /api/ingest
    pub(crate) user: Arc<String>,
    pub(crate) pass_hash: Arc<String>,          // argon2id ; vide = auth OFF (dev localhost)
    // GATE D'AUTH ENGAGÉE ? — cache recalculé au boot ET à chaque mutation de comptes (create/disable/
    // role-change/delete) pour éviter une requête DB par requête HTTP. `true` dès qu'un hash env est
    // posé (FORGE_CONSOLE_PASS_HASH) OU qu'au moins un compte activé existe en base : la gate s'engage
    // sur l'ÉTAT DB, pas seulement sur l'env (ferme le trou dev-open « comptes en base, env vide »).
    // FAIL-CLOSED : tant qu'un compte activé ou un hash existe, la gate reste engagée.
    pub(crate) auth_required: Arc<AtomicBool>,
    pub(crate) operator_hash: Arc<String>,      // argon2id du rôle OPÉRATEUR (C2) ; vide => FAIL-CLOSED (403 sur tout C2)
    pub(crate) allowed_hosts: Arc<Vec<String>>, // anti-DNS-rebinding
    pub(crate) ledger_path: Arc<String>,        // JSONL du ledger d'engagement (FORGE_CONSOLE_LEDGER)
    pub(crate) pkg_dir: Arc<String>,            // racine du paquet Forge (cwd du spawn `python -m forge.cli`)
    pub(crate) python: Arc<String>,            // interpréteur python (FORGE_PYTHON, défaut python3)
    pub(crate) scope_in: Arc<Vec<String>>,      // in_scope autorisé (recopié dans le scope du run, fail-closed)
    pub(crate) scope_mode: Arc<String>,         // mode du scope (white|grey|black) recopié tel quel
    // DÉTECTION (défensif, purple) : SOURCE de détection CONFIGURABLE (plugin), plus rien de codé en
    // dur. Objet JSON `{kind, endpoint?, auth?:{type,secret}, query?, mapping?}` chargé au boot depuis
    // `settings.detection_source`, avec REPLI rétro-compat sur l'env legacy PLUME_URL/PLUME_TOKEN
    // (traité comme `{kind:plume, endpoint:PLUME_URL, auth:{type:basic,secret:PLUME_TOKEN}}`). `kind`
    // absent/none => couverture en FAIL-OPEN LISIBLE (source_reachable:false, aucune métrique inventée).
    // Le SECRET (auth.secret) n'est JAMAIS renvoyé par un GET, ni journalisé, ni ledgerisé (rédigé).
    // Verrou RW : rechargé (reload_detection_source) après toute mutation de `settings.detection_source`.
    pub(crate) detection_source: Arc<std::sync::RwLock<Arc<Value>>>,
    pub(crate) run_timeout_secs: u64,           // watchdog (FORGE_RUN_TIMEOUT, défaut 1800s)
    pub(crate) run_state: Arc<AsyncMutex<RunState>>,
    /// RÉSERVATIONS de slot FIFO (CONC-1) — engagement_id dont un `run_create` a réservé le slot mais
    /// dont le run n'est PAS encore promu dans `run_state` (fenêtre fs-writes / DB insert / spawn /
    /// ledger). Mutex std SYNCHRONE tenu quelques MICROSECONDES uniquement (jamais à travers un
    /// `.await`) : c'est ce qui permet une libération CANCELLATION-SAFE via un guard RAII `Drop`
    /// (cf. runs.rs::RunReservation) — le slot est libéré sur retour normal, early-return, panic ET
    /// drop du future (déconnexion/annulation à un point d'await), là où une re-lock awaitée fuiterait.
    /// `run_cancel`/`runs_list`/`reconcile_runs`/superviseur n'y touchent JAMAIS (ils opèrent sur
    /// `run_state` = runs VIVANTS) : un slot réservé-non-encore-spawné leur est invisible (aucun
    /// pgid, aucun kill erroné). `Arc<Mutex<..>>` (et non `Mutex` nu) car App est `Clone`/`State<App>`
    /// est cloné par requête : tous les clones DOIVENT partager le MÊME set (sinon réservations perdues).
    pub(crate) run_reservations: Arc<Mutex<std::collections::HashSet<i64>>>,
    pub(crate) events: broadcast::Sender<RunEvent>, // bus SSE lock-free (clone du Sender)
    // Sérialise lecture-head -> calcul -> écriture du ledger JSONL (anti-race : deux appends
    // concurrents liraient le MÊME prev/seq et casseraient la chaîne SHA-256). Cache aussi le head
    // (prev,seq) pour éviter de relire tout le fichier à chaque append (O(n²) -> O(1) amorti).
    pub(crate) ledger_lock: Arc<Mutex<LedgerHead>>,
}

/// Head courant du ledger console (dernier hash + dernière seq), maintenu sous `ledger_lock`.
/// `loaded=false` => pas encore initialisé depuis le disque (lecture paresseuse au 1er append).
#[derive(Default)]
pub(crate) struct LedgerHead {
    pub(crate) prev: String,
    pub(crate) seq: i64,
    pub(crate) loaded: bool,
}

impl App {
    /// Verrouille la connexion SQLite en RÉCUPÉRANT un mutex empoisonné (un panic en section
    /// critique empoisonnait le Mutex et tout `.lock().unwrap()` ultérieur paniquait à son tour ->
    /// DoS API permanent). `into_inner()` reprend la garde : la connexion rusqlite reste utilisable
    /// (une requête échouée renvoie une Err, pas un état mémoire corrompu). Fail-open contrôlé.
    /// SEAM (Stage 2b) : plus AUCUN appelant runtime — tout le chemin de données passe désormais par
    /// `store()` (routé sur le backend ACTIF SQLite/Postgres). `db()` reste UNIQUEMENT pour les tests
    /// (qui verrouillent la connexion SQLite directement) et les carve-outs boot/CLI ; d'où `dead_code`
    /// autorisé dans un build sans tests (même discipline que les helpers `&Connection` `settings_get`/
    /// `upsert_user` conservés pour les tests).
    #[allow(dead_code)]
    pub(crate) fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// PORTABLE DB SEAM (Stage 0) — acquires the SAME `Mutex<Connection>` guard `db()` does and hands
    /// it to a backend-agnostic `Store` (public API leaks no rusqlite type; a Postgres backend
    /// satisfies it at Stage 2 without touching call sites). Holds the lock for the `Store`'s lifetime,
    /// so a sequence of `store.execute/query` runs under ONE lock exactly like `let db = self.db();`
    /// followed by several `db.*` calls — locking granularity and concurrency semantics are unchanged.
    /// Same poisoned-mutex recovery as `db()`. Like `db()`, NEVER hold the returned `Store` across an
    /// `.await` (the guard is `!Send`). Modules migrate from `db()` to `store()` one at a time.
    pub(crate) fn store(&self) -> crate::store::Store<'_> {
        // POSTGRES (feature `store-postgres`) : si un client PG session-pinné est présent, le seam route
        // dessus (même modèle held-guard : on tient le Mutex du client pour la vie du Store). Sinon —
        // et TOUJOURS dans le build community (bloc non compilé) — on retombe sur SQLite, inchangé.
        #[cfg(feature = "store-postgres")]
        if let Some(pg) = self.pg.as_ref() {
            // POOL : on CHECKOUT un client LIBRE parmi les N du pool (guard tenu pour la vie du Store,
            // rendu au drop). Les opérateurs concurrents tombent sur des slots DIFFÉRENTS -> pas de
            // sérialisation sur un unique client. Stage 4 HA : le guard porte aussi le DSN -> reconnect+
            // retry single-shot sur coupure, la reconnexion échange le client frais DANS ce slot.
            let guard = pg.checkout();
            return crate::store::Store::postgres_reconnectable(guard, &pg.url);
        }
        crate::store::Store::sqlite(self.db.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Vrai s'il existe AU MOINS un compte ACTIVÉ (`disabled=0`) dans la table `users`. Requête légère
    /// (`LIMIT 1`). Ne verrouille QUE le mutex DB : ne JAMAIS l'appeler en tenant déjà `self.db()`
    /// (deadlock). Un échec de lecture -> false (l'engagement de la gate retombe alors sur `pass_hash`).
    pub(crate) fn any_enabled_user(&self) -> bool {
        let store = self.store();
        store.query_row("SELECT 1 FROM users WHERE disabled=0 LIMIT 1", &crate::sql_params![], |_| Ok(())).is_ok()
    }

    /// Recalcule et met en cache `auth_required` : la gate d'auth s'engage si un hash d'env est posé
    /// (`FORGE_CONSOLE_PASS_HASH` non vide) OU si au moins un compte activé existe en base. À appeler
    /// au BOOT et après CHAQUE mutation de comptes pour que l'état DB pilote la gate sans requête par
    /// requête. FAIL-CLOSED : on n'ouvre jamais la gate tant qu'un compte activé ou un hash existe.
    /// Ne pas appeler en tenant `self.db()` (any_enabled_user reverrouille le mutex).
    pub(crate) fn recompute_auth_required(&self) {
        let required = !self.pass_hash.is_empty() || self.any_enabled_user();
        self.auth_required.store(required, Ordering::SeqCst);
    }

    /// Lecture O(1) du cache : la gate d'auth est-elle engagée ? (voir recompute_auth_required).
    pub(crate) fn auth_required(&self) -> bool {
        self.auth_required.load(Ordering::SeqCst)
    }

    /// Vrai s'il existe AU MOINS un compte ADMIN activé (`role='admin' AND disabled=0`). Distinct de
    /// any_enabled_user (qui compte TOUT rôle) : le wizard de 1er déploiement considère la console
    /// « provisionnée » dès qu'un ADMIN peut administrer (pas un simple viewer). Requête légère
    /// (`LIMIT 1`). Ne verrouille QUE le mutex DB (ne pas appeler en tenant déjà `self.db()`).
    pub(crate) fn any_enabled_admin(&self) -> bool {
        let store = self.store();
        store.query_row("SELECT 1 FROM users WHERE role='admin' AND disabled=0 LIMIT 1", &crate::sql_params![], |_| Ok(())).is_ok()
    }

    /// La console est-elle déjà PROVISIONNÉE ? Vrai si un admin activé existe en base OU si un hash
    /// d'amorçage env est posé (`FORGE_CONSOLE_PASS_HASH`). Pilote l'auto-désactivation du wizard de
    /// 1er déploiement : `POST /api/setup` se ferme (409) dès que `provisioned()` est vrai. Ne pas
    /// appeler en tenant déjà `self.db()` (any_enabled_admin reverrouille le mutex).
    pub(crate) fn provisioned(&self) -> bool {
        !self.pass_hash.is_empty() || self.any_enabled_admin()
    }

    /// Configuration COURANTE de la source de détection (clone bon-marché de l'`Arc<Value>` en cache).
    /// Récupère un verrou empoisonné (into_inner) : un panic passé ne doit pas geler la lecture purple.
    pub(crate) fn detection_config(&self) -> Arc<Value> {
        self.detection_source.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Recalcule le cache `detection_source` depuis `settings.detection_source` (repli env legacy
    /// PLUME_URL/PLUME_TOKEN si la clé est absente). À appeler au BOOT et après CHAQUE mutation de
    /// `settings.detection_source` (wizard/config admin) pour que la source pilote la couverture sans
    /// relire la table à chaque requête. Ne pas appeler en tenant déjà `self.store()`/`self.db()` (relock
    /// du mutex DB). SEAM (Stage 2b) : lit `settings.detection_source` via `self.store()` -> le backend
    /// ACTIF (SQLite OU Postgres), plus la connexion SQLite brute — le cache de couverture purple reflète
    /// donc la source réellement stockée côté Postgres, sans lecture SQLite en split-brain.
    pub(crate) fn reload_detection_source(&self) {
        let cfg = {
            let store = self.store();
            resolve_detection_source_store(&store)
        };
        let mut w = self.detection_source.write().unwrap_or_else(|e| e.into_inner());
        *w = Arc::new(cfg);
    }

    /// Invalide le cache du head ledger (prev/seq) -> le PROCHAIN `append_console_ledger` relira le
    /// head depuis le disque. À appeler après une mutation du fichier ledger effectuée HORS de
    /// `append_console_ledger` (ex. un restore qui remplace intégralement le ledger par celui de
    /// l'archive) : sans cela, le cache (prev/seq) resterait périmé et le prochain append casserait la
    /// chaîne SHA-256. Récupère un verrou empoisonné (into_inner) : un panic passé ne gèle pas l'audit.
    pub(crate) fn invalidate_ledger_head(&self) {
        let mut head = self.ledger_lock.lock().unwrap_or_else(|e| e.into_inner());
        head.loaded = false;
    }

    /// B6 — CROSS-INSTANCE CACHE INVALIDATION (write side). Bumps the SHARED `settings.cache_epoch` so
    /// peers' `ha::cache_poll_loop` observe the change and reload their local caches (detection_source /
    /// auth_required). Called at each relevant mutation site (detection-source set, user create/disable/
    /// role/delete) AFTER the local reload. GATED on `ha_enabled`: a NO-OP (no write, no behaviour change)
    /// on single-instance / community — the caches only need cross-instance invalidation under HA. Must NOT
    /// be called from the reload fns themselves (the poll calls those; bumping there would ping-pong).
    ///
    /// MONOTONIC COUNTER (not a wall-clock stamp): the epoch is ATOMICALLY INCREMENTED at the DB
    /// (`value = value + 1`) so every mutation STRICTLY increases it. A wall-clock (seconds) stamp would leave
    /// two mutations in the SAME second identical -> a peer polling between them would see no change and stay
    /// stale. The increment is a single UPDATE (the DB serialises concurrent bumps: N -> N+1 -> N+2), so a
    /// peer's next poll ALWAYS observes a different value and reloads. Portable across both backends:
    /// `CAST(CAST(value AS INTEGER)+1 AS TEXT)` are standard-SQL casts SQLite AND Postgres both evaluate
    /// identically (value is a TEXT column holding the integer); seeds at '1' on first bump. Monotonic
    /// regardless of any legacy epoch-seconds value already stored (it just keeps incrementing from there).
    pub(crate) fn bump_cache_epoch(&self) {
        if !crate::ha::ha_enabled(self) {
            return;
        }
        let store = self.store();
        let _ = store.execute(
            // `datetime('now')` is lowered to `CAST(CURRENT_TIMESTAMP AS TEXT)` on PG by the seam. The
            // ON CONFLICT arm increments the EXISTING row's value atomically (single UPDATE, no read-modify-
            // write race). No `?` params: the value is derived server-side from the current row.
            "INSERT INTO settings(key,value,updated) VALUES('cache_epoch','1',datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(settings.value AS INTEGER) + 1 AS TEXT), updated=datetime('now')",
            &crate::sql_params![],
        );
    }

    /// Reads the SHARED `settings.cache_epoch` (0 when unset). The poll compares consecutive reads to detect
    /// a peer's mutation. Fail-soft: any read error => 0 (a benign "no change since 0" — the next real bump
    /// still triggers a reload). PG-only: consumed solely by `ha::cache_poll_loop` (spawned under HA); the
    /// community build has no poll, so this is compiled only under the Postgres backend.
    #[cfg(feature = "store-postgres")]
    pub(crate) fn current_cache_epoch(&self) -> i64 {
        let store = self.store();
        store
            .query_row("SELECT value FROM settings WHERE key='cache_epoch'", &crate::sql_params![], |r| r.get_str(0))
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0)
    }
}

pub(crate) fn gs(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}


// --- settings KV : configuration mutable d'administration (get/set avec horodatage) ---

/// Lit une clé de configuration dans la table `settings`. None si absente ou erreur DB (fail-soft en
/// LECTURE : une clé non provisionnée => valeur par défaut côté appelant, jamais de valeur inventée).
#[allow(dead_code)] // substrat consommé par les routes settings/setup/detection à venir
pub(crate) fn settings_get(db: &Connection, key: &str) -> Option<String> {
    db.query_row("SELECT value FROM settings WHERE key=?", [key], |r| r.get::<_, String>(0)).ok()
}

/// PORTABLE SEAM analogue of [`settings_get`] over `App::store()`. Byte-identical SQL/semantics: a
/// fail-soft LECTURE (absent key or read error -> `None`, never a fabricated value). Runtime callers
/// migrated off `app.db()` use this; the `&Connection` version above remains for tests (which lock the
/// DB directly) and the boot/CLI carve-outs.
pub(crate) fn settings_get_store(store: &crate::store::Store, key: &str) -> Option<String> {
    store
        .query_row("SELECT value FROM settings WHERE key=?", &crate::sql_params![key], |r| r.get_str(0))
        .ok()
}

/// Écrit (upsert) une clé de configuration avec l'horodatage `updated` courant. PRIMARY KEY sur `key`
/// => une seule ligne par clé (pas de doublon). Renvoie une erreur si l'écriture DB échoue (l'appelant
/// admin doit pouvoir la propager avant de ledgeriser). Mutations réservées à check_admin.
#[allow(dead_code)] // substrat consommé par les routes settings/setup/detection à venir
pub(crate) fn settings_set(db: &Connection, key: &str, value: &str) -> Result<(), String> {
    db.execute(
        "INSERT INTO settings(key,value,updated) VALUES(?,?,datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
        rusqlite::params![key, value],
    )
    .map(|_| ())
    .map_err(|e| format!("écriture settings échouée: {e}"))
}

/// PORTABLE SEAM analogue of [`settings_set`] over `App::store()`. Byte-identical SQL/params (verbatim
/// upsert; `datetime('now')` stays on SQLite, is dialect-mapped only on a Postgres backend) and the
/// same error text on failure. Runtime callers use this; the `&Connection` version above stays for
/// tests and the boot/CLI carve-outs.
pub(crate) fn settings_set_store(store: &crate::store::Store, key: &str, value: &str) -> Result<(), String> {
    store
        .execute(
            "INSERT INTO settings(key,value,updated) VALUES(?,?,datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
            &crate::sql_params![key, value],
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
pub(crate) fn session_ttl_secs() -> i64 {
    std::env::var("FORGE_CONSOLE_SESSION_TTL")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(3600) // 1 h par défaut
}

/// Epoch s courant (UTC). Sans dépendance chrono — SystemTime depuis l'UNIX_EPOCH.
pub(crate) fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}


/// Génère un token de session opaque (256 bits hex via CSPRNG OS). Le Result de getrandom est propagé
/// (panic) : un échec d'entropie produirait un token PRÉVISIBLE -> usurpation de session.
pub(crate) fn gen_session_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("CSPRNG (getrandom) indisponible — refus de générer une session faible");
    hex(&b)
}


/// Provisionne un compte dans la table `users` (argon2id). Idempotent vis-à-vis du login : si le login
/// existe déjà, MET À JOUR rôle + hash + réactive (disabled=0). Renvoie le rôle validé ou une erreur.
/// Utilisé par la sous-commande CLI `useradd`. Validation login/role stricte (fail-closed).
pub(crate) fn upsert_user(db: &Connection, login: &str, role: &str, pass_hash: &str) -> Result<String, String> {
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

/// PORTABLE SEAM analogue of [`upsert_user`] over `App::store()`. Same validation (login/role), same
/// verbatim upsert SQL/params and identical error text. Runtime handlers use this; the `&Connection`
/// version above stays for tests and the `console user` CLI carve-out (its own connection).
pub(crate) fn upsert_user_store(store: &crate::store::Store, login: &str, role: &str, pass_hash: &str) -> Result<String, String> {
    let login = validate_login(login)?;
    let role = validate_role(role)?;
    if pass_hash.is_empty() {
        return Err("hash de mot de passe vide".into());
    }
    store
        .execute(
            "INSERT INTO users(login,role,pass_hash,disabled,created)
         VALUES(?,?,?,0,datetime('now'))
         ON CONFLICT(login) DO UPDATE SET role=excluded.role, pass_hash=excluded.pass_hash, disabled=0",
            &crate::sql_params![&login, &role, pass_hash],
        )
        .map_err(|e| format!("écriture users échouée: {e}"))?;
    Ok(role)
}

pub(crate) async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

/// Vérifie le bearer token (sha256). Gate des écritures (ingest, panels).
pub(crate) fn check_token(app: &App, headers: &HeaderMap) -> bool {
    let tok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    ct_eq_str(&sha_hex(tok), &app.token_sha)
}


// ===========================================================================================
// Endpoints de PARITÉ LECTURE / GOUVERNANCE (viewer, aucun spawn armé).
//
// Ces routes exposent la décision de scope, un plan « à blanc » (dry-plan, rien ne tire), le
// rafraîchissement du registre de modules, et le rendu markdown d'un rapport de run. Toutes
// réutilisent les garde-fous existants (host_in_server_scope, validate_*, scope FORCÉ allow_*=false).
// ===========================================================================================

/// L'engagement_id PROPRIÉTAIRE d'un run (run_job.engagement_id), ou None si le run_id est inconnu.
/// SOURCE UNIQUE de la résolution run→engagement pour les gardes de tenancy des routes run-keyed. `run_log`
/// ne PORTE PAS de colonne engagement_id : une lecture de logs résout donc son propriétaire via `run_job`
/// (run_log.run_id == run_job.run_id) — IDENTIQUE au JOIN run_log→run_job ON run_log.run_id=run_job.run_id.
pub(crate) fn owning_engagement_of_run(app: &App, run_id: &str) -> Option<i64> {
    let store = app.store();
    store
        .query_row("SELECT engagement_id FROM run_job WHERE run_id=?", &crate::sql_params![run_id], |r| r.get_i64(0))
        .ok()
}

/// GARDE FAIL-CLOSED (ENTERPRISE, flag-gated) d'une LECTURE run-keyed (detail/report/logs/sse). Résout
/// l'engagement PROPRIÉTAIRE du run (owning_engagement_of_run) et vérifie `tenancy::engagement_visible` —
/// la MÊME helper que `engagement_report` (reports.rs). Community (flag OFF) => retour IMMÉDIAT `None`
/// (aucune requête, comportement mono-tenant BYTE-IDENTIQUE). Enterprise (flag ON) => `Some(404)` quand le
/// run n'est PAS visible du caller : run inconnu (propriétaire None) OU engagement d'un tenant non accordé.
/// 404 — JAMAIS 403 — sur une LECTURE : un run_id cross-tenant est INDISTINGUABLE d'un run inexistant (pas
/// d'oracle d'existence). Les mêmes octets `{"error":"unknown_run"}` que la branche « run inconnu » existante.
pub(crate) fn run_read_denied(app: &App, headers: &HeaderMap, run_id: &str) -> Option<Response> {
    if !crate::tenancy::enabled(app) {
        return None; // community — no-op, byte-identical single-tenant behaviour
    }
    let visible = matches!(
        owning_engagement_of_run(app, run_id),
        Some(eid) if crate::tenancy::engagement_visible(app, headers, eid)
    );
    if visible {
        None
    } else {
        Some((StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"}))).into_response())
    }
}

/// GET /api/runs/:id/report — rend en markdown un rapport d'engagement pour CE run, à partir des
/// données stockées côté console (run_job + findings + roe_decision pour le run_id). Miroir Rust de
/// `forge.report.build_report` (synthèse, findings, transparence ROE). LECTURE (viewer).
/// 404 si le run_id est inconnu de run_job — OU (enterprise) si le run appartient à un tenant non accordé.
pub(crate) async fn run_report(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    // ISOLATION CROSS-TENANT (ENTERPRISE, fail-closed) : le rapport d'un run appartenant à un engagement
    // d'un tenant NON accordé au caller est indisponible -> 404 (mêmes octets que « run inconnu » : ni
    // existence ni données divulguées). No-op en community (engagement_visible => true).
    if let Some(deny) = run_read_denied(&app, &headers, &id) {
        return deny;
    }
    // format : md (DÉFAUT — rétro-compat), html (livrable client brandé), pdf (si outil dispo).
    let format = q.get("format").map(|s| s.as_str()).unwrap_or("md");
    // le run doit exister (sinon 404, comme run_detail). Le verrou DB est confiné dans ce bloc :
    // AUCUN MutexGuard rusqlite (!Send) ne doit survivre à l'await réseau plus bas.
    let (job, fired) = {
        // Verrou DB confiné à ce bloc `store` : il DROPPE avant read_fired_techniques (qui reprend le même
        // Mutex via app.store() -> sinon deadlock). query_row rend Err(NoRows) sur run inconnu -> 404.
        let job = {
            let store = app.store();
            match store.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), &crate::sql_params![&id], run_job_json) {
                Ok(v) => v,
                Err(_) => return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"}))).into_response(),
            }
        };
        // PURPLE : techniques TIRÉES par CE run (red) — lues après relâche du verrou. Le filtre est le
        // `run_id` lui-même (un run appartient à un seul engagement) ; le CONTRÔLE D'ACCÈS cross-tenant
        // n'est PAS assuré par ce filtre mais par la garde `run_read_denied` en tête de handler (ci-dessus).
        let fired = read_fired_techniques(&app, None, Some(("run_id", &id)));
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
                let store = app.store();
                render_run_report_html(&store, &id, &job, Some(&purple), &custody)
            };
            ([("content-type", "text/html; charset=utf-8")], Html(html)).into_response()
        }
        "pdf" => {
            // PDF : depuis le HTML brandé, via un outil système SI présent (pas de dep lourde ajoutée).
            let html = {
                let store = app.store();
                render_run_report_html(&store, &id, &job, Some(&purple), &custody)
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
                let store = app.store();
                render_run_report_md(&store, &id, &job, Some(&purple), Some(&custody))
            };
            (StatusCode::OK, [("content-type", "text/markdown; charset=utf-8")], md).into_response()
        }
    }
}




/// Résout le `ledger_path` de l'engagement PROPRIÉTAIRE d'un run (via run_job.engagement_id ->
/// engagement.ledger_path). Défaut : App.ledger_path (engagement #1 / rétro-compat). ISOLATION : tout
/// acte console lié à un run (cancel, fin de run) est journalisé dans le ledger de SON engagement,
/// jamais celui d'un autre.
pub(crate) fn engagement_ledger_for_run(app: &App, run_id: &str) -> String {
    let store = app.store();
    store
        .query_row(
            "SELECT e.ledger_path FROM run_job j JOIN engagement e ON e.id=j.engagement_id WHERE j.run_id=?",
            &crate::sql_params![run_id],
            |r| r.get_str(0),
        )
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| app.ledger_path.as_str().to_string())
}

/// Journalise un acte de run dans le ledger de SON engagement. Si l'engagement partage le ledger de la
/// console (App.ledger_path = engagement #1), on passe par append_console_ledger (cache de head O(1),
/// chaîne préservée). Sinon on écrit dans le ledger DÉDIÉ de l'engagement via ledger_append_standalone
/// (relecture de head à la volée). Dans les DEUX cas la chaîne SHA-256 reste vérifiable
/// (/api/ledger/verify) et un engagement ne touche JAMAIS le ledger d'un autre.
pub(crate) fn append_run_ledger_path(app: &App, ledger_path: &str, kind: &str, detail: Value) {
    if ledger_path == app.ledger_path.as_str() {
        append_console_ledger(app, kind, detail);
    } else {
        // DEDICATED engagement ledger (a distinct SHARED file). B5: `ledger_append_standalone` already
        // re-reads the tail from disk every call (no cache to invalidate), so wrapping it in the SAME
        // cross-instance advisory lock keyed on THIS path makes the dedicated-ledger append fork-safe under
        // HA. Single-instance (!ha): `with_ledger_lock` is a pass-through -> byte-identical.
        // Fire-and-forget run-ledger helper. A FAIL-CLOSED outage REFUSES the append (logged by
        // `with_ledger_lock`); the run act it records is itself blocked by the same PG outage, so discard the
        // `Result`. Single-instance (!ha): pass-through, always `Ok`, byte-identical.
        let _ = crate::ha::with_ledger_lock(app, ledger_path, || {
            let _ = ledger_append_standalone(ledger_path, kind, &detail);
        });
    }
}

/// Horodatage compact UTC pour les run_id, sans dépendance chrono : YYYYmmddHHMMSS dérivé du temps
/// unix (suffisant pour l'unicité combiné au token aléatoire).
pub(crate) fn chrono_now_compact() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — BOOT SERVEUR + DISPATCH CLI + STORE-GATE (STEP 4 du refactor archi,
//! docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2). PURE MOVE depuis main.rs : `dispatch_cli`, `serve`
//! (~390 l, avec ses blocs `cfg(feature="store-postgres"/"encryption")`), `enterprise_store_gate`
//! et `enum StoreSelection`. Ces items ne consomment que `App` + des helpers déjà re-exportés à la
//! racine de crate ; le déplacement n'ajoute que des `use`. Aucun ordre d'étape, aucun spawn, aucun
//! gating HA, aucun code de sortie CLI, aucun message ne change (binaire release byte-identique).
//! Résolution `crate::*` == l'ancien contexte racine de main.rs (mêmes items, mêmes privés visibles).
use crate::*;

/// Dispatch des sous-commandes CLI (hors chemin HTTP) — PURE EXTRACTION du `match args.get(1)` inline
/// de main() : mêmes sous-commandes, MÊMES codes de sortie, même ordre. Renvoie `Some(exit_code)` si une
/// sous-commande a été prise en charge (l'appelant sort avec ce code) ou `None` pour enchaîner sur le
/// boot serveur. Purement synchrone (aucun await).
pub(crate) fn dispatch_cli(args: &[String]) -> Option<i32> {
    match args.get(1).map(String::as_str) {
        // --version / -V : imprime la version unique (fichier VERSION, include_str! à la compile).
        Some("--version") | Some("-V") => {
            println!("forge {}", forge_version());
            Some(0)
        }
        Some("hashpw") | Some("hashpw-operator") => {
            match args.get(2) {
                Some(pw) if !pw.is_empty() => {
                    println!("{}", hash_pw(pw));
                    Some(0)
                }
                _ => {
                    eprintln!("usage: forge {} <password>", args[1]);
                    Some(2)
                }
            }
        }
        // Parité LECTURE locale (CLI) : lit la MÊME base SQLite que l'API, en READ-ONLY, et
        // imprime en table (défaut) ou JSON (--json). Aucune écriture, aucun spawn — pure lecture.
        Some(cmd @ ("findings" | "roe" | "coverage" | "query")) => {
            Some(run_read_cli(cmd, &args[2..]))
        }
        // Provisioning d'un COMPTE INDIVIDUEL : forge useradd <login> <role> [--pass <pw>]
        //   role ∈ {viewer|operator|admin}. Le mot de passe est lu sur STDIN par défaut (jamais en
        //   argv -> pas de fuite via ps/cmdline) ; `--pass <pw>` est toléré pour le scripting. Le hash
        //   argon2id est calculé ici et stocké dans `users` (idempotent par login : upsert + réactive).
        Some("useradd") => {
            Some(run_useradd_cli(&args[2..]))
        }
        // AMORÇAGE DÉMO : forge seed-demo [--dir <path>] [--campaign <name>]
        //   Charge l'engagement de référence synthétique (examples/reference-engagement/) DIRECTEMENT
        //   dans la base SQLite (hors-ligne, sans réseau, sans /api/ingest) pour qu'une console fraîche
        //   affiche immédiatement Findings/Coverage/Purple/Runs. Idempotent (purge la campagne démo).
        Some("seed-demo") => {
            Some(run_seed_demo_cli(&args[2..]))
        }
        // MIGRATION DE DONNÉES : forge migrate --from <dir|db> --to <db> [--ledger <path>]
        //   [--verify] [--encrypt --key-env <ENVVAR>]. Importe un install Forge existant (non-Docker)
        //   vers une base cible (Docker/autre) : copie DB (VACUUM INTO / SQLCipher), ledger + clé
        //   .ed25519 (0600), puis SCHEMA + migrate() sur la cible. UX primaire = conteneur one-shot.
        Some("migrate") => {
            Some(run_migrate_cli(&args[2..]))
        }
        // MIGRATION DE STORE (feature `store-postgres`) : forge migrate-store --to <postgres-url>
        //   [--from <sqlite-path>] [--dry-run] [--force] [--ledger <path>]. Copie gouvernée SQLite ->
        //   Postgres à travers le seam (ids + typage préservés, ordre FK, recalage IDENTITY, vérif des
        //   comptes, checkpoint ledger signé). Arm ENTIÈREMENT gardé par la feature -> le build community
        //   (défaut) ne la connaît pas (retombe sur le boot serveur), et reste BYTE-IDENTICAL.
        #[cfg(feature = "store-postgres")]
        Some("migrate-store") => {
            Some(crate::cli::run_migrate_store_cli(&args[2..]))
        }
        // SAUVEGARDE CHIFFRÉE : forge backup --out <archive> --passphrase-env <ENVVAR>
        //   [--db <path>] [--ledger <path>]. Archive TOUJOURS chiffrée (argon2id + XChaCha20-Poly1305)
        //   regroupant snapshot DB (VACUUM INTO) + ledger + clé .ed25519 + manifest.json. Passphrase
        //   lue UNIQUEMENT depuis l'ENV (jamais argv). Chaîne ledger vérifiée avant, backup tracé.
        Some("backup") => {
            Some(run_backup_cli(&args[2..]))
        }
        // RESTAURATION CHIFFRÉE : forge restore --in <archive> --passphrase-env <ENVVAR>
        //   [--to <db>] [--ledger <path>] [--force]. Déchiffre (mauvaise passphrase/altération => rien
        //   écrit), vérifie les sha256 du manifest + la chaîne ledger, refuse d'écraser un install non
        //   vide sans --force, place db/ledger/clé (.ed25519 = 0600). Restore tracé au ledger.
        Some("restore") => {
            Some(run_restore_cli(&args[2..]))
        }
        // ROUND-TRIP BLOBSTORE (feature `object-store`) : forge blob-selftest [--key <key>]
        //   [--no-delete]. PUT -> GET -> compare octets -> EXISTS -> (DELETE) sur le store ACTIF (S3/MinIO
        //   si FORGE_BLOB_S3_* configuré, sinon local FORGE_BLOB_DIR). Preuve d'aller-retour sans serveur.
        //   Arm ENTIÈREMENT gardé par la feature -> le build community (défaut) ne le connaît pas.
        #[cfg(feature = "object-store")]
        Some("blob-selftest") => {
            Some(crate::blob::run_blob_selftest_cli(&args[2..]))
        }
        // VÉRIF LEDGER (lecture seule, NON INTERACTIVE, RAPIDE) : forge ledger verify
        //   [--ledger <path>] [--json]. Recompute la chaîne SHA-256 du ledger JSONL et exit immédiat
        //   (0 intègre / 1 rompu-absent / 2 usage). NE démarre PAS le serveur, n'ouvre PAS la base,
        //   ne lit PAS STDIN. La vérif de signature reste côté `forge ledger verify --pubkey` (Python).
        Some("ledger") => {
            Some(run_ledger_cli(&args[2..]))
        }
        // ÉTAT (lecture seule, NON INTERACTIF, RAPIDE) : forge status [--db <path>]
        //   [--ledger <path>] [--json]. Imprime version, VERSION DE SCHÉMA persistée, backend actif,
        //   base RÉDIGÉE, tête de ledger vérifiée — SANS démarrer le serveur. Base d'un upgrade sûr.
        Some("status") => {
            Some(run_status_cli(&args[2..]))
        }
        // UPGRADE SÛR EN UNE COMMANDE (fail-closed avec rollback) : forge upgrade
        //   --passphrase-env <ENV> [--db <path>] [--ledger <path>] [--backup-dir <dir>]
        //   [--to <postgres-url>] [--force] [--dry-run]. Snapshot pré-upgrade CHIFFRÉ (moteur backup
        //   audité) -> migrate additif (+ migration de store si --to) -> vérif schéma/ledger/santé ->
        //   RESTORE (rollback à l'état exact d'avant) sur tout échec. Idempotent ; --dry-run ne mute rien.
        Some("upgrade") => {
            Some(run_upgrade_cli(&args[2..]))
        }
        _ => None,
    }
}

/// Boot du serveur HTTP — PURE EXTRACTION du corps de main() après le dispatch CLI. Sélection du store
/// (gate enterprise), pool PG hors-runtime, gate HA fail-closed, chargement du scope serveur, construction
/// de l'App, amorçage boot routé par le backend ACTIF (SQLite/Postgres), spawns des boucles de fond
/// (heartbeat/leader-tick/cache-poll/présence puis backup-scheduler) puis bind + serve. L'ordre des étapes,
/// l'ordre des spawns et le gating HA sont STRICTEMENT inchangés par rapport à l'ancien main() monolithique.
pub(crate) async fn serve() {
    let db_path = std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge.db".to_string());
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
    // SQLITE CARVE-OUT (connexion brute, backend-specific) : PRAGMA/SCHEMA/migrate/SQLCipher préparent
    // la base SQLite qui devient `App.db` (toujours présente, même en mode Postgres — c'est le fallback
    // du seam). `execute_batch(SCHEMA)+migrate()` est la BRANCHE SQLITE du backend-switch de DDL boot :
    // quand le backend actif sera Postgres, PG_SCHEMA est appliqué EN PLUS via `app.store()` après la
    // construction de l'App (cf. plus bas). L'AMORÇAGE (ensure_default_*/populate_modules/reconcile_runs)
    // ne s'exécute plus ICI : il est routé par le backend ACTIF (`app.store()`), après l'App.
    conn.execute_batch(SCHEMA).expect("schema");
    migrate(&conn); // ALTER additifs error-ignored (run_id, fix, panel étendu, run_job C2, dashboard_id)

    // ENTERPRISE STORE (Postgres) — CÂBLÉ (Stage 2b batch 5). La gate décide le backend ACTIF depuis
    // FORGE_ENTERPRISE_STORE + FORGE_DB_URL : Postgres UNIQUEMENT si la feature `store-postgres` est
    // compilée ET FORGE_DB_URL est posé (sinon erreur claire) ; tout autre cas => SQLite (défaut
    // community inchangé/byte-identique). Le split-brain d'antan n'existe plus : quand PG est actif,
    // TOUT le DML + l'amorçage boot passent par `app.store()` (routé sur le client PG) et le DDL boot
    // applique PG_SCHEMA au lieu de SCHEMA+migrate (cf. bloc AMORÇAGE plus bas). La connexion SQLite
    // ouverte ci-dessus reste le repli du seam (`App.db`), non utilisée quand `App.pg` est `Some`.
    let requested_store = std::env::var("FORGE_ENTERPRISE_STORE").ok();
    let db_url_env = std::env::var("FORGE_DB_URL").ok();
    let store_selection = match enterprise_store_gate(requested_store.as_deref(), db_url_env.as_deref()) {
        Ok(sel) => sel,
        Err(msg) => {
            eprintln!("[forge] FATAL {msg}");
            std::process::exit(2);
        }
    };
    // Connexion PG (feature `store-postgres`) : établie HORS du runtime tokio (le client `postgres`
    // synchrone pilote son PROPRE `block_on` — le connecter depuis le runtime `#[tokio::main]`
    // paniquerait « runtime within a runtime »). On la fait donc sur un `std::thread` dédié, puis on
    // porte le client session-pinné dans `App.pg`. En SQLite (ou build community, bloc non compilé) :
    // `None` -> `store()` retombe sur SQLite.
    #[cfg(feature = "store-postgres")]
    let pg: Option<Arc<crate::store::PgPool>> = match &store_selection {
        StoreSelection::Postgres(url) => {
            let url = url.clone();
            // Taille du pool : FORGE_PG_POOL (défaut 8, borné 1..=64). N clients = N écritures
            // concurrentes non sérialisées au sein d'une instance.
            let pool_size = std::env::var("FORGE_PG_POOL")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n > 0)
                .map(|n| n.min(64))
                .unwrap_or(8);
            let connect_url = url.clone();
            // Connexion HORS du runtime tokio (le client `postgres` synchrone pilote son PROPRE
            // `block_on` — connecter depuis `#[tokio::main]` paniquerait « runtime within a runtime »).
            // On connecte les N clients sur un `std::thread` dédié ; un échec sur l'un est fatal.
            let clients: Vec<crate::store::PgClient> = std::thread::spawn(move || {
                (0..pool_size)
                    .map(|_| crate::store::connect_postgres(&connect_url))
                    .collect::<Result<Vec<_>, _>>()
            })
            .join()
            .expect("postgres connect thread panicked")
            .unwrap_or_else(|e| {
                eprintln!("[forge] FATAL {e}");
                std::process::exit(2);
            });
            println!("[forge] store: Postgres (FORGE_DB_URL) — pool de {pool_size} clients connecté (écritures concurrentes, reconnect+retry HA armé)");
            // Stage 4 HA : le DSN voyage AVEC le pool pour re-établir un client cassé dans son slot après
            // une coupure (restart/failover) — cf. `Store::postgres_reconnectable`.
            Some(Arc::new(crate::store::PgPool::new(url, clients)))
        }
        StoreSelection::Sqlite => None,
    };
    #[cfg(not(feature = "store-postgres"))]
    let _ = &store_selection; // SQLite only (community) — variable consommée pour éviter un warning

    // ================================ HA (#10 Wave A) — OPT-IN + FAIL-CLOSED ================================
    // HA engages ONLY when FORGE_HA is truthy AND the ACTIVE store is Postgres. On a NON-Postgres store a
    // shared leader lease is meaningless (each replica has its own SQLite file) and UNSAFE, so we FAIL CLOSED
    // at boot (clear error + non-zero exit) rather than silently run split-brain. `instance_id` is this
    // process's identity (FORGE_INSTANCE_ID | container hostname | a boot gen_token) — the lease holder key
    // and a per-replica id under `--scale`. Read ONCE here; stored on `App.{ha,instance_id,is_leader}`.
    #[cfg(feature = "store-postgres")]
    let (ha, instance_id) = {
        let want_ha = flags::env_truthy("FORGE_HA");
        if want_ha && pg.is_none() {
            eprintln!("[forge] FATAL FORGE_HA=1 requires FORGE_ENTERPRISE_STORE=postgres — HA is unsafe on SQLite");
            std::process::exit(2);
        }
        let iid = std::env::var("FORGE_INSTANCE_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(gen_token);
        (want_ha && pg.is_some(), iid)
    };
    // Community build (no Postgres backend compiled): HA is impossible. If the operator set FORGE_HA expecting
    // it, FAIL CLOSED with the same guidance rather than silently running a single unsynchronised instance.
    #[cfg(not(feature = "store-postgres"))]
    if flags::env_truthy("FORGE_HA") {
        eprintln!("[forge] FATAL FORGE_HA=1 requires FORGE_ENTERPRISE_STORE=postgres — HA is unsafe on SQLite (this binary has no Postgres backend; rebuild with --features store-postgres)");
        std::process::exit(2);
    }

    // Ingest/console bearer: resolve FORGE_CONSOLE_TOKEN with a `*_FILE` fallback (Docker/k8s secret),
    // then auto-generate an ephemeral token when NEITHER is supplied. An empty/unreadable source is
    // treated as "not provided" (never a silent empty bearer that would leave /api/ingest open).
    let provided_token = secret_from_env("FORGE_CONSOLE_TOKEN");
    let token = provided_token.clone().unwrap_or_else(gen_token);
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
        .unwrap_or(3600); // 1 h — budget réaliste pour un run large (500+ actions). Le watchdog reste un
                          // garde-fou de sûreté, désormais NON destructif : un run tué flushe et conserve
                          // le travail accompli (ingest incrémental) — voir spawn_supervisor + ingest(partial).
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
    // NB: l'amorçage ENGAGEMENT #1 / TENANT #1 (migration ZÉRO-PERTE) est routé par le backend ACTIF via
    // `app.store()` APRÈS la construction de l'App (cf. bloc « AMORÇAGE BOOT »), plus ici sur `conn` brut.
    // racine des assets web statiques (style.css/app.js/fonts/…) servis en fallback.
    let web_dir = resolve_web_dir();
    println!("[forge] web assets: {web_dir}");

    // NE PAS journaliser le token en clair (fuite via logs/journald/historique terminal). On affiche
    // une empreinte courte (8 hex de sha256) — suffisante pour corréler/diagnostiquer sans exposer le
    // secret. Le token en clair reste disponible à l'opérateur via FORGE_CONSOLE_TOKEN (qu'il a posé).
    let token_was_provided = provided_token.is_some();
    let token_fp = &sha_hex(&token)[..8];
    if token_was_provided {
        println!("[forge] ingest token: (fourni via env) fp=sha8:{token_fp}");
    } else {
        // token auto-généré, ÉPHÉMÈRE : on n'imprime QUE l'empreinte (comme la branche env), JAMAIS le
        // secret en clair (fuite via logs/journald/historique terminal). Le moteur spawné le reçoit en
        // mémoire (App.token_raw) — la boucle purple / l'ingest interne fonctionnent sans l'afficher. Pour
        // un `/api/ingest` MANUEL reproductible, l'opérateur POSE `FORGE_CONSOLE_TOKEN=<valeur connue>`
        // (qu'il choisit) et redémarre : la branche « fourni via env » ci-dessus s'appliquera alors.
        println!("[forge] ingest token (auto-généré, éphémère) fp=sha8:{token_fp} — pose FORGE_CONSOLE_TOKEN=<valeur connue> pour le fixer et t'en servir en /api/ingest manuel");
    }
    println!("[forge] db: {db_path}");
    println!("[forge] ledger: {ledger_path}");
    // ÉTAT DB de la gate d'auth : un compte activé en base engage la gate MÊME sans hash env (ferme le
    // trou dev-open historique). On le calcule ici sur `conn` (avant son déplacement dans App) pour un
    // log fidèle ; App.recompute_auth_required() recalcule ensuite le cache faisant autorité.
    let has_enabled_user: bool =
        conn.query_row("SELECT 1 FROM users WHERE disabled=0 LIMIT 1", [], |_| Ok(())).is_ok();
    if pass_hash.is_empty() && !has_enabled_user {
        println!("[forge] AUTH OFF (dev localhost) — ni FORGE_CONSOLE_PASS_HASH ni compte activé en base. `forge useradd <login> admin` (ou pose le hash env) pour engager la gate.");
    } else if pass_hash.is_empty() {
        println!("[forge] auth ON (état DB) — gate engagée par au moins un compte activé (table users) ; connexion via POST /api/login (session individuelle) ; hash env absent");
    } else {
        println!("[forge] auth ON — user={user}, lectures protégées (Basic), écritures par token (comptes individuels via POST /api/login également acceptés)");
    }
    if operator_hash.is_empty() {
        println!("[forge] C2 FAIL-CLOSED — rôle opérateur NON provisionné (FORGE_CONSOLE_OPERATOR_HASH absent) : /api/run* renverra 403. `forge hashpw-operator '...'` pour l'activer.");
    } else {
        println!("[forge] C2 armé — rôle opérateur via en-tête X-Forge-Operator ; cibles ⊆ scope serveur ({} entrée(s)) ; exploit/destructif possibles UNIQUEMENT via opt-in haut-impact gouverné (allow_high_impact + arm + reason, journalisé au ledger) ; scope-guard moteur inchangé (hors-scope = VETO) ; watchdog={run_timeout_secs}s", scope_in.len());
    }

    // (log DÉTECTION déplacé après la construction de l'App + reload_detection_source — la source
    //  n'est connue qu'une fois le cache chargé depuis settings/env.)

    // [SÉCURITÉ XFF] Garde-fou/migration du réglage `trusted_proxy` : il doit désormais contenir le/les
    // CIDR(s) du proxy amont (Traefik/cluster, egress Cloudflare…). Une valeur héritée « truthy » non-CIDR
    // (ex. "1"/"true") ne produit AUCUN CIDR valide -> on n'accorde foi à AUCUN X-Forwarded-For (repli
    // fail-closed sur le pair TCP). On alerte l'opérateur pour qu'il reconfigure explicitement.
    match settings_get(&conn, "trusted_proxy") {
        Some(raw) if !raw.trim().is_empty() && parse_trusted_proxy_cidrs(&raw).is_empty() => {
            eprintln!("[forge] WARN trusted_proxy={raw:?} n'est PAS un CIDR valide — X-Forwarded-For sera IGNORÉ (repli fail-closed sur le pair TCP). Reconfigure `trusted_proxy` sur le(s) CIDR(s) du proxy amont réel (ex. le CIDR Traefik/cluster ou l'egress Cloudflare), sinon la politique opérateur source-CIDR verra l'IP du proxy et jamais celle du client.");
        }
        Some(raw) if !raw.trim().is_empty() => {
            println!("[forge] trusted_proxy: X-Forwarded-For honoré UNIQUEMENT si le pair TCP appartient à {:?}", parse_trusted_proxy_cidrs(&raw));
        }
        _ => {}
    }

    let (events, _) = broadcast::channel::<RunEvent>(1024);
    let app = App {
        db: Arc::new(Mutex::new(conn)),
        db_path: Arc::new(db_path.clone()),
        // ENTERPRISE STORE (Stage 2b batch 5) : `Some(client)` quand PG est sélectionné (gate ci-dessus),
        // sinon `None` -> `store()` route sur SQLite. Le champ n'existe que sous la feature (struct
        // byte-identique quand OFF).
        #[cfg(feature = "store-postgres")]
        pg,
        // HA (#10 Wave A) — computed once above. `is_leader` starts at `!ha` : a single instance (or a
        // non-HA Postgres deploy) is leader immediately; under HA it starts NOT-leader until the first
        // heartbeat acquires the lease (`ha::is_leader` short-circuits to true when `ha` is false anyway).
        #[cfg(feature = "store-postgres")]
        ha,
        #[cfg(feature = "store-postgres")]
        instance_id: Arc::new(instance_id),
        #[cfg(feature = "store-postgres")]
        is_leader: Arc::new(AtomicBool::new(!ha)),
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
        run_state: Arc::new(AsyncMutex::new(RunState { current: HashMap::new() })),
        run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        events,
        ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
    };

    // ========================= AMORÇAGE BOOT (routé par le backend ACTIF) =========================
    // Backend-switch du DDL boot : la BRANCHE SQLITE (execute_batch(SCHEMA)+migrate) a déjà tourné sur
    // la connexion de repli ci-dessus ; si le backend ACTIF est Postgres (`app.pg` = Some), on applique
    // PG_SCHEMA via `app.store()` (routé sur le client PG) — le miroir PG du SCHEMA, colonnes de
    // migrate() déjà fusionnées — À LA PLACE de SCHEMA+migrate pour le backend actif. En SQLite (`app.pg`
    // = None, et build community non compilé) cette branche ne s'exécute pas : SCHEMA+migrate sur la
    // connexion SQLite = App.db font foi. L'amorçage ci-dessous passe ENSUITE par `app.store()` : il sème
    // le backend ACTIF (SQLite = byte-identique ; Postgres via le MÊME chemin seeder, cf. seeders portés).
    // WAVE-B LOW FIX — COLD-START DDL RACE (HA) : sous HA, deux réplicas démarrant un cluster VIERGE lancent
    // `execute_batch(PG_SCHEMA)` + les seeders id=1 (dashboard/engagement/tenant) SIMULTANÉMENT. `CREATE …
    // IF NOT EXISTS` (catalogue PG PARTAGÉ) et `SELECT COUNT(*) … puis INSERT id=1` NE sont PAS concurrency-
    // safe -> un réplica panique (« tuple concurrently updated » sur pg_type/pg_class, ou duplicate key). On
    // SÉRIALISE toute la section DDL+seed sous un `pg_advisory_xact_lock(BOOT_DDL_LOCK_KEY)` cluster-global :
    // un SEUL réplica applique schéma/seeds à la fois, les autres attendent puis voient tout déjà présent
    // (idempotent, aucun panic/abort). `populate_modules` (spawn python, upsert ON CONFLICT row-safe) et le
    // boot-reconcile restent HORS du verrou (aucune course id=1 ; on ne tient pas le verrou pendant un spawn).
    // En SQLite/community : chemin INCHANGÉ (aucun catalogue partagé -> aucun verrou, seeders directs).
    #[cfg(feature = "store-postgres")]
    let pg_active = app.pg.is_some();
    #[cfg(not(feature = "store-postgres"))]
    let pg_active = false;
    if pg_active {
        // PG : PG_SCHEMA + seeders id=1 + recalage des séquences IDENTITY, TOUT sous le verrou DDL cluster-
        // global (pg_advisory_xact_lock, auto-relâché au COMMIT). Le miroir PG du SCHEMA a les colonnes de
        // migrate() déjà fusionnées. Les seeders reçoivent le store TRANSACTIONNEL (tx.store()) -> même
        // connexion, dans le BEGIN, donc dans la section critique verrouillée.
        #[cfg(feature = "store-postgres")]
        app.store()
            .with_tx(|tx| {
                // FIX (isolation assumption): this serialization is correct ONLY under READ COMMITTED — the
                // seam's `with_tx` default isolation. Under READ COMMITTED the SECOND replica, once it wins the
                // advisory lock, re-evaluates its `SELECT COUNT(*)` seeder predicates against the FIRST
                // replica's ALREADY-COMMITTED rows and sees id=1 present -> no re-seed (idempotent). A stricter
                // level (REPEATABLE READ / SERIALIZABLE) would pin the second replica's snapshot at BEGIN,
                // BEFORE the first replica committed, so its COUNT(*) would still read 0 and it would re-INSERT
                // id=1 -> duplicate-key / double-seed. Do NOT raise the isolation of THIS boot tx without
                // moving the seeders to ON CONFLICT DO NOTHING upserts. (Comment only — no behaviour change.)
                tx.execute("SELECT pg_advisory_xact_lock(?)", &crate::sql_params![crate::ha::BOOT_DDL_LOCK_KEY])?;
                tx.execute_batch(PG_SCHEMA)?;
                // `tx.store()` is a getter returning the tx-owned `&Store` (the transaction owns the critical
                // section — there is no separate guard to tighten); call it inline so no aliasing binding is
                // held past its use. Behaviour-identical to a `let s = tx.store();` alias.
                ensure_default_dashboard(tx.store()); // dashboard #1 (rétro-compat) + rattache les panels orphelins
                // ENGAGEMENT #1 / TENANT #1 (migration ZÉRO-PERTE) — idempotents (count>0 => no-op). Sous le
                // verrou, un seul réplica les crée ; l'autre voit count>0 et ne réinsère pas id=1.
                ensure_default_engagement(tx.store(), &app.scope_in, &app.scope_mode, &app.ledger_path);
                ensure_default_tenant(tx.store());
                // Après TOUT seeding à id explicite : recale les séquences IDENTITY sur max(id) (sinon le 1er
                // INSERT-sans-id régénère id=1 -> duplicate key). Idempotent.
                advance_pg_identity_sequences(tx.store());
                // SCHEMA VERSION STAMP (parité avec la branche SQLite où `migrate()` tamponne) : le backend
                // Postgres applique `PG_SCHEMA` (colonnes de migrate déjà fusionnées) sans passer par
                // `migrate()`, donc on tamponne ICI, sous le même verrou DDL, après le schéma+seed.
                crate::schema::stamp_schema_version(tx.store());
                Ok::<(), crate::store::StoreError>(())
            })
            .expect("pg boot schema+seed (serialized under the DDL advisory lock)");
    } else {
        // SQLite (repli du seam) / community : SCHEMA+migrate ont déjà tourné sur la connexion brute ci-dessus.
        // Seeders directs, exactement comme historiquement (byte-identique). advance_pg_identity_sequences est
        // un NO-OP en SQLite (is_postgres()=false).
        ensure_default_dashboard(&app.store());
        ensure_default_engagement(&app.store(), &app.scope_in, &app.scope_mode, &app.ledger_path);
        ensure_default_tenant(&app.store());
        advance_pg_identity_sequences(&app.store());
    }
    // `populate_modules` : INCONDITIONNEL sur CHAQUE instance (upsert idempotent de la table `module`
    // PARTAGÉE, jamais leader-sensible ; hors du verrou DDL car il spawn un process python). En HA les 2
    // réplicas peuplent (upsert ON CONFLICT row-safe). En mono-instance : identique à avant.
    populate_modules(&app.store());
    // OUTILS AJOUTÉS PAR L'UI : re-marque `module.user_added=1` pour les ToolSpecs présents dans le dir
    // server-managed (le re-probe upsert le module mais `user_added` défaute à 0). Idempotent, no-op si
    // aucun outil UI. Garantit que GET/DELETE /api/tools reconnaissent les outils utilisateur après reboot.
    crate::tools::sync_user_added_flags(&app.store());
    // BOOT-RECONCILE (run_job 'running' orphelins d'un crash -> 'failed', killpg des pgid locaux) :
    //   - mono-instance (!ha) : ICI, scope=All (byte-identique au comportement historique) ;
    //   - HA : DIFFÉRÉ au leader-tick (is_leader est FAUX au boot ; cf. runs::leader_tick_loop) — boot-
    //     reconcile OWNER-SCOPÉ des propres orphelins une fois le bail acquis, jamais killpg cross-host.
    if !crate::ha::ha_enabled(&app) {
        reconcile_runs(&app.store(), runs_ha::ReconcileScope::All);
    }

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
            println!("[forge] DÉTECTION OFF — aucune source configurée : /api/detection/coverage (alias /api/purple/coverage) répondra en fail-open lisible (source_reachable:false). Configure `settings.detection_source` (wizard) ou pose PLUME_URL/PLUME_TOKEN (rétro-compat kind=plume).");
        } else {
            // JAMAIS le secret dans le log — kind + endpoint + type d'auth seuls.
            println!("[forge] DÉTECTION armée — kind={kind} endpoint={endpoint} auth={} ; LECTURE seule, joint runrecord[fired] (red) vs détections de la source (blue).",
                ds_auth_type(&cfg));
        }
    }

    // HA (#10 Wave A) — HEARTBEAT : quand HA est engagé (FORGE_HA + store Postgres actif), une tâche
    // périodique renouvelle/acquiert le bail `run-worker` toutes les ~TTL/3 s et publie l'état de
    // leadership sur `App.is_leader` (lu par /health). INERTE cette vague : AUCUN consumer ne gate encore
    // sur is_leader (reconcile/run/scheduler inchangés). Non-HA (single instance) : aucun ticker, is_leader
    // reste true. Cloné AVANT que build_router ne déplace `app`.
    #[cfg(feature = "store-postgres")]
    if app.ha {
        println!(
            "[forge] HA ARMÉ — instance_id={} ; bail scope='run-worker' TTL={}s ; heartbeat toutes les {}s ; leader-tick toutes les {}s (claim pending + reap failover + cancel-watch, leader-only) ; leader/instance_id publiés sur /health.",
            app.instance_id, crate::ha::LEASE_TTL_SECS, crate::ha::HEARTBEAT_TICK_SECS, crate::runs_ha::LEADER_TICK_SECS
        );
        tokio::spawn(crate::ha::heartbeat_loop(app.clone()));
        // RUN-LEADER (Wave B) : le tick du leader draine la file 'pending' (claim + spawn), réape les
        // orphelins des leaders morts (failover) et exécute les cancels observés pour ses runs. Ne fait le
        // travail QUE quand `is_leader` (cf. leader_tick_loop). Cloné AVANT que build_router ne déplace `app`.
        tokio::spawn(crate::runs_ha::leader_tick_loop(app.clone()));
        // CACHE-INVALIDATION CROSS-INSTANCE (Wave C, B6) : chaque réplica poll `settings.cache_epoch` et
        // recharge ses caches locaux (detection_source / auth_required) quand un PAIR l'a bumpé (mutation
        // detection-source / user create-disable-role-delete). Tourne sur CHAQUE instance (pas seulement le
        // leader). Cloné AVANT que build_router ne déplace `app`.
        tokio::spawn(crate::ha::cache_poll_loop(app.clone()));
        // GC PRÉSENCE PÉRIODIQUE (Wave C, write-amplification fix) : la purge des lignes `presence` périmées
        // n'est PLUS faite sur chaque lecture `/api/presence` (amplification proportionnelle au trafic) mais
        // par un DELETE de fond leader-only à la cadence du heartbeat ; le snapshot filtre déjà les périmés
        // sur la lecture (TTL inchangé). Cloné AVANT que build_router ne déplace `app`.
        tokio::spawn(crate::presence::presence_gc_loop(app.clone()));
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
    println!("[forge] http://{addr}");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("serve");
}

/// Backend the console boots on, as decided by [`enterprise_store_gate`]. The `Postgres` arm only
/// exists under the `store-postgres` feature (the DEFAULT build can only ever select SQLite).
#[derive(Debug)]
pub(crate) enum StoreSelection {
    Sqlite,
    #[cfg(feature = "store-postgres")]
    Postgres(String), // the FORGE_DB_URL DSN to connect the session-pinned client to
}

/// Enterprise store-selection gate (Stage 2b batch 5). Decides — from the runtime values of
/// `FORGE_ENTERPRISE_STORE` (`requested`) and `FORGE_DB_URL` (`db_url`) — which backend the console
/// boots on, FAIL-CLOSED:
///   - `requested == Some("postgres")` WITH the `store-postgres` feature compiled: `Ok(Postgres(url))`
///     IFF `FORGE_DB_URL` is set to a non-empty DSN; otherwise `Err` (clear "requires FORGE_DB_URL").
///   - `requested == Some("postgres")` WITHOUT the feature: `Err` telling the operator to rebuild with
///     `--features store-postgres` (the Postgres arm is not compiled into this binary).
///   - Anything else (`None`, `"sqlite"`, `""`, …): `Ok(Sqlite)` — the community default, unchanged.
///
/// Pure over its inputs so the whole contract is unit-testable without touching the environment.
pub(crate) fn enterprise_store_gate(requested: Option<&str>, db_url: Option<&str>) -> Result<StoreSelection, String> {
    if requested == Some("postgres") {
        #[cfg(feature = "store-postgres")]
        {
            return match db_url {
                Some(u) if !u.is_empty() => Ok(StoreSelection::Postgres(u.to_string())),
                _ => Err("FORGE_ENTERPRISE_STORE=postgres requires FORGE_DB_URL to be set to a \
                          postgres:// DSN; refusing to start without it."
                    .to_string()),
            };
        }
        #[cfg(not(feature = "store-postgres"))]
        {
            let _ = db_url; // unused in the community build
            return Err("FORGE_ENTERPRISE_STORE=postgres requires a binary built with the \
                        store-postgres feature; rebuild with --features store-postgres."
                .to_string());
        }
    }
    Ok(StoreSelection::Sqlite)
}

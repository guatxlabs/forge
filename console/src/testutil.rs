// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — HELPERS DE TEST PARTAGÉS (hoistés depuis le `mod tests` inline de main.rs :
//! ils servaient plusieurs sous-systèmes — backup/dbmigrate/cli en plus de main.rs — et sont
//! désormais mutualisés ici plutôt que dupliqués. `#[cfg(test)]` : aucun code émis hors tests.
//! Corps IDENTIQUES à l'original ; seule la visibilité (`pub(crate)`) est ajoutée pour l'accès
//! cross-module. Les modules consommateurs font `use crate::testutil::*` dans leur `mod tests`.
#![cfg(test)]
use crate::*;
use axum::http::HeaderMap;
use rusqlite::Connection;
use serde_json::Value;

    /// Verrou global sérialisant les tests qui LISENT/ÉCRIVENT des variables d'ENV partagées
    /// (FORGE_ALLOW_API_MIGRATE / FORGE_CONSOLE_IMPORT_DIR) — l'ENV du process est global, donc ces
    /// tests ne doivent pas courir en parallèle. Empoisonnement ignoré (into_inner) : un panic
    /// antérieur ne doit pas bloquer les suivants.
    pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Engage l'escape-hatch SSRF (`FORGE_ALLOW_INTERNAL_INTEGRATIONS=1`) UNE SEULE FOIS pour TOUT le
    /// binaire de test (`Once` => pas de course set_var/getenv). Les mocks OIDC des tests SSO bindent
    /// 127.0.0.1 (cibles loopback LÉGITIMEMENT internes) ; la garde d'intégration les refuserait sinon.
    /// On ne l'unset JAMAIS : c'est l'état partagé DÉSIRÉ (aucun test n'attend le refus PAR l'env — le
    /// refus est prouvé par les fonctions PURES `reject_internal_addr`/`integration_ip_denied`). En
    /// production la garde reste pleinement active (ce helper n'existe qu'en `#[cfg(test)]`).
    pub(crate) fn allow_internal_integrations_once() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| std::env::set_var(crate::ALLOW_INTERNAL_INTEGRATIONS_ENV, "1"));
    }

    pub(crate) fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        let uniq = format!("{}-{}-{}", name, std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        p.push(uniq);
        p.to_string_lossy().into_owned()
    }

    /// Crée un dossier temporaire unique.
    pub(crate) fn tmp_dir(name: &str) -> String {
        let d = tmp_path(name);
        std::fs::create_dir_all(&d).expect("mkdir tmp");
        d
    }

    /// Sème une base SOURCE au schéma ANCIEN : `finding` SANS les colonnes additives (cwe/run_id/…),
    /// et PAS de table settings/users. La migration doit l'upgrader EN PLACE (SCHEMA + migrate()).
    pub(crate) fn seed_old_source_db(path: &str) {
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

    /// Récupère l'id d'un compte par login (helper de test).
    pub(crate) fn uid_of(app: &App, login: &str) -> i64 {
        let db = app.db();
        db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
    }

    /// Construit un HeaderMap avec un Authorization: Bearer <tok> (utilisé pour simuler une session).
    pub(crate) fn bearer_headers(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {tok}").parse().unwrap());
        h
    }

    /// Consomme une Response axum et parse son corps JSON (helper de test).
    pub(crate) async fn resp_json(r: Response) -> Value {
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&b).unwrap_or(Value::Null)
    }

// ============================================================================================
// HELPERS DE TEST PARTAGÉS hoistés depuis le `mod tests` de tests.rs (STEP 2a du refactor archi) :
// fixtures cross-test (test_app, http_raw/get_req/post_req, seed_two_tenants, …) mutualisées ici
// avant le découpage de tests.rs en tests_*.rs cohésifs. Corps IDENTIQUES à l'original ; seule la
// visibilité (pub(crate)) est ajoutée pour l'accès cross-fichier. Résolution `crate::*` == l'ancien
// `super::*` (même racine de crate) — aucun import supplémentaire requis.
// ============================================================================================
    /// App minimale pour tester append_console_ledger (ledger sur disque, reste inerte).
    pub(crate) fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(SCHEMA).expect("schema");
        // Le boot serveur enchaîne TOUJOURS SCHEMA puis migrate() (colonnes additives : engagement.tenant_id,
        // engagement.allow_private, run_job.*, …). On applique donc migrate ici aussi pour que l'App de test
        // reflète le schéma de PRODUCTION (idempotent/additif : n'altère aucune colonne existante).
        migrate(&conn);
        let (events, _) = broadcast::channel::<RunEvent>(64);
        App {
            db: Arc::new(Mutex::new(conn)),
            db_path: Arc::new(":memory:".into()),
            #[cfg(feature = "store-postgres")]
            pg: None,
            #[cfg(feature = "store-postgres")]
            ha: false,
            #[cfg(feature = "store-postgres")]
            instance_id: Arc::new("test-instance".into()),
            #[cfg(feature = "store-postgres")]
            is_leader: Arc::new(AtomicBool::new(true)),
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
            run_state: Arc::new(AsyncMutex::new(RunState { current: HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        }
    }


    /// App de test avec un SCOPE SERVEUR non vide (pour les endpoints scope-guardés comme /api/import).
    /// Applique aussi `migrate()` (colonnes additives run_id/cwe/cvss du finding) comme en production —
    /// le boot serveur enchaîne toujours SCHEMA puis migrate ; les INSERT findings en dépendent.
    pub(crate) fn test_app_scoped(ledger_path: &str, scope_in: Vec<String>) -> App {
        let mut a = test_app(ledger_path);
        a.scope_in = Arc::new(scope_in);
        { let db = a.db(); migrate(&db); }
        a
    }

    /// Construit un HeaderMap avec un X-Forge-Operator (repli bootstrap env-hash).
    pub(crate) fn operator_headers(pw: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forge-operator", pw.parse().unwrap());
        h
    }

    /// Compte les sessions d'un user_id (helper de test).
    pub(crate) fn session_count(app: &App, uid: i64) -> i64 {
        let db = app.db();
        db.query_row("SELECT COUNT(*) FROM session WHERE user_id=?", [uid], |r| r.get(0)).unwrap()
    }

    /// Client HTTP brut minimal (aucune dép externe) : envoie `req` et lit toute la réponse jusqu'à EOF
    /// (le serveur ferme la connexion sur `Connection: close`). Suffisant pour tester le câblage réel.
    pub(crate) async fn http_raw(addr: SocketAddr, req: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        s.write_all(req.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.expect("read");
        String::from_utf8_lossy(&buf).into_owned()
    }
    pub(crate) fn get_req(path: &str, extra: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\r\n")
    }
    pub(crate) fn post_req(path: &str, body: &str, extra: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
    }
    pub(crate) fn parse_status(resp: &str) -> u16 {
        resp.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }
    pub(crate) fn body_of(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }
    pub(crate) fn cookie_token(resp: &str) -> Option<String> {
        let head = resp.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(resp);
        let idx = head.find("forge_session=")?;
        let rest = &head[idx + "forge_session=".len()..];
        let end = rest.find(';').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }

    /// Insère un engagement de test (scope_json dérivé de scope_in/mode, out_scope vide).
    pub(crate) fn insert_test_engagement(app: &App, id: i64, scope_in: &[&str], mode: &str, ledger: &str) {
        
        let scope_json = json!({"mode": mode, "in_scope": scope_in, "out_scope": []}).to_string();
        app.db().execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(?,?,'active',?,?,?,datetime('now'),datetime('now'))",
            rusqlite::params![id, format!("eng{id}"), mode, scope_json, ledger],
        )
        .unwrap();
    }

    /// Corps /api/run minimal (campaign + targets + engagement_id optionnel).
    pub(crate) fn run_body(campaign: &str, engagement_id: Option<i64>, targets: &[&str]) -> Value {
        let mut b = json!({"campaign": campaign, "targets": targets, "mode": "propose"});
        if let Some(e) = engagement_id {
            b["engagement_id"] = json!(e);
        }
        b
    }

    /// Query<HashMap> pratique pour cibler un engagement en lecture dans les tests (`?engagement=<id>`).
    pub(crate) fn eng_query(id: i64) -> Query<HashMap<String, String>> {
        Query(HashMap::from([("engagement".to_string(), id.to_string())]))
    }

    /// Engage le flag enterprise via la config par-DB `enterprise.tenancy=on` (isolé par test, pas d'ENV
    /// global). Le comportement community reste le défaut (flag absent).
    pub(crate) fn enable_enterprise_tenancy(app: &App) {
        let db = app.db();
        settings_set(&db, "enterprise.tenancy", "on").unwrap();
    }

    /// Rattache l'engagement `eid` au tenant `tid` (crée la ligne tenant si besoin).
    pub(crate) fn set_engagement_tenant(app: &App, eid: i64, tid: i64) {
        let db = app.db();
        db.execute(
            "INSERT OR IGNORE INTO tenant(id,name,status,created,updated) VALUES(?,?,'active',datetime('now'),datetime('now'))",
            rusqlite::params![tid, format!("tenant{tid}")],
        ).unwrap();
        db.execute("UPDATE engagement SET tenant_id=? WHERE id=?", rusqlite::params![tid, eid]).unwrap();
    }

    /// Accorde à `user_id` l'accès au tenant `tid` (rôle tenant_*).
    pub(crate) fn grant_tenant(app: &App, user_id: i64, tid: i64, role: &str) {
        let db = app.db();
        db.execute(
            "INSERT OR IGNORE INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,?,?,datetime('now'))",
            rusqlite::params![user_id, tid, role],
        ).unwrap();
    }

    /// PER-ENGAGEMENT RBAC (readiness #14) : pose un grant engagement-spécifique (override tenant).
    pub(crate) fn grant_engagement(app: &App, user_id: i64, eid: i64, role: &str) {
        let db = app.db();
        db.execute(
            "INSERT OR REPLACE INTO engagement_grant(user_id,engagement_id,role,created) VALUES(?,?,?,datetime('now'))",
            rusqlite::params![user_id, eid, role],
        ).unwrap();
    }

    /// Sème deux tenants (1,2), deux engagements (#1->tenant1, #2->tenant2), chacun avec un finding/
    /// runrecord/roe/run_job, et deux users (alice->tenant1, bob->tenant2). Retourne (app, alice_headers,
    /// bob_headers, fid_a, fid_b). L'app est en mode ENTERPRISE.
    pub(crate) fn seed_two_tenants(ledger: &str, ledger2: &str) -> (App, HeaderMap, HeaderMap, i64, i64) {
        let app = test_app_scoped(ledger, vec!["a.example.com".into(), "b.example.com".into()]);
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", ledger);  // A
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", ledger2); // B
        set_engagement_tenant(&app, 1, 1);
        set_engagement_tenant(&app, 2, 2);
        {
            let db = app.db();
            upsert_user(&db, "alice", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "bob", "operator", &hash_pw("pw")).unwrap();
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('fa','a.example.com','cA','HIGH',1)", []).unwrap();
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('fb','b.example.com','cB','LOW',2)", []).unwrap();
            db.execute("INSERT INTO runrecord(campaign,target,kind,mitre,fired,engagement_id) VALUES('cA','a.example.com','recon.http','T1190',1,1)", []).unwrap();
            db.execute("INSERT INTO runrecord(campaign,target,kind,mitre,fired,engagement_id) VALUES('cB','b.example.com','recon.http','T1046',1,2)", []).unwrap();
            db.execute("INSERT INTO roe_decision(campaign,run_id,action_id,target,kind,verdict,engagement_id) VALUES('cA','r1','a1','a.example.com','recon.http','FIRE',1)", []).unwrap();
            db.execute("INSERT INTO roe_decision(campaign,run_id,action_id,target,kind,verdict,engagement_id) VALUES('cB','r2','a2','b.example.com','recon.http','VETO',2)", []).unwrap();
            db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('r1','cA','done','propose',1)", []).unwrap();
            db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('r2','cB','done','propose',2)", []).unwrap();
        }
        let (uid_a, uid_b) = (uid_of(&app, "alice"), uid_of(&app, "bob"));
        grant_tenant(&app, uid_a, 1, "tenant_operator");
        grant_tenant(&app, uid_b, 2, "tenant_operator");
        let (atok, _) = create_session(&app, uid_a);
        let (btok, _) = create_session(&app, uid_b);
        let fid_a: i64 = { let db = app.db(); db.query_row("SELECT id FROM finding WHERE title='fa'", [], |r| r.get(0)).unwrap() };
        let fid_b: i64 = { let db = app.db(); db.query_row("SELECT id FROM finding WHERE title='fb'", [], |r| r.get(0)).unwrap() };
        enable_enterprise_tenancy(&app);
        (app, bearer_headers(&atok), bearer_headers(&btok), fid_a, fid_b)
    }

    /// Provisionne un compte `admin` + une session, renvoie ses headers bearer.
    pub(crate) fn admin_session(app: &App, login: &str) -> HeaderMap {
        { let db = app.db(); upsert_user(&db, login, "admin", &hash_pw("pw")).unwrap(); }
        let (tok, _) = create_session(app, uid_of(app, login));
        bearer_headers(&tok)
    }

    /// Désigne le(s) super-admin(s) via la clé de PROVISIONING par-DB `enterprise.superadmin` (isolée par
    /// test, pas d'ENV global). N'est PAS une route UI normale (aucune API n'écrit une clé settings arbitraire).
    pub(crate) fn designate_superadmin(app: &App, csv: &str) {
        let db = app.db();
        settings_set(&db, "enterprise.superadmin", csv).unwrap();
    }

    /// Écrit la config de source de détection dans le cache de l'App (utilitaire de test).
    pub(crate) fn set_detection_source(app: &App, cfg: Value) {
        *app.detection_source.write().unwrap() = Arc::new(cfg);
    }

    /// Serveur HTTP mock (UNE connexion) : renvoie `body` en 200 et retourne la requête reçue (ligne +
    /// en-têtes) pour inspection (ex. vérifier l'en-tête d'auth). Bind éphémère 127.0.0.1:0.
    pub(crate) async fn mock_http_once(body: String) -> (SocketAddr, tokio::task::JoinHandle<String>) {
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

    /// Seed la table `module` d'une App de test avec un module recon (web_allowed) et un module
    /// exploit (haut-impact). Réutilisé par les tests du gate haut-impact.
    pub(crate) fn seed_modules(app: &App) {
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

    pub(crate) fn simple_toolspec() -> Value {
        json!({
            "kind": "custom.echotool", "vuln_class": "Recon", "binary": "echo",
            "argv_template": ["{target}"], "parser": "lines", "hit_status": "tested",
            "severity": "INFO", "description": "echo wrapper (test)"
        })
    }

    pub(crate) fn dir_spec(dir: &str, kind: &str) -> std::path::PathBuf { std::path::Path::new(dir).join(format!("{kind}.json")) }
    pub(crate) fn dir_has_spec(dir: &str, kind: &str) -> bool { dir_spec(dir, kind).is_file() }

    // =============================================================================================
    // SÉLECTION DE TECHNIQUES PAR-SCOPE (profil + toggles catégorie/technique) — validation, persistance,
    // catalogue groupé par catégorie (spawn moteur), endpoint gouverné (opérateur/admin) + ledgerisé.
    // =============================================================================================

    pub(crate) fn conn_info() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:5555".parse().unwrap())
    }

    /// Aplati {groups:{cat:[{kind,enabled_for_current_scope}]}} en une map kind -> activé.
    pub(crate) fn flatten_enabled(body: &Value) -> std::collections::HashMap<String, bool> {
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


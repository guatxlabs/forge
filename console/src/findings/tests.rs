// SPDX-License-Identifier: AGPL-3.0-or-later
//! `findings` — module de test EXTRAIT (PURE MOVE depuis `console/src/findings.rs`).
//! Corps IDENTIQUE ; ENFANT de `findings`, il voit donc toujours ses items privés.
use super::*;

    use super::*;
    use crate::{create_session, hash_pw, read_ledger_lines, upsert_user, LedgerHead, RunEvent, RunState};
    use rusqlite::Connection;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    fn tmp_ledger(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "forge-fbulk-{}-{}-{}.jsonl",
            tag,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        p.to_string_lossy().into_owned()
    }

    fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        crate::migrate(&conn);
        let (events, _) = broadcast::channel::<RunEvent>(64);
        App {
            db: Arc::new(Mutex::new(conn)),
            #[cfg(feature = "store-postgres")]
            pg: None,
            #[cfg(feature = "store-postgres")]
            ha: false,
            #[cfg(feature = "store-postgres")]
            instance_id: Arc::new("test-instance".into()),
            #[cfg(feature = "store-postgres")]
            is_leader: Arc::new(AtomicBool::new(true)),
            db_path: Arc::new(":memory:".into()),
            token_sha: Arc::new(crate::sha_hex("t")),
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
            run_state: Arc::new(AsyncMutex::new(RunState { current: std::collections::HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        }
    }

    fn seed_engagement(app: &App, id: i64, name: &str) {
        let db = app.db();
        db.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(?,?, 'active','grey','{}','',datetime('now'),datetime('now'))",
            rusqlite::params![id, name],
        )
        .unwrap();
    }
    /// Insère un finding dans un engagement donné, renvoie son id.
    fn seed_finding(app: &App, eid: i64, title: &str, status: &str) -> i64 {
        let db = app.db();
        db.execute(
            "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,engagement_id)
             VALUES(datetime('now'),'c','t.example',?,'HIGH','','T1',?,'','','',?)",
            rusqlite::params![title, status, eid],
        )
        .unwrap();
        db.last_insert_rowid()
    }
    fn bearer(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {tok}").parse().unwrap());
        h
    }
    fn uid_of(app: &App, login: &str) -> i64 {
        let db = app.db();
        db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
    }
    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:9".parse().unwrap())
    }
    fn noq() -> Query<HashMap<String, String>> {
        Query(HashMap::new())
    }
    async fn to_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn to_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }
    fn status_of(app: &App, id: i64) -> String {
        let db = app.db();
        db.query_row("SELECT status FROM finding WHERE id=?", [id], |r| r.get(0)).unwrap()
    }
    fn seed_roles(app: &App) -> (String, String) {
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
        }
        let (v, _) = create_session(app, uid_of(app, "vv"));
        let (o, _) = create_session(app, uid_of(app, "oo"));
        (v, o)
    }

    /// FINDING UPDATE — INJECTION D'ÉCHEC : un TRIGGER `BEFORE UPDATE ... RAISE(ABORT)` fait ÉCHOUER
    /// l'écriture (les SELECT d'existence passent). Le handler DOIT alors : (a) renvoyer 500 typé
    /// `db_write_failed` (PAS un faux `ok:true`), (b) N'ÉCRIRE AUCUNE entrée au ledger (anti divergence
    /// ledger↔DB — la piste tamper-evident ne doit jamais attester une mutation qui n'a pas eu lieu),
    /// (c) laisser le finding INTOUCHÉ. Régression directe du bug audité (write avalé -> faux 200 + ledger).
    #[tokio::test]
    async fn finding_update_db_failure_500_and_no_ledger() {
        let led = tmp_ledger("upd-fail");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);
        // Injecte un échec d'ÉCRITURE : tout UPDATE de finding est ABORTé (les lectures restent OK).
        {
            let db = app.db();
            db.execute_batch("CREATE TRIGGER t_block_upd BEFORE UPDATE ON finding BEGIN SELECT RAISE(ABORT,'boom'); END;")
                .unwrap();
        }
        let before = read_ledger_lines(&led).len();
        let r = finding_update(State(app.clone()), peer(), bearer(&otok), Path(f1),
            Query(HashMap::from([("engagement".into(), "1".into())])),
            Json(json!({"status": "confirmed", "classification": "GREEN"}))).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR, "écriture échouée -> 500");
        let b = to_json(r).await;
        assert_eq!(b["error"], "db_write_failed", "erreur typée (enveloppe existante)");
        assert_eq!(status_of(&app, f1), "new", "aucune mutation appliquée (état intouché)");
        assert_eq!(read_ledger_lines(&led).len(), before, "un échec d'écriture NE ledgerise PAS");
        let _ = std::fs::remove_file(&led);
    }

    // -------------------------------------------------------------------------------------------
    //  KEYSET / CURSOR PAGINATION (#P1-4) — seek pour très gros sets, offset intact
    // -------------------------------------------------------------------------------------------

    /// Petit helper : lit la liste d'ids d'une page de findings.
    fn ids_of(b: &Value) -> Vec<i64> {
        b["findings"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect()
    }

    /// (a) COUVERTURE : paginer TOUT le set via `?cursor` rend CHAQUE ligne EXACTEMENT une fois, dans le
    /// même ordre que le set complet trié (`id DESC`) — zéro trou, zéro doublon — et `next_cursor` devient
    /// null à la fin.
    #[tokio::test]
    async fn keyset_full_coverage_no_gaps_no_dupes() {
        let led = tmp_ledger("ks-cov");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let mut all: Vec<i64> = Vec::new();
        for i in 0..25 {
            all.push(seed_finding(&app, 1, &format!("f{i}"), "new"));
        }
        all.sort_unstable();
        let expected: Vec<i64> = all.iter().rev().cloned().collect(); // id DESC = ordre de référence

        let mut got: Vec<i64> = Vec::new();
        // Première page : `cursor=""` (vide) entre en mode keyset depuis le haut.
        let mut cursor: String = String::new();
        let mut guard = 0;
        loop {
            guard += 1;
            assert!(guard < 100, "boucle de pagination non bornée");
            let qp = HashMap::from([
                ("engagement".to_string(), "1".to_string()),
                ("limit".to_string(), "7".to_string()),
                ("cursor".to_string(), cursor.clone()),
            ]);
            let resp = findings(State(app.clone()), HeaderMap::new(), Query(qp)).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let b = to_json(resp).await;
            let page = ids_of(&b);
            assert!(page.len() <= 7, "la page respecte le limit");
            got.extend(page);
            match b["next_cursor"].as_str() {
                Some(c) => cursor = c.to_string(),
                None => break,
            }
        }
        assert_eq!(got, expected, "keyset couvre chaque ligne exactement une fois, dans l'ordre id DESC");
        let mut uniq = got.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), got.len(), "aucun doublon sur l'ensemble des pages");
        let _ = std::fs::remove_file(&led);
    }

    /// (b) STABILITÉ SOUS INSERT CONCURRENT : après avoir lu la page 1, insérer de NOUVELLES lignes (ids
    /// plus grands) NE fait PAS sauter/dupliquer les lignes d'origine via keyset — alors que le chemin
    /// OFFSET, lui, DÉRAILLE (fenêtre décalée -> skip + dupe).
    #[tokio::test]
    async fn keyset_stable_under_concurrent_insert() {
        let led = tmp_ledger("ks-conc");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let mut orig: Vec<i64> = Vec::new();
        for i in 0..10 {
            orig.push(seed_finding(&app, 1, &format!("o{i}"), "new"));
        }

        // Page 1 (limit 5, `cursor=""` -> mode keyset depuis le haut) — le client voit les 5 ids les plus hauts.
        let q1 = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("limit".to_string(), "5".to_string()),
            ("cursor".to_string(), String::new()),
        ]));
        let b1 = to_json(findings(State(app.clone()), HeaderMap::new(), q1).await).await;
        let p1 = ids_of(&b1);
        assert_eq!(p1.len(), 5);
        let cur = b1["next_cursor"].as_str().expect("page pleine -> next_cursor présent").to_string();

        // Insert concurrent de 3 lignes (ids strictement plus grands que tous les orig).
        for i in 0..3 {
            seed_finding(&app, 1, &format!("n{i}"), "new");
        }

        // Page 2 via CURSEUR — reprend STRICTEMENT après la position, insensible aux inserts.
        let mut q2m = HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("limit".to_string(), "5".to_string()),
        ]);
        q2m.insert("cursor".to_string(), cur);
        let b2 = to_json(findings(State(app.clone()), HeaderMap::new(), Query(q2m)).await).await;
        let p2 = ids_of(&b2);

        let mut seen = p1.clone();
        seen.extend(p2.iter().cloned());
        let mut seen_sorted = seen.clone();
        seen_sorted.sort_unstable();
        let mut orig_sorted = orig.clone();
        orig_sorted.sort_unstable();
        assert_eq!(seen_sorted, orig_sorted, "keyset : les 10 lignes d'origine couvertes exactement une fois malgré les inserts");
        let mut u = seen.clone();
        u.sort_unstable();
        u.dedup();
        assert_eq!(u.len(), seen.len(), "keyset : aucun doublon sous insert concurrent");

        // CONTRASTE : OFFSET page 2 (offset=5) APRÈS les inserts déraille (skip + dupe) -> union != orig.
        let qo = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("limit".to_string(), "5".to_string()),
            ("offset".to_string(), "5".to_string()),
        ]));
        let bo = to_json(findings(State(app.clone()), HeaderMap::new(), qo).await).await;
        let po = ids_of(&bo);
        let mut off_union = p1.clone();
        off_union.extend(po.iter().cloned());
        off_union.sort_unstable();
        assert_ne!(off_union, orig_sorted, "OFFSET saute/duplique sous insert concurrent (ce que keyset évite)");
        let _ = std::fs::remove_file(&led);
    }

    /// (c) FAIL-CLOSED : un curseur/after_id malformé -> 400 `bad_cursor` (JAMAIS un scan complet). Un
    /// curseur VALIDE et un `after_id` entier restent 200.
    #[tokio::test]
    async fn keyset_malformed_cursor_is_400() {
        use base64::Engine as _;
        let led = tmp_ledger("ks-bad");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let id = seed_finding(&app, 1, "f", "new");

        let enc = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        // base64 invalide, mauvaise version, entier non parsable, pas de préfixe, entier vide.
        let bads = vec![
            "****not-base64****".to_string(),
            enc("f2:5"),
            enc("f1:abc"),
            enc("nope"),
            enc("f1:"),
        ];
        for bad in &bads {
            let q = Query(HashMap::from([
                ("engagement".to_string(), "1".to_string()),
                ("cursor".to_string(), bad.clone()),
            ]));
            let resp = findings(State(app.clone()), HeaderMap::new(), q).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "curseur malformé '{bad}' -> 400");
            let b = to_json(resp).await;
            assert_eq!(b["error"], "bad_cursor");
        }
        // after_id non entier -> 400 également.
        let q = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("after_id".to_string(), "not-an-int".to_string()),
        ]));
        assert_eq!(findings(State(app.clone()), HeaderMap::new(), q).await.status(), StatusCode::BAD_REQUEST);

        // Curseur VALIDE (encode l'id existant + 1 pour capter la ligne) -> 200 + la ligne.
        let good = super::encode_id_cursor(id + 1);
        let q = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("cursor".to_string(), good),
        ]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(ids_of(&b), vec![id], "curseur valide -> seek correct");

        // after_id entier -> 200.
        let q = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("after_id".to_string(), (id + 1).to_string()),
        ]));
        assert_eq!(findings(State(app.clone()), HeaderMap::new(), q).await.status(), StatusCode::OK);
        let _ = std::fs::remove_file(&led);
    }

    /// (d) OFFSET INCHANGÉ : sans cursor/after_id, la forme de réponse reste `{total,limit,offset,findings}`
    /// (avec `offset`, SANS `next_cursor`) — compat ascendante byte-identique. Le chemin keyset, lui, expose
    /// `next_cursor` et PAS `offset`.
    #[tokio::test]
    async fn offset_path_shape_unchanged() {
        let led = tmp_ledger("ks-off");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        for i in 0..3 {
            seed_finding(&app, 1, &format!("f{i}"), "new");
        }
        // Chemin OFFSET (par défaut) : garde `offset`, PAS de `next_cursor`.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert!(b.get("offset").is_some(), "offset path conserve `offset`");
        assert!(b.get("next_cursor").is_none(), "offset path n'ajoute PAS `next_cursor`");
        assert_eq!(b["findings"].as_array().unwrap().len(), 3);

        // Chemin KEYSET : expose `next_cursor` (clé présente, ici null car page partielle), PAS `offset`.
        let q = Query(HashMap::from([
            ("engagement".to_string(), "1".to_string()),
            ("after_id".to_string(), "999999".to_string()),
        ]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert!(b.get("next_cursor").is_some(), "keyset path expose la clé `next_cursor`");
        assert!(b["next_cursor"].is_null(), "page partielle -> next_cursor null");
        assert!(b.get("offset").is_none(), "keyset path n'expose PAS `offset`");
        let _ = std::fs::remove_file(&led);
    }

    /// BOUND engagement_id — le filtre d'isolation `engagement_id=?` LIÉ (Param) rend EXACTEMENT les mêmes
    /// résultats que l'ancien `engagement_id={eid}` inliné : la liste `findings` d'un engagement ne contient
    /// QUE ses propres findings (aucun cross-engagement), et `finding_detail` 404 un id d'un AUTRE engagement.
    /// Prouve la neutralité comportementale de la conversion valeur-interpolée -> valeur-liée (Tâche B).
    #[tokio::test]
    async fn engagement_id_binding_isolates_identically() {
        let led = tmp_ledger("eid-bind");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let a1 = seed_finding(&app, 1, "a1", "new");
        let _a2 = seed_finding(&app, 1, "a2", "new");
        let b1 = seed_finding(&app, 2, "b1", "new");

        // liste engagement 1 -> exactement SES 2 findings, aucun de l'engagement 2.
        let q1 = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let body = to_json(findings(State(app.clone()), HeaderMap::new(), q1).await).await;
        assert_eq!(body["total"], 2, "engagement 1 voit ses 2 findings (bound eid)");
        let titles: Vec<String> = body["findings"].as_array().unwrap().iter()
            .map(|f| f["title"].as_str().unwrap_or("").to_string()).collect();
        assert!(titles.contains(&"a1".to_string()) && titles.contains(&"a2".to_string()), "ses findings présents");
        assert!(!titles.contains(&"b1".to_string()), "AUCUN finding cross-engagement (isolation liée)");

        // detail : b1 (engagement 2) est INVISIBLE depuis l'engagement 1 -> 404 via engagement_id=? lié.
        let q1b = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let r = finding_detail(State(app.clone()), HeaderMap::new(), Path(b1), q1b).await.into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "id d'un AUTRE engagement -> 404 (isolation liée)");
        // detail : a1 (engagement 1) est VISIBLE depuis l'engagement 1.
        let q1c = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let r = finding_detail(State(app.clone()), HeaderMap::new(), Path(a1), q1c).await.into_response();
        assert_eq!(r.status(), StatusCode::OK, "propre finding visible (bound eid)");
        let _ = std::fs::remove_file(&led);
    }

    // -------------------------------------------------------------------------------------------
    //  OWNERSHIP (P1-4) — assign / bulk-assign : grant-scopé, isolé par engagement, ledgerisé
    // -------------------------------------------------------------------------------------------

    fn assignee_of(app: &App, id: i64) -> Option<i64> {
        let db = app.db();
        db.query_row("SELECT assignee FROM finding WHERE id=?", [id], |r| r.get::<_, Option<i64>>(0)).unwrap()
    }
    fn seed_user(app: &App, login: &str, role: &str) -> i64 {
        {
            let db = app.db();
            upsert_user(&db, login, role, &hash_pw("pw")).unwrap();
        }
        uid_of(app, login)
    }
    fn q_eng(eid: &str) -> Query<HashMap<String, String>> {
        Query(HashMap::from([("engagement".to_string(), eid.to_string())]))
    }

    /// ASSIGN (community) : operator assigne un finding à un user (persistance colonne + ledger
    /// `console.finding.assign`), puis DÉSASSIGNE (assignee:null). Viewer -> 403 (aucune mutation).
    #[tokio::test]
    async fn assign_persists_unassign_and_ledgered() {
        let led = tmp_ledger("assign");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (vtok, otok) = seed_roles(&app);
        let bob = seed_user(&app, "bob", "viewer");

        // viewer -> 403, aucune mutation.
        let r = finding_assign(State(app.clone()), peer(), bearer(&vtok), Path(f1), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(assignee_of(&app, f1), None, "403 ne mute rien");

        // operator assigne à bob.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        assert_eq!(b["assignee"], bob);
        assert_eq!(assignee_of(&app, f1), Some(bob), "assignation persistée");
        let last = read_ledger_lines(&led).pop().unwrap();
        assert_eq!(last["kind"], "console.finding.assign");
        assert_eq!(last["detail"]["assignee"], bob);
        assert_eq!(last["detail"]["finding_id"], f1);

        // détail : assignee + login résolu.
        let d = finding_detail(State(app.clone()), HeaderMap::new(), Path(f1), q_eng("1")).await.into_response();
        let dj = to_json(d).await;
        assert_eq!(dj["assignee"], bob);
        assert_eq!(dj["assignee_login"], "bob");

        // désassignation (null).
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": null}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(assignee_of(&app, f1), None, "désassigné");
        let _ = std::fs::remove_file(&led);
    }

    /// ASSIGN : champ absent -> 400 ; assigné inconnu -> 400 (aucune mutation).
    #[tokio::test]
    async fn assign_bad_and_unknown_user_400() {
        let led = tmp_ledger("assign-bad");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);

        // champ 'assignee' absent -> 400.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        // user inexistant -> 400, aucune mutation.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": 99999}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(assignee_of(&app, f1), None, "assigné inconnu ne mute rien");
        let _ = std::fs::remove_file(&led);
    }

    /// ASSIGN : ISOLATION — un finding d'un AUTRE engagement -> 404 (jamais assigné, pas de cross-engagement).
    #[tokio::test]
    async fn assign_cross_engagement_is_404() {
        let led = tmp_ledger("assign-xeng");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let fx = seed_finding(&app, 2, "fx", "new"); // AUTRE engagement
        let (_v, otok) = seed_roles(&app);
        let bob = seed_user(&app, "bob", "viewer");

        // engagement actif #1, cible fx (#2) -> 404, intouché.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(fx), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "id d'un AUTRE engagement -> 404");
        assert_eq!(assignee_of(&app, fx), None, "finding cross-engagement INTOUCHÉ");
        let _ = std::fs::remove_file(&led);
    }

    /// ASSIGN — INJECTION D'ÉCHEC : trigger BEFORE UPDATE ABORT -> 500 `db_write_failed`, AUCUN ledger,
    /// finding intouché (régression anti write-avalé).
    #[tokio::test]
    async fn assign_db_failure_500_and_no_ledger() {
        let led = tmp_ledger("assign-fail");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);
        let bob = seed_user(&app, "bob", "viewer");
        {
            let db = app.db();
            db.execute_batch("CREATE TRIGGER t_block_upd BEFORE UPDATE ON finding BEGIN SELECT RAISE(ABORT,'boom'); END;")
                .unwrap();
        }
        let before = read_ledger_lines(&led).len();
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(to_json(r).await["error"], "db_write_failed");
        assert_eq!(assignee_of(&app, f1), None, "aucune mutation");
        assert_eq!(read_ledger_lines(&led).len(), before, "un échec d'écriture NE ledgerise PAS");
        let _ = std::fs::remove_file(&led);
    }

    /// FILTER : `?assignee=<uid>` rend les findings de ce propriétaire ; `?assignee=unassigned` rend les
    /// non assignés — chacun le bon sous-ensemble.
    #[tokio::test]
    async fn filter_by_assignee() {
        let led = tmp_ledger("filter-assignee");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let f2 = seed_finding(&app, 1, "f2", "new");
        let _f3 = seed_finding(&app, 1, "f3", "new"); // reste non assigné
        let (_v, otok) = seed_roles(&app);
        let bob = seed_user(&app, "bob", "viewer");

        // assigne f1 et f2 à bob.
        for f in [f1, f2] {
            let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f), q_eng("1"),
                Json(json!({"assignee": bob}))).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        // filtre par bob -> f1,f2.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("assignee".to_string(), bob.to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        let ids: Vec<i64> = b["findings"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert_eq!(b["total"], 2);
        assert!(ids.contains(&f1) && ids.contains(&f2) && !ids.contains(&_f3), "filtre owner exact");
        // filtre unassigned -> seulement f3.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("assignee".to_string(), "unassigned".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(b["total"], 1, "un seul non assigné");
        assert_eq!(b["findings"][0]["id"], _f3);
        let _ = std::fs::remove_file(&led);
    }

    fn seed_tenant_grant(app: &App, uid: i64, tid: i64, role: &str) {
        let db = app.db();
        db.execute(
            "INSERT INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,?,?,datetime('now'))",
            rusqlite::params![uid, tid, role],
        )
        .unwrap();
    }

    /// ENTERPRISE (tenancy ON) : GRANT-SCOPÉ DES DEUX CÔTÉS. L'appelant operator (grant tenant) peut assigner
    /// à un user QUI A un grant sur l'engagement, mais est REJETÉ (403) pour un user SANS grant. Prouve que
    /// `resolve_assignee` gate l'assigné sur l'engagement (on n'assigne qu'à quelqu'un réellement dessus).
    #[tokio::test]
    async fn assign_grant_scoped_enterprise() {
        let led = tmp_ledger("assign-ent");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A"); // tenant_id défaut = 1
        let f1 = seed_finding(&app, 1, "f1", "new");
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
        }
        // caller operator (rôle global operator + grant tenant_operator sur tenant 1 => voit+opère eng 1).
        let (_v, otok) = seed_roles(&app);
        seed_tenant_grant(&app, uid_of(&app, "oo"), 1, "tenant_operator");
        // assigné AVEC grant sur le tenant 1.
        let insider = seed_user(&app, "insider", "viewer");
        seed_tenant_grant(&app, insider, 1, "tenant_viewer");
        // assigné SANS aucun grant.
        let outsider = seed_user(&app, "outsider", "viewer");

        // assigné hors-grant -> 403, aucune mutation.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": outsider}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "assigné sans grant sur l'engagement -> 403");
        assert_eq!(assignee_of(&app, f1), None, "hors-grant ne mute rien");

        // assigné avec grant -> OK.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": insider}))).await;
        assert_eq!(r.status(), StatusCode::OK, "assigné avec grant sur l'engagement -> OK");
        assert_eq!(assignee_of(&app, f1), Some(insider));
        let _ = std::fs::remove_file(&led);
    }

    /// ENTERPRISE : un operator SANS grant sur l'engagement ne peut PAS assigner (can_operate_engagement
    /// fail-closed -> 403), même s'il est operator global.
    #[tokio::test]
    async fn assign_caller_without_engagement_grant_403() {
        let led = tmp_ledger("assign-nocaller");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
        }
        let (_v, otok) = seed_roles(&app); // operator global, MAIS aucun grant tenant/engagement
        let bob = seed_user(&app, "bob", "viewer");
        seed_tenant_grant(&app, bob, 1, "tenant_viewer");

        // sans grant, l'engagement #1 n'est même pas visible -> 404 (isolation) plutôt que d'exposer.
        let r = finding_assign(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"assignee": bob}))).await;
        assert!(
            r.status() == StatusCode::NOT_FOUND || r.status() == StatusCode::FORBIDDEN,
            "operator sans grant sur l'engagement ne peut pas assigner (404/403 fail-closed), got {}",
            r.status()
        );
        assert_eq!(assignee_of(&app, f1), None, "aucune mutation");
        let _ = std::fs::remove_file(&led);
    }

    /// M5 — SSE `finding_events` SCOPÉ PAR TENANT (fuite de métadonnées cross-tenant fermée). Le filtre
    /// `finding_event_visible_for` ne forwarde un event de triage que si son `engagement` est visible au
    /// caller. Community (tenancy off) => tout passe (no-op). Enterprise => un caller granté SEULEMENT sur le
    /// tenant A NE reçoit PAS les events du tenant B (from/to/by/finding_id d'un autre tenant jamais divulgués).
    #[tokio::test]
    async fn finding_events_scoped_per_tenant() {
        let led = tmp_ledger("sse-scope");
        let app = test_app(&led);
        // engagement 1 => tenant 1 (défaut) ; engagement 2 => tenant 2 (explicite).
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        {
            let db = app.db();
            db.execute("UPDATE engagement SET tenant_id=2 WHERE id=2", []).unwrap();
        }
        let (vtok, otok) = seed_roles(&app);
        let ho = bearer(&otok);
        // operator granté UNIQUEMENT sur le tenant 1.
        seed_tenant_grant(&app, uid_of(&app, "oo"), 1, "tenant_operator");

        let ev_a = json!({"finding_id": 10, "from": "new", "to": "triaging", "engagement": 1, "by": "oo"});
        let ev_b = json!({"finding_id": 20, "from": "new", "to": "confirmed", "engagement": 2, "by": "mallory"});

        // COMMUNITY (tenancy off) : les deux events passent (no-op, byte-identique single-tenant).
        assert!(finding_event_visible_for(&app, &ho, &ev_a), "community forwarde tenant 1");
        assert!(finding_event_visible_for(&app, &ho, &ev_b), "community forwarde tenant 2 (no-op)");

        // ENTERPRISE (tenancy on) : seul le tenant 1 (visible) passe ; le tenant 2 est DROPPÉ.
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
        }
        assert!(finding_event_visible_for(&app, &ho, &ev_a), "tenant granté (A) reçoit ses propres events");
        assert!(!finding_event_visible_for(&app, &ho, &ev_b), "tenant NON granté (B) ne fuit PAS cross-tenant");

        // Payload sans `engagement` => fail-closed (droppé).
        assert!(!finding_event_visible_for(&app, &ho, &json!({"finding_id": 30, "to": "triaging"})),
            "payload sans engagement -> droppé (fail-closed)");

        // Un caller SANS aucun grant (viewer vv) ne voit RIEN (deny-by-default).
        let hv = bearer(&vtok);
        assert!(!finding_event_visible_for(&app, &hv, &ev_a), "sans grant -> aucun event visible");
        assert!(!finding_event_visible_for(&app, &hv, &ev_b), "sans grant -> aucun event visible");
        let _ = std::fs::remove_file(&led);
    }

    /// ASSIGNABLE (community) : liste les users actifs assignables + NE DEADLOCK PAS (le handler calcule
    /// tenancy::enabled AVANT de tenir le guard `store`, sinon reprise réentrante du Mutex -> figé).
    #[tokio::test]
    async fn assignable_lists_users_no_deadlock() {
        let led = tmp_ledger("assignable");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_user(&app, "bob", "viewer");
        seed_user(&app, "carol", "viewer");
        let r = findings_assignable(State(app.clone()), HeaderMap::new(), q_eng("1")).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        let logins: Vec<String> = b["users"].as_array().unwrap().iter().map(|u| u["login"].as_str().unwrap().to_string()).collect();
        assert!(logins.contains(&"bob".to_string()) && logins.contains(&"carol".to_string()), "users assignables listés");
        let _ = std::fs::remove_file(&led);
    }

    // -------------------------------------------------------------------------------------------
    //  TRIAGE WORKFLOW — machine à états gouvernée : transition légale (persist + ledger + SSE),
    //  transition illégale (409, aucune écriture), isolation, write-failure, indépendance vs `status`.
    // -------------------------------------------------------------------------------------------

    fn triage_of(app: &App, id: i64) -> String {
        let db = app.db();
        db.query_row("SELECT triage FROM finding WHERE id=?", [id], |r| r.get::<_, Option<String>>(0))
            .unwrap()
            .unwrap_or_default()
    }
    /// Force l'état de triage EN BASE (bypass matrice) — SEEDING pour tester des transitions depuis un état
    /// arbitraire. N'utilise PAS l'API (donc pas de validation) : uniquement pour préparer les fixtures.
    fn set_triage(app: &App, id: i64, state: &str) {
        let db = app.db();
        db.execute("UPDATE finding SET triage=? WHERE id=?", rusqlite::params![state, id]).unwrap();
    }

    /// PURE : la matrice fermée autorise EXACTEMENT les transitions spécifiées, rien d'autre (fail-closed).
    #[test]
    fn triage_matrix_is_closed() {
        assert!(triage_allows("new", "triaging"));
        assert!(triage_allows("new", "false_positive"));
        assert!(triage_allows("new", "duplicate"));
        assert!(triage_allows("triaging", "confirmed"));
        assert!(triage_allows("confirmed", "resolved"));
        assert!(triage_allows("confirmed", "false_positive"));
        assert!(triage_allows("false_positive", "triaging"));
        assert!(triage_allows("duplicate", "triaging"));
        assert!(triage_allows("resolved", "reopened"));
        assert!(triage_allows("reopened", "triaging"));
        assert!(triage_allows("reopened", "confirmed"));
        assert!(triage_allows("reopened", "resolved"));
        // Rejets représentatifs (fail-closed) :
        assert!(!triage_allows("new", "resolved"), "raccourci interdit");
        assert!(!triage_allows("new", "confirmed"), "saut d'étape interdit");
        assert!(!triage_allows("resolved", "confirmed"), "resolved -> confirmed interdit");
        assert!(!triage_allows("confirmed", "duplicate"), "confirmed -> duplicate interdit");
        assert!(!triage_allows("new", "new"), "self-transition interdite");
        assert!(!triage_allows("bogus", "triaging"), "état inconnu -> aucune transition");
    }

    /// LEGAL (community) : operator transitionne new -> triaging. Persistance colonne `triage`, `status` de
    /// PREUVE INCHANGÉ (indépendance), ledger `console.finding.triage` {from,to}, ET event SSE sur le bus.
    /// Viewer -> 403 (aucune mutation).
    #[tokio::test]
    async fn triage_legal_persists_ledgered_and_sse() {
        let led = tmp_ledger("triage-ok");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "triaged"); // status de PREUVE = "triaged"
        let (vtok, otok) = seed_roles(&app);

        // viewer -> 403, aucune mutation.
        let r = finding_triage(State(app.clone()), peer(), bearer(&vtok), Path(f1), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(triage_of(&app, f1), "new", "403 ne mute rien");

        // s'abonne au bus AVANT la transition (broadcast : seuls les messages postérieurs sont reçus).
        let mut rx = app.events.subscribe();

        // operator : new -> triaging.
        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = to_json(r).await;
        assert_eq!(b["from"], "new");
        assert_eq!(b["to"], "triaging");
        assert_eq!(triage_of(&app, f1), "triaging", "triage persisté");
        assert_eq!(status_of(&app, f1), "triaged", "le status de PREUVE est INDÉPENDANT — jamais touché");

        // ledger : console.finding.triage {from:new, to:triaging}.
        let last = read_ledger_lines(&led).pop().unwrap();
        assert_eq!(last["kind"], "console.finding.triage");
        assert_eq!(last["detail"]["from"], "new");
        assert_eq!(last["detail"]["to"], "triaging");
        assert_eq!(last["detail"]["finding_id"], f1);

        // event SSE émis sur le bus (topic FINDINGS_TOPIC, kind finding.triage).
        let ev = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await
            .expect("event SSE reçu avant timeout").expect("event SSE valide");
        assert_eq!(ev.run_id, FINDINGS_TOPIC);
        assert_eq!(ev.kind, "finding.triage");
        assert_eq!(ev.payload["to"], "triaging");
        assert_eq!(ev.payload["finding_id"], f1);

        // détail : triage exposé.
        let d = finding_detail(State(app.clone()), HeaderMap::new(), Path(f1), q_eng("1")).await.into_response();
        assert_eq!(to_json(d).await["triage"], "triaging");
        let _ = std::fs::remove_file(&led);
    }

    /// ILLEGAL : new -> resolved (hors matrice) -> 409, AUCUNE écriture, AUCUN ledger. La réponse rappelle
    /// l'état courant + les états atteignables (guidage). Le `status` de PREUVE reste intact.
    #[tokio::test]
    async fn triage_illegal_409_no_write_no_ledger() {
        let led = tmp_ledger("triage-illegal");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);
        let before = read_ledger_lines(&led).len();

        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "resolved"}))).await;
        assert_eq!(r.status(), StatusCode::CONFLICT, "transition illégale -> 409");
        let b = to_json(r).await;
        assert_eq!(b["error"], "illegal_transition");
        assert_eq!(b["current"], "new");
        let allowed: Vec<String> = b["allowed"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(allowed.contains(&"triaging".to_string()) && !allowed.contains(&"resolved".to_string()), "états atteignables rappelés");
        assert_eq!(triage_of(&app, f1), "new", "409 ne mute rien");
        assert_eq!(read_ledger_lines(&led).len(), before, "une transition illégale NE ledgerise PAS");
        let _ = std::fs::remove_file(&led);
    }

    /// BAD TARGET : `to` absent -> 400 ; `to` hors vocabulaire -> 400 (aucune mutation, aucun ledger).
    #[tokio::test]
    async fn triage_bad_target_400() {
        let led = tmp_ledger("triage-bad");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);

        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "'to' absent -> 400");
        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "bogus"}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "'to' hors vocabulaire -> 400");
        assert_eq!(triage_of(&app, f1), "new", "aucune mutation");
        let _ = std::fs::remove_file(&led);
    }

    /// ISOLATION : un finding d'un AUTRE engagement -> 404 (jamais transitionné, pas de cross-engagement).
    #[tokio::test]
    async fn triage_cross_engagement_404() {
        let led = tmp_ledger("triage-xeng");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        let fx = seed_finding(&app, 2, "fx", "new"); // AUTRE engagement
        let (_v, otok) = seed_roles(&app);

        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(fx), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "id d'un AUTRE engagement -> 404");
        assert_eq!(triage_of(&app, fx), "new", "finding cross-engagement INTOUCHÉ");
        let _ = std::fs::remove_file(&led);
    }

    /// INJECTION D'ÉCHEC : trigger BEFORE UPDATE ABORT -> 500 `db_write_failed`, AUCUN ledger, triage intouché.
    #[tokio::test]
    async fn triage_db_failure_500_and_no_ledger() {
        let led = tmp_ledger("triage-fail");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let (_v, otok) = seed_roles(&app);
        {
            let db = app.db();
            db.execute_batch("CREATE TRIGGER t_block_upd BEFORE UPDATE ON finding BEGIN SELECT RAISE(ABORT,'boom'); END;").unwrap();
        }
        let before = read_ledger_lines(&led).len();
        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(to_json(r).await["error"], "db_write_failed");
        assert_eq!(triage_of(&app, f1), "new", "aucune mutation");
        assert_eq!(read_ledger_lines(&led).len(), before, "un échec d'écriture NE ledgerise PAS");
        let _ = std::fs::remove_file(&led);
    }

    /// FILTER : `?triage=<state>` rend EXACTEMENT le sous-ensemble dans cet état. Valeur bornée en Param.
    #[tokio::test]
    async fn filter_by_triage() {
        let led = tmp_ledger("filter-triage");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        let f2 = seed_finding(&app, 1, "f2", "new");
        let _f3 = seed_finding(&app, 1, "f3", "new"); // reste 'new'
        let (_v, otok) = seed_roles(&app);
        for f in [f1, f2] {
            let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f), q_eng("1"),
                Json(json!({"to": "triaging"}))).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        // filtre triaging -> f1,f2.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("triage".to_string(), "triaging".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(b["total"], 2);
        let ids: Vec<i64> = b["findings"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert!(ids.contains(&f1) && ids.contains(&f2) && !ids.contains(&_f3), "filtre triage exact");
        // filtre new -> seulement f3.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("triage".to_string(), "new".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(b["total"], 1);
        assert_eq!(b["findings"][0]["id"], _f3);
        // valeur hors vocabulaire -> filtre IGNORÉ (best-effort) : tous les findings.
        let q = Query(HashMap::from([("engagement".to_string(), "1".to_string()), ("triage".to_string(), "bogus".to_string())]));
        let b = to_json(findings(State(app.clone()), HeaderMap::new(), q).await).await;
        assert_eq!(b["total"], 3, "valeur invalide -> filtre ignoré (aucune injection, aucun 500)");
        let _ = std::fs::remove_file(&led);
    }

    /// MIGRATE additif + idempotent : les findings existants héritent de `triage='new'` (DEFAULT backfill) ;
    /// rejouer `migrate()` ne panique pas et la colonne reste présente/valide.
    #[test]
    fn triage_migrate_default_new_and_idempotent() {
        let led = tmp_ledger("triage-migrate");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new"); // inséré sans `triage` -> DEFAULT 'new'
        assert_eq!(triage_of(&app, f1), "new", "finding existant backfillé à 'new'");
        // rejouer migrate (idempotent : ADD COLUMN error-ignored) -> pas de panic, colonne toujours là.
        {
            let db = app.db();
            crate::migrate(&db);
            crate::migrate(&db);
        }
        assert_eq!(triage_of(&app, f1), "new", "triage préservé après re-migration");
        let _ = std::fs::remove_file(&led);
    }

    /// ENTERPRISE (tenancy ON) : un operator SANS grant sur l'engagement ne peut PAS transitionner (fail-closed
    /// : l'engagement n'est même pas visible -> 404/403), et le finding reste intouché.
    #[tokio::test]
    async fn triage_caller_without_engagement_grant_denied() {
        let led = tmp_ledger("triage-nocaller");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        let f1 = seed_finding(&app, 1, "f1", "new");
        {
            let db = app.db();
            crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
        }
        let (_v, otok) = seed_roles(&app); // operator global, MAIS aucun grant tenant/engagement
        let r = finding_triage(State(app.clone()), peer(), bearer(&otok), Path(f1), q_eng("1"),
            Json(json!({"to": "triaging"}))).await;
        assert!(
            r.status() == StatusCode::NOT_FOUND || r.status() == StatusCode::FORBIDDEN,
            "operator sans grant sur l'engagement ne peut pas transitionner (404/403 fail-closed), got {}",
            r.status()
        );
        assert_eq!(triage_of(&app, f1), "new", "aucune mutation");
        let _ = std::fs::remove_file(&led);
    }

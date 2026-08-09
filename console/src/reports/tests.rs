// SPDX-License-Identifier: AGPL-3.0-or-later
//! `reports` — module de test EXTRAIT (PURE MOVE depuis `console/src/reports.rs`).
//! Corps IDENTIQUE ; ENFANT de `reports`, il voit donc toujours ses items privés.
use super::*;

    use super::*;
    use crate::{create_session, hash_pw, read_ledger_lines, upsert_user, LedgerHead, RunEvent, RunState};
    use rusqlite::Connection;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    const S_AWS: &str = "AKIAIOSFODNN7EXAMPLE";
    const S_PWD: &str = "Sup3rSecretValue123";
    const S_JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKLmnop";

    fn tmp_ledger(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "forge-rep-{}-{}-{}.jsonl",
            tag,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        p.push(uniq);
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
             VALUES(?,?, 'active','grey','{\"in_scope\":[\"a.example.com\"]}','',datetime('now'),datetime('now'))",
            rusqlite::params![id, name],
        )
        .unwrap();
    }

    /// Insère un finding dans un engagement. `evidence` peut porter des secrets (test de rédaction).
    fn seed_finding(app: &App, eid: i64, title: &str, target: &str, sev: &str, evidence: &str) {
        let db = app.db();
        db.execute(
            "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score,engagement_id)
             VALUES(datetime('now'),'camp',?,?,?,'idor','T1190','vulnerable',?,'oracle.idor','','Contrôle accès','','CWE-639','',0,?)",
            rusqlite::params![target, title, sev, evidence, eid],
        )
        .unwrap();
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
    fn seed_roles(app: &App) -> (String, String, String) {
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let (v, _) = create_session(app, uid_of(app, "vv"));
        let (o, _) = create_session(app, uid_of(app, "oo"));
        let (a, _) = create_session(app, uid_of(app, "aa"));
        (v, o, a)
    }

    async fn to_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn to_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Une BORNE franchie ne doit renvoyer AUCUN conseil d'installation — ni dans `why`, ni dans `hint`,
    /// ni ailleurs dans le corps. On cherche la RACINE « install » (couvre installez/installer/install)
    /// et les gestionnaires de paquets courants, sur le corps ENTIER : c'est ce que dit la phrase, donc
    /// c'est ce qui doit être vérifié (l'assertion précédente ne testait qu'un préfixe de `hint`).
    fn assert_no_install_advice(body: &Value) {
        let txt = format!("{body}").to_lowercase();
        for needle in ["install", "apt-get", "apt ", "pip ", "brew "] {
            assert!(
                !txt.contains(needle),
                "une borne franchie ne doit JAMAIS conseiller une installation (« {needle} ») : {body}"
            );
        }
    }

    /// La rédaction Rust neutralise les mêmes formes de secrets que le générateur Python.
    #[test]
    fn redaction_neutralizes_known_secrets() {
        let text = format!("k {S_AWS} password={S_PWD} h Authorization: Bearer {S_JWT}");
        let red = redact_secrets(&text);
        for s in [S_AWS, S_PWD, S_JWT] {
            assert!(!red.contains(s), "secret non rédigé: {s}");
        }
        assert!(red.contains(crate::redact::REDACT));
        // idempotent
        assert_eq!(redact_secrets(&red), red);
        // texte anodin conservé (URL, domaine, mot 'author')
        let benign = "voir https://a.example.com/orders author:john sur a.example.com";
        assert_eq!(redact_secrets(benign), benign);
    }

    /// ISOLATION : le rapport JSON de l'engagement A ne contient QUE les findings de A (jamais B).
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn report_is_engagement_isolated() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("iso");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_engagement(&app, 2, "eng-B");
        seed_finding(&app, 1, "A-finding", "a.example.com", "HIGH", "rien");
        seed_finding(&app, 2, "B-finding", "b.example.com", "CRITICAL", "rien");
        let (vtok, _o, _a) = seed_roles(&app);

        let mut q = HashMap::new();
        q.insert("format".to_string(), "json".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q.clone())).await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = to_json(r).await;
        let titles: Vec<String> = body["findings"].as_array().unwrap().iter()
            .map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(titles.contains(&"A-finding".to_string()), "le finding de A est présent");
        assert!(!titles.iter().any(|t| t == "B-finding"), "AUCUN finding de B (isolation)");
        // sérialisation entière : rien de B ne fuit.
        let whole = serde_json::to_string(&body).unwrap();
        assert!(!whole.contains("B-finding"));
        assert!(!whole.contains("b.example.com"));
        assert_eq!(body["summary"]["total"], 1);
        let _ = std::fs::remove_file(&led);
    }

    /// ENTERPRISE (flag-gated) — ISOLATION TENANT : le rapport d'un engagement d'un tenant NON accordé au
    /// caller est refusé (404, mêmes octets que « inconnu ») ; aucune donnée de l'autre tenant ne fuit.
    /// Community (flag OFF) => no-op : le même rapport est servi normalement (byte-identique).
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn report_tenant_isolation_fail_closed() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("tnc");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_engagement(&app, 2, "eng-B");
        seed_finding(&app, 2, "B-secret-finding", "b.example.com", "CRITICAL", "rien");
        // engagement #2 -> tenant 2 ; alice (viewer) accordée UNIQUEMENT au tenant 1.
        {
            let db = app.db();
            db.execute("UPDATE engagement SET tenant_id=2 WHERE id=2", []).unwrap();
            upsert_user(&db, "alice", "viewer", &hash_pw("pw")).unwrap();
            db.execute(
                "INSERT INTO tenant_grant(user_id,tenant_id,role,created)
                 SELECT id,1,'tenant_viewer',datetime('now') FROM users WHERE login='alice'",
                [],
            ).unwrap();
            crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
            drop(db);
        }
        let (atok, _) = create_session(&app, uid_of(&app, "alice"));
        let mut q = HashMap::new();
        q.insert("format".to_string(), "json".to_string());

        // ENTERPRISE ON : rapport de B (tenant 2) par alice (tenant 1) -> 404 (fail-closed).
        let r = engagement_report(State(app.clone()), bearer(&atok), Path(2), Query(q.clone())).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "rapport cross-tenant refusé (404)");
        let body = to_json(r).await;
        assert!(!serde_json::to_string(&body).unwrap().contains("B-secret-finding"), "aucune donnée de B ne fuit");

        // COMMUNITY (flag OFF) : le MÊME appel est servi (no-op — comportement mono-tenant historique).
        { let db = app.db(); db.execute("DELETE FROM settings WHERE key='enterprise.tenancy'", []).unwrap(); }
        let r = engagement_report(State(app.clone()), bearer(&atok), Path(2), Query(q)).await;
        assert_eq!(r.status(), StatusCode::OK, "community (flag OFF) : rapport servi (no-op)");

        let _ = std::fs::remove_file(&led);
    }

    /// RÉDACTION : les secrets d'un finding sont masqués dans HTML, CSV et JSON.
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn secrets_redacted_in_html_csv_json() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("redact");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        let evidence = format!("leak {S_AWS} and password={S_PWD} hdr Authorization: Bearer {S_JWT}");
        seed_finding(&app, 1, "leaky", "a.example.com", "HIGH", &evidence);
        let (vtok, _o, _a) = seed_roles(&app);

        for fmt in ["html", "csv", "json"] {
            let mut q = HashMap::new();
            q.insert("format".to_string(), fmt.to_string());
            let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
            assert_eq!(r.status(), StatusCode::OK, "{fmt}");
            let body = to_text(r).await;
            for s in [S_AWS, S_PWD, S_JWT] {
                assert!(!body.contains(s), "{fmt}: secret '{s}' non rédigé");
            }
            assert!(body.contains(crate::redact::REDACT), "{fmt}: marqueur de rédaction attendu");
        }
        let _ = std::fs::remove_file(&led);
    }

    /// RÔLE : sous auth engagée, l'anonyme est refusé (403) et le viewer autorisé (200) ; la génération
    /// est LEDGERISÉE (console.report.generate, attribuée) et le ledger ne contient AUCUN secret.
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn role_gated_and_ledgered() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("role");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        let evidence = format!("password={S_PWD}");
        seed_finding(&app, 1, "f1", "a.example.com", "HIGH", &evidence);
        let (vtok, _o, _a) = seed_roles(&app);
        app.recompute_auth_required(); // comptes créés -> auth engagée

        // anonyme (aucun header) -> 403, rien de ledgerisé.
        let mut q = HashMap::new();
        q.insert("format".to_string(), "json".to_string());
        let r = engagement_report(State(app.clone()), HeaderMap::new(), Path(1), Query(q.clone())).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "anonyme refusé quand l'auth est engagée");
        assert!(read_ledger_lines(&led).is_empty(), "un 403 ne ledgerise rien");

        // viewer -> 200 + ledger attribué.
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        assert_eq!(r.status(), StatusCode::OK, "viewer autorisé (viewer+)");
        let entries = read_ledger_lines(&led);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.report.generate");
        assert_eq!(last["detail"]["actor"], "vv", "attribué au viewer acteur");
        assert_eq!(last["detail"]["engagement_id"], 1);
        assert_eq!(last["detail"]["format"], "json");
        // le ledger NE contient JAMAIS de secret.
        let whole = serde_json::to_string(&entries).unwrap();
        assert!(!whole.contains(S_PWD), "secret fuité dans le ledger");
        let _ = std::fs::remove_file(&led);
    }

    /// [S6 — CWE-1236] Le CSV d'engagement est LE livrable que le client ouvre dans un TABLEUR. Un `title`
    /// vient de la sortie des scanners (donc influençable par la cible) : s'il commence par `=`, `+`, `-`,
    /// `@`, une TABULATION ou un RETOUR CHARIOT, il doit ressortir NEUTRALISÉ (préfixe `'`) — même garde
    /// que l'export bulk des findings (`common::csv_field`, l'unique implémentation côté Rust).
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn csv_export_neutralizes_spreadsheet_formula_injection() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("csvinj");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        let payloads = ["=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\tTAB", "\rCR"];
        for p in payloads {
            seed_finding(&app, 1, p, "a.example.com", "HIGH", "preuve");
        }
        let (vtok, _o, _a) = seed_roles(&app);
        let mut q = HashMap::new();
        q.insert("format".to_string(), "csv".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let csv = to_text(r).await;
        for p in payloads {
            assert!(
                csv.contains(&format!("\"'{p}\"")),
                "titre {:?} non neutralisé dans le CSV d'engagement",
                p
            );
        }
        let _ = std::fs::remove_file(&led);
    }

    /// [S6 — CWE-1236] ANTI-DÉRIVE INTER-LANGAGES. Le rapport d'engagement en CSV a DEUX générateurs :
    /// celui-ci (Rust, `render_csv` via `common::csv_field`) et `forge/report_engagement.py::build_csv`
    /// (servi par `python -m forge.report_engagement --format csv`). Le jeu de préfixes dangereux n'est
    /// écrit qu'à UN endroit — `console/testdata/csv_injection_vectors.json` — lu par CETTE assertion ET
    /// par `tests/test_report_engagement.py::TestCsvFormulaNeutralization`. Toucher le jeu sans corriger
    /// les deux implémentations fait échouer les DEUX suites (c'est le garde, pas une promesse).
    #[test]
    fn csv_injection_vectors_shared_with_python_exporter() {
        let v: Value = serde_json::from_str(include_str!(
            // Relatif au FICHIER : ce module vit désormais dans `reports/`, donc un `../` de plus
            // qu'avant l'extraction. Sans ça le build échoue sur `src/reports/../testdata/…`.
            "../../testdata/csv_injection_vectors.json",
        ))
            .expect("vecteurs CSV partagés lisibles");
        let neutral = v["neutralizer"].as_str().expect("neutralizer");
        let strs = |k: &str| -> Vec<String> {
            v[k].as_array().expect(k).iter().map(|x| x.as_str().expect("str").to_string()).collect()
        };
        let prefixes = strs("dangerous_prefixes");
        let payloads = strs("payloads");
        let benign = strs("benign");
        for p in &payloads {
            assert!(
                prefixes.iter().any(|pref| p.starts_with(pref.as_str())),
                "payload {p:?} n'exerce aucun préfixe déclaré (vecteurs incohérents)"
            );
            assert_eq!(
                csv_field(p),
                format!("\"{neutral}{}\"", p.replace('"', "\"\"")),
                "payload {p:?} non neutralisé par csv_field"
            );
        }
        for pref in &prefixes {
            assert!(
                payloads.iter().any(|p| p.starts_with(pref.as_str())),
                "préfixe {pref:?} déclaré mais non exercé par un payload"
            );
        }
        for b in &benign {
            assert_eq!(
                csv_field(b),
                format!("\"{}\"", b.replace('"', "\"\"")),
                "valeur légitime {b:?} altérée par la neutralisation"
            );
        }
        // CLASSE des préfixes AVALÉS par le tableur (contrôles/espaces/BOM) : la règle « premier
        // caractère » les laissait passer. Le fichier ne porte que des ÉCHANTILLONS ; la règle, elle,
        // est une classe (`starts_spreadsheet_formula`). Chaque échantillon porte SON attendu, y compris
        // les cas qui NE DOIVENT PAS être altérés (préfixe avalé sans déclencheur derrière).
        for e in v["swallowed_then_formula"].as_array().expect("swallowed_then_formula") {
            let raw = e["raw"].as_str().expect("raw");
            let cell = e["cell"].as_str().expect("cell");
            assert_eq!(
                csv_field(raw),
                format!("\"{}\"", cell.replace('"', "\"\"")),
                "préfixe avalé mal traité pour {raw:?} ({})",
                e["why"].as_str().unwrap_or("")
            );
        }
        // COÛT ASSUMÉ : contenu de scanner LÉGITIME mais commençant par un caractère dangereux — il EST
        // altéré, et c'est pinné ici pour que le comportement ne puisse pas changer dans un seul langage.
        for e in v["benign_prefixed"].as_array().expect("benign_prefixed") {
            let raw = e["raw"].as_str().expect("raw");
            let cell = e["cell"].as_str().expect("cell");
            assert_eq!(
                csv_field(raw),
                format!("\"{}\"", cell.replace('"', "\"\"")),
                "coût d'altération non conforme pour le contenu légitime {raw:?}"
            );
            assert_eq!(cell, format!("{neutral}{raw}"), "vecteurs incohérents pour {raw:?}");
        }
    }


    /// Faux exécutable (script shell) qui remplace le moteur/l'outil externe dans les tests de bornes —
    /// aucun process réel n'est lancé, le comportement (lent) est déterministe.
    #[cfg(unix)]
    fn stub_bin(tag: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::env::temp_dir();
        p.push(format!("forge-stub-{tag}-{}.sh", std::process::id()));
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_string_lossy().into_owned()
    }

    /// [S5-bis — livrable] `GET /api/engagements/:id/report?format=docx` (viewer+) délègue à
    /// `python -m forge.report_engagement` : un spawn de process PAR REQUÊTE, au coût SUPÉRIEUR au
    /// dry-plan. Il doit être borné dans le TEMPS (`FORGE_ENGINE_TIMEOUT`) — jamais une requête suspendue.
    /// CAUSE EXACTE (correctif) : le budget dépassé rend 504 `docx_engine_timeout` en NOMMANT la variable,
    /// et surtout PAS 501 « installez python3 » : python3 était installé, c'est la borne qui a parlé.
    /// Le 501 reste réservé au cas où le générateur a échoué ou n'a pas pu être lancé (test voisin).
    #[cfg(unix)]
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV process-global
    #[tokio::test]
    async fn docx_delegation_spawn_is_time_bounded() {
        let _g = crate::testutil::env_lock();
        std::env::set_var("FORGE_ENGINE_TIMEOUT", "1");
        let led = tmp_ledger("docxbound");
        let mut app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_finding(&app, 1, "f1", "a.example.com", "HIGH", "x");
        let (vtok, _o, _a) = seed_roles(&app);
        app.python = Arc::new(stub_bin("docx-timeout", "sleep 30"));
        let mut q = HashMap::new();
        q.insert("format".to_string(), "docx".to_string());
        let started = std::time::Instant::now();
        let fut = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q));
        let r = tokio::time::timeout(std::time::Duration::from_secs(10), fut).await;
        std::env::remove_var("FORGE_ENGINE_TIMEOUT");
        let r = r.expect("la délégation DOCX DOIT être bornée dans le temps — aucune réponse rendue");
        assert_eq!(r.status(), StatusCode::GATEWAY_TIMEOUT, "budget dépassé -> 504 (pas 501 « pas installé »)");
        assert!(started.elapsed() < std::time::Duration::from_secs(8), "réponse rendue à la borne");
        let body = to_json(r).await;
        assert_eq!(body["error"], "docx_engine_timeout", "la cause RENDUE est la borne franchie");
        let why = body["why"].as_str().unwrap_or("");
        assert!(why.contains("FORGE_ENGINE_TIMEOUT"), "le message NOMME la variable qui règle la borne: {why}");
        // L'assertion porte sur le CORPS ENTIER (`why` ET `hint`), pas sur un préfixe : la phrase
        // « surtout pas d'installation » et ce qui est vérifié disent maintenant la même chose.
        // Mesuré avant correctif : le `hint` d'un 504 contenait « installez python3 + le paquet forge »
        // — un test de préfixe ne le voyait pas.
        assert_no_install_advice(&body);
        let _ = std::fs::remove_file(&led);
        let _ = std::fs::remove_file(app.python.as_str());
    }

    /// [CAUSE EXACTE — une SATURATION n'est pas une DÉPENDANCE MANQUANTE] Mesuré avant correctif, avec
    /// python3 INSTALLÉ : deux lectures viewer tenant les slots suffisaient à faire répondre au livrable
    /// client `501 {"error":"docx_unavailable","hint":"installez python3..."}` — pour TOUT LE MONDE, en
    /// 7 ms. Un exploitant diagnostiquait une installation cassée pendant qu'il subissait une saturation.
    /// Ici : plafond ramené à 0 slot disponible (`FORGE_ENGINE_MAX_CONCURRENT=1` + un slot tenu par une
    /// lecture en vol) -> la réponse doit être 429, NOMMER la variable, et surtout ne PAS parler
    /// d'installation. Le 501 `docx_unavailable` reste vérifié à côté pour la VRAIE absence de générateur.
    #[cfg(unix)]
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn docx_saturation_is_not_reported_as_a_missing_dependency() {
        let _g = crate::testutil::env_lock();
        std::env::set_var("FORGE_ENGINE_MAX_CONCURRENT", "1");
        std::env::set_var("FORGE_ENGINE_TIMEOUT", "3");
        let led = tmp_ledger("docxbusy");
        let mut app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_finding(&app, 1, "f1", "a.example.com", "HIGH", "x");
        let (vtok, _o, _a) = seed_roles(&app);
        app.python = Arc::new(stub_bin("docx-busy", "sleep 30"));
        // 1 slot occupé par une lecture EN VOL (le générateur DOCX d'une autre requête).
        let (a, t) = (app.clone(), vtok.clone());
        let inflight = tokio::spawn(async move {
            let mut q = HashMap::new();
            q.insert("format".to_string(), "docx".to_string());
            engagement_report(State(a), bearer(&t), Path(1), Query(q)).await.status()
        });
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let mut q = HashMap::new();
        q.insert("format".to_string(), "docx".to_string());
        let started = std::time::Instant::now();
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "refus immédiat, pas d'attente muette");
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "saturation -> 429 (et surtout pas 501)");
        let body = to_json(r).await;
        assert_eq!(body["error"], "docx_engine_busy");
        let txt = format!("{body}");
        assert!(txt.contains("FORGE_ENGINE_MAX_CONCURRENT"), "le refus NOMME la variable: {txt}");
        assert!(!txt.contains("indisponible sur l'hôte"), "une saturation ne doit pas se dire « indisponible sur l'hôte »: {txt}");
        // … et ne doit pas non plus CONSEILLER une installation (le doc-comment le dit : c'est
        // maintenant ce qui est vérifié, sur tout le corps).
        assert_no_install_advice(&body);
        let _ = inflight.await;
        // les formats PUR-RUST restent servis pendant la saturation (aucune régression de lecture).
        let mut q = HashMap::new();
        q.insert("format".to_string(), "csv".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        assert_eq!(r.status(), StatusCode::OK, "CSV (pur Rust) sert toujours");
        std::env::remove_var("FORGE_ENGINE_MAX_CONCURRENT");
        std::env::remove_var("FORGE_ENGINE_TIMEOUT");
        let _ = std::fs::remove_file(&led);
        let _ = std::fs::remove_file(app.python.as_str());
    }

    /// [S5-bis — livrable] `?format=pdf` spawne `wkhtmltopdf`/`weasyprint` (outil SYSTÈME) par requête,
    /// viewer+ : même borne de temps, même dégradation documentée (None -> 501 `pdf_unavailable`).
    /// On préfixe le PATH d'un faux `wkhtmltopdf` lent (le reste du PATH est conservé).
    #[cfg(unix)]
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn pdf_render_spawn_is_time_bounded() {
        let _g = crate::testutil::env_lock();
        let stub_dir = std::env::temp_dir().join(format!("forge-pdfstub-{}", std::process::id()));
        std::fs::create_dir_all(&stub_dir).unwrap();
        let bin = stub_dir.join("wkhtmltopdf");
        std::fs::write(&bin, "#!/bin/sh\nsleep 30\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", stub_dir.display()));
        std::env::set_var("FORGE_ENGINE_TIMEOUT", "1");
        let started = std::time::Instant::now();
        let fut = crate::render_pdf_from_html("<html><body>x</body></html>");
        let got = tokio::time::timeout(std::time::Duration::from_secs(10), fut).await;
        std::env::set_var("PATH", old_path);
        std::env::remove_var("FORGE_ENGINE_TIMEOUT");
        let _ = std::fs::remove_dir_all(&stub_dir);
        let got = got.expect("le rendu PDF DOIT être borné dans le temps — aucune réponse rendue");
        // CAUSE EXACTE : un moteur PDF PRÉSENT mais coupé à la borne remonte `Bound(Timeout)`, jamais
        // `NoEngine` (qui ferait annoncer « aucun moteur PDF détecté » alors qu'il y en a un).
        match got {
            Err(crate::PdfErr::Bound(crate::EngineBoundErr::Timeout(_))) => {}
            Err(crate::PdfErr::NoEngine) => panic!("borne franchie rendue comme « aucun moteur PDF » — cause FAUSSE"),
            Err(crate::PdfErr::Bound(e)) => panic!("borne attendue = temps, obtenue: {}", e.why()),
            Ok(_) => panic!("moteur PDF coupé à la borne -> jamais un PDF partiel"),
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(8), "réponse rendue à la borne");
    }

    /// CSV/JSON round-trip : l'export se reparse et retrouve les valeurs attendues.
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn csv_json_round_trip() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("rt");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_finding(&app, 1, "SSRF interne", "a.example.com", "HIGH", "preuve");
        let (vtok, _o, _a) = seed_roles(&app);

        // CSV
        let mut q = HashMap::new();
        q.insert("format".to_string(), "csv".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let csv = to_text(r).await;
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], CSV_COLS.join(","), "en-tête CSV stable");
        assert_eq!(lines.len(), 2, "en-tête + 1 finding");
        assert!(lines[1].contains("SSRF interne"));
        assert!(lines[1].contains("HIGH"));
        assert!(lines[1].contains("idor"));

        // JSON
        let mut q = HashMap::new();
        q.insert("format".to_string(), "json".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let body = to_json(r).await;
        assert_eq!(body["findings"].as_array().unwrap().len(), 1);
        assert_eq!(body["findings"][0]["title"], "SSRF interne");
        assert_eq!(body["findings"][0]["cwe"], "CWE-639");
        assert_eq!(body["summary"]["by_severity"]["HIGH"], 1);
        let _ = std::fs::remove_file(&led);
    }

    /// PDF/DOCX dégradent GRACIEUSEMENT (status, pas de crash). PDF : 200 (moteur présent) OU 501
    /// documenté. DOCX : python bidon -> 501 déterministe (jamais un crash).
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn pdf_and_docx_degrade_gracefully() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("degrade");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_finding(&app, 1, "f1", "a.example.com", "HIGH", "x");
        let (vtok, _o, _a) = seed_roles(&app);

        // PDF : selon la présence d'un moteur -> 200 ou 501 (jamais 500/panic).
        let mut q = HashMap::new();
        q.insert("format".to_string(), "pdf".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let st = r.status();
        assert!(st == StatusCode::OK || st == StatusCode::NOT_IMPLEMENTED, "PDF: status {st}");
        if st == StatusCode::NOT_IMPLEMENTED {
            let body = to_json(r).await;
            assert_eq!(body["error"], "pdf_unavailable");
        }

        // DOCX : interpréteur python inexistant -> 501 (dégradation gracieuse déterministe).
        let mut app2 = app.clone();
        app2.python = Arc::new("forge-no-such-python-xyz".into());
        let mut q = HashMap::new();
        q.insert("format".to_string(), "docx".to_string());
        let r = engagement_report(State(app2), bearer(&vtok), Path(1), Query(q)).await;
        assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED, "python absent -> DOCX dégradé 501");
        let body = to_json(r).await;
        assert_eq!(body["error"], "docx_unavailable");
        // SYMÉTRIE de l'assertion « une borne ne conseille pas d'installer » : ICI, le générateur manque
        // POUR DE BON, donc le conseil d'installation DOIT être là. Sans cette assertion, on pourrait
        // satisfaire l'autre test en supprimant le conseil partout — et perdre l'aide réellement utile.
        assert!(
            body["hint"].as_str().unwrap_or("").contains("installez"),
            "vraie absence du générateur : le conseil d'installation doit être rendu, {body}"
        );
        let _ = std::fs::remove_file(&led);
    }

    /// Engagement inconnu -> 404 (jamais les données d'un autre) ; format inconnu -> 400.
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn unknown_engagement_404_bad_format_400() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("nf");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        let (vtok, _o, _a) = seed_roles(&app);

        let mut q = HashMap::new();
        q.insert("format".to_string(), "json".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(999), Query(q)).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "engagement inconnu -> 404");
        assert!(read_ledger_lines(&led).is_empty(), "un 404 ne ledgerise rien");

        let mut q = HashMap::new();
        q.insert("format".to_string(), "xls".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "format inconnu -> 400");
        let _ = std::fs::remove_file(&led);
    }

    /// BRANDING : GET viewer OK ; POST admin écrit + ledgerise ; POST viewer/operator refusé (admin).
    /// Le branding global apparaît dans le rapport HTML (nom client).
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn branding_admin_gated_and_rendered() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("brand");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        let (vtok, otok, atok) = seed_roles(&app);

        // POST viewer -> 403.
        let r = branding_set(State(app.clone()), bearer(&vtok), Query(HashMap::new()),
            Json(json!({"customer_name": "ACME"}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "viewer ne configure pas le branding");
        // POST operator -> 403 (admin requis).
        let r = branding_set(State(app.clone()), bearer(&otok), Query(HashMap::new()),
            Json(json!({"customer_name": "ACME"}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "operator ne configure pas le branding");

        // POST admin -> 200 + ledger.
        let r = branding_set(State(app.clone()), bearer(&atok), Query(HashMap::new()),
            Json(json!({"customer_name": "ACME Corp", "vendor": "GuatX Forge"}))).await;
        assert_eq!(r.status(), StatusCode::OK, "admin configure le branding");
        assert_eq!(read_ledger_lines(&led).last().unwrap()["kind"], "console.report.branding.set");

        // GET viewer -> 200 + effective.customer_name.
        let r = branding_get(State(app.clone()), bearer(&vtok), Query(HashMap::new())).await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = to_json(r).await;
        assert_eq!(body["effective"]["customer_name"], "ACME Corp");

        // le rapport HTML porte le nom client.
        let mut q = HashMap::new();
        q.insert("format".to_string(), "html".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let html = to_text(r).await;
        assert!(html.contains("ACME Corp"), "branding rendu dans le rapport");
        let _ = std::fs::remove_file(&led);
    }

    /// Extrait (status, headers, octets) d'une réponse — pour les formats binaires (docx) où l'on
    /// vérifie EN-TÊTES + magic bytes sans supposer de l'UTF-8.
    async fn to_parts(resp: Response) -> (StatusCode, HeaderMap, Vec<u8>) {
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap().to_vec();
        (parts.status, parts.headers, bytes)
    }

    /// EXPORT NON-BLANC sur engagement VIDE (0 finding) — régression B7 (« export blanc »).
    /// JSON : 200 + corps JSON valide NON vide (summary.total=0, findings []). DOCX : 200 + .docx
    /// valide (magic ZIP `PK\x03\x04`, non vide, content-type/disposition corrects) quand python est
    /// présent ; 501 documenté (docx_unavailable) s'il est absent — JAMAIS un 200 blanc.
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn empty_engagement_json_docx_nonblank() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("empty");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-vide"); // AUCUN finding
        let (vtok, _o, _a) = seed_roles(&app);

        // JSON : toujours 200, corps NON vide et parsable, comptes à zéro.
        let mut q = HashMap::new();
        q.insert("format".to_string(), "json".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let (st, hdrs, bytes) = to_parts(r).await;
        assert_eq!(st, StatusCode::OK, "JSON engagement vide -> 200");
        assert!(bytes.len() > 50, "JSON NON blanc (len={})", bytes.len());
        assert_eq!(hdrs.get("content-type").unwrap(), "application/json; charset=utf-8");
        let v: Value = serde_json::from_slice(&bytes).expect("JSON valide");
        assert_eq!(v["summary"]["total"], 0, "0 finding");
        assert_eq!(v["findings"].as_array().unwrap().len(), 0);
        assert!(v.get("engagement").is_some() && v.get("custody").is_some(), "structure complète");

        // DOCX : 200 + .docx valide quand python présent ; sinon 501 documenté (jamais 200 blanc).
        let mut q = HashMap::new();
        q.insert("format".to_string(), "docx".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let (st, hdrs, bytes) = to_parts(r).await;
        assert!(st == StatusCode::OK || st == StatusCode::NOT_IMPLEMENTED, "DOCX: 200 ou 501, jamais autre (got {st})");
        if st == StatusCode::OK {
            assert!(!bytes.is_empty() && bytes.starts_with(b"PK\x03\x04"), "DOCX = ZIP OOXML valide non vide");
            assert_eq!(
                hdrs.get("content-type").unwrap(),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            );
            let cd = hdrs.get("content-disposition").unwrap().to_str().unwrap();
            assert!(cd.contains("attachment") && cd.contains("forge-engagement-1.docx"), "disposition: {cd}");
        } else {
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v["error"], "docx_unavailable");
        }
        let _ = std::fs::remove_file(&led);
    }

    /// SÉLECTEUR DE FORMAT UNIQUE (régression B8) : le document d'APERÇU (`?preview=1`) N'EMBARQUE
    /// AUCUN lien `?format=` ni barre d'actions — le seul contrôle de format est celui du panneau.
    /// Le HTML autonome (sans preview) conserve UNIQUEMENT le bouton « Imprimer » (toujours zéro lien
    /// ?format= : ils dupliqueraient le contrôle et seraient inertes hors serveur).
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn preview_has_single_format_control() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("preview");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_finding(&app, 1, "f1", "a.example.com", "HIGH", "x");
        let (vtok, _o, _a) = seed_roles(&app);

        // preview=1 : aucune barre d'actions, aucun lien ?format=.
        let mut q = HashMap::new();
        q.insert("format".to_string(), "html".to_string());
        q.insert("preview".to_string(), "1".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let html = to_text(r).await;
        assert!(!html.contains("?format="), "aperçu : AUCUN lien ?format= (sélecteur unique = panneau)");
        assert!(!html.contains("class=\"toolbar"), "aperçu : aucune barre d'actions embarquée");

        // sans preview : HTML autonome — bouton Imprimer présent, MAIS toujours zéro lien ?format=.
        let mut q = HashMap::new();
        q.insert("format".to_string(), "html".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let html = to_text(r).await;
        assert!(!html.contains("?format="), "HTML autonome : plus de liens ?format= dupliqués");
        assert!(html.contains("window.print()"), "HTML autonome : bouton Imprimer conservé");
        let _ = std::fs::remove_file(&led);
    }

    /// LOGO CLIENT OPTIONNEL (régression B9) : sans logo configuré -> AUCUN `<img class="qz">` ni
    /// fallback `/quetzal.svg` (pas de carré vide). Avec un logo -> il est rendu, src ÉCHAPPÉ (anti-XSS).
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn client_logo_hidden_when_unset() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
        let led = tmp_ledger("logo");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        let (vtok, _o, _a) = seed_roles(&app);

        // sans logo : ni img qz ni quetzal fallback.
        let mut q = HashMap::new();
        q.insert("format".to_string(), "html".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q.clone())).await;
        let html = to_text(r).await;
        assert!(!html.contains("class=\"qz\""), "logo non configuré -> pas d'<img class=qz> (pas de carré vide)");
        assert!(!html.contains("/quetzal.svg"), "logo non configuré -> pas de fallback quetzal");

        // avec un logo hostile : rendu + src échappé (pas d'injection d'attribut/handler).
        let store = app.store();
        crate::settings_set_store(&store, "branding",
            &json!({"logo": "https://cdn.example.com/l.png\" onerror=\"alert(1)"}).to_string()).unwrap();
        drop(store);
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let html = to_text(r).await;
        assert!(html.contains("<img class=\"qz\""), "logo configuré -> img rendu");
        assert!(!html.contains("onerror=\"alert(1)\""), "src échappé (pas d'attribut injecté)");
        assert!(html.contains("&quot;"), "guillemets échappés dans le src");
        let _ = std::fs::remove_file(&led);
    }

    /// RUPTURE CORRIGÉE — le livrable client AGRÉGÉ part des findings STOCKÉS et ne regardait JAMAIS
    /// si les runs qui les ont produits étaient allés au bout. Un engagement dont un run a expiré
    /// rendait donc un rapport qui RESSEMBLE à un rapport complet : « aucun risque critique » s'y lit
    /// comme un verdict, alors que le plan n'a pas tourné. La bannière est maintenant DÉRIVÉE de
    /// `run_job.status`, elle NOMME les runs concernés, et un engagement dont tous les runs sont
    /// terminés n'en porte aucune trace.
    ///
    /// ⚠️ RESTE OUVERT (hors périmètre de ce fichier) : le format **DOCX** est délégué à
    /// `python -m forge.report_engagement`, qui ne lit pas encore la clef `partial` — c'est le SEUL
    /// format qui ne dit pas qu'un engagement est partiel. Patch signalé dans le rapport de session.
    #[tokio::test]
    async fn engagement_report_announces_an_interrupted_run() {
        let led = tmp_ledger("engpartial");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_finding(&app, 1, "f1", "a.example.com", "HIGH", "preuve");
        {
            let db = app.db();
            db.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,started_by,engagement_id)
                 VALUES('run-cut','camp',datetime('now'),'timeout','grey',1,0,0,0,'operator',1)",
                [],
            ).unwrap();
        }
        let (vtok, _o, _a) = seed_roles(&app);
        let mut q = HashMap::new();
        q.insert("format".to_string(), "html".to_string());
        let r = engagement_report(State(app.clone()), bearer(&vtok), Path(1), Query(q)).await;
        let html = to_text(r).await;
        assert!(html.contains("ENGAGEMENT PARTIEL"), "aucune bannière de partialité sur un run coupé");
        assert!(html.contains("run-cut"), "le run interrompu doit être NOMMÉ, pas juste compté");
        assert!(html.contains("budget dépassé (timeout)"), "la cause du run coupé doit être dite");
        assert!(
            html.find("ENGAGEMENT PARTIEL").unwrap() < html.find("Résumé exécutif").unwrap(),
            "la bannière BORNE le résumé exécutif : elle doit le précéder"
        );

        // …et un engagement dont tous les runs sont terminés n'en porte AUCUNE trace.
        let led2 = tmp_ledger("engdone");
        let app2 = test_app(&led2);
        seed_engagement(&app2, 1, "eng-B");
        seed_finding(&app2, 1, "f1", "a.example.com", "HIGH", "preuve");
        {
            let db = app2.db();
            db.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,started_by,engagement_id)
                 VALUES('run-ok','camp',datetime('now'),'done','grey',1,0,0,0,'operator',1)",
                [],
            ).unwrap();
        }
        let (vtok2, _o2, _a2) = seed_roles(&app2);
        let mut q2 = HashMap::new();
        q2.insert("format".to_string(), "html".to_string());
        let r2 = engagement_report(State(app2.clone()), bearer(&vtok2), Path(1), Query(q2)).await;
        let html2 = to_text(r2).await;
        assert!(!html2.contains("ENGAGEMENT PARTIEL"), "un engagement complet ne doit pas s'annoncer partiel");
        let _ = std::fs::remove_file(&led);
        let _ = std::fs::remove_file(&led2);
    }

    /// Le sous-routeur se construit sans conflit matchit.
    #[test]
    fn routes_build() {
        let _r: Router<App> = routes();
    }

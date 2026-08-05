// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sso` — module de test EXTRAIT (PURE MOVE depuis `console/src/sso.rs`).
//! Corps IDENTIQUE ; ENFANT de `sso`, il voit donc toujours ses items privés.
use super::*;

    use super::*;
    use crate::testutil::tmp_path;
    use crate::App;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rusqlite::Connection;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    // --- Test RSA keys (generated offline, PKCS#8). GOOD is published in the mock JWKS; ROGUE is used to
    //     forge a bad-signature token (JWKS only ever carries GOOD -> a ROGUE-signed token must be rejected).
    const GOOD_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDgydj5CrnsjonD
g1hGnaE+Mbquba+mxoZ/11HR8z6XRW9avqATc1bFg2eltd6FM1iqNtoojisd2XH6
2e8afdK7Gucysg7vqkO6W4VjqEEow4SXVlmfwLaK2Cq68m+t6D38V5aCMcXNe0rj
XPB+3r4ytK7h5fUe4ecirW82Lqo9qRS3VHLmuqKE5WjVZEiKjlobDpDWEXDf7X6Z
h25fK0IK3Umnz0xyeys2rPSoNMpSv+o0D0wtnoEGlSEUg5qAkI3ZszeAjwoT3wjG
0yRH651nFH/crEGNmSyrafo54tGQWq4x6ZbfyTMpD2d2ZDDgz1th39WvenEPQDnT
O7t5MWM/AgMBAAECggEABNW4/PvmE9h2muXwUbronokJr60pFThstcM3CoHMDtgU
SEQuKgm8P0AcTDKLnrUEBMufomlGAO/0XtjhJuJRIThRULdtUTcjgP0G8wwwNDHZ
+dQgCV4Ajx8nJbsHlYExR1D69vUeTaHuDAXe7MINuGytqXfKVee1+PqR/pa/KQq3
oV6Ow5+Ac4K8SZGm+puiAEfggNorNyiyqR4/mmVMrXPflVYMyK42q3h9w67ol0Kx
UDbMDHLCziAycJnEtrHjeypTsDJF15kq5uumEQBXJPVV9R1tc8voIMV8BLYh/9gD
oSowR4jZfp5P6BIWw7LXUusISI6pMYmbsKoGrHJPAQKBgQD60g54iDCfXvXtfHcW
D27lXNeo+o72lo7/jeHpaGKRzFkRh/JudoOqzFfedKFMCUUxog2jG2CJ/HPVilCV
yDYEsh4stpAUB8ObTvPX7pX+T6lutFtvMMeMGtppXKP5/5yKX+p3Vys95zozp6J9
/HHdQhrFvQNIRuohtBcJz87JDwKBgQDlbiysY4DYd5cuuXt7OUSvT3QTT9ZMIk1P
7rbSuN87OOU6z4L72pZGkypwGpwD/skSs/vySfV0sv4IRXCHGx0ed07uJQbfVTjn
NG46pqCQeNH7ymzVC8qFkB9nfmqpuxeWrOh8fx0LcBHpIcpWTwGztP1vL63CwNqF
QdiuviDi0QKBgQDhOH2F/cSrVrm95mWIiZMqoZOFSHfXNJpzHxQcYn8gLD5OX6Rx
TDouxA6i0leDz08yojFcpNirDuV0eh6iYIUg8k/mFoiJc+9RJjQPUU2ebinWHl18
GnEUfYhh063qbnxCRJ5lSwCpNVgtyfk+58/WveUMagzoecUDPpLxXIhyQQKBgBGs
AtTkdTA3RfXbY5+CMcAvJom2RJNosPvPL1Xb15YAM+frw/MSSzD0dPhdlFbacTJ3
mph3CekLQHXyo1BEzmFiXzoIsBbTwaZNa5Ao9YUrSUFTvj5Kwja3ezPFkQGx34dD
mkS8pcgTwc1rROKRA1iMQFkoGwI9SJerEr2i93WBAoGBAK7vEgmNN13r8JCqqM0A
EEcSrFIn/saqZM9Zwh5QW7MF/m0LnyXnipX+A2CWrJwFbbYLaEqMDAhUtZWMugPn
JBP2J1Y29oJwigBRnLE2K9AWHqIdKomikIecgf4SjZKOqRzusy6SlXQsh1EUvzNv
MSwrwH8+FMHL/yIMTRGUjMNm
-----END PRIVATE KEY-----";
    // GOOD public key JWK components (base64url of the RSA modulus / exponent).
    const GOOD_N: &str = "4MnY-Qq57I6Jw4NYRp2hPjG6rm2vpsaGf9dR0fM-l0VvWr6gE3NWxYNnpbXehTNYqjbaKI4rHdlx-tnvGn3SuxrnMrIO76pDuluFY6hBKMOEl1ZZn8C2itgquvJvreg9_FeWgjHFzXtK41zwft6-MrSu4eX1HuHnIq1vNi6qPakUt1Ry5rqihOVo1WRIio5aGw6Q1hFw3-1-mYduXytCCt1Jp89McnsrNqz0qDTKUr_qNA9MLZ6BBpUhFIOagJCN2bM3gI8KE98IxtMkR-udZxR_3KxBjZksq2n6OeLRkFquMemW38kzKQ9ndmQw4M9bYd_Vr3pxD0A50zu7eTFjPw";
    const GOOD_E: &str = "AQAB";
    const ROGUE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDmYrVowayPQs55
t6dS1Bjccj1/ztrWp+fLo3NMzVK49Q6PMmkJ9LyM+ykDgtpo1IlZ3fuAg60CdyQM
cLEQmr4EJSuhmbAFSCZ4zOGexVt5gXJK5l1WDx+uXvTzOYrHx77nZFpz+yX7lPsi
GVYC/9YScohDR8eD0K0ENYIOGa/Na7xZuZDr6zEVHKSwClsQk83U9YI0PlX09PzZ
TvpANoOCJJIgMAbUMHM8S5M+ba74NuRXG2vjN1E/rs4idmYasyyNsi5kDqFJx0/b
FIvcZoquD0z+82XXRTTKdURzlxsCDpkTc/39/GQY2Yac1J/MD5eBDiq5jIDdnNPr
N98oX5arAgMBAAECggEAUWpgoXyP9rCtNuZoAyVhA8Z7ZUc8ns8HYzeH74Q/z40K
cCBoblRGrau0esErXhB92XxQ/MGLymtAGgVZDX0h2WUpXhpp0fQFZHtC4FDuWqoc
McvnABqoH37/IVUcbi1wkWUtcf83FQk5FnvNoZG3nR1MejpLj5GXEv210DXTosvc
FMXh4JTaq36+243bM780rCgqjYHBskr2uuYrUJJ6bL31Sxlunl9sPYshAHRUNXuP
9e4V8A02wOK9UYL0GdLShqsEMQrA+if8iIsXanqHFmoC7TRSEv2pzCIfTGb4tGhx
+kksLk7f9pit5aW901vtWmmL9+ihtL/EOmCMphN3gQKBgQD+qtpdpwuLCt9OStwN
m/JxTE5+LhUtC/pjHd0LSpE4MitMx6eqZNgBYC2S2EUmjv8SoEHBkhNGZckzndw/
7SAcUxlAoR1SWFHB2SkdFqpmGjaXUeagBdXx+uxn8kccAl6QL6JgJ269v7mufjpm
IG9RkRdMlupo+vNGKf+Sjl+RyQKBgQDnl1QHbPIYG9I5isyaXtmvh+Q47g+GPuE1
1PJZ4iCeWu9BiB8GIYzal64+hkmNslnNzpIVgz6sKlmkMrbqK7q4OerIInT0sSlB
bDbzcRZpL/+xFhxuuUvs1qdra+6UfmSI52jYj2xU2F2bH1urBfr+JuP2Qpfn/HeU
t4dGx83+0wKBgQCVmQPBc/lB6lcXBL6TeAJJL8wEL0ndNmYVh1tr4JfB7SamabpC
TA7fcAIVetnUNrf71wwJi6eq+OviWF8jZkYwnVf+MSaqUptkRg7yuXfLlqZu6XuS
kRsGlKH+xcGj4HhwNqsp1MAm0tNef2QKzg7WWWbYZOa6WIBDvTQWgW/+kQKBgCqH
VKwEarTYrxNYFNioYGtmlheKSBmMBImBMHwnFXxfEJ7FI4VZtecSgbIDsRAvV2R+
8b63mlO9dza7BXIdU62vHRlhkn645e2YtMKh2s64PMlFWTVQG8xDYv1MFcT5LPcj
H9LdC7TNAuuQp6HReFUhyS0Y75Jvf3o09ceeu4p3AoGBAPv5wwgjLfP4vYm3azyJ
vvNKria3WmmbTH46x0FIEp21UyrdAu5PWq1OuFV0n8156jAUgE1IpH20uo/gLS7h
oVGTEwS7LY+Ncvq0vhIDT4uhs29Iju2b+yoNefutM77abV96Zl5934hz14dI4rdY
byHb5g3JqJSE6WJSuyEQrUob
-----END PRIVATE KEY-----";
    const KID: &str = "test-key-1";

    // ---- minimal HTTP helpers (self-contained; the crate's own test helpers live in a sibling module) ----
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
        resp.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).unwrap_or(0)
    }
    fn body_of(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }
    fn header_val(resp: &str, name: &str) -> Option<String> {
        let head = resp.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(resp);
        let want = format!("{}:", name.to_ascii_lowercase());
        for line in head.lines() {
            if line.to_ascii_lowercase().starts_with(&want) {
                return Some(line[want.len()..].trim().to_string());
            }
        }
        None
    }
    fn cookie_token(resp: &str) -> Option<String> {
        let sc = header_val(resp, "set-cookie")?;
        let idx = sc.find("forge_session=")?;
        let rest = &sc[idx + "forge_session=".len()..];
        let end = rest.find(';').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
    fn qparam(url: &str, key: &str) -> Option<String> {
        let q = url.split_once('?')?.1;
        for kv in q.split('&') {
            if let Some((k, v)) = kv.split_once('=') {
                if k == key {
                    return Some(v.to_string());
                }
            }
        }
        None
    }

    /// App backed by an in-memory DB (mirrors crate::tests::test_app; that helper is in a sibling module,
    /// not reachable here). Fields are crate-private but visible to this descendant module.
    fn sso_test_app(ledger_path: &str) -> App {
        // Les mocks OIDC de ces tests bindent 127.0.0.1 -> la garde SSRF d'intégration les refuserait.
        // On engage l'escape-hatch (comme un IdP privé on-prem légitime) UNE fois pour tout le binaire.
        crate::testutil::allow_internal_integrations_once();
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        let (events, _) = broadcast::channel::<crate::RunEvent>(64);
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
            run_state: Arc::new(AsyncMutex::new(crate::RunState { current: HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(crate::LedgerHead::default())),
        }
    }

    /// Engage the enterprise SSO flag on THIS db (per-DB, isolated — no env mutation).
    fn engage_flag(app: &App) {
        let db = app.db();
        crate::settings_set(&db, "enterprise.sso", "on").unwrap();
    }

    /// [LOW — cap de lecture du token OIDC] `http_post_form_blocking` BORNE le corps lu à
    /// `MAX_RESPONSE_BYTES` via `take()` (miroir de `net.rs::http_get_blocking`) : un IdP hostile/compromis
    /// renvoyant un corps ILLIMITÉ ne peut pas faire exploser la mémoire de la console. On sert un corps
    /// > cap ; le résultat est TRONQUÉ au cap (jamais lu en entier). L'appel blocant tourne en
    /// `spawn_blocking` (comme le vrai callback) pour ne pas figer le runtime current-thread du test.
    #[tokio::test]
    async fn oidc_token_read_is_capped() {
        crate::testutil::allow_internal_integrations_once(); // les mocks bindent 127.0.0.1 (escape-hatch SSRF)
        let oversized_len = crate::net::MAX_RESPONSE_BYTES as usize + 4096;
        let (addr, _h) = crate::testutil::mock_http_once("A".repeat(oversized_len)).await;
        let url = format!("http://{addr}/token");
        let body = tokio::task::spawn_blocking(move || {
            http_post_form_blocking(&url, "", "grant_type=x", Duration::from_secs(5))
        })
        .await
        .expect("join")
        .expect("post ok (statut 200 mock)");
        assert!(
            (body.len() as u64) <= crate::net::MAX_RESPONSE_BYTES && body.len() < oversized_len,
            "corps token TRONQUÉ au cap (lu {} <= cap {} < envoyé {})",
            body.len(), crate::net::MAX_RESPONSE_BYTES, oversized_len
        );
    }

    /// Write an SSO config directly into settings (bypasses the admin route — for flow tests).
    fn set_config(app: &App, issuer: &str, allowed: Vec<&str>, provisioning: &str, default_role: &str, user_claim: &str) {
        let cfg = json!({
            "issuer": issuer,
            "client_id": "forge-client",
            "client_secret": "s3cr3t-value",
            "redirect_uri": "http://localhost/api/sso/callback",
            "allowed_redirect_uris": allowed,
            "provisioning": provisioning,
            "default_role": default_role,
            "user_claim": user_claim,
        });
        let db = app.db();
        crate::settings_set(&db, CFG_KEY, &cfg.to_string()).unwrap();
    }

    /// Forge an ID token (RS256) with `pem`, embedding the given claims (incl. `email_verified`).
    #[allow(clippy::too_many_arguments)]
    fn make_id_token(pem: &str, kid: &str, iss: &str, aud: &str, sub: &str, email: &str, email_verified: bool, nonce: &str, exp_offset: i64) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let now = crate::now_epoch();
        let claims = json!({
            "iss": iss, "aud": aud, "sub": sub, "email": email, "email_verified": email_verified, "nonce": nonce,
            "exp": now + exp_offset, "iat": now
        });
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
        encode(&header, &claims, &key).expect("sign")
    }

    /// Forge an ID token carrying a `groups` claim (feeds advanced RBAC — used by the F6 downgrade test).
    #[allow(clippy::too_many_arguments)]
    fn make_id_token_groups(pem: &str, kid: &str, iss: &str, aud: &str, sub: &str, email: &str, email_verified: bool, nonce: &str, exp_offset: i64, groups: &[&str]) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let now = crate::now_epoch();
        let claims = json!({
            "iss": iss, "aud": aud, "sub": sub, "email": email, "email_verified": email_verified,
            "nonce": nonce, "groups": groups, "exp": now + exp_offset, "iat": now
        });
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
        encode(&header, &claims, &key).expect("sign")
    }

    /// Spawn a mock OIDC IdP whose discovery document advertises a CROSS-ORIGIN `token_endpoint` (SSO F5).
    /// The issuer/jwks/authorize are same-origin; only token_endpoint points elsewhere (port 1) so the
    /// same-origin pin must reject it. Returns the issuer base URL.
    async fn spawn_mock_idp_crossorigin() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock idp x-origin");
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let discovery = json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": "http://127.0.0.1:1/token", // DIFFERENT origin -> must be rejected
            "jwks_uri": format!("{base}/jwks"),
        })
        .to_string();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    discovery.len(),
                    discovery
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        base
    }

    /// Spawn a mock OIDC IdP. Serves discovery + JWKS (GOOD key) statically; `/token` returns whatever
    /// ID token the test has placed in the returned slot. Loops until the runtime tears down.
    async fn spawn_mock_idp() -> (String, Arc<Mutex<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock idp");
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let discovery = json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
        })
        .to_string();
        let jwks = json!({
            "keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": GOOD_N, "e": GOOD_E}]
        })
        .to_string();
        let slot = Arc::new(Mutex::new(String::new()));
        let slot2 = slot.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let mut buf = vec![0u8; 16384];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("");
                let payload = if path.starts_with("/.well-known/openid-configuration") {
                    discovery.clone()
                } else if path.starts_with("/jwks") {
                    jwks.clone()
                } else if path.starts_with("/token") {
                    json!({
                        "access_token": "mock-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "id_token": slot2.lock().unwrap().clone(),
                    })
                    .to_string()
                } else {
                    "{}".to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        (base, slot)
    }

    /// Boot the FULL router (build_router — parity with prod) and return its address.
    async fn serve(app: App) -> SocketAddr {
        let router = crate::build_router(app, "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;
        addr
    }

    /// Drive login -> parse state+nonce from the authorize redirect -> return (state, nonce, loc). Also
    /// asserts login_start bound the state to a browser cookie (SSO F2).
    async fn start_login(addr: SocketAddr, return_to: &str) -> (String, String, String) {
        let r = http_raw(addr, &get_req(&format!("/api/sso/login?return_to={}", pct_encode(return_to)), "")).await;
        assert_eq!(parse_status(&r), 302, "login should 302 to the IdP: {r}");
        let loc = header_val(&r, "location").expect("Location header on login");
        let state = qparam(&loc, "state").expect("state in authorize url");
        let nonce = qparam(&loc, "nonce").expect("nonce in authorize url");
        // F2: login_start must set the HttpOnly state-binding cookie == the authorize `state`.
        let sc = header_val(&r, "set-cookie").expect("state cookie on login_start");
        assert!(sc.contains(&format!("{STATE_COOKIE}={state}")), "state cookie carries state: {sc}");
        assert!(sc.contains("HttpOnly") && sc.contains("SameSite=Lax"), "state cookie hardened: {sc}");
        (state, nonce, loc)
    }

    /// A callback GET carrying the browser state-binding cookie (as a real browser would after login_start).
    fn callback_req(state: &str, code: &str) -> String {
        get_req(
            &format!("/api/sso/callback?code={code}&state={state}"),
            &format!("Cookie: {STATE_COOKIE}={state}\r\n"),
        )
    }

    // ------------------------------------------------------------------------------------------------
    // 1) HAPPY PATH — a valid OIDC callback issues a session + maps to a (auto-provisioned) user.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn valid_callback_issues_session_and_maps_user() {
        let ledger = tmp_path("sso-happy-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "operator", "email");
        let addr = serve(app.clone()).await;

        // login -> authorize redirect carries S256 PKCE + our client_id + return target's state/nonce.
        let (state, nonce, loc) = start_login(addr, "http://localhost/app").await;
        assert!(loc.starts_with(&format!("{issuer}/authorize?")), "authorize endpoint: {loc}");
        assert!(loc.contains("code_challenge_method=S256"), "PKCE S256: {loc}");
        assert!(loc.contains("client_id=forge-client"), "client_id present: {loc}");

        // IdP returns an ID token bound to OUR nonce, aud, issuer (email verified -> email mapping allowed).
        let idt = make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "oidc-sub-123", "Alice@Corp.com", true, &nonce, 3600);
        *slot.lock().unwrap() = idt;

        let r = http_raw(addr, &callback_req(&state, "authz-code")).await;
        assert_eq!(parse_status(&r), 302, "valid callback should 302: {r}");
        assert_eq!(header_val(&r, "location").as_deref(), Some("http://localhost/app"), "redirect to allowlisted target");
        let tok = cookie_token(&r).expect("forge_session cookie issued");
        let sc = header_val(&r, "set-cookie").unwrap();
        // Cookie durci : HttpOnly + SameSite=Strict TOUJOURS. `Secure` est désormais posé PAR DÉFAUT
        // (durcissement — le cookie de session ne transite jamais en clair), PLUS déduit du
        // `X-Forwarded-Proto` spoofable. L'opt-out `FORGE_COOKIE_INSECURE=1` (dev http-loopback) le
        // retirerait (non engagé ici).
        assert!(sc.contains("HttpOnly") && sc.contains("SameSite=Strict"), "hardened cookie: {sc}");
        assert!(sc.contains("; Secure"), "Secure posé par défaut (cookie de session jamais en clair): {sc}");

        // The session identifies the mapped user (email 'Alice@Corp.com' -> login 'alice.corp.com', operator).
        let w = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&w), 200, "whoami with SSO session: {w}");
        assert!(body_of(&w).contains("\"login\":\"alice.corp.com\""), "mapped login: {}", body_of(&w));
        assert!(body_of(&w).contains("\"role\":\"operator\""), "provisioned role: {}", body_of(&w));

        // Ledger: login recorded, secret/tokens NEVER present.
        let lines = crate::read_ledger_lines(&ledger);
        let last = lines.last().expect("ledger entry");
        assert_eq!(last["kind"], "console.sso.login");
        assert_eq!(last["detail"]["actor"], "alice.corp.com");
        assert_eq!(last["detail"]["provisioned"], true);
        let ser = serde_json::to_string(&last).unwrap();
        assert!(!ser.contains("s3cr3t-value"), "client_secret must never be ledgered");
        assert!(!ser.contains("id_token") && !ser.contains("mock-access-token"), "tokens must never be ledgered");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 2) FAIL-CLOSED — mismatched state is rejected (no session).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn mismatched_state_is_rejected() {
        let ledger = tmp_path("sso-state-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        set_config(&app, "http://idp.invalid", vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        // callback with a state that was never issued (but a matching binding cookie) -> 403, no cookie.
        let r = http_raw(addr, &callback_req("deadbeefdoesnotexist", "c")).await;
        assert_eq!(parse_status(&r), 403, "unknown state -> 403: {r}");
        assert!(body_of(&r).contains("invalid_state"), "reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none(), "no session on state mismatch");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 3) FAIL-CLOSED — mismatched nonce is rejected.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn mismatched_nonce_is_rejected() {
        let ledger = tmp_path("sso-nonce-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        let (state, _nonce, _) = start_login(addr, "http://localhost/app").await;
        // ID token carries the WRONG nonce.
        let idt = make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "sub-x", "u@x.com", true, "not-the-nonce", 3600);
        *slot.lock().unwrap() = idt;
        let r = http_raw(addr, &callback_req(&state, "c")).await;
        assert_eq!(parse_status(&r), 403, "nonce mismatch -> 403: {r}");
        assert!(body_of(&r).contains("invalid_id_token"), "reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none());
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 4) FAIL-CLOSED — wrong audience is rejected.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let ledger = tmp_path("sso-aud-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        let (state, nonce, _) = start_login(addr, "http://localhost/app").await;
        // aud is some OTHER client.
        let idt = make_id_token(GOOD_PEM, KID, &issuer, "someone-else", "sub-x", "u@x.com", true, &nonce, 3600);
        *slot.lock().unwrap() = idt;
        let r = http_raw(addr, &callback_req(&state, "c")).await;
        assert_eq!(parse_status(&r), 403, "aud mismatch -> 403: {r}");
        assert!(body_of(&r).contains("invalid_id_token"), "reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none());
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 5) FAIL-CLOSED — bad signature (token signed by a key NOT in the JWKS) is rejected.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn bad_signature_is_rejected() {
        let ledger = tmp_path("sso-sig-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        let (state, nonce, _) = start_login(addr, "http://localhost/app").await;
        // Signed with ROGUE key but claims KID=test-key-1 (which the JWKS maps to the GOOD key) -> sig fails.
        let idt = make_id_token(ROGUE_PEM, KID, &issuer, "forge-client", "sub-x", "u@x.com", true, &nonce, 3600);
        *slot.lock().unwrap() = idt;
        let r = http_raw(addr, &callback_req(&state, "c")).await;
        assert_eq!(parse_status(&r), 403, "bad signature -> 403: {r}");
        assert!(body_of(&r).contains("invalid_id_token"), "reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none());
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 6) REDIRECT ALLOWLIST — a non-allowlisted return target is refused up front (fail-closed).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn non_allowlisted_redirect_is_refused() {
        let ledger = tmp_path("sso-redir-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        set_config(&app, "http://idp.invalid", vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        let r = http_raw(
            addr,
            &get_req(&format!("/api/sso/login?return_to={}", pct_encode("https://evil.example/steal")), ""),
        )
        .await;
        assert_eq!(parse_status(&r), 403, "off-list redirect -> 403: {r}");
        assert!(body_of(&r).contains("redirect_not_allowed"), "reason: {}", body_of(&r));
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 7) CONFIG — client_secret is write-only: redacted on GET, but persisted in the DB.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn client_secret_redacted_on_config_get() {
        let ledger = tmp_path("sso-cfg-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        // Provision an admin + open a session (config routes require an admin session).
        let admin_tok = {
            let hash = crate::hash_pw("adminpw");
            let db = app.db();
            crate::upsert_user(&db, "root", "admin", &hash).unwrap();
            let id: i64 = db.query_row("SELECT id FROM users WHERE login=?", ["root"], |r| r.get(0)).unwrap();
            drop(db);
            crate::create_session(&app, id).0
        };
        app.recompute_auth_required();
        let addr = serve(app.clone()).await;
        let auth = format!("Cookie: forge_session={admin_tok}\r\n");

        // POST config WITH a secret.
        let cfg = json!({
            "issuer": "http://idp.invalid",
            "client_id": "forge-client",
            "client_secret": "top-secret-oidc",
            "redirect_uri": "http://localhost/api/sso/callback",
            "allowed_redirect_uris": ["http://localhost/app"],
            "provisioning": "match"
        })
        .to_string();
        let r = http_raw(addr, &post_req("/api/sso/config", &cfg, &auth)).await;
        assert_eq!(parse_status(&r), 200, "admin config POST: {r}");
        assert!(!body_of(&r).contains("top-secret-oidc"), "POST response must not echo the secret: {}", body_of(&r));

        // GET config — secret redacted, but presence flagged.
        let g = http_raw(addr, &get_req("/api/sso/config", &auth)).await;
        assert_eq!(parse_status(&g), 200, "admin config GET: {g}");
        assert!(!body_of(&g).contains("top-secret-oidc"), "secret must be redacted on GET: {}", body_of(&g));
        assert!(body_of(&g).contains("\"client_secret_set\":true"), "secret presence flagged: {}", body_of(&g));
        assert!(!body_of(&g).contains("\"client_secret\""), "no client_secret key at all: {}", body_of(&g));

        // But the secret IS persisted (write-only store).
        {
            
            let stored = crate::settings_get(&app.db(), CFG_KEY).unwrap();
            assert!(stored.contains("top-secret-oidc"), "secret persisted verbatim in settings");
        }
        // Ledger never carries the secret.
        let lines = crate::read_ledger_lines(&ledger);
        let last = lines.last().expect("config ledger entry");
        assert_eq!(last["kind"], "console.sso.config");
        assert!(!serde_json::to_string(&last).unwrap().contains("top-secret-oidc"), "secret never ledgered");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 8) FLAG OFF — /api/sso/* disabled (404) and LOCAL login is unchanged.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn flag_off_disables_sso_and_keeps_local_login() {
        let ledger = tmp_path("sso-off-ledger");
        let app = sso_test_app(&ledger);
        // NOTE: flag NOT engaged. Provision a local admin so /api/login has something to authenticate.
        {
            let hash = crate::hash_pw("localpw");
            let db = app.db();
            crate::upsert_user(&db, "root", "admin", &hash).unwrap();
        }
        app.recompute_auth_required();
        let addr = serve(app).await;

        // Every /api/sso/* route behaves as absent (404) with the flag off.
        for path in ["/api/sso/login", "/api/sso/callback?code=c&state=s", "/api/sso/config"] {
            let r = http_raw(addr, &get_req(path, "")).await;
            assert_eq!(parse_status(&r), 404, "flag off -> {path} disabled (404): {r}");
        }

        // LOCAL login is completely unchanged: valid creds -> 200 + forge_session cookie.
        let lr = http_raw(addr, &post_req("/api/login", "{\"login\":\"root\",\"password\":\"localpw\"}", "")).await;
        assert_eq!(parse_status(&lr), 200, "local login still works: {lr}");
        assert!(cookie_token(&lr).is_some(), "local login still issues forge_session");
        // Bad creds still rejected.
        let br = http_raw(addr, &post_req("/api/login", "{\"login\":\"root\",\"password\":\"wrong\"}", "")).await;
        assert_eq!(parse_status(&br), 401, "local login still rejects bad creds: {br}");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 9) SSO F1 — email-keyed mapping requires email_verified. false => reject; true => accept.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn email_verified_gates_email_mapping() {
        let ledger = tmp_path("sso-ev-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "operator", "email");
        let addr = serve(app.clone()).await;

        // email_verified == false -> refuse to map by email (fail-closed anti-collision).
        let (s1, n1, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "sub-a", "alice@corp.com", false, &n1, 3600);
        let r1 = http_raw(addr, &callback_req(&s1, "c")).await;
        assert_eq!(parse_status(&r1), 403, "unverified email -> 403: {r1}");
        assert!(body_of(&r1).contains("user_mapping_failed"), "reason: {}", body_of(&r1));
        assert!(cookie_token(&r1).is_none(), "no session for unverified email");

        // email_verified == true -> accepted, session issued.
        let (s2, n2, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "sub-a", "alice@corp.com", true, &n2, 3600);
        let r2 = http_raw(addr, &callback_req(&s2, "c")).await;
        assert_eq!(parse_status(&r2), 302, "verified email -> 302: {r2}");
        assert!(cookie_token(&r2).is_some(), "session issued for verified email");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 10) SSO F1 — `sub`-keyed mapping is EXEMPT (email_verified irrelevant; sub is a stable identifier).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn sub_mapping_bypasses_email_verified() {
        let ledger = tmp_path("sso-sub-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "sub");
        let addr = serve(app.clone()).await;
        let (s, n, _) = start_login(addr, "http://localhost/app").await;
        // Email present but UNVERIFIED — irrelevant because the login key is `sub`.
        *slot.lock().unwrap() =
            make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "sub-z", "x@x.com", false, &n, 3600);
        let r = http_raw(addr, &callback_req(&s, "c")).await;
        assert_eq!(parse_status(&r), 302, "sub mapping ok despite unverified email: {r}");
        assert!(cookie_token(&r).is_some());
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 11) SSO F2 — the callback requires the browser state-binding cookie. Absent/mismatched => reject.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn state_cookie_mismatch_is_rejected() {
        let ledger = tmp_path("sso-f2-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app.clone()).await;
        let (state, nonce, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "sub-x", "u@x.com", true, &nonce, 3600);

        // WRONG cookie value -> reject BEFORE consuming the pending state (fail-closed anti login-CSRF).
        let bad = get_req(
            &format!("/api/sso/callback?code=c&state={state}"),
            &format!("Cookie: {STATE_COOKIE}=not-the-state\r\n"),
        );
        let r = http_raw(addr, &bad).await;
        assert_eq!(parse_status(&r), 403, "state cookie mismatch -> 403: {r}");
        assert!(body_of(&r).contains("state_binding_failed"), "reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none(), "no session on state-binding failure");

        // ABSENT cookie -> reject too (the pending state is still intact, so a bound retry would work).
        let absent = http_raw(addr, &get_req(&format!("/api/sso/callback?code=c&state={state}"), "")).await;
        assert_eq!(parse_status(&absent), 403, "absent state cookie -> 403: {absent}");
        assert!(body_of(&absent).contains("state_binding_failed"), "reason: {}", body_of(&absent));

        // The correctly-bound callback still succeeds (the pending entry was never consumed above).
        let ok = http_raw(addr, &callback_req(&state, "c")).await;
        assert_eq!(parse_status(&ok), 302, "bound callback succeeds: {ok}");
        assert!(cookie_token(&ok).is_some());
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 12) SSO F5 — a discovery doc whose token_endpoint is CROSS-ORIGIN to the issuer is rejected.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn crossorigin_discovery_endpoint_is_rejected() {
        let ledger = tmp_path("sso-f5-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let issuer = spawn_mock_idp_crossorigin().await;
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "email");
        let addr = serve(app).await;
        let r = http_raw(
            addr,
            &get_req(&format!("/api/sso/login?return_to={}", pct_encode("http://localhost/app")), ""),
        )
        .await;
        assert_eq!(parse_status(&r), 502, "cross-origin discovery -> 502: {r}");
        assert!(body_of(&r).contains("discovery_failed"), "reason: {}", body_of(&r));
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 13) SSO F6 — a stale SSO admin is downgraded when its IdP group no longer confers the role. A
    //     local (non-SSO) admin is untouched (downgrade is scoped by user_id to SSO-managed accounts).
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn stale_admin_is_downgraded_on_group_removal() {
        let ledger = tmp_path("sso-f6-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        // sub-keyed (no email_verified concern), auto-provision, default viewer.
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "sub");
        // Force the rbac_group_map table to exist (resolve side-effect), then map forge-admins -> admin.
        let _ = crate::rbac::resolve(&app, &["seed".to_string()]);
        // A LOCAL admin that never logs in via SSO -> must stay admin (never SSO-managed).
        let hash = crate::hash_pw("localpw");
        {
            let db = app.db();
            db.execute(
                "INSERT INTO rbac_group_map(idp_group,role,tenant_id,tenant_role,created) VALUES('forge-admins','admin',NULL,NULL,0)",
                [],
            )
            .unwrap();
            crate::upsert_user(&db, "root", "admin", &hash).unwrap();
            drop(db);
        }
        let addr = serve(app.clone()).await;

        // Login 1: groups=[forge-admins] -> provisioned as admin (SSO-managed).
        let (s1, n1, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token_groups(GOOD_PEM, KID, &issuer, "forge-client", "user-1", "", false, &n1, 3600, &["forge-admins"]);
        let r1 = http_raw(addr, &callback_req(&s1, "c")).await;
        assert_eq!(parse_status(&r1), 302, "login1 -> 302: {r1}");
        let t1 = cookie_token(&r1).unwrap();
        let w1 = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={t1}\r\n"))).await;
        assert!(body_of(&w1).contains("\"role\":\"admin\""), "login1 confers admin: {}", body_of(&w1));

        // Login 2: groups=[some-other] (present but no match) -> DOWNGRADE to viewer (fail-closed).
        let (s2, n2, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token_groups(GOOD_PEM, KID, &issuer, "forge-client", "user-1", "", false, &n2, 3600, &["some-other-group"]);
        let r2 = http_raw(addr, &callback_req(&s2, "c")).await;
        assert_eq!(parse_status(&r2), 302, "login2 -> 302: {r2}");
        let t2 = cookie_token(&r2).unwrap();
        let w2 = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={t2}\r\n"))).await;
        assert!(body_of(&w2).contains("\"role\":\"viewer\""), "stale admin downgraded to viewer: {}", body_of(&w2));

        // The local admin (never SSO-managed) is untouched.
        let root_role: String = {
            let db = app.db();
            db.query_row("SELECT role FROM users WHERE login='root'", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(root_role, "admin", "local (non-SSO) admin must NOT be downgraded");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 13b) M4 — an OIDC claim colliding with an existing UNMARKED LOCAL login does NOT authenticate as,
    //      nor re-role, that account. Only an explicit SSO binding marker (sso_managed) permits adoption.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn sso_never_adopts_or_reroles_unmarked_local_account() {
        let ledger = tmp_path("sso-m4-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        // auto-provision, sub-keyed (no email_verified concern), default viewer.
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "sub");
        // Map forge-admins -> admin so the IdP `groups` claim WOULD re-role the colliding login if adopted.
        let _ = crate::rbac::resolve(&app, &["seed".to_string()]);
        let hash = crate::hash_pw("localpw");
        {
            let db = app.db();
            db.execute(
                "INSERT INTO rbac_group_map(idp_group,role,tenant_id,tenant_role,created) VALUES('forge-admins','admin',NULL,NULL,0)",
                [],
            )
            .unwrap();
            // A pre-existing LOCAL account (role viewer), created via admin CRUD — NEVER via SSO/SCIM.
            crate::upsert_user(&db, "victim", "viewer", &hash).unwrap();
            drop(db);
        }
        let addr = serve(app.clone()).await;

        // SSO login whose `sub` sanitises to the existing local login "victim", carrying an admin-conferring group.
        let (s, n, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token_groups(GOOD_PEM, KID, &issuer, "forge-client", "victim", "", false, &n, 3600, &["forge-admins"]);
        let r = http_raw(addr, &callback_req(&s, "c")).await;
        assert_eq!(parse_status(&r), 403, "[M4] colliding claim on unmarked local account -> 403: {r}");
        assert!(body_of(&r).contains("user_mapping_failed"), "[M4] reason: {}", body_of(&r));
        assert!(cookie_token(&r).is_none(), "[M4] no session issued for the local account");

        // The local account is NEITHER authenticated-as NOR re-roled (still viewer, never admin).
        let role: String = {
            let db = app.db();
            db.query_row("SELECT role FROM users WHERE login='victim'", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(role, "viewer", "[M4] unmarked local account must NOT be re-roled by the IdP groups claim");

        // Regression: a FRESH `sub` (no collision) still auto-provisions and logs in normally.
        let (s2, n2, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "brand-new-sub", "", false, &n2, 3600);
        let r2 = http_raw(addr, &callback_req(&s2, "c")).await;
        assert_eq!(parse_status(&r2), 302, "[M4] fresh SSO account still provisions: {r2}");
        assert!(cookie_token(&r2).is_some(), "[M4] fresh SSO login issues a session");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 13b') COMBINED SCIM+SSO — the M4 adopt-gate is broadened to accept a SCIM-PROVISIONED account
    //       (has a `scim_user` row) at SSO login, WITHOUT weakening the M4 property: an UNMARKED LOCAL
    //       account (neither SSO- nor SCIM-managed) is STILL refused fail-closed. Covers:
    //         (a) SCIM-managed pre-existing account -> SSO login ADOPTS it (session issued);
    //         (b) UNMARKED LOCAL account            -> STILL refused (no session, role unchanged);
    //         (c) SSO-managed account               -> still works (fresh provision + re-adoption).
    //       Role handling on adoption (SAFE, least-surprising): map_user only decides ADOPTION, never
    //       role. When the IdP asserts NO mapping group, `apply_to_user` leaves the role untouched and
    //       the F6 downgrade cannot fire (the SCIM-only account is not `sso_managed`), so SCIM's role
    //       authority is preserved — no surprise escalation of a SCIM account via SSO groups.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn sso_adopts_scim_managed_account_but_still_refuses_unmarked_local() {
        let ledger = tmp_path("sso-scimsso-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        let (issuer, slot) = spawn_mock_idp().await;
        // auto-provision, sub-keyed, default viewer.
        set_config(&app, &issuer, vec!["http://localhost/app"], "auto", "viewer", "sub");

        let hash = crate::hash_pw("localpw");
        {
            let db = app.db();
            // (a) SCIM-PROVISIONED account: a local `users` row PLUS a `scim_user` mapping — the exact
            //     predicate SCIM uses everywhere to mark an account it OWNS. Role operator (SCIM authority).
            crate::upsert_user(&db, "scim-alice", "operator", &hash).unwrap();
            let scim_id: i64 =
                db.query_row("SELECT id FROM users WHERE login='scim-alice'", [], |r| r.get(0)).unwrap();
            db.execute_batch(
                "CREATE TABLE IF NOT EXISTS scim_user(
                   user_id INTEGER PRIMARY KEY, external_id TEXT NOT NULL DEFAULT '',
                   email TEXT NOT NULL DEFAULT '', given_name TEXT NOT NULL DEFAULT '',
                   family_name TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL DEFAULT '',
                   created INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0);",
            )
            .unwrap();
            db.execute("INSERT INTO scim_user(user_id,created,updated) VALUES(?,0,0)", [scim_id]).unwrap();
            // (b) plain LOCAL account — NO markers (never SSO, never SCIM). Must stay refused.
            crate::upsert_user(&db, "local-bob", "viewer", &hash).unwrap();
            drop(db);
        }
        let addr = serve(app.clone()).await;

        // (a) SCIM-managed account -> SSO login ADOPTS it (session issued). No mapping group asserted, so
        //     SCIM's role authority is preserved (operator unchanged).
        let (s, n, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "scim-alice", "", false, &n, 3600);
        let r = http_raw(addr, &callback_req(&s, "c")).await;
        assert_eq!(parse_status(&r), 302, "[SCIM+SSO] SCIM-managed account ADOPTS at SSO login: {r}");
        assert!(cookie_token(&r).is_some(), "[SCIM+SSO] session issued for the SCIM-managed account");
        let role_a: String = {
            let db = app.db();
            db.query_row("SELECT role FROM users WHERE login='scim-alice'", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(role_a, "operator", "[SCIM+SSO] no mapping group -> SCIM's role preserved (no surprise re-role)");

        // (b) UNMARKED LOCAL account -> STILL refused (M4 property preserved). No session, role unchanged.
        let (s2, n2, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "local-bob", "", false, &n2, 3600);
        let r2 = http_raw(addr, &callback_req(&s2, "c")).await;
        assert_eq!(parse_status(&r2), 403, "[M4] unmarked local account STILL refused: {r2}");
        assert!(body_of(&r2).contains("user_mapping_failed"), "[M4] reason: {}", body_of(&r2));
        assert!(cookie_token(&r2).is_none(), "[M4] no session for the unmarked local account");
        let role_b: String = {
            let db = app.db();
            db.query_row("SELECT role FROM users WHERE login='local-bob'", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(role_b, "viewer", "[M4] unmarked local account NOT re-roled by the IdP claim");

        // (c) SSO-managed account -> still works. A fresh `sub` auto-provisions AND marks it `sso_managed`;
        //     a SECOND login with the same `sub` re-adopts it via the `is_sso_managed` path.
        let (s3, n3, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "sso-carol", "", false, &n3, 3600);
        let r3 = http_raw(addr, &callback_req(&s3, "c")).await;
        assert_eq!(parse_status(&r3), 302, "[SSO] fresh SSO account provisions + logs in: {r3}");
        assert!(cookie_token(&r3).is_some(), "[SSO] session issued (fresh sso_managed account)");
        let (s4, n4, _) = start_login(addr, "http://localhost/app").await;
        *slot.lock().unwrap() =
            make_id_token(GOOD_PEM, KID, &issuer, "forge-client", "sso-carol", "", false, &n4, 3600);
        let r4 = http_raw(addr, &callback_req(&s4, "c")).await;
        assert_eq!(parse_status(&r4), 302, "[SSO] SSO-managed account RE-ADOPTS on second login: {r4}");
        assert!(cookie_token(&r4).is_some(), "[SSO] session re-issued for the SSO-managed account");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 13c) L6 — SSO default_role is bounded to viewer|operator (never admin). Parity with SCIM's clamp.
    // ------------------------------------------------------------------------------------------------
    #[tokio::test]
    async fn sso_default_role_bounded_below_admin() {
        // Pure clamp: admin -> operator; viewer/operator pass through; unknown -> viewer (fail-closed).
        assert_eq!(clamp_sso_default_role("admin"), "operator", "[L6] admin default clamps down (never auto-confers admin)");
        assert_eq!(clamp_sso_default_role("operator"), "operator");
        assert_eq!(clamp_sso_default_role("viewer"), "viewer");
        assert_eq!(clamp_sso_default_role("root"), "viewer", "[L6] unknown -> viewer (fail-closed)");

        // End-to-end via load_config: a stored config with default_role="admin" loads as "operator".
        let ledger = tmp_path("sso-l6-ledger");
        let app = sso_test_app(&ledger);
        engage_flag(&app);
        set_config(&app, "http://idp", vec!["http://localhost/app"], "auto", "admin", "sub");
        let cfg = load_config(&app).expect("config loads");
        assert_eq!(cfg.default_role, "operator", "[L6] SSO default_role=admin bounded to operator at load");
        let _ = std::fs::remove_file(&ledger);
    }

    // ------------------------------------------------------------------------------------------------
    // 14) UNIT — sanitize_login / redirect_allowed / pct_encode / code_challenge / origin_of edge cases.
    // ------------------------------------------------------------------------------------------------
    #[test]
    fn unit_helpers() {
        assert_eq!(sanitize_login("Alice@Corp.com").unwrap(), "alice.corp.com");
        assert_eq!(sanitize_login("auth0|abc123").unwrap(), "auth0-abc123");
        assert!(sanitize_login("@@@").is_err(), "nothing valid remains -> err");
        let cfg = SsoConfig {
            issuer: "http://i".into(),
            client_id: "c".into(),
            client_secret: "s".into(),
            redirect_uri: "http://localhost/cb".into(),
            allowed_redirect_uris: vec!["http://localhost/app".into()],
            provisioning: "match".into(),
            default_role: "viewer".into(),
            user_claim: "email".into(),
            require_email_verified: true,
        };
        assert!(redirect_allowed(&cfg, "http://localhost/app"), "exact allowlist match");
        assert!(redirect_allowed(&cfg, "/dashboard"), "safe same-origin relative");
        assert!(redirect_allowed(&cfg, "/"), "root allowed");
        assert!(!redirect_allowed(&cfg, "https://evil/x"), "off-list absolute refused");
        assert!(!redirect_allowed(&cfg, "//evil.example"), "protocol-relative refused");
        assert_eq!(pct_encode("a b&c=d"), "a%20b%26c%3Dd");
        // Known RFC 7636 PKCE S256 test vector.
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        // origin_of: default-port normalisation + cross-origin discrimination (SSO F5 substrate).
        assert_eq!(origin_of("http://idp.example/x"), origin_of("http://idp.example:80/y"), "http default port");
        assert_eq!(origin_of("https://idp.example/a"), origin_of("https://idp.example:443/b"), "https default port");
        assert_ne!(origin_of("http://idp.example/x"), origin_of("http://evil.example/x"), "different host");
        assert_ne!(origin_of("http://idp.example/x"), origin_of("http://idp.example:8443/x"), "different port");
        assert_ne!(origin_of("http://idp.example/x"), origin_of("https://idp.example/x"), "different scheme");
        assert!(origin_of("ftp://idp.example").is_none(), "non-http(s) => None");
    }

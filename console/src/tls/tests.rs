// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests du SEAM TLS. Trois choses à prouver, pas une de moins :
//!   1. le découpage d'URL est fail-closed (PUR) ;
//!   2. la VÉRIFICATION DE CERTIFICAT MORD — un pair qui présente un certificat non fiable ne reçoit
//!      AUCUN octet applicatif (la connexion échoue au handshake). Sans ce test, rien ne distingue ce
//!      TLS d'un tunnel qui accepte tout ;
//!   3. il n'existe AUCUNE échappatoire de vérification dans la source du crate.

use super::*;
use base64::Engine;
use std::net::TcpListener;

// ---------------------------------------------------------------------------------------------
//  Matériel de test : une AC de test (auto-signée, INCONNUE des racines Mozilla) et une feuille
//  serveur QU'ELLE SIGNE. C'est la forme exacte de ce qu'un MITM présente : une chaîne bien formée,
//  simplement pas ancrée dans une racine de confiance. Le client DOIT la refuser.
//
//  POURQUOI PAS UN SIMPLE AUTO-SIGNÉ (première version de ce test) : rustls-webpki refuse un
//  certificat d'AC utilisé comme feuille (`CaUsedAsEndEntity`) AVANT même de statuer sur la
//  confiance. La MUTATION de contrôle (« ajouter ce certificat aux racines ») restait donc VERTE — un
//  constat sur le test, pas un succès. Avec une vraie paire AC + feuille, ajouter l'AC aux racines
//  fait RÉUSSIR le handshake, et le test rougit : sa couleur est bien gouvernée par la DÉCISION DE
//  CONFIANCE, ce qu'il doit mesurer. ECDSA P-256, SAN `untrusted.test` (+ 127.0.0.1), 100 ans.
// ---------------------------------------------------------------------------------------------

/// AC de test (DER, base64) — auto-signée, absente des racines Mozilla, donc NON FIABLE.
const UNTRUSTED_CA_DER_B64: &str = "MIIBqjCCAVGgAwIBAgIUIHzfm2Yg/rEtjA+SxNbf+hrxGEYwCgYIKoZIzj0EAwIwIjEgMB4GA1UEAwwXZm9yZ2UtdGVzdC11bnRydXN0ZWQtY2EwIBcNMjYwODA2MTAyMTUzWhgPMjEyNjA3MTMxMDIxNTNaMCIxIDAeBgNVBAMMF2ZvcmdlLXRlc3QtdW50cnVzdGVkLWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoJXJfB87dpFsprzV9CZpB9fuBad/rOJ2UCgbOwaYF0CSmpTwYSgFD80YnZgwDoEgORuLJWoWR06ihKhogMVY3aNjMGEwHQYDVR0OBBYEFIT8mr33VGcjHc5MtAvJfbyVaKBlMB8GA1UdIwQYMBaAFIT8mr33VGcjHc5MtAvJfbyVaKBlMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0cAMEQCH2RVQSWGOfzX2X46myyxVQYuwqk58fAY0v9ORpbKbR4CIQC3A3ClbJveD0xVZmUud4XCyxHlo27YKE10U32EGejxGA==";

/// Feuille serveur (DER, base64) signée par l'AC ci-dessus : `CA:FALSE`, EKU `serverAuth`,
/// SAN `untrusted.test`. Chaîne BIEN FORMÉE — seule la confiance manque.
const UNTRUSTED_CERT_DER_B64: &str = "MIIB2DCCAX2gAwIBAgIUPSgIIQ1WZpJYQrnL+Ck/V4QteNowCgYIKoZIzj0EAwIwIjEgMB4GA1UEAwwXZm9yZ2UtdGVzdC11bnRydXN0ZWQtY2EwIBcNMjYwODA2MTAyMTUzWhgPMjEyNjA3MTMxMDIxNTNaMBkxFzAVBgNVBAMMDnVudHJ1c3RlZC50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYtfHg7+XK/rIM8ZEQq9zR0CHQFqWtmBOiuA9BJ5puflQ7Jh2dJA+3uiBwS+ijqXYYk7VN/p98GUQvATM/yhjGaOBlzCBlDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAfBgNVHREEGDAWgg51bnRydXN0ZWQudGVzdIcEfwAAATAdBgNVHQ4EFgQUmtLQQPdo8R/wn3UysNEm+MQsPL8wHwYDVR0jBBgwFoAUhPyavfdUZyMdzky0C8l9vJVooGUwCgYIKoZIzj0EAwIDSQAwRgIhAMJpURY0yxYY8dZCDMK/pKDrgKSn8XgvT+KWHdF4eJd6AiEAwT8JqmcRKX3OhnI/1TZBi2YtTnD/gGPGDPTvpcELmfQ=";

/// Clé privée de la feuille (PKCS#8 DER, base64). Matériel de TEST uniquement : elle ne protège rien,
/// elle sert à faire parler un serveur TLS jetable sur loopback.
const UNTRUSTED_KEY_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9AkxZaJ+e+Xd+z1S5cIu/af7YLLXjf3mhuuXixt3e5qhRANCAARi18eDv5cr+sgzxkRCr3NHQIdAWpa2YE6K4D0Enmm5+VDsmHZ0kD7e6IHBL6KOpdhiTtU3+n3wZRC8BMz/KGMZ";

/// Nom d'hôte porté par le certificat de test (SAN DNS). On le passe en `verify_host` pour que le
/// refus attendu porte sur la CHAÎNE (émetteur inconnu) et non sur une simple discordance de nom.
const UNTRUSTED_HOST: &str = "untrusted.test";

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).expect("base64 de fixture")
}

/// Serveur TLS jetable sur loopback, servant la chaîne NON FIABLE ci-dessus (feuille + AC de test).
/// Accepte `accepts` connexions puis meurt. Les erreurs de handshake sont ATTENDUES (le client refuse
/// la chaîne et envoie une alerte) : on les ignore côté serveur.
fn spawn_untrusted_tls_server(accepts: usize) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr locale");
    let chain = vec![
        rustls::pki_types::CertificateDer::from(b64(UNTRUSTED_CERT_DER_B64)),
        rustls::pki_types::CertificateDer::from(b64(UNTRUSTED_CA_DER_B64)),
    ];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(b64(
        UNTRUSTED_KEY_DER_B64,
    )));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions TLS")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("chaîne+clé de test");
    let cfg = Arc::new(cfg);
    let h = std::thread::spawn(move || {
        for _ in 0..accepts {
            let Ok((mut sock, _)) = listener.accept() else { return };
            // Borne dure : un client en clair (le contrôle de joignabilité) ne dira jamais rien —
            // le thread ne doit pas rester pendu pour autant.
            sock.set_read_timeout(Some(Duration::from_millis(800))).ok();
            let Ok(mut session) = rustls::ServerConnection::new(cfg.clone()) else { return };
            let _ = session.complete_io(&mut sock); // échec attendu : le client refuse le certificat
        }
    });
    (addr, h)
}

// =============================================================================================
//  1. DÉCOUPAGE D'URL — PUR, fail-closed
// =============================================================================================

/// `split_url` reconnaît les DEUX schémas, applique le bon port par défaut, et refuse tout le reste.
/// MUTATION : retirer la branche `https://` (retour à l'ancien refus) -> ce test rougit.
#[test]
fn split_url_parses_both_schemes_and_fails_closed() {
    let t = split_url("https://idp.example/token").expect("https accepté");
    assert_eq!(t.scheme, Scheme::Https);
    assert!(t.scheme.is_tls(), "https => transport chiffré");
    assert_eq!((t.host.as_str(), t.port, t.path.as_str()), ("idp.example", 443, "/token"));
    assert_eq!(t.authority, "idp.example", "l'en-tête Host: garde la forme d'origine");

    let t = split_url("http://collecteur.interne:9200").expect("http accepté");
    assert_eq!(t.scheme, Scheme::Http);
    assert!(!t.scheme.is_tls(), "http => clair");
    assert_eq!((t.host.as_str(), t.port, t.path.as_str()), ("collecteur.interne", 9200, "/"));
    assert_eq!(t.authority, "collecteur.interne:9200");

    assert_eq!(split_url("https://h.example:8443/x").unwrap().port, 8443, "port explicite prime");
    // Fail-closed : schéma hors jeu, autorité vide, CR/LF (injection d'en-tête Host:).
    for bad in ["ftp://h/x", "gopher://h", "h.example/x", "", "https://", "http:///path", "http://h\r\nX: y/x"] {
        assert!(split_url(bad).is_err(), "URL refusée attendue: {bad:?}");
    }
}

// =============================================================================================
//  2. LA VÉRIFICATION DE CERTIFICAT MORD
// =============================================================================================

/// LE test qui distingue ce seam d'un tunnel qui accepte tout : face à un pair présentant une chaîne
/// bien formée mais NON ANCRÉE dans une racine de confiance (exactement ce que présente un MITM),
/// `connect` ÉCHOUE — et elle échoue AU HANDSHAKE, donc l'appelant n'obtient aucun flux et ne peut
/// écrire aucun octet (aucun `client_secret`, aucun jeton de canal) vers ce pair.
///
/// CONTRÔLE DANS LE MÊME TEST : le MÊME port, joint en `Scheme::Http`, rend un `Ok`. Le refus ci-dessus
/// est donc bien le VERDICT DU VÉRIFICATEUR, pas une cible injoignable.
///
/// MUTATION (faite, puis annulée) : ajouter l'AC de test aux racines de `client_config` -> le handshake
/// RÉUSSIT et ce test rougit. Sa couleur est donc gouvernée par la DÉCISION DE CONFIANCE — et cette
/// même mutation sert de CONTRÔLE POSITIF : elle prouve que le seam mène un handshake vérifié jusqu'au
/// bout quand la confiance est établie (indémontrable autrement sans réseau).
#[test]
fn tls_handshake_rejects_untrusted_certificate() {
    let (addr, server) = spawn_untrusted_tls_server(2);
    let timeout = Duration::from_secs(5);

    // `.err()` plutôt que `expect_err` : `Conn` n'implémente PAS `Debug` — une session TLS ne doit pas
    // pouvoir être imprimée par accident (clés, état de handshake). L'assertion reste la même.
    let err = connect(&addr, UNTRUSTED_HOST, Scheme::Https, timeout)
        .err()
        .expect("une chaîne non fiable DOIT faire échouer la connexion");
    let low = err.to_ascii_lowercase();
    assert!(low.contains("handshake tls"), "l'échec doit être nommé comme un échec de handshake: {err}");
    assert!(
        low.contains("certificat") || low.contains("unknownissuer"),
        "l'échec doit désigner le certificat/l'émetteur inconnu: {err}"
    );

    // Contrôle de joignabilité : même adresse, transport clair -> connexion établie.
    assert!(
        connect(&addr, UNTRUSTED_HOST, Scheme::Http, timeout).is_ok(),
        "le port est joignable — le refus https vient bien du vérificateur"
    );
    server.join().expect("thread serveur");
}

/// La config TLS est construite avec des racines NON VIDES et le provider `ring` explicite ; elle est
/// PARTAGÉE (une seule construction pour tout le processus, donc une seule politique de confiance).
#[test]
fn tls_client_config_has_roots_and_is_shared() {
    assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty(), "racines Mozilla compilées");
    let a = client_config().expect("config TLS");
    let b = client_config().expect("config TLS");
    assert!(Arc::ptr_eq(&a, &b), "une seule config TLS pour tout le processus");
}

/// Un hôte de vérification syntaxiquement invalide est refusé AVANT toute E/S (on ne se connecte pas
/// « au hasard » pour découvrir ensuite qu'on ne sait pas quoi vérifier).
#[test]
fn tls_refuses_an_unusable_verification_host() {
    let (addr, server) = spawn_untrusted_tls_server(1);
    let e = connect(&addr, "hôte invalide!", Scheme::Https, Duration::from_secs(5))
        .err()
        .expect("nom d'hôte invalide -> refus");
    assert!(e.contains("nom d'hôte TLS invalide"), "message attendu, obtenu: {e}");
    // Le serveur attend toujours une connexion : on la lui donne pour qu'il termine.
    let _ = connect(&addr, UNTRUSTED_HOST, Scheme::Http, Duration::from_secs(5));
    server.join().expect("thread serveur");
}

// =============================================================================================
//  3. AUCUNE ÉCHAPPATOIRE DE VÉRIFICATION DANS LA SOURCE
// =============================================================================================

/// Garde de SOURCE (même idiome que `tests/test_portability_guard.py` et son marqueur
/// `portability-ok`) : aucun fichier de `console/src` n'a le droit d'ouvrir l'API `dangerous` de
/// rustls, d'installer un vérificateur de certificat maison, ni de porter un drapeau « accepter
/// n'importe quel certificat ». C'est ce qui rend l'invariant #2 du module VÉRIFIABLE une fois pour
/// toutes, y compris contre un ajout futur dans un autre module.
///
/// Une ligne peut être blanchie explicitement par le marqueur `tls-danger-ok` (les lignes qui DÉFINISSENT
/// les motifs ci-dessous le portent — sinon la garde se déclencherait sur elle-même).
///
/// MUTATION : ouvrir l'API dangereuse de rustls dans `tls.rs` -> ce test rougit (vérifié).
#[test]
fn tls_source_carries_no_verification_escape_hatch() {
    // Motifs interdits — chacun est UNE façon connue de neutraliser la vérification.
    const FORBIDDEN: &[&str] = &[
        ".dangerous(",              // tls-danger-ok — rustls : seule porte vers un vérificateur maison
        "set_certificate_verifier", // tls-danger-ok — l'installation elle-même
        "ServerCertVerifier",       // tls-danger-ok — implémenter le trait = se donner le droit de tout accepter
        "danger_accept_invalid",    // tls-danger-ok — idiome reqwest/native-tls
        "insecure_skip_verify",     // tls-danger-ok — idiome Go, cité dans les demandes de contournement
    ];
    const PRAGMA: &str = "tls-danger-ok";

    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rs_files(&src, &mut files);
    assert!(files.len() > 20, "la garde doit scanner tout le crate, {} fichiers trouvés", files.len());

    let mut violations: Vec<String> = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else { continue };
        for (i, line) in text.lines().enumerate() {
            if line.contains(PRAGMA) {
                continue;
            }
            for needle in FORBIDDEN {
                if line.contains(needle) {
                    violations.push(format!("{}:{} — {needle}", f.display(), i + 1));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "échappatoire de vérification TLS dans la source (un TLS qui ne vérifie rien est du clair \
         déguisé) :\n{}",
        violations.join("\n")
    );
}

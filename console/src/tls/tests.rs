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

// ---------------------------------------------------------------------------------------------
//  Matériel de test #2 : une SECONDE AC, sans aucun lien avec la première, et une feuille EXPIRÉE
//  qu'elle signe. Elle sert à deux mesures que la première AC seule ne permet pas :
//    - « UNE AUTRE CA fournie en PEM d'entreprise laisse échouer » — sans quoi on ne saurait pas si
//      le knob VÉRIFIE ou s'il GOBE (une implémentation qui accepterait tout passerait le test
//      positif tout seul) ;
//    - « l'EXPIRATION reste honorée, ancre d'entreprise en place » — le contrôle le plus facile à
//      perdre en croyant « juste ajouter une ancre ».
//  ECDSA P-256. AC : 100 ans. Feuille : SAN `expired.test` (+127.0.0.1), VALIDITÉ RÉVOLUE (jan. 2020).
// ---------------------------------------------------------------------------------------------

/// Seconde AC de test, en PEM — la forme EXACTE sous laquelle un opérateur fournit sa CA d'entreprise.
const ENTERPRISE_CA2_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBsDCCAVegAwIBAgIUdGL8jyNuqre8v3ipd3/h77TaiDIwCgYIKoZIzj0EAwIw
JTEjMCEGA1UEAwwaZm9yZ2UtdGVzdC1lbnRlcnByaXNlLWNhLTIwIBcNMjYwODA2
MTIzMDUxWhgPMjEyNjA3MTMxMjMwNTFaMCUxIzAhBgNVBAMMGmZvcmdlLXRlc3Qt
ZW50ZXJwcmlzZS1jYS0yMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXp5w1dtw
/biJ2Rw5Dm+DzcvlEdJJV08gDTZYdUshfani0TJGCA6EpN3t886AaxLLajsRZfJ7
CUWKefN93/3I0KNjMGEwHQYDVR0OBBYEFISZV+5KDlyeTiprVXmgUYr50A7mMB8G
A1UdIwQYMBaAFISZV+5KDlyeTiprVXmgUYr50A7mMA8GA1UdEwEB/wQFMAMBAf8w
DgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0cAMEQCIDFzrVl1xQzmgr+5l6G7
AGG5DJz5ldhaQl51Hqoopp1AAiAmsguX8JJ+glEKjIlaLwsvf10Q3su1nqMDIfCg
VzxKsQ==
-----END CERTIFICATE-----
";

/// La même AC #2, en DER base64 — pour la CHAÎNE que sert le serveur jetable.
const ENTERPRISE_CA2_DER_B64: &str = "MIIBsDCCAVegAwIBAgIUdGL8jyNuqre8v3ipd3/h77TaiDIwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwaZm9yZ2UtdGVzdC1lbnRlcnByaXNlLWNhLTIwIBcNMjYwODA2MTIzMDUxWhgPMjEyNjA3MTMxMjMwNTFaMCUxIzAhBgNVBAMMGmZvcmdlLXRlc3QtZW50ZXJwcmlzZS1jYS0yMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXp5w1dtw/biJ2Rw5Dm+DzcvlEdJJV08gDTZYdUshfani0TJGCA6EpN3t886AaxLLajsRZfJ7CUWKefN93/3I0KNjMGEwHQYDVR0OBBYEFISZV+5KDlyeTiprVXmgUYr50A7mMB8GA1UdIwQYMBaAFISZV+5KDlyeTiprVXmgUYr50A7mMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0cAMEQCIDFzrVl1xQzmgr+5l6G7AGG5DJz5ldhaQl51Hqoopp1AAiAmsguX8JJ+glEKjIlaLwsvf10Q3su1nqMDIfCgVzxKsQ==";

/// Feuille serveur EXPIRÉE (jan. 2020) signée par l'AC #2. Chaîne PARFAITE, ancre FOURNIE — seule la
/// VALIDITÉ TEMPORELLE manque.
const EXPIRED_CERT_DER_B64: &str = "MIIB0zCCAXqgAwIBAgIUKqlr2lRd8iPlLTq4eVBtcpr+lFQwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwaZm9yZ2UtdGVzdC1lbnRlcnByaXNlLWNhLTIwHhcNMjAwMTAxMDAwMDAwWhcNMjAwMjAxMDAwMDAwWjAXMRUwEwYDVQQDDAxleHBpcmVkLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQfQM+Nhhg0j0mW6nKe5MAcruxWW3L6MtzbRUnmlU4og4NRsJVqmaB8tzMq02mbp5nbaxjAcuqqD0c6w1xIHU8do4GVMIGSMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdEQQWMBSCDGV4cGlyZWQudGVzdIcEfwAAATAdBgNVHQ4EFgQUObvtBVFfB2uYlbYBUQyPdtyJod0wHwYDVR0jBBgwFoAUhJlX7koOXJ5OKmtVeaBRivnQDuYwCgYIKoZIzj0EAwIDRwAwRAIgYG5PZU9izdXAYAKkEM0sqPLwknjCRn0HnLhpZGykSisCIGCwJK0zBhJKvqIAHoV6qWFXWvoPFmUxz+n4eAlW3F3g";

/// Clé privée de la feuille expirée (PKCS#8 DER, base64). Matériel de TEST uniquement.
const EXPIRED_KEY_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPgmV38loVqvx3ILOdgczD3CLBGUf04yKfpVtt6v0s+qhRANCAAQfQM+Nhhg0j0mW6nKe5MAcruxWW3L6MtzbRUnmlU4og4NRsJVqmaB8tzMq02mbp5nbaxjAcuqqD0c6w1xIHU8d";

/// Feuille serveur VALIDE signée par la MÊME AC #2, MÊME sujet, MÊME SAN — SEULE la fenêtre de
/// validité change. C'est le CONTRÔLE du test d'expiration : sans elle, « refusé » pourrait venir de
/// n'importe quoi d'autre dans la chaîne.
const LIVE_CERT_DER_B64: &str = "MIIB1jCCAXygAwIBAgIUOn87EgIL8XMAv1vge9q61bz6GQAwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwaZm9yZ2UtdGVzdC1lbnRlcnByaXNlLWNhLTIwIBcNMjYwODA2MTIzNTUxWhgPMjEyNjA3MTMxMjM1NTFaMBcxFTATBgNVBAMMDGV4cGlyZWQudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPTbhs8jIxBIaIqnO0s4dXg6TXJC73Pt+87pXnfEVCki/cnHzQrWgFemeziHl3WsSUfni/d2JGZQghJwFuHkgUWjgZUwgZIwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0RBBYwFIIMZXhwaXJlZC50ZXN0hwR/AAABMB0GA1UdDgQWBBQBLotIe7cHHYXb1AQpKuJZpwBanDAfBgNVHSMEGDAWgBSEmVfuSg5cnk4qa1V5oFGK+dAO5jAKBggqhkjOPQQDAgNIADBFAiEAzuXZyKih0vNDCva02deNIzyqDPc3oxiybAypNE83CkICIGUTv0oIi8Qt/HsP/nWb2xKCLjPyEMA6NxCX04EEI+Wg";

/// Clé privée de la feuille VALIDE (PKCS#8 DER, base64). Matériel de TEST uniquement.
const LIVE_KEY_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguZcf9r1pOO2CSrIAeRZ3smiRj9mt7U6nv2aRxo7zxFShRANCAAT024bPIyMQSGiKpztLOHV4Ok1yQu9z7fvO6V53xFQpIv3Jx80K1oBXpns4h5d1rElH54v3diRmUIIScBbh5IFF";

/// Nom d'hôte porté par la feuille EXPIRÉE (SAN DNS).
const EXPIRED_HOST: &str = "expired.test";

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).expect("base64 de fixture")
}

/// L'AC de test #1 rendue en PEM — construite À PARTIR du DER de la fixture existante, donc c'est
/// EXACTEMENT l'ancre que le serveur jetable utilise, sans seconde source de vérité.
fn untrusted_ca_pem() -> String {
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in UNTRUSTED_CA_DER_B64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 ascii"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Serveur TLS jetable sur loopback, servant la chaîne NON FIABLE ci-dessus (feuille + AC de test).
/// Accepte `accepts` connexions puis meurt. Les erreurs de handshake sont ATTENDUES (le client refuse
/// la chaîne et envoie une alerte) : on les ignore côté serveur.
fn spawn_untrusted_tls_server(accepts: usize) -> (SocketAddr, std::thread::JoinHandle<()>) {
    spawn_tls_server(UNTRUSTED_CERT_DER_B64, UNTRUSTED_CA_DER_B64, UNTRUSTED_KEY_DER_B64, accepts)
}

/// Serveur TLS jetable sur loopback servant une chaîne ARBITRAIRE (feuille + son AC) — la même
/// mécanique pour les DEUX AC de test. Accepte `accepts` connexions puis meurt. Un échec de handshake
/// est un RÉSULTAT possible (c'est même ce que la moitié des tests mesure) : il est ignoré côté serveur.
fn spawn_tls_server(
    leaf_der_b64: &str,
    ca_der_b64: &str,
    key_der_b64: &str,
    accepts: usize,
) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr locale");
    let chain = vec![
        rustls::pki_types::CertificateDer::from(b64(leaf_der_b64)),
        rustls::pki_types::CertificateDer::from(b64(ca_der_b64)),
    ];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(b64(
        key_der_b64,
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

// =============================================================================================
//  2bis. LA CA PRIVÉE D'ENTREPRISE — UNE ANCRE DE PLUS, AUCUN CONTRÔLE DE MOINS
//
//  Le COUPLE qui fait tout : sans le test POSITIF on ne saurait pas si le knob sert à quelque chose ;
//  sans les trois NÉGATIFS on ne saurait pas s'il VÉRIFIE ou s'il GOBE. Les quatre partagent la même
//  fixture et le même seam (`connect_with`), donc ils mesurent bien la MÊME décision de confiance.
// =============================================================================================

/// [POSITIF] La MÊME AC qui fait ÉCHOUER `tls_handshake_rejects_untrusted_certificate`, fournie en PEM
/// d'entreprise, fait ABOUTIR le handshake. C'est la démonstration que le knob EXISTE et OPÈRE.
///
/// MUTATION : ne pas passer `Some(pem)` à `build_client_config` (ou lui faire ignorer le PEM) -> ce
/// test rougit. MUTATION SYMÉTRIQUE : ajouter cette AC aux racines par DÉFAUT -> c'est le test de rejet
/// qui rougit. Les deux couleurs sont donc gouvernées par le PEM, et par rien d'autre.
#[test]
fn enterprise_ca_pem_makes_its_own_chain_verify() {
    let (addr, server) = spawn_untrusted_tls_server(1);
    let cfg = build_client_config(Some(&untrusted_ca_pem())).expect("config avec ancre d'entreprise");
    // `.is_ok()` plutôt que `expect` : `Conn` n'implémente PAS `Debug` (une session TLS ne doit pas
    // pouvoir être imprimée par accident). On capture donc l'erreur AVANT pour la diagnostiquer.
    let r = connect_with(&addr, UNTRUSTED_HOST, Scheme::Https, Duration::from_secs(5), Some(cfg));
    let ok = match r {
        Ok(_) => None,
        Err(e) => Some(e),
    };
    assert!(
        ok.is_none(),
        "l'ancre d'entreprise FOURNIE doit faire ABOUTIR le handshake, obtenu: {}",
        ok.unwrap_or_default()
    );
    server.join().expect("thread serveur");
}

/// [NÉGATIF 1 — CHAÎNE] Une AUTRE CA fournie en PEM d'entreprise NE fait PAS passer la chaîne du
/// serveur. C'est LA mesure qui distingue « ancre de confiance » de « interrupteur de vérification » :
/// un knob qui goberait tout passerait le test positif ci-dessus tout seul.
///
/// MUTATION : faire accepter n'importe quelle chaîne dès qu'un PEM est posé -> ce test rougit.
#[test]
fn enterprise_ca_pem_still_rejects_another_ca() {
    let (addr, server) = spawn_untrusted_tls_server(2);
    // PEM d'entreprise VALIDE et bien chargé… mais c'est l'AC #2, qui n'a rien signé ici.
    let cfg = build_client_config(Some(ENTERPRISE_CA2_PEM)).expect("config avec l'AUTRE ancre");
    let err = connect_with(&addr, UNTRUSTED_HOST, Scheme::Https, Duration::from_secs(5), Some(cfg))
        .err()
        .expect("une ancre SANS RAPPORT ne rend pas la chaîne fiable");
    let low = err.to_ascii_lowercase();
    assert!(low.contains("handshake tls"), "échec de handshake attendu: {err}");
    assert!(
        low.contains("certificat") || low.contains("unknownissuer"),
        "l'échec doit désigner l'émetteur inconnu: {err}"
    );
    // Contrôle de joignabilité : le refus vient du vérificateur, pas d'un port mort.
    assert!(connect_with(&addr, UNTRUSTED_HOST, Scheme::Http, Duration::from_secs(5), None).is_ok());
    server.join().expect("thread serveur");
}

/// [NÉGATIF 2 — NOM D'HÔTE] Ancre d'entreprise EN PLACE et chaîne PARFAITE, mais on vérifie contre un
/// nom que le certificat ne porte pas => REFUS. Ajouter une ancre n'a pas désactivé le contrôle de nom.
///
/// MUTATION : ne plus vérifier le nom d'hôte -> ce test rougit.
#[test]
fn enterprise_ca_pem_still_verifies_the_hostname() {
    let (addr, server) = spawn_untrusted_tls_server(2);
    let cfg = build_client_config(Some(&untrusted_ca_pem())).expect("config avec ancre d'entreprise");
    // La feuille porte SAN `untrusted.test` ; on demande à vérifier `autre.test`.
    let err = connect_with(&addr, "autre.test", Scheme::Https, Duration::from_secs(5), Some(cfg))
        .err()
        .expect("nom d'hôte hors SAN => refus, ancre d'entreprise ou pas");
    let low = err.to_ascii_lowercase();
    assert!(low.contains("handshake tls"), "échec de handshake attendu: {err}");
    assert!(
        low.contains("notvalidforname") || low.contains("certificat"),
        "l'échec doit désigner le nom d'hôte: {err}"
    );
    assert!(connect_with(&addr, UNTRUSTED_HOST, Scheme::Http, Duration::from_secs(5), None).is_ok());
    server.join().expect("thread serveur");
}

/// [NÉGATIF 3 — EXPIRATION] Ancre d'entreprise EN PLACE, chaîne PARFAITE, nom d'hôte CORRECT — mais la
/// feuille a expiré en février 2020 => REFUS. C'est le contrôle le plus facile à perdre en croyant
/// « juste ajouter une ancre » : une CA d'entreprise émet des certificats courts, et un déploiement qui
/// accepterait les périmés ne s'en apercevrait jamais.
///
/// MUTATION : ignorer la validité temporelle -> ce test rougit.
///
/// CONTRE-EXEMPLE INTÉGRÉ, et il est OBLIGATOIRE : sans lui, « refusé » pourrait venir de n'importe
/// quoi d'autre (mauvaise ancre, SAN, EKU, courbe…) et l'assertion ne prouverait rien sur l'expiration.
/// Le contrôle est donc la MÊME AC, le MÊME sujet, le MÊME SAN, la MÊME clé d'ancre — feuille NON
/// expirée : elle ABOUTIT. La seule variable entre les deux moitiés est la FENÊTRE DE VALIDITÉ.
///
/// (Note mesurée : rustls-webpki statue sur la validité temporelle AVANT l'ancrage — sans l'ancre, le
/// pair expiré est refusé pour EXPIRATION, pas pour émetteur inconnu. Une contre-épreuve « sans ancre
/// => unknownissuer » serait donc FAUSSE ; c'est le contrôle ci-dessous qui porte la preuve.)
#[test]
fn enterprise_ca_pem_still_honours_expiry() {
    let timeout = Duration::from_secs(5);
    let cfg = || build_client_config(Some(ENTERPRISE_CA2_PEM)).expect("config avec ancre d'entreprise #2");

    // (1) MESURE — même ancre, feuille EXPIRÉE : REFUS, et le refus NOMME l'expiration.
    let (addr, server) = spawn_tls_server(EXPIRED_CERT_DER_B64, ENTERPRISE_CA2_DER_B64, EXPIRED_KEY_DER_B64, 1);
    let err = connect_with(&addr, EXPIRED_HOST, Scheme::Https, timeout, Some(cfg()))
        .err()
        .expect("une feuille EXPIRÉE est refusée, même signée par l'ancre fournie");
    let low = err.to_ascii_lowercase();
    assert!(low.contains("handshake tls"), "échec de handshake attendu: {err}");
    assert!(low.contains("expired"), "l'échec doit désigner l'EXPIRATION: {err}");
    server.join().expect("thread serveur");

    // (2) CONTRE-EXEMPLE — MÊME ancre, MÊME sujet/SAN, feuille NON expirée : le handshake ABOUTIT.
    //     Sans cette moitié, l'assertion (1) pourrait passer au vert pour une mauvaise raison.
    let (addr, server) = spawn_tls_server(LIVE_CERT_DER_B64, ENTERPRISE_CA2_DER_B64, LIVE_KEY_DER_B64, 1);
    let r = connect_with(&addr, EXPIRED_HOST, Scheme::Https, timeout, Some(cfg()));
    let why = match r {
        Ok(_) => None,
        Err(e) => Some(e),
    };
    assert!(
        why.is_none(),
        "CONTRE-EXEMPLE EN ÉCHEC : la MÊME ancre doit faire ABOUTIR une feuille NON expirée — sinon \
         le refus mesuré en (1) ne prouve rien sur l'expiration. Obtenu: {}",
        why.unwrap_or_default()
    );
    server.join().expect("thread serveur");
}

/// FAIL-CLOSED du knob : un PEM configuré mais INEXPLOITABLE est une ERREUR, jamais une dégradation
/// silencieuse vers « pas d'ancre » — c'est exactement ce qui ferait croire à un opérateur que sa CA
/// est installée. Couvre le PARSING (poubelle, PEM sans bloc CERTIFICATE) et la RÉSOLUTION d'env
/// (`<VAR>_FILE` illisible / vide), plus la précédence du motif maison.
///
/// MUTATION : rendre `Ok(None)` au lieu de `Err` sur PEM invalide -> ce test rougit.
#[test]
fn enterprise_ca_pem_fails_closed_when_unusable() {
    // ⚠️ ANTI-CONTAMINATION, et c'est un vrai risque, pas une précaution de principe : `client_config()`
    // mémoïse la politique de confiance du PROCESSUS dans un `OnceLock`, en la lisant de l'ENVIRONNEMENT.
    // Ce test et `enterprise_ca_pem_from_env_reaches_a_real_handshake` sont les SEULS à poser
    // `FORGE_EXTRA_CA_PEM` (ils se sérialisent entre eux par `env_lock`) — et la suite est PARALLÈLE : si un autre test
    // (`tls_handshake_rejects_untrusted_certificate`, `tls_client_config_has_roots_and_is_shared`,
    // `tls_refuses_an_unusable_verification_host`) provoquait la PREMIÈRE initialisation pendant que la
    // variable est posée, il hériterait de l'ancre de test — et le test de REJET passerait au vert pour
    // la pire des raisons. On force donc l'initialisation ICI, AVANT de toucher à l'environnement : le
    // `OnceLock` est dès lors figé sur « aucune ancre supplémentaire » et la fenêtre n'existe plus.
    let _ = client_config().expect("config de processus");
    // L'env est global au processus : on sérialise malgré tout avec le reste de la suite.
    let _g = crate::testutil::env_lock();

    // --- PARSING (PUR) ---
    assert!(build_client_config(None).is_ok(), "aucun PEM => config standard, cas par défaut");
    for bad in ["ceci n'est pas du PEM", "", "-----BEGIN CERTIFICATE-----\nzzzz\n-----END CERTIFICATE-----\n"] {
        assert!(
            build_client_config(Some(bad)).is_err(),
            "PEM inexploitable accepté en silence: {bad:?}"
        );
    }
    // Un PEM qui ne porte QUE des blocs d'un autre type n'est pas « zéro ancre, tant pis » : c'est un refus.
    let e = build_client_config(Some("-----BEGIN PRIVATE KEY-----\nMIG=\n-----END PRIVATE KEY-----\n"))
        .expect_err("aucun bloc CERTIFICATE => refus");
    assert!(e.contains(EXTRA_CA_VAR), "le refus doit NOMMER la variable, obtenu: {e}");

    // --- RÉSOLUTION D'ENV (motif maison : <VAR> puis <VAR>_FILE) ---
    // Ce test est le SEUL à toucher ces variables, et il les retire toujours.
    let file_var = format!("{EXTRA_CA_VAR}_FILE");
    std::env::remove_var(EXTRA_CA_VAR);
    std::env::remove_var(&file_var);
    assert_eq!(extra_ca_pem_from_env().expect("rien de posé => Ok"), None, "rien configuré => aucune ancre");

    // Variable DIRECTE : porte le PEM verbatim.
    std::env::set_var(EXTRA_CA_VAR, ENTERPRISE_CA2_PEM);
    assert_eq!(extra_ca_pem_from_env().expect("Ok").as_deref(), Some(ENTERPRISE_CA2_PEM));
    assert!(preflight().expect("preflight OK").is_some(), "ancre chargée => ligne de boot annoncée");
    std::env::remove_var(EXTRA_CA_VAR);

    // Jumeau `_FILE` : porte un CHEMIN. Fichier ABSENT => Err (et NON `None` : c'est LA différence
    // assumée avec `secret_env::secret_from_env`, qui est fail-SOFT).
    std::env::set_var(&file_var, "/nonexistent/forge/ca/does-not-exist.pem");
    let e = extra_ca_pem_from_env().expect_err("PEM configuré mais illisible => Err");
    assert!(e.contains(&file_var), "le refus doit NOMMER la variable, obtenu: {e}");
    assert!(preflight().is_err(), "le boot doit MOURIR sur un PEM illisible");
    // Fichier PRÉSENT mais vide => Err aussi (zéro ancre silencieuse).
    let empty = crate::testutil::tmp_path("forge-extra-ca-vide.pem");
    std::fs::write(&empty, "   \n").expect("écriture fixture");
    std::env::set_var(&file_var, &empty);
    assert!(extra_ca_pem_from_env().is_err(), "PEM vide => Err, jamais « pas d'ancre »");
    // Fichier PRÉSENT et valide => chargé.
    let good = crate::testutil::tmp_path("forge-extra-ca.pem");
    std::fs::write(&good, ENTERPRISE_CA2_PEM).expect("écriture fixture");
    std::env::set_var(&file_var, &good);
    assert_eq!(extra_ca_pem_from_env().expect("Ok").as_deref(), Some(ENTERPRISE_CA2_PEM));
    // PRÉCÉDENCE : la variable directe prime sur le jumeau `_FILE`.
    std::env::set_var(EXTRA_CA_VAR, &untrusted_ca_pem());
    assert_eq!(extra_ca_pem_from_env().expect("Ok").as_deref(), Some(untrusted_ca_pem().as_str()));

    std::env::remove_var(EXTRA_CA_VAR);
    std::env::remove_var(&file_var);
    let _ = std::fs::remove_file(&empty);
    let _ = std::fs::remove_file(&good);
}

/// [JOINTURE] DE LA VARIABLE JUSQU'AU HANDSHAKE — le scénario que vit réellement l'exploitant.
///
/// Le couple ci-dessus prouve les deux moitiés SÉPARÉMENT : d'un côté « l'env rend bien le PEM »
/// (comparaison de chaînes), de l'autre « un PEM passé EN PARAMÈTRE fait aboutir la chaîne ». Entre
/// les deux, rien ne vérifiait que le PEM SORTI DE L'ENV est utilisable pour un vrai handshake — un
/// `_FILE` lu avec un BOM, une fin de ligne mangée, une précédence inversée passeraient toutes les
/// assertions d'égalité et casseraient l'unique usage réel. La composition testée ici est
/// EXACTEMENT celle de `client_config()` : `build_client_config(extra_ca_pem_from_env()?.as_deref())`.
///
/// POURQUOI UN TEST À PART, et c'est le point : la jointure vivait d'abord DANS
/// `enterprise_ca_pem_fails_closed_when_unusable`, et les mutations n'y arrivaient JAMAIS — les
/// assertions antérieures du même test avortaient avant elle. Un test qui ne s'EXÉCUTE pas sous
/// mutation ne prouve rien, quel que soit son contenu. Isolé, il rougit (vérifié : `build_client_config`
/// qui jette son paramètre, et `extra_ca_pem_from_env` qui rend `Ok(None)`).
///
/// LIMITE ASSUMÉE : ce test REPRODUIT la composition de `client_config()`, il ne l'APPELLE pas —
/// `client_config()` mémoïse dans un `OnceLock` et n'est donc pas re-testable après coup. Un défaut
/// interne à cette fonction d'une ligne resterait invisible ici.
#[test]
fn enterprise_ca_pem_from_env_reaches_a_real_handshake() {
    // Même anti-contamination que le test voisin : on fige le `OnceLock` du processus sur « aucune
    // ancre » AVANT de toucher l'environnement, sinon un test parallèle pourrait hériter de l'ancre
    // de test et passer au vert pour la pire des raisons.
    let _ = client_config().expect("config de processus");
    let _g = crate::testutil::env_lock();
    let file_var = format!("{EXTRA_CA_VAR}_FILE");
    std::env::remove_var(EXTRA_CA_VAR);
    std::env::remove_var(&file_var);

    // POSITIF : la variable posée, la chaîne du serveur devient fiable.
    std::env::set_var(EXTRA_CA_VAR, untrusted_ca_pem());
    let (addr, server) = spawn_untrusted_tls_server(1);
    let cfg = build_client_config(extra_ca_pem_from_env().expect("Ok").as_deref())
        .expect("config bâtie DEPUIS l'environnement");
    // `Conn` n'implémente pas `Debug` (une session TLS ne doit pas pouvoir être imprimée par
    // accident) : on capture l'erreur avant d'assertir.
    let err = match connect_with(&addr, UNTRUSTED_HOST, Scheme::Https, Duration::from_secs(5), Some(cfg)) {
        Ok(_) => None,
        Err(e) => Some(e),
    };
    server.join().expect("thread serveur");
    std::env::remove_var(EXTRA_CA_VAR);
    assert!(
        err.is_none(),
        "la CA posée dans {EXTRA_CA_VAR} doit faire ABOUTIR le handshake, obtenu: {}",
        err.unwrap_or_default()
    );

    // CONTRE-EXEMPLE, sans quoi l'aboutissement ci-dessus pourrait venir d'une confiance acquise
    // AILLEURS (racines par défaut polluées, config héritée) plutôt que de la variable : variable
    // retirée, la MÊME chaîne redevient refusée.
    let (addr, server) = spawn_untrusted_tls_server(1);
    let cfg = build_client_config(extra_ca_pem_from_env().expect("Ok").as_deref())
        .expect("config standard, sans ancre d'entreprise");
    let refused =
        connect_with(&addr, UNTRUSTED_HOST, Scheme::Https, Duration::from_secs(5), Some(cfg)).is_err();
    server.join().expect("thread serveur");
    assert!(
        refused,
        "sans {EXTRA_CA_VAR}, la même chaîne DOIT redevenir refusée — sinon la confiance ne vient pas de la variable"
    );
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

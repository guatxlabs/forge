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

// ---------------------------------------------------------------------------------------------
//  Matériel de test #3 : une AC CLIENTE et la feuille CLIENTE qu'elle signe — c'est-à-dire NOTRE
//  identité, celle que la console PRÉSENTE quand le pair l'exige (mTLS).
//
//  POURQUOI UNE TROISIÈME AC PLUTÔT QUE RÉUTILISER LA FEUILLE #1 : rustls-webpki vérifie un certificat
//  CLIENT avec `KeyUsage::client_auth()`. La feuille #1 porte l'EKU `serverAuth` — un serveur mTLS la
//  refuserait pour la MAUVAISE raison (mauvais EKU), et le test positif ne pourrait jamais passer au
//  vert. La feuille ci-dessous porte donc `clientAuth`, `CA:FALSE`, SAN `forge-console-client`.
//  ECDSA P-256, 100 ans. Les DEUX PEM sont sous la forme EXACTE que l'opérateur pose dans
//  `FORGE_CLIENT_CERT_PEM` / `FORGE_CLIENT_KEY_PEM`.
// ---------------------------------------------------------------------------------------------

/// AC CLIENTE de test — la seule autorité dont le serveur jetable accepte une identité.
const CLIENT_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBpjCCAUugAwIBAgIUMmdTBaKLbBnKfkCI2frFc6tHmkkwCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUZm9yZ2UtdGVzdC1jbGllbnQtY2EwIBcNMjYwODA2MjA1MDM0
WhgPMjEyNjA3MTMyMDUwMzRaMB8xHTAbBgNVBAMMFGZvcmdlLXRlc3QtY2xpZW50
LWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBw17zdcRfGmx0Kk3IbDhlEix
ocfg4dQm/5yJckauHBkMLI7beneDpMqWxfknX7wmnA/vgTKU6/8/4dJ81TV34qNj
MGEwHQYDVR0OBBYEFLLQHTO6Q3uwM6XkyhsoZ5rth8FGMB8GA1UdIwQYMBaAFLLQ
HTO6Q3uwM6XkyhsoZ5rth8FGMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgEGMAoGCCqGSM49BAMCA0kAMEYCIQDJoBKS3ANEbnMWsKei7MDSVMRnpww0Abmf
qugLXSQUYAIhALQblMuM/Hh/LnPlojVnWEc/AesYkW7HYg3UT0c6XIb6
-----END CERTIFICATE-----
";

/// NOTRE certificat client (feuille signée par l'AC ci-dessus, EKU `clientAuth`).
const CLIENT_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIB2zCCAYCgAwIBAgIUcPqy/p8W65zS/31VmD8+sVKmPRAwCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUZm9yZ2UtdGVzdC1jbGllbnQtY2EwIBcNMjYwODA2MjA1MDM0
WhgPMjEyNjA3MTMyMDUwMzRaMB8xHTAbBgNVBAMMFGZvcmdlLWNvbnNvbGUtY2xp
ZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmxcZcz7tAqOIW5KG1t8x1IPt
EGQvIaNwxivbgzEH8nrh/nL8vFmbpaxV3uysgMgrR0ZUw7hmv7Wam7Ote5uiJ6OB
lzCBlDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
BgEFBQcDAjAfBgNVHREEGDAWghRmb3JnZS1jb25zb2xlLWNsaWVudDAdBgNVHQ4E
FgQUvXjB2B4Ybha/cSP3zB3ka8gUDC4wHwYDVR0jBBgwFoAUstAdM7pDe7AzpeTK
Gyhnmu2HwUYwCgYIKoZIzj0EAwIDSQAwRgIhAOtlb5BCDV7ZIus0VfcVNGliRCc5
sy00MalAoxFxQuIvAiEAtT1D9RMn7mG7j9IPO/xSj4EWZTjhuyfgJfGEDZfP4fI=
-----END CERTIFICATE-----
";

/// La CLÉ PRIVÉE de ce certificat (PKCS#8). Matériel de TEST : elle ne protège rien. C'est néanmoins
/// elle que balaient `client_key_material_never_leaks_into_*` — le corps base64 ci-dessous ne doit
/// apparaître dans AUCUNE sortie du binaire.
const CLIENT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTEnZxFJkDk8i6Z3O
/t///C9i97J54ksHJT/YALJQqV+hRANCAASbFxlzPu0Co4hbkobW3zHUg+0QZC8h
o3DGK9uDMQfyeuH+cvy8WZulrFXe7KyAyCtHRlTDuGa/tZqbs617m6In
-----END PRIVATE KEY-----
";

/// Une clé P-256 VALIDE mais SANS AUCUN RAPPORT avec `CLIENT_CERT_PEM` — le DÉPAREILLAGE, c'est-à-dire
/// la faute qu'un opérateur commet en renouvelant l'un sans l'autre.
const OTHER_CLIENT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgI0v6wqNHlW/qVi2B
zJW63jG8eE2HjkwXLFJYN3Zvfy2hRANCAAQBlJTUCQGSP3ynivSC8obhWvbRTS/j
ObqpcRRfnOQWWtD4eXOH3y1tDCIwQfKAhlldvXnhD9GkwSCNTOaw9qwG
-----END PRIVATE KEY-----
";

/// Octets applicatifs que le serveur mTLS n'écrit QU'APRÈS avoir authentifié le pair. Les lire est la
/// preuve, côté client, d'avoir été accepté.
const MTLS_BANNER: &[u8] = b"FORGE-MTLS-OK";

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

/// Verdict SERVEUR d'une connexion mTLS — la moitié serveur de la mesure. Sans elle, un test client qui
/// échoue ne dirait pas si c'est le pair qui a refusé, ou n'importe quoi d'autre.
struct MtlsVerdict {
    /// Le handshake est-il allé à son terme côté serveur ?
    handshake_ok: bool,
    /// Le serveur a-t-il reçu et vérifié un certificat CLIENT ?
    peer_authenticated: bool,
}

/// Serveur TLS jetable qui **EXIGE** un certificat client, ancré sur [`CLIENT_CA_PEM`]. Il sert la même
/// chaîne serveur que les autres (feuille #1 + AC #1), donc le client la vérifie EXACTEMENT comme
/// ailleurs, via l'ancre d'entreprise — les deux authentifications restent bien distinctes.
///
/// ⚠️ LA BANNIÈRE EST ÉCRITE DÈS QUE LE HANDSHAKE ABOUTIT, sans regarder `peer_certificates()`, et ce
/// détail est TOUT le test négatif. Première version : le serveur n'écrivait la bannière QUE s'il avait
/// vu un certificat client. La mutation de contrôle (remplacer `WebPkiClientVerifier` par
/// `with_no_client_auth`) restait alors VERTE — un constat sur le test, pas un succès : le refus venait
/// de CE `if`, pas de l'EXIGENCE du pair, et le test ne prouvait donc rien sur `with_client_auth_cert`.
/// La bannière ne mesure plus qu'une chose, la bonne : « la session porte des octets applicatifs ». Le
/// verdict `peer_authenticated` reste rendu à part, pour le test POSITIF.
fn spawn_mtls_server() -> (SocketAddr, std::thread::JoinHandle<MtlsVerdict>) {
    use rustls::pki_types::pem::PemObject;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr locale");
    let chain = vec![
        rustls::pki_types::CertificateDer::from(b64(UNTRUSTED_CERT_DER_B64)),
        rustls::pki_types::CertificateDer::from(b64(UNTRUSTED_CA_DER_B64)),
    ];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(b64(
        UNTRUSTED_KEY_DER_B64,
    )));
    // Magasin d'AC CLIENTES : la seule autorité dont ce serveur accepte une identité.
    let mut client_roots = rustls::RootCertStore::empty();
    for der in rustls::pki_types::CertificateDer::pem_slice_iter(CLIENT_CA_PEM.as_bytes()) {
        client_roots.add(der.expect("AC cliente de test")).expect("ancre cliente");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // ⚠️ C'EST LA LIGNE QUI DONNE SON SENS AU COUPLE : `WebPkiClientVerifier` (par opposition à
    // `with_no_client_auth`, utilisé par l'autre serveur jetable) EXIGE un certificat client. La
    // remplacer fait passer au VERT le test négatif — c'est la mutation qui prouve qu'il mesure bien
    // une EXIGENCE du pair et pas un hasard.
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots),
        provider.clone(),
    )
    .build()
    .expect("vérificateur de certificat client");
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions TLS")
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .expect("chaîne+clé serveur de test"),
    );
    let h = std::thread::spawn(move || {
        let refused = MtlsVerdict { handshake_ok: false, peer_authenticated: false };
        let Ok((mut sock, _)) = listener.accept() else { return refused };
        sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
        sock.set_write_timeout(Some(Duration::from_secs(2))).ok();
        let Ok(mut session) = rustls::ServerConnection::new(cfg) else { return refused };
        // Handshake mené à terme : c'est ICI que le certificat client est exigé et vérifié. Un client
        // sans identité fait échouer ce `complete_io` (rustls y flushe l'alerte avant de rendre l'erreur,
        // donc le client la voit) — et c'est POUR ÇA que la bannière plus bas n'est jamais atteinte.
        let mut rounds = 0usize;
        while session.is_handshaking() {
            rounds += 1;
            if rounds > 8 || session.complete_io(&mut sock).is_err() {
                return refused;
            }
        }
        let peer_authenticated = matches!(session.peer_certificates(), Some(c) if !c.is_empty());
        // INCONDITIONNEL (cf. le doc ci-dessus) : ce que la bannière mesure, c'est que le handshake a
        // abouti — donc que le pair n'a RIEN exigé qu'on n'ait fourni.
        if session.writer().write_all(MTLS_BANNER).is_err() {
            return MtlsVerdict { handshake_ok: true, peer_authenticated };
        }
        let _ = session.complete_io(&mut sock);
        MtlsVerdict { handshake_ok: true, peer_authenticated }
    });
    (addr, h)
}

/// Aboutissement MESURÉ côté client : le handshake, PUIS la première lecture APPLICATIVE.
///
/// POURQUOI PAS SEULEMENT `connect_with` — et c'est la subtilité de tout ce couple : en TLS 1.3 le
/// client considère son handshake terminé dès qu'il a envoyé son `Finished`. Le VERDICT du serveur sur
/// notre certificat (alerte `certificate_required`) n'arrive qu'ENSUITE. Un test qui s'arrêterait à
/// `connect_with` mesurerait donc « on a parlé », pas « on a été accepté ». On lit la bannière que le
/// serveur n'écrit qu'après nous avoir authentifiés : c'est la seule mesure qui vaut pour les deux
/// versions du protocole.
fn mtls_read_banner(addr: &SocketAddr, cfg: Arc<rustls::ClientConfig>) -> Result<String, String> {
    let mut conn = connect_with(addr, UNTRUSTED_HOST, Scheme::Https, Duration::from_secs(5), Some(cfg))?;
    let mut buf = [0u8; 64];
    let n = conn
        .read(&mut buf)
        .map_err(|e| format!("lecture applicative refusée: {e}"))?;
    if n == 0 {
        return Err("le pair a fermé sans un seul octet applicatif".to_string());
    }
    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

/// Construit une identité cliente à partir de deux PEM. Les champs sont privés au module `tls` — un
/// `mod tests` enfant y accède, la production non : elle ne peut fabriquer une identité QUE par
/// [`client_identity_from_env`].
fn identity(cert_pem: &str, key_pem: &str) -> ClientIdentityPem {
    ClientIdentityPem { cert: cert_pem.to_string(), key: key_pem.to_string() }
}

/// Toutes les FENÊTRES de 12 caractères du CORPS base64 d'une clé PEM (en-têtes exclus).
///
/// POURQUOI DES FENÊTRES ET PAS UNE SENTINELLE : une sortie qui ne recopierait « qu'un bout » de la clé
/// est tout aussi disqualifiante, et une sentinelle unique ne l'attraperait pas. 12 caractères de
/// l'alphabet base64 ≈ 72 bits : aucune collision fortuite avec un message d'erreur en français.
fn key_body_windows(key_pem: &str) -> Vec<String> {
    let body: Vec<char> = key_pem
        .lines()
        .filter(|l| !l.trim_start().starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    assert!(body.len() > 40, "fixture de clé inattendue ({} car.)", body.len());
    body.windows(12).map(|w| w.iter().collect()).collect()
}

/// Assertion de CONFINEMENT : aucun fragment du corps de `key_pem` n'apparaît dans `haystack`.
fn assert_no_key_material(haystack: &str, key_pem: &str, what: &str) {
    for w in key_body_windows(key_pem) {
        assert!(
            !haystack.contains(&w),
            "FUITE DE CLÉ PRIVÉE dans {what} : le fragment {w:?} du corps de la clé apparaît dans la \
             sortie.\nSortie complète : {haystack}"
        );
    }
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
    let cfg = build_client_config(Some(&untrusted_ca_pem()), None).expect("config avec ancre d'entreprise");
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
    let cfg = build_client_config(Some(ENTERPRISE_CA2_PEM), None).expect("config avec l'AUTRE ancre");
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
    let cfg = build_client_config(Some(&untrusted_ca_pem()), None).expect("config avec ancre d'entreprise");
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
    let cfg = || build_client_config(Some(ENTERPRISE_CA2_PEM), None).expect("config avec ancre d'entreprise #2");

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
    assert!(build_client_config(None, None).is_ok(), "aucun PEM => config standard, cas par défaut");
    for bad in ["ceci n'est pas du PEM", "", "-----BEGIN CERTIFICATE-----\nzzzz\n-----END CERTIFICATE-----\n"] {
        assert!(
            build_client_config(Some(bad), None).is_err(),
            "PEM inexploitable accepté en silence: {bad:?}"
        );
    }
    // Un PEM qui ne porte QUE des blocs d'un autre type n'est pas « zéro ancre, tant pis » : c'est un refus.
    let e = build_client_config(Some("-----BEGIN PRIVATE KEY-----\nMIG=\n-----END PRIVATE KEY-----\n"), None)
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
/// EXACTEMENT celle de `client_config()` : `build_client_config(extra_ca_pem_from_env()?.as_deref(), client_identity_from_env()?.as_ref())`.
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
    let cfg = build_client_config(extra_ca_pem_from_env().expect("Ok").as_deref(), None)
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
    let cfg = build_client_config(extra_ca_pem_from_env().expect("Ok").as_deref(), None)
        .expect("config standard, sans ancre d'entreprise");
    let refused =
        connect_with(&addr, UNTRUSTED_HOST, Scheme::Https, Duration::from_secs(5), Some(cfg)).is_err();
    server.join().expect("thread serveur");
    assert!(
        refused,
        "sans {EXTRA_CA_VAR}, la même chaîne DOIT redevenir refusée — sinon la confiance ne vient pas de la variable"
    );
}

// =============================================================================================
//  2ter. mTLS — L'IDENTITÉ QUE NOUS PRÉSENTONS
//
//  Le COUPLE, et il est indissociable : sans le NÉGATIF, on ne saurait pas si le serveur de test EXIGE
//  réellement un certificat — le positif passerait au vert même contre un pair qui n'en demande aucun,
//  et ne prouverait donc RIEN sur `with_client_auth_cert`. Les deux tests partagent le MÊME serveur
//  ([`spawn_mtls_server`]) et le MÊME chemin client ([`mtls_read_banner`]) : la seule variable entre
//  eux est la présence de l'identité.
// =============================================================================================

/// [POSITIF] Identité cliente configurée => le pair mTLS nous AUTHENTIFIE et la session porte des
/// octets applicatifs. Mesuré des DEUX côtés : le serveur confirme avoir vu un certificat client, le
/// client lit la bannière que le serveur n'écrit qu'après.
///
/// MUTATION : faire ignorer `client_identity` par `build_client_config` (retomber sur
/// `with_no_client_auth`) -> ce test rougit.
#[test]
fn mtls_client_certificate_is_presented_and_accepted() {
    let (addr, server) = spawn_mtls_server();
    let id = identity(CLIENT_CERT_PEM, CLIENT_KEY_PEM);
    // L'ancre d'entreprise sert à vérifier le SERVEUR ; l'identité sert à nous authentifier AUPRÈS de
    // lui. Les deux dans la même config, et elles ne se marchent pas dessus.
    let cfg = build_client_config(Some(&untrusted_ca_pem()), Some(&id)).expect("config avec identité cliente");
    let banner = mtls_read_banner(&addr, cfg);
    let v = server.join().expect("thread serveur");
    assert!(v.handshake_ok, "le handshake mTLS doit aboutir côté serveur");
    assert!(
        v.peer_authenticated,
        "le serveur mTLS doit avoir AUTHENTIFIÉ le pair (certificat client reçu et vérifié)"
    );
    assert_eq!(
        banner.as_deref(),
        Ok(std::str::from_utf8(MTLS_BANNER).expect("bannière ascii")),
        "le client doit lire les octets applicatifs que le pair n'écrit qu'après nous avoir acceptés"
    );
}

/// [NÉGATIF] AUCUNE identité configurée, MÊME serveur => le pair nous REFUSE et la session ne porte
/// AUCUN octet applicatif. C'est ce test qui donne son sens au positif : il établit que le serveur
/// EXIGE bien quelque chose.
///
/// MUTATION : remplacer `WebPkiClientVerifier` par `with_no_client_auth` dans [`spawn_mtls_server`]
/// -> ce test rougit (le pair anonyme serait accepté).
#[test]
fn mtls_peer_refuses_us_without_a_client_certificate() {
    let (addr, server) = spawn_mtls_server();
    // MÊME config que le positif, à l'identité près.
    let cfg = build_client_config(Some(&untrusted_ca_pem()), None).expect("config SANS identité cliente");
    let outcome = mtls_read_banner(&addr, cfg);
    let v = server.join().expect("thread serveur");
    // L'ASSERTION QUI PORTE LA PREUVE : le pair EXIGE un certificat, donc le handshake n'aboutit pas et
    // la session ne porte AUCUN octet applicatif. La bannière étant écrite dès que le handshake aboutit
    // (cf. `spawn_mtls_server`), un pair qui n'exigerait rien la ferait lire ici -> rouge.
    assert!(
        outcome.is_err(),
        "sans certificat client, la session ne doit porter AUCUN octet applicatif — obtenu: {outcome:?}"
    );
    assert!(!v.handshake_ok, "le handshake ne doit PAS aboutir face à un pair qui exige un certificat");
    assert!(!v.peer_authenticated, "le serveur mTLS ne doit avoir authentifié PERSONNE");
}

/// PAS DE RUPTURE POUR LES INSTALLS EXISTANTES, et il faut le dire explicitement : une identité
/// configurée n'est PRÉSENTÉE QUE si le pair la DEMANDE. Contre un serveur ordinaire (celui des autres
/// tests, `with_no_client_auth`), le handshake aboutit exactement comme avant.
///
/// MUTATION : rendre l'identité obligatoire côté client (échouer quand le pair n'en demande pas)
/// -> ce test rougit.
#[test]
fn client_identity_does_not_disturb_a_peer_that_never_asks() {
    let (addr, server) = spawn_untrusted_tls_server(1);
    let id = identity(CLIENT_CERT_PEM, CLIENT_KEY_PEM);
    let cfg = build_client_config(Some(&untrusted_ca_pem()), Some(&id)).expect("config avec identité");
    // `.err()` : on capture l'erreur AVANT d'assertir — `Conn` n'implémente pas `Debug` (une session TLS
    // ne doit pas pouvoir être imprimée par accident), donc pas d'`expect` sur le `Ok`.
    let err = connect_with(&addr, UNTRUSTED_HOST, Scheme::Https, Duration::from_secs(5), Some(cfg)).err();
    server.join().expect("thread serveur");
    assert!(
        err.is_none(),
        "un pair qui ne demande pas de certificat client doit rester joignable, obtenu: {}",
        err.unwrap_or_default()
    );
}

/// FAIL-CLOSED sur la MOITIÉ : un certificat sans clé (ou l'inverse) tue le boot en NOMMANT la variable
/// manquante. Sans ça, rustls ne présenterait simplement rien et l'opérateur lirait « connexion
/// refusée » — un message qui ne désigne pas la vraie cause.
///
/// MUTATION : rendre `Ok(None)` au lieu de `Err` quand une seule des deux est posée -> ce test rougit.
#[test]
fn client_identity_fails_closed_when_only_half_configured() {
    // Même anti-contamination que les tests d'ancre : on fige le `OnceLock` du processus AVANT de
    // toucher l'environnement (cf. `enterprise_ca_pem_fails_closed_when_unusable`).
    let _ = client_config().expect("config de processus");
    let _g = crate::testutil::env_lock();
    let vars = [
        CLIENT_CERT_VAR.to_string(),
        format!("{CLIENT_CERT_VAR}_FILE"),
        CLIENT_KEY_VAR.to_string(),
        format!("{CLIENT_KEY_VAR}_FILE"),
    ];
    for v in &vars {
        std::env::remove_var(v);
    }
    assert!(
        client_identity_from_env().expect("rien de posé => Ok").is_none(),
        "rien configuré => aucune identité, cas par défaut"
    );

    // CERT seul.
    std::env::set_var(CLIENT_CERT_VAR, CLIENT_CERT_PEM);
    // `.err().expect(..)` et non `expect_err` : `ClientIdentityPem` n'implémente PAS `Debug` — la
    // CONTRAINTE fait son travail jusque dans les tests, qui ne peuvent pas imprimer une clé « pour voir ».
    let e = client_identity_from_env().err().expect("certificat sans clé => refus");
    assert!(e.contains(CLIENT_KEY_VAR), "le refus doit NOMMER la variable manquante, obtenu: {e}");
    assert!(preflight().is_err(), "le boot doit MOURIR sur une identité à moitié posée");
    std::env::remove_var(CLIENT_CERT_VAR);

    // CLÉ seule.
    std::env::set_var(CLIENT_KEY_VAR, CLIENT_KEY_PEM);
    let e = client_identity_from_env().err().expect("clé sans certificat => refus");
    assert!(e.contains(CLIENT_CERT_VAR), "le refus doit NOMMER la variable manquante, obtenu: {e}");
    assert_no_key_material(&e, CLIENT_KEY_PEM, "le refus « clé sans certificat »");
    assert!(preflight().is_err(), "le boot doit MOURIR sur une identité à moitié posée");
    std::env::remove_var(CLIENT_KEY_VAR);

    // Les DEUX : plus de refus.
    std::env::set_var(CLIENT_CERT_VAR, CLIENT_CERT_PEM);
    std::env::set_var(CLIENT_KEY_VAR, CLIENT_KEY_PEM);
    assert!(
        client_identity_from_env().expect("les deux posées => Ok").is_some(),
        "CONTRE-EXEMPLE EN ÉCHEC : les deux moitiés posées doivent être ACCEPTÉES — sinon les refus \
         ci-dessus ne prouvent rien sur la MOITIÉ"
    );
    for v in &vars {
        std::env::remove_var(v);
    }
}

/// FAIL-CLOSED sur le DÉPAREILLAGE : une clé VALIDE mais qui n'est pas celle du certificat est refusée
/// à la CONSTRUCTION de la config, donc au boot. C'est la faute qu'on commet en renouvelant l'un sans
/// l'autre ; elle ne doit pas se découvrir au premier handshake.
///
/// PUR (aucun env) : les deux PEM sont des paramètres. CONTRE-EXEMPLE INTÉGRÉ — la MÊME chaîne avec sa
/// VRAIE clé est acceptée, sinon « refusé » pourrait venir de n'importe quoi d'autre.
///
/// MUTATION : traiter l'erreur de `with_client_auth_cert` comme « pas d'identité » -> ce test rougit.
#[test]
fn client_identity_fails_closed_when_the_key_does_not_match_the_certificate() {
    let e = build_client_config(None, Some(&identity(CLIENT_CERT_PEM, OTHER_CLIENT_KEY_PEM)))
        .expect_err("clé dépareillée => refus");
    assert!(e.contains(CLIENT_KEY_VAR) && e.contains(CLIENT_CERT_VAR), "le refus doit NOMMER les deux variables, obtenu: {e}");
    assert_no_key_material(&e, OTHER_CLIENT_KEY_PEM, "le refus de dépareillage");
    // CONTRE-EXEMPLE : même certificat, VRAIE clé => accepté.
    assert!(
        build_client_config(None, Some(&identity(CLIENT_CERT_PEM, CLIENT_KEY_PEM))).is_ok(),
        "CONTRE-EXEMPLE EN ÉCHEC : la paire APPARIÉE doit être acceptée — sinon le refus ci-dessus ne \
         prouve rien sur le dépareillage"
    );
}

/// LE CŒUR DU TRAVAIL, et ce n'est pas le handshake : **la clé privée ne fuit dans AUCUNE erreur.**
///
/// On BALAIE la sortie plutôt que de relire le code : chaque message produit par un chemin qui TOUCHE
/// la clé est passé au crible des fenêtres de 12 caractères de son corps base64. Le piège visé est
/// précis et mesuré — `rustls::pki_types::pem::Error` recopie la LIGNE fautive
/// (`IllegalSectionStart`) et un octet du corps (`Base64Decode`) ; propager `{e:?}` « pour aider au
/// diagnostic » déverserait donc du matériel de clé dans les journaux. Chaque refus doit dire QUE la
/// clé est invalide, jamais en montrer un fragment.
///
/// PUR (aucun env) — les chemins env/boot sont balayés par les deux tests suivants, ISOLÉS pour qu'une
/// assertion antérieure ne puisse pas les faire avorter sous mutation.
///
/// MUTATION : interpoler le PEM (ou l'erreur brute de la bibliothèque) dans `invalid_key_msg` /
/// `parse_client_key` -> ce test rougit.
#[test]
fn client_key_material_never_leaks_into_an_error() {
    // Le corps de la clé, injecté dans des PEM cassés de plusieurs façons. Chaque cas DOIT échouer —
    // sinon on ne balaierait rien du tout (assertion explicite ci-dessous).
    let body: String = CLIENT_KEY_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\n");
    let broken: Vec<(&str, String)> = vec![
        // corps pollué par un caractère hors alphabet base64 -> `Base64Decode`
        ("corps base64 corrompu", format!("-----BEGIN PRIVATE KEY-----\n{body}%\n-----END PRIVATE KEY-----\n")),
        // en-tête malformé (4 tirets) -> `IllegalSectionStart`, qui recopie la LIGNE
        ("en-tête PEM malformé", format!("-----BEGIN PRIVATE KEY----\n{body}\n-----END PRIVATE KEY-----\n")),
        // fin de section absente -> `MissingSectionEnd`
        ("fin de section absente", format!("-----BEGIN PRIVATE KEY-----\n{body}\n")),
        // aucun bloc de clé : le corps est là, mais sous une étiquette qui n'en est pas une
        ("aucun bloc de clé", format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")),
        // DEUX clés -> ambiguïté refusée
        ("deux clés", format!("{CLIENT_KEY_PEM}{CLIENT_KEY_PEM}")),
        // clé valide mais DÉPAREILLÉE -> `client_auth_error`
        ("clé dépareillée", OTHER_CLIENT_KEY_PEM.to_string()),
    ];
    for (what, key_pem) in &broken {
        let e = build_client_config(None, Some(&identity(CLIENT_CERT_PEM, key_pem)))
            .expect_err(&format!("clé inexploitable ({what}) => refus attendu"));
        assert!(
            e.contains(CLIENT_KEY_VAR),
            "le refus doit NOMMER la variable ({what}), obtenu: {e}"
        );
        assert_no_key_material(&e, key_pem, &format!("le refus « {what} »"));
        // Et le corps de la VRAIE clé non plus (les cas construits le contiennent verbatim).
        assert_no_key_material(&e, CLIENT_KEY_PEM, &format!("le refus « {what} »"));
    }
}

/// La clé ne fuit pas non plus dans la LIGNE DE BOOT — celle que l'opérateur voit, copie dans un ticket
/// et colle dans un rapport d'incident. ISOLÉ de son jumeau « erreur » pour qu'aucune assertion
/// antérieure ne puisse le faire avorter sous mutation.
///
/// MUTATION : mettre la clé (ou son empreinte étendue) dans la ligne de `preflight` -> ce test rougit.
#[test]
fn client_key_material_never_leaks_into_the_boot_line() {
    let _ = client_config().expect("config de processus");
    let _g = crate::testutil::env_lock();
    let file_var = format!("{CLIENT_KEY_VAR}_FILE");
    std::env::remove_var(&file_var);
    std::env::remove_var(format!("{CLIENT_CERT_VAR}_FILE"));
    std::env::set_var(CLIENT_CERT_VAR, CLIENT_CERT_PEM);
    std::env::set_var(CLIENT_KEY_VAR, CLIENT_KEY_PEM);
    let line = preflight().expect("identité valide => preflight OK");
    std::env::remove_var(CLIENT_CERT_VAR);
    std::env::remove_var(CLIENT_KEY_VAR);
    let line = line.expect("identité armée => une ligne de boot est annoncée");
    assert!(line.contains(CLIENT_CERT_VAR) && line.contains(CLIENT_KEY_VAR), "la ligne doit nommer les variables, obtenue: {line}");
    assert_no_key_material(&line, CLIENT_KEY_PEM, "la ligne de boot");
}

/// La clé ne fuit pas non plus quand le boot MEURT à cause d'elle — le pire moment, parce que ce
/// message-là part dans stderr, journald et le ticket de l'exploitant. ISOLÉ pour la même raison.
///
/// MUTATION : interpoler le PEM dans le message FATAL -> ce test rougit.
#[test]
fn client_key_material_never_leaks_when_the_boot_dies_on_it() {
    let _ = client_config().expect("config de processus");
    let _g = crate::testutil::env_lock();
    std::env::remove_var(format!("{CLIENT_KEY_VAR}_FILE"));
    std::env::remove_var(format!("{CLIENT_CERT_VAR}_FILE"));
    std::env::set_var(CLIENT_CERT_VAR, CLIENT_CERT_PEM);
    // Clé VALIDE mais dépareillée : le boot doit mourir, en nommant les variables et rien d'autre.
    std::env::set_var(CLIENT_KEY_VAR, OTHER_CLIENT_KEY_PEM);
    let fatal = preflight().expect_err("clé dépareillée => le boot MEURT");
    std::env::remove_var(CLIENT_CERT_VAR);
    std::env::remove_var(CLIENT_KEY_VAR);
    assert!(fatal.contains(CLIENT_KEY_VAR), "le FATAL doit NOMMER la variable, obtenu: {fatal}");
    assert_no_key_material(&fatal, OTHER_CLIENT_KEY_PEM, "le message FATAL de boot");
}

/// [JOINTURE] DE LA VARIABLE JUSQU'AU HANDSHAKE mTLS — le scénario que vit réellement l'exploitant.
///
/// Même raison d'être que `enterprise_ca_pem_from_env_reaches_a_real_handshake` : les tests ci-dessus
/// prouvent les moitiés SÉPARÉMENT (« l'env rend bien les deux PEM » d'un côté, « une identité passée
/// EN PARAMÈTRE fait aboutir le mTLS » de l'autre). Entre les deux, rien ne vérifiait que les PEM
/// SORTIS DE L'ENV — via le jumeau `_FILE`, celui que recommande la doc pour la clé — sont utilisables
/// pour un vrai handshake. La composition testée est EXACTEMENT celle de `client_config()`.
///
/// CONTRE-EXEMPLE INTÉGRÉ : variables retirées, le MÊME serveur nous refuse. Sans lui, l'aboutissement
/// pourrait venir d'ailleurs que des variables.
///
/// MUTATION : faire rendre `Ok(None)` à `client_identity_from_env` -> ce test rougit.
#[test]
fn client_identity_from_env_reaches_a_real_mtls_handshake() {
    let _ = client_config().expect("config de processus");
    let _g = crate::testutil::env_lock();
    let cert_file = format!("{CLIENT_CERT_VAR}_FILE");
    let key_file = format!("{CLIENT_KEY_VAR}_FILE");
    for v in [CLIENT_CERT_VAR, CLIENT_KEY_VAR] {
        std::env::remove_var(v);
    }
    // Forme `_FILE` — celle que la doc recommande pour la clé (un fichier monté root-only plutôt qu'un
    // secret lisible dans /proc/<pid>/environ).
    let cert_path = crate::testutil::tmp_path("forge-client-cert.pem");
    let key_path = crate::testutil::tmp_path("forge-client-key.pem");
    std::fs::write(&cert_path, CLIENT_CERT_PEM).expect("écriture fixture");
    std::fs::write(&key_path, CLIENT_KEY_PEM).expect("écriture fixture");
    std::env::set_var(&cert_file, &cert_path);
    std::env::set_var(&key_file, &key_path);

    // POSITIF : les variables posées, le pair mTLS nous authentifie.
    let (addr, server) = spawn_mtls_server();
    let cfg = build_client_config(
        extra_ca_pem_from_env().expect("Ok").as_deref().or(Some(&untrusted_ca_pem())),
        client_identity_from_env().expect("Ok").as_ref(),
    )
    .expect("config bâtie DEPUIS l'environnement");
    let banner = mtls_read_banner(&addr, cfg);
    let v = server.join().expect("thread serveur");
    assert!(v.peer_authenticated, "l'identité posée dans l'env doit nous faire AUTHENTIFIER");
    assert!(banner.is_ok(), "la session doit porter des octets applicatifs, obtenu: {banner:?}");

    // CONTRE-EXEMPLE : variables retirées, le MÊME serveur nous refuse.
    std::env::remove_var(&cert_file);
    std::env::remove_var(&key_file);
    let (addr, server) = spawn_mtls_server();
    let cfg = build_client_config(
        Some(&untrusted_ca_pem()),
        client_identity_from_env().expect("Ok").as_ref(),
    )
    .expect("config standard, sans identité");
    let refused = mtls_read_banner(&addr, cfg).is_err();
    let v = server.join().expect("thread serveur");
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    assert!(
        refused && !v.peer_authenticated,
        "sans {CLIENT_CERT_VAR}/{CLIENT_KEY_VAR}, le MÊME pair DOIT nous refuser — sinon l'aboutissement \
         ci-dessus ne vient pas des variables"
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

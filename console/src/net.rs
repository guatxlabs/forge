// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — CLIENT HTTP-OUT (fetcher intégré) extrait de main.rs (PURE MOVE). Regroupe le schéma
//! d'authentification du fetcher (`HttpAuth`), sa construction depuis la config source (`parse_http_auth`),
//! le GET HTTP/1.1 minimal et BLOQUANT sur socket TCP brut (`http_get_blocking`, aucune dépendance HTTP
//! lourde ni TLS/openssl) et le décodage `chunked` (`dechunk`). Réutilise les helpers de source de
//! détection (`ds_auth_type`/`ds_secret`) restés à la racine de crate via `use crate::*`, et est re-exporté
//! à la racine par `pub(crate) use crate::net::*` — les appelants inter-modules (`crate::http_get_blocking`,
//! `crate::HttpAuth`, `crate::dechunk` depuis sso/scim/detection) ET les tests inline de main.rs (`super::*`)
//! résolvent donc ces fonctions/types INCHANGÉS.
use crate::*;

use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Escape-hatch env : autorise les fetches d'INTÉGRATION de la console à joindre une cible interne/privée
/// (SIEM/IdP on-prem légitime sur un réseau privé). Absent/faux => la deny-list SSRF ci-dessous s'applique.
pub(crate) const ALLOW_INTERNAL_INTEGRATIONS_ENV: &str = "FORGE_ALLOW_INTERNAL_INTEGRATIONS";

/// L11/L12 — BORNE DURE de mémoire pour le fetcher d'intégration : plafond du corps de réponse bufferisé
/// (`read_to_end`) ET plafond de taille de chunk `chunked`. Une source configurée par un admin reste dans la
/// trust boundary, mais un endpoint compromis/hostile (ou un MITM) ne doit pas pouvoir épuiser la RAM de la
/// console via une réponse illimitée ou une taille de chunk aberrante. 8 MiB couvre largement tout payload
/// JSON de détection/OIDC légitime.
pub(crate) const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// Deny-list SSRF (defense-in-depth) pour les fetches SERVEUR PROPRES À LA CONSOLE — c.-à-d. les URLs
/// CONFIGURÉES PAR UN ADMIN que la console va chercher elle-même : sources de détection (detection.rs
/// `rust_http_collect`/`http_get_blocking`) et endpoints OIDC discovery / JWKS / token (sso.rs).
///
/// PÉRIMÈTRE — FETCHES D'INTÉGRATION UNIQUEMENT. Cette garde NE DOIT PAS s'appliquer aux fetches de CIBLE
/// scope-guardés du MOTEUR (oracles/outils) : ceux-ci tournent dans le moteur Python (`forge.cli campaign …`,
/// spawné par runs_proc::claim_and_spawn) et joignent LÉGITIMEMENT des hôtes internes EN SCOPE pendant un
/// engagement — c'est précisément le rôle de l'outil, et le scope-guard du moteur en reste seul juge. La
/// console Rust n'effectue JAMAIS ces fetches de cible elle-même : tout appelant de `http_get_blocking` /
/// du POST OIDC de sso.rs est un fetch d'intégration piloté par la config, donc les garder ici ne peut pas
/// toucher les cibles du moteur.
///
/// Refuse loopback, link-local (dont métadonnées cloud 169.254.169.254 & fd00:ec2::254 IMDSv6), RFC1918,
/// RFC4193 ULA (fc00::/7) et l'adresse « unspecified » — SAUF si `FORGE_ALLOW_INTERNAL_INTEGRATIONS`=1.
/// Renvoie la raison du refus (`Some`) ou `None` si l'IP est publique/autorisée.
pub(crate) fn integration_ip_denied(ip: &IpAddr) -> Option<&'static str> {
    // Réduit un IPv6 mappé/compatible-IPv4 (::ffff:169.254.169.254, ::a.b.c.d) à sa forme v4 pour qu'une
    // adresse interne encapsulée en v6 ne contourne pas les tests v4.
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                Some("0.0.0.0/unspecified")
            } else if v4.is_loopback() {
                Some("loopback 127.0.0.0/8")
            } else if v4.is_link_local() {
                Some("link-local/metadata 169.254.0.0/16")
            } else if v4.is_private() {
                Some("RFC1918 privé (10/8, 172.16/12, 192.168/16)")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                Some("::/unspecified")
            } else if v6.is_loopback() {
                Some("loopback ::1")
            } else {
                let seg0 = v6.segments()[0];
                if (seg0 & 0xfe00) == 0xfc00 {
                    Some("RFC4193 ULA fc00::/7 (dont fd00:ec2::254 IMDSv6)")
                } else if (seg0 & 0xffc0) == 0xfe80 {
                    Some("link-local fe80::/10")
                } else {
                    None
                }
            }
        }
    }
}

/// Garde fail-closed d'une cible d'INTÉGRATION résolue. Vérifie l'adresse EXACTE que l'on s'apprête à
/// contacter (resolve-then-check-then-connect la MÊME `addr` => neutralise le DNS-rebinding POUR CETTE
/// connexion : le contrôle porte sur l'IP effectivement connectée, pas sur un 2e lookup). No-op si
/// l'escape-hatch env est posé. Renvoie `Err(raison)` pour refuser. À appeler AVANT `connect_timeout`.
/// La décision de refus PURE est déléguée à `reject_internal_addr` (testable sans toucher l'env global).
pub(crate) fn guard_integration_addr(addr: &SocketAddr) -> Result<(), String> {
    if crate::env_flag_enabled(ALLOW_INTERNAL_INTEGRATIONS_ENV) {
        return Ok(());
    }
    reject_internal_addr(addr)
}

/// Décision de refus PURE (SANS lecture d'env) : `Err(raison)` si l'adresse est interne/privée/métadonnées,
/// `Ok(())` sinon. Séparée de l'escape-hatch env pour que la deny-list soit testable de façon déterministe
/// (sans muter la variable d'environnement process-globale, source de flakiness inter-tests).
pub(crate) fn reject_internal_addr(addr: &SocketAddr) -> Result<(), String> {
    match integration_ip_denied(&addr.ip()) {
        Some(reason) => Err(format!(
            "deny-list SSRF : fetch d'intégration console vers cible interne {} refusé ({reason}) ; \
             poser {ALLOW_INTERNAL_INTEGRATIONS_ENV}=1 pour autoriser une cible privée on-prem",
            addr.ip()
        )),
        None => Ok(()),
    }
}

/// Schéma d'authentification HTTP du fetcher intégré. `mtls` n'est PAS ici (le client TCP brut ne fait
/// pas de TLS — un endpoint mTLS passe par un kind délégué au collecteur Python).
pub(crate) enum HttpAuth {
    None,
    Basic(String),                         // base64 de user:pass -> `Authorization: Basic ...`
    Bearer(String),                        // token -> `Authorization: Bearer ...`
    ApiKeyHeader { name: String, value: String }, // en-tête d'API arbitraire (ex: X-API-Key: ...)
}

/// Construit l'`HttpAuth` du fetcher intégré depuis la config source. `basic`/`bearer` prennent
/// `auth.secret` ; `api_key_header` prend `auth.header` (défaut `X-API-Key`) + `auth.secret`. `none`,
/// `mtls` ou un type inconnu => aucun en-tête (le TLS/mTLS relève d'un kind délégué au Python).
pub(crate) fn parse_http_auth(cfg: &Value) -> HttpAuth {
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
pub(crate) fn http_get_blocking(url: &str, auth: &HttpAuth, timeout: Duration, allow_https: bool) -> Result<String, String> {
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
    // SSRF defense-in-depth (INTÉGRATION console) : cet appelant est un fetch d'URL CONFIGURÉE (source de
    // détection / OIDC), jamais une cible scope-guardée du moteur — on refuse donc loopback/link-local/
    // métadonnées/RFC1918/ULA sur l'IP RÉSOLUE que l'on va connecter (anti-DNS-rebinding), sauf escape-hatch.
    guard_integration_addr(&addr)?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connexion {addr} échouée: {e}"))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: forge-detection\r\nAccept: application/json\r\nConnection: close\r\n"
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
    // L11 — BUFFERING BORNÉ : `take(MAX_RESPONSE_BYTES)` cape la lecture (anti-OOM sur une réponse illimitée).
    // Le read-timeout par-read (set_read_timeout ci-dessus) borne déjà la LATENCE ; ce cap borne la MÉMOIRE.
    (&mut stream)
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut raw)
        .map_err(|e| format!("lecture réponse échouée: {e}"))?;
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
        // IDIO-1 : dé-chunk sur les OCTETS BRUTS du corps (l'en-tête HTTP est ASCII, donc l'offset
        // `split + 4` calculé sur la vue lossy est le même offset d'octet dans `raw`).
        Ok(dechunk(&raw[split + 4..]))
    } else {
        Ok(body.to_string())
    }
}

/// Décode un corps HTTP `chunked` (best-effort) : tailles hex par ligne, terminé par un chunk 0.
///
/// IDIO-1 : le dé-chunking opère sur les OCTETS BRUTS (`&[u8]`). Les tailles de chunk sont des comptes
/// d'octets ; indexer une chaîne issue de `from_utf8_lossy` avec ces offsets pouvait tomber au milieu
/// d'un caractère (les octets invalides deviennent U+FFFD, 3 octets) -> panique de tranche `&str` ou
/// sortie décalée. On assemble d'abord les octets utiles, puis on convertit UNE fois en fin. Pour une
/// entrée ASCII valide, la sortie est identique à l'ancienne implémentation.
pub(crate) fn dechunk(body: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::new();
    let mut rest: &[u8] = body;
    while let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") {
        let size_line = &rest[..nl];
        // la taille peut porter des extensions après ';' — on ne garde que l'hex.
        let hex_seg = size_line.split(|&b| b == b';').next().unwrap_or(&[]);
        let size = match std::str::from_utf8(hex_seg)
            .ok()
            .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
        {
            Some(s) => s,
            None => break,
        };
        if size == 0 {
            break;
        }
        // L12 — taille de chunk aberrante (au-delà du cap de réponse) => stop best-effort (anti-OOM),
        // cohérent avec `MAX_RESPONSE_BYTES` de L11. Empêche aussi un `out` non borné multi-chunks.
        if size > MAX_RESPONSE_BYTES as usize || out.len().saturating_add(size) > MAX_RESPONSE_BYTES as usize {
            break;
        }
        let start = nl + 2;
        // L12 — `checked_add` : une taille de chunk malicieuse ne peut plus faire déborder `start + size`
        // (panique/wrap d'index). Overflow => stop best-effort.
        let end = match start.checked_add(size) {
            Some(e) => e,
            None => break,
        };
        if end > rest.len() {
            out.extend_from_slice(&rest[start..]);
            break;
        }
        out.extend_from_slice(&rest[start..end]);
        // saute le CRLF de fin de chunk.
        rest = if end + 2 <= rest.len() { &rest[end + 2..] } else { &[] };
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod dechunk_tests {
    use super::{dechunk, MAX_RESPONSE_BYTES};

    /// Décodage nominal : deux chunks ASCII valides -> concaténation, terminé par le chunk 0.
    #[test]
    fn dechunk_valid_ascii() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(body), "Wikipedia");
    }

    /// L12 — taille de chunk NON hex (malformée) => stop best-effort, aucune panique.
    #[test]
    fn dechunk_malformed_size_no_panic() {
        let body = b"zz\r\ngarbage\r\n0\r\n\r\n";
        assert_eq!(dechunk(body), "", "taille invalide -> break sans crash");
    }

    /// L12 — `checked_add` : une taille de chunk énorme (proche de usize::MAX, > buffer réel) ne provoque NI
    /// overflow d'index NI panique de tranche. On tronque best-effort à ce qui reste.
    #[test]
    fn dechunk_overflow_size_no_panic() {
        // ffffffffffffffff = usize::MAX en hex sur 64 bits : `start + size` déborderait sans checked_add.
        let body = b"ffffffffffffffff\r\nABC";
        // > MAX_RESPONSE_BYTES -> break AVANT toute arithmétique dangereuse ; sortie vide, aucune panique.
        assert_eq!(dechunk(body), "");
    }

    /// L12 — une taille de chunk supérieure au cap de réponse est refusée (anti-OOM), sortie bornée.
    #[test]
    fn dechunk_oversized_chunk_capped() {
        // taille annoncée = MAX_RESPONSE_BYTES + 1 (hex) -> break immédiat, rien n'est bufferisé.
        let big = format!("{:x}\r\nXY", MAX_RESPONSE_BYTES as usize + 1);
        assert_eq!(dechunk(big.as_bytes()), "", "chunk au-delà du cap -> refusé");
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::{guard_integration_addr, integration_ip_denied, reject_internal_addr};
    use std::net::{IpAddr, SocketAddr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn sa(s: &str) -> SocketAddr {
        SocketAddr::new(ip(s), 80)
    }

    /// La matrice de deny-list (fonction PURE, sans env) : métadonnées cloud / loopback / RFC1918 / ULA /
    /// link-local / unspecified sont refusés ; un hôte public est autorisé. Couvre aussi les IPv6 mappés-v4
    /// (::ffff:… ne doit pas contourner les tests v4).
    #[test]
    fn deny_list_matrix() {
        // REFUSÉS.
        assert!(integration_ip_denied(&ip("169.254.169.254")).is_some(), "métadonnées cloud IMDSv4");
        assert!(integration_ip_denied(&ip("127.0.0.1")).is_some(), "loopback");
        assert!(integration_ip_denied(&ip("10.0.0.5")).is_some(), "RFC1918 10/8");
        assert!(integration_ip_denied(&ip("172.16.9.9")).is_some(), "RFC1918 172.16/12");
        assert!(integration_ip_denied(&ip("192.168.1.1")).is_some(), "RFC1918 192.168/16");
        assert!(integration_ip_denied(&ip("0.0.0.0")).is_some(), "unspecified");
        assert!(integration_ip_denied(&ip("::1")).is_some(), "loopback v6");
        assert!(integration_ip_denied(&ip("fd00:ec2::254")).is_some(), "ULA / IMDSv6");
        assert!(integration_ip_denied(&ip("fe80::1")).is_some(), "link-local v6");
        assert!(integration_ip_denied(&ip("::ffff:169.254.169.254")).is_some(), "v4-mapped métadonnées");
        assert!(integration_ip_denied(&ip("::ffff:127.0.0.1")).is_some(), "v4-mapped loopback");
        // AUTORISÉS (publics).
        assert!(integration_ip_denied(&ip("8.8.8.8")).is_none(), "public v4 autorisé");
        assert!(integration_ip_denied(&ip("1.1.1.1")).is_none(), "public v4 autorisé");
        assert!(integration_ip_denied(&ip("2606:4700:4700::1111")).is_none(), "public v6 autorisé");
    }

    /// La garde d'intégration RÉELLE (`reject_internal_addr`, décision PURE utilisée par http_get_blocking /
    /// le POST OIDC) refuse une cible interne (métadonnées / loopback / RFC1918) et autorise un hôte public.
    /// Le message d'erreur porte la deny-list (ce qui remonte au fetch de source de détection / OIDC).
    /// PUR (sans env) => déterministe et sans course inter-tests.
    #[test]
    fn integration_guard_rejects_internal_allows_public() {
        let e = reject_internal_addr(&sa("169.254.169.254")).unwrap_err();
        assert!(e.contains("deny-list SSRF"), "message deny-list attendu, obtenu: {e}");
        assert!(reject_internal_addr(&sa("127.0.0.1")).is_err(), "loopback refusé");
        assert!(reject_internal_addr(&sa("10.1.2.3")).is_err(), "RFC1918 refusé");
        assert!(reject_internal_addr(&sa("8.8.8.8")).is_ok(), "public autorisé");
    }

    /// L'ESCAPE-HATCH `FORGE_ALLOW_INTERNAL_INTEGRATIONS=1` fait passer une cible interne via la garde
    /// complète `guard_integration_addr` (SIEM/IdP privé on-prem légitime). On POSE la var et on la laisse
    /// posée : c'est l'état DÉSIRÉ par tout le binaire de test (les mocks OIDC loopback des tests SSO en
    /// dépendent), donc AUCUN test ne l'unset -> pas de course sur l'env process-global. La direction
    /// « refus par défaut » est prouvée par `reject_internal_addr` (pur) ci-dessus.
    #[test]
    fn escape_hatch_env_allows_internal() {
        crate::testutil::allow_internal_integrations_once(); // pose la var UNE fois (jamais unset)
        assert!(guard_integration_addr(&sa("169.254.169.254")).is_ok(), "escape-hatch autorise métadonnées");
        assert!(guard_integration_addr(&sa("10.1.2.3")).is_ok(), "escape-hatch autorise RFC1918");
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — CLIENT HTTP-OUT (fetcher intégré) extrait de main.rs (PURE MOVE). Regroupe le schéma
//! d'authentification du fetcher (`HttpAuth`), sa construction depuis la config source (`parse_http_auth`),
//! le GET HTTP/1.1 minimal et BLOQUANT (`http_get_blocking`, aucune dépendance HTTP lourde), la garde
//! SSRF d'intégration (`reject_internal_addr`/`resolve_guarded_with`) et le décodage
//! `chunked` (`dechunk`). Le TRANSPORT est délégué au seam `crate::tls` — `http://` (clair GOUVERNÉ) et
//! `https://` (TLS VÉRIFIÉ) sont donc tous deux servis ici. Réutilise les helpers de source de
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

/// LA lecture de l'escape-hatch d'environnement — un seul endroit dans tout le crate. Les trois sorties
/// la consultent au bord (leur fonction publique) et passent ensuite le booléen en PARAMÈTRE jusqu'à la
/// décision ; aucune couche profonde ne relit `std::env`. C'est ce qui rend la deny-list testable de
/// façon déterministe, sans muter une variable process-globale.
pub(crate) fn internal_targets_allowed() -> bool {
    crate::env_flag_enabled(ALLOW_INTERNAL_INTEGRATIONS_ENV)
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

/// Résolution + deny-list SSRF en UN geste — LE goulot des sorties qui partent d'une URL (fetcher de
/// détection, discovery/JWKS/token OIDC). Résout `host:port`, puis applique la deny-list à l'adresse
/// EXACTE que l'on va connecter — c'est cette adresse-là, et pas un 2e lookup, qui part ensuite dans
/// `tls::connect` (anti-DNS-rebinding). Une seule copie de ce geste : impossible de résoudre sans garder.
///
/// PUR vis-à-vis de l'ENVIRONNEMENT : l'autorisation des cibles internes est un PARAMÈTRE, pas une
/// lecture de `std::env` (elle est faite une fois au bord, par [`internal_targets_allowed`]). Même
/// patron que `notify_channels::plan_delivery`, et pour la même raison : le binaire de test POSE
/// globalement l'escape-hatch (les mocks OIDC/webhook bindent sur loopback) et ne l'unset jamais — sans
/// ce paramètre, la direction « refus par défaut » ne serait pas testable de bout en bout.
pub(crate) fn resolve_guarded_with(host: &str, port: u16, allow_internal: bool) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("résolution {host}:{port} échouée: {e}"))?
        .next()
        .ok_or_else(|| format!("aucune adresse pour {host}:{port}"))?;
    if !allow_internal {
        reject_internal_addr(&addr)?;
    }
    Ok(addr)
}

// =====================================================================================
//  UN SECRET D'INTÉGRATION NE TRAVERSE PAS UN RÉSEAU PUBLIC EN CLAIR — règle PARTAGÉE
// =====================================================================================

/// UNE seule implémentation de la règle, pour les DEUX egress de la console qui portent un secret :
/// le webhook de notification (`notify_channels::plan_delivery`) et le fetcher de source de détection
/// ([`http_get_blocking_with`]). Elle vivait en copie INLINE dans le premier, et n'existait PAS DU TOUT
/// dans le second — un `generic_http`/`plume` en `http://` vers une source PUBLIQUE mettait donc son
/// `Authorization:` en clair sur Internet, sans qu'aucune garde ne s'y oppose. C'était le clair
/// résiduel le plus grave qui restait : il est fermé ici, et la règle se vérifie désormais UNE fois.
///
/// LA RÈGLE, et ses bornes exactes :
///   - pas de secret => rien à protéger, OK (le fetch anonyme en clair reste servi) ;
///   - `https://` => le secret part dans une session dont le certificat est VÉRIFIÉ (chaîne + nom +
///     validité, ancres Mozilla ET, si configurée, la CA privée d'entreprise — cf. `tls::EXTRA_CA_VAR`).
///     C'est la VOIE PROPRE, et depuis le knob de CA d'entreprise elle est ouverte même à un
///     collecteur/IdP interne signé par l'organisation ;
///   - `http://` avec un secret vers TOUTE adresse ROUTABLE — publique **ou privée** — => REFUS, et
///     **aucune** variable d'environnement ne l'ouvre. `FORGE_ALLOW_INTERNAL_INTEGRATIONS` autorise
///     à ATTEINDRE une adresse interne ; il n'a jamais autorisé à y envoyer un secret en clair, et
///     depuis ce resserrement il ne le fait plus ;
///   - `http://` avec un secret vers le LOOPBACK (`127.0.0.0/8`, `::1`) => SERVI. **Seule exception
///     survivante à « pas de clair », et elle tient par la PHYSIQUE, pas par une politique** : le
///     paquet ne traverse aucune interface réseau, donc il n'y a pas de fil sur lequel intercepter
///     quoi que ce soit. Et quiconque peut lire le loopback de cette machine peut déjà lire la
///     mémoire et la configuration du processus, où le secret vit de toute façon en clair. Exiger TLS
///     d'un sidecar co-localisé n'achèterait rien de réel.
///
/// HISTORIQUE DE LA DÉCISION, pour qu'elle ne soit pas re-litigée à l'envers. Le clair vers une cible
/// interne ROUTABLE a d'abord été CONSERVÉ (2026-08-06), au motif — mesuré — qu'un collecteur on-prem
/// sans écouteur TLS n'aurait plus aucune voie, l'ancre d'entreprise fournissant « une ancre, pas un
/// écouteur ». Deux faits ont renversé l'arbitrage (2026-08-07) :
///   1. la mesure invoquée portait sur deux tests dont les fixtures sont des mocks HTTP de LOOPBACK
///      (`testutil::mock_http_once` binde `127.0.0.1:0`) — ils éprouvent le parsing des détections,
///      pas une contrainte de déploiement. Le coût constaté était un coût de FIXTURES, et l'exception
///      loopback le laisse d'ailleurs intact : ces tests passent inchangés ;
///   2. le dépôt n'a AUCUNE install déployée — donc aucune dette de compatibilité, et fermer avant
///      publication est gratuit là où fermer après serait une rupture.
/// Reste le seul coût réel : un collecteur interne joint par son IP de LAN doit terminer TLS. Ce
/// n'est plus un cul-de-sac depuis que le seam accepte une CA privée (`tls::EXTRA_CA_VAR`) : un
/// certificat auto-signé ou signé par la CA de l'organisation est VÉRIFIÉ. On fournit la moitié
/// cliente ; monter l'écouteur est du travail ordinaire, pas une impasse.
pub(crate) fn reject_cleartext_secret(
    scheme: crate::tls::Scheme,
    has_secret: bool,
    target_is_loopback: bool,
) -> Result<(), String> {
    if !has_secret || scheme.is_tls() {
        return Ok(());
    }
    if target_is_loopback {
        return Ok(()); // le paquet ne quitte pas la machine — cf. le doc ci-dessus
    }
    Err(
        "secret d'intégration configuré vers une cible ROUTABLE en HTTP clair — refusé (le jeton \
         partirait en clair sur le fil). Un réseau PRIVÉ ne change rien : \
         FORGE_ALLOW_INTERNAL_INTEGRATIONS autorise à ATTEINDRE une adresse interne, jamais à y \
         envoyer un secret en clair. Utiliser https:// (TLS vérifié ; un certificat auto-signé ou \
         une CA privée d'entreprise se fournit via FORGE_EXTRA_CA_PEM), viser un service co-localisé \
         sur 127.0.0.1, ou retirer le secret."
            .to_string(),
    )
}

/// Schéma d'authentification HTTP du fetcher intégré. `mtls` n'est PAS ici, et la raison a CHANGÉ :
/// le seam TLS installe désormais un certificat client (`tls::CLIENT_CERT_VAR` / `tls::CLIENT_KEY_VAR`,
/// via `with_client_auth_cert`), donc un endpoint mTLS est joignable EN RUST. Mais cette identité est
/// celle du PROCESSUS — une seule politique de confiance pour tout le binaire, cf. `tls::client_config`
/// — alors que `auth.type` est un réglage PAR SOURCE. Ce qui reste délégué au collecteur Python, c'est
/// donc le cas d'une identité PROPRE À UNE SOURCE, pas le mTLS en soi. `HttpAuth` ne décrit que des
/// en-têtes ; le transport, mTLS compris, n'a jamais rien à y faire.
pub(crate) enum HttpAuth {
    None,
    Basic(String),                         // base64 de user:pass -> `Authorization: Basic ...`
    Bearer(String),                        // token -> `Authorization: Bearer ...`
    ApiKeyHeader { name: String, value: String }, // en-tête d'API arbitraire (ex: X-API-Key: ...)
}

impl HttpAuth {
    /// Ce schéma mettra-t-il RÉELLEMENT un secret sur le fil ? Miroir EXACT des gardes du `match` qui
    /// écrit les en-têtes plus bas (une valeur vide n'émet aucun en-tête, donc ne porte aucun secret) —
    /// les deux doivent rester d'accord, sinon on refuserait un fetch anonyme ou on laisserait passer
    /// un jeton.
    pub(crate) fn carries_secret(&self) -> bool {
        match self {
            HttpAuth::None => false,
            HttpAuth::Basic(v) | HttpAuth::Bearer(v) => !v.is_empty(),
            HttpAuth::ApiKeyHeader { name, value } => !name.is_empty() && !value.is_empty(),
        }
    }
}

/// Construit l'`HttpAuth` du fetcher intégré depuis la config source. `basic`/`bearer` prennent
/// `auth.secret` ; `api_key_header` prend `auth.header` (défaut `X-API-Key`) + `auth.secret`. `none`,
/// `mtls` ou un type inconnu => aucun en-tête (le mTLS relève du TRANSPORT : il est servi par
/// l'identité cliente du seam quand elle est configurée, jamais par un en-tête).
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
/// Gère `http://host[:port]/path` **et** `https://host[:port]/path` : le transport vient du seam
/// `crate::tls` (en https, le certificat du pair est VÉRIFIÉ — chaîne + nom d'hôte — avant qu'un seul
/// octet applicatif ne parte). `auth` porte le schéma d'authentification (none/basic/bearer/
/// api_key_header). Renvoie le corps (string) en cas de 200, sinon Err. Timeout dur (connect +
/// handshake + lecture).
///
/// HISTORIQUE — cette fonction REFUSAIT `https://` faute de client TLS, et ce refus était la source de
/// vérité citée partout ailleurs (« la console ne parle pas TLS »). Il est OBSOLÈTE depuis le seam.
pub(crate) fn http_get_blocking(url: &str, auth: &HttpAuth, timeout: Duration) -> Result<String, String> {
    http_get_blocking_with(url, auth, timeout, internal_targets_allowed())
}

/// Cœur de [`http_get_blocking`], avec l'autorisation des cibles internes en PARAMÈTRE (cf.
/// [`resolve_guarded_with`]) : c'est ce qui rend la deny-list SSRF de CE fetcher testable de bout en
/// bout, sans dépendre de l'état d'une variable d'environnement process-globale.
pub(crate) fn http_get_blocking_with(
    url: &str,
    auth: &HttpAuth,
    timeout: Duration,
    allow_internal: bool,
) -> Result<String, String> {
    use std::io::{Read, Write};
    let t = crate::tls::split_url(url)?;
    // SSRF defense-in-depth (INTÉGRATION console) : cet appelant est un fetch d'URL CONFIGURÉE (source de
    // détection / OIDC), jamais une cible scope-guardée du moteur — on refuse donc loopback/link-local/
    // métadonnées/RFC1918/ULA sur l'IP RÉSOLUE que l'on va connecter (anti-DNS-rebinding), sauf escape-hatch.
    // Le TLS ne remplace PAS cette garde : chiffrer un fetch vers 169.254.169.254 ne le rend pas légitime.
    let addr = resolve_guarded_with(&t.host, t.port, allow_internal)?;
    // PAS DE SECRET EN CLAIR VERS UNE CIBLE PUBLIQUE — règle PARTAGÉE avec le webhook de notification
    // (cf. `reject_cleartext_secret`). Ce site ne l'avait PAS : une source de détection publique en
    // `http://` avec un bearer/basic mettait son `Authorization:` sur le fil. Le refus tombe AVANT le
    // connect, donc avant qu'un seul octet ne parte.
    reject_cleartext_secret(t.scheme, auth.carries_secret(), addr.ip().is_loopback())?;
    let mut stream = crate::tls::connect(&addr, &t.host, t.scheme, timeout)?;
    let (authority, path) = (&t.authority, &t.path);
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
    // LIGNE VIDE DE FIN D'EN-TÊTES (RFC 9112 §2.1) — SANS elle, la requête n'est jamais COMPLÈTE : le
    // serveur reste bloqué à lire des en-têtes, la console expire en lecture (EAGAIN) et la source
    // remonte « injoignable » alors qu'elle répond. Miroir EXACT du POST OIDC (sso.rs
    // ::http_post_form_blocking, qui pousse déjà ce "\r\n" avant son corps).
    req.push_str("\r\n");
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
    use super::{integration_ip_denied, reject_internal_addr};
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

    /// LA DENY-LIST MORD DANS LE FETCHER LUI-MÊME, pas seulement dans la fonction pure — et le seam TLS
    /// n'y change RIEN : une cible interne est refusée en `http://` COMME en `https://`, AVANT toute
    /// connexion et donc avant tout handshake. (Chiffrer un fetch vers 169.254.169.254 ne le rend pas
    /// légitime.) Déterministe : `allow_internal` est un PARAMÈTRE, pas une lecture d'env.
    /// MUTATION : retirer `reject_internal_addr(&addr)?` de `resolve_guarded_with` -> ce test rougit.
    #[test]
    fn fetcher_applies_the_deny_list_over_both_schemes() {
        use crate::HttpAuth;
        use std::time::Duration;
        let t = Duration::from_millis(200);
        for url in [
            "http://127.0.0.1:9/x",
            "https://127.0.0.1:9/x",
            "http://169.254.169.254/latest/meta-data",
            "https://169.254.169.254/latest/meta-data",
            "https://10.1.2.3/x",
        ] {
            let e = super::http_get_blocking_with(url, &HttpAuth::None, t, false)
                .expect_err("cible interne refusée");
            assert!(e.contains("deny-list SSRF"), "refus SSRF attendu pour {url}, obtenu: {e}");
        }
        // Avec l'autorisation explicite (collecteur on-prem), la garde laisse passer : l'échec restant
        // est de CONNEXION (port fermé), plus un refus de politique.
        let e = super::http_get_blocking_with("http://127.0.0.1:9/x", &HttpAuth::None, t, true)
            .expect_err("port fermé");
        assert!(!e.contains("deny-list"), "escape-hatch : plus de refus de politique, obtenu: {e}");
    }

    /// LA RÈGLE PARTAGÉE « pas de secret en clair sur un RÉSEAU », PURE et exhaustive. Elle gouverne
    /// DEUX egress (webhook de notification + fetcher de source de détection) ; la prouver ici une
    /// fois vaut pour les deux. Le 3ᵉ paramètre est `target_is_loopback`, et le changement de nom
    /// EST le resserrement : le critère n'est plus « la cible est-elle interne ? » mais « le paquet
    /// quitte-t-il la machine ? ».
    ///
    /// MUTATION : rendre `Ok(())` inconditionnel -> ce test rougit (2 assertions).
    #[test]
    fn cleartext_secret_rule_is_exhaustive() {
        use crate::tls::Scheme::{Http, Https};
        use super::reject_cleartext_secret;
        // Sans secret : le clair reste servi partout (fetch anonyme, webhook sans jeton).
        assert!(reject_cleartext_secret(Http, false, false).is_ok(), "pas de secret, cible routable");
        assert!(reject_cleartext_secret(Http, false, true).is_ok(), "pas de secret, loopback");
        // En TLS : le secret est protégé par une session au certificat VÉRIFIÉ -> servi partout.
        assert!(reject_cleartext_secret(Https, true, false).is_ok(), "secret + https routable : la voie propre");
        assert!(reject_cleartext_secret(Https, true, true).is_ok(), "secret + https loopback");
        // LE REFUS : clair + secret + toute cible ROUTABLE. Aucune variable d'environnement ne l'ouvre.
        let e = reject_cleartext_secret(Http, true, false).expect_err("clair + secret + routable => refus");
        assert!(e.contains("en clair"), "refus nommé attendu, obtenu: {e}");
        assert!(e.contains("FORGE_EXTRA_CA_PEM"), "le refus doit indiquer la VOIE PROPRE, obtenu: {e}");
        // LA SEULE EXCEPTION SURVIVANTE : clair + secret vers le LOOPBACK. Elle tient par la PHYSIQUE
        // (le paquet ne traverse aucune interface) et non par une politique ; cf. le doc de la règle.
        assert!(reject_cleartext_secret(Http, true, true).is_ok(), "clair + secret vers 127.0.0.1 : servi");
    }

    /// LE RESSERREMENT DU 2026-08-07, éprouvé sur des ADRESSES RÉELLES et non sur un booléen — sans
    /// quoi on ne prouverait que l'arithmétique de la fonction pure, jamais que les APPELANTS
    /// classent correctement. C'est précisément là qu'était le relâchement : le critère était
    /// « interne » (donc 192.168.x, 10.x, ULA… tous exemptés), il est désormais « loopback ».
    ///
    /// MUTATION : rebrancher les appelants sur `reject_internal_addr(&addr).is_err()` -> rouge, car
    /// une IP de LAN redevient exemptée.
    #[test]
    fn a_secret_in_the_clear_to_a_private_lan_address_is_now_refused() {
        use crate::tls::Scheme::Http;
        use super::reject_cleartext_secret;
        use std::net::SocketAddr;
        // Ces adresses sont TOUTES « internes » au sens de `reject_internal_addr` — c'est exactement
        // ce qui les exemptait AVANT. Aucune n'est le loopback : le paquet quitte la machine.
        for a in ["192.168.1.10:8080", "10.0.0.5:80", "172.16.0.9:8080", "[fd00::1]:80"] {
            let addr: SocketAddr = a.parse().expect("adresse de test");
            assert!(reject_internal_addr(&addr).is_err(), "prérequis : {a} est bien classée INTERNE");
            let e = reject_cleartext_secret(Http, true, addr.ip().is_loopback())
                .expect_err("secret en clair vers une IP de LAN doit être REFUSÉ, adresse: {a}");
            assert!(e.contains("ROUTABLE"), "le refus doit dire pourquoi, obtenu: {e}");
        }
        // CONTRE-EXEMPLE, sinon « tout est refusé » passerait ce test pour la mauvaise raison.
        for a in ["127.0.0.1:8080", "[::1]:80"] {
            let addr: SocketAddr = a.parse().expect("adresse de test");
            assert!(reject_internal_addr(&addr).is_err(), "le loopback reste INTERNE pour l'anti-SSRF");
            assert!(
                reject_cleartext_secret(Http, true, addr.ip().is_loopback()).is_ok(),
                "le loopback reste servi : {a}"
            );
        }
    }

    /// LE FETCHER APPLIQUE la règle — pas seulement la fonction pure. Une source de détection PUBLIQUE
    /// en `http://` avec un bearer est refusée AVANT le connect (donc avant qu'un octet ne parte), et le
    /// message ne recrache PAS le jeton. C'était le trou : ce site n'avait aucune garde de ce genre.
    ///
    /// MUTATION : retirer l'appel `reject_cleartext_secret(...)` de `http_get_blocking_with` -> rouge.
    #[test]
    fn fetcher_refuses_a_secret_in_the_clear_towards_a_public_target() {
        use crate::HttpAuth;
        use std::time::Duration;
        const TOKEN: &str = "JETON-SOURCE-NE-DOIT-PAS-PARTIR";
        let t = Duration::from_millis(200);
        // 8.8.8.8 : cible PUBLIQUE, résolue sans DNS -> le test ne dépend pas du réseau, et le refus
        // tombe avant toute tentative de connexion.
        for auth in [
            HttpAuth::Bearer(TOKEN.to_string()),
            HttpAuth::Basic(TOKEN.to_string()),
            HttpAuth::ApiKeyHeader { name: "X-API-Key".into(), value: TOKEN.into() },
        ] {
            let e = super::http_get_blocking_with("http://8.8.8.8/api/alerts", &auth, t, false)
                .expect_err("secret en clair vers une cible publique => refus");
            assert!(e.contains("en clair"), "refus credential-en-clair attendu, obtenu: {e}");
            assert!(!e.contains(TOKEN), "le refus ne doit PAS recracher le jeton: {e}");
        }
        // CONTRÔLE : la MÊME cible publique en clair SANS secret reste servie par la politique — l'échec
        // qui subsiste est de CONNEXION, pas de politique. Sans ce contrôle, le refus ci-dessus pourrait
        // venir de n'importe quoi d'autre sur ce chemin.
        let e = super::http_get_blocking_with("http://8.8.8.8:9/x", &HttpAuth::None, t, false)
            .expect_err("port fermé");
        assert!(!e.contains("en clair"), "sans secret, aucun refus de politique, obtenu: {e}");
        // `carries_secret` est le prédicat exact des en-têtes émis : une valeur VIDE n'émet rien.
        assert!(!HttpAuth::Bearer(String::new()).carries_secret(), "valeur vide => aucun en-tête, aucun secret");
        assert!(!HttpAuth::None.carries_secret());
    }

    /// LE FETCHER APPLIQUE LE RESSERREMENT du 2026-08-07 — et ce test existe parce que le test de la
    /// fonction PURE ne suffisait pas : il calcule `is_loopback` LUI-MÊME et ne touche donc jamais les
    /// appelants. Vérifié par mutation : rebrancher les DEUX appelants sur l'ancien critère
    /// `reject_internal_addr(&addr).is_err()` laissait toute la suite VERTE. Un test qui reproduit la
    /// composition au lieu de l'APPELER ne prouve rien sur le câblage — c'est ici qu'on l'appelle.
    ///
    /// MUTATION : remettre `reject_internal_addr(&addr).is_err()` en 3ᵉ argument dans
    /// `http_get_blocking_with` -> une IP de LAN redevient exemptée -> ce test rougit.
    #[test]
    fn fetcher_refuses_a_secret_in_the_clear_towards_a_private_lan_address() {
        use crate::HttpAuth;
        use std::time::Duration;
        const TOKEN: &str = "JETON-LAN-NE-DOIT-PAS-PARTIR";
        let t = Duration::from_millis(200);
        let auth = HttpAuth::Bearer(TOKEN.to_string());
        // `allow_internal = true` : l'escape-hatch d'ACCÈS est ACCORDÉ, et c'est tout l'intérêt du
        // test — on prouve qu'il n'emporte PLUS le droit d'envoyer un secret en clair. Ces adresses
        // sont littérales, donc aucune résolution DNS : le test ne dépend pas du réseau.
        // PAS d'IPv6 littéral ici, et ce n'est pas un oubli : `tls::split_url` ne gère pas les
        // crochets RFC 3986 — `http://[fd00::1]/api` devient l'hôte `[fd00` et le port `80`, puis
        // échoue à la RÉSOLUTION. Découvert par ce test. Le défaut est FAIL-CLOSED (on n'atteint
        // jamais la cible, donc aucun contournement de garde), mais il rend les littéraux IPv6
        // inadressables pour les sources de détection et les webhooks. Traité à part.
        for url in ["http://192.168.1.10/api/alerts", "http://10.0.0.5/api", "http://172.16.0.9/api"] {
            let e = super::http_get_blocking_with(url, &auth, t, true)
                .expect_err("secret en clair vers une IP de LAN doit être REFUSÉ");
            assert!(e.contains("ROUTABLE"), "refus « cible routable » attendu pour {url}, obtenu: {e}");
            assert!(!e.contains(TOKEN), "le refus ne doit PAS recracher le jeton: {e}");
        }
        // CONTRE-EXEMPLE : la même IP de LAN, MÊME secret, mais en `https://` -> la politique laisse
        // passer et l'échec qui subsiste est de CONNEXION. Sans lui, « ça refuse » pourrait venir de
        // l'anti-SSRF ou de n'importe quoi d'autre sur ce chemin.
        let e = super::http_get_blocking_with("https://192.168.1.10:9/api", &auth, t, true)
            .expect_err("port fermé");
        assert!(!e.contains("ROUTABLE"), "en https la politique ne refuse pas, obtenu: {e}");
        // Et le LOOPBACK reste servi en clair avec secret : l'exception survivante, au niveau APPELANT.
        let e = super::http_get_blocking_with("http://127.0.0.1:9/api", &auth, t, true)
            .expect_err("port fermé");
        assert!(!e.contains("ROUTABLE"), "le loopback en clair reste servi, obtenu: {e}");
    }

    /// `resolve_guarded_with` est LE goulot résolution+garde : impossible d'obtenir une adresse interne
    /// sans autorisation explicite. MUTATION : retirer le `if !allow_internal { … }` -> ce test rougit.
    #[test]
    fn resolve_guarded_is_the_single_chokepoint() {
        assert!(super::resolve_guarded_with("127.0.0.1", 9, false).is_err(), "loopback refusé par défaut");
        assert!(super::resolve_guarded_with("127.0.0.1", 9, true).is_ok(), "autorisé explicitement");
    }

    /// L'ESCAPE-HATCH `FORGE_ALLOW_INTERNAL_INTEGRATIONS=1` est LU (`internal_targets_allowed`) et
    /// COMPOSÉ tel quel avec la garde — c'est la composition EXACTE de la production (lecture au bord,
    /// booléen passé en paramètre) : une cible interne passe alors, SIEM/IdP privé on-prem légitime. On
    /// POSE la var et on la laisse posée : c'est l'état DÉSIRÉ par tout le binaire de test (les mocks
    /// OIDC/webhook loopback en dépendent), donc AUCUN test ne l'unset -> pas de course sur l'env
    /// process-global. La direction « refus par défaut » est prouvée par `reject_internal_addr` (pur) et
    /// par `fetcher_applies_the_deny_list_over_both_schemes` (bout en bout) ci-dessus.
    #[test]
    fn escape_hatch_env_allows_internal() {
        crate::testutil::allow_internal_integrations_once(); // pose la var UNE fois (jamais unset)
        assert!(super::internal_targets_allowed(), "l'escape-hatch est bien lu depuis l'env");
        let allow = super::internal_targets_allowed();
        assert!(super::resolve_guarded_with("169.254.169.254", 80, allow).is_ok(), "métadonnées autorisées");
        assert!(super::resolve_guarded_with("10.1.2.3", 80, allow).is_ok(), "RFC1918 autorisé");
    }
}

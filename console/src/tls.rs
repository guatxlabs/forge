// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — SEAM TLS SORTANT : **le** point de sortie TCP de la console.
//!
//! POURQUOI CE MODULE EXISTE. La console a exactement TROIS sorties TCP en production — l'échange de
//! jeton OIDC (`sso/mod.rs`), le webhook de notification (`notify_channels.rs`) et le fetcher de source
//! de détection (`net.rs`). Elles partaient toutes en `TcpStream::connect_timeout` brut, donc EN CLAIR.
//! La plus grave était la première : le POST au token endpoint porte le **`client_secret`** (`Authorization:
//! Basic`) ET le **`code`** d'autorisation ; en clair, les deux sont interceptables sur le fil, et la
//! documentation de déploiement prescrivait un proxy TLS d'egress en contournement. La décision est
//! tranchée : **pas de clair**. Ce module est la conséquence.
//!
//! CE QU'IL GARANTIT — invariants, chacun avec un test qui ROUGIT si on le retire :
//!   1. **UNE seule implémentation TLS.** Les trois sites appellent [`connect`] ; aucun ne construit de
//!      session TLS pour son compte. La propriété se vérifie donc UNE fois, ici.
//!   2. **VÉRIFICATION COMPLÈTE, SANS ÉCHAPPATOIRE.** Le `ClientConfig` est bâti par
//!      [`client_config`] avec le vérificateur webpki STANDARD (chaîne jusqu'aux racines Mozilla de
//!      `webpki-roots` + nom d'hôte). Il n'existe **aucun** drapeau, aucune variable d'environnement,
//!      aucun paramètre pour l'affaiblir : ni `insecure_skip_verify` (tls-danger-ok — mention, pas
//!      usage), ni « accepter un certificat auto-signé », ni
//!      vérificateur maison. Un TLS qui ne vérifie rien est du clair déguisé — c'est précisément par là
//!      que les échappatoires entrent. `tls_source_carries_no_verification_escape_hatch` fige ça au
//!      niveau SOURCE (le crate n'a pas le droit d'ouvrir l'API `dangerous` de rustls).
//!   3. **Le handshake décide AVANT le premier octet applicatif** — [`connect`] le mène à son terme, donc
//!      un certificat non fiable fait échouer la CONNEXION, pas une lecture ultérieure. Aucune requête
//!      (donc aucun secret) n'est écrite sur une session dont le pair n'est pas prouvé.
//!   4. **openssl-freedom préservée.** `rustls` est épinglé sur le provider `ring`
//!      (`default-features = false`) : ni `aws-lc-rs`, ni `native-tls`, ni `openssl-sys`, ni `schannel`,
//!      ni `security-framework` dans la fermeture. Les racines viennent de `webpki-roots` (données
//!      pures), jamais du magasin système — donc aucune dépendance OS.
//!
//! CE QU'IL NE FAIT PAS. Il ne décide pas QUI l'on a le droit de joindre : la deny-list SSRF
//! (`net::reject_internal_addr`, via `net::resolve_guarded_with`) reste en amont et s'applique à
//! l'adresse RÉSOLUE que l'on va connecter. [`connect`] prend une `SocketAddr` DÉJÀ gardée — le seam
//! transporte, il n'autorise pas. Et il ne fait pas de SMTP : STARTTLS est une élévation NÉGOCIÉE
//! (classe d'injection de commandes en clair) et le SMTP réel se pratique en TLS opportuniste contre des
//! relais auto-signés ; débuter un client TLS sur le protocole aux pires sémantiques d'élévation serait
//! le mauvais ordre (cf. la note en fin de `notify_channels.rs`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Schéma de transport d'une cible d'intégration. Jeu FERMÉ : tout le reste est refusé au parsing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Scheme {
    /// `http://` — clair. Reste possible là où c'est GOUVERNÉ (collecteur/IdP on-prem via
    /// `FORGE_ALLOW_INTERNAL_INTEGRATIONS`), jamais avec un secret vers une cible publique.
    Http,
    /// `https://` — TLS avec vérification complète du certificat.
    Https,
}

impl Scheme {
    /// Port par défaut du schéma (RFC 9110 §4.2).
    pub(crate) fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
    /// Le transport chiffre-t-il ? Seul prédicat que les appelants doivent connaître pour décider
    /// qu'un secret peut légitimement partir (cf. `notify_channels::plan_delivery`).
    pub(crate) fn is_tls(self) -> bool {
        matches!(self, Scheme::Https)
    }
}

/// Cible d'intégration décomposée. `authority` est la forme BRUTE (`host[:port]`) telle qu'elle doit
/// repartir dans l'en-tête `Host:` ; `host` est le nom utilisé pour la RÉSOLUTION et pour la
/// VÉRIFICATION du certificat (SNI + nom d'hôte du certificat).
pub(crate) struct Target {
    pub(crate) scheme: Scheme,
    pub(crate) authority: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
}

/// Décompose une URL d'intégration `scheme://authority[/path]` — PUR, sans réseau, sans env.
///
/// UNE seule copie de ce découpage pour les trois sites (chacun avait la sienne, au schéma près).
/// Fail-closed : schéma hors {http, https} refusé, autorité vide ou porteuse de CR/LF refusée (une
/// injection d'en-tête `Host:` n'a jamais lieu d'être). Le `path` par défaut est `/`.
pub(crate) fn split_url(url: &str) -> Result<Target, String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r)
    } else {
        return Err("l'endpoint doit commencer par http:// ou https://".to_string());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('\r') || authority.contains('\n') {
        return Err("autorité d'endpoint invalide (vide ou CR/LF) — refusé".to_string());
    }
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        return Err("hôte d'endpoint vide — refusé".to_string());
    }
    let port: u16 = authority
        .split(':')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| scheme.default_port());
    Ok(Target {
        scheme,
        authority: authority.to_string(),
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

/// Connexion sortante d'intégration : socket nu (clair GOUVERNÉ) ou session TLS VÉRIFIÉE. Les appelants
/// écrivent/lisent du HTTP/1.1 dessus sans savoir laquelle des deux ils tiennent — c'est ce qui permet
/// aux trois sites de partager un seul chemin.
pub(crate) enum Conn {
    Plain(TcpStream),
    /// Boxée : `StreamOwned` porte tout l'état de session rustls (gros) — on ne le met pas sur la pile
    /// des appelants ni dans chaque `Result`.
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// Nombre maximal de tours de `complete_io` pour mener le handshake. Un socket BLOQUANT à timeout mène
/// normalement le handshake en UN tour ; la borne interdit qu'un pair pathologique (progrès nul répété)
/// fasse tourner la boucle indéfiniment. Franchie => erreur nommée, jamais une attente infinie.
const HANDSHAKE_ROUNDS: usize = 8;

/// Config client TLS PARTAGÉE, construite UNE fois (`OnceLock`) : provider `ring` EXPLICITE + racines
/// Mozilla `webpki-roots` + vérificateur webpki STANDARD (chaîne + nom d'hôte) + aucun certificat client.
///
/// Le provider est passé EXPLICITEMENT plutôt que pris du défaut de process : c'est ce qui garantit
/// qu'aucun autre backend crypto (aws-lc-rs) ne puisse être installé sous nos pieds par une dépendance
/// tierce. `with_root_certificates` installe le vérificateur webpki standard — il n'y a, dans ce crate,
/// AUCUN chemin qui le remplace.
fn client_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CFG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if roots.is_empty() {
            // Fail-closed : sans racine, TOUT certificat serait non vérifiable — on refuse de bâtir une
            // config plutôt que de laisser un appelant croire qu'il parle TLS.
            return Err("aucune racine CA compilée (webpki-roots vide) — TLS refusé".to_string());
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("configuration TLS invalide: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(cfg))
    })
    .clone()
}

/// LE point de sortie TCP de la console. Connecte `addr` — **déjà résolue ET déjà passée par la
/// deny-list SSRF de l'appelant** (`net::resolve_guarded_with` / `net::reject_internal_addr`) —, pose
/// les timeouts de lecture/écriture, puis :
///   - `Scheme::Http`  : rend le socket nu (clair, cas GOUVERNÉ on-prem) ;
///   - `Scheme::Https` : mène le handshake TLS À SON TERME, avec vérification complète du certificat
///     contre `verify_host`. Un certificat non fiable (auto-signé, chaîne inconnue, nom d'hôte qui ne
///     correspond pas, expiré) fait échouer CETTE fonction — donc avant qu'un seul octet applicatif,
///     `client_secret` compris, n'ait pu être écrit.
///
/// `verify_host` est le nom d'hôte de l'URL (jamais l'IP résolue) : c'est lui qui est présenté en SNI et
/// contre lequel le certificat est vérifié.
pub(crate) fn connect(addr: &SocketAddr, verify_host: &str, scheme: Scheme, timeout: Duration) -> Result<Conn, String> {
    let sock = TcpStream::connect_timeout(addr, timeout).map_err(|e| format!("connexion {addr} échouée: {e}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();
    if !scheme.is_tls() {
        return Ok(Conn::Plain(sock));
    }
    let cfg = client_config()?;
    let server_name = rustls::pki_types::ServerName::try_from(verify_host.to_string())
        .map_err(|_| format!("nom d'hôte TLS invalide: {verify_host}"))?;
    let mut session = rustls::ClientConnection::new(cfg, server_name)
        .map_err(|e| format!("session TLS impossible vers {verify_host}: {e}"))?;
    let mut sock = sock;
    // HANDSHAKE MENÉ À TERME ICI. `complete_io` fait tourner l'E/S jusqu'à ce que rustls n'ait plus rien
    // à écrire/lire ; la vérification du certificat s'y produit et remonte en `Err`. Tant que le pair
    // n'est pas prouvé, l'appelant n'a pas de flux — il ne peut donc rien lui écrire.
    let mut rounds = 0usize;
    while session.is_handshaking() {
        rounds += 1;
        if rounds > HANDSHAKE_ROUNDS {
            return Err(format!("handshake TLS vers {verify_host} sans progrès — abandon"));
        }
        session
            .complete_io(&mut sock)
            .map_err(|e| format!("handshake TLS vers {verify_host} ({addr}) échoué: {e}"))?;
    }
    Ok(Conn::Tls(Box::new(rustls::StreamOwned::new(session, sock))))
}

#[cfg(test)]
mod tests;

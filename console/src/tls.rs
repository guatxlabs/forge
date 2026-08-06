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
//!
//!   2bis. **CA PRIVÉE D'ENTREPRISE — une ANCRE DE PLUS, JAMAIS un contrôle DE MOINS.** Le magasin de
//!      CA du SYSTÈME n'est PAS lu (c'est ce qui évite `schannel`/`security-framework`/`openssl` —
//!      invariant #4). Sans knob, un déploiement dont l'IdP OIDC ou le collecteur est signé par la CA
//!      privée de l'organisation n'avait que de mauvaises issues, dont le retour au clair. Le knob
//!      [`EXTRA_CA_VAR`] fournit donc des ancres SUPPLÉMENTAIRES, explicitement posées par l'opérateur.
//!      La DISTINCTION est tout le sujet, et elle est prouvée par un COUPLE de tests :
//!        - AJOUTER une ancre ÉLARGIT l'ensemble des émetteurs de confiance. La chaîne est toujours
//!          validée jusqu'à une ancre, le nom d'hôte toujours vérifié, l'expiration toujours honorée —
//!          `enterprise_ca_pem_makes_its_own_chain_verify` (l'ancre fournie fait ABOUTIR le handshake)
//!          FACE À `enterprise_ca_pem_still_rejects_another_ca`, `…_still_verifies_the_hostname` et
//!          `…_still_honours_expiry` (les trois autres contrôles MORDENT toujours, ancre en place) ;
//!        - RELÂCHER un contrôle (accepter n'importe quelle chaîne, ne plus vérifier le nom, ignorer
//!          l'expiration) reste INTERDIT et le demeure au niveau SOURCE. `with_root_certificates`
//!          accepte des ancres supplémentaires SANS jamais toucher à l'API `dangerous` de rustls.
//!      FAIL-CLOSED : un PEM configuré mais illisible/invalide fait ÉCHOUER LE BOOT ([`preflight`]) ;
//!      il ne dégrade JAMAIS en silence vers « pas d'ancre » (l'opérateur croirait sa CA en place).
//!
//!   2ter. **IDENTITÉ CLIENTE (mTLS) — ce que NOUS présentons, quand le pair l'EXIGE.** Le seam
//!      n'installait AUCUN certificat client (`with_no_client_auth`), et un endpoint mTLS — IdP OIDC
//!      d'entreprise, collecteur derrière un service-mesh — restait donc DÉLÉGUÉ au collecteur Python.
//!      Ce délégué n'existe plus : [`CLIENT_CERT_VAR`] / [`CLIENT_KEY_VAR`] (motif maison `<VAR>` +
//!      jumeau `_FILE`, comme l'ancre d'entreprise) posent une chaîne et sa clé, et rustls les présente
//!      NATIVEMENT (`with_client_auth_cert`) — aucune dépendance nouvelle, aucune bibliothèque système.
//!      Deux choses à ne pas confondre : présenter une identité est une AUTHENTIFICATION DE NOUS vers le
//!      pair ; ça ne touche EN RIEN la vérification du certificat SERVEUR, qui reste pleine (invariant
//!      #2) — `mtls_client_certificate_is_presented_and_accepted` s'appuie d'ailleurs sur l'ancre
//!      d'entreprise pour vérifier le serveur de test.
//!      **LA CLÉ PRIVÉE EST LE SECRET LE PLUS SENSIBLE DE CE BINAIRE**, et le cœur du travail n'est pas
//!      le handshake mais son confinement : elle n'apparaît NI dans un log, NI dans une erreur, NI au
//!      boot, NI nulle part ailleurs. Tout échec qui la touche est CLASSÉ, jamais CITÉ
//!      ([`invalid_key_msg`]) — y compris l'erreur de la bibliothèque, qui recopie volontiers la ligne
//!      fautive. `client_key_material_never_leaks_into_an_error` et
//!      `client_key_material_never_leaks_into_the_boot_line` BALAIENT les sorties à la recherche d'un
//!      fragment du corps de la clé.
//!      FAIL-CLOSED : une identité à MOITIÉ configurée (cert sans clé, ou l'inverse), un PEM illisible,
//!      ou une clé qui NE CORRESPOND PAS au certificat font ÉCHOUER LE BOOT ([`preflight`]) en nommant
//!      la variable — jamais un mTLS silencieusement absent qui se découvrirait au premier handshake
//!      sous la forme d'une « connexion refusée » qui ne désigne pas la cause.
//!
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

// =================================================================================================
//  ANCRES DE CONFIANCE SUPPLÉMENTAIRES — la CA privée d'entreprise
// =================================================================================================

/// Variable d'environnement portant le PEM des ancres de confiance SUPPLÉMENTAIRES (CA privée
/// d'entreprise). MOTIF MAISON `secret_env` : la variable porte le PEM VERBATIM,
/// `FORGE_EXTRA_CA_PEM_FILE` porte un CHEMIN vers le fichier PEM (montage Docker/k8s ConfigMap) —
/// la variable directe prime, le jumeau `_FILE` est le repli.
pub(crate) const EXTRA_CA_VAR: &str = "FORGE_EXTRA_CA_PEM";

/// Résout un PEM depuis l'environnement selon le MOTIF MAISON : `<VAR>` porte le PEM VERBATIM,
/// `<VAR>_FILE` porte un CHEMIN (montage Docker/k8s) — la variable directe prime, le jumeau est le
/// repli. `what` nomme ce qu'on chargeait, pour un message d'échec qui SITUE le problème.
/// `Ok(None)` = RIEN de configuré. `Ok(Some(pem))` = PEM à parser. `Err` = configuré mais INEXPLOITABLE.
///
/// ⚠️ AUCUN chemin d'ici ne met le CONTENU dans un message — seulement le NOM de la variable et le KIND
/// d'erreur d'E/S. Ce n'est pas de la coquetterie : cette fonction sert AUSSI à résoudre la CLÉ PRIVÉE
/// cliente ([`CLIENT_KEY_VAR`]), et un `format!` de confort ici la déverserait dans les journaux.
///
/// POURQUOI PAS `secret_env::secret_from_env` TEL QUEL, alors qu'on en suit le motif : ce helper est
/// FAIL-SOFT par contrat (un `<VAR>_FILE` illisible rend `None` + un avertissement, pour que le repli
/// de l'appelant — auto-génération, refus — s'engage). Ici, `None` signifierait « pas d'ancre
/// d'entreprise » / « pas d'identité cliente » : l'opérateur croirait sa CA (ou son certificat) en
/// place, et le premier handshake vers son IdP échouerait sans que rien ne désigne le PEM. C'est la
/// DÉGRADATION SILENCIEUSE que tout ce travail interdit. On duplique donc la PRÉCÉDENCE (identique,
/// testée) mais pas la POLITIQUE D'ÉCHEC : ici un PEM configuré et illisible est une ERREUR, remontée
/// jusqu'au boot.
fn pem_from_env(var: &str, what: &str) -> Result<Option<String>, String> {
    // 1) Variable directe posée & non blanche : c'est le PEM lui-même.
    if let Ok(v) = std::env::var(var) {
        if !v.trim().is_empty() {
            return Ok(Some(v));
        }
    }
    // 2) `<VAR>_FILE` : la variable porte un CHEMIN, le PEM vit dans le fichier monté.
    let file_var = format!("{var}_FILE");
    let path = match std::env::var(&file_var) {
        Ok(p) if !p.trim().is_empty() => p,
        _ => return Ok(None), // 3) rien de configuré — cas par défaut
    };
    match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => Ok(Some(s)),
        Ok(_) => Err(format!(
            "{file_var} désigne un fichier VIDE — {what} n'en sortirait pas, et le déploiement croirait \
             sa configuration en place. Refus (fail-closed)."
        )),
        // On nomme la VARIABLE et le KIND d'erreur d'E/S, jamais le contenu.
        Err(e) => Err(format!(
            "{file_var} illisible ({}) — impossible de charger {what}. Refus (fail-closed) plutôt que \
             de démarrer SANS ce que l'opérateur croit avoir posé.",
            e.kind()
        )),
    }
}

/// Résout le PEM d'ancres supplémentaires depuis l'environnement (motif maison, cf. [`pem_from_env`]).
pub(crate) fn extra_ca_pem_from_env() -> Result<Option<String>, String> {
    pem_from_env(EXTRA_CA_VAR, "l'ancre de confiance d'entreprise")
}

/// Parse un PEM en ancres de confiance. FAIL-CLOSED de bout en bout : un bloc mal formé, un contenu
/// sans aucun `CERTIFICATE`, ou un certificat que le vérificateur refuse comme ancre => `Err`. Il
/// n'existe AUCUN chemin qui ignore un bloc en silence et rende quand même une liste amputée.
fn parse_extra_anchors(pem: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    use rustls::pki_types::pem::PemObject;
    let mut out = Vec::new();
    for item in rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
        out.push(item.map_err(|e| {
            format!("{EXTRA_CA_VAR} : PEM invalide ({e:?}) — aucune ancre chargée (fail-closed)")
        })?);
    }
    if out.is_empty() {
        return Err(format!(
            "{EXTRA_CA_VAR} : aucun bloc CERTIFICATE dans le PEM fourni — refus (fail-closed). Une CA \
             d'entreprise se fournit en PEM `-----BEGIN CERTIFICATE-----`."
        ));
    }
    Ok(out)
}

// =================================================================================================
//  IDENTITÉ CLIENTE — le certificat que NOUS présentons quand le pair l'EXIGE (mTLS)
// =================================================================================================

/// Variable portant la CHAÎNE de certificats CLIENTE au format PEM (feuille D'ABORD, intermédiaires
/// ensuite). MOTIF MAISON `secret_env` : `FORGE_CLIENT_CERT_PEM_FILE` porte un CHEMIN — la variable
/// directe prime, le jumeau `_FILE` est le repli. Un certificat est PUBLIC (le pair le reçoit sur le
/// fil) : ses échecs de parsing peuvent donc être détaillés, contrairement à ceux de la clé.
pub(crate) const CLIENT_CERT_VAR: &str = "FORGE_CLIENT_CERT_PEM";

/// Variable portant la CLÉ PRIVÉE de cette chaîne (PEM PKCS#8, PKCS#1 ou SEC1).
///
/// ⚠️ **C'EST LE SECRET LE PLUS SENSIBLE QUE CE BINAIRE MANIPULE** — davantage qu'un `client_secret`
/// OIDC ou qu'un jeton d'ingest : elle ne s'expire pas d'elle-même et elle SIGNE notre identité auprès
/// de tout pair mTLS. Elle ne doit apparaître NI dans un log, NI dans une erreur, NI dans le ledger, NI
/// dans un finding, NI dans une réponse d'API, NI dans un message de diagnostic au boot. Les seuls
/// chemins qui la touchent sont [`pem_from_env`] (qui ne cite jamais le contenu), [`parse_client_key`]
/// et [`client_auth_error`] (qui CLASSENT l'échec au lieu de le CITER). La forme `_FILE` est la forme
/// RECOMMANDÉE : l'environnement d'un processus se lit dans `/proc/<pid>/environ` et se recopie dans
/// tout dump de configuration ; un fichier monté root-only, non.
pub(crate) const CLIENT_KEY_VAR: &str = "FORGE_CLIENT_KEY_PEM";

/// Identité cliente RÉSOLUE, sous sa forme PEM, telle que l'opérateur l'a fournie.
///
/// **NE DÉRIVE PAS `Debug`, et ne doit jamais en dériver** : c'est ce qui rend impossible d'imprimer la
/// clé « par accident » (un `dbg!`, un `{:?}` dans un `Result`, un log d'erreur générique). Même raison
/// que l'absence de `Debug` sur [`Conn`]. Le type est éphémère : il vit le temps de bâtir la config
/// TLS et rien ne le stocke.
pub(crate) struct ClientIdentityPem {
    /// Chaîne de certificats (PUBLIQUE).
    cert: String,
    /// Clé privée (SECRÈTE — cf. [`CLIENT_KEY_VAR`]).
    key: String,
}

/// Résout l'identité cliente depuis l'environnement, FAIL-CLOSED sur la MOITIÉ.
///
/// `Ok(None)` = rien de configuré (cas de l'immense majorité des installs : aucun certificat client
/// présenté, comportement byte-identique à avant). `Ok(Some(id))` = les DEUX moitiés sont là.
///
/// UNE SEULE DES DEUX => `Err`. C'est le cas qu'il fallait trancher : un certificat sans clé ne peut
/// rien signer, une clé sans certificat ne prouve aucune identité, et dans les deux cas rustls
/// n'enverrait tout simplement PAS de certificat. Le pair mTLS refuserait alors la connexion et
/// l'opérateur lirait « connexion refusée » — un message qui ne désigne pas la variable manquante. On
/// meurt donc au boot, en la nommant.
pub(crate) fn client_identity_from_env() -> Result<Option<ClientIdentityPem>, String> {
    let cert = pem_from_env(CLIENT_CERT_VAR, "le certificat client (mTLS)")?;
    // `Some(_)`/`is_some()` UNIQUEMENT sur la clé : sa valeur ne doit transiter par aucun message.
    let key = pem_from_env(CLIENT_KEY_VAR, "la clé privée cliente (mTLS)")?;
    match (cert, key) {
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => Ok(Some(ClientIdentityPem { cert, key })),
        (Some(_), None) => Err(format!(
            "{CLIENT_CERT_VAR} est posé mais ni {CLIENT_KEY_VAR} ni {CLIENT_KEY_VAR}_FILE — un \
             certificat client SANS SA CLÉ ne peut rien signer : aucune identité ne serait présentée, \
             et un pair mTLS refuserait la connexion sans que rien ne désigne la cause. Refus \
             (fail-closed)."
        )),
        (None, Some(_)) => Err(format!(
            "{CLIENT_KEY_VAR} est posé mais ni {CLIENT_CERT_VAR} ni {CLIENT_CERT_VAR}_FILE — une clé \
             privée SANS SON CERTIFICAT ne prouve aucune identité : aucune identité ne serait \
             présentée, et un pair mTLS refuserait la connexion sans que rien ne désigne la cause. \
             Refus (fail-closed)."
        )),
    }
}

/// Parse la CHAÎNE de certificats CLIENTE. FAIL-CLOSED : bloc mal formé ou aucun `CERTIFICATE` => `Err`.
/// Le détail de l'erreur est ADMIS ici — un certificat client est public, le pair le reçoit sur le fil.
fn parse_client_certs(pem: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    use rustls::pki_types::pem::PemObject;
    let mut out = Vec::new();
    for item in rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
        out.push(item.map_err(|e| {
            format!("{CLIENT_CERT_VAR} : PEM invalide ({e:?}) — aucun certificat client chargé (fail-closed)")
        })?);
    }
    if out.is_empty() {
        return Err(format!(
            "{CLIENT_CERT_VAR} : aucun bloc CERTIFICATE dans le PEM fourni — refus (fail-closed). Une \
             chaîne cliente se fournit en PEM `-----BEGIN CERTIFICATE-----`, feuille d'abord."
        ));
    }
    Ok(out)
}

/// Message d'échec portant sur la CLÉ PRIVÉE : NOMME la variable et la NATURE du défaut, JAMAIS le
/// contenu. `reason` est choisi dans un jeu FERMÉ de littéraux (tous les appels sont dans ce fichier) —
/// **aucune donnée ne peut transiter par ce paramètre**, c'est ce qui rend le confinement vérifiable
/// par relecture en plus du balayage de `client_key_material_never_leaks_into_an_error`.
fn invalid_key_msg(reason: &str) -> String {
    format!(
        "{CLIENT_KEY_VAR} : clé privée cliente inexploitable — {reason}. Refus (fail-closed). Aucun \
         extrait de la clé n'est journalisé, ici ni ailleurs : cette variable porte le secret le plus \
         sensible du binaire."
    )
}

/// Parse la CLÉ PRIVÉE cliente (PKCS#8 / PKCS#1 / SEC1).
///
/// ⚠️ AUCUN message d'ici ne porte le moindre octet du PEM — ni la valeur, ni un fragment, ni l'erreur
/// de la bibliothèque. Ce dernier point est le piège, et il est MESURÉ, pas supposé :
/// `rustls::pki_types::pem::Error::IllegalSectionStart` recopie la LIGNE fautive et `Base64Decode`
/// recopie un octet du corps. Propager `{e:?}` « pour aider au diagnostic » serait donc déverser du
/// matériel de clé dans les journaux. On CLASSE l'échec (jeu fermé de raisons), on ne le CITE pas.
fn parse_client_key(pem: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    use rustls::pki_types::pem::PemObject;
    let mut keys = rustls::pki_types::PrivateKeyDer::pem_slice_iter(pem.as_bytes());
    let first = match keys.next() {
        Some(Ok(k)) => k,
        Some(Err(_)) => return Err(invalid_key_msg("PEM illisible ou corrompu")),
        None => {
            return Err(invalid_key_msg(
                "aucun bloc de clé privée (« PRIVATE KEY », « RSA PRIVATE KEY » ou « EC PRIVATE KEY »)",
            ))
        }
    };
    // Plusieurs clés dans un même PEM : laquelle présenter ? Aucune réponse défendable => refus, plutôt
    // qu'un « la première gagne » que l'opérateur ne pourrait pas deviner.
    match keys.next() {
        None => {}
        Some(Ok(_)) => {
            return Err(invalid_key_msg(
                "PLUSIEURS clés privées dans le même PEM — laquelle présenter serait arbitraire",
            ))
        }
        Some(Err(_)) => return Err(invalid_key_msg("PEM illisible ou corrompu après la première clé")),
    }
    Ok(first)
}

/// Traduit un échec d'installation du certificat client. Comme [`parse_client_key`] : on CLASSE, on ne
/// CITE pas. `rustls::Error::General` porte une chaîne fournie par le fournisseur crypto — rien ne
/// garantit CONTRACTUELLEMENT qu'elle restera exempte de matériel, et on ne parie pas là-dessus pour un
/// secret de ce niveau.
///
/// Le cas qui compte est le DÉPAREILLAGE : rustls compare les `SubjectPublicKeyInfo` de la clé et du
/// certificat (`CertifiedKey::from_der` -> `keys_match`) et rend `InconsistentKeys`. C'est exactement la
/// faute qu'un opérateur commet en renouvelant l'un sans l'autre, et elle DOIT tuer le boot.
fn client_auth_error(e: &rustls::Error) -> String {
    if matches!(e, rustls::Error::InconsistentKeys(_)) {
        return format!(
            "{CLIENT_KEY_VAR} ne correspond PAS à {CLIENT_CERT_VAR} — la clé fournie n'est pas celle du \
             certificat (SubjectPublicKeyInfo différents). Refus (fail-closed) : une identité \
             dépareillée ne se découvrirait qu'au premier handshake mTLS, sous la forme d'une \
             « connexion refusée » qui ne désigne pas la cause."
        );
    }
    invalid_key_msg("refusée par le fournisseur crypto `ring` (format ou algorithme non supporté)")
}

/// Bâtit un `ClientConfig` : provider `ring` EXPLICITE + racines Mozilla `webpki-roots` + les ancres
/// SUPPLÉMENTAIRES éventuelles + vérificateur webpki STANDARD (chaîne + nom d'hôte + validité) +
/// l'identité CLIENTE éventuelle.
///
/// Le provider est passé EXPLICITEMENT plutôt que pris du défaut de process : c'est ce qui garantit
/// qu'aucun autre backend crypto (aws-lc-rs) ne puisse être installé sous nos pieds par une dépendance
/// tierce. `with_root_certificates` installe le vérificateur webpki standard — il n'y a, dans ce crate,
/// AUCUN chemin qui le remplace, et AJOUTER une ancre ne le change pas : `roots` est l'ENSEMBLE des
/// émetteurs de confiance, pas un interrupteur de vérification. Les PEM sont des PARAMÈTRES (jamais une
/// lecture d'env ici) — c'est ce qui rend les couples de tests déterministes.
///
/// `client_identity` = `None` (cas par défaut, immense majorité des installs) reproduit exactement
/// l'ancien `with_no_client_auth`. `Some(..)` installe la chaîne + la clé : rustls ne les présentera
/// QUE si le pair DEMANDE un certificat, et la vérification du certificat SERVEUR n'en est pas
/// affectée d'un iota.
pub(crate) fn build_client_config(
    extra_ca_pem: Option<&str>,
    client_identity: Option<&ClientIdentityPem>,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if roots.is_empty() {
        // Fail-closed : sans racine, TOUT certificat serait non vérifiable — on refuse de bâtir une
        // config plutôt que de laisser un appelant croire qu'il parle TLS.
        return Err("aucune racine CA compilée (webpki-roots vide) — TLS refusé".to_string());
    }
    if let Some(pem) = extra_ca_pem {
        for der in parse_extra_anchors(pem)? {
            // `add` VALIDE le certificat comme ancre (il doit être une CA exploitable) : un PEM qui
            // porte autre chose est REFUSÉ ici, pas silencieusement rangé dans le magasin.
            roots.add(der).map_err(|e| {
                format!("{EXTRA_CA_VAR} : certificat refusé comme ancre de confiance ({e}) — fail-closed")
            })?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("configuration TLS invalide: {e}"))?
        .with_root_certificates(roots);
    let cfg = match client_identity {
        None => builder.with_no_client_auth(),
        Some(id) => {
            let certs = parse_client_certs(&id.cert)?;
            // `key` n'est JAMAIS mis dans un message : `with_client_auth_cert` la consomme, et l'erreur
            // éventuelle passe par `client_auth_error`, qui classe sans citer.
            let key = parse_client_key(&id.key)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| client_auth_error(&e))?
        }
    };
    Ok(Arc::new(cfg))
}

/// Config client TLS PARTAGÉE DU PROCESSUS, construite UNE fois (`OnceLock`) depuis l'environnement.
/// Une seule politique de confiance pour tout le binaire — ancres d'entreprise ET identité cliente
/// comprises. Les PEM résolus meurent avec cet appel : rien ne conserve la clé privée sous forme de
/// texte au-delà de la construction.
fn client_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CFG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CFG.get_or_init(|| {
        build_client_config(
            extra_ca_pem_from_env()?.as_deref(),
            client_identity_from_env()?.as_ref(),
        )
    })
    .clone()
}

/// CONTRÔLE AU BOOT de TOUTE la matière TLS configurable — ancres d'entreprise ET identité cliente
/// (mTLS). Appelé AVANT que quoi que ce soit ne démarre, pour qu'un PEM illisible/invalide, une
/// identité à moitié posée ou une clé dépareillée tuent le boot BRUYAMMENT, au lieu de se découvrir au
/// premier handshake, des heures plus tard, sous la forme d'un « certificat inconnu » ou d'une
/// « connexion refusée » qui ne désignent pas la vraie cause.
///
/// UN SEUL préflight, délibérément : le seam a UNE politique (une config, un `OnceLock`), donc UN point
/// où elle est contrôlée. Ajouter un second contrôle pour l'identité cliente aurait ouvert la porte à
/// deux ordres de boot divergents.
///
/// `Ok(None)` : rien de configuré — boot STRICTEMENT silencieux (byte-identique pour l'immense majorité
/// des installs). `Ok(Some(lignes))` : une ligne par élément chargé, à annoncer. `Err(raison)` : FATAL.
///
/// ⚠️ La ligne d'annonce de l'identité cliente ne porte AUCUN octet de la clé : elle dit qu'une clé a
/// été chargée et depuis quelle variable, rien d'autre
/// (`client_key_material_never_leaks_into_the_boot_line`).
pub(crate) fn preflight() -> Result<Option<String>, String> {
    let pem = extra_ca_pem_from_env()?;
    let identity = client_identity_from_env()?;
    let count = match &pem {
        Some(p) => parse_extra_anchors(p)?.len(),
        None => 0,
    };
    let chain_len = match &identity {
        Some(id) => parse_client_certs(&id.cert)?.len(),
        None => 0,
    };
    // Construit RÉELLEMENT la config : un PEM qui parse mais dont un certificat n'est pas une ancre
    // exploitable, ou une clé qui ne correspond pas au certificat, doivent tomber ICI, au boot, pas au
    // premier egress.
    build_client_config(pem.as_deref(), identity.as_ref())?;
    let mut lines: Vec<String> = Vec::new();
    if count > 0 {
        lines.push(format!(
            "[forge] TLS — {count} ancre(s) de confiance d'ENTREPRISE chargée(s) depuis {EXTRA_CA_VAR} \
             (en PLUS des racines Mozilla). La vérification reste PLEINE : chaîne validée, nom d'hôte \
             vérifié, expiration honorée — une ancre de plus, aucun contrôle de moins."
        ));
    }
    if identity.is_some() {
        lines.push(format!(
            "[forge] TLS — IDENTITÉ CLIENTE (mTLS) armée : chaîne de {chain_len} certificat(s) depuis \
             {CLIENT_CERT_VAR}, clé privée chargée depuis {CLIENT_KEY_VAR} (jamais journalisée, sous \
             aucune forme). Elle n'est présentée QUE si le pair la DEMANDE ; la vérification du \
             certificat SERVEUR reste pleine et inchangée."
        ));
    }
    if lines.is_empty() {
        return Ok(None);
    }
    Ok(Some(lines.join("\n")))
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
    connect_with(addr, verify_host, scheme, timeout, None)
}

/// Cœur de [`connect`], avec la POLITIQUE DE CONFIANCE en PARAMÈTRE (`None` => la config partagée du
/// processus, bâtie depuis l'environnement). Même patron exact que
/// `net::http_get_blocking_with(_, allow_internal)` et `notify_channels::plan_delivery(_, allow_internal)`,
/// et pour la même raison : ce qui décide d'un REFUS doit être injectable, sinon la direction du refus
/// (« cette chaîne-là passe, cette autre non ») n'est pas mesurable de façon déterministe. La
/// production n'a qu'UN appelant, [`connect`], qui passe `None`.
pub(crate) fn connect_with(
    addr: &SocketAddr,
    verify_host: &str,
    scheme: Scheme,
    timeout: Duration,
    cfg: Option<Arc<rustls::ClientConfig>>,
) -> Result<Conn, String> {
    let sock = TcpStream::connect_timeout(addr, timeout).map_err(|e| format!("connexion {addr} échouée: {e}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();
    if !scheme.is_tls() {
        return Ok(Conn::Plain(sock));
    }
    let cfg = match cfg {
        Some(c) => c,
        None => client_config()?,
    };
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

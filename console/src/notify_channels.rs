// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — CANAL DE NOTIFICATION SORTANT (webhook), gouverné comme l'egress LLM.
//!
//! Les notifications IN-APP (`notifications.rs`) restent la voie par défaut : elles ne quittent jamais
//! le processus. Ce module ajoute UNE sortie, et une seule : un POST HTTP vers un endpoint configuré par
//! un admin, quand une notification est créée. C'est de l'EGRESS DEPUIS UN OUTIL OFFENSIF — un finding
//! porte des preuves. Tout ici existe pour que ce qui sort soit inoffensif, et que ce qui est tracé ne
//! le soit pas.
//!
//! GOUVERNANCE (chaque garde a un test qui ROUGIT si on la retire) :
//!   1. OFF PAR DÉFAUT — aucune clé `settings.notify_channel` => `{kind:none, enabled:false}` =>
//!      AUCUN octet ne sort. Miroir EXACT de `scope.llm.enabled` (forge/llm.py) : l'opt-in est explicite,
//!      admin-only et ledgerisé. Un build/déploiement qui ne touche à rien est byte-identique.
//!   2. RÉDACTION PAR LA MÊME SURFACE QUE LES RAPPORTS — le corps passe par `redact::redact_secrets`
//!      (LA copie unique utilisée par `reports.rs`), PUIS par [`neutralize_urls`] : une URL de cible
//!      porte en général l'identifiant de la victime, elle ne sort donc jamais. Aucun secret de session,
//!      aucun matériel d'auth (le rédacteur couvre Bearer/JWT/AKIA/gh*/xox*/clef=valeur sensible).
//!   3. ANTI-SSRF — la deny-list d'INTÉGRATION partagée (`net::reject_internal_addr`) s'applique à
//!      l'ADRESSE RÉSOLUE que l'on va connecter (anti-DNS-rebinding) : loopback / RFC1918 / link-local /
//!      métadonnées cloud / ULA REFUSÉS par défaut, sauf `FORGE_ALLOW_INTERNAL_INTEGRATIONS=1` (le même
//!      escape-hatch que le fetcher de source de détection et le POST OIDC — pas un nouveau knob).
//!   4. SECRET WRITE-ONLY — le token du canal suit le motif maison (`detection_source`, contexte auth
//!      d'engagement) : jamais re-servi en lecture (`GET` rend `secret_set: bool`), jamais journalisé,
//!      jamais ledgerisé. `keep_secret:true` le conserve sans le retaper.
//!   5. PAS DE CREDENTIAL EN CLAIR SUR UN RÉSEAU PUBLIC — règle PARTAGÉE (`net::reject_cleartext_secret`),
//!      plus une copie locale : le fetcher de source de détection l'applique désormais AUSSI (il n'avait
//!      RIEN, et mettait son `Authorization:` en clair vers une source publique). La règle n'a pas changé
//!      pour CE site, sa CONSÉQUENCE si.
//!      La console parle désormais TLS nativement (seam `crate::tls`, certificat VÉRIFIÉ), donc :
//!        - `https://` vers une cible PUBLIQUE avec un secret => AUTORISÉ. C'est ce qui rend Slack /
//!          Teams / PagerDuty joignables, alors que le canal livré jusqu'ici ne pouvait atteindre qu'un
//!          collecteur on-prem ;
//!        - `http://` (clair) vers une cible PUBLIQUE avec un secret => TOUJOURS REFUSÉ. Le jeton
//!          partirait sur le fil ; aucune raison n'a jamais justifié ça, et le TLS n'en crée pas une ;
//!        - `http://` vers un collecteur INTERNE explicitement autorisé
//!          (`FORGE_ALLOW_INTERNAL_INTEGRATIONS=1`) => inchangé, avec ou sans secret. C'est le clair
//!          GOUVERNÉ, exactement comme la source de détection authentifiée on-prem d'aujourd'hui.
//!   6. ON JOURNALISE L'ENVOI, PAS LE CONTENU — le ledger porte le canal, le DESTINATAIRE RÉDIGÉ
//!      (`scheme://authority` — le PATH et la QUERY sont JETÉS : une URL de webhook style Slack porte
//!      son jeton dans le chemin), l'événement, les identifiants, et succès/échec. Jamais le texte.
//!   7. BEST-EFFORT — l'envoi ne casse ni ne ralentit la notification in-app : il part dans une tâche
//!      détachée (bornée en temps), et son échec n'a AUCUN effet sur la mutation appelante.
//!
//! NON CONSTRUIT, DÉLIBÉRÉMENT (cf. docs) : le canal SMTP. Voir la note en fin de fichier — il reste
//! refusé INDÉPENDAMMENT du seam TLS : STARTTLS est une élévation NÉGOCIÉE, pas un transport chiffré
//! d'emblée.
//!
//! CONSOMMATEUR EN AVAL : le SLA de triage (`notify_sla.rs`) n'ouvre PAS un second chemin de sortie —
//! il entre par `notifications::emit`, donc par [`dispatch`] ci-dessous, donc par CES rédactions.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Map, Value};
use std::net::SocketAddr;
use std::time::Duration;

use crate::{admin_denied, append_console_ledger, attribution_login, check_admin, App};

/// Clé `settings` qui porte la config du canal (une seule ligne, upsert admin).
pub(crate) const SETTINGS_KEY: &str = "notify_channel";

/// Jeu FERMÉ des canaux reconnus. `none` = pas de canal (défaut). Un kind inconnu est refusé à
/// l'écriture (fail-closed : jamais persisté, donc jamais tenté).
pub(crate) const CHANNEL_KINDS: &[&str] = &["none", "webhook"];

/// Jeu FERMÉ des schémas d'auth du canal (le token reste write-only quel que soit le schéma).
const AUTH_TYPES: &[&str] = &["none", "bearer", "header"];

/// Budget dur d'un envoi (connect + écriture + lecture). Court : une notification n'est pas critique,
/// et un endpoint lent ne doit pas retenir une tâche.
const SEND_TIMEOUT: Duration = Duration::from_secs(8);

/// Borne de lecture de la réponse du webhook (on ne lit que le statut ; anti-OOM sur un endpoint hostile).
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Borne du corps sortant (le texte d'une notification est court ; anti-abus).
const MAX_BODY_BYTES: usize = 16 * 1024;

/// Marqueur qui remplace toute URL neutralisée dans un corps sortant.
const URL_MARK: &str = "[URL]";

// =====================================================================================
//  CONFIG — lecture / rédaction (PURES, testables sans DB ni réseau)
// =====================================================================================

/// Config EFFECTIVE du canal : `settings.notify_channel` si c'est un objet JSON valide, sinon le défaut
/// FERMÉ `{kind:none, enabled:false}`. Il n'existe AUCUN repli par variable d'environnement : on
/// n'active pas un egress par accident de déploiement.
pub(crate) fn resolve_channel(store: &crate::store::Store) -> Value {
    resolve_channel_from(crate::settings_get_store(store, SETTINGS_KEY))
}

/// Cœur PUR de la résolution (testable sans store). Toute valeur illisible/non-objet retombe sur le
/// défaut fermé — jamais sur une config partiellement devinée.
pub(crate) fn resolve_channel_from(setting: Option<String>) -> Value {
    if let Some(s) = setting {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if v.is_object() {
                return v;
            }
        }
    }
    json!({"kind": "none", "enabled": false})
}

/// `kind` déclaré (défaut `none`).
pub(crate) fn ch_kind(cfg: &Value) -> String {
    cfg.get("kind").and_then(|v| v.as_str()).unwrap_or("none").trim().to_string()
}

/// Le canal est-il ARMÉ ? Exige `enabled:true` ET un kind ACTIF (jamais `none`) ET un endpoint non vide.
/// Fail-closed : toute config incomplète est INERTE (aucun octet ne sort).
pub(crate) fn ch_enabled(cfg: &Value) -> bool {
    cfg.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)
        && ch_kind(cfg) != "none"
        && !ch_endpoint(cfg).is_empty()
}

/// Endpoint configuré (URL du webhook), trim.
pub(crate) fn ch_endpoint(cfg: &Value) -> String {
    cfg.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
}

/// Schéma d'auth déclaré (`auth.type`), défaut `none`. Ne renvoie JAMAIS le secret — juste le NOM.
pub(crate) fn ch_auth_type(cfg: &Value) -> String {
    cfg.get("auth").and_then(|a| a.get("type")).and_then(|v| v.as_str()).unwrap_or("none").trim().to_string()
}

/// Nom d'en-tête pour `auth.type = header` (défaut `X-Forge-Token`).
fn ch_auth_header(cfg: &Value) -> String {
    let h = cfg.get("auth").and_then(|a| a.get("header")).and_then(|v| v.as_str()).unwrap_or("").trim();
    if h.is_empty() { "X-Forge-Token".to_string() } else { h.to_string() }
}

/// Secret du canal TEL QU'AU REPOS — possiblement une ENVELOPPE `forge:fenc1:…` depuis que ce champ
/// est chiffré au repos (`field_crypto`). MANIÉ COMME UN SECRET DE SESSION : jamais renvoyé par une
/// lecture d'API, jamais loggé, jamais ledgerisé.
///
/// ⚠️ CE N'EST PAS LE PLAINTEXT. Réservé aux usages qui n'en ont pas besoin : le booléen `secret_set`
/// et la réinjection `keep_secret` (qui recopie l'enveloppe telle quelle). Pour METTRE le jeton sur le
/// fil, la config passe d'abord par [`open_channel_config`], qui est FAILLIBLE.
pub(crate) fn ch_secret(cfg: &Value) -> String {
    crate::field_crypto::config_field_raw(cfg, crate::field_crypto::CH_SECRET_PATH)
}

/// Config de canal avec son jeton OUVERT, pour le POINT D'USAGE (construction de l'en-tête d'auth).
///
/// FAILLIBLE, DÉLIBÉRÉMENT : sans la clé de champ, ou si l'enveloppe n'ouvre pas, on rend `Err` NOMMÉE
/// plutôt qu'un jeton vide. Un jeton vide partirait comme un webhook ANONYME — le collecteur répondrait
/// 401 et l'admin diagnostiquerait un problème d'endpoint, pas une clé de champ absente.
pub(crate) fn open_channel_config(cfg: &Value) -> Result<Value, String> {
    crate::field_crypto::open_config_secret(
        cfg,
        crate::field_crypto::CH_SECRET_PATH,
        crate::field_crypto::key_from_env().as_deref(),
    )
}

/// Config de canal avec son jeton SCELLÉ, pour la PERSISTANCE. IDEMPOTENT (valeur déjà enveloppée
/// laissée telle quelle — chemin `keep_secret`). Sans secret => no-op, aucune clé requise. FAIL-CLOSED :
/// un jeton en clair à sceller sans clé => `Err`.
pub(crate) fn seal_channel_config(cfg: &Value) -> Result<Value, String> {
    crate::field_crypto::seal_config_secret(
        cfg,
        crate::field_crypto::CH_SECRET_PATH,
        crate::field_crypto::key_from_env().as_deref(),
    )
}

/// Copie de la config SANS le secret (ce qui peut être rendu à un client admin). Le reste est conservé
/// verbatim : c'est la config que l'admin a lui-même saisie.
pub(crate) fn redact_channel_config(cfg: &Value) -> Value {
    let mut out = cfg.clone();
    if let Some(auth) = out.get_mut("auth").and_then(|a| a.as_object_mut()) {
        auth.remove("secret");
    }
    out
}

// =====================================================================================
//  RÉDACTION DU CORPS SORTANT — la MÊME surface que les rapports, plus les URL de cible
// =====================================================================================

/// Neutralise toute URL absolue (`scheme://…`) d'un texte, remplacée par [`URL_MARK`].
///
/// POURQUOI : le rédacteur de secrets attrape les MATÉRIELS d'auth (Bearer/JWT/clefs cloud/clef=valeur),
/// pas les URL. Or le titre d'un finding porte typiquement l'URL de la cible — et une URL de cible porte
/// en général l'identifiant de la victime (`/account/8412/invoice`). Sur un canal sortant, cette chaîne
/// est la donnée la plus sensible du message. On la retire ENTIÈREMENT plutôt que d'essayer de deviner
/// quelle partie est identifiante.
///
/// PUR + IDEMPOTENT (le marqueur ne contient pas `://`, réappliquer ne change rien). Une URL court
/// jusqu'au premier blanc ou délimiteur de citation — les guillemets français du texte de notification
/// (`« … »`) sont donc respectés.
pub(crate) fn neutralize_urls(s: &str) -> String {
    const TERMINATORS: &[char] = &['"', '\'', '<', '>', '»', '«', '`'];
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0usize;
    // Début du segment non encore recopié.
    let mut copied = 0usize;
    while i + 3 <= bytes.len() {
        if &bytes[i..i + 3] == b"://" {
            // remonte au début du schéma : [A-Za-z][A-Za-z0-9+.-]* collé au `://`.
            let mut start = i;
            while start > 0 {
                let c = bytes[start - 1] as char;
                if c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-' {
                    start -= 1;
                } else {
                    break;
                }
            }
            // un schéma DOIT commencer par une lettre (sinon `1://` n'est pas une URL — on ne touche pas).
            if start < i && (bytes[start] as char).is_ascii_alphabetic() {
                // avance jusqu'au premier blanc / terminateur (bornes de caractères respectées).
                let mut end = i + 3;
                for (off, ch) in s[i + 3..].char_indices() {
                    if ch.is_whitespace() || TERMINATORS.contains(&ch) {
                        end = i + 3 + off;
                        break;
                    }
                    end = i + 3 + off + ch.len_utf8();
                }
                out.push_str(&s[copied..start]);
                out.push_str(URL_MARK);
                copied = end;
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[copied..]);
    out
}

/// LA rédaction du canal sortant : rédacteur de secrets PARTAGÉ (celui des rapports, `redact.rs` —
/// aucune 2e copie ici), PUIS neutralisation des URL. Les deux sont nécessaires et couvrent des choses
/// différentes : le premier masque le matériel d'auth, le second l'identifiant de victime porté par une
/// URL de cible.
pub(crate) fn redact_outbound(text: &str) -> String {
    neutralize_urls(&crate::redact::redact_secrets(text))
}

/// Corps JSON sortant — MINIMAL et RÉDIGÉ. Aucune preuve, aucune pièce jointe, aucun champ libre du
/// finding : l'événement, les identifiants (qui permettent de retrouver le finding DANS la console) et
/// le texte rédigé. Le destinataire est nommé pour le routage côté récepteur (c'est un compte de la
/// console de l'opérateur, jamais une donnée de cible).
pub(crate) fn outbound_payload(event: &str, engagement_id: i64, finding_id: i64, recipient: &str, text: &str) -> Value {
    let mut body = redact_outbound(text);
    if body.len() > MAX_BODY_BYTES {
        body = body.chars().take(MAX_BODY_BYTES / 4).collect();
    }
    json!({
        "source": "forge-console",
        "event": event,
        "engagement_id": engagement_id,
        "finding_id": finding_id,
        "recipient": redact_outbound(recipient),
        "text": body,
    })
}

/// DESTINATAIRE RÉDIGÉ pour le ledger/les logs : `scheme://authority` — le PATH et la QUERY sont JETÉS.
/// Ce n'est pas de la cosmétique : une URL de webhook (Slack, Teams, Discord) porte SON JETON DANS LE
/// CHEMIN. Ledgeriser l'URL entière reviendrait à écrire le credential du canal dans le ledger.
pub(crate) fn target_redacted(endpoint: &str) -> String {
    let e = endpoint.trim();
    let Some(pos) = e.find("://") else {
        return "[endpoint]".to_string();
    };
    let after = &e[pos + 3..];
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    // Un userinfo (`user:pass@host`) est lui aussi un credential : on ne garde que l'hôte.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    format!("{}://{}", &e[..pos], host)
}

// =====================================================================================
//  PLAN D'ENVOI — décision PURE (aucune lecture d'env), donc testable sans course inter-tests
// =====================================================================================

/// Ce qu'il faut pour poser la requête, une fois TOUTES les gardes passées.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct Delivery {
    pub(crate) addr: SocketAddr,
    /// Transport décidé par le plan : clair (GOUVERNÉ) ou TLS vérifié. C'est aussi ce qui autorise —
    /// ou non — un secret vers une cible publique.
    pub(crate) scheme: crate::tls::Scheme,
    pub(crate) authority: String,
    /// Nom d'hôte SEUL (sans port) : ce contre quoi le certificat du pair est vérifié en TLS.
    pub(crate) host: String,
    pub(crate) path: String,
    /// En-tête d'auth déjà formé (`Nom: valeur`), ou `None`. Jamais loggé.
    pub(crate) auth_header: Option<String>,
}

/// Décide si — et vers quoi — on envoie. PURE vis-à-vis de l'ENVIRONNEMENT : l'autorisation des cibles
/// internes est un PARAMÈTRE (`allow_internal`), pas une lecture de `std::env` — la deny-list est donc
/// testable de façon déterministe (le binaire de test pose l'escape-hatch globalement pour les mocks SSO).
/// Le seul appelant de production passe `env_flag_enabled(FORGE_ALLOW_INTERNAL_INTEGRATIONS)`.
///
/// Ordre des refus (tout ce qui peut refuser le fait AVANT le moindre octet réseau) :
///   canal armé -> schéma de transport -> résolution -> deny-list SSRF -> credential-en-clair-vers-public.
pub(crate) fn plan_delivery(cfg: &Value, allow_internal: bool) -> Result<Delivery, String> {
    if !ch_enabled(cfg) {
        return Err("canal de notification désactivé (opt-in explicite requis) — aucun egress".to_string());
    }
    if ch_kind(cfg) != "webhook" {
        return Err(format!("canal '{}' non supporté (seul 'webhook' existe)", ch_kind(cfg)));
    }
    let endpoint = ch_endpoint(cfg);
    // Découpage PARTAGÉ (seam) : http:// ET https:// sont reconnus, tout le reste est refusé.
    let t = crate::tls::split_url(&endpoint)
        .map_err(|e| format!("endpoint de webhook invalide : {e}"))?;
    let (authority, host, path) = (t.authority.clone(), t.host.clone(), t.path.clone());
    use std::net::ToSocketAddrs;
    let addr = (host.as_str(), t.port)
        .to_socket_addrs()
        .map_err(|e| format!("résolution {host}:{} échouée: {e}", t.port))?
        .next()
        .ok_or_else(|| format!("aucune adresse pour {host}:{}", t.port))?;
    // ANTI-SSRF : on garde l'ADRESSE que l'on va effectivement connecter (resolve-then-check-then-connect
    // => le DNS-rebinding ne peut pas décaler la cible entre le contrôle et la connexion).
    let internal = crate::net::reject_internal_addr(&addr).err();
    if let Some(why) = &internal {
        if !allow_internal {
            return Err(why.clone());
        }
    }
    // CREDENTIAL EN CLAIR — un jeton de canal ne traverse JAMAIS un RÉSEAU en clair, public ou privé.
    // La règle était CODÉE ICI, en copie unique ; elle vit désormais dans `net::reject_cleartext_secret`,
    // PARTAGÉE avec le fetcher de source de détection (qui ne l'avait pas du tout). Elle a été RESSERRÉE
    // le 2026-08-07 : le critère n'est plus « la cible est-elle interne ? » mais « le paquet quitte-t-il
    // la machine ? ». Un jeton de canal vers une IP de LAN en `http://` est désormais REFUSÉ — l'autorisation
    // d'ATTEINDRE l'interne (`internal`, ci-dessus) reste distincte et n'emporte plus le droit d'y envoyer
    // un secret en clair. Seul le loopback subsiste, et par la physique (cf. le doc de la règle).
    let secret = ch_secret(cfg);
    crate::net::reject_cleartext_secret(t.scheme, !secret.is_empty(), addr.ip().is_loopback())?;
    let auth_header = if secret.is_empty() {
        None
    } else {
        // Anti-injection d'en-tête : un CR/LF dans le nom ou la valeur casserait la requête -> refus.
        let (name, value) = match ch_auth_type(cfg).as_str() {
            "bearer" => ("Authorization".to_string(), format!("Bearer {secret}")),
            "header" => (ch_auth_header(cfg), secret.clone()),
            _ => return Err("auth.type inconnu pour un secret posé (none|bearer|header)".to_string()),
        };
        let no_crlf = |s: &str| !s.contains('\r') && !s.contains('\n');
        if !no_crlf(&name) || !no_crlf(&value) {
            return Err("CR/LF refusé dans l'en-tête d'auth du canal".to_string());
        }
        Some(format!("{name}: {value}"))
    };
    Ok(Delivery { addr, scheme: t.scheme, authority, host, path, auth_header })
}

// =====================================================================================
//  ENVOI — POST HTTP/1.1 minimal sur socket brut (aucune dépendance nouvelle)
// =====================================================================================

/// POST bloquant du corps JSON. Miroir de `net::http_get_blocking` / `sso::http_post_form_blocking` :
/// transport pris au seam PARTAGÉ `crate::tls` (clair GOUVERNÉ ou TLS VÉRIFIÉ — en https le handshake,
/// donc la vérification du certificat, aboutit AVANT que l'en-tête d'auth ne soit écrit), timeouts
/// connect+handshake+read+write, réponse LUE BORNÉE (on ne veut que le statut). Renvoie le code de
/// statut, ou une erreur NOMMÉE. Ne loggue ni le corps ni l'en-tête d'auth.
fn post_blocking(d: &Delivery, body: &[u8], timeout: Duration) -> Result<u16, String> {
    use std::io::{Read, Write};
    let mut stream = crate::tls::connect(&d.addr, &d.host, d.scheme, timeout)?;
    let mut req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: forge-notify\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        d.path,
        d.authority,
        body.len()
    );
    if let Some(h) = &d.auth_header {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    let mut raw = req.into_bytes();
    raw.extend_from_slice(body);
    stream.write_all(&raw).map_err(|e| format!("écriture requête échouée: {e}"))?;
    let mut resp = Vec::new();
    (&mut stream)
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut resp)
        .map_err(|e| format!("lecture réponse échouée: {e}"))?;
    let text = String::from_utf8_lossy(&resp);
    let status_line = text.lines().next().unwrap_or("");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "réponse HTTP malformée (pas de statut)".to_string())?;
    if !(200..300).contains(&code) {
        return Err(format!("statut HTTP inattendu: {code}"));
    }
    Ok(code)
}

/// Envoi COMPLET et BLOQUANT (plan + POST) — le seul chemin d'egress. `allow_internal` est un
/// paramètre (cf. [`plan_delivery`]) : la production passe l'escape-hatch d'env, les tests passent une
/// valeur explicite. Rend `Ok(status)` ou `Err(raison NOMMÉE)` — la raison est destinée au ledger et à
/// l'admin ; elle ne contient jamais le corps ni le secret.
pub(crate) fn deliver_blocking(cfg: &Value, payload: &Value, allow_internal: bool) -> Result<u16, String> {
    // POINT D'USAGE UNIQUE du jeton de canal : OUVERT ici, une fois, juste avant le plan. `plan_delivery`
    // reste donc PURE et reçoit un secret en clair — c'est ce qui garde ses tests déterministes.
    // FAILLIBLE : clé absente / enveloppe illisible => `Err` NOMMÉE, ledgerisée comme un échec d'envoi.
    let cfg = &open_channel_config(cfg)?;
    let d = plan_delivery(cfg, allow_internal)?;
    let body = serde_json::to_vec(payload).map_err(|e| format!("sérialisation du corps échouée: {e}"))?;
    post_blocking(&d, &body, SEND_TIMEOUT)
}

/// HOOK appelé par `notifications::emit` après la création d'une notification in-app. NO-OP TOTAL quand
/// le canal est désactivé (le cas par défaut) : aucune requête DB supplémentaire, aucune tâche, aucun
/// octet. Sinon : résout le login du destinataire, compose le corps RÉDIGÉ, et détache l'envoi (la
/// mutation appelante n'est ni ralentie ni cassée). L'issue est ledgerisée `console.notify.dispatch`.
pub(crate) fn dispatch(app: &App, recipient_uid: i64, engagement_id: i64, finding_id: i64, event: &str, text: &str) {
    let (cfg, login) = {
        let store = app.store();
        let cfg = resolve_channel(&store);
        if !ch_enabled(&cfg) {
            return; // OFF PAR DÉFAUT — on n'a même pas lu le login.
        }
        let login = store
            .query_row("SELECT login FROM users WHERE id=?", &crate::sql_params![recipient_uid], |r| r.get_str(0))
            .unwrap_or_default();
        (cfg, login)
    };
    let payload = outbound_payload(event, engagement_id, finding_id, &login, text);
    let target = target_redacted(&ch_endpoint(&cfg));
    let app2 = app.clone();
    let event2 = event.to_string();
    // Tâche DÉTACHÉE : le cycle de vie est celui du runtime, pas celui du handler appelant. Hors runtime
    // (chemin CLI/test synchrone) on ne tente rien plutôt que de paniquer.
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    tokio::spawn(async move {
        let allow_internal = crate::env_flag_enabled(crate::net::ALLOW_INTERNAL_INTEGRATIONS_ENV);
        let cfg2 = cfg.clone();
        let payload2 = payload.clone();
        let res = tokio::task::spawn_blocking(move || deliver_blocking(&cfg2, &payload2, allow_internal))
            .await
            .unwrap_or_else(|e| Err(format!("tâche d'envoi interrompue: {e}")));
        ledger_dispatch(&app2, "", &target, &event2, engagement_id, finding_id, &res);
    });
}

/// Écrit l'issue d'un envoi au ledger. LE CONTENU N'Y EST JAMAIS : canal, DESTINATAIRE RÉDIGÉ, événement,
/// identifiants, succès/échec (+ la raison NOMMÉE d'un échec). C'est la trace d'un EGRESS, pas une copie
/// du message.
fn ledger_dispatch(app: &App, actor: &str, target: &str, event: &str, eid: i64, fid: i64, res: &Result<u16, String>) {
    let mut detail = json!({
        "channel": "webhook",
        "target": target,
        "event": event,
        "engagement_id": eid,
        "finding_id": fid,
        "ok": res.is_ok(),
    });
    if let Some(m) = detail.as_object_mut() {
        if !actor.is_empty() {
            m.insert("actor".into(), json!(actor));
        }
        match res {
            Ok(code) => {
                m.insert("status".into(), json!(code));
            }
            Err(why) => {
                m.insert("why".into(), json!(why));
            }
        }
    }
    append_console_ledger(app, "console.notify.dispatch", detail);
}

// =====================================================================================
//  VALIDATION D'ENTRÉE (fail-closed) + HANDLERS ADMIN
// =====================================================================================

/// Valide une config entrante et rend la forme CANONIQUE à persister. Fail-closed : tout champ inconnu
/// est REFUSÉ (aucune capacité surprise), le kind et le type d'auth viennent de jeux FERMÉS, l'endpoint
/// est borné et sans CRLF.
pub(crate) fn validate_channel(cfg: &Value) -> Result<Value, String> {
    const TOP: &[&str] = &["kind", "enabled", "endpoint", "auth"];
    const AUTH_KEYS: &[&str] = &["type", "header", "secret"];
    let obj = cfg.as_object().ok_or("la config du canal doit être un objet")?;
    for k in obj.keys() {
        if !TOP.contains(&k.as_str()) {
            return Err(format!("champ inconnu '{k}' — refusé (config déclarative bornée)"));
        }
    }
    let kind = ch_kind(cfg);
    if !CHANNEL_KINDS.contains(&kind.as_str()) {
        return Err(format!("kind de canal inconnu : {kind}"));
    }
    let mut out = Map::new();
    out.insert("kind".into(), json!(kind));
    out.insert("enabled".into(), json!(cfg.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)));
    let endpoint = ch_endpoint(cfg);
    if endpoint.len() > 2048 || endpoint.contains('\0') || endpoint.contains('\r') || endpoint.contains('\n') {
        return Err("endpoint trop long ou contenant un caractère interdit".into());
    }
    out.insert("endpoint".into(), json!(endpoint));
    if let Some(auth) = cfg.get("auth") {
        let am = auth.as_object().ok_or("'auth' doit être un objet")?;
        for k in am.keys() {
            if !AUTH_KEYS.contains(&k.as_str()) {
                return Err(format!("champ d'auth inconnu '{k}' — refusé"));
            }
        }
        let atype = ch_auth_type(cfg);
        if !AUTH_TYPES.contains(&atype.as_str()) {
            return Err(format!("auth.type inconnu : {atype} (none|bearer|header)"));
        }
        let mut ao = Map::new();
        ao.insert("type".into(), json!(atype));
        let header = ch_auth_header(cfg);
        if header.len() > 64 || header.chars().any(|c| c.is_control() || c == ':' || c.is_whitespace()) {
            return Err("auth.header invalide (nom d'en-tête HTTP borné, sans ':' ni blanc)".into());
        }
        ao.insert("header".into(), json!(header));
        if let Some(s) = am.get("secret").and_then(|v| v.as_str()) {
            if s.len() > 4096 || s.contains('\r') || s.contains('\n') || s.contains('\0') {
                return Err("secret de canal trop long ou contenant un caractère interdit".into());
            }
            if !s.is_empty() {
                ao.insert("secret".into(), json!(s));
            }
        }
        out.insert("auth".into(), Value::Object(ao));
    }
    Ok(Value::Object(out))
}

/// Réinjecte le secret DÉJÀ POSÉ quand l'appelant demande `keep_secret` et n'en fournit pas un nouveau.
/// C'est ce qui rend le write-only utilisable : l'admin peut corriger l'endpoint sans retaper le jeton.
fn apply_kept_secret(app: &App, incoming: &Value, keep: bool) -> Value {
    let mut cfg = incoming.clone();
    if !keep || !ch_secret(&cfg).is_empty() {
        return cfg;
    }
    let stored = {
        let store = app.store();
        resolve_channel(&store)
    };
    let prev = ch_secret(&stored);
    if prev.is_empty() {
        return cfg;
    }
    let auth = cfg
        .as_object_mut()
        .expect("validate_channel garantit un objet")
        .entry("auth")
        .or_insert_with(|| json!({"type": "none", "header": "X-Forge-Token"}));
    if let Some(m) = auth.as_object_mut() {
        m.insert("secret".into(), json!(prev));
    }
    cfg
}

pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/notify/channel", get(channel_get).post(channel_set))
        .route("/api/notify/channel/test", post(channel_test))
}

/// GET /api/notify/channel — ADMIN (fail-closed 403). Rend la config SANS le secret + `secret_set`
/// (booléen de présence) + le jeu fermé des kinds. Le secret n'est JAMAIS re-servi : la forme
/// write-only + booléen EST la garantie (aucun endpoint ne peut le rendre).
pub(crate) async fn channel_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let cfg = {
        let store = app.store();
        resolve_channel(&store)
    };
    let secret_set = !ch_secret(&cfg).is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "channel": redact_channel_config(&cfg),
            "secret_set": secret_set,
            "kinds": CHANNEL_KINDS,
            "enabled": ch_enabled(&cfg),
        })),
    )
        .into_response()
}

/// POST /api/notify/channel — ADMIN (fail-closed 403). Persiste la config VALIDÉE. Corps :
/// `{channel:{…}}` ou l'objet à plat, + `keep_secret?:bool`. Ledgerise `console.notify.channel.set`
/// (actor + kind + enabled + DESTINATAIRE RÉDIGÉ + auth_type — JAMAIS le secret ni l'URL complète).
pub(crate) async fn channel_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let incoming: Value = if let Some(v) = body.get("channel").filter(|v| v.is_object()) {
        v.clone()
    } else if body.is_object() && body.get("kind").is_some() {
        let mut c = body.clone();
        if let Some(m) = c.as_object_mut() {
            m.remove("keep_secret");
        }
        c
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "bad_request", "why": "corps attendu : {channel:{kind,…}} ou {kind,…}"})),
        )
            .into_response();
    };
    let canon = match validate_channel(&incoming) {
        Ok(v) => v,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "channel_invalid", "why": why}))).into_response(),
    };
    let keep = body.get("keep_secret").and_then(|v| v.as_bool()).unwrap_or(false);
    let cfg = apply_kept_secret(&app, &canon, keep);
    // CHIFFREMENT AU REPOS du jeton, AVANT la persistance. Fail-closed : sans clé de champ on REFUSE
    // d'écrire un jeton en clair dans `settings` (503 nommé). Idempotent sur le chemin `keep_secret`.
    let cfg = match seal_channel_config(&cfg) {
        Ok(c) => c,
        Err(e) => {
            let code = if crate::field_crypto::is_key_missing(&e) {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (code, Json(json!({"error": "field_key_missing", "why": e}))).into_response();
        }
    };
    {
        let store = app.store();
        if let Err(e) = crate::settings_set_store(&store, SETTINGS_KEY, &cfg.to_string()) {
            drop(store);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "settings_write_failed", "why": e}))).into_response();
        }
    }
    append_console_ledger(&app, "console.notify.channel.set", json!({
        "actor": actor,
        "kind": ch_kind(&cfg),
        "enabled": ch_enabled(&cfg),
        "target": target_redacted(&ch_endpoint(&cfg)),
        "auth_type": ch_auth_type(&cfg),
    }));
    (
        StatusCode::OK,
        Json(json!({
            "channel": redact_channel_config(&cfg),
            "secret_set": !ch_secret(&cfg).is_empty(),
            "enabled": ch_enabled(&cfg),
            "saved": true,
        })),
    )
        .into_response()
}

/// POST /api/notify/channel/test — ADMIN (fail-closed 403). Envoie UN message de vérification, avec la
/// config STOCKÉE uniquement (aucune URL fournie dans le corps : l'endpoint n'est pas un paramètre de
/// requête, sinon la route deviendrait un proxy SSRF pour admin). Ledgerisé comme tout envoi.
pub(crate) async fn channel_test(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let cfg = {
        let store = app.store();
        resolve_channel(&store)
    };
    let target = target_redacted(&ch_endpoint(&cfg));
    let payload = outbound_payload("channel.test", 0, 0, &actor, "Test du canal de notification Forge.");
    let allow_internal = crate::env_flag_enabled(crate::net::ALLOW_INTERNAL_INTEGRATIONS_ENV);
    let cfg2 = cfg.clone();
    let res = tokio::task::spawn_blocking(move || deliver_blocking(&cfg2, &payload, allow_internal))
        .await
        .unwrap_or_else(|e| Err(format!("tâche d'envoi interrompue: {e}")));
    ledger_dispatch(&app, &actor, &target, "channel.test", 0, 0, &res);
    match res {
        Ok(code) => (StatusCode::OK, Json(json!({"ok": true, "status": code, "target": target}))).into_response(),
        Err(why) => (StatusCode::OK, Json(json!({"ok": false, "why": why, "target": target}))).into_response(),
    }
}

// =====================================================================================
//  CE QUI N'EST PAS CONSTRUIT, ET POURQUOI (décision, pas oubli)
//
//  SMTP — TOUJOURS REFUSÉ, et le seam TLS N'Y CHANGE RIEN. L'argument d'hier (« la console n'a pas de
//  client TLS ») est caduc ; celui d'aujourd'hui tient tout seul, et il est plus fort :
//    - STARTTLS est une élévation NÉGOCIÉE : la session DÉBUTE en clair et se hisse sur une commande
//      échangée en clair. C'est une classe d'INJECTION DE COMMANDES EN CLAIR (CVE-2011-0411 et toute sa
//      descendance : ce que l'attaquant injecte avant le handshake est traité APRÈS, dans la session
//      chiffrée). Le seam, lui, ne connaît qu'un TLS d'emblée, vérifié avant le premier octet ;
//    - le SMTP réel se pratique en TLS OPPORTUNISTE contre des relais à certificat auto-signé. Le servir
//      honnêtement demanderait soit d'accepter des certificats non fiables — l'échappatoire de
//      vérification que ce chantier REFUSE par principe —, soit d'imposer une PKI que les relais de mail
//      n'ont pas. Les deux sont de mauvaises réponses.
//  Débuter un client TLS par le protocole aux PIRES sémantiques d'élévation serait le mauvais ordre. Un
//  relais on-prem sans auth reste couvert — mieux — par le webhook vers un collecteur interne ; et un
//  vrai besoin SMTP se délègue au moteur Python (`smtplib` + `ssl`), qui est une autre couche.
//
//  SLA — LIVRÉ DEPUIS, dans son PROPRE module (`notify_sla.rs`), et pas ici : un SLA est un
//  ORDONNANCEUR (balayage périodique), pas un canal. Il réutilise le patron de `backup_sched.rs` et
//  emprunte CE canal par la porte des notifications — il n'ajoute donc aucun chemin d'egress.
// =====================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // --- Canaris : des chaînes qu'on va CHERCHER dans ce qui sort. ---
    const CANARY_BEARER: &str = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW0ifQ.c2lnbmF0dXJlZGV0ZXN0";
    const CANARY_URL: &str = "https://cible.example/account/8412/invoice?session=abc123";
    const CANARY_TOKEN: &str = "ghp_0123456789abcdefghijABCDEF";

    fn cfg_webhook(endpoint: &str, secret: Option<&str>) -> Value {
        let mut c = json!({"kind": "webhook", "enabled": true, "endpoint": endpoint});
        if let Some(s) = secret {
            c["auth"] = json!({"type": "bearer", "secret": s});
        }
        c
    }

    // =============================================================================
    //  GARDE 1 — OFF PAR DÉFAUT
    // =============================================================================

    /// Sans config (clé settings absente), le canal est INERTE : `plan_delivery` refuse AVANT toute
    /// résolution DNS. MUTATION : retirer le `if !ch_enabled(cfg) { return Err(...) }` de plan_delivery
    /// fait passer ce refus à une tentative de résolution -> ce test rougit.
    #[test]
    fn off_by_default_no_egress() {
        let cfg = resolve_channel_from(None);
        assert_eq!(ch_kind(&cfg), "none");
        assert!(!ch_enabled(&cfg), "canal inerte par défaut");
        let e = plan_delivery(&cfg, true).unwrap_err();
        assert!(e.contains("désactivé"), "refus explicite attendu, obtenu: {e}");
    }

    /// `enabled:true` mais endpoint vide / kind none => TOUJOURS inerte (fail-closed sur config partielle).
    #[test]
    fn partial_config_stays_inert() {
        assert!(!ch_enabled(&json!({"kind": "webhook", "enabled": true, "endpoint": ""})));
        assert!(!ch_enabled(&json!({"kind": "none", "enabled": true, "endpoint": "http://h/x"})));
        assert!(!ch_enabled(&json!({"kind": "webhook", "endpoint": "http://h/x"})), "enabled absent => off");
    }

    // =============================================================================
    //  GARDE 2 — RÉDACTION (secrets ET URL de cible)
    // =============================================================================

    /// Le corps sortant passe par LE rédacteur des rapports : un Bearer/JWT et un token GitHub n'en
    /// ressortent pas. MUTATION : remplacer `redact_secrets(text)` par `text.to_string()` dans
    /// `redact_outbound` -> ce test rougit.
    #[test]
    fn outbound_body_is_secret_redacted() {
        let text = format!("assigné le finding #7 avec {CANARY_BEARER} et token={CANARY_TOKEN}");
        let out = redact_outbound(&text);
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"), "JWT sorti en clair: {out}");
        assert!(!out.contains(CANARY_TOKEN), "token GitHub sorti en clair: {out}");
        assert!(out.contains("[REDACTED]"), "marqueur de rédaction attendu: {out}");
    }

    /// Une URL de cible (qui porte l'identifiant de la victime) est NEUTRALISÉE. MUTATION : retirer
    /// l'appel `neutralize_urls` de `redact_outbound` -> ce test rougit (le rédacteur de secrets, lui,
    /// laisse passer une URL : c'est précisément pourquoi les DEUX gardes existent).
    #[test]
    fn outbound_body_has_no_target_url() {
        let text = format!("IDOR confirmé sur {CANARY_URL} « facture d'un autre compte »");
        // Preuve que la 2e garde n'est pas redondante : le rédacteur de secrets SEUL laisse l'URL.
        assert!(
            crate::redact::redact_secrets(&text).contains("cible.example"),
            "le rédacteur de secrets ne masque pas les URL — la 2e garde est nécessaire"
        );
        let out = redact_outbound(&text);
        assert!(!out.contains("cible.example"), "hôte de cible sorti: {out}");
        assert!(!out.contains("8412"), "identifiant de victime sorti: {out}");
        assert!(!out.contains("session=abc123"), "session de cible sortie: {out}");
        assert!(out.contains(URL_MARK), "marqueur d'URL attendu: {out}");
        assert!(out.contains("IDOR confirmé sur"), "le texte utile survit: {out}");
        assert!(out.contains("facture d'un autre compte"), "le texte après l'URL survit: {out}");
    }

    /// La neutralisation d'URL est IDEMPOTENTE et ne mange pas du texte ordinaire (pas de faux positif
    /// sur `a://` sans schéma alphabétique, ni sur une prose sans URL).
    #[test]
    fn url_neutralisation_is_idempotent_and_precise() {
        let once = neutralize_urls("voir http://a.example/x puis fin");
        assert_eq!(once, format!("voir {URL_MARK} puis fin"));
        assert_eq!(neutralize_urls(&once), once, "idempotent");
        assert_eq!(neutralize_urls("aucune url ici : ratio 3://4 texte"), "aucune url ici : ratio 3://4 texte");
        assert_eq!(neutralize_urls("prose normale, accents éàü"), "prose normale, accents éàü");
    }

    /// Le corps JSON complet ne porte QUE des champs bornés (pas de preuve, pas de pièce jointe) et son
    /// texte est rédigé.
    #[test]
    fn payload_shape_is_minimal_and_redacted() {
        let p = outbound_payload("finding.assigned", 3, 7, "alice", &format!("titre {CANARY_URL}"));
        let keys: Vec<&str> = p.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["engagement_id", "event", "finding_id", "recipient", "source", "text"]);
        assert!(!p["text"].as_str().unwrap().contains("cible.example"));
        assert_eq!(p["finding_id"], 7);
    }

    // =============================================================================
    //  GARDE 3 — ANTI-SSRF (deny-list d'intégration PARTAGÉE)
    // =============================================================================

    /// Une cible interne (loopback / RFC1918 / métadonnées cloud) est REFUSÉE par défaut, et le refus
    /// vient de la deny-list PARTAGÉE (message `deny-list SSRF`). MUTATION : retirer le bloc
    /// `reject_internal_addr(&addr)` de `plan_delivery` -> ce test rougit.
    #[test]
    fn internal_targets_are_refused_by_default() {
        for ep in ["http://127.0.0.1:9/hook", "http://10.1.2.3/hook", "http://169.254.169.254/latest/meta-data"] {
            let e = plan_delivery(&cfg_webhook(ep, None), false).unwrap_err();
            assert!(e.contains("deny-list SSRF"), "attendu refus SSRF pour {ep}, obtenu: {e}");
        }
        // Avec l'autorisation explicite (escape-hatch on-prem), la même cible passe le plan.
        assert!(plan_delivery(&cfg_webhook("http://127.0.0.1:9/hook", None), true).is_ok());
    }

    /// HTTPS est SERVI (seam TLS) : le plan aboutit, retient le port 443 par défaut et marque le
    /// transport comme chiffré. Un schéma hors {http, https} reste refusé. MUTATION : retirer la
    /// branche `https://` de `tls::split_url` -> ce test rougit.
    #[test]
    fn https_endpoint_is_planned_over_tls() {
        // 8.8.8.8 : cible PUBLIQUE, résolution triviale et sans DNS -> le plan ne dépend pas du réseau.
        let d = plan_delivery(&cfg_webhook("https://8.8.8.8/hook", None), false).expect("https planifié");
        assert!(d.scheme.is_tls(), "transport chiffré attendu");
        assert_eq!(d.addr.port(), 443, "port par défaut du schéma https");
        assert_eq!(d.host, "8.8.8.8", "hôte de vérification du certificat");
        // Schéma hors jeu fermé -> refus net (jamais une tentative silencieuse).
        let e = plan_delivery(&cfg_webhook("ftp://hooks.example/x", None), true).unwrap_err();
        assert!(e.contains("endpoint de webhook invalide"), "refus de schéma attendu, obtenu: {e}");
    }

    // =============================================================================
    //  GARDE 5 — pas de credential en clair vers une cible publique
    // =============================================================================

    /// Un secret de canal + une cible PUBLIQUE en HTTP CLAIR => REFUS (inchangé). La même config vers
    /// une cible INTERNE explicitement autorisée passe (clair GOUVERNÉ on-prem). La règle est désormais
    /// PARTAGÉE avec le fetcher de source de détection (`net::reject_cleartext_secret`) — ce test mesure
    /// qu'elle est bien CÂBLÉE ICI. MUTATION : retirer l'appel `net::reject_cleartext_secret(...)` de
    /// `plan_delivery` -> ce test rougit (le jeton partirait en clair sur Internet).
    #[test]
    fn secret_never_crosses_a_public_network_in_the_clear() {
        let e = plan_delivery(&cfg_webhook("http://8.8.8.8/hook", Some("s3cr3t-de-canal")), false).unwrap_err();
        assert!(e.contains("en clair"), "refus credential-en-clair attendu, obtenu: {e}");
        let ok = plan_delivery(&cfg_webhook("http://127.0.0.1:9/hook", Some("s3cr3t-de-canal")), true);
        assert!(ok.is_ok(), "collecteur interne autorisé : le secret est acceptable, obtenu: {ok:?}");
        assert!(ok.unwrap().auth_header.unwrap().starts_with("Authorization: Bearer "));
    }

    /// L'ASSOUPLISSEMENT, et sa borne. Le MÊME secret vers la MÊME cible publique :
    ///   - en `https://` => AUTORISÉ (le jeton part dans une session dont le certificat est vérifié) ;
    ///   - en `http://`  => REFUSÉ.
    /// C'est exactement ce qui rend Slack/Teams/PagerDuty joignables sans rouvrir le clair. MUTATION :
    /// remplacer `!t.scheme.is_tls()` par `false` (assouplir aussi le clair) -> la 2e moitié rougit ;
    /// retirer la condition entière -> la 2e moitié rougit ; garder l'ancien refus sans le prédicat de
    /// schéma -> la 1re moitié rougit.
    #[test]
    fn secret_towards_a_public_target_is_allowed_over_tls_only() {
        const SECRET: &str = "jeton-de-canal-slack";
        let over_tls = plan_delivery(&cfg_webhook("https://8.8.8.8/services/T00/B11/XXX", Some(SECRET)), false)
            .expect("https + secret vers cible publique : légitime");
        assert!(over_tls.scheme.is_tls());
        assert_eq!(
            over_tls.auth_header.as_deref(),
            Some(&format!("Authorization: Bearer {SECRET}")[..]),
            "le jeton est bien porté par la requête"
        );
        let in_the_clear = plan_delivery(&cfg_webhook("http://8.8.8.8/services/T00/B11/XXX", Some(SECRET)), false);
        assert!(
            in_the_clear.unwrap_err().contains("en clair"),
            "le même jeton en http vers la même cible publique reste REFUSÉ"
        );
    }

    // =============================================================================
    //  GARDE 6 — destinataire RÉDIGÉ (le chemin d'un webhook EST un credential)
    // =============================================================================

    /// `target_redacted` jette le chemin, la query et un éventuel userinfo. MUTATION : rendre
    /// l'endpoint verbatim -> ce test rougit (le jeton Slack/Teams entrerait au ledger).
    #[test]
    fn ledger_target_drops_path_query_and_userinfo() {
        assert_eq!(target_redacted("http://hooks.example/services/T000/B111/XXXSECRETXXX"), "http://hooks.example");
        assert_eq!(target_redacted("http://h.example:8443/x?token=abc"), "http://h.example:8443");
        assert_eq!(target_redacted("http://user:pass@h.example/x"), "http://h.example");
        assert_eq!(target_redacted("pas-une-url"), "[endpoint]");
    }

    // =============================================================================
    //  VALIDATION D'ENTRÉE — fail-closed
    // =============================================================================

    #[test]
    fn unknown_fields_and_kinds_are_refused() {
        assert!(validate_channel(&json!({"kind": "webhook", "endpoint": "http://h/x", "cmd": "rm"})).is_err());
        assert!(validate_channel(&json!({"kind": "smtp", "endpoint": "h"})).is_err(), "kind hors jeu fermé");
        assert!(validate_channel(&json!({"kind": "webhook", "endpoint": "http://h/x\r\nX: y"})).is_err(), "CRLF");
        assert!(validate_channel(&json!({"kind": "webhook", "endpoint": "http://h/x", "auth": {"type": "kerberos"}})).is_err());
        assert!(validate_channel(&json!({"kind": "webhook", "enabled": true, "endpoint": "http://h/x"})).is_ok());
    }

    // =============================================================================
    //  BOUT EN BOUT — ce qui part RÉELLEMENT sur le fil
    // =============================================================================

    /// Serveur HTTP jetable sur loopback : lit UNE requête, répond 200, rend la requête brute.
    fn one_shot_server() -> (String, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().expect("accept");
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut buf = [0u8; 8192];
            let n = s.read(&mut buf).unwrap_or(0);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (format!("http://127.0.0.1:{port}/hook"), h)
    }

    /// L'envoi RÉEL ne met sur le fil ni le JWT ni l'URL de cible — on lit les octets reçus par le
    /// serveur, pas une valeur de retour. MUTATION : retirer l'une des deux rédactions -> rouge.
    #[test]
    fn wire_bytes_carry_neither_secret_nor_target_url() {
        testutil::allow_internal_integrations_once(); // loopback = cible interne
        let (endpoint, handle) = one_shot_server();
        let cfg = cfg_webhook(&endpoint, None);
        let payload = outbound_payload(
            "finding.assigned",
            1,
            7,
            "alice",
            &format!("IDOR sur {CANARY_URL} avec {CANARY_BEARER}"),
        );
        let code = deliver_blocking(&cfg, &payload, true).expect("envoi vers le mock");
        assert_eq!(code, 200);
        let raw = handle.join().expect("thread serveur");
        assert!(raw.starts_with("POST /hook HTTP/1.1"), "requête inattendue: {raw}");
        assert!(!raw.contains("cible.example"), "URL de cible sur le fil: {raw}");
        assert!(!raw.contains("8412"), "identifiant de victime sur le fil: {raw}");
        assert!(!raw.contains("eyJhbGciOiJIUzI1NiJ9"), "JWT sur le fil: {raw}");
        assert!(!raw.to_ascii_lowercase().contains("authorization:"), "en-tête d'auth alors qu'aucun secret n'est posé");
        assert!(raw.contains("\"finding_id\":7"), "le corps utile est bien parti: {raw}");
    }

    /// Un endpoint injoignable NE PANIQUE PAS et rend une raison nommée (best-effort : la notification
    /// in-app a déjà été créée, l'envoi n'a le droit de rien casser).
    #[test]
    fn unreachable_endpoint_is_a_named_error_not_a_panic() {
        testutil::allow_internal_integrations_once();
        // port 1 sur loopback : rien n'écoute.
        let cfg = cfg_webhook("http://127.0.0.1:1/hook", None);
        let e = deliver_blocking(&cfg, &json!({"x": 1}), true).unwrap_err();
        assert!(e.contains("connexion"), "raison nommée attendue, obtenu: {e}");
    }

    // =============================================================================
    //  HANDLERS — gate admin, secret WRITE-ONLY, ledger sans contenu
    // =============================================================================

    fn ledger_text(path: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    /// GET et POST sont ADMIN-ONLY (403 sans session admin) — la config d'un egress n'est pas une
    /// écriture d'UI ordinaire. MUTATION : retirer `check_admin` d'un des deux -> ce test rougit.
    #[tokio::test]
    async fn channel_routes_are_admin_only() {
        let led = testutil::tmp_path("notif-admin.jsonl");
        let app = testutil::test_app(&led);
        let anon = HeaderMap::new();
        assert_eq!(channel_get(State(app.clone()), anon.clone()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            channel_set(State(app.clone()), anon.clone(), Json(json!({"kind": "webhook"}))).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(channel_test(State(app.clone()), anon).await.status(), StatusCode::FORBIDDEN);
        let _ = std::fs::remove_file(&led);
    }

    /// Le secret du canal est WRITE-ONLY : posé par POST, JAMAIS re-servi par GET (seul `secret_set`
    /// le signale), et `keep_secret` permet de corriger l'endpoint sans le retaper. MUTATION : retirer
    /// `auth.remove("secret")` de `redact_channel_config` -> ce test rougit.
    #[tokio::test]
    async fn channel_secret_is_write_only_and_keepable() {
        // Le jeton est CHIFFRÉ AU REPOS : ce test traverse le handler HTTP, il lui faut donc la clé de
        // champ du processus de test (le refus fail-closed « clé absente » est couvert par l'API PURE).
        crate::field_crypto::test_install_process_key();
        let led = testutil::tmp_path("notif-wo.jsonl");
        let app = testutil::test_app(&led);
        let adm = testutil::admin_session(&app, "adm");
        const SECRET: &str = "canal-token-tres-secret-42";

        let r = channel_set(
            State(app.clone()),
            adm.clone(),
            Json(json!({"channel": {"kind": "webhook", "enabled": true, "endpoint": "http://127.0.0.1:9/hook",
                                    "auth": {"type": "bearer", "secret": SECRET}}})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = testutil::resp_json(r).await;
        assert!(!b.to_string().contains(SECRET), "le secret est ressorti de la réponse POST: {b}");

        let b = testutil::resp_json(channel_get(State(app.clone()), adm.clone()).await).await;
        assert_eq!(b["secret_set"], true, "présence signalée");
        assert!(!b.to_string().contains(SECRET), "le secret est ressorti d'un GET: {b}");
        assert!(b["channel"]["auth"].get("secret").is_none(), "aucune clé 'secret' rendue");

        // keep_secret : on change l'endpoint SANS retaper le jeton -> il est conservé.
        let r = channel_set(
            State(app.clone()),
            adm.clone(),
            Json(json!({"channel": {"kind": "webhook", "enabled": true, "endpoint": "http://127.0.0.1:10/hook",
                                    "auth": {"type": "bearer"}}, "keep_secret": true})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = testutil::resp_json(channel_get(State(app.clone()), adm).await).await;
        assert_eq!(b["secret_set"], true, "le jeton survit à une édition d'endpoint");
        assert_eq!(b["channel"]["endpoint"], "http://127.0.0.1:10/hook");

        // Et il n'a jamais atterri au ledger.
        assert!(!ledger_text(&led).contains(SECRET), "secret ledgerisé !");
        let _ = std::fs::remove_file(&led);
    }

    /// Le ledger d'un ENVOI porte le canal, le destinataire RÉDIGÉ et l'issue — JAMAIS le contenu, JAMAIS
    /// l'URL complète du webhook (dont le chemin est un credential). MUTATION : ledgeriser `payload` ou
    /// `ch_endpoint()` au lieu de `target_redacted()` -> ce test rougit.
    #[tokio::test]
    async fn dispatch_ledger_carries_no_content_and_a_redacted_target() {
        testutil::allow_internal_integrations_once();
        let led = testutil::tmp_path("notif-ledger.jsonl");
        let app = testutil::test_app(&led);
        let adm = testutil::admin_session(&app, "adm");
        // endpoint dont le CHEMIN est le jeton (forme Slack/Teams) + port fermé (l'envoi échouera : c'est
        // l'ÉCHEC qu'on veut voir tracé, sans divulgation).
        channel_set(
            State(app.clone()),
            adm.clone(),
            Json(json!({"channel": {"kind": "webhook", "enabled": true,
                                    "endpoint": "http://127.0.0.1:1/services/T00/B11/XXXSECRETPATHXXX"}})),
        )
        .await;
        let r = channel_test(State(app.clone()), adm).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = testutil::resp_json(r).await;
        assert_eq!(b["ok"], false, "port fermé -> échec rapporté, pas masqué");
        assert_eq!(b["target"], "http://127.0.0.1:1", "réponse : cible rédigée");

        let l = ledger_text(&led);
        assert!(l.contains("console.notify.dispatch"), "envoi non ledgerisé");
        assert!(!l.contains("XXXSECRETPATHXXX"), "chemin-credential du webhook ledgerisé: {l}");
        assert!(!l.contains("Test du canal"), "CONTENU du message ledgerisé: {l}");
        assert!(l.contains("\"ok\":false"), "issue non tracée: {l}");
        let _ = std::fs::remove_file(&led);
    }

    /// Le hook d'émission est un NO-OP TOTAL quand le canal est off (le cas par défaut) : aucune ligne de
    /// ledger, aucune tentative. C'est ce qui rend l'ajout byte-identique pour un déploiement existant.
    #[tokio::test]
    async fn dispatch_is_a_total_noop_when_channel_is_off() {
        let led = testutil::tmp_path("notif-noop.jsonl");
        let app = testutil::test_app(&led);
        dispatch(&app, 1, 1, 7, "finding.assigned", "peu importe");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(ledger_text(&led).is_empty(), "un canal éteint a produit une trace : {}", ledger_text(&led));
        let _ = std::fs::remove_file(&led);
    }
}

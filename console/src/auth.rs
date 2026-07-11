// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — AUTH / SESSIONS / GARDES (extrait de main.rs, PURE MOVE). Regroupe l'auth opérateur
//! (argon2) + RBAC repris du modèle auth_guard/host_guard de Plume : preuve viewer Basic (`check_basic`),
//! rôle opérateur C2 fail-closed (`check_operator`/`check_operator_env`/`operator_denied`) avec sa politique
//! source-CIDR (`ip_in_cidr`/`effective_client_ip`/`cidr_is_valid`/`parse_trusted_proxy_cidrs`/
//! `operator_source_allowed`), rôle admin (`check_admin`/`admin_denied`), l'identité résolue (`Identity`,
//! `session_token_from_headers`/`resolve_session_identity`/`resolve_identity`/`attribution_login`), la
//! création de session (`create_session`), le handler `GET /api/whoami` (`whoami`) et les middlewares de
//! garde HTTP (`host_guard`/`host_allowed` anti-rebinding, `auth_guard`/`auth_guard_allows` RBAC).
//!
//! Les structs d'ÉTAT (App) et les helpers de session sans état (`now_epoch`/`session_ttl_secs`/
//! `gen_session_token`), les settings KV (`settings_get`) et le crypto (`sha_hex`/`verify_pw`/`ct_eq_str`)
//! restent à la racine de crate / dans common et sont référencés via `use crate::*`. Ce module est
//! re-exporté à la racine par `pub(crate) use crate::auth::*` — les routes de build_router (`get(whoami)`,
//! middlewares `host_guard`/`auth_guard`), les appelants inter-modules (`crate::check_admin`,
//! `crate::check_operator`, `crate::attribution_login`, `crate::create_session`,
//! `crate::resolve_session_identity`, `crate::session_token_from_headers`, `crate::operator_denied`,
//! `crate::admin_denied` …) ET les tests inline de main.rs (`super::*`) résolvent donc ces fonctions/types
//! INCHANGÉS.
use crate::*;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use base64::Engine;
use serde_json::{json, Value};
use std::net::IpAddr;

// --- auth opérateur (argon2) + RBAC, repris du modèle auth_guard/host_guard de Plume ---

pub(crate) fn check_basic(app: &App, b64: &str) -> bool {
    let raw = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let s = match String::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut it = s.splitn(2, ':');
    let u = it.next().unwrap_or("");
    let p = it.next().unwrap_or("");
    u == app.user.as_str() && verify_pw(p, &app.pass_hash)
}

// --- rôle OPÉRATEUR (C2-light) — FAIL-CLOSED, indépendant du viewer ---
//
// Le lancement de campagnes (POST /api/run, cancel) est une capacité PRIVILÉGIÉE, distincte de la
// simple lecture du dashboard (viewer Basic/Bearer). Elle exige une preuve d'opérateur dédiée via
// l'en-tête `X-Forge-Operator: <mot de passe>` vérifiée contre `operator_hash` (argon2id).
//
// FAIL-CLOSED : si `operator_hash` est vide (non configuré), AUCUN endpoint C2 n'est ouvert — 403,
// même quand le viewer tourne en mode dev-open (pass_hash vide). check_operator NE consulte JAMAIS
// pass_hash/token : l'authz C2 est totalement découplée de l'auth viewer. Sous-commande pour le
// hash : `forge-console hashpw-operator <mot de passe>`.

/// Preuve opérateur par HASH ENV (rétro-compat) : vrai seulement si `operator_hash` est configuré ET
/// que l'en-tête `X-Forge-Operator` correspond. Vide => toujours faux (fail-closed). Aucune
/// dépendance au viewer (pass_hash/token). C'est le repli 'bootstrap' quand aucun compte individuel
/// n'est en session.
pub(crate) fn check_operator_env(app: &App, headers: &HeaderMap) -> bool {
    if app.operator_hash.is_empty() {
        return false; // FAIL-CLOSED : rôle opérateur non provisionné via env -> repli C2 refusé
    }
    let supplied = headers
        .get("x-forge-operator")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if supplied.is_empty() {
        return false;
    }
    verify_pw(supplied, &app.operator_hash)
}

/// Test d'APPARTENANCE d'une IP à un CIDR (ou à une IP exacte quand il n'y a pas de `/`). std-only
/// (u32/u128 + masque de préfixe, aucune dépendance). Familles hétérogènes (v4 vs v6) -> false.
/// Réseau/préfixe malformé ou hors borne -> false (fail-closed pour CETTE entrée). Fonction PURE.
pub(crate) fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    let cidr = cidr.trim();
    let (net, prefix): (&str, Option<u32>) = match cidr.split_once('/') {
        Some((n, p)) => match p.trim().parse::<u32>() {
            Ok(v) => (n.trim(), Some(v)),
            Err(_) => return false, // préfixe non numérique -> entrée rejetée (fail-closed)
        },
        None => (cidr, None), // pas de '/' -> comparaison d'IP exacte
    };
    let net_ip: IpAddr = match net.parse() {
        Ok(i) => i,
        Err(_) => return false,
    };
    match (ip, net_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let bits = prefix.unwrap_or(32);
            if bits > 32 {
                return false;
            }
            let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(*a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let bits = prefix.unwrap_or(128);
            if bits > 128 {
                return false;
            }
            let mask: u128 = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(*a) & mask) == (u128::from(b) & mask)
        }
        _ => false, // v4 vs v6 : jamais dans le même réseau
    }
}

/// IP client EFFECTIVE pour la politique opérateur source-CIDR. Par défaut = IP du pair TCP
/// (ConnectInfo). On n'honore le DERNIER hop de `X-Forwarded-For` QUE si le pair TCP réel `peer` est
/// LUI-MÊME un proxy de confiance, c.-à-d. tombe dans l'un des `trusted_proxy_cidrs`. Sinon (client
/// direct qui court-circuite le vrai proxy, pair hors CIDR, ou pair inconnu) le XFF est INTÉGRALEMENT
/// IGNORÉ et on retombe FAIL-CLOSED sur `peer` — sans quoi un client se connectant directement à
/// l'origine pourrait forger `X-Forwarded-For: <IP-dans-l'allowlist>` et usurper la politique source.
/// La liste `trusted_proxy_cidrs` vide => aucun proxy de confiance => XFF toujours ignoré.
/// Fonction PURE (testable sans connexion réelle).
pub(crate) fn effective_client_ip(peer: Option<IpAddr>, headers: &HeaderMap, trusted_proxy_cidrs: &[String]) -> Option<IpAddr> {
    if let Some(p) = peer {
        // Le pair TCP DOIT être un proxy de confiance pour qu'on accorde foi au XFF qu'il a posé.
        if !trusted_proxy_cidrs.is_empty() && trusted_proxy_cidrs.iter().any(|c| ip_in_cidr(&p, c)) {
            if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                if let Some(last) = xff.split(',').map(|s| s.trim()).rfind(|s| !s.is_empty()) {
                    if let Ok(ip) = last.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
            // pair = proxy de confiance mais aucun XFF exploitable -> repli sur le pair (le proxy).
        }
    }
    // pair non-proxy (client direct), hors CIDR, ou inconnu -> XFF IGNORÉ, fail-closed sur le pair.
    peer
}

/// Test de VALIDITÉ d'une entrée CIDR (ou IP exacte sans `/`) selon les mêmes critères que
/// `ip_in_cidr` : IP v4/v6 parsable + préfixe numérique dans les bornes de la famille. Sert à
/// distinguer un `trusted_proxy` réellement configuré (au moins un CIDR valide) d'une valeur héritée
/// « truthy » non-CIDR (ex. "1", "true") qui NE doit PAS valoir « tout faire confiance ». Fonction PURE.
pub(crate) fn cidr_is_valid(cidr: &str) -> bool {
    let cidr = cidr.trim();
    match cidr.split_once('/') {
        Some((n, p)) => match p.trim().parse::<u32>() {
            Ok(bits) => match n.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => bits <= 32,
                Ok(IpAddr::V6(_)) => bits <= 128,
                Err(_) => false,
            },
            Err(_) => false,
        },
        None => cidr.parse::<IpAddr>().is_ok(),
    }
}

/// Parse le réglage `settings.trusted_proxy` en une LISTE de CIDRs de proxies de confiance. Accepte
/// (dans l'ordre) : (1) un tableau JSON de chaînes CIDR `["10.0.0.0/24","..."]` ; (2) une liste
/// séparée par des virgules `10.0.0.0/24, 172.16.0.0/12` ; (3) un CIDR unique. Chaque entrée est
/// VALIDÉE (`cidr_is_valid`) ; les entrées invalides sont écartées. RÉTRO-COMPAT / MIGRATION : une
/// valeur héritée « truthy » non-CIDR (ex. "1", "true", "yes") ne produit AUCUN CIDR valide -> liste
/// VIDE -> AUCUN proxy de confiance (repli fail-closed sur le pair). On ne conserve JAMAIS
/// silencieusement l'ancien comportement « boolean = fais confiance à tout XFF ». Fonction PURE.
pub(crate) fn parse_trusted_proxy_cidrs(raw: &str) -> Vec<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let candidates: Vec<String> = match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(arr)) => arr.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).collect(),
        // pas un tableau JSON (chaîne "1", bool true, CSV, CIDR nu…) -> split CSV / valeur unique.
        _ => raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
    };
    candidates.into_iter().filter(|c| cidr_is_valid(c)).collect()
}

/// POLITIQUE OPÉRATEUR source-CIDR — OPT-IN, fail-closed UNIQUEMENT quand configurée. Lit
/// `settings.operator_policy.source_cidrs` : si absent/vide -> AUCUNE restriction (true, défaut = none,
/// zéro valeur codée en dur). Sinon l'IP client effective (cf. effective_client_ip) DOIT tomber dans
/// l'un des CIDRs, faute de quoi l'action opérateur est refusée. Politique active + IP indéterminée
/// (aucun pair, aucun XFF) -> refus (fail-closed). Ne restreint QUE le C2 opérateur (appelée depuis
/// check_operator) — jamais l'admin ni le viewer.
pub(crate) fn operator_source_allowed(app: &App, headers: &HeaderMap, peer: Option<IpAddr>) -> bool {
    let (cidrs, trusted_proxy_cidrs) = {
        let store = app.store();
        let cidrs: Vec<String> = crate::settings_get_store(&store, "operator_policy")
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.get("source_cidrs").and_then(|c| c.as_array()).cloned())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        // `trusted_proxy` = CIDR(s) des proxies de confiance (cf. parse_trusted_proxy_cidrs). Un XFF
        // n'est honoré que si le pair TCP tombe dans l'un d'eux ; sinon repli fail-closed sur le pair.
        let trusted_proxy_cidrs = crate::settings_get_store(&store, "trusted_proxy")
            .map(|s| parse_trusted_proxy_cidrs(&s))
            .unwrap_or_default();
        drop(store);
        (cidrs, trusted_proxy_cidrs)
    };
    if cidrs.is_empty() {
        return true; // aucune contrainte source configurée -> défaut = aucune restriction
    }
    match effective_client_ip(peer, headers, &trusted_proxy_cidrs) {
        Some(ip) => cidrs.iter().any(|c| ip_in_cidr(&ip, c)),
        None => false, // politique active mais IP client indéterminée -> fail-closed
    }
}

/// Authz C2 (run/cancel) — FAIL-CLOSED. Vrai si :
///   1) une SESSION valide porte un rôle operator|admin (compte individuel) OU la preuve par hash env
///      (X-Forge-Operator) matche (compte 'bootstrap'/admin) — un viewer en session ne passe JAMAIS ;
///   2) ET la politique source-CIDR (opt-in) l'autorise : si `settings.operator_policy.source_cidrs`
///      est configuré, l'IP client (`peer`, ou dernier hop XFF UNIQUEMENT si le pair TCP est lui-même
///      dans un CIDR de `settings.trusted_proxy`) doit être dans l'allowlist ; non configuré ->
///      aucune restriction (défaut = none).
///
/// `peer` = IP du pair TCP (ConnectInfo) fournie par le handler ; None dans les tests/harness où elle
/// est simulée. La contrainte source ne s'applique QU'AU C2 opérateur — jamais admin/viewer.
pub(crate) fn check_operator(app: &App, headers: &HeaderMap, peer: Option<IpAddr>) -> bool {
    // 1) AUTHN opérateur : l'identité réelle en session prime (viewer -> refus, pas de repli env),
    //    sinon repli rétro-compat par hash env.
    let authed = match resolve_session_identity(app, headers) {
        Some(id) => id.is_operator,
        None => check_operator_env(app, headers),
    };
    if !authed {
        return false;
    }
    // 2) contrainte source-CIDR (opt-in, fail-closed quand configurée).
    operator_source_allowed(app, headers, peer)
}

/// Réponse standard d'un refus C2 (403). Distingue « non provisionné » (501-like message) de
/// « mauvaise preuve » sans fuir lequel — message stable, code 403 dans les deux cas (fail-closed).
pub(crate) fn operator_denied(app: &App) -> (StatusCode, Json<Value>) {
    // Message stable et non-fuiteur. On ne distingue plus que le cas « aucune voie operator possible »
    // (ni hash env, ni — par construction — session valide ici) du cas « preuve invalide/insuffisante ».
    let why = if app.operator_hash.is_empty() {
        "rôle opérateur non provisionné (aucune session operator|admin valide, FORGE_CONSOLE_OPERATOR_HASH absent) — C2 fermé"
    } else {
        "preuve opérateur invalide ou absente (session operator|admin via POST /api/login, ou en-tête X-Forge-Operator)"
    };
    (StatusCode::FORBIDDEN, Json(json!({"error": "operator_required", "why": why})))
}

// --- rôle ADMIN (administration : setup, comptes, settings, gouvernance des connecteurs) ---
//
// Distinct de l'opérateur : administrer la console (créer/désactiver des comptes, muter la table
// `settings`, gouverner les connecteurs) est une capacité de plus haut privilège que lancer un run.
//
// FAIL-CLOSED + ATTRIBUTION INDIVIDUELLE STRICTE : check_admin exige une SESSION valide portant le
// rôle `admin` (resolve_session_identity). Contrairement à check_operator, il N'Y A PAS de repli par
// hash env — une mutation d'administration DOIT être imputable à un compte individuel nommé (pas à un
// secret partagé « bootstrap »). Sans session admin -> refus. Un viewer/operator ne passe JAMAIS.

/// Authz ADMINISTRATION — FAIL-CLOSED. Vrai UNIQUEMENT si une session valide porte le rôle `admin`.
/// Aucun repli env-hash (attribution individuelle obligatoire). Miroir de check_operator, plus strict.
pub(crate) fn check_admin(app: &App, headers: &HeaderMap) -> bool {
    match resolve_session_identity(app, headers) {
        Some(id) => id.role == "admin",
        None => false, // aucune session individuelle -> refus (pas de repli hash env pour l'admin)
    }
}

/// Réponse standard d'un refus admin (403). Message stable et non-fuiteur (fail-closed).
pub(crate) fn admin_denied() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "admin_required",
            "why": "administration réservée à une session au rôle admin (POST /api/login) — pas de repli par secret partagé"
        })),
    )
}

/// Identité résolue d'un appelant : login affiché en attribution + rôle effectif. `is_operator`
/// = peut armer le C2 (operator|admin OU bootstrap env-hash). `via_session` distingue un compte
/// individuel (true) du repli bootstrap par hash env (false).
#[derive(Clone, Debug)]
pub(crate) struct Identity {
    pub(crate) login: String,
    pub(crate) role: String,
    pub(crate) is_operator: bool,
    pub(crate) via_session: bool,
}

/// Extrait le token de session du porteur : en-tête `Authorization: Bearer <t>` (priorité) OU cookie
/// `forge_session=<t>`. Renvoie le token EN CLAIR (à hasher avant lookup), vide si absent.
pub(crate) fn session_token_from_headers(headers: &HeaderMap) -> String {
    if let Some(authz) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(tok) = authz.strip_prefix("Bearer ") {
            let t = tok.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    // cookie forge_session=...
    if let Some(cookie) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            let p = part.trim();
            if let Some(val) = p.strip_prefix("forge_session=") {
                if !val.is_empty() {
                    return val.to_string();
                }
            }
        }
    }
    String::new()
}

/// Résout l'identité depuis une session VALIDE (non expirée, compte non désactivé). None si pas de
/// session présentée, session inconnue/expirée, ou compte désactivé (fail-closed). Purge en passant
/// la session expirée (best-effort). Lecture du compte au moment du lookup => un rôle changé/désactivé
/// prend effet immédiatement même sur une session déjà émise.
pub(crate) fn resolve_session_identity(app: &App, headers: &HeaderMap) -> Option<Identity> {
    let tok = session_token_from_headers(headers);
    if tok.is_empty() {
        return None;
    }
    let token_sha = sha_hex(&tok);
    let store = app.store();
    let row = store.query_row(
        "SELECT s.expires, u.login, u.role, u.disabled
           FROM session s JOIN users u ON u.id = s.user_id
          WHERE s.token_sha = ?",
        &crate::sql_params![&token_sha],
        |r| Ok((
            r.get_i64(0)?,
            r.get_str(1)?,
            r.get_str(2)?,
            r.get_i64(3)?,
        )),
    );
    match row {
        Ok((expires, login, role, disabled)) => {
            if disabled != 0 {
                return None; // compte désactivé -> fail-closed
            }
            if now_epoch() >= expires {
                // session expirée -> purge best-effort et refus
                let _ = store.execute("DELETE FROM session WHERE token_sha=?", &crate::sql_params![&token_sha]);
                drop(store);
                return None;
            }
            let is_operator = role == "operator" || role == "admin";
            Some(Identity { login, role, is_operator, via_session: true })
        }
        Err(_) => None,
    }
}

/// Identité effective d'un appelant pour l'ATTRIBUTION et l'AUTHZ C2 :
///   1) session valide (compte individuel) -> identité réelle (login/role) ;
///   2) SINON repli RÉTRO-COMPAT : preuve opérateur par hash env (X-Forge-Operator) -> compte
///      'bootstrap' (role=admin, is_operator=true) ; preuve viewer Basic -> 'bootstrap' viewer.
///
/// None => aucune identité (anonyme dev-open ou pas de preuve). via_session=false sur les replis env.
pub(crate) fn resolve_identity(app: &App, headers: &HeaderMap) -> Option<Identity> {
    if let Some(id) = resolve_session_identity(app, headers) {
        return Some(id);
    }
    // Repli bootstrap (rétro-compat) : l'en-tête opérateur env-hash agit comme un compte admin.
    if !app.operator_hash.is_empty() && check_operator_env(app, headers) {
        return Some(Identity {
            login: "bootstrap".into(),
            role: "admin".into(),
            is_operator: true,
            via_session: false,
        });
    }
    None
}

/// Login d'attribution : identité résolue si présente, sinon le littéral historique 'operator'
/// (ce qui préserve EXACTEMENT le comportement existant quand seul le hash env est en jeu mais qu'on
/// n'a pas matché ci-dessus — cas dev-open). N'altère aucun garde-fou.
pub(crate) fn attribution_login(app: &App, headers: &HeaderMap) -> String {
    resolve_identity(app, headers).map(|i| i.login).unwrap_or_else(|| "operator".into())
}

/// GET /api/whoami — identité effective de l'appelant (pour l'UI : afficher l'utilisateur connecté,
/// activer/masquer les actions C2 selon le rôle). Résout la session (compte individuel) ou le repli
/// bootstrap env-hash. `authenticated:false` si aucune identité (dev-open anonyme).
pub(crate) async fn whoami(State(app): State<App>, headers: HeaderMap) -> impl IntoResponse {
    // ENTERPRISE flags for the SPA (additive; all false in the community default => byte-identical UI).
    // Drives whether the enterprise views/nav render at all (server stays the authority via each module's
    // own flag + admin gate). Exposing "engaged or not" is not a secret (the login page already reveals
    // SSO availability). NEVER carries a client_secret / SCIM token.
    let enterprise = json!({
        "tenancy": tenancy::enabled(&app),
        "sso": sso::enabled(&app),
        "scim": scim::enabled(&app),
        "rbac": rbac::enabled(&app),
        "compliance": compliance::enabled(&app),
    });
    match resolve_identity(&app, &headers) {
        Some(id) => Json(json!({
            "authenticated": true,
            "login": id.login,
            "role": id.role,
            "is_operator": id.is_operator,
            "via_session": id.via_session, // false => repli bootstrap (hash env), true => compte individuel
            "enterprise": enterprise,
        })),
        None => Json(json!({"authenticated": false, "login": Value::Null, "role": Value::Null, "is_operator": false, "via_session": false, "enterprise": enterprise})),
    }
}

/// Crée une session pour `user_id` (token EN CLAIR renvoyé à l'appelant, SHA-256 persisté). Retourne
/// (token_clair, expires_epoch). Purge en passant les sessions expirées de l'utilisateur (best-effort).
pub(crate) fn create_session(app: &App, user_id: i64) -> (String, i64) {
    let token = gen_session_token();
    let token_sha = sha_hex(&token);
    let now = now_epoch();
    let expires = now + session_ttl_secs();
    let store = app.store();
    let _ = store.execute("DELETE FROM session WHERE user_id=? AND expires<=?", &crate::sql_params![user_id, now]);
    // OR REPLACE -> ON CONFLICT DO UPDATE (portable PG). Équivalent EXACT ici : `session` = (token_sha PK,
    // user_id, created, expires) — l'INSERT liste TOUTES les colonnes, aucun trigger DELETE ni FK ON DELETE
    // CASCADE ne dépend de la ligne, donc le DELETE-then-INSERT d'OR REPLACE et le UPDATE ciblé coïncident.
    let _ = store.execute(
        "INSERT INTO session(token_sha,user_id,created,expires) VALUES(?,?,?,?)
         ON CONFLICT(token_sha) DO UPDATE SET user_id=excluded.user_id, created=excluded.created, expires=excluded.expires",
        &crate::sql_params![token_sha, user_id, now, expires],
    );
    drop(store);
    (token, expires)
}

/// Construit la valeur `Set-Cookie` du cookie de session `forge_session`. Attributs durcis (`HttpOnly`,
/// `SameSite=Strict`, `Path=/`, `Max-Age=<ttl>`) ET `Secure` PAR DÉFAUT — le déploiement documenté
/// (DEPLOYMENT.md) termine la TLS en amont (reverse-proxy), donc le cookie de session ne doit jamais
/// transiter en clair. FAIL-CLOSED : `Secure` est posé sauf si l'affordance de dev HTTP local est
/// explicitement engagée via `FORGE_COOKIE_INSECURE` (accès direct http://127.0.0.1:7100 du 1er
/// déploiement — les navigateurs modernes traitent localhost comme contexte sûr, mais l'opt-out reste
/// disponible pour un proxy non-TLS). Un flag mal orthographié => Secure conservé (jamais un fail-open).
pub(crate) fn session_cookie(token: &str, ttl: i64) -> String {
    let secure = if crate::env_flag_enabled("FORGE_COOKIE_INSECURE") { "" } else { "; Secure" };
    format!("forge_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}{secure}")
}

/// Anti-DNS-rebinding : l'en-tête Host doit être NON VIDE et présent dans l'allowlist.
/// FAIL-CLOSED : un Host absent/vide est REFUSÉ (avant, il passait — fail-open exploitable par un
/// client qui omet/efface Host pour contourner le filtre anti-rebinding). 421 dans tous les cas non
/// autorisés (Host vide OU hors allowlist).
pub(crate) async fn host_guard(State(app): State<App>, req: Request, next: Next) -> Response {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    if host_allowed(host, &app.allowed_hosts) {
        next.run(req).await
    } else {
        (StatusCode::MISDIRECTED_REQUEST, "host non autorisé (anti-rebinding)").into_response()
    }
}

/// Décision pure du host_guard (testable) : le Host (port retiré) doit être NON VIDE et présent dans
/// l'allowlist. FAIL-CLOSED sur Host vide/absent.
pub(crate) fn host_allowed(host_header: &str, allowed: &[String]) -> bool {
    let h = host_header.split(':').next().unwrap_or("");
    !h.is_empty() && allowed.iter().any(|a| a == h)
}

/// Décision PURE du auth_guard (testable sans middleware/HTTP) : la requête est-elle AUTORISÉE à
/// passer ? `true` => on laisse passer ; `false` => le middleware répond 401 (login portal côté SPA).
///
/// La gate s'engage sur `auth_required` (cache : hash env posé OU compte activé en base — voir
/// recompute_auth_required), et NON plus sur `pass_hash` seul : un fresh install avec des comptes en
/// base mais sans hash env est désormais GATÉ (ferme le trou dev-open historique). Quand la gate est
/// désengagée (dev-open : ni hash env, ni compte activé), tout passe (les ÉCRITURES restent gatées par
/// leur propre check_token/check_operator). Quand elle est engagée, on accepte : (1) une session
/// individuelle valide (cookie/Bearer <session>, tout rôle) ; (2) Basic viewer (pass_hash env) ;
/// (3) Bearer = token d'ingest. Sinon refus (401). FAIL-CLOSED.
pub(crate) fn auth_guard_allows(app: &App, headers: &HeaderMap) -> bool {
    if !app.auth_required() {
        return true; // dev-open : ni hash env ni compte activé -> gate désengagée
    }
    // Session individuelle (cookie forge_session ou Bearer <session>) -> accès lecture (tout rôle).
    // Vérifié AVANT le Bearer ingest-token : un token de session valide identifie un compte réel.
    if resolve_session_identity(app, headers).is_some() {
        return true;
    }
    let authz = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(b64) = authz.strip_prefix("Basic ") {
        if check_basic(app, b64.trim()) {
            return true;
        }
    }
    if let Some(tok) = authz.strip_prefix("Bearer ") {
        if ct_eq_str(&sha_hex(tok.trim()), &app.token_sha) {
            return true;
        }
    }
    false
}

/// RBAC (middleware) : la gate s'engage dès qu'un hash env est posé OU qu'un compte activé existe en
/// base (auth_required). Engagée + sans preuve valide -> 401 (le SPA affiche alors le portail de
/// login). Désengagée (dev-open) -> passe. Toute la décision vit dans auth_guard_allows (testable).
pub(crate) async fn auth_guard(State(app): State<App>, req: Request, next: Next) -> Response {
    if auth_guard_allows(&app, req.headers()) {
        return next.run(req).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Basic realm=\"forge\"")],
        "auth requise",
    )
        .into_response()
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — sous-système DÉTECTION / PURPLE-COVERAGE, extrait de `state.rs` (PURE MOVE). Regroupe
//! la SOURCE DE DÉTECTION configurable (`resolve_detection_source*`/`ds_*`/`redact_*`/`apply_kept_secret`/
//! `DETECTION_KINDS`/`is_known_detection_kind`), la COLLECTE (`collect_detections*`/`rust_http_collect`/
//! `collect_via_python`/`map_detections`/`json_path*`/`parse_plume_detections`/`generic_http_url`), la
//! CORRÉLATION purple (`parse_fire_ts`/`read_fired_techniques`/`compute_purple_coverage`/`purple_fail_open`/
//! `fetch_purple_coverage`) et les HANDLERS HTTP (`purple_coverage`/`detection_test`/`detection_source_get`/
//! `detection_source_set`).
//!
//! Ré-exporté `pub(crate)` à la racine de crate (`pub(crate) use crate::detection::*;`) : le
//! `build_router`/`main` de main.rs, les modules frères (`crate::fetch_purple_coverage`/
//! `crate::read_fired_techniques` …) ET le bloc de tests inline (`super::*`) résolvent ces items INCHANGÉS.
//! PURE MOVE : corps/signatures IDENTIQUES ; seule la localisation du fichier change (byte-identique au
//! tir). Tous les `#[cfg(...)]` préservés VERBATIM.
use crate::*;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

// ===========================================================================================
// PURPLE-TEAM (DÉFENSIF) — mesure de la couverture de DÉTECTION du SOC.
//
// Objectif blue-team : pour chaque technique ATT&CK TIRÉE en red-team autorisée par Forge
// (runrecord.fired=1), vérifier si la colonne BLEUE Plume l'a DÉTECTÉE (une alerte taguée du
// même `mitre`). On expose les TROUS de détection (missed) + le délai moyen de détection (MTTD).
//
// Source RED  : table `runrecord` (fired=1) de CETTE console — la technique + l'horodatage du tir.
// Source BLUE : GET {PLUME_URL}/api/coverage/detections -> [{mitre, count, first_ts}] (epoch s).
// Jointure    : sur les TECHNIQUES du champ `mitre` (ex T1190/T1046/T1110.001), tags multi-techniques
//   ÉCLATÉS des deux côtés (cf. `mitre_techniques`). TROIS ÉTATS : `detected-exact` (même technique),
//   `detected-parent-approx` (sous-technique tirée, seule la parente est couverte -> angle mort NOMMÉ,
//   hors taux et hors MTTD), `missed` (rien).
//   MTTD/tech = first_ts(détection) - ts(tir red) en secondes (>=0 ; négatif tronqué à 0 — une
//   détection antérieure au tir vient d'un run précédent, on ne « gagne » pas de temps négatif),
//   échantillonné UNIQUEMENT sur `detected-exact`.
//
// FAIL-OPEN LISIBLE (NON négociable) : si Plume est injoignable / PLUME_URL absent / réponse
// illisible, on renvoie `plume_reachable:false` et on NE FABRIQUE JAMAIS de detected/parent_approx/missed/MTTD
// (listes vides, agrégats nuls). Un SOC muet ne doit pas se traduire en « tout détecté » NI en
// « tout raté » — l'opérateur voit explicitement que la mesure n'a pas pu être faite.
// LECTURE pure : aucun spawn, aucune écriture ; gardée par auth_guard comme le reste de l'API.
// ===========================================================================================

/// Parse un horodatage de tir red-team en epoch secondes (i64). Forge émet de l'ISO-8601 UTC
/// (`2026-06-26T12:00:00+00:00` / `...Z`) ; on tolère aussi un epoch déjà nu (défensif). Renvoie
/// `None` si illisible -> le MTTD de cette technique est marqué indisponible (jamais inventé).
pub(crate) fn parse_fire_ts(ts: &str) -> Option<i64> {
    let s = ts.trim();
    if s.is_empty() {
        return None;
    }
    // 1) epoch nu déjà fourni (ex "1719403200") — tolérance, pas le cas nominal.
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    // 2) ISO-8601 : YYYY-MM-DDTHH:MM:SS[.frac][Z|±HH:MM]. On lit la partie civile UTC et applique
    //    l'offset éventuel. Pas de chrono : conversion calendaire jours-depuis-epoch à la main
    //    (algorithme « days_from_civil », valable pour le calendrier grégorien proleptique).
    let (date_part, rest) = s.split_once('T').or_else(|| s.split_once(' '))?;
    let mut d = date_part.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // sépare l'heure de l'offset/zone (Z, +hh:mm, -hh:mm). On coupe au 1er marqueur d'offset.
    let mut offset_secs: i64 = 0;
    let time_str: &str = {
        let r = rest.trim_end();
        if let Some(stripped) = r.strip_suffix('Z').or_else(|| r.strip_suffix('z')) {
            stripped
        } else {
            // l'offset commence au 1er '+'/'-' rencontré dans `rest` (HH:MM:SS n'en contient pas) ;
            // le 'T' a déjà été retiré en amont, donc tout signe ici borne le décalage de fuseau.
            if let Some(pos) = r.find(['+', '-']) {
                let (t, off) = r.split_at(pos);
                let sign = if off.starts_with('-') { -1 } else { 1 };
                let off = &off[1..];
                let mut op = off.split(':');
                let oh: i64 = op.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                let om: i64 = op.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                offset_secs = sign * (oh * 3600 + om * 60);
                t
            } else {
                r
            }
        }
    };
    // heure civile (on coupe une éventuelle fraction de seconde).
    let time_core = time_str.split('.').next().unwrap_or(time_str);
    let mut t = time_core.split(':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let ss: i64 = t.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    if !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=60).contains(&ss) {
        return None;
    }
    // days_from_civil (Howard Hinnant) : jours depuis 1970-01-01 pour une date grégorienne.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0,365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468;
    let epoch_utc = days * 86400 + hh * 3600 + mm * 60 + ss;
    // l'horodatage civil était exprimé dans le fuseau `offset_secs` -> on revient à l'UTC.
    Some(epoch_utc - offset_secs)
}

// ===========================================================================================
// SOURCE DE DÉTECTION CONFIGURABLE (plugin infra-agnostique) — substrat de la boucle purple.
//
// La console ne code plus « Plume » en dur. La SOURCE de détection (SIEM/IDS/pare-feu) est décrite
// par un objet JSON `{kind, endpoint?, auth?:{type,secret}, query?, mapping?}` rangé dans
// `settings.detection_source`. `kind` ∈ {plume, generic_http, crowdsec, fortigate_syslog, pfsense,
// opnsense, file_jsonl, elastic, exec, none} ; `auth.type` ∈ {none, basic, bearer, api_key_header,
// mtls}. Les kinds `plume`/`generic_http` sont interrogés EN RUST (fetcher intégré ci-dessous), en
// http:// COMME en https:// (le seam TLS `crate::tls` porte le transport) ;
// les kinds « messy » (et `auth.type=mtls` : le seam SAIT présenter un certificat client, mais son
// identité est celle du PROCESSUS — deux sources exigeant deux certificats distincts ne sont pas
// représentables ici) sont DÉLÉGUÉS au collecteur Python
// (`forge.cli detections`). Dans TOUS les cas la sortie est normalisée en `[(mitre,count,first_ts)]`
// puis passée à `compute_purple_coverage` (jointure MITRE INCHANGÉE). Échec/mauvaise config =>
// FAIL-OPEN LISIBLE (source_reachable:false), jamais de detected/parent_approx/missed/MTTD inventés.
// ===========================================================================================

/// Résout la config de source de détection : `settings.detection_source` (VERBATIM si objet JSON
/// valide) sinon REPLI rétro-compat sur l'env legacy PLUME_URL/PLUME_TOKEN (implicitement
/// `{kind:plume, endpoint:PLUME_URL, auth:{type:basic,secret:PLUME_TOKEN}}`), sinon `{kind:none}`.
/// Le repli n'a lieu QUE si la clé settings est ABSENTE (une config explicite `{kind:none}` NE
/// retombe PAS sur l'env). Fonction pure vis-à-vis de la DB (lecture seule).
#[allow(dead_code)] // version &Connection CONSERVÉE pour les tests ; le runtime passe par le seam (_store)
pub(crate) fn resolve_detection_source(db: &Connection) -> Value {
    resolve_detection_source_from(settings_get(db, "detection_source"))
}

/// PORTABLE SEAM analogue of [`resolve_detection_source`] over `App::store()` : lit
/// `settings.detection_source` sur le backend ACTIF (SQLite OU Postgres) via `settings_get_store`, puis
/// applique la MÊME politique de résolution. Utilisé par `reload_detection_source` pour que le cache de
/// couverture purple soit peuplé depuis le backend RÉELLEMENT interrogé au runtime — plus de lecture
/// SQLite en split-brain quand l'App tourne sur Postgres.
pub(crate) fn resolve_detection_source_store(store: &crate::store::Store) -> Value {
    resolve_detection_source_from(settings_get_store(store, "detection_source"))
}

/// Cœur PARTAGÉ (backend-agnostique) de la résolution de source de détection : mappe la valeur brute
/// éventuelle de `settings.detection_source` vers la config effective — objet JSON VERBATIM si valide,
/// sinon REPLI env legacy `PLUME_URL`/`PLUME_TOKEN` (uniquement si la clé settings est ABSENTE/illisible),
/// sinon `{kind:none}`. Fed par `settings_get` (Connection) OU `settings_get_store` (Store) : une SEULE
/// politique de résolution pour les deux lecteurs.
fn resolve_detection_source_from(setting: Option<String>) -> Value {
    if let Some(s) = setting {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if v.is_object() {
                return v;
            }
        }
    }
    // repli env legacy : uniquement si settings n'a PAS de detection_source lisible.
    let url = std::env::var("PLUME_URL").unwrap_or_default().trim_end_matches('/').to_string();
    // PLUME_TOKEN with a `*_FILE` fallback (Docker/k8s secret) — the detection creds can live in a
    // mounted file. Only consulted for the LEGACY env path (settings.detection_source wins above).
    let token = crate::secret_from_env("PLUME_TOKEN").unwrap_or_default();
    if !url.is_empty() {
        return json!({"kind": "plume", "endpoint": url, "auth": {"type": "basic", "secret": token}});
    }
    json!({"kind": "none"})
}

/// `kind` de la source (défaut "none", trim).
pub(crate) fn ds_kind(cfg: &Value) -> String {
    cfg.get("kind").and_then(|v| v.as_str()).unwrap_or("none").trim().to_string()
}

/// `endpoint` de la source (URL http(s):// ou chemin fichier selon le kind ; défaut vide, trim).
pub(crate) fn ds_endpoint(cfg: &Value) -> String {
    cfg.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
}

/// Type d'auth déclaré (`auth.type`, avec tolérance à la forme plate `auth_type` écrite par le
/// wizard). Défaut "none". NE renvoie JAMAIS le secret — juste le NOM du schéma (pour le ledger/log).
pub(crate) fn ds_auth_type(cfg: &Value) -> String {
    cfg.get("auth").and_then(|a| a.get("type")).and_then(|v| v.as_str())
        .or_else(|| cfg.get("auth_type").and_then(|v| v.as_str()))
        .unwrap_or("none").trim().to_string()
}

/// Secret d'auth (`auth.secret`) TEL QU'AU REPOS — possiblement une ENVELOPPE `forge:fenc1:…` depuis
/// que ce champ est chiffré au repos (`field_crypto`). MANIÉ COMME UN SECRET DE SESSION : jamais
/// renvoyé/journalisé/ledgerisé.
///
/// ⚠️ CE N'EST PAS LE PLAINTEXT. N'utiliser que pour les usages qui n'en ont pas besoin — le booléen
/// `secret_set` (« un secret est-il posé ? ») et la réinjection `keep_secret` (qui recopie l'enveloppe
/// telle quelle, sans jamais l'ouvrir). Pour METTRE le secret sur le fil, passer par
/// [`open_source_config`], qui est FAILLIBLE — c'est tout l'intérêt.
pub(crate) fn ds_secret(cfg: &Value) -> String {
    crate::field_crypto::config_field_raw(cfg, crate::field_crypto::DS_SECRET_PATH)
}

/// Config de source avec son secret OUVERT, pour le POINT D'USAGE (en-tête d'auth du fetch Rust,
/// passage au collecteur Python, rédaction des messages d'erreur).
///
/// FAILLIBLE, DÉLIBÉRÉMENT : sans la clé, ou si l'enveloppe n'ouvre pas, on rend `Err` NOMMÉE plutôt
/// qu'un secret vide. Un secret vide se présenterait comme « source anonyme » et la collecte partirait
/// SANS authentification — un 401 diagnostiqué comme une panne de SIEM, alors que la cause est une clé
/// de champ absente. C'est exactement la dégradation silencieuse que le chiffrement de champ interdit.
pub(crate) fn open_source_config(cfg: &Value) -> Result<Value, String> {
    crate::field_crypto::open_config_secret(
        cfg,
        crate::field_crypto::DS_SECRET_PATH,
        crate::field_crypto::key_from_env().as_deref(),
    )
}

/// Config de source avec son secret SCELLÉ, pour la PERSISTANCE. IDEMPOTENT (une valeur déjà
/// enveloppée — cas de la réinjection `keep_secret` — est laissée telle quelle). Config sans secret =>
/// no-op, aucune clé requise. FAIL-CLOSED : un secret en clair à sceller sans clé => `Err`, on refuse
/// de persister un credential en clair.
pub(crate) fn seal_source_config(cfg: &Value) -> Result<Value, String> {
    crate::field_crypto::seal_config_secret(
        cfg,
        crate::field_crypto::DS_SECRET_PATH,
        crate::field_crypto::key_from_env().as_deref(),
    )
}

/// Secret PLAINTEXT destiné à la RÉDACTION des messages (défense en profondeur). BEST-EFFORT : si
/// l'enveloppe n'ouvre pas, on retombe sur la valeur brute — un message ne peut de toute façon pas
/// porter un plaintext que le processus n'a jamais su produire.
pub(crate) fn ds_secret_for_redaction(cfg: &Value) -> String {
    open_source_config(cfg).map(|c| ds_secret(&c)).unwrap_or_else(|_| ds_secret(cfg))
}

/// Remplace toute occurrence du secret par `[secret rédigé]` dans un message destiné à une réponse/au
/// log/au ledger. Garde-fou défense-en-profondeur (les messages d'erreur n'échoient normalement pas le
/// secret) ; no-op si le secret est vide ou trop court pour être remplacé sans risque de sur-rédaction.
pub(crate) fn redact_secret(msg: &str, secret: &str) -> String {
    if secret.len() < 4 {
        return msg.to_string();
    }
    msg.replace(secret, "[secret rédigé]")
}

/// Liste FERMÉE des `kind` de source de détection acceptés (parité avec le registre du collecteur Python
/// `forge.collectors` + les kinds interrogés en Rust). `none` désactive la mesure (fail-open lisible).
/// Sert de garde-fou d'entrée sur POST /api/detection/source (fail-closed : un kind inconnu est refusé,
/// jamais persisté) et alimente le sélecteur de l'UI admin/wizard.
pub(crate) const DETECTION_KINDS: &[&str] = &[
    "none", "plume", "generic_http", "crowdsec", "elastic", "opensearch",
    "fortigate_syslog", "pfsense", "opnsense", "file_jsonl", "exec",
];

pub(crate) fn is_known_detection_kind(kind: &str) -> bool {
    DETECTION_KINDS.contains(&kind)
}

/// Copie RÉDIGÉE d'une config de source : retire le secret d'auth (`auth.secret`) et tout `secret` posé
/// à plat. Utilisée par GET /api/detection/source et la réponse de POST — le SECRET n'est JAMAIS renvoyé
/// (manié comme un secret de session). Tout le reste (kind/endpoint/auth.type/query/mapping) est conservé
/// pour permettre l'édition côté admin sans jamais re-rendre le secret.
pub(crate) fn redact_detection_config(cfg: &Value) -> Value {
    let mut out = cfg.clone();
    if let Some(m) = out.as_object_mut() {
        m.remove("secret");
        if let Some(auth) = m.get_mut("auth").and_then(|a| a.as_object_mut()) {
            auth.remove("secret");
        }
    }
    out
}

/// Sémantique WRITE-ONLY du secret : si `keep_secret` et que la config entrante ne porte PAS de secret
/// non vide, réinjecte le secret STOCKÉ (config de détection effective courante) dans `auth.secret`.
/// Permet à l'admin d'éditer endpoint/mapping — ou de TESTER la source — SANS re-saisir le secret (jamais
/// rendu côté UI : affiché ••• une fois posé). No-op si aucun secret n'est déjà stocké, ou si l'appelant
/// fournit un nouveau secret non vide (celui-ci prime alors).
pub(crate) fn apply_kept_secret(app: &App, cfg: &Value, keep_secret: bool) -> Value {
    let mut out = cfg.clone();
    if keep_secret && ds_secret(cfg).is_empty() {
        let stored = ds_secret(&app.detection_config());
        if !stored.is_empty() {
            let atype = ds_auth_type(cfg);
            if let Some(m) = out.as_object_mut() {
                let auth = m.entry("auth").or_insert_with(|| json!({}));
                if !auth.is_object() {
                    *auth = json!({});
                }
                if let Some(am) = auth.as_object_mut() {
                    am.entry("type").or_insert_with(|| json!(atype));
                    am.insert("secret".into(), json!(stored));
                }
            }
        }
    }
    out
}


/// Éclate un tag MITRE en ses techniques DISTINCTES, **sous-technique PRÉSERVÉE**.
///
/// POURQUOI : un tag `mitre` peut porter PLUSIEURS techniques séparées par espace/virgule/
/// point-virgule — c'est la NORME chez SigmaHQ (plusieurs `attack.` par règle), et le champ `mitre`
/// de Plume le documente lui-même (`daemon/src/handlers/alerts.rs::mitre_parents`). Avec une
/// jointure par ÉGALITÉ DE CHAÎNE, un tag `"T1595.002 T1046"` ne matche AUCUNE clé côté Forge : le
/// corpus Sigma FABRIQUE alors de faux « missed ». On éclate donc le tag DES DEUX CÔTÉS de la
/// jointure (tirs Forge ET détections de la source).
///
/// La sous-technique n'est JAMAIS repliée sur sa parente ici : c'est précisément la distinction
/// `detected-exact` / `detected-parent-approx` qui porte l'information (cf. compute_purple_coverage).
/// Format accepté : `T` + chiffres, avec une sous-technique optionnelle `.` + chiffres (casse
/// insensible, normalisée en haut de casse). Un token hors format est ignoré. Dédupliqué, ordre
/// d'apparition préservé. PUR / testable.
pub(crate) fn mitre_techniques(tag: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in tag.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let t = tok.trim().to_ascii_uppercase();
        let Some(rest) = t.strip_prefix('T') else { continue };
        let (base, sub) = match rest.split_once('.') {
            Some((b, s)) => (b, Some(s)),
            None => (rest, None),
        };
        if base.is_empty() || !base.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // une sous-technique doit être un bloc de chiffres unique ("T1110.001.2" est rejeté).
        if let Some(s) = sub {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
        }
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// CLÉS DE JOINTURE d'un tag `mitre` : ses techniques ATT&CK si le tag en contient au moins une,
/// sinon le tag BRUT (trimé) tel quel.
///
/// ANTI-SILENT-DROP (même garantie que `attack_matrix`) : un tag vendeur/custom qui ne ressemble
/// pas à `T####` ne doit pas DISPARAÎTRE de la mesure — une technique tirée qui s'évapore, c'est un
/// angle mort rendu INVISIBLE, exactement l'inverse de ce que le produit vend. Il reste donc joint
/// VERBATIM, comme avant l'éclatement (rétro-compat exacte pour ces tags).
fn mitre_join_keys(tag: &str) -> Vec<String> {
    let techs = mitre_techniques(tag);
    if !techs.is_empty() {
        return techs;
    }
    let raw = tag.trim();
    if raw.is_empty() { Vec::new() } else { vec![raw.to_string()] }
}

/// Technique PARENTE d'une SOUS-technique (`T1110.001` -> `T1110`). `None` si le tag n'est pas une
/// sous-technique bien formée (une technique parente n'a pas elle-même de parente).
fn mitre_parent_of(tid: &str) -> Option<String> {
    let (base, sub) = tid.split_once('.')?;
    let b = base.strip_prefix('T')?;
    if b.is_empty() || !b.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if sub.is_empty() || !sub.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(base.to_string())
}

/// Corrélation PURE (testable, sans I/O) red-team(tiré) × blue-team(détecté).
///
/// - `fired` : techniques tirées par Forge -> (mitre, ts_epoch_du_tir Option). Une technique peut
///   apparaître plusieurs fois (plusieurs tirs) ; on prend le tir le PLUS RÉCENT pour le MTTD (le SOC
///   doit détecter le tir courant), et on compte les tirs.
/// - `detections` : map mitre -> (count_alertes, first_ts_epoch) renvoyée par la source de détection.
///
/// Les tags des DEUX côtés sont éclatés par `mitre_join_keys` (multi-techniques Sigma) avant la
/// jointure ; côté bleu, deux tags qui retombent sur la MÊME technique sont agrégés (counts sommés,
/// `first_ts` = min — la PREMIÈRE détection).
///
/// TROIS ÉTATS, pas deux :
///   * `detected-exact` — la source a une détection sur EXACTEMENT la technique tirée ;
///   * `detected-parent-approx` — Forge a tiré une SOUS-technique (`T1110.001`) et la source n'a de
///     détection que sur la technique PARENTE (`T1110`) ;
///   * `missed` — rien, ni exact ni parent.
///
/// POURQUOI LE PARENT-APPROX N'EST **PAS** COMPTÉ COMME DÉTECTÉ (invariant de `detection_rate`) :
/// le tag d'une règle PARENTE ne dit RIEN du VECTEUR qu'elle couvre. La jointure voit un identifiant,
/// pas une requête de détection : elle ne peut donc pas PROUVER que la sous-technique tirée est
/// détectée. « Détecté » est une affirmation ; on ne l'émet que quand on l'a mesurée.
///
/// Ce n'est pas théorique — cas relevé sur les règles LIVRÉES de plume, `T1110` tagué / `T1110.001`
/// tiré (module `network.ssh` : devinette de mot de passe SSH). Trois des règles `T1110` livrées
/// (catalogue `config.d/rules/catalog/`, requêtes relevées verbatim) ne peuvent PAS attraper un
/// brute-force SSH MONO-SOURCE :
///   `ca-cred-mail-bruteforce`       : `search source=mail action=failure …`  -> bornée au MAIL,
///   `ca-cred-web-login-bruteforce`  : `search source=web status=401 …`       -> bornée au WEB,
///   `ca-cred-distributed-bruteforce`: `search category=auth action=failure | stats dc(src_ip)`
///                                                                            -> exige la DISPERSION d'IP.
/// D'autres règles `T1110` sont seedées et POURRAIENT couvrir ce vecteur selon la télémétrie branchée
/// (`seeds.rs` : `search category=auth action=failure | stats count by src_ip | where count > 15`) —
/// et c'est exactement le point : selon le corpus ACTIVÉ et les sources branchées, la parente couvre ou
/// ne couvre pas. La jointure ne peut pas trancher, donc elle ne tranche pas : elle NOMME le doute au
/// lieu de l'arbitrer en faveur du vendeur. Compter ce rapprochement comme « détecté » produirait un
/// taux non mesuré et un MTTD calculé entre le tir SSH et une alerte potentiellement sans rapport.
/// Le taux vitrine ne compte donc QUE `detected-exact`, et le MTTD n'est échantillonné QUE sur
/// `detected-exact` (un MTTD sur un rapprochement approximatif est un chiffre inventé). Pour faire
/// passer une sous-technique au vert : taguer une règle DE CETTE sous-technique.
///
/// Le parent-approx n'est pas pour autant du DÉCHET : c'est un angle mort NOMMÉ (« tu as tiré
/// T1110.001, tu n'as que des règles T1110 génériques »), rendu dans sa propre liste `parent_approx`
/// avec son propre compteur `techniques_parent_approx`.
///
/// Renvoie l'objet JSON exposé par /api/purple/coverage (hors champ plume_reachable, ajouté par
/// le handler). INVARIANT : detected + parent_approx + missed == techniques_fired — SAUF EN FAIL-OPEN,
/// et cette réserve compte : `purple_fail_open` rend `techniques_fired = N` avec les TROIS compteurs à
/// 0, délibérément (on ne déclare pas « raté » ce qu'on n'a pas pu interroger). Un consommateur qui
/// dériverait `missed = fired - detected - parent_approx` fabriquerait donc, en fail-open, exactement
/// les faux « ratés » que le fail-open existe pour empêcher. `missed` est une LISTE rendue, à lire
/// telle quelle — jamais à recalculer.
pub(crate) fn compute_purple_coverage(
    fired: &[(String, Option<i64>)],
    detections: &std::collections::HashMap<String, (i64, i64)>,
) -> Value {
    // côté BLEU : éclatement des tags multi-techniques + agrégation par technique (count sommé,
    // first_ts = min : la PREMIÈRE détection, cohérent avec `map_detections`).
    let mut det_by: std::collections::BTreeMap<String, (i64, i64)> = std::collections::BTreeMap::new();
    for (tag, (count, first_ts)) in detections {
        for tech in mitre_join_keys(tag) {
            let e = det_by.entry(tech).or_insert((0, *first_ts));
            e.0 += *count;
            if *first_ts < e.1 {
                e.1 = *first_ts;
            }
        }
    }

    // côté ROUGE : même éclatement, puis agrégation des tirs par technique (nb de tirs + horodatage
    // du tir le plus récent, pour le MTTD). Un tir portant 2 techniques compte 1 tir pour CHACUNE.
    let mut fired_by: std::collections::BTreeMap<String, (i64, Option<i64>)> = std::collections::BTreeMap::new();
    for (tag, ts) in fired {
        for tech in mitre_join_keys(tag) {
            let e = fired_by.entry(tech).or_insert((0, None));
            e.0 += 1;
            if let Some(t) = ts {
                // on garde le tir le PLUS RÉCENT (max) -> MTTD calculé contre le dernier tir.
                e.1 = Some(e.1.map_or(*t, |cur: i64| cur.max(*t)));
            }
        }
    }

    let mut detected: Vec<Value> = Vec::new();
    let mut parent_approx: Vec<Value> = Vec::new();
    let mut missed: Vec<Value> = Vec::new();
    let mut mttd_samples: Vec<i64> = Vec::new();

    for (mitre, (fires, last_fire_ts)) in &fired_by {
        // (1) DETECTED-EXACT — même technique des deux côtés. Seul état qui alimente le taux et le MTTD.
        if let Some((count, first_ts)) = det_by.get(mitre) {
            // MTTD = première détection - dernier tir. Indisponible si le ts du tir est illisible.
            // Tronqué à 0 si négatif (détection antérieure = run précédent ; pas de gain négatif).
            let mttd = last_fire_ts.map(|ft| (*first_ts - ft).max(0));
            if let Some(m) = mttd {
                mttd_samples.push(m);
            }
            detected.push(json!({
                "mitre": mitre,
                "state": "detected-exact",
                "fires": fires,
                "alert_count": count,
                "first_detection_ts": first_ts,
                "fire_ts": last_fire_ts,
                "mttd_secs": mttd,
            }));
            continue;
        }
        // (2) DETECTED-PARENT-APPROX — sous-technique tirée, seule la parente est couverte côté bleu.
        // AUCUN MTTD n'est émis : on n'a pas de détection de CE vecteur à dater.
        if let Some(parent) = mitre_parent_of(mitre) {
            if let Some((count, first_ts)) = det_by.get(&parent) {
                parent_approx.push(json!({
                    "mitre": mitre,
                    "state": "detected-parent-approx",
                    "parent": parent,
                    "fires": fires,
                    "fire_ts": last_fire_ts,
                    "parent_alert_count": count,
                    "parent_first_detection_ts": first_ts,
                    "why": format!(
                        "{mitre} a été tirée ; la source ne détecte que la technique parente {parent}. \
Une règle parente générique ne prouve pas la couverture de CE vecteur — non comptée dans le taux, aucun MTTD calculé."
                    ),
                }));
                continue;
            }
        }
        // (3) MISSED — ni exact ni parent.
        missed.push(json!({
            "mitre": mitre,
            "state": "missed",
            "fires": fires,
            "fire_ts": last_fire_ts,
        }));
    }

    let n_fired = fired_by.len() as i64;
    let n_detected = detected.len() as i64;
    let n_approx = parent_approx.len() as i64;
    let n_missed = missed.len() as i64;
    // TAUX VITRINE : `detected-exact` UNIQUEMENT (cf. justification ci-dessus). Le parent-approx a son
    // propre compteur et n'entre JAMAIS au numérateur.
    let detection_rate = if n_fired > 0 { n_detected as f64 / n_fired as f64 } else { 0.0 };
    let mttd_avg = if !mttd_samples.is_empty() {
        Some(mttd_samples.iter().sum::<i64>() as f64 / mttd_samples.len() as f64)
    } else {
        None
    };
    let mttd_max = mttd_samples.iter().copied().max();

    json!({
        "techniques_fired": n_fired,
        "techniques_detected": n_detected,          // detected-exact SEULEMENT
        "techniques_parent_approx": n_approx,       // sous-technique tirée, seule la parente est couverte
        "techniques_missed": n_missed,
        "detection_rate": detection_rate,   // [0,1] — part des techniques tirées détectées EXACTEMENT
        "mttd_avg_secs": mttd_avg,           // null si aucun échantillon mesurable (exact uniquement)
        "mttd_max_secs": mttd_max,           // null si aucun échantillon mesurable (exact uniquement)
        "detected": detected,                // techniques tirées ET détectées EXACTEMENT (avec MTTD)
        "parent_approx": parent_approx,      // ANGLES MORTS NOMMÉS : parente couverte, vecteur non prouvé
        "missed": missed,                    // TROUS de détection : tirées, ni exact ni parent
    })
}

/// Construit l'objet de FAIL-OPEN LISIBLE (source_reachable/plume_reachable:false) : compte les
/// techniques tirées (pour information) mais NE FABRIQUE PAS de detected/parent_approx/missed/MTTD. Réutilisé par
/// tous les chemins où la mesure n'a pas pu se faire (source absente/injoignable/illisible, lecture DB
/// échouée). `plume_reachable`/`plume_url` sont conservés (rétro-compat du SPA et du rapport qui les
/// lisent) et MIROITÉS en `source_reachable`/`source_url` (nommage neutre infra-agnostique). `url` ne
/// contient JAMAIS le secret (endpoint seul). `reason` a déjà été rédigé par l'appelant.
pub(crate) fn purple_fail_open(url: &str, fired: &[(String, Option<i64>)], reason: &str) -> Value {
    // MÊME comptage des techniques distinctes que la mesure réelle (`mitre_join_keys`) : un tag
    // multi-techniques compte pour chacune de ses techniques, sinon le « pour information » d'un
    // fail-open contredirait le `techniques_fired` mesuré sur les mêmes tirs.
    let n_fired = fired
        .iter()
        .flat_map(|(m, _)| mitre_join_keys(m))
        .collect::<std::collections::BTreeSet<_>>()
        .len() as i64;
    json!({
        "plume_reachable": false,
        "source_reachable": false,
        "plume_url": url,
        "source_url": url,
        "error": reason,
        "techniques_fired": n_fired,
        "techniques_detected": 0,
        "techniques_parent_approx": 0,
        "techniques_missed": 0,
        "detection_rate": 0.0,
        "mttd_avg_secs": Value::Null,
        "mttd_max_secs": Value::Null,
        "detected": [],
        "parent_approx": [],
        "missed": [],
    })
}

/// Lit les techniques tirées (runrecord.fired=1, mitre non vide) + horodatage du tir, filtrées par
/// une clause WHERE additionnelle (campaign ou run_id) déjà validée par l'appelant (param lié).
pub(crate) fn read_fired_techniques(app: &App, eid: Option<i64>, extra_cond: Option<(&str, &str)>) -> Vec<(String, Option<i64>)> {
    let store = app.store();
    // ENGAGEMENT : `eid=Some(id)` restreint aux tirs de CET engagement (vue /purple/coverage). `None`
    // = pas de filtre engagement (run_report : le `run_id` isole déjà les records d'un seul engagement).
    // engagement_id est un entier RÉSOLU -> inliné sans risque d'injection.
    // `engagement_id` (entier résolu) LIÉ en Param quand présent — plus d'interpolation de valeur. `{col}`
    // reste interpolé : c'est un IDENTIFIANT de colonne FIXE (campaign|run_id) fourni par l'appelant, jamais
    // une valeur client (non paramétrable en SQL). ORDRE des placeholders : engagement_id apparaît AVANT
    // `AND {col}=?`, donc son Param est poussé EN PREMIER.
    let eng_clause = if eid.is_some() { " AND engagement_id=?" } else { "" };
    let sql = match extra_cond {
        Some((col, _)) => format!("SELECT mitre, ts FROM runrecord WHERE fired=1 AND mitre<>''{eng_clause} AND {col}=?"),
        None => format!("SELECT mitre, ts FROM runrecord WHERE fired=1 AND mitre<>''{eng_clause}"),
    };
    // LENIENT (query_lax) : un prepare échoué -> Err -> unwrap_or_default -> vec![] (à l'identique de
    // l'early-return d'avant) ; une ligne malformée est ignorée (filter_map(ok)).
    let mut params: Vec<crate::store::Param> = Vec::new();
    if let Some(e) = eid { params.push(crate::store::Param::Int(e)); }
    if let Some((_, val)) = extra_cond { params.push(crate::store::Param::Text(val.to_string())); }
    store
        .query_lax(&sql, &params, |r| {
            let mitre = r.get_opt_str(0)?.unwrap_or_default();
            let ts_raw = r.get_opt_str(1)?.unwrap_or_default();
            Ok((mitre, parse_fire_ts(&ts_raw)))
        })
        .unwrap_or_default()
}

/// Accès à une valeur JSON par CHEMIN POINTÉ ("a.b.c") ; None si un segment manque. Un chemin vide
/// renvoie la valeur racine. Sert au `mapping` des sources generic_http (champ natif -> mitre/ts/count).
pub(crate) fn json_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        if seg.is_empty() {
            continue;
        }
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Valeur au chemin pointé rendue en String (string telle quelle, sinon repr scalaire, sinon vide).
pub(crate) fn json_path_str(v: &Value, path: &str) -> String {
    match json_path(v, path) {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.as_str().map(str::to_string).unwrap_or_default(),
        None => String::new(),
    }
}

/// Valeur au chemin pointé rendue en i64 (int, sinon f64 tronqué, sinon parse d'une string ; None si
/// absent/illisible).
pub(crate) fn json_path_i64(v: &Value, path: &str) -> Option<i64> {
    let n = json_path(v, path)?;
    n.as_i64()
        .or_else(|| n.as_f64().map(|f| f as i64))
        .or_else(|| n.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
}

/// Mapping IDENTITÉ de la réponse Plume `{detections:[{mitre,count,first_ts}]}` -> `[(mitre,count,ts)]`.
/// Réutilisé aussi pour la sortie NORMALISÉE du collecteur Python (même contrat de sortie).
pub(crate) fn parse_plume_detections(parsed: &Value) -> Vec<(String, i64, i64)> {
    let mut out = Vec::new();
    if let Some(arr) = parsed.get("detections").and_then(|v| v.as_array()) {
        for d in arr {
            let mitre = d.get("mitre").and_then(|v| v.as_str()).unwrap_or("");
            if mitre.is_empty() {
                continue;
            }
            let count = d.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            let first_ts = d.get("first_ts").and_then(|v| v.as_i64()).unwrap_or(0);
            out.push((mitre.to_string(), count, first_ts));
        }
    }
    out
}

/// Applique le `mapping` d'une source generic_http à une réponse arbitraire -> `[(mitre,count,ts)]`.
/// `mapping` : `{records?: "chemin.vers.tableau", mitre?: "champ", ts?: "champ", count?: "champ"}`.
/// - `records` localise le tableau d'enregistrements (défaut : tableau racine, sinon champ `detections`
///   / `results`) ;
/// - chaque enregistrement fournit `mitre` (défaut champ "mitre"), `ts` (défaut "first_ts"), et un
///   `count` OPTIONNEL (si absent chaque enregistrement compte 1) ;
/// - agrégation par mitre : count sommé, first_ts = min. Aucune fabrication : un tableau introuvable
///   ou vide -> Err / vec vide (l'appelant bascule alors en fail-open).
pub(crate) fn map_detections(parsed: &Value, mapping: Option<&Value>) -> Result<Vec<(String, i64, i64)>, String> {
    let default_map = json!({});
    let m = mapping.unwrap_or(&default_map);
    let records_path = m.get("records").and_then(|v| v.as_str()).unwrap_or("");
    let mitre_field = m.get("mitre").and_then(|v| v.as_str()).unwrap_or("mitre");
    let ts_field = m.get("ts").and_then(|v| v.as_str()).unwrap_or("first_ts");
    let count_field = m.get("count").and_then(|v| v.as_str());

    let arr: Vec<Value> = if !records_path.is_empty() {
        json_path(parsed, records_path)
            .and_then(|v| v.as_array().cloned())
            .ok_or_else(|| format!("aucun tableau de détections au chemin '{records_path}'"))?
    } else {
        parsed
            .as_array()
            .cloned()
            .or_else(|| parsed.get("detections").and_then(|v| v.as_array()).cloned())
            .or_else(|| parsed.get("results").and_then(|v| v.as_array()).cloned())
            .ok_or_else(|| "aucun tableau de détections (records/detections/results absents)".to_string())?
    };

    // agrégation par mitre : (count sommé, first_ts min).
    let mut agg: std::collections::BTreeMap<String, (i64, i64)> = std::collections::BTreeMap::new();
    for rec in &arr {
        let mitre = json_path_str(rec, mitre_field);
        if mitre.is_empty() {
            continue;
        }
        let ts = json_path_i64(rec, ts_field).unwrap_or(0);
        let c = match count_field {
            Some(cf) => json_path_i64(rec, cf).unwrap_or(1),
            None => 1,
        };
        let e = agg.entry(mitre).or_insert((0, ts));
        e.0 += c;
        if ts < e.1 {
            e.1 = ts;
        }
    }
    Ok(agg.into_iter().map(|(k, (c, t))| (k, c, t)).collect())
}

/// Construit l'URL d'une source generic_http : endpoint + `query` optionnelle (string, `{since}`
/// substitué), jointe par '?' si l'endpoint n'a pas de query-string, sinon '&'.
pub(crate) fn generic_http_url(endpoint: &str, query: Option<&Value>, since: i64) -> String {
    match query.and_then(|v| v.as_str()).filter(|q| !q.is_empty()) {
        Some(q) => {
            let q = q.replace("{since}", &since.to_string());
            let q = q.trim_start_matches(['?', '&']);
            let sep = if endpoint.contains('?') { '&' } else { '?' };
            format!("{endpoint}{sep}{q}")
        }
        None => endpoint.to_string(),
    }
}

/// Fetch + normalisation EN RUST d'une source http(s) (`plume` ou `generic_http`). `is_plume` :
/// URL = `{endpoint}/api/coverage/detections?since=N` + mapping IDENTITÉ ; sinon URL = endpoint +
/// `query` + mapping configuré. Les DEUX acceptent désormais `https://` (le seam TLS porte le
/// transport, certificat VÉRIFIÉ) — un `PLUME_URL` en https n'est plus refusé.
/// BLOQUANT (à lancer via spawn_blocking).
pub(crate) fn rust_http_collect(cfg: &Value, since: i64, is_plume: bool) -> Result<Vec<(String, i64, i64)>, String> {
    let endpoint = ds_endpoint(cfg);
    if endpoint.is_empty() {
        return Err("endpoint de la source de détection non configuré".to_string());
    }
    let auth = parse_http_auth(cfg);
    let timeout = Duration::from_secs(8);
    let url = if is_plume {
        format!("{}/api/coverage/detections?since={}", endpoint.trim_end_matches('/'), since)
    } else {
        generic_http_url(&endpoint, cfg.get("query"), since)
    };
    let body = http_get_blocking(&url, &auth, timeout)?;
    let parsed: Value = serde_json::from_str(body.trim())
        .map_err(|e| format!("réponse illisible (JSON invalide): {e}"))?;
    if is_plume {
        Ok(parse_plume_detections(&parsed))
    } else {
        map_detections(&parsed, cfg.get("mapping"))
    }
}

/// Délègue la collecte au COLLECTEUR PYTHON pour les kinds « messy » (crowdsec/fortigate_syslog/
/// pfsense/opnsense/file_jsonl/elastic/exec). `generic_http` en https N'EN FAIT PLUS PARTIE : le seam
/// TLS le sert en Rust. Même patron de
/// spawn no-shell que populate_modules (`python3 -m forge.cli detections --since N --source ...`).
/// La config (AVEC secret) est passée par ENV `FORGE_DETECTION_SOURCE` (jamais en argv -> pas de fuite
/// via `ps`/cmdline, cf. le token console de run_create) ; l'argv ne porte que `--source env:...`. Le
/// collecteur émet `{detections:[{mitre,count,first_ts}]}` sur stdout. Toute erreur -> Err (fail-open),
/// le stderr éventuel étant RÉDIGÉ du secret avant de remonter.
/// S5-bis — CE SPAWN EST UN COÛT MACHINE sur une route de LECTURE (`GET /api/detection/coverage`,
/// viewer) : il est BORNÉ par le helper partagé (slots en vol `ENGINE_GATE`, budget
/// `FORGE_ENGINE_TIMEOUT` avec kill du groupe, plafond d'octets, mort de l'enfant si la requête est
/// abandonnée). Toute borne franchie => `Err` lisible => le FAIL-OPEN déjà documenté de la couverture
/// (`source_reachable:false` + raison), jamais une requête suspendue.
pub(crate) async fn collect_via_python(app: &App, cfg: &Value, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    let secret = ds_secret(cfg);
    let mut cmd = tokio::process::Command::new(app.python.as_str());
    cmd.args([
        "-m", "forge.cli", "detections",
        "--since", &since.to_string(),
        "--source", "env:FORGE_DETECTION_SOURCE",
    ])
    .current_dir(app.pkg_dir.as_str())
    .env("FORGE_DETECTION_SOURCE", cfg.to_string());
    let out = crate::bounded_engine_output(
        &crate::ENGINE_GATE,
        cmd,
        std::time::Duration::from_secs(crate::engine_timeout_secs()),
        crate::ENGINE_TEXT_MAX_BYTES,
        None,
    )
    .await
    // CAUSE EXACTE : un plafond de concurrence atteint n'est PAS un collecteur « injoignable » — le dire
    // ferait diagnostiquer une panne de source alors qu'on subit une saturation (c'est exactement le
    // travers corrigé sur le chemin DOCX). Chaque borne garde donc son propre libellé.
    .map_err(|e| match e {
        crate::EngineBoundErr::Busy { .. } => redact_secret(&e.why(), &secret),
        _ => format!("collecteur Python injoignable: {}", redact_secret(&e.why(), &secret)),
    })?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = redact_secret(err.trim(), &secret);
        let err: String = err.chars().take(240).collect();
        return Err(format!("collecteur Python a échoué (code {:?}): {err}", out.status.code()));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("sortie du collecteur illisible (JSON invalide): {e}"))?;
    Ok(parse_plume_detections(&parsed))
}

/// AIGUILLAGE central : collecte les détections de la source CONFIGURÉE (cache App) -> `[(mitre,count,
/// first_ts)]`. Voir `collect_detections_with` pour la logique de dispatch sur `kind`.
pub(crate) async fn collect_detections(app: &App, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    let cfg = app.detection_config();
    collect_detections_with(app, &cfg, since).await
}

/// Dispatch sur `kind` d'une config source DONNÉE (utilisé aussi par POST /api/detection/test pour
/// tester une config fournie sans la persister). `plume`/`generic_http` (http:// ET https://) -> fetch
/// Rust ; kinds messy -> collecteur Python. Résultat -> jointure MITRE INCHANGÉE.
///
/// L'AIGUILLAGE https -> Python A ÉTÉ RETIRÉ : il n'existait QUE parce que le fetcher Rust ne parlait pas
/// TLS. Le seam `crate::tls` le fait désormais, donc une source https est servie EN RUST — sans spawn de
/// processus sur une route de LECTURE, et avec la même deny-list SSRF que le reste.
pub(crate) async fn collect_detections_with(app: &App, cfg: &Value, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    // POINT D'USAGE UNIQUE du secret de source : il est OUVERT ici, une fois, pour les DEUX chemins en
    // aval (fetch Rust et collecteur Python — ce dernier reçoit la config par ENV et ne saurait pas
    // ouvrir une enveloppe). FAILLIBLE À DESSEIN : clé absente ou enveloppe illisible => `Err` NOMMÉE,
    // qui ressort en fail-open LISIBLE (`source_reachable:false` + raison). Jamais une collecte partie
    // SANS authentification, qui se lirait comme un SIEM en panne.
    let cfg = &open_source_config(cfg)?;
    match ds_kind(cfg).as_str() {
        "none" | "" => {
            Err("source de détection non configurée (kind=none) — couverture indisponible".to_string())
        }
        kind @ ("plume" | "generic_http") => {
            let is_plume = kind == "plume";
            let cfg_owned = cfg.clone();
            tokio::task::spawn_blocking(move || rust_http_collect(&cfg_owned, since, is_plume))
                .await
                .unwrap_or_else(|e| Err(format!("tâche HTTP interrompue: {e}")))
        }
        "crowdsec" | "fortigate_syslog" | "pfsense" | "opnsense" | "file_jsonl" | "elastic" | "exec" => {
            collect_via_python(app, cfg, since).await
        }
        other => Err(format!("kind de source de détection inconnu: {other}")),
    }
}

/// Interroge la SOURCE DE DÉTECTION configurée et corrèle avec les techniques `fired` -> objet de
/// couverture complet. FAIL-OPEN LISIBLE à chaque étape qui peut échouer (source absente/injoignable/
/// illisible) : `source_reachable`/`plume_reachable:false` + raison RÉDIGÉE, JAMAIS de detected/parent_approx/missed/
/// MTTD inventés. La jointure MITRE (compute_purple_coverage) est INCHANGÉE quel que soit le `kind`.
/// Réutilisé par l'endpoint /api/purple/coverage (alias /api/detection/coverage) ET la section purple
/// du rapport de run. `endpoint`/`source_url` exposés pour la traçabilité NE contiennent jamais le secret.
pub(crate) async fn fetch_purple_coverage(app: &App, fired: Vec<(String, Option<i64>)>) -> Value {
    let cfg = app.detection_config();
    let disp = ds_endpoint(&cfg); // endpoint seul (jamais le secret) pour la traçabilité
    let kind = ds_kind(&cfg);
    // AUTONOME (standalone) vs source configurée : une source EST configurée si `kind` n'est ni none/vide
    // ni un kind http (plume/generic_http) sans endpoint (parité EXACTE avec le log de boot). Ce booléen
    // permet au SPA de distinguer « aucune source configurée — Forge en autonome » (état NORMAL, attendu)
    // de « source configurée mais INJOIGNABLE » (anomalie à signaler). Aucun des deux n'invente de métrique.
    let http_kind = kind == "plume" || kind == "generic_http";
    let source_configured = !(kind == "none" || kind.is_empty() || (http_kind && disp.is_empty()));
    // `since` = plus ancien tir red (borne la fenêtre côté source) ; 0 si aucun tir horodaté lisible.
    let since = fired.iter().filter_map(|(_, t)| *t).min().unwrap_or(0);
    match collect_detections(app, since).await {
        Ok(dets) => {
            let mut detections: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
            for (mitre, count, first_ts) in dets {
                if mitre.is_empty() {
                    continue;
                }
                // dernière occurrence prime (agrégée en amont) ; contrat identique à l'ancien parse.
                detections.insert(mitre, (count, first_ts));
            }
            // corrélation pure -> réponse. reachable:true (la mesure a bien eu lieu).
            let mut cov = compute_purple_coverage(&fired, &detections);
            if let Value::Object(ref mut m) = cov {
                m.insert("plume_reachable".into(), json!(true));
                m.insert("source_reachable".into(), json!(true));
                m.insert("plume_url".into(), json!(disp));
                m.insert("source_url".into(), json!(disp));
                m.insert("source_kind".into(), json!(kind));
                m.insert("source_configured".into(), json!(true));
            }
            cov
        }
        // fail-open lisible ; la raison est rédigée du secret (défense en profondeur). On y JOINT le
        // `kind` et `source_configured` pour que le SPA/rapport rende l'état AUTONOME (source absente,
        // normal) distinctement d'une source configurée mais injoignable (anomalie).
        Err(e) => {
            let mut fo = purple_fail_open(&disp, &fired, &redact_secret(&e, &ds_secret_for_redaction(&cfg)));
            if let Value::Object(ref mut m) = fo {
                m.insert("source_kind".into(), json!(kind));
                m.insert("source_configured".into(), json!(source_configured));
            }
            fo
        }
    }
}

/// GET /api/detection/coverage[?campaign=X] (alias rétro-compat /api/purple/coverage) — couverture de
/// DÉTECTION (purple-team défensif). Joint runrecord[fired=1] (techniques tirées en red-team Forge)
/// avec les détections de la SOURCE configurée (kind=plume/generic_http/crowdsec/…). Réponse :
///   {
///     "source_reachable": bool,        // (miroir rétro-compat: plume_reachable) false => FAIL-OPEN lisible
///     "source_configured": bool,       // false => AUCUNE source configurée (Forge AUTONOME/standalone) ;
///                                       //   true + source_reachable:false => source posée mais injoignable
///     "source_url": "...",             // (miroir: plume_url) endpoint pour traçabilité — JAMAIS le secret
///     "source_kind": "...",            // kind de la source (none en autonome)
///     "techniques_fired|detected|parent_approx|missed": i64,   // detected = EXACT seulement
///     "detection_rate": f64,           // [0,1] — detected-exact / fired (parent-approx EXCLU)
///     "mttd_avg_secs"|"mttd_max_secs": f64|i64|null,           // échantillons detected-exact seulement
///     "detected":      [ {mitre, state:"detected-exact", fires, alert_count, first_detection_ts, fire_ts, mttd_secs} ],
///     "parent_approx": [ {mitre, state:"detected-parent-approx", parent, fires, fire_ts,
///                         parent_alert_count, parent_first_detection_ts, why} ],
///     "missed":        [ {mitre, state:"missed", fires, fire_ts} ],
///     ("error": "...")                 // présent UNIQUEMENT si source_reachable=false (raison lisible)
///   }
/// INVARIANT : techniques_detected + techniques_parent_approx + techniques_missed == techniques_fired.
/// Si source_reachable=false : detected/parent_approx/missed=[], compteurs/MTTD nuls — jamais de faux
/// détecté/raté.
pub(crate) async fn purple_coverage(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : la couverture de détection est calculée sur les tirs de l'engagement actif UNIQUEMENT.
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // côté RED : techniques tirées (fired=1) + horodatage du tir, filtrées par campaign optionnelle.
    let fired = read_fired_techniques(&app, Some(eid), q.get("campaign").map(|c| ("campaign", c.as_str())));
    (StatusCode::OK, Json(fetch_purple_coverage(&app, fired).await))
}

/// POST /api/detection/test — ADMIN (check_admin, fail-closed 403). Exécute collect_detections UNE
/// fois contre une config FOURNIE (`{detection_source:{...}}` ou l'objet config à plat dans le corps)
/// ou, à défaut, la config STOCKÉE. Renvoie `{reachable, count, sample_mitres, error?}` — le SECRET
/// n'est JAMAIS renvoyé. Ledgerise `console.detection.test` (actor + kind + endpoint + auth_type +
/// reachable + count ; JAMAIS le secret). LECTURE seule côté source (ne persiste pas la config testée).
pub(crate) async fn detection_test(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    // WRITE-ONLY : `keep_secret` permet de tester une config éditée SANS re-saisir le secret déjà posé
    // (le secret write-only n'est jamais rendu par GET). apply_kept_secret réinjecte alors le secret stocké.
    let keep = body.get("keep_secret").and_then(|v| v.as_bool()).unwrap_or(false);
    // config à tester : {detection_source:{...}} > objet-config à plat ({kind:...}) > config stockée.
    let cfg: Arc<Value> = if let Some(v) = body.get("detection_source").filter(|v| v.is_object()) {
        Arc::new(apply_kept_secret(&app, v, keep))
    } else if body.is_object() && body.get("kind").is_some() {
        Arc::new(apply_kept_secret(&app, &body, keep))
    } else {
        app.detection_config()
    };
    // RÉDACTION : il faut le PLAINTEXT pour pouvoir le masquer — `ds_secret` ne rend plus qu'une
    // enveloppe. Best-effort : si elle n'ouvre pas, on n'a jamais su produire ce plaintext, donc aucun
    // message ne peut le porter.
    let secret = ds_secret_for_redaction(&cfg);
    let kind = ds_kind(&cfg);
    // since=0 : test « prends tout » (le but est de vérifier la joignabilité, pas une fenêtre précise).
    let result = collect_detections_with(&app, &cfg, 0).await;
    let (reachable, count, samples, error) = match result {
        Ok(dets) => {
            let count = dets.len() as i64;
            // échantillon de mitres DISTINCTS (max 8) — aide au diagnostic sans divulguer de secret.
            let mut seen = std::collections::BTreeSet::new();
            let mut samples: Vec<String> = Vec::new();
            for (m, _, _) in &dets {
                if seen.insert(m.clone()) {
                    samples.push(m.clone());
                }
                if samples.len() >= 8 {
                    break;
                }
            }
            (true, count, samples, None)
        }
        Err(e) => (false, 0i64, Vec::new(), Some(redact_secret(&e, &secret))),
    };
    // AUDIT : trace du test. JAMAIS le secret (endpoint + type d'auth seuls).
    append_console_ledger(&app, "console.detection.test", json!({
        "actor": actor,
        "kind": kind,
        "endpoint": ds_endpoint(&cfg),
        "auth_type": ds_auth_type(&cfg),
        "reachable": reachable,
        "count": count,
    }));
    let mut out = json!({
        "reachable": reachable,
        "count": count,
        "sample_mitres": samples,
    });
    if let (Value::Object(ref mut m), Some(e)) = (&mut out, error) {
        m.insert("error".into(), json!(e));
    }
    (StatusCode::OK, Json(out)).into_response()
}

/// GET /api/detection/source — ADMIN (check_admin, fail-closed 403). Renvoie la config de source de
/// détection EFFECTIVE (settings.detection_source sinon repli env legacy PLUME_URL/PLUME_TOKEN), le
/// SECRET RETIRÉ (jamais renvoyé — manié comme un secret de session), plus `secret_set` (un secret
/// est-il posé ?) et la liste FERMÉE des kinds. L'UI admin/wizard édite cette config ; le secret
/// write-only s'affiche ••• (secret_set) et n'est jamais re-rendu au client.
pub(crate) async fn detection_source_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let cfg = app.detection_config();
    let secret_set = !ds_secret(&cfg).is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "source": redact_detection_config(&cfg),
            "secret_set": secret_set,
            "kinds": DETECTION_KINDS,
        })),
    )
        .into_response()
}

/// POST /api/detection/source — ADMIN (check_admin, fail-closed 403). Persiste `settings.detection_source`
/// (config VERBATIM) puis recharge le cache (la couverture utilise immédiatement la nouvelle source).
/// Corps : `{detection_source:{...}}` OU l'objet-config à plat (`{kind,...}`), + `keep_secret?:bool`
/// (write-only : conserver le secret déjà posé sans le re-saisir). `kind` est validé contre la liste
/// FERMÉE (fail-closed, jamais persisté sinon). Ledgerise `console.detection.source.set` (actor + kind +
/// endpoint + auth_type — JAMAIS le secret). Réponse = config RÉDIGÉE + secret_set (le secret n'y est jamais).
pub(crate) async fn detection_source_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    // config entrante : {detection_source:{...}} > objet-config à plat ({kind:...}). Les clés de contrôle
    // (keep_secret) sont retirées de la config à plat pour ne pas polluer ce qui est persisté.
    let incoming: Value = if let Some(v) = body.get("detection_source").filter(|v| v.is_object()) {
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
            Json(json!({"error": "bad_request", "why": "corps attendu : {detection_source:{kind,...}} ou {kind,...}"})),
        )
            .into_response();
    };
    let kind = ds_kind(&incoming);
    if !is_known_detection_kind(&kind) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "bad_kind", "why": format!("kind de source inconnu : {kind}")})),
        )
            .into_response();
    }
    // WRITE-ONLY : si keep_secret et aucun nouveau secret fourni, réinjecte le secret déjà posé (sous
    // sa forme AU REPOS — l'enveloppe est recopiée telle quelle, jamais ouverte pour être re-scellée).
    let keep = body.get("keep_secret").and_then(|v| v.as_bool()).unwrap_or(false);
    let cfg = apply_kept_secret(&app, &incoming, keep);
    // CHIFFREMENT AU REPOS du secret d'intégration, AVANT la persistance. Fail-closed : sans clé de
    // champ, on REFUSE d'écrire un jeton en clair dans `settings` (503 nommé), on ne le fait pas
    // « quand même ». Idempotent sur une valeur déjà scellée (chemin keep_secret).
    let cfg = match seal_source_config(&cfg) {
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
        // Écriture ISOLÉE (le bloc n'appelle aucun autre helper `&Connection`) -> routée par le seam pour
        // la portabilité PG. SQL/params/erreur VERBATIM de `settings_set` (INSERT..ON CONFLICT déjà
        // portable ; `datetime('now')` reste un point dialecte Stage-2). Le helper `settings_set(&Connection)`
        // est CONSERVÉ pour ses appelants boot-partagés (main.rs `settings_get` sur la conn de boot) et
        // interleaved (setup.rs `upsert_user` dans le même guard) — convertis en bloc au Stage 2.
        
        let r = app.store()
            .execute(
                "INSERT INTO settings(key,value,updated) VALUES(?,?,datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
                &crate::sql_params!["detection_source", cfg.to_string()],
            )
            .map(|_| ())
            .map_err(|e| format!("écriture settings échouée: {e}"));
        if let Err(e) = r {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "settings_write_failed", "why": e})),
            )
                .into_response();
        }
    }
    // recharge le cache -> /api/detection/coverage bascule immédiatement sur la nouvelle source.
    app.reload_detection_source();
    app.bump_cache_epoch(); // B6 (HA): invalide le cache detection_source des pairs (nouvelle source)
    // AUDIT : mutation d'administration attribuée + ledgerisée. JAMAIS le secret (endpoint + type seuls).
    append_console_ledger(&app, "console.detection.source.set", json!({
        "actor": actor,
        "kind": kind,
        "endpoint": ds_endpoint(&cfg),
        "auth_type": ds_auth_type(&cfg),
    }));
    let secret_set = !ds_secret(&cfg).is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "source": redact_detection_config(&cfg),
            "secret_set": secret_set,
            "saved": true,
        })),
    )
        .into_response()
}

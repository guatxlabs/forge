// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — FINDINGS LIBRARY (bibliothèque de modèles de findings réutilisables).
//!
//! Couche livrable-client (à la Ghostwriter) : l'opérateur capitalise ses findings récurrents en
//! MODÈLES paramétrés (`{target}`/`{param}` remplis à l'application), réutilisables D'UN ENGAGEMENT À
//! L'AUTRE. Un `finding_template` est **GLOBAL** — il n'appartient à AUCUN engagement, et la liste
//! n'est jamais filtrée par engagement. En revanche, **APPLIQUER** un modèle crée un finding dans
//! l'engagement **ACTIF UNIQUEMENT** : le finding produit est estampillé de son `engagement_id` et
//! respecte l'isolation exactement comme tout autre finding (jamais dans un autre engagement).
//!
//! Gouvernance (miroir des autres mutations console, fail-closed) :
//!   - `GET  /api/finding-templates`         → liste (lecture, global)
//!   - `POST /api/finding-templates`         → créer   (OPÉRATEUR)
//!   - `POST /api/finding-templates/:id`     → éditer  (OPÉRATEUR)
//!   - `DELETE /api/finding-templates/:id`   → supprimer (ADMIN)
//!   - `POST /api/finding-templates/:id/apply` → applique → 1 finding dans l'engagement ACTIF (OPÉRATEUR)
//!
//! Chaque mutation est ATTRIBUÉE (login acteur) et LEDGERISÉE `console.finding_template.*` dans le
//! ledger console (chaîne SHA-256 tamper-evident). Un refus 403 ne mute jamais.
//!
//! Ce module réutilise `App` et les helpers d'auth/ledger de `main.rs` (visibles depuis un module
//! descendant de la racine de crate). Il n'ajoute AUCUN état ni aucune dépendance nouvelle.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::store::{Param, Row, StoreResult};
use crate::{
    admin_denied, append_console_ledger, attribution_login, check_admin, check_operator,
    cvss_base_for_severity, operator_denied, resolve_mutation_engagement_id, App,
};

/// Sévérités valides — miroir EXACT de `forge/schema.py::SEVERITIES` (source de vérité côté moteur).
/// Contrainte APPLICATIVE (pas SQL) : une sévérité hors de cet ensemble est refusée (fail-closed).
const SEVERITIES: [&str; 5] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

/// Colonnes projetées dans l'ordre attendu par [`row_to_json`]. `refs` (SQL-safe) exposé `references`.
const SELECT_COLS: &str =
    "id,name,vuln_class,cwe,severity,title_tmpl,description_tmpl,remediation_tmpl,refs,created,updated";

/// Sous-routeur des modèles de findings — FUSIONNÉ dans le routeur protégé de `build_router` (hérite
/// donc de l'auth_guard/host_guard). Les segments statiques (`/apply`) et le paramètre `:id` (i64) ne
/// collisionnent pas (matchit).
pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/finding-templates", get(ft_list).post(ft_create))
        .route("/api/finding-templates/{id}", post(ft_edit).delete(ft_delete))
        .route("/api/finding-templates/{id}/apply", post(ft_apply))
}

// --- helpers de réponse (JSON stable, non-fuiteur) ---------------------------------------------

fn bad(why: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": why.into()}))).into_response()
}
fn not_found(why: impl Into<String>) -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"error": "not_found", "why": why.into()}))).into_response()
}
fn internal(why: impl Into<String>) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal", "why": why.into()}))).into_response()
}

/// Normalise + valide une sévérité (casse insensible). None si hors SEVERITIES.
fn norm_severity(s: &str) -> Option<String> {
    let up = s.trim().to_ascii_uppercase();
    if SEVERITIES.contains(&up.as_str()) { Some(up) } else { None }
}

/// Nom de modèle valide : non vide après trim, ≤ 120 caractères. Substrat neutre (on ne contraint pas
/// la grammaire — un nom est un libellé humain), juste des bornes anti-abus.
fn valid_name(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.chars().count() <= 120
}

/// Lit `key` du corps comme chaîne trimmée (absent/non-string -> None).
fn body_str<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(|v| v.as_str()).map(str::trim)
}

/// Sérialise une ligne `finding_template` (colonnes = SELECT_COLS) en JSON d'API. `refs` -> `references`.
fn row_to_json(r: &Row) -> StoreResult<Value> {
    Ok(json!({
        "id": r.get_i64(0)?,
        "name": r.get_str(1)?,
        "vuln_class": r.get_str(2)?,
        "cwe": r.get_str(3)?,
        "severity": r.get_str(4)?,
        "title_tmpl": r.get_str(5)?,
        "description_tmpl": r.get_str(6)?,
        "remediation_tmpl": r.get_str(7)?,
        "references": r.get_str(8)?,
        "created": r.get_str(9)?,
        "updated": r.get_str(10)?,
    }))
}

/// Remplit les placeholders `{clef}` d'un gabarit par `params[clef]`. PUREMENT TEXTUEL (aucune
/// exécution : le contenu d'un modèle n'est jamais de confiance). Un placeholder SANS valeur est laissé
/// TEL QUEL (`{clef}` reste visible dans le finding → l'opérateur voit ce qui reste à compléter). Une
/// accolade non-appariée ou un `{...}` non-clef (contenu autre qu'alphanum/`._-`) est conservé littéral.
fn render_template(tmpl: &str, params: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(tmpl.len());
    let mut it = tmpl.chars().peekable();
    while let Some(c) = it.next() {
        if c != '{' {
            out.push(c);
            continue;
        }
        // collecte jusqu'à '}' (ou fin de chaîne)
        let mut key = String::new();
        let mut closed = false;
        while let Some(&nc) = it.peek() {
            it.next();
            if nc == '}' {
                closed = true;
                break;
            }
            key.push(nc);
        }
        let is_key = !key.is_empty()
            && key.chars().all(|k| k.is_ascii_alphanumeric() || k == '_' || k == '-' || k == '.');
        if closed && is_key {
            match params.get(&key) {
                Some(v) => out.push_str(v),
                None => {
                    // placeholder non fourni -> conservé visible
                    out.push('{');
                    out.push_str(&key);
                    out.push('}');
                }
            }
        } else {
            // pas une clef / accolade non-appariée -> conservé littéralement
            out.push('{');
            out.push_str(&key);
            if closed {
                out.push('}');
            }
        }
    }
    out
}

/// Construit la table de substitution depuis le corps d'apply : `params` (objet clef->valeur, valeurs
/// coercées en chaîne) + `target` de haut niveau injecté comme `{target}` (sans écraser un `params.target`
/// explicite). Substrat neutre : aucun placeholder inventé.
fn params_from_body(body: &Value) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(obj) = body.get("params").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Null => String::new(),
                other => other.to_string(),
            };
            m.insert(k.clone(), s);
        }
    }
    if let Some(t) = body.get("target").and_then(|v| v.as_str()) {
        m.entry("target".to_string()).or_insert_with(|| t.to_string());
    }
    m
}

// --- handlers ----------------------------------------------------------------------------------

/// GET /api/finding-templates — LISTE GLOBALE des modèles (lecture). JAMAIS filtrée par engagement :
/// un modèle est réutilisable across engagements. Trié par nom (insensible casse) puis id.
async fn ft_list(State(app): State<App>) -> Response {
    let store = app.store();
    let sql = format!(
        "SELECT {SELECT_COLS} FROM finding_template ORDER BY name COLLATE NOCASE ASC, id ASC"
    );
    // LENIENT read (pre-seam: `query_map(..).filter_map(|x| x.ok()).collect()`): prepare/bind errors
    // still 500, but a single malformed row is skipped rather than sinking the whole list.
    let rows: Vec<Value> = match store.query_lax(&sql, &[], row_to_json) {
        Ok(rows) => rows,
        Err(e) => return internal(e.to_string()),
    };
    drop(store); // release DB lock before serializing the response (no DB access below)
    (StatusCode::OK, Json(json!({"templates": rows, "count": rows.len()}))).into_response()
}

/// POST /api/finding-templates — CRÉE un modèle (OPÉRATEUR, fail-closed 403). Corps :
/// `{name, vuln_class?, cwe?, severity?, title_tmpl?, description_tmpl?, remediation_tmpl?, references?}`.
/// Attribué + ledgerisé `console.finding_template.create`.
async fn ft_create(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    let name = match body_str(&body, "name") {
        Some(n) if valid_name(n) => n.to_string(),
        _ => return bad("nom de modèle invalide (1..120 caractères, non vide)"),
    };
    let severity = match body_str(&body, "severity") {
        None => "INFO".to_string(),
        Some("") => "INFO".to_string(),
        Some(s) => match norm_severity(s) {
            Some(v) => v,
            None => return bad(format!("sévérité '{s}' invalide (INFO|LOW|MEDIUM|HIGH|CRITICAL)")),
        },
    };
    let vuln_class = body_str(&body, "vuln_class").unwrap_or("").to_string();
    let cwe = body_str(&body, "cwe").unwrap_or("").to_string();
    let title_tmpl = body.get("title_tmpl").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let description_tmpl = body.get("description_tmpl").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let remediation_tmpl = body.get("remediation_tmpl").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // `references` (API) -> colonne `refs` ; on accepte aussi `refs` en repli.
    let refs = body
        .get("references")
        .or_else(|| body.get("refs"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let actor = attribution_login(&app, &headers);
    let id = {
        let store = app.store();
        // execute_returning_id : id du modèle lu du MÊME INSERT (RETURNING id sur PG), sans lastval() —
        // session-indépendant, sûr sur backend poolé.
        match store.execute_returning_id(
            "INSERT INTO finding_template(name,vuln_class,cwe,severity,title_tmpl,description_tmpl,remediation_tmpl,refs,created,updated)
             VALUES(?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))",
            &crate::sql_params![
                name.clone(),
                vuln_class.clone(),
                cwe,
                severity.clone(),
                title_tmpl,
                description_tmpl,
                remediation_tmpl,
                refs
            ],
        ) {
            Ok(id) => id,
            Err(e) => return internal(format!("création du modèle échouée: {e}")),
        }
    };
    append_console_ledger(&app, "console.finding_template.create", json!({
        "actor": actor, "id": id, "name": name, "severity": severity, "vuln_class": vuln_class,
    }));
    (StatusCode::OK, Json(json!({
        "ok": true,
        "template": {"id": id, "name": name, "severity": severity, "vuln_class": vuln_class}
    }))).into_response()
}

/// POST /api/finding-templates/:id — ÉDITE un modèle (OPÉRATEUR, fail-closed 403). Champs fournis
/// SEULEMENT (partiel). Au moins un champ requis. Modèle inconnu -> 404. Attribué + ledgerisé
/// `console.finding_template.edit`.
async fn ft_edit(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    // existence (fail-closed : on n'édite jamais un modèle fantôme).
    {
        let store = app.store();
        let exists = store
            .query_row("SELECT 1 FROM finding_template WHERE id=?", &crate::sql_params![id], |_| Ok(()))
            .is_ok();
        drop(store); // release DB lock; the existence check is a standalone read (no atomic follow-up write here)
        if !exists {
            return not_found(format!("modèle {id} introuvable"));
        }
    }
    // validations préalables (avant toute écriture) : nom / sévérité.
    let new_name: Option<String> = match body.get("name") {
        None => None,
        Some(v) => {
            let n = v.as_str().unwrap_or("").trim().to_string();
            if !valid_name(&n) {
                return bad("nom de modèle invalide (1..120 caractères, non vide)");
            }
            Some(n)
        }
    };
    let new_sev: Option<String> = match body_str(&body, "severity") {
        None => None,
        Some(s) => match norm_severity(s) {
            Some(v) => Some(v),
            None => return bad(format!("sévérité '{s}' invalide (INFO|LOW|MEDIUM|HIGH|CRITICAL)")),
        },
    };
    // champs texte librement modifiables (présence = mise à jour, même vers "").
    let mut sets: Vec<&str> = Vec::new();
    let mut vals: Vec<String> = Vec::new();
    let mut changed: Vec<String> = Vec::new();
    if let Some(n) = &new_name { sets.push("name=?"); vals.push(n.clone()); changed.push("name".into()); }
    if let Some(s) = &new_sev { sets.push("severity=?"); vals.push(s.clone()); changed.push("severity".into()); }
    for (key, col) in [
        ("vuln_class", "vuln_class"),
        ("cwe", "cwe"),
        ("title_tmpl", "title_tmpl"),
        ("description_tmpl", "description_tmpl"),
        ("remediation_tmpl", "remediation_tmpl"),
    ] {
        if let Some(v) = body.get(key).and_then(|v| v.as_str()) {
            sets.push(match col {
                "vuln_class" => "vuln_class=?",
                "cwe" => "cwe=?",
                "title_tmpl" => "title_tmpl=?",
                "description_tmpl" => "description_tmpl=?",
                _ => "remediation_tmpl=?",
            });
            vals.push(v.to_string());
            changed.push(col.into());
        }
    }
    // `references` (API) -> colonne `refs`.
    if let Some(v) = body.get("references").or_else(|| body.get("refs")).and_then(|v| v.as_str()) {
        sets.push("refs=?");
        vals.push(v.to_string());
        changed.push("references".into());
    }
    if sets.is_empty() {
        return bad("aucun changement fourni (name|severity|vuln_class|cwe|title_tmpl|description_tmpl|remediation_tmpl|references)");
    }
    let actor = attribution_login(&app, &headers);
    {
        let store = app.store();
        let sql = format!("UPDATE finding_template SET {}, updated=datetime('now') WHERE id=?", sets.join(", "));
        // Dynamic parameter list: the SET values (all TEXT) followed by the WHERE `id` bind.
        let mut params: Vec<Param> = vals.iter().map(|s| Param::Text(s.clone())).collect();
        params.push(Param::Int(id));
        if let Err(e) = store.execute(&sql, &params) {
            return internal(format!("édition du modèle échouée: {e}"));
        }
    }
    append_console_ledger(&app, "console.finding_template.edit", json!({
        "actor": actor, "id": id, "changed": changed,
    }));
    (StatusCode::OK, Json(json!({"ok": true, "id": id, "changed": changed}))).into_response()
}

/// DELETE /api/finding-templates/:id — SUPPRIME un modèle (ADMIN, fail-closed 403). Modèle inconnu ->
/// 404. Attribué + ledgerisé `console.finding_template.delete`. Ne touche AUCUN finding déjà créé
/// (les findings issus d'un modèle sont indépendants — supprimer le modèle n'affecte pas l'engagement).
async fn ft_delete(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let name: String = {
        let store = app.store();
        match store.query_row(
            "SELECT name FROM finding_template WHERE id=?",
            &crate::sql_params![id],
            |r| r.get_str(0),
        ) {
            Ok(n) => n,
            Err(_) => return not_found(format!("modèle {id} introuvable")),
        }
    };
    let actor = attribution_login(&app, &headers);
    {
        let store = app.store();
        if let Err(e) = store.execute("DELETE FROM finding_template WHERE id=?", &crate::sql_params![id]) {
            return internal(format!("suppression du modèle échouée: {e}"));
        }
    }
    append_console_ledger(&app, "console.finding_template.delete", json!({
        "actor": actor, "id": id, "name": name,
    }));
    (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response()
}

/// POST /api/finding-templates/:id/apply — APPLIQUE un modèle : crée UN finding dans l'engagement ACTIF
/// (OPÉRATEUR, fail-closed 403). Corps : `{engagement_id?, target?, campaign?, params?:{}}`. L'engagement
/// est résolu par `resolve_mutation_engagement_id` (query `?engagement=` > body `engagement_id` > actif) :
/// un id EXPLICITE doit EXISTER (fail-closed). Le finding produit porte cet `engagement_id` — ISOLATION :
/// il n'atterrit JAMAIS dans un autre engagement, même si le modèle est global. Les gabarits sont rendus
/// avec `params` (+ `{target}`). Attribué + ledgerisé `console.finding_template.apply`.
async fn ft_apply(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    // ENGAGEMENT ACTIF (isolation) : le finding créé appartient à CET engagement uniquement. ENTERPRISE
    // (flag-gated) : l'engagement cible doit être d'un tenant accordé (fail-closed) — cf. resolve_mutation.
    let engagement_id = match resolve_mutation_engagement_id(&app, &headers, &q, &body) {
        Ok(e) => e,
        Err(why) => return bad(why),
    };
    // charge le modèle (fail-closed : modèle fantôme -> 404).
    let (name, severity, vuln_class, cwe, title_t, desc_t, rem_t): (String, String, String, String, String, String, String) = {
        let store = app.store();
        match store.query_row(
            "SELECT name,severity,vuln_class,cwe,title_tmpl,description_tmpl,remediation_tmpl FROM finding_template WHERE id=?",
            &crate::sql_params![id],
            |r| Ok((r.get_str(0)?, r.get_str(1)?, r.get_str(2)?, r.get_str(3)?, r.get_str(4)?, r.get_str(5)?, r.get_str(6)?)),
        ) {
            Ok(t) => t,
            Err(_) => return not_found(format!("modèle {id} introuvable")),
        }
    };
    let params = params_from_body(&body);
    let title = {
        let t = render_template(&title_t, &params);
        if t.trim().is_empty() { name.clone() } else { t } // titre vide -> repli sur le nom du modèle
    };
    let description = render_template(&desc_t, &params);
    let remediation = render_template(&rem_t, &params);
    let target = body_str(&body, "target").unwrap_or("").to_string();
    let campaign = body_str(&body, "campaign").unwrap_or("").to_string();
    let tool = format!("template:{name}");
    let (cvss_vec, cvss_score) = cvss_base_for_severity(&severity);

    let (created, finding_id) = {
        let store = app.store();
        // INSERT OR IGNORE : la contrainte UNIQUE(campaign,target,title) du finding s'applique (dédup) —
        // un doublon exact est ignoré (created=false), jamais une erreur.
        // execute_returning_id_opt : id du finding lu du MÊME INSERT (RETURNING id sur PG), sans
        // lastval() — session-indépendant, sûr sur backend poolé. `None` == ON CONFLICT DO NOTHING a
        // ignoré un doublon (aucune ligne insérée), byte-identique à l'ancien garde `if n > 0`.
        match store.execute_returning_id_opt(
            "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score,engagement_id)
             VALUES(datetime('now'),?,?,?,?,?,'','tested',?,?,'',?,'',?,?,?,?) ON CONFLICT DO NOTHING",
            &crate::sql_params![
                campaign,
                target.clone(),
                title.clone(),
                severity.clone(),
                vuln_class,
                description,
                tool,
                remediation,
                cwe,
                cvss_vec,
                cvss_score,
                engagement_id
            ],
        ) {
            Ok(Some(id)) => (true, id),
            Ok(None) => (false, -1),
            Err(e) => return internal(format!("création du finding échouée: {e}")),
        }
    };

    if !created {
        return (StatusCode::CONFLICT, Json(json!({
            "ok": false, "created": false, "engagement_id": engagement_id, "template_id": id,
            "why": "finding déjà présent (campagne/cible/titre identiques) — dédupliqué"
        }))).into_response();
    }
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.finding_template.apply", json!({
        "actor": actor, "template_id": id, "template_name": name,
        "engagement_id": engagement_id, "finding_id": finding_id, "target": target,
    }));
    (StatusCode::OK, Json(json!({
        "ok": true, "created": true, "finding_id": finding_id,
        "engagement_id": engagement_id, "template_id": id, "title": title, "severity": severity,
    }))).into_response()
}

// =====================================================================================
//  TESTS — CRUD gouverné (rôle) + ledgerisé, et apply isolé à l'engagement ACTIF.
//
//  Auto-portants : on construit une App de test (DB in-memory, SCHEMA + migrate comme au boot serveur)
//  et on appelle les handlers directement. Les helpers de crate (upsert_user/create_session/hash_pw/
//  read_ledger_lines/migrate) sont visibles depuis ce module descendant de la racine.
// =====================================================================================
#[cfg(test)]
mod tests {
    // `super::*` apporte déjà App, les extracteurs axum (State/ConnectInfo/Path/Query), HeaderMap,
    // StatusCode, Json, Response, Router, json/Value/HashMap, SocketAddr et les helpers de crate
    // (check_operator/…). On n'importe explicitement QUE ce qui n'y est pas.
    use super::*;
    use crate::{create_session, hash_pw, read_ledger_lines, upsert_user, LedgerHead, RunEvent, RunState};
    use rusqlite::Connection;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    /// Chemin de ledger unique dans le tempdir de l'OS (cross-platform — jamais /tmp en dur).
    fn tmp_ledger(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "forge-ft-{}-{}-{}.jsonl",
            tag,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        p.push(uniq);
        p.to_string_lossy().into_owned()
    }

    /// App de test : DB in-memory avec SCHEMA **puis** migrate() (comme le boot serveur — les colonnes
    /// additives engagement_id/cwe/cvss du finding en dépendent), ledger sur disque (tempfile).
    fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        crate::migrate(&conn);
        let (events, _) = broadcast::channel::<RunEvent>(64);
        App {
            db: Arc::new(Mutex::new(conn)),
            #[cfg(feature = "store-postgres")]
            pg: None,
            #[cfg(feature = "store-postgres")]
            ha: false,
            #[cfg(feature = "store-postgres")]
            instance_id: Arc::new("test-instance".into()),
            #[cfg(feature = "store-postgres")]
            is_leader: Arc::new(AtomicBool::new(true)),
            db_path: Arc::new(":memory:".into()),
            token_sha: Arc::new(crate::sha_hex("t")),
            token_raw: Arc::new("t".into()),
            user: Arc::new("forge".into()),
            pass_hash: Arc::new(String::new()),
            auth_required: Arc::new(AtomicBool::new(false)),
            operator_hash: Arc::new(String::new()),
            allowed_hosts: Arc::new(vec!["localhost".into()]),
            ledger_path: Arc::new(ledger_path.to_string()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(RunState { current: std::collections::HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        }
    }

    /// Insère un engagement (id imposé) — les tests apply ont besoin d'engagements existants.
    fn seed_engagement(app: &App, id: i64, name: &str) {
        let db = app.db();
        db.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(?,?, 'active','grey','{}','',datetime('now'),datetime('now'))",
            rusqlite::params![id, name],
        )
        .unwrap();
    }

    fn bearer(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {tok}").parse().unwrap());
        h
    }
    fn uid_of(app: &App, login: &str) -> i64 {
        let db = app.db();
        db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
    }
    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:9".parse().unwrap())
    }
    /// Seed les 3 rôles et renvoie leurs tokens de session (viewer, operator, admin).
    fn seed_roles(app: &App) -> (String, String, String) {
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let (v, _) = create_session(app, uid_of(app, "vv"));
        let (o, _) = create_session(app, uid_of(app, "oo"));
        let (a, _) = create_session(app, uid_of(app, "aa"));
        (v, o, a)
    }
    fn tid_of(app: &App, name: &str) -> i64 {
        let db = app.db();
        db.query_row("SELECT id FROM finding_template WHERE name=?", [name], |r| r.get(0)).unwrap()
    }
    fn tmpl_count(app: &App) -> i64 {
        let db = app.db();
        db.query_row("SELECT COUNT(*) FROM finding_template", [], |r| r.get(0)).unwrap()
    }

    /// render_template : substitution, placeholder manquant conservé, accolade non-appariée conservée.
    #[test]
    fn render_fills_and_preserves() {
        let mut p = std::collections::HashMap::new();
        p.insert("target".to_string(), "app.example.com".to_string());
        p.insert("param".to_string(), "q".to_string());
        assert_eq!(
            render_template("SQLi sur {target} via {param}", &p),
            "SQLi sur app.example.com via q"
        );
        // placeholder non fourni -> conservé visible
        assert_eq!(render_template("reste {todo}", &p), "reste {todo}");
        // accolade non-appariée / non-clef -> littéral
        assert_eq!(render_template("a { b } c", &p), "a { b } c");
        assert_eq!(render_template("open {target", &p), "open {target");
        assert_eq!(render_template("no placeholders", &p), "no placeholders");
    }

    /// CREATE role-gated (viewer 403, operator 200) + ledgerisé + persistance.
    #[tokio::test]
    async fn create_is_operator_gated_and_ledgered() {
        let led = tmp_ledger("create");
        let app = test_app(&led);
        let (vtok, otok, _atok) = seed_roles(&app);

        // viewer -> 403 ET aucune création.
        let r = ft_create(
            State(app.clone()), peer(), bearer(&vtok),
            Json(json!({"name": "XSS reflété", "severity": "HIGH"})),
        ).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "viewer refusé (fail-closed)");
        assert_eq!(tmpl_count(&app), 0, "un refus 403 ne DOIT rien créer");

        // operator -> 200 + persistance + ledger attribué.
        let r = ft_create(
            State(app.clone()), peer(), bearer(&otok),
            Json(json!({"name": "XSS reflété", "severity": "high", "cwe": "CWE-79",
                        "vuln_class": "xss", "title_tmpl": "XSS sur {target}",
                        "description_tmpl": "Param {param} reflété.", "remediation_tmpl": "Encoder la sortie.",
                        "references": "https://owasp.org/xss"})),
        ).await;
        assert_eq!(r.status(), StatusCode::OK, "operator autorisé");
        assert_eq!(tmpl_count(&app), 1, "modèle persisté");
        let (sev, cwe, refs): (String, String, String) = {
            let db = app.db();
            db.query_row("SELECT severity,cwe,refs FROM finding_template WHERE name='XSS reflété'", [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
        };
        assert_eq!(sev, "HIGH", "sévérité normalisée en majuscule");
        assert_eq!(cwe, "CWE-79");
        assert_eq!(refs, "https://owasp.org/xss", "references -> colonne refs");
        let entries = read_ledger_lines(&led);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.finding_template.create");
        assert_eq!(last["detail"]["actor"], "oo", "attribué à l'opérateur acteur");

        // sévérité invalide -> 400.
        let r = ft_create(State(app.clone()), peer(), bearer(&otok),
            Json(json!({"name": "x", "severity": "URGENT"}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "sévérité hors ensemble -> 400");
        // nom vide -> 400.
        let r = ft_create(State(app.clone()), peer(), bearer(&otok),
            Json(json!({"name": "   "}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "nom vide -> 400");
        let _ = std::fs::remove_file(&led);
    }

    /// EDIT operator-gated (viewer 403) + partiel + ledgerisé ; DELETE admin-gated (operator 403).
    #[tokio::test]
    async fn edit_operator_delete_admin_gated_ledgered() {
        let led = tmp_ledger("edit");
        let app = test_app(&led);
        let (vtok, otok, atok) = seed_roles(&app);
        // seed un modèle via l'API (operator).
        ft_create(State(app.clone()), peer(), bearer(&otok),
            Json(json!({"name": "IDOR", "severity": "MEDIUM"}))).await;
        let id = tid_of(&app, "IDOR");

        // EDIT viewer -> 403, aucune mutation.
        let r = ft_edit(State(app.clone()), peer(), bearer(&vtok), Path(id),
            Json(json!({"severity": "HIGH"}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "viewer ne peut éditer");
        let sev: String = { let db = app.db(); db.query_row("SELECT severity FROM finding_template WHERE id=?", [id], |r| r.get(0)).unwrap() };
        assert_eq!(sev, "MEDIUM", "un 403 ne mute rien");

        // EDIT operator -> 200 + changement.
        let r = ft_edit(State(app.clone()), peer(), bearer(&otok), Path(id),
            Json(json!({"severity": "critical", "cwe": "CWE-639", "references": "ref"}))).await;
        assert_eq!(r.status(), StatusCode::OK, "operator peut éditer");
        let (sev, cwe): (String, String) = { let db = app.db(); db.query_row("SELECT severity,cwe FROM finding_template WHERE id=?", [id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!(sev, "CRITICAL");
        assert_eq!(cwe, "CWE-639");
        let last = read_ledger_lines(&led);
        assert_eq!(last.last().unwrap()["kind"], "console.finding_template.edit");

        // EDIT sans champ -> 400.
        let r = ft_edit(State(app.clone()), peer(), bearer(&otok), Path(id), Json(json!({}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "aucun changement -> 400");
        // EDIT id inconnu -> 404.
        let r = ft_edit(State(app.clone()), peer(), bearer(&otok), Path(9999), Json(json!({"cwe": "x"}))).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "modèle inconnu -> 404");

        // DELETE operator -> 403 (admin requis), modèle intact.
        let r = ft_delete(State(app.clone()), bearer(&otok), Path(id)).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "operator ne peut supprimer (admin requis)");
        assert_eq!(tmpl_count(&app), 1, "un 403 delete ne supprime rien");

        // DELETE admin -> 200 + suppression + ledger.
        let r = ft_delete(State(app.clone()), bearer(&atok), Path(id)).await;
        assert_eq!(r.status(), StatusCode::OK, "admin peut supprimer");
        assert_eq!(tmpl_count(&app), 0, "modèle supprimé");
        assert_eq!(read_ledger_lines(&led).last().unwrap()["kind"], "console.finding_template.delete");
        // DELETE inconnu -> 404.
        let r = ft_delete(State(app.clone()), bearer(&atok), Path(id)).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "delete inconnu -> 404");
        let _ = std::fs::remove_file(&led);
    }

    /// LISTE non filtrée par engagement (GLOBALE) : un modèle est visible quel que soit l'engagement.
    #[tokio::test]
    async fn list_is_global_not_engagement_filtered() {
        let led = tmp_ledger("list");
        let app = test_app(&led);
        seed_engagement(&app, 2, "eng-B"); // #1 absent ici — la liste ne dépend d'aucun engagement.
        let (_v, otok, _a) = seed_roles(&app);
        ft_create(State(app.clone()), peer(), bearer(&otok), Json(json!({"name": "T1"}))).await;
        ft_create(State(app.clone()), peer(), bearer(&otok), Json(json!({"name": "T2"}))).await;

        let r = ft_list(State(app.clone())).await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = to_json(r).await;
        assert_eq!(body["count"], 2, "les 2 modèles listés, indépendamment de tout engagement");
        let names: Vec<String> = body["templates"].as_array().unwrap().iter()
            .map(|t| t["name"].as_str().unwrap().to_string()).collect();
        assert!(names.contains(&"T1".to_string()) && names.contains(&"T2".to_string()));
        let _ = std::fs::remove_file(&led);
    }

    /// APPLY : préremplit un finding dans l'engagement ACTIF (ici #2) — jamais dans un autre (#1).
    /// Vérifie le remplissage des placeholders, l'isolation, et le ledger `apply`.
    #[tokio::test]
    async fn apply_creates_finding_in_current_engagement_only() {
        let led = tmp_ledger("apply");
        let app = test_app(&led);
        seed_engagement(&app, 1, "eng-A");
        seed_engagement(&app, 2, "eng-B");
        let (vtok, otok, _a) = seed_roles(&app);
        ft_create(State(app.clone()), peer(), bearer(&otok),
            Json(json!({"name": "SQLi", "severity": "HIGH", "cwe": "CWE-89", "vuln_class": "sqli",
                        "title_tmpl": "SQLi sur {target}", "description_tmpl": "Param {param} injectable.",
                        "remediation_tmpl": "Requêtes paramétrées."}))).await;
        let id = tid_of(&app, "SQLi");

        // viewer -> 403 (fail-closed), aucun finding.
        let r = ft_apply(State(app.clone()), peer(), bearer(&vtok), Path(id),
            Query(std::collections::HashMap::new()),
            Json(json!({"engagement_id": 2, "target": "b.example.com", "params": {"param": "id"}}))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "viewer ne peut appliquer");
        let total: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM finding", [], |r| r.get(0)).unwrap() };
        assert_eq!(total, 0, "un 403 apply ne crée aucun finding");

        // operator applique sur l'engagement #2 (ACTIF ciblé).
        let r = ft_apply(State(app.clone()), peer(), bearer(&otok), Path(id),
            Query(std::collections::HashMap::new()),
            Json(json!({"engagement_id": 2, "target": "b.example.com", "params": {"param": "id"}}))).await;
        assert_eq!(r.status(), StatusCode::OK, "operator applique");
        let body = to_json(r).await;
        assert_eq!(body["created"], true);
        let fid = body["finding_id"].as_i64().unwrap();

        // le finding appartient à l'engagement #2, PAS #1 (isolation).
        let (eid, title, sev, cwe, cat, evidence, fix): (i64, String, String, String, String, String, String) = {
            let db = app.db();
            db.query_row("SELECT engagement_id,title,severity,cwe,category,evidence,fix FROM finding WHERE id=?", [fid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))).unwrap()
        };
        assert_eq!(eid, 2, "finding créé dans l'engagement ACTIF (#2), jamais un autre");
        assert_eq!(title, "SQLi sur b.example.com", "titre : placeholder {{target}} rempli");
        assert_eq!(sev, "HIGH");
        assert_eq!(cwe, "CWE-89");
        assert_eq!(cat, "sqli", "vuln_class -> category");
        assert_eq!(evidence, "Param id injectable.", "description -> evidence, {{param}} rempli");
        assert_eq!(fix, "Requêtes paramétrées.", "remediation -> fix");

        // vue engagement #1 : ZÉRO finding (isolation prouvée).
        let n1: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=1", [], |r| r.get(0)).unwrap() };
        let n2: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=2", [], |r| r.get(0)).unwrap() };
        assert_eq!(n1, 0, "l'engagement #1 ne voit PAS le finding de #2");
        assert_eq!(n2, 1, "le finding vit dans l'engagement #2");

        // ledger apply attribué + estampillé engagement.
        let last = read_ledger_lines(&led);
        let e = last.last().unwrap();
        assert_eq!(e["kind"], "console.finding_template.apply");
        assert_eq!(e["detail"]["actor"], "oo");
        assert_eq!(e["detail"]["engagement_id"], 2);
        assert_eq!(e["detail"]["template_id"], id);

        // apply sur un engagement inexistant -> 400 (fail-closed, jamais de finding orphelin).
        let r = ft_apply(State(app.clone()), peer(), bearer(&otok), Path(id),
            Query(std::collections::HashMap::new()),
            Json(json!({"engagement_id": 777, "target": "z"}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "engagement inexistant -> 400");
        // apply modèle inconnu -> 404.
        let r = ft_apply(State(app.clone()), peer(), bearer(&otok), Path(4242),
            Query(std::collections::HashMap::new()),
            Json(json!({"engagement_id": 2, "target": "z"}))).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "modèle inconnu -> 404");
        let _ = std::fs::remove_file(&led);
    }

    /// Le sous-routeur se construit sans conflit matchit (`:id` vs `:id/apply`).
    #[test]
    fn routes_do_not_conflict() {
        let _r: Router<App> = routes();
    }

    /// Décode le corps JSON d'une Response (tests uniquement).
    async fn to_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}

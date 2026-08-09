// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — RAPPORT D'ENGAGEMENT AGRÉGÉ (le livrable client, couche à la Ghostwriter).
//!
//! `run_report` (main.rs) rend le rapport d'UN run. Ce module rend le rapport AGRÉGÉ d'un ENGAGEMENT
//! (tous ses findings/runs), brandé au commanditaire :
//!   `GET /api/engagements/:id/report?format=html|pdf|docx|csv|json`
//!
//! GARANTIES (jamais affaiblies) :
//!   - ISOLATION PAR ENGAGEMENT : toute lecture (findings/runs/techniques/ledger) est FILTRÉE sur
//!     `engagement_id = :id`. Le rapport de l'engagement A ne touche JAMAIS les données de B. Un id
//!     inconnu -> 404 (jamais les données d'un autre).
//!   - RÔLE (viewer+) : la génération est réservée à une identité authentifiée (session viewer/operator/
//!     admin ou repli bootstrap). En dev-open (auth non engagée) la lecture reste ouverte, cohérent avec
//!     les autres endpoints de lecture. La CONFIG de branding est réservée à l'ADMIN.
//!   - LEDGERISÉ : chaque génération journalise `console.report.generate` (métadonnées : engagement,
//!     format, comptes par sévérité/statut — JAMAIS de secret). Chaque écriture de branding journalise
//!     `console.report.branding.set`.
//!   - SECRETS RÉDIGÉS dans TOUS les formats (HTML/CSV/JSON ; le DOCX est délégué au générateur Python
//!     qui rédige aussi). La rédaction s'applique une fois, au niveau des données.
//!   - CROSS-PLATFORM : PDF via un outil système résolu dans le PATH (dégrade en 501 + note d'impression
//!     si absent) ; DOCX délégué à `python -m forge.report_engagement` (dégrade en 501 si python absent).
//!
//! Réutilise `App` + les helpers d'auth/ledger/rapport de `main.rs` (visibles depuis ce module
//! descendant de la racine de crate). N'ajoute AUCUN état ni dépendance nouvelle.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::{
    admin_denied, append_console_ledger, attribution_login, bounded_engine_output, canon_json, check_admin,
    csv_field, cvss_base_for_severity, delegated_render_error, engagement_ledger_path,
    engine_timeout_secs, extract_cwe,
    fetch_purple_coverage, html_escape,
    load_engagement, read_fired_techniques, read_ledger_lines, render_pdf_from_html,
    resolve_identity, sev_css_class, sha_hex, App, EngineBoundErr, ENGINE_BINARY_MAX_BYTES, ENGINE_GATE,
    REPORT_CSS,
};

const SEVERITIES: [&str; 5] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const VALID_FORMATS: [&str; 5] = ["html", "pdf", "docx", "csv", "json"];
/// Taille max d'un logo de branding (data-URI/URL) — borne anti-abus (documents autonomes).
const MAX_LOGO_LEN: usize = 512 * 1024;

/// Sous-routeur du livrable client — FUSIONNÉ dans le routeur protégé de `build_router` (hérite de
/// l'auth_guard/host_guard). Segments statiques (`/report`) sous `:id` (i64) : aucun conflit matchit.
pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/api/engagements/{id}/report", get(engagement_report))
        .route("/api/report/branding", get(branding_get).post(branding_set))
}

// --- réponses JSON stables --------------------------------------------------------------------
fn bad(why: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": why.into()}))).into_response()
}

// =====================================================================================
//  RÉDACTION DES SECRETS — désormais MUTUALISÉE dans `crate::redact` (union des listes de clefs
//  sensibles reports.rs + compliance.rs ; strip de blocs PEM + scan mot-à-mot). Voir src/redact.rs.
// =====================================================================================
use crate::redact::redact_secrets;

// =====================================================================================
//  BRANDING (config admin-éditable, globale ou par-engagement)
// =====================================================================================

/// Branding effectif d'un engagement : `settings.branding` (global) surchargé par
/// `settings.branding.<id>` (par-engagement). Champs : customer_name, logo, vendor, confidentiality.
/// Aucun secret. Substrat neutre : clef absente -> défaut sobre (jamais inventé).
fn effective_branding(app: &App, eid: i64) -> Value {
    let store = app.store();
    let global = crate::settings_get_store(&store, "branding")
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(|| json!({}));
    let per = crate::settings_get_store(&store, &format!("branding.{eid}"))
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(|| json!({}));
    drop(store);
    let pick = |key: &str, default: &str| -> String {
        per.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| global.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
            .unwrap_or(default)
            .to_string()
    };
    json!({
        "customer_name": pick("customer_name", ""),
        "logo": pick("logo", ""),
        "vendor": pick("vendor", "GuatX Forge"),
        "confidentiality": pick("confidentiality",
            "Document confidentiel — diffusion restreinte au commanditaire"),
    })
}

/// GET /api/report/branding[?engagement=<id>] — branding EFFECTIF + valeurs brutes (global + override).
/// Lecture (viewer+). Aucun secret exposé (le branding n'en contient pas).
async fn branding_get(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if !viewer_allowed(&app, &headers) {
        return viewer_denied();
    }
    let eid = q.get("engagement").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(1);
    let (global, per) = {
        let store = app.store();
        (
            crate::settings_get_store(&store, "branding").and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or_else(|| json!({})),
            crate::settings_get_store(&store, &format!("branding.{eid}")).and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or_else(|| json!({})),
        )
    };
    (StatusCode::OK, Json(json!({
        "engagement_id": eid,
        "effective": effective_branding(&app, eid),
        "global": global,
        "override": per,
    }))).into_response()
}

/// POST /api/report/branding[?engagement=<id>] — écrit la config de branding (ADMIN, fail-closed 403).
/// Corps `{customer_name?, logo?, vendor?, confidentiality?}`. Avec `?engagement=<id>` -> override
/// `settings.branding.<id>` ; sinon -> global `settings.branding`. Ledgerisé `console.report.branding.set`.
async fn branding_set(
    State(app): State<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let scope_eid = q.get("engagement").and_then(|s| s.trim().parse::<i64>().ok());
    // On ne conserve QUE les clefs connues (substrat neutre, pas de champ arbitraire injecté).
    let mut obj = serde_json::Map::new();
    for key in ["customer_name", "logo", "vendor", "confidentiality"] {
        if let Some(v) = body.get(key).and_then(|v| v.as_str()) {
            if key == "logo" && v.len() > MAX_LOGO_LEN {
                return bad(format!("logo trop volumineux (> {} octets)", MAX_LOGO_LEN));
            }
            obj.insert(key.to_string(), json!(v));
        }
    }
    if obj.is_empty() {
        return bad("aucun champ de branding fourni (customer_name|logo|vendor|confidentiality)");
    }
    let key = match scope_eid {
        Some(id) => format!("branding.{id}"),
        None => "branding".to_string(),
    };
    let value = Value::Object(obj.clone()).to_string();
    {
        let store = app.store();
        if let Err(e) = crate::settings_set_store(&store, &key, &value) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal", "why": e}))).into_response();
        }
    }
    let actor = attribution_login(&app, &headers);
    // ledger : on journalise les CLEFS écrites (pas les valeurs — sobriété, même si non secrètes).
    let changed: Vec<String> = obj.keys().cloned().collect();
    append_console_ledger(&app, "console.report.branding.set", json!({
        "actor": actor, "scope": scope_eid.map(|i| i.to_string()).unwrap_or_else(|| "global".into()),
        "changed": changed,
    }));
    (StatusCode::OK, Json(json!({"ok": true, "scope": key, "changed": changed}))).into_response()
}

// =====================================================================================
//  RÔLE (viewer+)
// =====================================================================================

/// Vrai si l'appelant peut générer un rapport : identité authentifiée (session viewer/operator/admin
/// OU repli bootstrap) ; à défaut, autorisé UNIQUEMENT si l'auth n'est pas engagée (dev-open), comme
/// les autres endpoints de lecture. Fail-closed dès qu'une auth est engagée sans identité.
fn viewer_allowed(app: &App, headers: &HeaderMap) -> bool {
    if resolve_identity(app, headers).is_some() {
        return true;
    }
    !app.auth_required()
}

fn viewer_denied() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "auth_required",
            "why": "génération de rapport réservée à une session authentifiée (viewer+) — POST /api/login"
        })),
    )
        .into_response()
}

// =====================================================================================
//  ASSEMBLAGE DES DONNÉES (isolé à l'engagement) + rendu
// =====================================================================================

/// Dérive (cwe, cvss_vector, cvss_score) d'un finding avec repli : cwe depuis category si vide ; CVSS
/// depuis la sévérité si absent (parité EXACTE avec read_finding_rows de main.rs).
fn derive_taxo(category: &str, severity: &str, cwe_in: &str, vec_in: &str, score_in: f64) -> (String, String, f64) {
    let cwe = if cwe_in.is_empty() { extract_cwe(category) } else { cwe_in.to_string() };
    if vec_in.is_empty() && score_in <= 0.0 {
        let (v, s) = cvss_base_for_severity(severity);
        (cwe, v.to_string(), s)
    } else {
        (cwe, vec_in.to_string(), score_in)
    }
}

/// Lit les findings de l'engagement `eid` (UNIQUEMENT) en Value JSON, chaque champ texte RÉDIGÉ.
/// `category` est exposé aussi bien en `category` qu'en `vuln_class` (le générateur groupe dessus).
fn read_engagement_findings(app: &App, eid: i64) -> Vec<Value> {
    let store = app.store();
    // LENIENT (query_lax) : prepare échoué -> vec vide, ligne malformée ignorée (idem query_map+filter_map).
    store.query_lax(
        "SELECT title,target,severity,category,mitre,status,tool,evidence,poc,fix,cwe,cvss_vector,cvss_score,campaign,ts \
         FROM finding WHERE engagement_id=? ORDER BY id DESC",
        &crate::sql_params![eid],
        |r| {
            let title = r.get_opt_str(0)?.unwrap_or_default();
            let target = r.get_opt_str(1)?.unwrap_or_default();
            let severity = r.get_opt_str(2)?.unwrap_or_default();
            let category = r.get_opt_str(3)?.unwrap_or_default();
            let mitre = r.get_opt_str(4)?.unwrap_or_default();
            let status = r.get_opt_str(5)?.unwrap_or_default();
            let tool = r.get_opt_str(6)?.unwrap_or_default();
            let evidence = r.get_opt_str(7)?.unwrap_or_default();
            let poc = r.get_opt_str(8)?.unwrap_or_default();
            let fix = r.get_opt_str(9)?.unwrap_or_default();
            let cwe_in = r.get_opt_str(10)?.unwrap_or_default();
            let vec_in = r.get_opt_str(11)?.unwrap_or_default();
            let score_in = r.get_opt_f64(12)?.unwrap_or(0.0);
            let campaign = r.get_opt_str(13)?.unwrap_or_default();
            let ts = r.get_opt_str(14)?.unwrap_or_default();
            let (cwe, cvss_vector, cvss_score) = derive_taxo(&category, &severity, &cwe_in, &vec_in, score_in);
            // RÉDACTION des champs texte libre (severity/cwe/mitre/status/cvss = énumérés/ids -> intacts).
            Ok(json!({
                "title": redact_secrets(&title),
                "target": redact_secrets(&target),
                "severity": severity,
                "category": redact_secrets(&category),
                "vuln_class": redact_secrets(&category),
                "mitre": mitre,
                "status": status,
                "tool": redact_secrets(&tool),
                "evidence": redact_secrets(&evidence),
                "poc": redact_secrets(&poc),
                "fix": redact_secrets(&fix),
                "cwe": cwe,
                "cvss_vector": cvss_vector,
                "cvss_score": cvss_score,
                "campaign": redact_secrets(&campaign),
                "ts": ts,
                "engagement_id": eid,
            }))
        },
    )
    .unwrap_or_default()
}

/// Lit les runs de l'engagement `eid` (UNIQUEMENT) en Value JSON (métadonnées de run, pas de secret).
fn read_engagement_runs(app: &App, eid: i64) -> Vec<Value> {
    let store = app.store();
    // LENIENT (query_lax) : prepare échoué -> vec vide, ligne malformée ignorée (idem query_map+filter_map).
    store.query_lax(
        "SELECT run_id,campaign,mode,status,started,finished,started_by,fired,dry_run,vetoed,errors \
         FROM run_job WHERE engagement_id=? ORDER BY id DESC",
        &crate::sql_params![eid],
        |r| {
            Ok(json!({
                "run_id": r.get_opt_str(0)?.unwrap_or_default(),
                "campaign": r.get_opt_str(1)?.unwrap_or_default(),
                "mode": r.get_opt_str(2)?.unwrap_or_default(),
                "status": r.get_opt_str(3)?.unwrap_or_default(),
                "started": r.get_opt_str(4)?.unwrap_or_default(),
                "finished": r.get_opt_str(5)?.unwrap_or_default(),
                "started_by": r.get_opt_str(6)?.unwrap_or_default(),
                "fired": r.get_opt_i64(7)?.unwrap_or(0),
                "dry_run": r.get_opt_i64(8)?.unwrap_or(0),
                "vetoed": r.get_opt_i64(9)?.unwrap_or(0),
                "errors": r.get_opt_i64(10)?.unwrap_or(0),
            }))
        },
    )
    .unwrap_or_default()
}

/// Agrège les techniques ATT&CK EXERCÉES (fired=1) de l'engagement `eid` (UNIQUEMENT), groupées par
/// identifiant MITRE : kinds, cibles, nombre de tirs. Trié par MITRE.
fn aggregate_techniques(app: &App, eid: i64) -> Vec<Value> {
    
    // LENIENT (query_lax) : prepare/ligne en erreur -> rows vide -> agrégation vide (idem l'ancien
    // double early-return `return vec![]`, dont la sortie finale était de toute façon vide).
    let rows: Vec<(String, String, String)> = app.store().query_lax(
        "SELECT mitre,kind,target FROM runrecord WHERE engagement_id=? AND fired=1 AND mitre<>''",
        &crate::sql_params![eid],
        |r| {
            Ok((
                r.get_opt_str(0)?.unwrap_or_default(),
                r.get_opt_str(1)?.unwrap_or_default(),
                r.get_opt_str(2)?.unwrap_or_default(),
            ))
        },
    ).unwrap_or_default();
    // agrégation déterministe (BTreeMap trie par MITRE ; sets triés).
    use std::collections::{BTreeMap, BTreeSet};
    let mut agg: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>, i64)> = BTreeMap::new();
    for (mitre, kind, target) in rows {
        let e = agg.entry(mitre).or_insert_with(|| (BTreeSet::new(), BTreeSet::new(), 0));
        if !kind.is_empty() {
            e.0.insert(kind);
        }
        if !target.is_empty() {
            e.1.insert(redact_secrets(&target));
        }
        e.2 += 1;
    }
    agg.into_iter()
        .map(|(mitre, (kinds, targets, fires))| json!({
            "mitre": mitre,
            "kinds": kinds.into_iter().collect::<Vec<_>>(),
            "targets": targets.into_iter().collect::<Vec<_>>(),
            "fires": fires,
        }))
        .collect()
}

/// Annexe chaîne-de-custody pour un ledger DONNÉ (celui de l'engagement — ISOLATION). Recalcule la
/// chaîne SHA-256 (sans clef) : head, nb entrées, algo, validité. La clef publique Ed25519 éventuelle
/// vient de l'env (informative). Miroir de build_ledger_custody de main.rs, mais sur un chemin explicite.
fn build_custody(ledger_path: &str) -> Value {
    const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let pubkey = std::env::var("FORGE_CONSOLE_LEDGER_PUBKEY").unwrap_or_default();
    let entries = read_ledger_lines(ledger_path);
    if entries.is_empty() {
        let exists = std::path::Path::new(ledger_path).exists();
        return json!({
            "ledger_path": ledger_path, "entries": 0, "head": "", "alg": "",
            "chain_ok": exists, "why": if exists { "" } else { "ledger absent" }, "pubkey": pubkey,
        });
    }
    let mut prev = GENESIS.to_string();
    let mut head = GENESIS.to_string();
    let mut alg = String::new();
    let mut chain_ok = true;
    let mut why = String::new();
    for rec in &entries {
        let seq = rec.get("seq").cloned().unwrap_or(Value::Null);
        let ts = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let detail = rec.get("detail").cloned().unwrap_or(Value::Null);
        let stored_prev = rec.get("prev").and_then(|v| v.as_str()).unwrap_or("");
        let stored_hash = rec.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        alg = rec.get("alg").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if stored_prev != prev {
            chain_ok = false;
            why = "chaînage rompu (prev)".into();
            break;
        }
        let seq_str = match &seq {
            Value::Number(n) => n.to_string(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        let preimage = format!("{prev}|{seq_str}|{ts}|{kind}|{}", canon_json(&detail));
        if sha_hex(&preimage) != stored_hash {
            chain_ok = false;
            why = "hash recalculé != hash stocké (entrée altérée)".into();
            break;
        }
        prev = stored_hash.to_string();
        head = stored_hash.to_string();
    }
    json!({
        "ledger_path": ledger_path, "entries": entries.len(), "head": head, "alg": alg,
        "chain_ok": chain_ok, "why": why, "pubkey": pubkey,
    })
}

/// Compteurs du résumé exécutif (par sévérité + par statut + total) — utilisés pour le ledger et le
/// rendu. AUCUN texte de finding (juste des comptes) -> sûr à journaliser.
fn summarize(findings: &[Value]) -> Value {
    let mut by_sev: HashMap<String, i64> = HashMap::new();
    let mut by_status: HashMap<String, i64> = HashMap::new();
    let mut by_class: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    for f in findings {
        let sev = f.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO");
        let sev = if SEVERITIES.contains(&sev) { sev } else { "INFO" };
        *by_sev.entry(sev.to_string()).or_insert(0) += 1;
        let st = f.get("status").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("tested");
        *by_status.entry(st.to_string()).or_insert(0) += 1;
        let vc = f.get("vuln_class").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("(non classé)");
        *by_class.entry(vc.to_string()).or_insert(0) += 1;
    }
    let sev_obj: serde_json::Map<String, Value> = SEVERITIES
        .iter()
        .rev()
        .map(|s| (s.to_string(), json!(by_sev.get(*s).copied().unwrap_or(0))))
        .collect();
    json!({
        "total": findings.len(),
        "by_severity": sev_obj,
        "by_status": by_status,
        "by_vuln_class": by_class,
    })
}

/// Assemble la STRUCTURE COMPLÈTE du rapport (isolée à `eid`) : branding + engagement + summary +
/// findings (rédigés) + runs + attack (techniques exercées + détection) + custody (ledger d'engagement).
/// Cette Value alimente TOUS les formats (json direct, csv/html en Rust, docx délégué à Python).
async fn build_report_data(app: &App, eid: i64) -> Value {
    // méta engagement (name/status/classification) + scope (via load_engagement).
    let (name, status, classification): (String, String, String) = {
        let store = app.store();
        store.query_row(
            "SELECT COALESCE(name,''),COALESCE(status,''),COALESCE(classification,'') FROM engagement WHERE id=?",
            &crate::sql_params![eid],
            |r| Ok((r.get_str(0)?, r.get_str(1)?, r.get_str(2)?)),
        )
        .unwrap_or_default()
    };
    // load_engagement passe désormais par le seam Store (state.rs) — portable Postgres.
    let eng = load_engagement(&app.store(), eid);
    let (mode, scope_in, scope_out) = match &eng {
        Some(e) => (e.mode.clone(), e.scope_in.clone(), e.scope_out.clone()),
        None => (String::new(), vec![], vec![]),
    };
    let generated: String = {
        let store = app.store();
        store.query_row("SELECT datetime('now')", &[], |r| r.get_str(0)).unwrap_or_default()
    };

    let findings = read_engagement_findings(app, eid);
    let runs = read_engagement_runs(app, eid);
    let techniques = aggregate_techniques(app, eid);

    // détection (purple) : fired ISOLÉ à l'engagement -> matrice à TROIS états (exact / parente-approx
    // / raté) si une source est configurée.
    let fired = read_fired_techniques(app, Some(eid), None);
    let purple = fetch_purple_coverage(app, fired).await;
    // Le rapport CLIENT rend les TROIS états de la jointure purple, jamais deux : `detected`
    // (detected-exact — le seul qui alimente `detection_rate` et le MTTD), `parent_approx`
    // (sous-technique tirée / seule la parente est couverte — un angle mort NOMMÉ, pas du déchet),
    // `missed`. Omettre le parent-approx ici ferait dire au rapport autre chose qu'à l'API.
    let attack = json!({
        "techniques": techniques,
        "detection_source_configured": purple.get("source_configured").and_then(|v| v.as_bool()).unwrap_or(false),
        "techniques_fired": purple.get("techniques_fired").cloned().unwrap_or(json!(0)),
        "techniques_detected": purple.get("techniques_detected").cloned().unwrap_or(json!(0)),
        "techniques_parent_approx": purple.get("techniques_parent_approx").cloned().unwrap_or(json!(0)),
        "techniques_missed": purple.get("techniques_missed").cloned().unwrap_or(json!(0)),
        "detection_rate": purple.get("detection_rate").cloned().unwrap_or(json!(0.0)),
        "detected": purple.get("detected").cloned().unwrap_or(json!([])),
        "parent_approx": purple.get("parent_approx").cloned().unwrap_or(json!([])),
        "missed": purple.get("missed").cloned().unwrap_or(json!([])),
    });

    let ledger_path = engagement_ledger_path(app, eid);
    let custody = build_custody(&ledger_path);
    let branding = effective_branding(app, eid);
    let summary = summarize(&findings);

    // PARTIALITÉ DE L'ENGAGEMENT — le livrable client agrège des findings STOCKÉS, sans jamais
    // regarder si les runs qui les ont produits sont allés au bout. Un engagement dont la moitié des
    // runs a expiré rendait donc un rapport qui RESSEMBLE à un rapport complet : « aucun risque
    // critique » s'y lit comme un verdict alors que le plan n'a pas tourné. Le rapport de run porte
    // déjà cette bannière ; l'agrégat la porte maintenant aussi, DÉRIVÉE de `run_job.status` (aucune
    // invention : on nomme les runs concernés et leur statut).
    let cut: Vec<Value> = runs
        .iter()
        .filter(|r| {
            crate::report_render::view::partial_cause(r.get("status").and_then(|v| v.as_str()).unwrap_or("")).is_some()
        })
        .map(|r| {
            json!({
                "run_id": r.get("run_id").cloned().unwrap_or(json!("")),
                "status": r.get("status").cloned().unwrap_or(json!("")),
                "why": crate::report_render::view::partial_cause(r.get("status").and_then(|v| v.as_str()).unwrap_or("")).unwrap_or(""),
            })
        })
        .collect();
    let partial = json!({
        "is_partial": !cut.is_empty(),
        "runs_total": runs.len(),
        "runs_interrupted": cut.len(),
        "runs": cut,
    });

    json!({
        "generated": generated,
        "branding": branding,
        "engagement": {
            "id": eid, "name": name, "mode": mode, "status": status,
            "classification": classification, "scope_in": scope_in, "scope_out": scope_out,
        },
        "summary": summary,
        "findings": findings,
        "runs": runs,
        // consommé par le HTML/JSON de ce module ET disponible pour le générateur DOCX Python
        // (`forge/report_engagement.py`) — voir le patch signalé : tant qu'il ne le lit pas, le DOCX
        // reste le SEUL format qui ne dit pas qu'un engagement est partiel.
        "partial": partial,
        "attack": attack,
        "custody": custody,
    })
}

// --- rendu CSV/HTML depuis la Value ----------------------------------------------------------

const CSV_COLS: [&str; 15] = [
    "severity", "vuln_class", "cwe", "cvss_score", "cvss_vector", "mitre", "status", "target", "title",
    "tool", "campaign", "evidence", "poc", "fix", "ts",
];

// Échappement CSV : `common::csv_field` (importé ci-dessus) — RFC-4180 + NEUTRALISATION de l'injection de
// formule tableur (CWE-1236). Ce module n'a plus sa propre variante : le CSV d'engagement est le livrable
// que le client ouvre dans un tableur, il ne peut pas avoir un garde plus faible que l'export bulk.
// ATTENTION : ce n'est PAS le seul générateur du CSV d'engagement — `forge/report_engagement.py::build_csv`
// rend le même livrable (15 mêmes colonnes) pour `python -m forge.report_engagement --format csv`. Les deux
// neutralisent le même jeu de préfixes, partagé via `console/testdata/csv_injection_vectors.json`.

/// Export CSV des findings (déjà rédigés). En-tête stable CSV_COLS -> round-trip trivial.
fn render_csv(data: &Value) -> String {
    let mut out = String::new();
    out.push_str(&CSV_COLS.join(","));
    out.push('\n');
    if let Some(arr) = data.get("findings").and_then(|v| v.as_array()) {
        for f in arr {
            let cells: Vec<String> = CSV_COLS
                .iter()
                .map(|c| {
                    let v = f.get(*c).cloned().unwrap_or(json!(""));
                    let s = match &v {
                        Value::String(s) => s.clone(),
                        Value::Null => String::new(),
                        other => other.to_string(),
                    };
                    csv_field(&s)
                })
                .collect();
            out.push_str(&cells.join(","));
            out.push('\n');
        }
    }
    out
}

/// Phrase en prose des comptes par sévérité (résumé exécutif).
fn prose_counts(summary: &Value) -> String {
    let total = summary.get("total").and_then(|v| v.as_i64()).unwrap_or(0);
    if total == 0 {
        return "Aucun finding n'a été retenu sur cet engagement.".into();
    }
    let sev = summary.get("by_severity").cloned().unwrap_or(json!({}));
    let labels = [
        ("CRITICAL", "critique"),
        ("HIGH", "élevé"),
        ("MEDIUM", "moyen"),
        ("LOW", "faible"),
        ("INFO", "informatif"),
    ];
    let mut parts = Vec::new();
    for (k, base) in labels {
        let n = sev.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        if n > 0 {
            parts.push(format!("{n} {base}{}", if n > 1 { "s" } else { "" }));
        }
    }
    format!(
        "L'évaluation a retenu {total} finding{} : {}.",
        if total > 1 { "s" } else { "" },
        parts.join(", ")
    )
}

fn dash(s: &str) -> &str {
    if s.is_empty() { "—" } else { s }
}

/// Rapport d'engagement HTML BRANDÉ (thème Aurora réutilisé de main.rs, `REPORT_CSS`). Document
/// autonome (CSS inliné, imprimable). Tout texte dynamique échappé HTML ; secrets déjà rédigés.
///
/// `preview` : rendu destiné à l'APERÇU intégré (iframe de la vue #reports). Dans ce mode la barre
/// d'actions du document est OMISE — le SÉLECTEUR DE FORMAT unique vit dans le panneau de la console
/// (`#rep-format` + « Générer »). Sans ce garde, le document embarquait ses PROPRES liens ?format=…
/// dupliquant le sélecteur du panneau (choix affichés deux fois) et, cliqués dans l'iframe sandboxée
/// (attachment -> download, sans allow-scripts pour `window.print`), aboutissant à un panneau BLANC.
/// En mode NON-preview (téléchargement HTML autonome) on ne conserve que le bouton « Imprimer »
/// (aucun lien ?format= : ils seraient inertes hors serveur et redupliqueraient le contrôle unique).
fn render_html(data: &Value, preview: bool) -> String {
    let e = html_escape;
    let getstr = |v: &Value, k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let branding = data.get("branding").cloned().unwrap_or(json!({}));
    let eng = data.get("engagement").cloned().unwrap_or(json!({}));
    let summary = data.get("summary").cloned().unwrap_or(json!({}));
    let empty: Vec<Value> = vec![];
    let findings = data.get("findings").and_then(|v| v.as_array()).cloned().unwrap_or(empty.clone());

    let customer = {
        let c = getstr(&branding, "customer_name");
        if c.is_empty() { "Commanditaire".to_string() } else { c }
    };
    let vendor = {
        let v = getstr(&branding, "vendor");
        if v.is_empty() { "GuatX Forge".to_string() } else { v }
    };
    let confidentiality = {
        let c = getstr(&branding, "confidentiality");
        if c.is_empty() { "Document confidentiel — diffusion restreinte au commanditaire".to_string() } else { c }
    };
    let logo = getstr(&branding, "logo");
    let eng_name = getstr(&eng, "name");
    let eng_id = eng.get("id").and_then(|v| v.as_i64()).unwrap_or(0);

    let mut h = String::with_capacity(16_384);
    h.push_str("<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    h.push_str(&format!("<title>{} — rapport d'engagement</title>", e(&customer)));
    h.push_str(REPORT_CSS);
    h.push_str("</head><body>");

    // ----- barre d'actions (écran seulement) -----
    // SÉLECTEUR DE FORMAT UNIQUE : il vit dans le panneau de la console (`#rep-format`), PAS dans le
    // document. En APERÇU (preview) : aucune barre (sinon les choix de format apparaîtraient deux fois
    // et, cliqués dans l'iframe sandboxée, blanchiraient le panneau). En téléchargement HTML autonome :
    // uniquement « Imprimer » (les liens ?format= seraient inertes hors serveur — on ne les remet pas).
    if !preview {
        h.push_str("<div class=\"toolbar noprint\">");
        h.push_str("<button type=\"button\" onclick=\"window.print()\">Imprimer / Enregistrer en PDF</button>");
        h.push_str("</div>");
    }

    // ----- PAGE DE GARDE brandée (logo client OPTIONNEL + nom) -----
    // Le logo de la page de garde est le logo DU COMMANDITAIRE (livrable brandé) : configurable par
    // l'admin (branding.logo, URL ou data-URI). ABSENT -> on N'AFFICHE RIEN (pas de carré vide ni de
    // mark Forge détournée en « logo client »). src échappé HTML (html_escape neutralise les quotes).
    h.push_str("<section class=\"cover\">");
    if !logo.is_empty() {
        h.push_str(&format!("<img class=\"qz\" src=\"{}\" alt=\"logo du commanditaire\">", e(&logo)));
    }
    h.push_str(&format!("<div class=\"brand\">{}</div>", e(&customer)));
    h.push_str(&format!("<div class=\"cover-camp\">Évaluation de sécurité — {}</div>", e(&vendor)));
    h.push_str("<h1 class=\"cover-title\">Rapport d'engagement</h1>");
    h.push_str(&format!(
        "<div class=\"cover-camp\">{}</div>",
        e(if eng_name.is_empty() { "(engagement sans nom)" } else { &eng_name })
    ));
    h.push_str("<dl class=\"cover-meta\">");
    for (k, v) in [
        ("Engagement", format!("#{eng_id}")),
        ("Mode", getstr(&eng, "mode")),
        ("Statut", getstr(&eng, "status")),
        ("Généré", getstr(data, "generated")),
    ] {
        h.push_str(&format!("<dt>{}</dt><dd>{}</dd>", e(k), e(dash(&v))));
    }
    h.push_str("</dl>");
    h.push_str(&format!("<div class=\"cover-foot\">{}</div>", e(&confidentiality)));
    h.push_str("</section>");

    // ----- BANNIÈRE DE PARTIALITÉ (avant le résumé exécutif : elle en BORNE la portée) -----
    let partial = data.get("partial").cloned().unwrap_or(json!({}));
    if partial.get("is_partial").and_then(|v| v.as_bool()).unwrap_or(false) {
        let n = partial.get("runs_interrupted").and_then(|v| v.as_i64()).unwrap_or(0);
        let tot = partial.get("runs_total").and_then(|v| v.as_i64()).unwrap_or(0);
        let detail: Vec<String> = partial
            .get("runs")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .map(|r| {
                        format!(
                            "{} ({})",
                            getstr(r, "run_id"),
                            getstr(r, "why"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        h.push_str(&format!(
            "<p class=\"posture posture-bad\">⚠️ ENGAGEMENT PARTIEL — {n} run(s) sur {tot} ne sont pas \
             allés au bout : {}. Ce rapport n'agrège que ce qui a effectivement tourné : une absence \
             de finding n'y vaut PAS une absence de vulnérabilité, et aucun verdict — surtout pas \
             négatif — n'a été émis pour ce qui n'a jamais été tenté.</p>",
            e(&detail.join(" · ")),
        ));
    }

    // ----- RÉSUMÉ EXÉCUTIF -----
    h.push_str("<section class=\"sec\"><h2>Résumé exécutif</h2>");
    let scope_in: Vec<String> = eng.get("scope_in").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let scope_phrase = if scope_in.is_empty() { "le périmètre planifié".to_string() } else { format!("le périmètre {}", e(&scope_in.join(", "))) };
    h.push_str(&format!("<p>Cet engagement a couvert {scope_phrase}. {}</p>", e(&prose_counts(&summary))));
    // cartes par sévérité
    let sev = summary.get("by_severity").cloned().unwrap_or(json!({}));
    h.push_str("<div class=\"sevgrid\">");
    for s in SEVERITIES.iter().rev() {
        let n = sev.get(*s).and_then(|v| v.as_i64()).unwrap_or(0);
        h.push_str(&format!(
            "<div class=\"sevcard {}\"><div class=\"n\">{}</div><div class=\"l\">{}</div></div>",
            sev_css_class(s), n, e(s)
        ));
    }
    h.push_str("</div>");
    // tableau par classe de vuln
    if let Some(bc) = summary.get("by_vuln_class").and_then(|v| v.as_object()).filter(|o| !o.is_empty()) {
        h.push_str("<h3>Par classe de vulnérabilité</h3><table class=\"vtab\"><thead><tr><th>Classe</th><th>#</th></tr></thead><tbody>");
        for (vc, n) in bc {
            h.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", e(vc), n.as_i64().unwrap_or(0)));
        }
        h.push_str("</tbody></table>");
    }
    h.push_str("</section>");

    // ----- FINDINGS (groupés sévérité -> classe) -----
    h.push_str("<section class=\"sec\"><h2>Findings détaillés</h2>");
    if findings.is_empty() {
        h.push_str("<p class=\"muted\">Aucun finding retenu.</p>");
    }
    // ordre : sévérité décroissante puis classe alpha.
    let mut ordered = findings.clone();
    let rank = |f: &Value| -> i32 {
        let s = f.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO");
        SEVERITIES.iter().position(|x| *x == s).map(|i| i as i32).unwrap_or(0)
    };
    ordered.sort_by(|a, b| {
        rank(b).cmp(&rank(a)).then_with(|| {
            getstr(a, "vuln_class").cmp(&getstr(b, "vuln_class"))
        })
    });
    for f in &ordered {
        let severity = getstr(f, "severity");
        let cvss_score = f.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let cvss_vector = getstr(f, "cvss_vector");
        let cvss_disp = if cvss_score <= 0.0 && cvss_vector.is_empty() {
            String::new()
        } else if cvss_vector.is_empty() {
            format!("{cvss_score:.1}")
        } else {
            format!("{cvss_score:.1} ({cvss_vector})")
        };
        h.push_str("<article class=\"finding\">");
        h.push_str(&format!(
            "<h3><span class=\"sevbadge {}\">{}</span> {} <span class=\"tgt\">{}</span></h3>",
            sev_css_class(&severity), e(&severity), e(&getstr(f, "title")), e(&getstr(f, "target"))
        ));
        h.push_str("<div class=\"taxo\">");
        h.push_str(&format!("<span class=\"chip\"><b>CWE</b> {}</span>", e(dash(&getstr(f, "cwe")))));
        h.push_str(&format!("<span class=\"chip\"><b>CVSS</b> {}</span>", e(dash(&cvss_disp))));
        h.push_str(&format!("<span class=\"chip\"><b>ATT&amp;CK</b> {}</span>", e(dash(&getstr(f, "mitre")))));
        h.push_str(&format!("<span class=\"chip\"><b>Classe</b> {}</span>", e(dash(&getstr(f, "vuln_class")))));
        h.push_str(&format!("<span class=\"chip\"><b>Statut</b> {}</span>", e(dash(&getstr(f, "status")))));
        h.push_str(&format!("<span class=\"chip\"><b>Outil</b> {}</span>", e(dash(&getstr(f, "tool")))));
        h.push_str("</div>");
        let evidence = getstr(f, "evidence");
        if !evidence.is_empty() {
            h.push_str(&format!("<div class=\"fld\"><div class=\"k\">Evidence</div><pre>{}</pre></div>", e(&evidence)));
        }
        let poc = getstr(f, "poc");
        if !poc.is_empty() {
            h.push_str(&format!("<div class=\"fld\"><div class=\"k\">PoC</div><pre>{}</pre></div>", e(&poc)));
        }
        let fix = getstr(f, "fix");
        if !fix.is_empty() {
            h.push_str(&format!("<div class=\"fld fix\"><div class=\"k\">Remédiation</div><div class=\"v\">{}</div></div>", e(&fix)));
        }
        h.push_str("</article>");
    }
    h.push_str("</section>");

    // ----- COUVERTURE ATT&CK -----
    h.push_str("<section class=\"sec\"><h2>Couverture ATT&amp;CK</h2>");
    let attack = data.get("attack").cloned().unwrap_or(json!({}));
    let techs = attack.get("techniques").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if techs.is_empty() {
        h.push_str("<p class=\"muted\">Aucune technique ATT&amp;CK taggée n'a été tirée sur cet engagement.</p>");
    } else {
        h.push_str("<table class=\"vtab\"><thead><tr><th>ATT&amp;CK</th><th>Kind(s)</th><th>Cible(s)</th><th>Tirs</th></tr></thead><tbody>");
        for t in &techs {
            let kinds: Vec<String> = t.get("kinds").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            let tgts: Vec<String> = t.get("targets").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            h.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                e(&getstr(t, "mitre")),
                e(dash(&kinds.join(", "))),
                e(dash(&tgts.join(", "))),
                t.get("fires").and_then(|v| v.as_i64()).unwrap_or(0)
            ));
        }
        h.push_str("</tbody></table>");
    }
    if attack.get("detection_source_configured").and_then(|v| v.as_bool()).unwrap_or(false) {
        // TROIS ÉTATS — le rapport d'engagement rend le parent-approx à part, comme l'API et le
        // rapport de run. Une surface qui n'en rend que deux dirait autre chose que les autres.
        h.push_str("<h3>Détection (source configurée)</h3><ul>");
        h.push_str(&format!(
            "<li>Tirées : {} · Détectées EXACTEMENT : {} · Couverture parente approximative : {} · Ratées : {}</li>",
            attack.get("techniques_fired").and_then(|v| v.as_i64()).unwrap_or(0),
            attack.get("techniques_detected").and_then(|v| v.as_i64()).unwrap_or(0),
            attack.get("techniques_parent_approx").and_then(|v| v.as_i64()).unwrap_or(0),
            attack.get("techniques_missed").and_then(|v| v.as_i64()).unwrap_or(0)
        ));
        h.push_str("</ul>");
        if let Some(missed) = attack.get("missed").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) {
            h.push_str("<h3>Techniques NON détectées (trous SOC)</h3><ul>");
            for m in missed {
                h.push_str(&format!(
                    "<li><code>{}</code> — tirée {}×</li>",
                    e(m.get("mitre").and_then(|v| v.as_str()).unwrap_or("?")),
                    m.get("fires").and_then(|v| v.as_i64()).unwrap_or(0)
                ));
            }
            h.push_str("</ul>");
        }
        if let Some(ap) = attack.get("parent_approx").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) {
            h.push_str("<h3>Couverture parente approximative (angle mort — NON comptée comme détectée)</h3><ul>");
            for a in ap {
                h.push_str(&format!(
                    "<li><code>{}</code> — tirée {}× ; aucune règle sur cette sous-technique, seule la parente <code>{}</code> alerte ({} alerte(s)).</li>",
                    e(a.get("mitre").and_then(|v| v.as_str()).unwrap_or("?")),
                    a.get("fires").and_then(|v| v.as_i64()).unwrap_or(0),
                    e(a.get("parent").and_then(|v| v.as_str()).unwrap_or("?")),
                    a.get("parent_alert_count").and_then(|v| v.as_i64()).unwrap_or(0)
                ));
            }
            h.push_str("</ul>");
        }
    } else {
        h.push_str("<p class=\"muted\">Aucune source de détection configurée — Forge en autonome. Matrice détecté / parente-approx / raté indisponible (aucune couverture inventée).</p>");
    }
    h.push_str("</section>");

    // ----- ANNEXE chaîne-de-custody -----
    h.push_str("<section class=\"sec\"><h2>Annexe — chaîne de custody</h2>");
    let custody = data.get("custody").cloned().unwrap_or(json!({}));
    h.push_str("<p class=\"muted\">Preuve d'intégrité de l'audit : chaîne de hachage SHA-256 du ledger d'engagement (chaque acte chaîné au précédent). La clef publique permet une vérification externe sans aucun secret.</p>");
    h.push_str("<dl class=\"custody\">");
    let chain_ok = custody.get("chain_ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let why = getstr(&custody, "why");
    let integrity = if chain_ok {
        "VALIDE (chaîne SHA-256 recalculée, chaînage cohérent)".to_string()
    } else {
        format!("ROMPUE — {}", if why.is_empty() { "intégrité non vérifiée".into() } else { why })
    };
    let head = getstr(&custody, "head");
    let alg = getstr(&custody, "alg");
    let pubkey = getstr(&custody, "pubkey");
    let ledger_path = getstr(&custody, "ledger_path");
    let mut rows = vec![
        ("Ledger", ledger_path.clone()),
        ("Entrées", custody.get("entries").and_then(|v| v.as_i64()).unwrap_or(0).to_string()),
        ("Algorithme", if alg.is_empty() { "—".into() } else { alg }),
        ("Head (dernier hash)", if head.is_empty() { "—".into() } else { head }),
        ("Intégrité", integrity),
    ];
    if !pubkey.is_empty() {
        rows.push(("Clé publique (Ed25519)", pubkey.clone()));
    }
    for (k, v) in &rows {
        h.push_str(&format!("<dt>{}</dt><dd><code>{}</code></dd>", e(k), e(v)));
    }
    h.push_str("</dl>");
    if !pubkey.is_empty() && !ledger_path.is_empty() {
        h.push_str(&format!(
            "<pre class=\"cmd\">forge ledger verify --ledger {} --pubkey {}</pre>",
            e(&ledger_path), e(&pubkey)
        ));
    }
    h.push_str("</section>");

    h.push_str("</body></html>");
    h
}

/// Délègue la génération DOCX au générateur Python (`python -m forge.report_engagement --format docx
/// --stdin`) : la Value du rapport (ISOLÉE à l'engagement) est envoyée sur stdin, les octets .docx
/// reviennent sur stdout. Réutilise le générateur zipfile stdlib (source unique). no-shell : argv FIXE,
/// aucun contenu client en argv.
/// S5-bis — CE SPAWN EST UN COÛT MACHINE sur une route de LECTURE (viewer+), au coût par requête
/// SUPÉRIEUR au dry-plan : il est BORNÉ par le seul helper qui prend un slot (`bounded_engine_output` :
/// plafond `ENGINE_GATE`, budget `FORGE_ENGINE_TIMEOUT` avec kill du GROUPE, plafond d'octets sur le DOCX
/// collecté, mort du groupe si la requête est abandonnée).
/// CAUSE RENDUE EXACTE (correctif) : la borne franchie n'est plus JETÉE. Avant, `try_acquire()?` et
/// `.ok()?` écrasaient « plafond atteint » et « budget dépassé » en `None`, que l'appelant traduisait en
/// « générateur DOCX indisponible sur l'hôte — installez python3 » : mesuré, avec python3 INSTALLÉ, deux
/// lectures viewer tenant les slots suffisaient à annoncer une installation cassée à tout le monde. On
/// remonte donc l'erreur TYPÉE ; l'appelant en fait un code HTTP et un message par cause.
async fn render_docx_via_python(app: &App, data: &Value) -> Result<Vec<u8>, EngineBoundErr> {
    let mut cmd = tokio::process::Command::new(app.python.as_str());
    cmd.args(["-m", "forge.report_engagement", "--format", "docx", "--stdin"])
        .current_dir(app.pkg_dir.as_str());
    let out = bounded_engine_output(
        &ENGINE_GATE,
        cmd,
        std::time::Duration::from_secs(engine_timeout_secs()),
        ENGINE_BINARY_MAX_BYTES,
        Some(data.to_string().into_bytes()),
    )
    .await?;
    if out.status.success() && !out.stdout.is_empty() {
        Ok(out.stdout)
    } else {
        // VRAIE cause « pas installé » : le module a tourné et a échoué (ex. `No module named forge`).
        // On la rend telle quelle, code de sortie compris, au lieu de la deviner.
        let err: String = String::from_utf8_lossy(&out.stderr).trim().chars().take(240).collect();
        Err(EngineBoundErr::Io(format!(
            "générateur DOCX rc={:?}{}",
            out.status.code(),
            if err.is_empty() { String::new() } else { format!(": {err}") }
        )))
    }
}

/// GET /api/engagements/:id/report?format=html|pdf|docx|csv|json — LE LIVRABLE CLIENT AGRÉGÉ.
/// ISOLÉ à l'engagement `:id` (404 si inconnu), viewer+ (fail-closed si auth engagée), ledgerisé
/// `console.report.generate`. HTML/PDF/CSV/JSON rendus en Rust (secrets rédigés) ; DOCX délégué à Python.
async fn engagement_report(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !viewer_allowed(&app, &headers) {
        return viewer_denied();
    }
    // format d'abord (400 si inconnu, sans rien assembler ni ledgeriser).
    let format = q.get("format").map(|s| s.as_str()).unwrap_or("html").to_string();
    if !VALID_FORMATS.contains(&format.as_str()) {
        return bad(format!("format inconnu '{format}' (html|pdf|docx|csv|json)"));
    }
    // ISOLATION : l'engagement doit EXISTER (sinon 404 — jamais les données d'un autre).
    let exists = { let store = app.store(); store.query_row("SELECT 1 FROM engagement WHERE id=?", &crate::sql_params![id], |_| Ok(())).is_ok() };
    if !exists {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_engagement", "id": id}))).into_response();
    }
    // ENTERPRISE (flag-gated) fail-closed : le rapport d'un engagement d'un tenant NON accordé au caller
    // est indisponible -> 404 (mêmes octets que « inconnu » : ni existence ni données divulguées).
    // No-op en community (engagement_visible => true).
    if crate::tenancy::enabled(&app) && !crate::tenancy::engagement_visible(&app, &headers, id) {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_engagement", "id": id}))).into_response();
    }

    let data = build_report_data(&app, id).await;

    // LEDGER : métadonnées (jamais de secret) — comptes par sévérité/statut, totaux, format.
    let summary = data.get("summary").cloned().unwrap_or(json!({}));
    let findings_total = data.get("findings").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
    let runs_total = data.get("runs").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.report.generate", json!({
        "actor": actor, "engagement_id": id, "format": format,
        "findings_total": findings_total, "runs_total": runs_total,
        "by_severity": summary.get("by_severity").cloned().unwrap_or(json!({})),
        "by_status": summary.get("by_status").cloned().unwrap_or(json!({})),
    }));

    match format.as_str() {
        "json" => (
            StatusCode::OK,
            [("content-type", "application/json; charset=utf-8")],
            serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".into()),
        )
            .into_response(),
        "csv" => (
            StatusCode::OK,
            [
                ("content-type", "text/csv; charset=utf-8".to_string()),
                ("content-disposition", format!("attachment; filename=\"forge-engagement-{id}.csv\"")),
            ],
            render_csv(&data),
        )
            .into_response(),
        "html" => {
            // `?preview=1` (aperçu intégré) : document SANS barre d'actions (le sélecteur de format
            // unique vit dans le panneau de la console). Sinon : HTML autonome (bouton Imprimer).
            let preview = q.get("preview").map(|v| v == "1" || v == "true").unwrap_or(false);
            ([("content-type", "text/html; charset=utf-8")], Html(render_html(&data, preview))).into_response()
        }
        "pdf" => {
            let html = render_html(&data, false);
            match render_pdf_from_html(&html).await {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        ("content-type", "application/pdf".to_string()),
                        ("content-disposition", format!("inline; filename=\"forge-engagement-{id}.pdf\"")),
                    ],
                    bytes,
                )
                    .into_response(),
                // BORNE franchie (saturation/budget/octets) : cause NOMMÉE, jamais « pas de moteur PDF ».
                Err(crate::PdfErr::Bound(e)) => delegated_render_error(
                    "pdf",
                    "réessayez, ou utilisez ?format=html puis « Imprimer » → « Enregistrer au format PDF »",
                    None,
                    &e,
                ),
                Err(crate::PdfErr::NoEngine) => (
                    StatusCode::NOT_IMPLEMENTED,
                    Json(json!({
                        "error": "pdf_unavailable",
                        "why": "aucun moteur PDF (wkhtmltopdf/weasyprint) détecté sur l'hôte",
                        "hint": "ouvrez ?format=html puis « Imprimer » → « Enregistrer au format PDF » (CSS @media print fourni), ou installez wkhtmltopdf/weasyprint"
                    })),
                )
                    .into_response(),
            }
        }
        "docx" => match render_docx_via_python(&app, &data).await {
            Ok(bytes) => (
                StatusCode::OK,
                [
                    ("content-type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_string()),
                    ("content-disposition", format!("attachment; filename=\"forge-engagement-{id}.docx\"")),
                ],
                bytes,
            )
                .into_response(),
            // `docx_unavailable` (501) est désormais RÉSERVÉ au cas où le générateur a réellement été
            // lancé et a échoué (ou n'a pas pu l'être) : la saturation rend 429, le budget 504, les
            // octets 502 — chacun avec la variable qui le règle.
            Err(e) => delegated_render_error(
                "docx",
                "réessayez, ou utilisez ?format=html/pdf/csv/json",
                // conseil d'INSTALLATION réservé au 501 « le générateur a réellement manqué » : une
                // saturation ou un budget dépassé ne doit pas envoyer l'exploitant vérifier son install.
                Some("si le générateur manque, installez python3 + le paquet forge"),
                &e,
            ),
        },
        _ => bad("format inconnu"), // inatteignable (validé plus haut)
    }
}

// =====================================================================================
//  TESTS — isolation, rédaction (html/csv/json), rôle (viewer+) + ledger, round-trip, dégradation.
// =====================================================================================

#[cfg(test)]
mod tests;

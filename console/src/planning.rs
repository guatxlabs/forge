// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SOUS-SYSTÈME PLANIFICATION / TECHNIQUES / WORKFLOWS / MODULES extrait de main.rs
//! (PURE MOVE). Regroupe : le catalogue de modules + son refresh gouverné (`modules`/`modules_refresh`,
//! GET /api/modules, POST /api/modules/refresh) ; le pré-vol de scope (`scope_check`, POST
//! /api/scope-check) ; la planification à blanc (`plan`, POST /api/plan) et son parseur de verdicts
//! (`parse_plan_verdicts`) ; le registre + la sélection de techniques ATT&CK (`techniques_catalog`,
//! `technique_selection_set` et leurs helpers) ; et le CRUD des workflows (`workflows_list`/
//! `workflow_create`/`workflow_edit` + validation/persistance). LECTURE/gouvernance : aucune campagne
//! armée ici — `plan` ne fait qu'un dry-run, `modules_refresh`/mutations sont gatés (opérateur/token).
//! Réutilise App + les helpers de la racine de crate (`check_operator`/`operator_denied`/`check_token`/
//! `populate_modules`/`validate_host`/`host_in_server_scope`/`resolve_*_engagement_id`/`append_console_ledger`
//! …) via `use crate::*`, et est re-exporté à la racine par `pub(crate) use crate::planning::*` — les
//! routes de build_router (`get(modules)`, `post(plan)`, `post(scope_check)`, `get(techniques_catalog)`,
//! `get(workflows_list).post(workflow_create)`, …) ET les tests inline de main.rs (`super::*`) résolvent
//! donc ces handlers/helpers INCHANGÉS. `modules_catalog`/`filter_enabled_modules`/`operator_disabled_modules`
//! restent consommés par `run_create` (main.rs) et `modules_refresh` (ici) via la ré-exportation racine.
use crate::*;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Catalogue des modules (lecture partagée par GET /api/modules et le read-back de refresh).
/// Expose la disponibilité SONDÉE (`available`), l'INTENTION opérateur (`enabled`,
/// `available_override`) ET la disponibilité EFFECTIVE dérivée (`effective_available`) pour piloter la
/// table de gouvernance de l'admin. Lecture pure (aucun effet de bord).
pub(crate) fn modules_catalog(db: &Connection) -> Vec<Value> {
    let mut stmt = match db.prepare(
        "SELECT kind,exploit,destructive,available,mitre,descr,web_allowed,enabled,available_override \
         FROM module ORDER BY kind",
    ) { Ok(s) => s, Err(_) => return vec![] };
    stmt.query_map([], |r| {
        let probed = r.get::<_, i64>(3)? != 0;
        let enabled = r.get::<_, i64>(7)? != 0;
        let override_bool: Option<bool> = r.get::<_, Option<i64>>(8)?.map(|v| v != 0);
        Ok(json!({
            "kind": r.get::<_, String>(0)?,
            "exploit": r.get::<_, i64>(1)? != 0,
            "destructive": r.get::<_, i64>(2)? != 0,
            "available": probed,                 // disponibilité SONDÉE (host)
            "mitre": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            "descr": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            "web_allowed": r.get::<_, i64>(6)? != 0,
            "enabled": enabled,                  // intention opérateur : connecteur (dés)installé
            "available_override": match override_bool { Some(b) => Value::Bool(b), None => Value::Null },
            "effective_available": module_effectively_available(enabled, override_bool, probed),
        }))
    })
    .map(|it| it.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Ensemble des kinds DÉSACTIVÉS par l'opérateur (module_operator_disabled) — injecté tel quel dans le
/// `scope.json` du run (`disabled_modules`) pour que le moteur les SKIP, y compris les modules choisis
/// par le PLANNER (au-delà de `--modules`). N'inclut PAS les modules simplement absents de l'hôte (le
/// moteur les SKIP déjà via sa propre sonde, avec la raison « outil absent »). Fail-closed lisible : sur
/// erreur DB -> liste vide (aucune désactivation fabriquée ; l'enforcement retombe sur le filtre argv).
pub(crate) fn operator_disabled_modules(app: &App) -> Vec<String> {
    let db = app.db();
    let mut stmt = match db.prepare("SELECT kind,enabled,available_override FROM module ORDER BY kind") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map([], |r| {
        let kind: String = r.get(0)?;
        let enabled = r.get::<_, i64>(1)? != 0;
        let ov: Option<bool> = r.get::<_, Option<i64>>(2)?.map(|v| v != 0);
        Ok((kind, module_operator_disabled(enabled, ov)))
    })
    .map(|it| it.filter_map(|x| x.ok()).filter(|(_, dis)| *dis).map(|(k, _)| k).collect())
    .unwrap_or_default()
}

/// Filtre une liste de kinds demandés vers le SOUS-ENSEMBLE non désactivé par l'opérateur. Défense en
/// profondeur au spawn : la liste `--modules` passée au moteur EXCLUT tout connecteur désactivé (même si
/// validate_modules l'a déjà refusé en amont, cette barrière garantit qu'un kind désactivé n'atteint
/// JAMAIS l'argv). Testable seul.
pub(crate) fn filter_enabled_modules(app: &App, requested: &[String]) -> Vec<String> {
    let disabled = operator_disabled_modules(app);
    requested.iter().filter(|m| !disabled.contains(m)).cloned().collect()
}

pub(crate) async fn modules(State(app): State<App>) -> impl IntoResponse {
    let db = app.db();
    Json(Value::Array(modules_catalog(&db)))
}

/// POST /api/scope-check {target} -> {target, in_scope, mode, allow_exploit, allow_destructive}.
/// LECTURE pure : réutilise host_in_server_scope (même règle que le pré-filtre de /api/run). Les
/// capacités exposées sont CELLES IMPOSÉES par la console au lancement web (exploit/destructif
/// toujours false depuis le web) — pas une bascule, juste de la transparence.
pub(crate) async fn scope_check(State(app): State<App>, Json(body): Json<Value>) -> impl IntoResponse {
    let target = body.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let validated = match validate_host(target) {
        Ok(h) => h,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_target", "why": e})));
        }
    };
    let in_scope = host_in_server_scope(&app, &validated);
    (StatusCode::OK, Json(json!({
        "target": validated,
        "in_scope": in_scope,
        "mode": app.scope_mode.as_str(),
        // ce que la console autorise depuis le web pour cette cible — INVARIANT (plancher exploit).
        "allow_exploit": false,
        "allow_destructive": false,
    })))
}

/// POST /api/plan {targets, modules?} -> dry-plan INERTE. Spawne `forge.cli campaign --mode propose`
/// (jamais armé : scope FORCÉ allow_exploit=false/allow_destructive=false, --modules borné aux kinds
/// web_allowed non-exploit), CAPTURE sa sortie et renvoie la liste action->verdict (VETO/DRY_RUN).
/// Aucune action ne tire — c'est un aperçu de gouvernance. Réutilise toutes les validations de
/// /api/run (campaign/host/modules/plancher exploit) SANS persister de run_job ni ouvrir le slot FIFO.
pub(crate) async fn plan(State(app): State<App>, Json(body): Json<Value>) -> impl IntoResponse {
    // (1) validation des cibles : host bien formé ET ⊆ scope serveur (fail-closed, comme /api/run).
    let targets_in = match body.get("targets").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_targets", "why": "targets[] requis (non vide)"}))),
    };
    let mut targets: Vec<String> = Vec::new();
    for t in &targets_in {
        let host = t.as_str().unwrap_or("");
        match validate_host(host) {
            Ok(h) => {
                if !host_in_server_scope(&app, &h) {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "out_of_scope", "why": format!("'{h}' hors du scope serveur autorisé")})));
                }
                targets.push(h);
            }
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_target", "why": e}))),
        }
    }
    // (2) modules : mêmes contraintes que /api/run (⊆ kinds connus, web_allowed, plancher exploit).
    // Le dry-plan est INERTE par construction (allow_high_impact=false) : le plancher exploit tient
    // toujours ici, l'opt-in haut-impact n'a pas de sens pour un aperçu qui ne tire rien.
    let requested_modules: Vec<String> = body
        .get("modules")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if let Err(e) = validate_modules(&app, &requested_modules, false) {
        return e.into_parts();
    }

    // (3) dir temp éphémère : scope.json (allow_* FORCÉS false) + targets.json. Nettoyé en fin.
    let stamp = format!("plan-{}-{}", chrono_now_compact(), gen_token().chars().take(8).collect::<String>());
    let plan_dir = std::env::temp_dir().join(format!("forge-run-{stamp}"));
    if let Err(e) = std::fs::create_dir_all(&plan_dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "mkdir_failed", "why": e.to_string()})));
    }
    let scope_doc = json!({
        "_comment": format!("dry-plan {stamp} — INERTE (exploit/destructif forcés false, mode propose)"),
        "mode": app.scope_mode.as_str(),
        "in_scope": targets,
        "out_scope": [],
        "rate": 5,
        "allow_exploit": false,
        "allow_destructive": false,
        "known_creds": [],
        "idor_targets": [],
        "notes": "dry-plan via console (gouverné) — rien ne tire"
    });
    let targets_doc: Vec<Value> = targets.iter().map(|h| json!({"host": h, "kind": "host"})).collect();
    let scope_path = plan_dir.join("scope.json");
    let targets_path = plan_dir.join("targets.json");
    if std::fs::write(&scope_path, serde_json::to_vec(&scope_doc).unwrap()).is_err()
        || std::fs::write(&targets_path, serde_json::to_vec(&Value::Array(targets_doc)).unwrap()).is_err()
    {
        let _ = std::fs::remove_dir_all(&plan_dir);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write_failed", "why": "écriture scope/targets impossible"})));
    }

    // (4) argv FIXE, --mode propose (NON armé). Pas de --ledger/--console : on ne persiste rien et on
    // ne POST aucun finding ; on capture juste la sortie pour en extraire les verdicts (transparence).
    let mut argv: Vec<String> = vec![
        "-m".into(), "forge.cli".into(), "campaign".into(),
        "--scope".into(), scope_path.to_string_lossy().into_owned(),
        "--targets".into(), targets_path.to_string_lossy().into_owned(),
        "--campaign".into(), "dry-plan".into(),
        "--mode".into(), "propose".into(),
        "--run-id".into(), stamp.clone(),
    ];
    if !requested_modules.is_empty() {
        argv.push("--modules".into());
        argv.push(requested_modules.join(","));
    }

    let output = std::process::Command::new(app.python.as_str())
        .args(&argv)
        .current_dir(app.pkg_dir.as_str())
        .stdin(std::process::Stdio::null())
        .output();
    let _ = std::fs::remove_dir_all(&plan_dir); // nettoyage best-effort quel que soit le résultat

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
            // extraction best-effort des verdicts de la sortie du moteur (propose -> DRY_RUN/VETO).
            let actions = parse_plan_verdicts(&stdout);
            (StatusCode::OK, Json(json!({
                "dry_run": true,
                "mode": "propose",
                "targets": targets,
                "modules": requested_modules,
                "actions": actions,
                "exit_ok": o.status.success(),
                "stdout": stdout,
                "stderr": stderr,
                "note": "dry-plan INERTE — aucune action n'a été tirée (exploit/destructif forcés false)"
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "spawn_failed", "why": e.to_string()}))),
    }
}

// =====================================================================================
// SÉLECTION DE TECHNIQUES PAR-SCOPE (profil + toggles catégorie/technique) — « au scope retirer des
// tests automatiques des techniques/outils ». La console persiste l'INTENTION (settings
// `technique_selection`) ; le MOTEUR l'ENFORCE (forge.techniques.resolve_enabled_kinds — SOURCE UNIQUE :
// profil ∪ activations − désactivations, DÉRIVÉ de la table, sans câblage par-technique). GET
// /api/techniques rend le catalogue GROUPÉ PAR CATÉGORIE avec l'état activé du scope ; POST
// /api/techniques/selection définit la sélection (opérateur/admin, ledgerisé).
// =====================================================================================

/// Sélection par défaut : profil bug_bounty (liste qualifiante) + aucun toggle. C'est le défaut
/// documenté quand `settings.technique_selection` est absent/illisible (jamais de valeur inventée
/// au-delà de ce défaut). Forme : {profile, categories:{cat:bool}, techniques:{kind:bool}}.
pub(crate) fn default_technique_selection() -> Value {
    json!({"profile": "bug_bounty", "categories": {}, "techniques": {}})
}

/// Clé `settings` de la sélection de techniques PAR ENGAGEMENT. Engagement #1 => clé LEGACY
/// `technique_selection` (rétro-compat : une base existante garde SA sélection au 1er boot post-MAJ) ;
/// autres engagements => clé suffixée `technique_selection:<id>`. Chaque engagement a donc SA sélection
/// de techniques/profil ISOLÉE (un toggle sur A n'affecte JAMAIS B). Fonction PURE.
pub(crate) fn technique_selection_key(eid: i64) -> String {
    if eid == 1 { "technique_selection".to_string() } else { format!("technique_selection:{eid}") }
}

/// Lit la sélection persistée de l'engagement `eid` (`settings[technique_selection_key(eid)]`).
/// Fail-soft : absente/illisible/non-objet -> défaut. Ne verrouille que le mutex DB.
pub(crate) fn technique_selection_value_for(app: &App, eid: i64) -> Value {
    let key = technique_selection_key(eid);
    let raw = { let db = app.db(); settings_get(&db, &key) };
    match raw.as_deref().map(serde_json::from_str::<Value>) {
        Some(Ok(v)) if v.is_object() => v,
        _ => default_technique_selection(),
    }
}

/// Rétro-compat : sélection de l'engagement #1 (clé legacy). Conservée pour les appelants qui n'ont
/// pas de contexte engagement (défaut mono-engagement) — dont les tests de round-trip de la clé legacy.
#[allow(dead_code)]
pub(crate) fn technique_selection_value(app: &App) -> Value {
    technique_selection_value_for(app, 1)
}

/// Valide/normalise une sélection POSTée : {profile?, categories?:{str:bool}, techniques?:{str:bool}}.
/// `profile` ∈ {bug_bounty,pentest,custom} (défaut bug_bounty). Les clés de toggle sont des noms bien
/// formés (grammaire [A-Za-z0-9._-], 1..64), les valeurs des booléens, la map bornée (≤256). Les clés
/// INCONNUES du registre sont TOLÉRÉES : le résolveur moteur les ignore (catégorie inconnue -> vide,
/// technique inconnue -> filtrée par ∩ technique_kinds) — jamais une capacité fabriquée. Fonction PURE.
pub(crate) fn validate_technique_selection(body: &Value) -> Result<Value, String> {
    if !body.is_object() {
        return Err("corps attendu : objet {profile?, categories?, techniques?}".into());
    }
    let profile = match body.get("profile") {
        None | Some(Value::Null) => "bug_bounty".to_string(),
        Some(Value::String(s)) => {
            if !matches!(s.as_str(), "bug_bounty" | "pentest" | "custom") {
                return Err(format!("profile '{s}' invalide (bug_bounty|pentest|custom)"));
            }
            s.clone()
        }
        Some(_) => return Err("profile doit être une chaîne".into()),
    };
    fn toggles(body: &Value, key: &str) -> Result<Value, String> {
        match body.get(key) {
            None | Some(Value::Null) => Ok(Value::Object(serde_json::Map::new())),
            Some(Value::Object(m)) => {
                if m.len() > 256 {
                    return Err(format!("{key} trop volumineux (>256 clés)"));
                }
                let mut o = serde_json::Map::new();
                for (k, v) in m {
                    if k.is_empty() || k.len() > 64
                        || !k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                    {
                        return Err(format!("{key} : clé '{k}' mal formée ([A-Za-z0-9._-], 1..64)"));
                    }
                    match v {
                        Value::Bool(b) => { o.insert(k.clone(), Value::Bool(*b)); }
                        _ => return Err(format!("{key} : la valeur de '{k}' doit être un booléen")),
                    }
                }
                Ok(Value::Object(o))
            }
            Some(_) => Err(format!("{key} doit être un objet {{clé: bool}}")),
        }
    }
    let mut out = serde_json::Map::new();
    out.insert("profile".into(), Value::String(profile));
    out.insert("categories".into(), toggles(body, "categories")?);
    out.insert("techniques".into(), toggles(body, "techniques")?);
    Ok(Value::Object(out))
}

/// Spawne `forge.cli techniques --json`, sélection injectée par env `FORGE_TECHNIQUE_SELECTION` (jamais
/// en argv — cohérent avec le passthrough sûr du reste). DÉRIVÉ du registre côté moteur (SOURCE UNIQUE :
/// groupement par catégorie + `enabled_for_current_scope` via resolve_enabled_kinds). Renvoie le
/// catalogue JSON parsé, ou une erreur lisible (moteur indisponible / JSON illisible).
pub(crate) fn spawn_techniques_catalog(app: &App, selection: &Value) -> Result<Value, String> {
    let out = std::process::Command::new(app.python.as_str())
        .args(["-m", "forge.cli", "techniques", "--json"])
        .current_dir(app.pkg_dir.as_str())
        .env("FORGE_TECHNIQUE_SELECTION", selection.to_string())
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn échoué: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "moteur techniques rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).chars().take(200).collect::<String>()
        ));
    }
    serde_json::from_slice::<Value>(&out.stdout).map_err(|e| format!("JSON illisible: {e}"))
}

/// GET /api/techniques — LE catalogue des techniques GROUPÉ PAR CATÉGORIE (vuln_class), reflétant l'état
/// ACTIVÉ pour la sélection par-scope PERSISTÉE (profil + toggles). Chaque entrée porte `kind`, `tools`,
/// `bug_bounty_eligible`, `pentest_only`, `enabled_for_current_scope`. Lecture (viewer) — la sélection
/// est visible de tous ; seule sa MUTATION est gouvernée (POST /api/techniques/selection). DÉRIVÉ du
/// registre côté moteur : un nouveau module @register apparaît AUTOMATIQUEMENT sous sa catégorie.
pub(crate) async fn techniques_catalog(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    // ENGAGEMENT : catalogue résolu contre la sélection/profil de l'engagement actif (par-engagement).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let sel = technique_selection_value_for(&app, eid);
    match spawn_techniques_catalog(&app, &sel) {
        Ok(mut v) => {
            if let Some(o) = v.as_object_mut() { o.insert("engagement_id".into(), json!(eid)); }
            (StatusCode::OK, Json(v)).into_response()
        }
        // fail-soft LISIBLE : le SPA affiche encore le sélecteur de profil même si le moteur est absent.
        Err(e) => (StatusCode::OK, Json(json!({
            "error": "techniques_unavailable", "why": e,
            "engagement_id": eid,
            "profile": sel.get("profile").cloned().unwrap_or(json!("bug_bounty")),
            "profiles": ["bug_bounty", "pentest", "custom"],
            "selection": sel, "enabled": [], "groups": {},
        }))).into_response(),
    }
}

/// POST /api/techniques/selection — définit la SÉLECTION de techniques par-scope (profil + toggles
/// catégorie/technique). OPÉRATEUR/ADMIN (check_operator, FAIL-CLOSED 403 sinon) + LEDGERISÉ
/// (`console.techniques.selection.set`, attribué à l'acteur individuel). Persiste
/// `settings.technique_selection` — l'intention est ensuite ENFORCÉE par le moteur à chaque run
/// (scope.json profile/techniques_enabled/categories_enabled -> resolve_enabled_kinds) : une technique
/// retirée n'est NI planifiée NI tirée (fail-closed), en plus du scope-guard.
pub(crate) async fn technique_selection_set(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    // ENGAGEMENT : la sélection est PAR-ENGAGEMENT (chaque engagement a SON profil/toggles). L'engagement
    // cible vient de `?engagement=` (ou body.engagement_id), défaut = engagement actif. Un id EXPLICITE
    // doit exister (fail-closed : on n'écrit jamais une sélection pour un engagement fantôme).
    let eid = match resolve_mutation_engagement_id(&app, &headers, &q, &body) {
        Ok(e) => e,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_engagement", "why": why}))).into_response(),
    };
    let sel = match validate_technique_selection(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_selection", "why": e}))).into_response(),
    };
    {
        let db = app.db();
        if let Err(e) = settings_set(&db, &technique_selection_key(eid), &sel.to_string()) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "persist_failed", "why": e}))).into_response();
        }
    }
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.techniques.selection.set", json!({
        "actor": actor, "by": "operator", "engagement_id": eid, "selection": sel,
    }));
    (StatusCode::OK, Json(json!({"ok": true, "engagement_id": eid, "selection": sel}))).into_response()
}

// =====================================================================================
// WORKFLOWS ÉDITABLES & SAUVEGARDÉS — pipelines COMPOSÉS par l'opérateur, SANS code (absorbe les
// scan-engines de reNgine / workflows d'Osmedeus / pipelines visuels de Trickest). Un workflow est
// une SÉLECTION ORDONNÉE de techniques/outils (+ params par-étape) puisée dans le registre. Persisté
// dans la table `settings` (clé `workflows`) comme JSON {name: workflow}, éditable admin/operator,
// ledgerisé au save. GOUVERNANCE fail-closed : un workflow est une PROPOSITION — le scope-guard ROE
// + la sélection par-scope restent seuls JUGES (l'engine ré-filtre par l'ensemble activé au tir).
// Les workflows INTÉGRÉS (builtins) sont DÉRIVÉS du registre côté moteur (`forge workflows --json`) :
// non supprimables. Le lancement passe par le C2 gouverné (POST /api/run avec modules=étapes).
// =====================================================================================

/// Noms des workflows INTÉGRÉS — RÉSERVÉS (non supprimables, non écrasables par un workflow utilisateur).
/// Doit rester en phase avec `forge/workflows.py::BUILTIN_NAMES` (source de vérité côté moteur ; ce
/// miroir sert uniquement à refuser localement une CRUD sur un nom réservé — fail-closed sans spawn).
pub(crate) const WORKFLOW_BUILTIN_NAMES: &[&str] = &["recon-surface", "bug-bounty-web", "full-pentest"];

pub(crate) fn workflow_name_is_builtin(name: &str) -> bool {
    WORKFLOW_BUILTIN_NAMES.contains(&name)
}

/// Valide/normalise un workflow POSTé : {name?, description?, steps:[{kind, params?}]}. `name_override`
/// (segment d'URL) prime sur `body["name"]`. Grammaire stricte du nom/kind, steps ≤ 128, params objet.
/// Les kinds INCONNUS du registre sont TOLÉRÉS (le résolveur moteur/engine les LARGUE via ∩ enabled —
/// jamais une capacité fabriquée), exactement comme validate_technique_selection tolère une clé inconnue.
/// Retourne le workflow canonique {name, description, builtin:false, steps:[{kind, params}]}. PURE.
pub(crate) fn validate_workflow_body(body: &Value, name_override: Option<&str>) -> Result<Value, String> {
    if !body.is_object() {
        return Err("corps attendu : objet {name?, description?, steps:[{kind, params?}]}".into());
    }
    let name = match name_override {
        Some(n) => n.to_string(),
        None => body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    };
    if !valid_workflow_token(&name) {
        return Err("nom de workflow invalide ([A-Za-z0-9._-], 1..64, pas de '-' en tête)".into());
    }
    let description = match body.get("description") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.chars().take(500).collect::<String>(),
        Some(_) => return Err("description doit être une chaîne".into()),
    };
    let raw_steps = match body.get("steps") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("steps doit être une liste [{kind, params?}]".into()),
    };
    if raw_steps.len() > 128 {
        return Err("trop d'étapes (> 128)".into());
    }
    let mut steps = Vec::new();
    for (i, st) in raw_steps.iter().enumerate() {
        let obj = st.as_object().ok_or_else(|| format!("steps[{i}] : objet {{kind, params?}} attendu"))?;
        let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if !valid_workflow_token(kind) {
            return Err(format!("steps[{i}] : kind '{kind}' mal formé ([A-Za-z0-9._-], 1..64)"));
        }
        let params = match obj.get("params") {
            None | Some(Value::Null) => Value::Object(serde_json::Map::new()),
            Some(Value::Object(m)) => Value::Object(m.clone()),
            Some(_) => return Err(format!("steps[{i}] : params doit être un objet {{clé: valeur}}")),
        };
        steps.push(json!({"kind": kind, "params": params}));
    }
    Ok(json!({"name": name, "description": description, "builtin": false, "steps": steps}))
}

/// Clé `settings` des workflows UTILISATEUR PAR ENGAGEMENT. Engagement #1 => clé LEGACY `workflows`
/// (rétro-compat) ; autres => `workflows:<id>`. Chaque engagement a donc SES propres workflows. PURE.
pub(crate) fn workflows_key(eid: i64) -> String {
    if eid == 1 { "workflows".to_string() } else { format!("workflows:{eid}") }
}

/// Lit la map des workflows UTILISATEUR de l'engagement `eid` (`settings[workflows_key(eid)]`).
/// Fail-soft : absente/illisible/non-objet -> map vide (jamais de valeur inventée). Verrouille le mutex DB.
pub(crate) fn workflows_user_map_for(app: &App, eid: i64) -> serde_json::Map<String, Value> {
    let key = workflows_key(eid);
    let raw = { let db = app.db(); settings_get(&db, &key) };
    match raw.as_deref().map(serde_json::from_str::<Value>) {
        Some(Ok(Value::Object(m))) => m,
        _ => serde_json::Map::new(),
    }
}

/// Rétro-compat : workflows de l'engagement #1 (clé legacy). Pour les appelants sans contexte engagement.
#[allow(dead_code)]
pub(crate) fn workflows_user_map(app: &App) -> serde_json::Map<String, Value> {
    workflows_user_map_for(app, 1)
}

/// Spawne `forge workflows --json` -> workflows INTÉGRÉS (DÉRIVÉS du registre côté moteur : SOURCE
/// UNIQUE, toujours à jour). Renvoie le tableau `builtins` parsé, ou une erreur lisible (moteur absent /
/// JSON illisible). Env passthrough sûr ; aucun argv sensible.
pub(crate) fn spawn_workflows_builtins(app: &App) -> Result<Vec<Value>, String> {
    let out = std::process::Command::new(app.python.as_str())
        .args(["-m", "forge.cli", "workflows", "--json"])
        .current_dir(app.pkg_dir.as_str())
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn échoué: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "moteur workflows rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).chars().take(200).collect::<String>()
        ));
    }
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("JSON illisible: {e}"))?;
    Ok(v.get("builtins").and_then(|b| b.as_array()).cloned().unwrap_or_default())
}

/// Enrichit un workflow (user ou builtin) avec `step_kinds` (ordre + dédup) + `step_count` — la forme
/// LUE par le SPA (le builder). PURE (aucune I/O). Les params par-étape sont conservés tels quels.
pub(crate) fn workflow_view(wf: &Value) -> Value {
    let mut kinds: Vec<String> = Vec::new();
    if let Some(steps) = wf.get("steps").and_then(|s| s.as_array()) {
        for st in steps {
            if let Some(k) = st.get("kind").and_then(|v| v.as_str()) {
                if !kinds.iter().any(|x| x == k) {
                    kinds.push(k.to_string());
                }
            }
        }
    }
    json!({
        "name": wf.get("name").cloned().unwrap_or(json!("")),
        "description": wf.get("description").cloned().unwrap_or(json!("")),
        "builtin": wf.get("builtin").and_then(|v| v.as_bool()).unwrap_or(false),
        "steps": wf.get("steps").cloned().unwrap_or(json!([])),
        "step_kinds": kinds,
        "step_count": wf.get("steps").and_then(|s| s.as_array()).map(|a| a.len()).unwrap_or(0),
    })
}

/// GET /api/workflows — LISTE les workflows : UTILISATEUR (persistés `settings.workflows`) + INTÉGRÉS
/// (dérivés du registre via le moteur). Lecture (viewer) — la composition est visible de tous ; seule
/// la MUTATION est gouvernée (POST). Fail-soft : si le moteur est absent, `builtins:[]` + note d'erreur
/// (le SPA affiche encore les workflows utilisateur et le builder). Le SPA croise chaque étape avec
/// `GET /api/techniques` (enabled_for_current_scope) pour montrer ce qui est activé/autorisé au scope.
pub(crate) async fn workflows_list(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    // ENGAGEMENT : les workflows UTILISATEUR sont PAR-ENGAGEMENT (chaque engagement a SA bibliothèque).
    // Les builtins (dérivés du registre moteur) sont communs. `?engagement=` -> défaut = engagement actif.
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    let user_map = workflows_user_map_for(&app, eid);
    let mut user: Vec<Value> = Vec::new();
    let mut names: Vec<&String> = user_map.keys().collect();
    names.sort();
    for n in names {
        if let Some(wf) = user_map.get(n) {
            user.push(workflow_view(wf));
        }
    }
    match spawn_workflows_builtins(&app) {
        Ok(builtins) => {
            let bl: Vec<Value> = builtins.iter().map(workflow_view).collect();
            (StatusCode::OK, Json(json!({"engagement_id": eid, "workflows": user, "builtins": bl}))).into_response()
        }
        Err(e) => (StatusCode::OK, Json(json!({
            "engagement_id": eid, "workflows": user, "builtins": [],
            "error": "builtins_unavailable", "why": e,
        }))).into_response(),
    }
}

/// Persiste la map des workflows utilisateur + ledgerise la mutation (attribuée à l'acteur). Facteur
/// commun de create/edit/delete. Retourne une Response 500 lisible si l'écriture settings échoue.
pub(crate) fn workflows_persist(app: &App, eid: i64, map: &serde_json::Map<String, Value>, action: &str, name: &str,
                     actor: &str, detail: Value) -> Result<(), Box<Response>> {
    {
        let db = app.db();
        if let Err(e) = settings_set(&db, &workflows_key(eid), &Value::Object(map.clone()).to_string()) {
            return Err(Box::new((StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "persist_failed", "why": e}))).into_response()));
        }
    }
    append_console_ledger(app, &format!("console.workflows.{action}"), json!({
        "actor": actor, "by": "operator", "engagement_id": eid, "name": name, "detail": detail,
    }));
    Ok(())
}

/// POST /api/workflows {name, description?, steps:[{kind, params?}]} — CRÉE/REMPLACE un workflow
/// UTILISATEUR. OPÉRATEUR/ADMIN (check_operator, FAIL-CLOSED 403 sinon) + LEDGERISÉ. Refuse un nom
/// INTÉGRÉ réservé (409). Le workflow est une PROPOSITION : aucune capacité n'est accordée ici — le
/// scope-guard + la sélection par-scope gouvernent l'exécution (POST /api/run avec modules=étapes).
pub(crate) async fn workflow_create(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    // ENGAGEMENT cible (par-engagement) : `?engagement=` (ou body.engagement_id), défaut = actif.
    let eid = match resolve_mutation_engagement_id(&app, &headers, &q, &body) {
        Ok(e) => e,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_engagement", "why": why}))).into_response(),
    };
    let wf = match validate_workflow_body(&body, None) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_workflow", "why": e}))).into_response(),
    };
    let name = wf["name"].as_str().unwrap_or("").to_string();
    if workflow_name_is_builtin(&name) {
        return (StatusCode::CONFLICT,
                Json(json!({"error": "reserved_name", "why": format!("nom réservé (workflow intégré non modifiable) : {name}")}))).into_response();
    }
    let mut map = workflows_user_map_for(&app, eid);
    map.insert(name.clone(), wf.clone());
    let actor = attribution_login(&app, &headers);
    if let Err(resp) = workflows_persist(&app, eid, &map, "save", &name, &actor,
                                         json!({"step_count": wf["steps"].as_array().map(|a| a.len()).unwrap_or(0)})) {
        return *resp;
    }
    (StatusCode::OK, Json(json!({"ok": true, "engagement_id": eid, "workflow": workflow_view(&wf)}))).into_response()
}

/// POST /api/workflows/:name — ÉDITE (upsert) ou SUPPRIME (`{"delete": true}`) un workflow UTILISATEUR.
/// OPÉRATEUR/ADMIN (check_operator, FAIL-CLOSED 403) + LEDGERISÉ. Bloque la SUPPRESSION d'un builtin
/// (409). Le `name` provient de l'URL (prime sur le corps). Édition = validate + remplace ; suppression
/// = retire de la map (404 si inconnu et non-builtin).
pub(crate) async fn workflow_edit(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    if !valid_workflow_token(&name) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_name", "why": "nom de workflow mal formé"}))).into_response();
    }
    // ENGAGEMENT cible (par-engagement) : `?engagement=` (ou body.engagement_id), défaut = actif.
    let eid = match resolve_mutation_engagement_id(&app, &headers, &q, &body) {
        Ok(e) => e,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_engagement", "why": why}))).into_response(),
    };
    let actor = attribution_login(&app, &headers);
    let is_delete = body.get("delete").and_then(|v| v.as_bool()).unwrap_or(false);
    if is_delete {
        // FAIL-CLOSED : un workflow INTÉGRÉ ne peut JAMAIS être supprimé (409).
        if workflow_name_is_builtin(&name) {
            return (StatusCode::CONFLICT,
                    Json(json!({"error": "builtin_protected", "why": format!("workflow intégré non supprimable : {name}")}))).into_response();
        }
        let mut map = workflows_user_map_for(&app, eid);
        if map.remove(&name).is_none() {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not_found", "why": format!("workflow inconnu : {name}")}))).into_response();
        }
        if let Err(resp) = workflows_persist(&app, eid, &map, "delete", &name, &actor, json!({})) {
            return *resp;
        }
        return (StatusCode::OK, Json(json!({"ok": true, "engagement_id": eid, "deleted": name}))).into_response();
    }
    // ÉDITION : refuse d'écraser un nom RÉSERVÉ (builtin).
    if workflow_name_is_builtin(&name) {
        return (StatusCode::CONFLICT,
                Json(json!({"error": "reserved_name", "why": format!("nom réservé (workflow intégré non modifiable) : {name}")}))).into_response();
    }
    let wf = match validate_workflow_body(&body, Some(&name)) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_workflow", "why": e}))).into_response(),
    };
    let mut map = workflows_user_map_for(&app, eid);
    map.insert(name.clone(), wf.clone());
    if let Err(resp) = workflows_persist(&app, eid, &map, "save", &name, &actor,
                                         json!({"step_count": wf["steps"].as_array().map(|a| a.len()).unwrap_or(0)})) {
        return *resp;
    }
    (StatusCode::OK, Json(json!({"ok": true, "engagement_id": eid, "workflow": workflow_view(&wf)}))).into_response()
}

/// Extrait les couples action->verdict de la sortie texte du moteur en mode propose. Sortie :
/// [{kind, target, verdict, line}], une entrée PAR ACTION réelle (pas par compteur de synthèse).
///
/// Le rapport (`report.py`) liste chaque action sous un en-tête de section (`**Simulées …**`,
/// `**Refusées (VETO)**`, `**Erreurs / skips**`, `**Déférées (budget)**`) avec des lignes
/// `- `kind` → `target` : raisons` qui ne portent PAS le mot-clé du verdict — celui-ci vient de la
/// section. On lève donc le verdict du CONTEXTE de section, et on ignore les lignes de SYNTHÈSE en
/// gras (`- **Tirées (FIRE)** : 0`) qui contiennent un mot-clé mais ne sont pas des actions (sinon
/// elles polluaient le plan de faux verdicts). On tolère aussi le format inline `[VERDICT] kind →
/// target` (CLI `forge plan`) : si la ligne porte un mot-clé de verdict hors d'un en-tête en gras,
/// il prime. Backticks et puce de liste retirés des cellules.
pub(crate) fn parse_plan_verdicts(stdout: &str) -> Vec<Value> {
    const VERDICTS: &[&str] = &["VETO", "DRY_RUN", "FIRE", "SKIP"];
    // En-tête de section -> verdict des lignes d'action qui suivent (jusqu'au prochain en-tête).
    fn section_verdict(line: &str) -> Option<&'static str> {
        if !line.starts_with("**") {
            return None;
        }
        if line.contains("VETO") {
            Some("VETO")
        } else if line.contains("Simulées") || line.contains("DRY_RUN") {
            Some("DRY_RUN")
        } else if line.contains("Erreurs") || line.contains("skips") || line.contains("Déférées") {
            Some("SKIP")
        } else {
            None
        }
    }
    // Découpe `kind → target` (ou `->`) en cellules nettoyées (backticks/espaces retirés).
    fn split_kind_target(line: &str) -> Option<(String, String)> {
        let unquote = |s: &str| s.trim().trim_matches('`').trim().to_string();
        line.split_once('→')
            .or_else(|| line.split_once("->"))
            .map(|(k, t)| {
                // kind = dernier jeton avant la flèche (après la puce/`[verdict]`), target = 1er après.
                let kind = unquote(k.split_whitespace().last().unwrap_or(""));
                // la cellule target peut être suivie de ` : raisons` -> on coupe au `:` hors-backtick.
                let t = t.split(" : ").next().unwrap_or(t);
                let target = unquote(t.split_whitespace().next().unwrap_or(""));
                (kind, target)
            })
    }

    let mut out = Vec::new();
    let mut section: Option<&'static str> = None;
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // 1) en-tête de section en gras -> (re)bascule le contexte : verdict connu, ou None pour
        //    une section neutre (`**Classes jamais tentées**`, `**Déférées (budget)**`…) afin que
        //    ses lignes ne héritent pas du verdict de la section précédente. Ne produit aucune action.
        if line.starts_with("**") {
            section = section_verdict(line);
            continue;
        }
        // 2) ligne de SYNTHÈSE en gras (`- **Tirées (FIRE)** : 0`) -> jamais une action.
        if line.trim_start_matches("- ").starts_with("**") {
            continue;
        }
        // 3) verdict inline explicite (CLI `forge plan` : `[DRY_RUN] kind → target`) -> prioritaire.
        let inline = VERDICTS.iter().find(|v| line.contains(*v)).copied();
        // 4) sinon, on retient la ligne SEULEMENT si elle décrit une action (`kind → target`) sous
        //    une section connue : c'est le format réel du rapport (lignes sans mot-clé de verdict).
        let verdict = match (inline, section) {
            (Some(v), _) => v,
            (None, Some(v)) if line.starts_with("- ") && (line.contains('→') || line.contains("->")) => v,
            _ => continue,
        };
        let (kind, target) = split_kind_target(line).unwrap_or_default();
        out.push(json!({
            "kind": kind,
            "target": target,
            "verdict": verdict,
            "line": line,
        }));
    }
    out
}

/// POST /api/modules/refresh — re-spawne `forge.cli modules --json` et re-seed la table `module`
/// (registre vivant). LECTURE/gouvernance : ne lance aucune campagne, n'arme rien — il rafraîchit
/// seulement le catalogue de capacités. Gaté par le rôle opérateur (fail-closed) car il modifie une
/// table d'état serveur. Renvoie le catalogue rafraîchi (même forme que GET /api/modules).
pub(crate) async fn modules_refresh(State(app): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> impl IntoResponse {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j);
    }
    {
        let db = app.db();
        populate_modules(&db); // re-spawn `forge.cli modules --json` + UPSERT dans `module`
    }
    // relit le catalogue pour le renvoyer (transparence : l'opérateur voit l'état post-refresh —
    // l'intention `enabled`/`available_override` est PRÉSERVÉE par le re-probe, cf. populate_modules).
    let db = app.db();
    let mods = modules_catalog(&db);
    (StatusCode::OK, Json(json!({"refreshed": mods.len(), "modules": mods})))
}

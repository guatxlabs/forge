// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — VALIDATION / GATING DES PARAMS DE MODULE du run-lifecycle (PURE MOVE extrait de
//! `runs.rs`). Fonctions PURES, sans état partagé : `validate_module_params` (forme {kind:{params}}),
//! `validate_modules` (⊆ kinds connus, web_allowed, PLANCHER EXPLOIT + opt-in haut-impact gouverné),
//! `high_impact_modules` (audit des capacités débloquées) et `high_impact_gate` (gate pur operator+arm+
//! reason).
//!
//! Réutilise App + les helpers de la racine (`validate_campaign`/`validate_param_value`/
//! `module_operator_disabled`) via `use crate::*` ; re-exporté `pub(crate)` à la racine — appelants
//! (`run_create`) ET tests inline de main.rs (`super::*`) INCHANGÉS.
use crate::error;
use crate::*;

use serde_json::Value;

/// Valide les params PAR-MODULE du corps /api/run. Forme attendue :
///   "module_params": { "<kind>": { ... }, ... }
/// Règles : chaque clé doit être un `kind` bien formé ([A-Za-z0-9._-], 1..64) ; si une allow-list de
/// modules est fournie (modules non vide), la clé DOIT y appartenir (on ne transporte pas de params
/// pour un module qui ne sera pas lancé) ; chaque valeur est un objet, validé récursivement (taille,
/// profondeur, NUL). Renvoie la map normalisée (kind -> objet params) ou 400. Absent/vide => map vide.
pub(crate) fn validate_module_params(
    body: &Value,
    modules: &[String],
) -> Result<serde_json::Map<String, Value>, error::ApiError> {
    let mut out = serde_json::Map::new();
    let raw = match body.get("module_params") {
        None | Some(Value::Null) => return Ok(out),
        Some(Value::Object(m)) => m,
        Some(_) => {
            return Err(error::ApiError::bad("bad_module_params", "module_params doit être un objet {kind: {params}}"));
        }
    };
    if raw.len() > 128 {
        return Err(error::ApiError::bad("bad_module_params", "trop de modules dans module_params (>128)"));
    }
    for (kind, params) in raw {
        // clé = kind bien formé (même grammaire que validate_campaign : pas de métacaractère/-en-tête).
        if let Err(e) = validate_campaign(kind) {
            return Err(error::ApiError::bad("bad_module_params", format!("clé module '{kind}' invalide: {e}")));
        }
        // si une allow-list explicite est fournie, on n'accepte de params QUE pour ces modules.
        if !modules.is_empty() && !modules.iter().any(|m| m == kind) {
            return Err(error::ApiError::bad("param_for_unrequested_module", format!("params fournis pour '{kind}' qui n'est pas dans modules[]")));
        }
        if !params.is_object() {
            return Err(error::ApiError::bad("bad_module_params", format!("params de '{kind}' doivent être un objet")));
        }
        if let Err(e) = validate_param_value(params, 0) {
            return Err(error::ApiError::bad("bad_module_params", format!("params de '{kind}': {e}")));
        }
        out.insert(kind.clone(), params.clone());
    }
    Ok(out)
}

/// DÉFENSE EN PROFONDEUR (echo de l'allowlist Python) : valide les `extra_args` par-module d'un
/// /api/run contre l'ALLOWLIST DE DRAPEAUX du module (colonne `module.flag_allowlist`, sondée depuis le
/// registre Python). Un /api/run CRAFTÉ (contournant l'UI) ne peut donc PAS injecter un drapeau interdit
/// même si le moteur Python le re-refuserait de toute façon (fail-closed à deux couches). Règles :
///   - `extra_args` absent -> ignoré (no-op, byte-identique au défaut) ;
///   - `extra_args` PAS une liste -> 400 (doit être une liste de tokens déjà séparés) ;
///   - un token non-string -> 400 ;
///   - un token RESSEMBLANT à un drapeau (`-x`/`--x`) HORS de l'allowlist du module -> 400.
/// Un module inconnu / sans allowlist => allowlist vide => tout drapeau libre est refusé (fail-closed).
pub(crate) fn validate_extra_args(app: &App, module_params: &serde_json::Map<String, Value>) -> Result<(), error::ApiError> {
    for (kind, params) in module_params {
        let extra = match params.get("extra_args") {
            None | Some(Value::Null) => continue,
            Some(v) => v,
        };
        let arr = match extra.as_array() {
            Some(a) => a,
            None => return Err(error::ApiError::bad("bad_extra_args", format!("extra_args de '{kind}' doit être une liste de tokens déjà séparés"))),
        };
        // allowlist du module (JSON stocké) ; absente/illisible => vide (fail-closed : tout flag refusé).
        let allow: Vec<String> = app.store().query_row(
            "SELECT flag_allowlist FROM module WHERE kind=?",
            &crate::sql_params![kind.as_str()],
            |r| r.get_str(0),
        ).ok().and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok()).unwrap_or_default();
        let allowset: std::collections::HashSet<&str> = allow.iter().map(|s| s.as_str()).collect();
        for t in arr {
            let s = match t.as_str() {
                Some(s) => s,
                None => return Err(error::ApiError::bad("bad_extra_args", format!("token extra_args de '{kind}' doit être une chaîne"))),
            };
            if s.starts_with('-') && !allowset.contains(s) {
                return Err(error::ApiError::bad("extra_arg_not_allowlisted", format!("drapeau '{s}' hors allowlist du module '{kind}' — refusé fail-closed")));
            }
        }
    }
    Ok(())
}

/// Vérifie qu'un module demandé existe (kinds connus), est web_allowed=1, et N'EST NI exploit NI
/// destructive (PLANCHER EXPLOIT). 400 sinon. Liste vide => OK (le planner choisira tout seul, et le
/// scope force allow_*=false de toute façon).
///
/// `allow_high_impact` : quand l'opt-in haut-impact gouverné est HONORÉ (operator + arm + reason —
/// cf. `high_impact_gate`), le PLANCHER EXPLOIT est levé : les modules exploit/destructive sont
/// acceptés (et la dérivée `web_allowed=0` qui n'existe QUE parce que exploit/destructif/idor est
/// elle aussi tolérée). Le contrôle `unknown_module` reste TOUJOURS appliqué — on n'accepte jamais
/// un kind inconnu du registre, même armé. `false` (défaut) => comportement actuel inchangé.
pub(crate) fn validate_modules(app: &App, modules: &[String], allow_high_impact: bool) -> Result<(), error::ApiError> {
    if modules.is_empty() {
        return Ok(());
    }
    
    for m in modules {
        let row = app.store().query_row(
            "SELECT exploit,destructive,web_allowed,enabled,available_override FROM module WHERE kind=?",
            &crate::sql_params![m],
            |r| Ok((
                r.get_i64(0)?, r.get_i64(1)?, r.get_i64(2)?,
                r.get_i64(3)? != 0, r.get_opt_i64(4)?.map(|v| v != 0),
            )),
        );
        match row {
            Ok((exploit, destructive, web_allowed, enabled, available_override)) => {
                // GOUVERNANCE CONNECTEUR (fail-closed) : un module DÉSACTIVÉ par l'opérateur (enabled=0
                // ou available_override=0) n'est JAMAIS lançable depuis le web — MÊME sous opt-in
                // haut-impact. Désactiver un connecteur = le désinstaller opérationnellement, un cran
                // AU-DESSUS du plancher exploit : vérifié AVANT le bypass high-impact. (Un binaire
                // simplement absent, sans intention opérateur, reste accepté puis SKIP par le moteur.)
                if module_operator_disabled(enabled, available_override) {
                    return Err(error::ApiError::bad("module_disabled", format!("module '{m}' désactivé (gouvernance connecteur) — non lançable, même armé")));
                }
                // Opt-in haut-impact honoré : on NE rejette PAS exploit/destructif. Le scope-guard du
                // moteur reste seul juge des cibles (hors-scope = VETO), l'écriture allow_* ne touche
                // que la capacité, jamais le périmètre.
                if allow_high_impact {
                    continue;
                }
                if exploit != 0 || destructive != 0 {
                    return Err(error::ApiError::bad("exploit_floor", format!("module '{m}' est exploit/destructif — interdit depuis le web (sans opt-in haut-impact gouverné)")));
                }
                if web_allowed == 0 {
                    return Err(error::ApiError::bad("not_web_allowed", format!("module '{m}' n'est pas lançable depuis le web (web_allowed=0)")));
                }
            }
            Err(_) => {
                return Err(error::ApiError::bad("unknown_module", format!("module '{m}' inconnu du registre")));
            }
        }
    }
    Ok(())
}

/// Liste, parmi `modules`, ceux marqués exploit OU destructive dans le registre — c.-à-d. les
/// modules HAUT-IMPACT effectivement autorisés par un opt-in honoré. Sert UNIQUEMENT à l'audit
/// (ledger + run_job) : tracer précisément quelles capacités haut-impact ont été débloquées pour ce
/// run. N'altère aucun garde-fou. Liste vide => le planner choisit seul (rien d'explicitement listé).
pub(crate) fn high_impact_modules(app: &App, modules: &[String]) -> Vec<String> {
    let store = app.store();
    modules
        .iter()
        .filter(|m| {
            store.query_row(
                "SELECT exploit,destructive,enabled,available_override FROM module WHERE kind=?",
                &crate::sql_params![m.as_str()],
                |r| Ok((
                    r.get_i64(0)?, r.get_i64(1)?,
                    r.get_i64(2)? != 0, r.get_opt_i64(3)?.map(|v| v != 0),
                )),
            )
            // haut-impact ET effectivement activable : un connecteur exploit/destructif DÉSACTIVÉ par
            // l'opérateur ne sera pas tiré -> il ne doit pas figurer parmi les capacités « débloquées »
            // dans l'audit (ledger/run_job). Consulte `enabled`/`available_override`.
            .map(|(e, d, en, ov)| (e != 0 || d != 0) && !module_operator_disabled(en, ov))
            .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// GATE de gouvernance haut-impact — fonction PURE (testable, aucun effet de bord).
///
/// Décide si l'opt-in `allow_high_impact` du corps /api/run est HONORÉ. L'opt-in n'est honoré QUE si
/// les TROIS conditions de gouvernance sont réunies :
///   (1) requête authentifiée operator (vérifiée en amont par `check_operator`, fail-closed —
///       passée ici via `operator_ok` pour garder la fonction pure et testable) ;
///   (2) `arm == true` (armement explicite) ;
///   (3) `reason` non vide (raison obligatoire, déjà bornée à 200 car. par l'appelant).
///
/// Retour :
///   - `Ok(false)` : opt-in NON demandé (`allow_high_impact=false`) -> comportement ACTUEL inchangé
///     (plancher exploit tient, scope écrit allow_*=false) ;
///   - `Ok(true)`  : opt-in demandé ET les 3 conditions réunies -> capacité haut-impact autorisée ;
///   - `Err((code, json))` : opt-in demandé mais une condition manque -> 400 explicite.
pub(crate) fn high_impact_gate(
    allow_high_impact: bool,
    operator_ok: bool,
    arm: bool,
    reason: &str,
) -> Result<bool, error::ApiError> {
    if !allow_high_impact {
        return Ok(false); // défaut : aucune dérogation, plancher exploit inchangé
    }
    // operator_ok est en principe TOUJOURS vrai à ce stade (check_operator a déjà gaté l'endpoint) ;
    // on le revérifie ici par défense en profondeur — un opt-in haut-impact ne peut JAMAIS être
    // honoré sans preuve operator, quelle que soit l'ordre des futurs appelants (fail-closed).
    if !operator_ok || !arm || reason.trim().is_empty() {
        return Err(error::ApiError::bad("high_impact_requires_arm_and_reason", "allow_high_impact n'est honoré qu'avec operator authentifié + arm=true + reason non vide"));
    }
    Ok(true)
}


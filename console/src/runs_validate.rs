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

// ===========================================================================================
//  R3 — PROFIL DE RESSOURCES + OVERRIDES PAR-LEVIER (Launch UI -> env du moteur).
//
//  CHOIX DE RESSOURCE UNIQUEMENT : ne touche NI le scope, NI le ROE, NI le plancher d'exploit, NI
//  aucune bascule de capacité. On ne fait QUE poser les variables d'environnement que le moteur (R1,
//  `forge/resource_profile.py`) LIT DÉJÀ, en préservant la précédence STRICTE `override > profil >
//  défaut`. Champ ABSENT/vide/illisible => la variable N'EST PAS posée => le défaut du profil (ou le
//  défaut-code) s'applique. `balanced` (profil par défaut) SANS override => AUCUNE variable posée =>
//  comportement byte-identique à aujourd'hui (no-op).
//
//  Bornes (garde-fous anti-abus, alignées sur les clamps du moteur) :
//    parallelism  ∈ [1, 64]   (engine._parallelism clamp) ; run_timeout ∈ [1, 604800] (≤ 7 jours) ;
//    tools_profile ∈ {mini, full} ; profile ∈ {low, full} honoré (balanced => None, no-op).
// ===========================================================================================

/// Options de ressources RÉSOLUES depuis le corps /api/run (`body["resource"]`). Chaque champ `None`
/// signifie « ne pas poser cette variable » (le défaut du profil s'applique). Pur data — aucune décision
/// de gouvernance ne dépend de ces valeurs.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct ResourceOptions {
    pub(crate) profile: Option<String>,       // FORGE_RESOURCE_PROFILE — "low"|"full" ; "balanced"/absent => None (no-op)
    pub(crate) parallelism: Option<i64>,      // FORGE_PARALLELISM      — [1, 64]
    pub(crate) run_timeout: Option<i64>,      // FORGE_RUN_TIMEOUT      — [1, 604800]
    pub(crate) tools_profile: Option<String>, // FORGE_TOOLS_PROFILE    — "mini"|"full"
}

impl ResourceOptions {
    /// Paires (variable d'env, valeur) à poser sur le process moteur. Un champ `None` => AUCUNE entrée
    /// (donc la variable n'est pas posée -> défaut du profil). C'est l'UNIQUE dérivation appliquée au
    /// `Command` du moteur (cf. `claim_and_spawn`). `balanced` sans override => vecteur VIDE (no-op).
    pub(crate) fn env_pairs(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        if let Some(p) = &self.profile {
            out.push(("FORGE_RESOURCE_PROFILE", p.clone()));
        }
        if let Some(n) = self.parallelism {
            out.push(("FORGE_PARALLELISM", n.to_string()));
        }
        if let Some(n) = self.run_timeout {
            out.push(("FORGE_RUN_TIMEOUT", n.to_string()));
        }
        if let Some(t) = &self.tools_profile {
            out.push(("FORGE_TOOLS_PROFILE", t.clone()));
        }
        out
    }

    /// Sérialise en `Value` (objet plat) pour le blob `run_job.spawn_spec` du chemin HA pending. Les
    /// champs `None` sont émis en `null` (round-trip fidèle via `from_value`).
    pub(crate) fn to_value(&self) -> Value {
        serde_json::json!({
            "profile": self.profile, "parallelism": self.parallelism,
            "run_timeout": self.run_timeout, "tools_profile": self.tools_profile,
        })
    }

    /// Reconstruit depuis un `Value` (objet plat produit par `to_value`). RE-VALIDE via `parse_resource_options`
    /// (mêmes bornes/fail-open) — un blob corrompu retombe donc sur les défauts (aucune variable posée).
    pub(crate) fn from_value(v: &Value) -> Self {
        parse_resource_options(&serde_json::json!({ "resource": v }))
    }
}

/// Parse `body["resource"]` en `ResourceOptions` validées. FAIL-OPEN sur garbage (un champ invalide =>
/// `None` => défaut du profil), JAMAIS d'erreur : un choix de ressource malformé ne doit pas bloquer un
/// lancement (le moteur retombe sur le profil/défaut). Absent/non-objet => tout `None` (no-op).
pub(crate) fn parse_resource_options(body: &Value) -> ResourceOptions {
    let obj = match body.get("resource") {
        Some(Value::Object(m)) => m,
        _ => return ResourceOptions::default(),
    };
    // profil : seuls "low"/"full" sont honorés (posent FORGE_RESOURCE_PROFILE). "balanced" (défaut) et
    // toute autre valeur => None => on ne force PAS la variable (no-op, comportement inchangé).
    let profile = obj
        .get("profile")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s == "low" || s == "full");
    // parallélisme : entier borné [1, 64] (clamp moteur). Hors bornes/illisible => None.
    let parallelism = obj
        .get("parallelism")
        .and_then(|v| v.as_i64())
        .filter(|n| *n >= 1 && *n <= 64);
    // watchdog run-timeout (s) : entier borné [1, 604800]. Hors bornes/illisible => None. NB : c'est un
    // DÉFAUT pour le snapshot moteur — le watchdog Rust reste plafonné par le cap serveur global.
    let run_timeout = obj
        .get("run_timeout")
        .and_then(|v| v.as_i64())
        .filter(|n| *n >= 1 && *n <= 604_800);
    // profil d'outils Docker : "mini"|"full" uniquement. Autre => None.
    let tools_profile = obj
        .get("tools_profile")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s == "mini" || s == "full");
    ResourceOptions { profile, parallelism, run_timeout, tools_profile }
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    use serde_json::json;

    /// (a) NO-OP : balanced sans override (et corps sans `resource`) => AUCUNE variable d'env posée =>
    /// comportement byte-identique à aujourd'hui. C'est la garantie « balanced = no-op » de R3.
    #[test]
    fn balanced_no_overrides_is_noop() {
        // corps sans clé `resource` du tout
        let opts = parse_resource_options(&json!({"campaign": "c"}));
        assert_eq!(opts, ResourceOptions::default());
        assert!(opts.env_pairs().is_empty(), "aucune variable posée sans resource");
        // `resource` présent mais profile=balanced, aucun override => toujours no-op
        let opts = parse_resource_options(&json!({"resource": {"profile": "balanced"}}));
        assert_eq!(opts.profile, None, "balanced n'est PAS honoré comme override (défaut)");
        assert!(opts.env_pairs().is_empty(), "balanced + rien => aucune variable => no-op");
    }

    /// (b) OVERRIDE ATTEINT LE MOTEUR : profile=low pose FORGE_RESOURCE_PROFILE=low ; un pool renseigné
    /// pose FORGE_PARALLELISM ; run_timeout pose FORGE_RUN_TIMEOUT ; tools_profile pose FORGE_TOOLS_PROFILE.
    #[test]
    fn profile_low_and_overrides_reach_env() {
        let opts = parse_resource_options(&json!({
            "resource": {"profile": "low", "parallelism": 8, "run_timeout": 3600, "tools_profile": "mini"}
        }));
        assert_eq!(opts.profile.as_deref(), Some("low"));
        assert_eq!(opts.parallelism, Some(8));
        assert_eq!(opts.run_timeout, Some(3600));
        assert_eq!(opts.tools_profile.as_deref(), Some("mini"));
        let env = opts.env_pairs();
        assert!(env.contains(&("FORGE_RESOURCE_PROFILE", "low".to_string())), "profil low posé");
        assert!(env.contains(&("FORGE_PARALLELISM", "8".to_string())), "pool override posé");
        assert!(env.contains(&("FORGE_RUN_TIMEOUT", "3600".to_string())), "run-timeout override posé");
        assert!(env.contains(&("FORGE_TOOLS_PROFILE", "mini".to_string())), "tools-profile override posé");
    }

    /// (b-bis) BLANK/ABSENT => variable ABSENTE : profile=full seul ne pose QUE FORGE_RESOURCE_PROFILE
    /// (les overrides non renseignés restent None -> variables non posées -> défaut du profil).
    #[test]
    fn full_profile_alone_sets_only_profile_var() {
        let opts = parse_resource_options(&json!({"resource": {"profile": "full"}}));
        let env = opts.env_pairs();
        assert_eq!(env, vec![("FORGE_RESOURCE_PROFILE", "full".to_string())]);
        // aucune des variables d'override par-levier n'est présente
        assert!(!env.iter().any(|(k, _)| *k == "FORGE_PARALLELISM"));
        assert!(!env.iter().any(|(k, _)| *k == "FORGE_RUN_TIMEOUT"));
        assert!(!env.iter().any(|(k, _)| *k == "FORGE_TOOLS_PROFILE"));
    }

    /// GARBAGE / HORS-BORNES => fail-open vers None (défaut profil), JAMAIS de variable posée avec une
    /// valeur invalide : parallélisme hors [1,64], run_timeout <=0, profils inconnus sont tous ignorés.
    #[test]
    fn garbage_and_out_of_bounds_fail_open() {
        let opts = parse_resource_options(&json!({
            "resource": {"profile": "turbo", "parallelism": 999, "run_timeout": 0, "tools_profile": "xxl"}
        }));
        assert_eq!(opts, ResourceOptions::default(), "tout garbage => défaut => aucune variable");
        assert!(opts.env_pairs().is_empty());
        // borne haute parallélisme respectée (64 OK, 65 rejeté)
        assert_eq!(parse_resource_options(&json!({"resource": {"parallelism": 64}})).parallelism, Some(64));
        assert_eq!(parse_resource_options(&json!({"resource": {"parallelism": 65}})).parallelism, None);
    }
}


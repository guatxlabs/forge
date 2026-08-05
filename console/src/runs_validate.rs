// SPDX-License-Identifier: AGPL-3.0-or-later
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

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
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
//  l'allowlist de sévérité nuclei, NI le planner coverage-safe, NI aucune bascule de capacité. On ne
//  fait QUE poser les variables d'environnement que le moteur (R1, `forge/resource_profile.py`) LIT
//  DÉJÀ, en préservant la précédence STRICTE `override > profil > défaut`. Champ ABSENT/vide/illisible
//  => la variable N'EST PAS posée => le défaut du profil (ou le défaut-code) s'applique. `balanced`
//  (profil par défaut) SANS override => AUCUNE variable posée => byte-identique à aujourd'hui (no-op).
//
//  ANTI-INJECTION (le point dur) : le corps N'EST JAMAIS ITÉRÉ. C'est l'ALLOWLIST `RESOURCE_KNOBS` qui
//  est parcourue, et pour chaque levier connu on va CHERCHER sa clé dans le corps. Conséquences :
//    * une clé inconnue du corps (`allow_private`, `PATH`, `LD_PRELOAD`, `FORGE_CONSOLE_TOKEN`…) est
//      IGNORÉE — elle ne peut atteindre NI l'environnement du moteur NI le blob spawn_spec ;
//    * chaque valeur est TYPÉE (i64 / enum fermé) et BORNÉE [min, max] — pas de chaîne libre ;
//    * le NOM de la variable d'environnement est une constante `&'static str` du binaire, jamais une
//      donnée venue du client (aucune variable arbitraire n'est constructible).
//
//  GOUVERNANCE — deux leviers de la table moteur sont VOLONTAIREMENT ABSENTS de l'allowlist :
//    * `nuclei_severity` : c'est une ALLOWLIST DE SÉVÉRITÉ (gouvernance), réglable par param de module
//      validé, jamais par le canal « ressources » ;
//    * `rate_per_sec`    : le débit est porté par le scope/ROE (champ `rate` du run, écrit dans
//      scope.json) — documentation-only côté profil.
//  Les exposer ici reviendrait à élargir une capacité depuis un réglage de confort : interdit.
// ===========================================================================================

/// Un levier de ressource ENTIER réglable depuis l'UI de lancement. `key` = clé acceptée dans
/// `body["resource"]` (et dans le blob spawn_spec) ; `knob` = nom du levier dans la table moteur
/// (`forge/resource_profile.py`, utilisé pour afficher le défaut du profil) ; `env` = variable
/// d'environnement posée sur le process moteur ; `[min, max]` = bornes serveur (⊆ clamps du moteur).
pub(crate) struct ResourceKnob {
    pub(crate) key: &'static str,
    pub(crate) knob: &'static str,
    pub(crate) env: &'static str,
    pub(crate) min: i64,
    pub(crate) max: i64,
    pub(crate) label: &'static str,
    pub(crate) hint: &'static str,
}

/// ALLOWLIST des leviers ENTIERS — LA seule liste dont un `/api/run` peut faire poser une variable
/// d'environnement. Bornes alignées sur les clamps du moteur : parallélisme `engine._parallelism`
/// [1,64] · profondeur de traversal `injection.PathTraversal._payloads` [1,12] · `llm.max_tokens`
/// [16,8192] · `llm.num_ctx` [0,131072]. Les libellés sont ceux vus par l'OPÉRATEUR (l'UI ne réinvente
/// aucun nom de variable). `run_timeout` garde sa clé HISTORIQUE (blobs spawn_spec déjà écrits).
pub(crate) const RESOURCE_KNOBS: &[ResourceKnob] = &[
    ResourceKnob { key: "parallelism", knob: "parallelism", env: "FORGE_PARALLELISM", min: 1, max: 64,
        label: "Actions simultanées",
        hint: "Actions tirées en parallèle dans une vague. Plus haut = plus rapide, plus gourmand en CPU/RAM." },
    ResourceKnob { key: "max_concurrent_procs", knob: "max_concurrent_procs", env: "FORGE_MAX_CONCURRENT_PROCS", min: 1, max: 64,
        label: "Processus outils simultanés",
        hint: "Garde-fou mémoire : nombre d'outils externes (nmap, nuclei…) vivants en même temps." },
    ResourceKnob { key: "action_timeout", knob: "action_timeout_secs", env: "FORGE_ACTION_TIMEOUT_SECS", min: 1, max: 86_400,
        label: "Délai max par action (s)",
        hint: "Au-delà, l'outil de CETTE action est coupé. Court = coupe vite sur machine lente ou lien mince." },
    ResourceKnob { key: "run_timeout", knob: "run_timeout_secs", env: "FORGE_RUN_TIMEOUT", min: 1, max: 604_800,
        label: "Délai max du run (s)",
        hint: "Watchdog du run complet. Le plafond serveur global reste appliqué en plus." },
    ResourceKnob { key: "crawl_max_endpoints", knob: "crawl_max_endpoints", env: "FORGE_CRAWL_MAX_ENDPOINTS", min: 1, max: 5_000,
        label: "Pages explorées au maximum",
        hint: "Nombre d'endpoints retenus par la découverte de surface." },
    ResourceKnob { key: "crawl_max_params", knob: "crawl_max_params", env: "FORGE_CRAWL_MAX_PARAMS", min: 1, max: 50,
        label: "Paramètres testés par page",
        hint: "Nombre de paramètres sondés sur chaque endpoint." },
    ResourceKnob { key: "crawl_max_depth", knob: "crawl_max_depth", env: "FORGE_CRAWL_MAX_DEPTH", min: 1, max: 12,
        label: "Profondeur d'exploration",
        hint: "Profondeur des variantes de chemin testées. Moins profond = moins de requêtes." },
    ResourceKnob { key: "content_fanout_max", knob: "content_fanout_max", env: "FORGE_CONTENT_FANOUT_MAX", min: 1, max: 500,
        label: "Cibles enchaînées au maximum",
        hint: "Plafond du fan-out cibles × scanners quand une découverte en déclenche d'autres." },
    ResourceKnob { key: "discovery_max_fanout", knob: "discovery_max_fanout", env: "FORGE_DISCOVERY_MAX_FANOUT", min: 1, max: 500,
        label: "Services/ports sondés au maximum",
        hint: "Plafond des services découverts et des ports re-sondés en HTTP." },
    ResourceKnob { key: "llm_max_tokens", knob: "llm_max_tokens", env: "FORGE_LLM_MAX_TOKENS", min: 16, max: 8_192,
        label: "IA — longueur de réponse max",
        hint: "Sans effet tant que l'assistance IA n'est pas activée dans le scope." },
    ResourceKnob { key: "llm_num_ctx", knob: "llm_num_ctx", env: "FORGE_LLM_NUM_CTX", min: 0, max: 131_072,
        label: "IA — fenêtre de contexte",
        hint: "0 = laisser le modèle décider (aucune option envoyée). Une valeur finie borne la RAM du modèle local." },
    ResourceKnob { key: "llm_enrich_max_endpoints", knob: "llm_enrich_max_endpoints", env: "FORGE_LLM_ENRICH_MAX_ENDPOINTS", min: 0, max: 100,
        label: "IA — endpoints enrichis par vague",
        hint: "0 = aucun appel IA. Les payloads suggérés restent confirmés par les oracles déterministes." },
    ResourceKnob { key: "triage_max_items", knob: "triage_max_items", env: "FORGE_TRIAGE_MAX_ITEMS", min: 1, max: 500,
        label: "Synthèse — findings listés",
        hint: "Taille du top affiché dans la synthèse. AUCUN finding n'est supprimé (le rapport garde tout)." },
    ResourceKnob { key: "triage_max_clusters", knob: "triage_max_clusters", env: "FORGE_TRIAGE_MAX_CLUSTERS", min: 1, max: 500,
        label: "Synthèse — groupes de bruit listés",
        hint: "Nombre de clusters de bruit surfacés dans la synthèse. Aucun finding n'est supprimé." },
];

/// Variable d'env du PROFIL (`low|balanced|full`) et du profil d'outils — les deux leviers non entiers.
pub(crate) const ENV_RESOURCE_PROFILE: &str = "FORGE_RESOURCE_PROFILE";
pub(crate) const ENV_TOOLS_PROFILE: &str = "FORGE_TOOLS_PROFILE";
/// Profils honorés comme OVERRIDE (le défaut `balanced` ne pose RIEN — no-op).
pub(crate) const RESOURCE_PROFILE_OVERRIDES: [&str; 2] = ["low", "full"];
/// Valeurs honorées pour le profil d'outils Docker.
pub(crate) const TOOLS_PROFILE_VALUES: [&str; 2] = ["mini", "full"];
/// Leviers de la table moteur VOLONTAIREMENT NON réglables ici (gouvernance) — affichés en lecture
/// seule dans l'UI avec la raison, pour que l'opérateur sache où ils se règlent VRAIMENT.
pub(crate) const GOVERNED_KNOBS: [(&str, &str, &str); 2] = [
    ("nuclei_severity", "Sévérité nuclei",
     "gouvernance : allowlist de sévérité — se règle dans les paramètres du module nuclei, pas ici"),
    ("rate_per_sec", "Débit requêtes/s",
     "gouvernance : le débit est porté par le scope/ROE — champ « Débit req/s » du lancement"),
];

/// Options de ressources RÉSOLUES depuis le corps /api/run (`body["resource"]`). Une entrée ABSENTE
/// signifie « ne pas poser cette variable » (le défaut du profil s'applique). Pur data — aucune décision
/// de gouvernance ne dépend de ces valeurs.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct ResourceOptions {
    pub(crate) profile: Option<String>,        // FORGE_RESOURCE_PROFILE — "low"|"full" ; "balanced"/absent => None (no-op)
    pub(crate) tools_profile: Option<String>,  // FORGE_TOOLS_PROFILE    — "mini"|"full"
    /// Leviers entiers retenus, clés ⊆ `RESOURCE_KNOBS[].key` (BTreeMap => ordre déterministe).
    pub(crate) ints: std::collections::BTreeMap<&'static str, i64>,
}

impl ResourceOptions {
    /// Valeur retenue pour un levier entier (`None` = non renseigné => défaut du profil).
    pub(crate) fn int(&self, key: &str) -> Option<i64> {
        self.ints.get(key).copied()
    }

    /// Paires (variable d'env, valeur) à poser sur le process moteur. Une entrée absente => AUCUNE
    /// paire (donc la variable n'est pas posée -> défaut du profil). C'est l'UNIQUE dérivation appliquée
    /// au `Command` du moteur (cf. `claim_and_spawn`). `balanced` sans override => vecteur VIDE (no-op).
    /// Les NOMS de variables viennent TOUS de constantes du binaire (jamais du corps de la requête).
    pub(crate) fn env_pairs(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        if let Some(p) = &self.profile {
            out.push((ENV_RESOURCE_PROFILE, p.clone()));
        }
        if let Some(t) = &self.tools_profile {
            out.push((ENV_TOOLS_PROFILE, t.clone()));
        }
        // ordre = ordre de l'ALLOWLIST (déterministe, indépendant de l'ordre des clés du client).
        for k in RESOURCE_KNOBS {
            if let Some(n) = self.ints.get(k.key) {
                out.push((k.env, n.to_string()));
            }
        }
        out
    }

    /// Sérialise en `Value` (objet plat) pour le blob `run_job.spawn_spec` du chemin HA pending. Les
    /// leviers non renseignés sont émis en `null` (round-trip fidèle via `from_value`).
    pub(crate) fn to_value(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("profile".into(), match &self.profile { Some(p) => Value::String(p.clone()), None => Value::Null });
        m.insert("tools_profile".into(), match &self.tools_profile { Some(t) => Value::String(t.clone()), None => Value::Null });
        for k in RESOURCE_KNOBS {
            m.insert(k.key.into(), match self.ints.get(k.key) { Some(n) => Value::from(*n), None => Value::Null });
        }
        Value::Object(m)
    }

    /// Reconstruit depuis un `Value` (objet plat produit par `to_value`). RE-VALIDE via `parse_resource_options`
    /// (mêmes bornes/allowlist/fail-open) — un blob corrompu ou LEGACY (écrit avant l'ajout d'un levier)
    /// retombe donc sur les défauts pour ce qu'il ne porte pas (aucune variable posée).
    pub(crate) fn from_value(v: &Value) -> Self {
        parse_resource_options(&serde_json::json!({ "resource": v }))
    }
}

/// Parse `body["resource"]` en `ResourceOptions` validées. FAIL-OPEN sur garbage (un champ invalide =>
/// absent => défaut du profil), JAMAIS d'erreur : un choix de ressource malformé ne doit pas bloquer un
/// lancement (le moteur retombe sur le profil/défaut). Absent/non-objet => tout vide (no-op).
/// ANTI-INJECTION : on itère l'ALLOWLIST, jamais les clés du corps (cf. en-tête de section).
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
        .filter(|s| RESOURCE_PROFILE_OVERRIDES.contains(&s.as_str()));
    // profil d'outils Docker : "mini"|"full" uniquement. Autre => None.
    let tools_profile = obj
        .get("tools_profile")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| TOOLS_PROFILE_VALUES.contains(&s.as_str()));
    // leviers entiers : pour CHAQUE levier de l'allowlist, on lit sa clé (si présente), on exige un
    // entier et on le borne. Hors bornes / non entier / absent => rien (défaut du profil).
    let mut ints = std::collections::BTreeMap::new();
    for k in RESOURCE_KNOBS {
        if let Some(n) = obj.get(k.key).and_then(|v| v.as_i64()).filter(|n| *n >= k.min && *n <= k.max) {
            ints.insert(k.key, n);
        }
    }
    ResourceOptions { profile, tools_profile, ints }
}

/// GET /api/resource-profile — CATALOGUE des leviers de ressources pour l'UI de lancement (lecture
/// pure, aucun effet de bord). Deux moitiés :
///   * `knobs` / `governed` / `*_choices` : l'ALLOWLIST SERVEUR (bornes + libellés opérateur) — c'est
///     elle qui fait foi sur ce qui est réglable, donc l'UI ne peut pas proposer autre chose ;
///   * `profiles` : la TABLE DU MOTEUR (`python -m forge.resource_profile`, SOURCE DE VÉRITÉ des
///     défauts) — l'UI AFFICHE ces valeurs au lieu d'en garder une copie qui dériverait.
/// Le moteur est interrogé en LECTURE SEULE (argv FIXE, sans shell, sans donnée client, borné dans le
/// temps). S'il est indisponible : `engine_ok=false` + `profiles:{}` — l'UI reste utilisable (les
/// champs restent réglables, seuls les défauts affichés manquent).
pub(crate) async fn resource_profile_catalog(State(app): State<App>) -> Response {
    let knobs: Vec<Value> = RESOURCE_KNOBS
        .iter()
        .map(|k| serde_json::json!({
            "key": k.key, "knob": k.knob, "env": k.env,
            "min": k.min, "max": k.max, "label": k.label, "hint": k.hint,
        }))
        .collect();
    let governed: Vec<Value> = GOVERNED_KNOBS
        .iter()
        .map(|(knob, label, why)| serde_json::json!({"knob": knob, "label": label, "why": why}))
        .collect();
    let engine = engine_resource_catalog(&app).await;
    let profiles = engine
        .as_ref()
        .and_then(|v| v.get("profiles"))
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let default_profile = engine
        .as_ref()
        .and_then(|v| v.get("default_profile"))
        .and_then(|v| v.as_str())
        .unwrap_or("balanced")
        .to_string();
    (StatusCode::OK, Json(serde_json::json!({
        "engine_ok": engine.is_some(),
        "env_var": ENV_RESOURCE_PROFILE,
        "default_profile": default_profile,
        "profiles": profiles,
        "profile_choices": [
            {"value": "balanced", "label": "balanced (défaut — comportement inchangé)"},
            {"value": "low", "label": "low (machine faible)"},
            {"value": "full", "label": "full (grosse machine)"},
        ],
        "tools_profile_choices": [
            {"value": "mini", "label": "mini (léger)"},
            {"value": "full", "label": "full (complet)"},
        ],
        "knobs": knobs,
        "governed": governed,
    }))).into_response()
}

/// Interroge le moteur pour la table des profils (`python -m forge.resource_profile` -> JSON sur
/// stdout). Argv FIXE (aucune donnée client, aucun shell), borné à 10 s, stdout borné. `None` si
/// l'interpréteur/moteur est absent, sort en erreur, dépasse le délai ou n'émet pas de JSON.
///
/// MÉMOÏSÉ pour la durée du process (la table de profils est une CONSTANTE du moteur) : un rafraîchis-
/// sement de l'UI ne relance donc pas un interpréteur, et cette route de lecture ne peut pas servir de
/// tapis roulant à spawns. Seuls les SUCCÈS sont mis en cache (un moteur momentanément indisponible
/// sera re-tenté), la clé inclut l'interpréteur ET la racine du paquet (isolation entre Apps de test).
async fn engine_resource_catalog(app: &App) -> Option<Value> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, Value>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let key = format!("{}\u{1}{}", app.python.as_str(), app.pkg_dir.as_str());
    if let Ok(c) = cache.lock() {
        if let Some(v) = c.get(&key) {
            return Some(v.clone());
        }
    }
    let parsed = engine_resource_catalog_uncached(app).await?;
    if let Ok(mut c) = cache.lock() {
        c.insert(key, parsed.clone());
    }
    Some(parsed)
}

/// Le spawn proprement dit (sans cache) — séparé pour rester lisible et testable isolément.
async fn engine_resource_catalog_uncached(app: &App) -> Option<Value> {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(app.python.as_str())
            .args(["-m", "forge.resource_profile"])
            .current_dir(app.pkg_dir.as_str())
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() || out.stdout.len() > 256 * 1024 {
        return None;
    }
    serde_json::from_slice::<Value>(&out.stdout).ok().filter(|v| v.is_object())
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    use crate::testutil::*;
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
        // ... et le blob spawn_spec d'un tel run se relit en no-op (round-trip du chemin HA pending).
        assert!(ResourceOptions::from_value(&opts.to_value()).env_pairs().is_empty());
    }

    /// (b) OVERRIDE ATTEINT LE MOTEUR : profile=low pose FORGE_RESOURCE_PROFILE=low ; un pool renseigné
    /// pose FORGE_PARALLELISM ; run_timeout pose FORGE_RUN_TIMEOUT ; tools_profile pose FORGE_TOOLS_PROFILE.
    #[test]
    fn profile_low_and_overrides_reach_env() {
        let opts = parse_resource_options(&json!({
            "resource": {"profile": "low", "parallelism": 8, "run_timeout": 3600, "tools_profile": "mini"}
        }));
        assert_eq!(opts.profile.as_deref(), Some("low"));
        assert_eq!(opts.int("parallelism"), Some(8));
        assert_eq!(opts.int("run_timeout"), Some(3600));
        assert_eq!(opts.tools_profile.as_deref(), Some("mini"));
        let env = opts.env_pairs();
        assert!(env.contains(&("FORGE_RESOURCE_PROFILE", "low".to_string())), "profil low posé");
        assert!(env.contains(&("FORGE_PARALLELISM", "8".to_string())), "pool override posé");
        assert!(env.contains(&("FORGE_RUN_TIMEOUT", "3600".to_string())), "run-timeout override posé");
        assert!(env.contains(&("FORGE_TOOLS_PROFILE", "mini".to_string())), "tools-profile override posé");
    }

    /// (b-bis) BLANK/ABSENT => variable ABSENTE : profile=full seul ne pose QUE FORGE_RESOURCE_PROFILE
    /// (les overrides non renseignés restent absents -> variables non posées -> défaut du profil).
    #[test]
    fn full_profile_alone_sets_only_profile_var() {
        let opts = parse_resource_options(&json!({"resource": {"profile": "full"}}));
        let env = opts.env_pairs();
        assert_eq!(env, vec![("FORGE_RESOURCE_PROFILE", "full".to_string())]);
        // aucune des variables d'override par-levier n'est présente
        for k in RESOURCE_KNOBS {
            assert!(!env.iter().any(|(name, _)| *name == k.env), "{} ne doit pas être posée", k.env);
        }
        assert!(!env.iter().any(|(k, _)| *k == ENV_TOOLS_PROFILE));
    }

    /// GARBAGE / HORS-BORNES => fail-open vers absent (défaut profil), JAMAIS de variable posée avec une
    /// valeur invalide : parallélisme hors [1,64], run_timeout <=0, profils inconnus sont tous ignorés.
    #[test]
    fn garbage_and_out_of_bounds_fail_open() {
        let opts = parse_resource_options(&json!({
            "resource": {"profile": "turbo", "parallelism": 999, "run_timeout": 0, "tools_profile": "xxl"}
        }));
        assert_eq!(opts, ResourceOptions::default(), "tout garbage => défaut => aucune variable");
        assert!(opts.env_pairs().is_empty());
        // borne haute parallélisme respectée (64 OK, 65 rejeté)
        assert_eq!(parse_resource_options(&json!({"resource": {"parallelism": 64}})).int("parallelism"), Some(64));
        assert_eq!(parse_resource_options(&json!({"resource": {"parallelism": 65}})).int("parallelism"), None);
    }

    /// (c) TOUS les leviers de l'allowlist sont réglables ET bornés : min/max acceptés, min-1/max+1
    /// REJETÉS, type non entier (chaîne, float, bool, null) REJETÉ. Balaie la table entière — un levier
    /// ajouté sans bornes cohérentes fait rougir ce test.
    #[test]
    fn every_allowlisted_knob_is_bounded_and_typed() {
        for k in RESOURCE_KNOBS {
            let at_min = parse_resource_options(&json!({"resource": {k.key: k.min}}));
            assert_eq!(at_min.int(k.key), Some(k.min), "{}: min accepté", k.key);
            assert_eq!(at_min.env_pairs(), vec![(k.env, k.min.to_string())], "{}: pose SA variable", k.key);
            assert_eq!(parse_resource_options(&json!({"resource": {k.key: k.max}})).int(k.key), Some(k.max), "{}: max accepté", k.key);
            assert_eq!(parse_resource_options(&json!({"resource": {k.key: k.min - 1}})).int(k.key), None, "{}: sous la borne rejeté", k.key);
            assert_eq!(parse_resource_options(&json!({"resource": {k.key: k.max + 1}})).int(k.key), None, "{}: au-dessus de la borne rejeté", k.key);
            for bad in [json!("8"), json!(1.5), json!(true), json!(null), json!([1]), json!({"v": 1})] {
                assert_eq!(parse_resource_options(&json!({"resource": {k.key: bad}})).int(k.key), None,
                           "{}: valeur non entière rejetée", k.key);
            }
        }
    }

    /// (d) GOUVERNANCE — ANTI-INJECTION : une clé HORS allowlist ne peut RIEN poser dans l'environnement
    /// du moteur. On envoie un corps hostile (bascules de capacité, variables d'env sensibles, noms de
    /// leviers gouvernés) : le résultat doit être le DÉFAUT, donc zéro variable.
    #[test]
    fn unknown_and_governance_keys_never_reach_env() {
        let hostile = json!({"resource": {
            // bascules de CAPACITÉ (elles ont leur propre gate, jamais ce canal)
            "allow_private": true, "allow_exploit": true, "allow_destructive": true,
            "high_impact": true, "arm": true, "exhaustive": true, "mode": "auto",
            // leviers GOUVERNÉS de la table moteur (volontairement hors allowlist)
            "nuclei_severity": "info,low,medium,high,critical", "rate_per_sec": 10000,
            // variables d'environnement sensibles / injection d'env arbitraire
            "FORGE_CONSOLE_TOKEN": "leak", "PATH": "/tmp/evil", "LD_PRELOAD": "/tmp/x.so",
            "PYTHONPATH": "/tmp", "FORGE_RESOURCE_PROFILE": "full",
            // scope / ROE
            "in_scope": ["evil.test"], "out_scope": [], "scope": {"in_scope": ["evil.test"]},
        }});
        let opts = parse_resource_options(&hostile);
        assert_eq!(opts, ResourceOptions::default(), "aucune clé hors allowlist retenue");
        assert!(opts.env_pairs().is_empty(), "aucune variable d'environnement posée");
        // même chose sur le chemin HA (blob spawn_spec re-validé à la relecture)
        assert!(ResourceOptions::from_value(hostile.get("resource").unwrap()).env_pairs().is_empty());
    }

    /// (d-bis) L'ENSEMBLE des variables posables est CLOS : quelles que soient les valeurs du corps, les
    /// noms de variables produits appartiennent à l'allowlist compilée (et commencent tous par FORGE_).
    /// Les leviers GOUVERNÉS (sévérité nuclei, débit) n'y figurent JAMAIS.
    #[test]
    fn env_name_set_is_closed_and_governance_knobs_absent() {
        let mut allowed: Vec<&str> = vec![ENV_RESOURCE_PROFILE, ENV_TOOLS_PROFILE];
        allowed.extend(RESOURCE_KNOBS.iter().map(|k| k.env));
        // unicité + préfixe FORGE_ + clés uniques
        let mut sorted = allowed.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), allowed.len(), "noms de variables dupliqués dans l'allowlist");
        assert!(allowed.iter().all(|e| e.starts_with("FORGE_")), "variable hors namespace FORGE_");
        let mut keys: Vec<&str> = RESOURCE_KNOBS.iter().map(|k| k.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), RESOURCE_KNOBS.len(), "clés de leviers dupliquées");
        // aucun levier gouverné dans l'allowlist (ni par clé, ni par nom de levier moteur)
        for (knob, _, _) in GOVERNED_KNOBS {
            assert!(!RESOURCE_KNOBS.iter().any(|k| k.key == knob || k.knob == knob),
                    "{knob} est un levier de GOUVERNANCE — il ne doit pas être réglable par le canal ressources");
        }
        // un corps qui renseigne TOUT ne produit que des variables de l'allowlist
        let mut body = serde_json::Map::new();
        body.insert("profile".into(), json!("low"));
        body.insert("tools_profile".into(), json!("mini"));
        for k in RESOURCE_KNOBS {
            body.insert(k.key.into(), json!(k.max));
        }
        let env = parse_resource_options(&json!({"resource": Value::Object(body)})).env_pairs();
        assert_eq!(env.len(), allowed.len(), "toutes les variables de l'allowlist sont posables");
        for (name, _) in &env {
            assert!(allowed.contains(name), "{name} hors allowlist");
        }
    }

    /// (e) ROUND-TRIP spawn_spec (chemin HA pending) : tous les leviers survivent à la sérialisation,
    /// et un blob LEGACY (écrit avant l'ajout des nouveaux leviers) se relit sans rien inventer.
    #[test]
    fn spawn_spec_round_trip_and_legacy_blob() {
        let mut body = serde_json::Map::new();
        body.insert("profile".into(), json!("low"));
        body.insert("tools_profile".into(), json!("mini"));
        for k in RESOURCE_KNOBS {
            body.insert(k.key.into(), json!(k.min));
        }
        let opts = parse_resource_options(&json!({"resource": Value::Object(body)}));
        assert_eq!(ResourceOptions::from_value(&opts.to_value()), opts, "round-trip fidèle");
        // blob LEGACY : uniquement les 4 champs historiques -> relu tel quel, rien d'autre inventé.
        let legacy = json!({"profile": "full", "parallelism": 12, "run_timeout": 7200, "tools_profile": "full"});
        let back = ResourceOptions::from_value(&legacy);
        assert_eq!(back.profile.as_deref(), Some("full"));
        assert_eq!(back.int("parallelism"), Some(12));
        assert_eq!(back.int("run_timeout"), Some(7200));
        assert_eq!(back.ints.len(), 2, "aucun levier fabriqué à partir d'un blob legacy");
    }

    /// (f) CATALOGUE `/api/resource-profile` : la moitié SERVEUR (allowlist + bornes + libellés + leviers
    /// gouvernés) est toujours servie, même si le moteur est injoignable (interpréteur bidon) — l'UI
    /// reste utilisable, `engine_ok=false` et `profiles` vide. Les libellés sont opérateur, pas du code.
    #[tokio::test]
    async fn catalog_serves_allowlist_without_engine() {
        let mut app = test_app(&tmp_path("rescat.jsonl"));
        app.python = std::sync::Arc::new("/nonexistent/python-forge-test".into());
        let resp = resource_profile_catalog(State(app)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        let v: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["engine_ok"], json!(false), "moteur injoignable => engine_ok=false");
        assert_eq!(v["profiles"], json!({}), "aucun défaut fabriqué sans le moteur");
        assert_eq!(v["default_profile"], json!("balanced"));
        let knobs = v["knobs"].as_array().expect("knobs");
        assert_eq!(knobs.len(), RESOURCE_KNOBS.len(), "tous les leviers exposés");
        for (i, k) in RESOURCE_KNOBS.iter().enumerate() {
            assert_eq!(knobs[i]["key"], json!(k.key));
            assert_eq!(knobs[i]["env"], json!(k.env));
            assert_eq!(knobs[i]["min"], json!(k.min));
            assert_eq!(knobs[i]["max"], json!(k.max));
            let label = knobs[i]["label"].as_str().unwrap_or("");
            assert!(!label.is_empty() && !label.contains('_'),
                    "libellé opérateur attendu (pas un nom de variable) : {label}");
        }
        // les leviers de gouvernance sont annoncés comme NON réglables, avec la raison.
        let gov = v["governed"].as_array().expect("governed");
        assert_eq!(gov.len(), GOVERNED_KNOBS.len());
        assert!(gov.iter().any(|g| g["knob"] == json!("nuclei_severity")));
        assert!(gov.iter().any(|g| g["knob"] == json!("rate_per_sec")));
    }

    /// (g) L'UI DE LANCEMENT est câblée sur ce catalogue : elle ne code en dur NI les défauts de profil
    /// NI la liste des leviers (source de vérité = le moteur via /api/resource-profile). Garde-fou
    /// anti-régression sur les marqueurs du front (le catalogue est fetché, les champs sont générés).
    #[test]
    fn launch_ui_reads_catalog_instead_of_hardcoding() {
        let js = include_str!("../web/js/views/launch/resource.js");
        assert!(js.contains("/resource-profile"), "l'UI n'interroge pas le catalogue serveur");
        assert!(js.contains("collectResourceBody"), "collecte du corps `resource` absente");
        assert!(!js.contains("RES_PRESETS"), "table de profils codée en dur encore présente dans l'UI");
        // aucune valeur de profil recopiée dans le front (les défauts viennent du moteur)
        for lit in ["'medium,high,critical'", "crawl_max_endpoints: 25", "parallelism: 12"] {
            assert!(!js.contains(lit), "valeur de profil dupliquée dans l'UI : {lit}");
        }
        let index = include_str!("../web/index.html");
        assert!(index.contains("id=\"lc-resprofile\""), "sélecteur de profil absent de l'UI");
        assert!(index.contains("id=\"lc-res-overrides\""), "conteneur des overrides par-levier absent");
    }
}


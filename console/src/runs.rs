// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SOUS-SYSTÈME RUN-LIFECYCLE / C2-light extrait de main.rs (PURE MOVE). Regroupe le
//! lancement GOUVERNÉ + AUDITÉ de campagnes depuis l'UI web et tout le cycle de vie d'un run :
//! `run_create` (POST /api/run), `run_cancel` (POST /api/runs/:id/cancel), `runs_list`/`run_detail`/
//! `run_logs`/`run_sse` (lecture + flux SSE), le superviseur détaché (`spawn_supervisor`), le
//! réconciliateur de boot (`reconcile_runs` + `purge_stale_run_dirs`), l'ingestion de scanners
//! existants (`import_scan`, POST /api/import), et la validation de params RUN-SPÉCIFIQUE
//! (`validate_module_params`/`validate_modules`/`high_impact_modules`/`high_impact_gate`) ainsi que les
//! helpers de process POSIX (`spawn_setsid`/`kill_group`), le pousseur de logs (`push_run_log`) et le
//! sérialiseur de run_job (`run_job_json`/`RUN_JOB_COLS`).
//!
//! Les structs d'ÉTAT (App / RunState / RunHandle / RunEvent / Engagement) RESTENT à la racine de crate
//! (stage `state`) et sont référencées via `crate::*`. Réutilise App + les helpers de la racine
//! (`check_operator`/`operator_denied`/`attribution_login`/`append_run_ledger_path`/`chrono_now_compact`/
//! `resolve_engagement`/`host_in_scope_list`/`filter_enabled_modules`/`operator_disabled_modules`/
//! `technique_selection_value_for`/`validate_campaign`/`validate_host`/`gen_token`/`gs`/`extract_cwe`/
//! `cvss_base_for_severity`/`sanitize_filename`/`valid_import_format`/`validate_param_value`/
//! `module_operator_disabled`/`append_console_ledger`/`paginate`/`resolve_view_engagement_id` …) via
//! `use crate::*`, et est re-exporté à la racine par `pub(crate) use crate::runs::*` — les routes de
//! build_router (`post(run_create)`, `post(import_scan)`, `post(run_cancel)`, `get(runs_list)`,
//! `get(run_detail)`, `get(run_logs)`, `get(run_sse)`) ET les tests inline de main.rs (`super::*`)
//! résolvent donc ces handlers/helpers INCHANGÉS. `RUN_JOB_COLS`/`run_job_json` restent consommés par
//! `run_report` (main.rs) via la ré-exportation racine.
use crate::*;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::sync::broadcast;

// ===========================================================================================
// POLITIQUE RÉSEAU (privé/LAN/loopback) — helpers de classification IP (std uniquement, ZÉRO crate).
//
// Ces helpers décident si une CIBLE LITTÉRALE (IP ou CIDR) est privée/LAN/loopback. C'est la 1re
// des deux couches d'enforcement (pré-spawn, Rust) ; la couche AUTORITATIVE (moteur Python roe.py)
// attrape en plus les HOSTNAMES qui RÉSOLVENT en privé (anti-rebinding). L'énumération ci-dessous est
// le MIROIR EXACT de `forge/roe.py::_ip_is_private` : mêmes plages -> verdict IDENTIQUE des deux côtés.
// ===========================================================================================

/// True si l'IPv4 est privée/LAN/loopback/unspecified/CGNAT. `is_private`/`is_loopback`/`is_link_local`/
/// `is_unspecified` sont stables (std) ; CGNAT 100.64/10 et 0.0.0.0/8 sont vérifiés à la main (pas de crate).
pub(crate) fn v4_is_private(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()            // 127.0.0.0/8
        || v4.is_private()      // 10/8, 172.16/12, 192.168/16 (RFC1918, strict)
        || v4.is_link_local()   // 169.254.0.0/16
        || v4.is_unspecified()  // 0.0.0.0 (l'adresse exacte)
        || o[0] == 0            // 0.0.0.0/8 (« this network », au-delà de l'unspecified exact)
        || (o[0] == 100 && (o[1] & 0xC0) == 64) // CGNAT 100.64.0.0/10 (RFC6598)
}

/// True si l'IPv6 est privée/LAN/loopback : ::1, ::, ULA fc00::/7, link-local fe80::/10, et IPv4-mapped
/// ::ffff:a.b.c.d (le verdict se décide alors sur l'IPv4 EMBARQUÉE — autoritatif, mappe vers v4_is_private).
pub(crate) fn v6_is_private(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return v4_is_private(v4);
    }
    let seg = v6.segments();
    v6.is_loopback()                       // ::1
        || v6.is_unspecified()             // ::
        || (seg[0] & 0xfe00) == 0xfc00     // ULA fc00::/7
        || (seg[0] & 0xffc0) == 0xfe80     // link-local fe80::/10
}

/// True si `ip` (déjà parsée) est privée/LAN/loopback.
pub(crate) fn ip_is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_private(v4),
        IpAddr::V6(v6) => v6_is_private(v6),
    }
}

/// True si la CIBLE VALIDÉE est un LITTÉRAL privé : soit une IP nue privée, soit un CIDR dont la BASE est
/// privée (ex: `10.0.0.0/24`). Un HOSTNAME => False (non tranchable ici sans résoudre ; le moteur Python
/// est le juge autoritatif pour les hostnames qui résolvent en privé — anti-rebinding).
pub(crate) fn target_is_private_literal(host: &str) -> bool {
    let h = host.trim();
    if let Ok(ip) = h.parse::<IpAddr>() {          // IP nue
        return ip_is_private(ip);
    }
    if let Some((base, _mask)) = h.split_once('/') {  // CIDR a.b.c.d/n ou v6/n -> base
        if let Ok(ip) = base.trim().parse::<IpAddr>() {
            return ip_is_private(ip);
        }
    }
    false
}

/// GET /api/network-policy — lit le MASTER SWITCH GLOBAL de la politique réseau. ADMIN (check_admin,
/// fail-closed 403). Renvoie `{allow_private: bool}`. C'est le « gros bouton rouge » instance-wide :
/// OFF (défaut) => AUCUN engagement ne peut scanner de cible privée/LAN/loopback (les deux portes doivent
/// être ouvertes ET la cible in-scope). L'UI admin l'affiche + avertit que OFF est le défaut sûr.
pub(crate) async fn network_policy_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    (StatusCode::OK, Json(json!({"allow_private": crate::network_allow_private(&app.store())}))).into_response()
}

/// POST /api/network-policy `{allow_private: bool}` — bascule le MASTER SWITCH GLOBAL. ADMIN (check_admin,
/// fail-closed 403). Persiste `settings.network.allow_private` (on/off) et LEDGERISE
/// `console.settings.network_policy` (actor + old->new). Prend effet IMMÉDIATEMENT (lu à CHAQUE run, sans
/// redémarrage). N'ouvre RIEN à lui seul : un run privé exige AUSSI l'opt-in per-engagement ET le scope.
pub(crate) async fn network_policy_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let new_val = match body.get("allow_private").and_then(|v| v.as_bool()) {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request", "why": "corps attendu : {allow_private: bool}"}))).into_response(),
    };
    let old_val = crate::network_allow_private(&app.store());
    if let Err(e) = crate::settings_set_store(&app.store(), "network.allow_private", if new_val { "on" } else { "off" }) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "settings_write_failed", "why": e}))).into_response();
    }
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.settings.network_policy", json!({
        "actor": actor, "setting": "network.allow_private", "old": old_val, "new": new_val,
        "note": "master switch global — OFF (défaut) = aucun scan de cible privée/LAN/loopback possible (fail-closed)"
    }));
    (StatusCode::OK, Json(json!({"allow_private": new_val, "old": old_val}))).into_response()
}

// ===========================================================================================
// C2-light — lancement GOUVERNÉ + AUDITÉ de campagnes Forge depuis l'UI web.
//
// Modèle de sûreté (non négociable) :
//   1. Rôle OPÉRATEUR fail-closed (check_operator) sur TOUTES les routes C2.
//   2. Validation stricte de l'entrée (campaign regex ; hosts hostname-ou-CIDR sans métacaractères ;
//      modules ⊆ kinds connus ET web_allowed=1).
//   3. PLANCHER EXPLOIT (défaut) : 400 si un module demandé est exploit=1 OU destructive=1. Levé
//      UNIQUEMENT par l'opt-in HAUT-IMPACT GOUVERNÉ : `allow_high_impact=true` honoré seulement si
//      operator authentifié (check_operator) + `arm=true` + `reason` non vide (sinon 400
//      'high_impact_requires_arm_and_reason'). Hors opt-in, le plancher tient comme avant.
//   4. Spawn SANS shell : argv fixe via tokio::process::Command ; scope & targets passés par FICHIERS
//      dans un dir temp par run ; le scope écrit force allow_exploit/allow_destructive = valeur de
//      l'opt-in honoré (false par défaut). L'opt-in ne touche QUE allow_exploit/destructive — JAMAIS
//      in_scope/out_scope : le scope-guard du moteur reste seul juge du périmètre (hors-scope = VETO).
//   5. setsid (process group) -> cancel/watchdog tuent le GROUPE ; watchdog timeout (FORGE_RUN_TIMEOUT).
//   6. FIFO : un seul run vivant à la fois (refus 409 sinon).
//   7. Reconciler au boot : tout run_job 'running' orphelin -> 'failed'.
// ===========================================================================================

/// POST /api/run — démarre une campagne. Corps JSON :
///   {campaign, targets:[host…], modules:[kind…]?, mode:"propose"|"auto"?, budget:num?,
///    exhaustive:bool?, reason:str?, arm:bool?, allow_high_impact:bool?}
/// Auth : X-Forge-Operator (FAIL-CLOSED). Renvoie 202 {run_id, status:"running", high_impact:bool}.
/// Opt-in haut-impact GOUVERNÉ : `allow_high_impact=true` n'est honoré qu'avec operator + `arm=true`
/// + `reason` non vide (sinon 400 'high_impact_requires_arm_and_reason'). Honoré => le plancher
///   exploit est levé (validate_modules) et le scope du run écrit allow_exploit/destructive=true ;
///   l'autorisation est journalisée au ledger. Hors opt-in : comportement actuel inchangé.
pub(crate) async fn run_create(State(app): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    // (1) rôle opérateur fail-closed (+ contrainte source-CIDR si configurée : cf. check_operator)
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j);
    }

    // (1b) ENGAGEMENT CIBLE — le run opère SUR un engagement (objet de 1re classe). `engagement_id`
    // (corps) sélectionne l'engagement ; absent => l'engagement actif le plus ancien (rétro-compat :
    // #1). C'est SON scope (in/out), SON mode et SON ledger qui gouvernent ce run — PAS les App globals
    // (qui ne restent que les défauts de l'engagement #1). Fail-closed : engagement inconnu => 400.
    let engagement_id = body.get("engagement_id").and_then(|v| v.as_i64());
    let eng = match resolve_engagement(&app, &headers, engagement_id) {
        Ok(e) => e,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_engagement", "why": why}))),
    };

    // (1c) ENTERPRISE PER-ENGAGEMENT RBAC (readiness #14) — the caller's EFFECTIVE role on THIS engagement
    // must allow OPERATE (tenant_admin|tenant_operator), most-specific-wins (engagement grant > tenant grant),
    // FAIL-CLOSED. A tenant_viewer (or a user with only a viewer override on this engagement) is DENIED here
    // even though the tenant is visible + they passed the console-global operator gate. Community (flag OFF)
    // => NO-OP (branch skipped, byte-identical). Cross-tenant is already refused by resolve_engagement above.
    if tenancy::enabled(&app) && !tenancy::can_operate_engagement(&app, &headers, eng.id) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "engagement_operator_required",
                        "why": format!("rôle operator requis sur l'engagement #{} (grant per-engagement/tenant insuffisant — fail-closed)", eng.id)})),
        );
    }

    // (2) validation stricte de l'entrée
    let campaign = match validate_campaign(body.get("campaign").and_then(|v| v.as_str()).unwrap_or("")) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_campaign", "why": e}))),
    };
    let targets_in = match body.get("targets").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_targets", "why": "targets[] requis (non vide)"}))),
    };
    // POLITIQUE RÉSEAU (privé/LAN/loopback) — DEUX PORTES CUMULATIVES calculées SERVER-SIDE :
    //   effectif = master GLOBAL (settings.network.allow_private, défaut FALSE) AND opt-in ENGAGEMENT
    //   (engagement.allow_private, défaut FALSE). Fail-closed : si l'une des deux est OFF => pas de scan privé.
    //   Lu à CHAQUE run (aucun cache) -> une bascule admin/opérateur prend effet SANS redémarrage.
    let global_master = crate::network_allow_private(&app.store());
    let allow_private_effective = global_master && eng.allow_private;

    let mut targets: Vec<String> = Vec::new();
    for t in &targets_in {
        let host = t.as_str().unwrap_or("");
        match validate_host(host) {
            Ok(h) => {
                // SCOPE-GUARD DE L'ENGAGEMENT (fail-closed) : le scope du run est restreint au scope
                // de CET engagement (in_scope) — une cible hors du périmètre de l'engagement est refusée
                // AVANT le spawn (le moteur la vétoerait, mais on ne dépense pas de process pour ça et on
                // n'élargit jamais le périmètre). ISOLATION : un run pour l'engagement A valide contre le
                // scope de A UNIQUEMENT — jamais les App globals ni le scope d'un autre engagement.
                if !host_in_scope_list(&eng.scope_in, &h) {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "out_of_scope", "why": format!("'{h}' hors du scope de l'engagement #{}", eng.id)})));
                }
                // POLITIQUE RÉSEAU (fail-closed, pré-spawn) : une cible LITTÉRALE privée/LAN/loopback (IP nue
                // ou CIDR de base privée) est REFUSÉE tant que les DEUX portes ne sont pas ouvertes. On ne
                // dépense aucun process pour ça. Les hostnames qui RÉSOLVENT en privé sont attrapés
                // AUTORITATIVEMENT par le moteur (roe.py, anti-rebinding) — ici on ne tranche que le littéral.
                if !allow_private_effective && target_is_private_literal(&h) {
                    return (StatusCode::BAD_REQUEST, Json(json!({
                        "error": "private_target_blocked",
                        "why": "cible privée/LAN/loopback refusée — active la politique réseau (global + engagement) pour l'autoriser"
                    })));
                }
                targets.push(h);
            }
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_target", "why": e}))),
        }
    }

    // Opt-in haut-impact GOUVERNÉ. Lu AVANT validate_modules car il décide si le plancher exploit
    // tient. `arm` et `reason` sont parsés ici (besoin du gate) — réutilisés tels quels plus bas.
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("").chars().take(200).collect::<String>();
    let arm = body.get("arm").and_then(|v| v.as_bool()).unwrap_or(false);
    let allow_high_impact = body.get("allow_high_impact").and_then(|v| v.as_bool()).unwrap_or(false);
    // GATE : honore l'opt-in seulement si operator (déjà vérifié ci-dessus) + arm=true + reason non
    // vide. Sinon 400 explicite. Ok(false) => plancher exploit inchangé (comportement actuel).
    let high_impact = match high_impact_gate(allow_high_impact, true, arm, &reason) {
        Ok(v) => v,
        Err(e) => return e.into_parts(),
    };

    // modules demandés : ⊆ kinds connus ET web_allowed=1 ; PLANCHER EXPLOIT (exploit|destructive => 400)
    // SAUF si l'opt-in haut-impact est honoré (high_impact=true) — alors exploit/destructif autorisés.
    let requested_modules: Vec<String> = body
        .get("modules")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if let Err(e) = validate_modules(&app, &requested_modules, high_impact) {
        return e.into_parts();
    }

    // params PAR-MODULE (passthrough) : validés (taille/profondeur/NUL/kind bien formé) puis
    // transportés tels quels jusqu'au moteur via scope.json + targets.json (cf. plus bas). Ne
    // touche AUCUN garde-fou : ce sont des paramètres d'exécution, pas des bascules de capacité —
    // allow_exploit/destructive restent forcés false plus bas, quel que soit le contenu des params.
    let module_params = match validate_module_params(&body, &requested_modules) {
        Ok(m) => m,
        Err(e) => return e.into_parts(),
    };
    // DÉFENSE EN PROFONDEUR : echo server-side de l'allowlist de drapeaux (un /api/run crafté ne peut pas
    // injecter un flag interdit dans extra_args, même si le moteur Python le re-refuserait). Fail-closed.
    if let Err(e) = validate_extra_args(&app, &module_params) {
        return e.into_parts();
    }

    let mode = match body.get("mode").and_then(|v| v.as_str()).unwrap_or("propose") {
        "auto" => "auto",
        "propose" => "propose",
        other => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_mode", "why": format!("mode '{other}' invalide (propose|auto)")}))),
    };
    let budget = body.get("budget").and_then(|v| v.as_f64());
    // DÉBIT (rate-limit) OPT-IN per-run : entier positif -> écrit dans scope.json (throttle oracle +
    // drapeaux de débit des outils). Absent/invalide/<=0 => None => défaut 5 (byte-identique). Borné.
    let rate: Option<i64> = body.get("rate").and_then(|v| v.as_i64()).filter(|n| *n > 0 && *n <= 100_000);
    let exhaustive = body.get("exhaustive").and_then(|v| v.as_bool()).unwrap_or(false);
    // --auto-pentest : MODE PENTEST AUTOMATISÉ — balaie TOUTES les techniques ACTIVÉES du scope à
    // travers la surface découverte (recon -> chaînage -> oracles), gouverné À L'IDENTIQUE d'un run
    // normal (scope-guard, plancher exploit, ledger). Ne CHANGE aucun garde-fou : il ne fait qu'élargir
    // le PLAN à l'ensemble effectif du scope (le moteur le re-filtre et le ROE le gate). Défaut : false.
    let auto_pentest = body.get("auto_pentest").and_then(|v| v.as_bool()).unwrap_or(false);
    // RESSOURCES (R3) — profil `low|balanced|full` + overrides par-levier (parallélisme / run-timeout /
    // tools-profile), threadés au moteur via les env vars que R1 lit déjà (précédence override>profil>
    // défaut). CHOIX DE RESSOURCE UNIQUEMENT : ne touche NI le scope, NI le ROE, NI le plancher exploit,
    // NI l'auth (gate operator déjà passé). Fail-open (champ invalide => None => défaut du profil) ;
    // `balanced` sans override => tout None => AUCUNE variable posée => comportement byte-identique.
    let resource = parse_resource_options(&body);
    // `reason`, `arm` et `allow_high_impact`/`high_impact` ont été parsés/évalués plus haut (le gate
    // les exige avant validate_modules). `arm` reste journalisé ; sans opt-in haut-impact honoré il
    // est inerte côté capacité (le scope écrit ci-dessous force allow_*=false dans ce cas).

    // SÉLECTION DE TECHNIQUES PAR-SCOPE — l'intention persistée (profil + toggles catégorie/technique)
    // est injectée dans le scope.json du run. Le moteur en RÉSOUT l'ensemble effectif
    // (resolve_enabled_kinds) et l'ENFORCE : une technique hors-profil/désactivée n'est NI planifiée NI
    // tirée (fail-closed). Une entrée de run explicite `technique_selection` dans le corps override la
    // sélection persistée. ENGAGEMENT : à défaut, la sélection PERSISTÉE est celle de CET engagement.
    // Résolue ICI (stateless, sur n'importe quelle instance) pour figer le spec avant le branchement HA.
    let selection = match body.get("technique_selection") {
        Some(v) if v.is_object() => validate_technique_selection(v).unwrap_or_else(|_| technique_selection_value_for(&app, eng.id)),
        _ => technique_selection_value_for(&app, eng.id),
    };
    // GOUVERNANCE CONNECTEUR : connecteurs DÉSACTIVÉS par l'opérateur (injectés au scope.json + ledger).
    let disabled_modules = operator_disabled_modules(&app);
    // ATTRIBUTION : identité individuelle (session) sinon repli 'operator'. `started_by` encode le compte
    // (+high_impact pour un run armé) -> traçabilité au COMPTE, sans nouvelle colonne. Résolus ICI
    // (stateless) : figés dans le spec pour que le LEADER qui claime un run pending préserve l'attribution.
    let actor = attribution_login(&app, &headers);
    let started_by = if high_impact { format!("{actor}+high_impact") } else { actor.clone() };
    // run_id : horodaté + suffixe aléatoire (traçable, unique). Figé maintenant : le même id est renvoyé
    // au client (202) et réutilisé par le leader s'il claime le run depuis 'pending'.
    let run_id = format!("run-{}-{}", chrono_now_compact(), gen_token().chars().take(8).collect::<String>());

    // SPEC RÉSOLU — capture TOUTE l'entrée validée+résolue (scope de l'engagement, cibles, modules,
    // params, mode, opt-in haut-impact, sélection, attribution). C'est l'UNIQUE source pour `claim_and_spawn`
    // (chemin direct comme chemin claim-pending) : sur le chemin pending il est SÉRIALISÉ dans
    // run_job.spawn_spec pour que le LEADER reconstruise scope.json/targets.json + argv à l'identique.
    let spec = RunSpawnSpec {
        run_id: run_id.clone(),
        eng_id: eng.id,
        eng_mode: eng.mode.clone(),
        eng_scope_out: eng.scope_out.clone(),
        eng_ledger_path: eng.ledger_path.clone(),
        campaign: campaign.clone(),
        targets,
        requested_modules,
        module_params: Value::Object(module_params),
        mode: mode.to_string(),
        budget,
        exhaustive,
        auto_pentest,
        reason,
        arm,
        high_impact,
        started_by,
        actor,
        selection,
        disabled_modules,
        body_targets: body.get("targets").cloned().unwrap_or(json!([])),
        rate,
        allow_private: allow_private_effective,
        resource,
        // CONTEXTE AUTH PAR-ENGAGEMENT (R5b) : le bloc `auth` de CET engagement (validé à l'écriture) est
        // propagé au scope.json du run pour que le moteur (AuthContext.from_scope) alimente les oracles
        // IDOR/ATO en cross-compte. None => aucun champ auth émis (byte-identique). Isolation : le scope du
        // run reste dicté par CET engagement — jamais l'auth d'un autre.
        eng_auth: eng.auth.clone(),
    };

    // ─── BRANCHEMENT RUN-LEADER (HA #10 Wave B) ──────────────────────────────────────────────────────
    // Toute la VALIDATION ci-dessus est STATELESS et correcte sur N'IMPORTE QUELLE instance. L'EXÉCUTION,
    // elle, doit être leader-only sous HA (sinon deux réplicas spawneraient/reaperaient les runs l'un de
    // l'autre). Deux cas :
    //   - non-HA (mono-instance) OU je SUIS le leader : SPAWN DIRECT via claim_and_spawn. En mono-instance
    //     `is_leader` court-circuite à true -> comportement HISTORIQUE byte-identique.
    //   - HA + je ne suis PAS le leader : j'ENQUEUE le run 'pending' (spec sérialisé) et je réponds 202
    //     {status:"pending"} — le LEADER le claime et le spawne (il écrit alors console.run.start). Aucun
    //     ledger console.run.start ici (écrivain unique = le leader, cohérent avec Wave C).
    if !crate::ha::ha_enabled(&app) || crate::ha::is_leader(&app) {
        // FIFO PAR ENGAGEMENT : réserve le slot (cancellation-safe) ; 409 si déjà vivant/réservé pour CET
        // engagement (isolation : un AUTRE engagement n'entrave rien). Puis spawn direct.
        let reservation = match reserve_engagement_slot(&app, eng.id).await {
            Some(r) => r,
            None => return (StatusCode::CONFLICT, Json(json!({"error": "run_in_progress", "engagement_id": eng.id, "why": format!("un run est déjà en cours pour l'engagement #{} (FIFO par engagement : un seul à la fois par engagement)", eng.id)}))),
        };
        claim_and_spawn(&app, &spec, reservation).await
    } else {
        enqueue_pending(&app, &spec)
    }
}

/// POST /api/import — INGESTION de sorties de SCANNERS EXISTANTS (migration Faraday/Trickest/reNgine/
/// Osmedeus). OPÉRATEUR/ADMIN (check_operator, 403 sinon) + LEDGERISÉ (`console.import`). Corps :
///   {campaign, format:"auto"|<fmt>, content:<texte du fichier>, filename?, flag_out_of_scope?}
///
/// GOUVERNANCE — PUR DATA, ZÉRO exécution : le fichier est PARSÉ par le moteur Python (`forge import`,
/// SOURCE UNIQUE des parseurs — pas de re-implémentation Rust qui dériverait) sous le SCOPE SERVEUR
/// autoritatif (roe.Scope, LE scope-guard unique). Les findings d'assets HORS périmètre sont JETÉS
/// (défaut) ou MARQUÉS (`flag_out_of_scope` -> status=skipped). Les secrets du fichier sont RÉDIGÉS par
/// le moteur AVANT tout finding ; le fichier temp est supprimé aussitôt le parse fini (aucun secret ne
/// persiste). Le ledger n'enregistre QUE l'attribution + les COMPTEURS (jamais le contenu). Orienté
/// preuve : les findings importés sont tested/reported_by_tool (jamais `vulnerable`). no-shell (argv FIXE).
pub(crate) async fn import_scan(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // (1) gate opérateur fail-closed (comme /api/run — une ingestion mute l'engagement).
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    // (1b) L9 FIX — ENGAGEMENT CIBLE (parité EXACTE avec run_create). Une ingestion MUTE un engagement :
    // elle DOIT viser un engagement résolu (tenant-aware, fail-closed) et non atterrir aveuglément sur #1.
    // `engagement_id` (corps) sélectionne l'engagement ; absent => l'engagement actif le plus ancien accessible.
    // Cross-tenant (tenant non accordé) => resolve refuse ici (400 bad_engagement) — jamais divulgué.
    let engagement_id = body.get("engagement_id").and_then(|v| v.as_i64());
    let eng = match resolve_engagement(&app, &headers, engagement_id) {
        Ok(e) => e,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_engagement", "why": why}))).into_response(),
    };
    // (1c) L9 FIX — ENTERPRISE PER-ENGAGEMENT RBAC (readiness #14, parité run_create) : le rôle EFFECTIF du
    // caller sur CET engagement doit permettre OPERATE (tenant_admin|tenant_operator), most-specific-wins,
    // FAIL-CLOSED. Un tenant_viewer (ou override viewer sur cet engagement) est REFUSÉ ici même s'il voit le
    // tenant et a passé le gate operator console-global. Community (flag OFF) => NO-OP (byte-identique).
    if tenancy::enabled(&app) && !tenancy::can_operate_engagement(&app, &headers, eng.id) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "engagement_operator_required",
                        "why": format!("rôle operator requis sur l'engagement #{} (grant per-engagement/tenant insuffisant — fail-closed)", eng.id)})),
        ).into_response();
    }
    // (2) validation stricte de l'entrée
    let campaign = match validate_campaign(body.get("campaign").and_then(|v| v.as_str()).unwrap_or("default")) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_campaign", "why": e}))).into_response(),
    };
    let fmt_in = body.get("format").and_then(|v| v.as_str()).unwrap_or("auto").trim().to_string();
    if !valid_import_format(&fmt_in) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_format",
            "why": "format inconnu (nmap|nuclei|burp|httpx|ffuf|hosts|generic-json|generic-csv|auto)"}))).into_response();
    }
    let content = match body.get("content").and_then(|v| v.as_str()) {
        Some(c) if !c.trim().is_empty() => c.to_string(),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_content", "why": "content (texte du fichier de scan) requis"}))).into_response(),
    };
    if content.len() > 64 * 1024 * 1024 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "too_large", "why": "fichier trop volumineux (>64 MiB)"}))).into_response();
    }
    let filename = sanitize_filename(body.get("filename").and_then(|v| v.as_str()).unwrap_or(""));
    let flag_oos = body.get("flag_out_of_scope").and_then(|v| v.as_bool()).unwrap_or(false);

    // (3) écrit le fichier + le SCOPE SERVEUR (autoritatif) dans un dossier temp, PUIS parse via le
    //     moteur Python. Le scope-guard (roe.Scope) filtre les assets hors périmètre au parse.
    let import_dir = std::env::temp_dir().join(format!("forge-import-{}-{}", chrono_now_compact(),
        gen_token().chars().take(8).collect::<String>()));
    if std::fs::create_dir_all(&import_dir).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "mkdir_failed"}))).into_response();
    }
    let file_path = import_dir.join("scan.input");
    let scope_path = import_dir.join("scope.json");
    // L9 FIX — scope AUTORITATIF de L'ENGAGEMENT CIBLE (mode/in_scope/out_scope), plus les App globals (qui
    // ne sont que les défauts de l'engagement #1). Le moteur filtre les findings importés contre le périmètre
    // de CET engagement — comme run_create écrit le scope depuis l'engagement (cf. build_run_scope_doc).
    let scope_doc = json!({
        "_comment": "scope serveur autoritatif — filtre les findings importés hors périmètre (scope-guard fail-closed)",
        "mode": eng.mode,
        "in_scope": eng.scope_in,
        "out_scope": eng.scope_out,
    });
    if std::fs::write(&file_path, content.as_bytes()).is_err()
        || std::fs::write(&scope_path, serde_json::to_vec(&scope_doc).unwrap()).is_err()
    {
        let _ = std::fs::remove_dir_all(&import_dir);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write_failed"}))).into_response();
    }
    // argv FIXE — aucune valeur concaténée à un shell ; le contenu ne transite QUE par un fichier.
    let mut argv: Vec<String> = vec![
        "-m".into(), "forge.cli".into(), "import".into(),
        "--format".into(), fmt_in.clone(),
        "--file".into(), file_path.to_string_lossy().into_owned(),
        "--scope".into(), scope_path.to_string_lossy().into_owned(),
        "--campaign".into(), campaign.clone(),
        "--json".into(),
    ];
    if flag_oos { argv.push("--flag-out-of-scope".into()); }
    // L10 FIX — spawn NON bloquant : `tokio::process::Command(...).output().await` (parité runs_proc/exec) ne
    // stalle plus un worker Tokio pendant que le moteur parse (le parse d'un gros fichier pouvait bloquer le
    // runtime). Comportement identique : `.output()` collecte stdout/stderr/status à l'identique de std.
    let spawn = tokio::process::Command::new(app.python.as_str())
        .args(&argv)
        .current_dir(app.pkg_dir.as_str())
        .stdin(std::process::Stdio::null())
        .output()
        .await;
    // nettoyage IMMÉDIAT — le contenu (secrets potentiels) ne persiste jamais sur disque au-delà du parse.
    let _ = std::fs::remove_dir_all(&import_dir);
    let out = match spawn {
        Ok(o) => o,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "spawn_failed", "why": e.to_string()}))).into_response(),
    };
    if !out.status.success() {
        // stderr rédigé/borné (le moteur n'imprime jamais le contenu ni un secret sur stderr).
        let why = String::from_utf8_lossy(&out.stderr).chars().take(300).collect::<String>();
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "parse_failed", "why": why}))).into_response();
    }
    let env: Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "bad_envelope", "why": e.to_string()}))).into_response(),
    };
    let fmt_detected = env.get("format").and_then(|v| v.as_str()).unwrap_or(fmt_in.as_str()).to_string();
    let counts = env.get("counts").cloned().unwrap_or_else(|| json!({}));

    // (4) INSÈRE les findings (déjà scope-filtrés par le moteur). MÊME dérivation CWE/CVSS que /api/ingest.
    let run_id = format!("import-{}-{}", chrono_now_compact(), gen_token().chars().take(6).collect::<String>());
    let mut ingested = 0i64;
    if let Some(arr) = env.get("findings").and_then(|v| v.as_array()) {
        let store = app.store();
        for f in arr {
            let cwe = { let c = gs(f, "cwe"); if c.is_empty() { extract_cwe(&gs(f, "category")) } else { c } };
            let (mut cvss_vec, mut cvss_score) = (gs(f, "cvss_vector"), f.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0));
            if cvss_vec.is_empty() && cvss_score == 0.0 {
                let (v, s) = cvss_base_for_severity(&gs(f, "severity"));
                cvss_vec = v.to_string();
                cvss_score = s;
            }
            if let Ok(n) = store.execute(
                // L9 FIX — engagement_id EXPLICITE = l'engagement CIBLE résolu (plus de DEFAULT 1 : les findings
                // importés appartiennent à l'engagement visé, pas systématiquement à #1).
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score,engagement_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                &crate::sql_params![gs(f,"ts"), &campaign, gs(f,"target"), gs(f,"title"), gs(f,"severity"),
                    gs(f,"category"), gs(f,"mitre"), gs(f,"status"), gs(f,"evidence"), gs(f,"tool"), gs(f,"poc"),
                    gs(f,"fix"), &run_id, cwe, cvss_vec, cvss_score, eng.id],
            ) {
                ingested += n as i64;
            }
        }
    }

    // (5) LEDGER : attribution + COMPTEURS uniquement — JAMAIS le contenu du fichier ni un secret.
    let actor = attribution_login(&app, &headers);
    append_console_ledger(&app, "console.import", json!({
        "actor": actor, "by": "operator", "campaign": campaign,
        "format": fmt_detected, "requested_format": fmt_in, "filename": filename,
        "run_id": run_id, "flag_out_of_scope": flag_oos,
        "counts": {
            "parsed": counts.get("parsed").cloned().unwrap_or(json!(null)),
            "in_scope": counts.get("in_scope").cloned().unwrap_or(json!(null)),
            "out_of_scope": counts.get("out_of_scope").cloned().unwrap_or(json!(null)),
            "emitted": counts.get("emitted").cloned().unwrap_or(json!(null)),
            "ingested": ingested,
        },
        "note": "import PUR DATA (aucune exécution) ; scope-guard appliqué (hors périmètre jeté/marqué) ; secrets rédigés par le moteur"
    }));

    (StatusCode::OK, Json(json!({
        "ok": true, "format": fmt_detected, "campaign": campaign, "run_id": run_id,
        "counts": counts, "ingested": ingested
    }))).into_response()
}

/// POST /api/runs/:id/cancel — annule un run vivant (kill group). Opérateur fail-closed.
pub(crate) async fn run_cancel(State(app): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Path(id): Path<String>) -> impl IntoResponse {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j);
    }
    // ENTERPRISE PER-ENGAGEMENT RBAC (readiness #14) — un cancel est une ÉCRITURE CROSS-TENANT-CAPABLE (DoS
    // sur l'op en cours d'un AUTRE tenant). Le check_operator console-GLOBAL ci-dessus ne suffit pas : le
    // caller doit AUSSI avoir OPERATE sur l'engagement PROPRIÉTAIRE du run (most-specific-wins, fail-closed —
    // même garde que run_create/finding_update). Community (flag OFF) => NO-OP (branche ignorée, byte-
    // identique). Run inconnu (propriétaire None) => non gardé ici : la branche unknown_run 404 plus bas s'en
    // charge (aucune fuite au-delà de ce que run_detail expose déjà). Non autorisé => 403.
    if tenancy::enabled(&app) {
        if let Some(eid) = owning_engagement_of_run(&app, &id) {
            if !tenancy::can_operate_engagement(&app, &headers, eid) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "engagement_operator_required",
                        "why": format!("rôle operator requis sur l'engagement #{eid} propriétaire du run (grant per-engagement/tenant insuffisant — fail-closed)")})),
                );
            }
        }
    }
    // Recherche du run vivant par run_id (GLOBAL-unique) parmi TOUS les engagements : `current` est
    // maintenant indexé par engagement_id, donc on balaie les valeurs. On ne cible que le pgid du run
    // demandé ; les slots des autres engagements ne sont ni lus ni modifiés (le kill ne vise que ce run).
    let pgid = {
        let st = app.run_state.lock().await;
        st.current.values().find(|h| h.run_id == id).map(|h| h.pgid).unwrap_or(-1)
    };
    // HA (#10 Wave B) — ROUTAGE DU CANCEL. Sous HA un cancel peut arriver sur N'IMPORTE QUEL réplica (LB)
    // alors que le run n'est trackée dans run_state (et killable) que sur son PROPRIÉTAIRE (le leader qui
    // l'a spawné). On route donc TOUT cancel HA par `run_cancel_ha` : il persiste l'intention 'cancelled'
    // (durable) + le ledger, puis killpg MAINTENANT si le run est LOCAL (pgid>1 dans mon run_state), sinon
    // laisse le propriétaire couper via son cancel-watch tick (JAMAIS de killpg cross-host). En mono-instance
    // `ha_enabled` est false -> ce bloc est inerte et le cancel reste LOCAL byte-identique (code ci-dessous).
    if crate::ha::ha_enabled(&app) {
        return run_cancel_ha(&app, &headers, &id, pgid).await;
    }
    if pgid <= 1 {
        // run inconnu ou déjà terminé.
        let exists: bool = {
            let store = app.store();
            store.query_row("SELECT 1 FROM run_job WHERE run_id=?", &crate::sql_params![&id], |_| Ok(())).is_ok()
        };
        return if exists {
            (StatusCode::CONFLICT, Json(json!({"error": "not_running", "why": "le run n'est pas en cours"})))
        } else {
            (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"})))
        };
    }
    // marque 'cancelled' AVANT le kill, mais SEULEMENT si le run est encore 'running' (UPDATE
    // conditionnel : course cancel vs finalisation superviseur — on ne ré-ouvre pas un run déjà
    // terminal en 'cancelled'). Le superviseur, lui, préserve 'cancelled' s'il le voit posé.
    {
        let store = app.store();
        let _ = store.execute("UPDATE run_job SET status='cancelled' WHERE run_id=? AND status='running'", &crate::sql_params![&id]);
    }
    let actor = attribution_login(&app, &headers);
    push_run_log(&app, &id, "system", &format!("cancel demandé par '{actor}' — kill group (SIGTERM→SIGKILL)"));
    // ledger de L'ENGAGEMENT propriétaire du run (isolation) — pas systématiquement App.ledger_path.
    let cancel_ledger = engagement_ledger_for_run(&app, &id);
    append_run_ledger_path(&app, &cancel_ledger, "console.run.cancel", json!({"run_id": id, "actor": actor, "by": "operator"}));
    // ARRÊT RÉEL DU MOTEUR (fix E4) — un cancel ne se contentait que de marquer la base : le moteur
    // détaché continuait de tourner (il relançait des outils). On coupe VRAIMENT :
    //   1) SIGTERM IMMÉDIAT au GROUPE (`kill_group`) — le handler D1 du moteur flushe le travail en vol
    //      (findings/couverture partielle) puis sort proprement ; son handler reape aussi ses outils en
    //      SESSIONS séparées (start_new_session) qui, sinon, ÉCHAPPENT au SIGTERM whole-run.
    //   2) ESCALADE SIGKILL après grâce (`escalate_kill_group`, DÉTACHÉE pour ne pas bloquer le handler
    //      HTTP) : si le moteur est wedgé et ne sort pas dans les temps, le SIGKILL du groupe le tue à
    //      coup sûr. Le superviseur récolte l'enfant (`child.wait`) et préserve le statut 'cancelled'
    //      déjà posé. Idempotent/fail-safe : pgid déjà mort -> signaux avalés (ESRCH), aucun panic.
    kill_group(pgid);
    let grace = std::time::Duration::from_secs(crate::runs_proc::CANCEL_GRACE_SECS);
    tokio::spawn(async move { crate::runs_proc::escalate_kill_group(pgid, grace).await; });
    (StatusCode::OK, Json(json!({"run_id": id, "status": "cancelling"})))
}

/// Sérialise un run_job en JSON (vue détaillée / liste).
pub(crate) fn run_job_json(r: &crate::store::Row) -> crate::store::StoreResult<Value> {
    Ok(json!({
        "run_id": r.get_str(0)?,
        "campaign": r.get_opt_str(1)?.unwrap_or_default(),
        "ts": r.get_opt_str(2)?.unwrap_or_default(),
        "status": r.get_opt_str(3)?.unwrap_or_default(),
        "mode": r.get_opt_str(4)?.unwrap_or_default(),
        "fired": r.get_opt_i64(5)?.unwrap_or(0),
        "dry_run": r.get_opt_i64(6)?.unwrap_or(0),
        "vetoed": r.get_opt_i64(7)?.unwrap_or(0),
        "errors": r.get_opt_i64(8)?.unwrap_or(0),
        "skipped_budget": serde_json::from_str::<Value>(&r.get_opt_str(9)?.unwrap_or_else(|| "[]".into())).unwrap_or(json!([])),
        "coverage_gaps": serde_json::from_str::<Value>(&r.get_opt_str(10)?.unwrap_or_else(|| "{}".into())).unwrap_or(json!({})),
        "started_by": r.get_opt_str(11)?.unwrap_or_default(),
        "reason": r.get_opt_str(12)?.unwrap_or_default(),
        "targets": serde_json::from_str::<Value>(&r.get_opt_str(13)?.unwrap_or_else(|| "[]".into())).unwrap_or(json!([])),
        "modules": serde_json::from_str::<Value>(&r.get_opt_str(14)?.unwrap_or_else(|| "[]".into())).unwrap_or(json!([])),
        "started": r.get_opt_str(15)?.unwrap_or_default(),
        "finished": r.get_opt_str(16)?.unwrap_or_default(),
        "exit_code": r.get_opt_i64(17)?,
    }))
}

pub(crate) const RUN_JOB_COLS: &str = "run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,skipped_budget,coverage_gaps,started_by,reason,targets,modules,started,finished,exit_code";

/// GET /api/runs — liste les runs (récents d'abord). Lecture (viewer) — pas besoin d'opérateur.
pub(crate) async fn runs_list(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : liste des runs de l'engagement actif UNIQUEMENT (isolation).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    
    // `engagement_id` (entier résolu) LIÉ en 1er Param ; RUN_JOB_COLS est une const de colonnes FIXES
    // (identifiants, non paramétrables). LIMIT/OFFSET (entiers clampés) LIÉS en derniers placeholders.
    let (mut conds, mut params): (Vec<String>, Vec<crate::store::Param>) =
        (vec!["engagement_id=?".into()], vec![crate::store::Param::Int(eid)]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?".into()); params.push(crate::store::Param::Text(c.clone())); }
    if let Some(s) = q.get("status") { conds.push("status=?".into()); params.push(crate::store::Param::Text(s.clone())); }
    let where_ = format!(" WHERE {}", conds.join(" AND "));
    let (limit, offset) = paginate(&q, 100, 1000);
    params.push(crate::store::Param::Int(limit));
    params.push(crate::store::Param::Int(offset));
    let sql = format!("SELECT {RUN_JOB_COLS} FROM run_job{where_} ORDER BY id DESC LIMIT ? OFFSET ?");
    // query_lax reproduit `query_map(..).filter_map(|r| r.ok())` (lignes malformées ignorées) ; une erreur
    // de prepare/bind PROPAGE (Err) -> unwrap_or_default() rend `[]`, identique à l'ancien `Err(_) => []`.
    let out: Vec<Value> = app.store().query_lax(&sql, &params, run_job_json).unwrap_or_default();
    Json(Value::Array(out))
}

/// GET /api/runs/:id — détail d'un run. Lecture (viewer). ISOLATION cross-tenant (enterprise, fail-closed) :
/// un run d'un tenant non accordé => 404 (indistinguable d'un run inconnu — pas d'oracle d'existence).
pub(crate) async fn run_detail(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Some(deny) = run_read_denied(&app, &headers, &id) {
        return deny;
    }
    let store = app.store();
    let sql = format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?");
    // query_row rend Err(NoRows) sur résultat vide (miroir de QueryReturnedNoRows) -> branche 404 inchangée.
    match store.query_row(&sql, &crate::sql_params![&id], run_job_json) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"}))).into_response(),
    }
}

/// GET /api/runs/:id/logs?after=ID — lignes de log d'un run (fallback polling de SSE).
/// `after` (id de ligne) permet l'incrémental ; renvoie {last_id, lines:[{id,ts,stream,line}]}.
/// ISOLATION cross-tenant (enterprise, fail-closed) : `run_log` n'a pas de colonne engagement_id, donc la
/// garde résout le propriétaire via run_job (== JOIN run_log→run_job) ; un run d'un tenant non accordé => 404
/// (aucune ligne de stdout/stderr brut d'un autre tenant ne fuit).
pub(crate) async fn run_logs(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(deny) = run_read_denied(&app, &headers, &id) {
        return deny;
    }
    let after = q.get("after").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(2000).clamp(1, 5000);
    
    let mut last = after;
    let lines: Vec<Value> = app.store()
        .query_lax(
            "SELECT id,ts,stream,line FROM run_log WHERE run_id=? AND id>? ORDER BY id LIMIT ?",
            &crate::sql_params![&id, after, limit],
            |r| {
                let lid = r.get_i64(0)?;
                Ok((lid, json!({
                    "id": lid,
                    "ts": r.get_opt_str(1)?.unwrap_or_default(),
                    "stream": r.get_opt_str(2)?.unwrap_or_default(),
                    "line": r.get_opt_str(3)?.unwrap_or_default(),
                })))
            },
        )
        .unwrap_or_default()
        .into_iter()
        .map(|(lid, v)| { if lid > last { last = lid; } v })
        .collect();
    Json(json!({"last_id": last, "lines": lines})).into_response()
}

/// GET /api/runs/:id/events — flux SSE des lignes de log + transitions de statut d'un run.
/// Events : `log` ({stream,line}) et `status` ({status,exit_code?}). Fallback : /api/runs/:id/logs.
/// Diffuse les events broadcast filtrés sur run_id. Termine quand le statut devient terminal.
pub(crate) async fn run_sse(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    // ISOLATION cross-tenant (enterprise, fail-closed) : la garde s'exécute AVANT d'ouvrir le flux — un run
    // d'un tenant non accordé => 404, aucun event live d'un autre tenant n'est jamais diffusé. No-op community.
    if let Some(deny) = run_read_denied(&app, &headers, &id) {
        return deny;
    }
    let rx = app.events.subscribe();
    let stream = futures_util::stream::unfold((rx, id, false), |(mut rx, id, mut done)| async move {
        if done {
            return None;
        }
        loop {
            match rx.recv().await {
                Ok(ev) if ev.run_id == id => {
                    if ev.kind == "status" {
                        let s = ev.payload.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        if matches!(s, "done" | "failed" | "timeout" | "cancelled") {
                            done = true;
                        }
                    }
                    let event = Event::default().event(ev.kind.clone()).json_data(&ev.payload).unwrap_or_else(|_| Event::default().comment("bad"));
                    // `Infallible` explicite : le handler renvoie désormais `Response` (au lieu de
                    // `Sse<impl Stream<Item=Result<Event, Infallible>>>`), donc plus rien ne pinne l'erreur du
                    // stream -> on l'annote ici (le flux SSE est infaillible : aucune branche ne produit Err).
                    return Some((Ok::<Event, Infallible>(event), (rx, id, done)));
                }
                Ok(_) => continue, // évènement d'un autre run
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // le consommateur SSE a pris du retard et a PERDU `n` évènements (buffer broadcast
                    // débordé). On émet un event `lag` explicite -> le client sait qu'il a un trou et
                    // peut se resynchroniser via /api/runs/:id/logs?after=... (au lieu d'un silence).
                    let event = Event::default().event("lag")
                        .json_data(json!({"dropped": n}))
                        .unwrap_or_else(|_| Event::default().comment("lag"));
                    return Some((Ok(event), (rx, id, done)));
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("keep-alive")).into_response()
}

// =====================================================================================
// TESTS — ISOLATION CROSS-TENANT des routes RUN-KEYED (IDOR fix). Vérifient les 3 propriétés exigées :
//   (a) ENTERPRISE ON : un caller accordé UNIQUEMENT sur l'engagement A obtient 404 sur detail/report/logs
//       (SSE identique — même garde en tête) d'un run appartenant à l'engagement B, et 403 sur cancel de B.
//   (b) le PROPRIÉTAIRE (accordé sur B) passe la garde (200 en lecture ; cancel non-403 -> 409 not_running).
//   (c) COMMUNITY (flag OFF) : TOUTES les routes se comportent EXACTEMENT comme avant (aucune régression).
// =====================================================================================
#[cfg(test)]
mod idor_tenancy_tests {
    use super::*;
    use crate::testutil::{bearer_headers, resp_json, uid_of};
    use rusqlite::Connection;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::Mutex as AsyncMutex;

    fn test_app() -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        crate::migrate(&conn);
        let (events, _) = broadcast::channel::<crate::RunEvent>(64);
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
            ledger_path: Arc::new(String::new()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(RunState { current: HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(crate::LedgerHead::default())),
        }
    }

    /// Engagement `id` appartenant au tenant `tid`, actif. Sème aussi la ligne `tenant` correspondante.
    fn seed_engagement(app: &App, id: i64, tid: i64) {
        let db = app.db();
        db.execute(
            "INSERT INTO tenant(id,name,status,created,updated) VALUES(?,?, 'active',datetime('now'),datetime('now'))
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![tid, format!("tenant-{tid}")],
        )
        .unwrap();
        db.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,tenant_id,created,updated)
             VALUES(?,?, 'active','grey','{\"in_scope\":[\"a.example.com\"]}','',?,datetime('now'),datetime('now'))",
            rusqlite::params![id, format!("eng-{id}"), tid],
        )
        .unwrap();
        drop(db); // relâche le guard DB tôt (clippy::significant_drop_tightening)
    }

    /// run_job `run_id` appartenant à l'engagement `eid`, statut `status`. Sème une ligne de log associée.
    fn seed_run(app: &App, run_id: &str, eid: i64, status: &str) {
        let db = app.db();
        db.execute(
            "INSERT INTO run_job(run_id,campaign,ts,status,engagement_id) VALUES(?,?,datetime('now'),?,?)",
            rusqlite::params![run_id, "camp", status, eid],
        )
        .unwrap();
        db.execute(
            "INSERT INTO run_log(run_id,ts,stream,line) VALUES(?,datetime('now'),'stdout','SECRET-B-LOG-LINE')",
            rusqlite::params![run_id],
        )
        .unwrap();
        drop(db); // relâche le guard DB tôt (clippy::significant_drop_tightening)
    }

    /// Crée un compte + session ; accorde `role` sur le tenant `tid`. Renvoie le token de session.
    fn user_with_tenant_grant(app: &App, login: &str, console_role: &str, tid: i64, tenant_role: &str) -> String {
        {
            let db = app.db();
            crate::upsert_user(&db, login, console_role, &crate::hash_pw("pw")).unwrap();
            db.execute(
                "INSERT INTO tenant_grant(user_id,tenant_id,role,created)
                 SELECT id,?,?,datetime('now') FROM users WHERE login=?",
                rusqlite::params![tid, tenant_role, login],
            )
            .unwrap();
        }
        let (tok, _) = create_session(app, uid_of(app, login));
        tok
    }

    fn enable_tenancy(app: &App) {
        let db = app.db();
        crate::settings_set(&db, "enterprise.tenancy", "on").unwrap();
    }
    fn disable_tenancy(app: &App) {
        let db = app.db();
        db.execute("DELETE FROM settings WHERE key='enterprise.tenancy'", []).unwrap();
    }

    fn q_fmt(fmt: &str) -> Query<HashMap<String, String>> {
        let mut m = HashMap::new();
        m.insert("format".to_string(), fmt.to_string());
        Query(m)
    }

    /// (a) ENTERPRISE ON — un caller accordé UNIQUEMENT sur A obtient 404 sur detail/report/logs d'un run de B,
    /// et 403 sur cancel de B ; AUCUNE donnée de B (log brut, run_id) ne fuit dans le corps.
    #[tokio::test]
    async fn cross_tenant_run_reads_are_404_and_cancel_is_403() {
        let app = test_app();
        seed_engagement(&app, 1, 1); // engagement A -> tenant 1
        seed_engagement(&app, 2, 2); // engagement B -> tenant 2
        seed_run(&app, "run-B", 2, "running");
        enable_tenancy(&app);
        // alice : operator console + grant tenant_operator sur le tenant 1 UNIQUEMENT (rien sur le tenant 2).
        let atok = user_with_tenant_grant(&app, "alice", "operator", 1, "tenant_operator");
        let h = bearer_headers(&atok);

        // detail -> 404 (indistinguable d'un run inconnu).
        let r = run_detail(State(app.clone()), h.clone(), Path("run-B".into())).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "detail cross-tenant -> 404");
        let body = resp_json(r).await;
        assert_eq!(body["error"], "unknown_run", "aucune existence divulguée");

        // report -> 404, aucune donnée de B.
        let r = run_report(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("md")).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "report cross-tenant -> 404");

        // logs -> 404, la ligne brute SECRET-B-LOG-LINE ne fuit jamais.
        let r = run_logs(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("")).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "logs cross-tenant -> 404");
        let txt = serde_json::to_string(&resp_json(r).await).unwrap();
        assert!(!txt.contains("SECRET-B-LOG-LINE"), "stdout brut de B ne fuit pas");

        // sse -> 404 (garde AVANT ouverture du flux).
        let r = run_sse(State(app.clone()), h.clone(), Path("run-B".into())).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "sse cross-tenant -> 404");

        // cancel (ÉCRITURE) -> 403 (autorisation par-engagement refusée).
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = run_cancel(State(app.clone()), axum::extract::ConnectInfo(peer), h.clone(), Path("run-B".into())).await;
        let resp = r.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "cancel cross-tenant -> 403");
        let body = resp_json(resp).await;
        assert_eq!(body["error"], "engagement_operator_required");
    }

    /// (b) ENTERPRISE ON — le PROPRIÉTAIRE (accordé sur B) passe la garde : 200 en lecture ; cancel non-403.
    #[tokio::test]
    async fn owner_of_run_still_authorized() {
        let app = test_app();
        seed_engagement(&app, 2, 2);
        seed_run(&app, "run-B", 2, "running");
        enable_tenancy(&app);
        let btok = user_with_tenant_grant(&app, "bob", "operator", 2, "tenant_operator");
        let h = bearer_headers(&btok);

        let r = run_detail(State(app.clone()), h.clone(), Path("run-B".into())).await;
        assert_eq!(r.status(), StatusCode::OK, "detail par le propriétaire -> 200");

        let r = run_report(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("md")).await;
        assert_eq!(r.status(), StatusCode::OK, "report par le propriétaire -> 200");

        let r = run_logs(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("")).await;
        assert_eq!(r.status(), StatusCode::OK, "logs par le propriétaire -> 200");
        let txt = serde_json::to_string(&resp_json(r).await).unwrap();
        assert!(txt.contains("SECRET-B-LOG-LINE"), "le propriétaire voit bien ses logs");

        // cancel : la garde per-engagement PASSE (non-403). Sans process vivant -> 409 not_running (preuve
        // que l'autorisation a été accordée et que le flux a atteint la logique de cancel).
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = run_cancel(State(app.clone()), axum::extract::ConnectInfo(peer), h.clone(), Path("run-B".into())).await;
        let resp = r.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "cancel autorisé -> pas de run vivant -> 409");
        let body = resp_json(resp).await;
        assert_eq!(body["error"], "not_running", "authz passée : on atteint la logique cancel");
    }

    /// (c) COMMUNITY (flag OFF) — le MÊME caller « étranger » accède à TOUT (aucune régression) : la garde est
    /// un NO-OP byte-identique. detail/report/logs -> 200 ; cancel -> 409 not_running (jamais 403).
    #[tokio::test]
    async fn community_flag_off_no_regression() {
        let app = test_app();
        seed_engagement(&app, 1, 1);
        seed_engagement(&app, 2, 2);
        seed_run(&app, "run-B", 2, "running");
        // tenancy VOLONTAIREMENT non activée (community). alice n'a AUCUN grant — sans effet en community.
        let atok = user_with_tenant_grant(&app, "alice", "operator", 1, "tenant_operator");
        disable_tenancy(&app); // s'assure que le flag est OFF
        let h = bearer_headers(&atok);

        let r = run_detail(State(app.clone()), h.clone(), Path("run-B".into())).await;
        assert_eq!(r.status(), StatusCode::OK, "community: detail servi (no-op)");
        let r = run_report(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("md")).await;
        assert_eq!(r.status(), StatusCode::OK, "community: report servi (no-op)");
        let r = run_logs(State(app.clone()), h.clone(), Path("run-B".into()), q_fmt("")).await;
        assert_eq!(r.status(), StatusCode::OK, "community: logs servis (no-op)");
        let r = run_sse(State(app.clone()), h.clone(), Path("run-B".into())).await;
        // SSE community : la garde ne court-circuite pas -> flux ouvert (200 OK, content-type event-stream).
        assert_eq!(r.status(), StatusCode::OK, "community: sse ouvert (no-op)");

        // cancel en community : gouverné par check_operator SEUL -> pas de 403 per-engagement -> 409 not_running.
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = run_cancel(State(app.clone()), axum::extract::ConnectInfo(peer), h.clone(), Path("run-B".into())).await;
        let resp = r.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "community: cancel -> 409 not_running (jamais 403)");
    }

    /// L9 — ENTERPRISE ON : un import CIBLANT l'engagement d'un AUTRE tenant est REFUSÉ (résolution tenant-
    /// aware fail-closed, comme run_create) AVANT tout spawn/insertion. Aucun finding n'atterrit dans
    /// l'engagement de B (le défaut historique faisait tomber les findings importés sur l'engagement #1).
    #[tokio::test]
    async fn cross_tenant_import_is_refused() {
        let app = test_app();
        seed_engagement(&app, 1, 1); // engagement A -> tenant 1
        seed_engagement(&app, 2, 2); // engagement B -> tenant 2
        enable_tenancy(&app);
        // alice : operator console + tenant_operator sur le tenant 1 UNIQUEMENT (rien sur le tenant 2).
        let atok = user_with_tenant_grant(&app, "alice", "operator", 1, "tenant_operator");
        let h = bearer_headers(&atok);

        let body = json!({"engagement_id": 2, "campaign": "camp", "format": "auto", "content": "1.2.3.4"});
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = import_scan(State(app.clone()), axum::extract::ConnectInfo(peer), h.clone(), Json(body)).await;
        let resp = r.into_response();
        // REFUS : la résolution tenant-aware rejette l'engagement cross-tenant AVANT le spawn (400 bad_engagement).
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "import cross-tenant -> refusé (jamais 200)");
        let jb = resp_json(resp).await;
        assert_eq!(jb["error"], "bad_engagement", "refus au stade résolution d'engagement (fail-closed)");

        // AUCUN finding n'a été inséré dans l'engagement de B (ni ailleurs) — l'import n'a rien muté.
        let n_b: i64 = { let s = app.store(); s.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=2", &[], |r| r.get_i64(0)).unwrap_or(-1) };
        assert_eq!(n_b, 0, "aucun finding importé dans l'engagement de B");
    }

    /// L8 — DELETE-THEN-ATTEST : si la cascade de suppression ÉCHOUE (rollback), AUCUNE attestation n'est
    /// écrite dans le ledger DÉDIÉ (le défaut précédent appendait `console.engagement.delete` AVANT la
    /// transaction, attestant un delete qui n'a jamais eu lieu). On force l'échec en supprimant `run_job`
    /// (une des cibles du DELETE) : la tx part en erreur -> 500 -> le ledger reste vierge et la ligne survit.
    #[tokio::test]
    async fn delete_rollback_writes_no_attestation() {
        let app = test_app();
        // Ledger DÉDIÉ sur disque (fichier temp), pré-ensemencé d'une ligne quelconque (il EXISTE déjà).
        let led = std::env::temp_dir().join(format!("forge-l8-ledger-{}.jsonl", std::process::id()));
        let led_s = led.to_string_lossy().to_string();
        std::fs::write(&led, b"{\"kind\":\"engagement.start\"}\n").unwrap();
        // Engagement #2 ARCHIVÉ (esquive la garde « dernier actif ») avec SON ledger dédié.
        {
            let db = app.db();
            db.execute(
                "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
                 VALUES(2,'eng-2','archived','grey','{\"in_scope\":[\"a.example.com\"]}',?,datetime('now'),datetime('now'))",
                rusqlite::params![led_s],
            ).unwrap();
            // Supprime la table `run_job` : la cascade `DELETE FROM run_job` échouera -> with_tx ROLLBACK.
            db.execute("DROP TABLE run_job", []).unwrap();
        }

        let res = engagement_do_delete(&app, 2, "tester");
        // La suppression a ÉCHOUÉ (rollback) -> 500.
        assert!(res.is_err(), "la cascade doit échouer (run_job absente)");
        assert_eq!(res.err().unwrap().0, StatusCode::INTERNAL_SERVER_ERROR, "-> 500 sur échec cascade");

        // Le ledger dédié NE contient PAS d'attestation de delete (delete-then-attest : jamais atteint).
        let content = std::fs::read_to_string(&led).unwrap();
        assert!(!content.contains("console.engagement.delete"),
            "aucune attestation de delete ne doit être écrite quand la cascade rollback");

        // La ligne engagement #2 a SURVÉCU (rollback) — l'état est cohérent.
        let still: i64 = { let s = app.store(); s.query_row("SELECT COUNT(*) FROM engagement WHERE id=2", &[], |r| r.get_i64(0)).unwrap_or(-1) };
        assert_eq!(still, 1, "l'engagement doit survivre au rollback");
        let _ = std::fs::remove_file(&led);
    }
}

// =====================================================================================
// TESTS — POLITIQUE RÉSEAU (privé/LAN/loopback) : classification IP LITTÉRALE (fonctions PURES).
// Prouve que `target_is_private_literal` bloque exactement l'énumération exigée (miroir de roe.py) et
// laisse passer le PUBLIC — c'est la 1re couche (pré-spawn Rust ; le moteur Python attrape la résolution).
// =====================================================================================
#[cfg(test)]
mod network_policy_ip_tests {
    use super::{ip_is_private, target_is_private_literal};
    use std::net::IpAddr;

    fn priv_ip(s: &str) -> bool {
        ip_is_private(s.parse::<IpAddr>().expect("ip"))
    }

    #[test]
    fn private_v4_literals_are_flagged() {
        for ip in ["127.0.0.1", "127.5.5.5", "10.0.0.5", "10.255.255.255",
                   "172.16.0.9", "172.31.255.1", "192.168.1.1", "169.254.1.1",
                   "0.0.0.0", "0.1.2.3", "100.64.0.1", "100.127.255.255"] {
            assert!(priv_ip(ip), "{ip} devait être classé privé");
        }
    }

    #[test]
    fn public_v4_literals_are_not_flagged() {
        // dont les plages DOCUMENTATION RFC5737 (utilisées comme « faux public » dans les tests) : NON bloquées.
        for ip in ["93.184.216.34", "8.8.8.8", "1.1.1.1", "203.0.113.10",
                   "198.51.100.5", "192.0.2.5", "172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.0"] {
            assert!(!priv_ip(ip), "{ip} devait être classé public");
        }
    }

    #[test]
    fn private_v6_literals_are_flagged() {
        for ip in ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1",
                   "::ffff:127.0.0.1", "::ffff:10.0.0.5", "::ffff:192.168.1.1"] {
            assert!(priv_ip(ip), "{ip} devait être classé privé");
        }
    }

    #[test]
    fn public_v6_literals_are_not_flagged() {
        for ip in ["2001:4860:4860::8888", "::ffff:93.184.216.34", "2606:4700:4700::1111"] {
            assert!(!priv_ip(ip), "{ip} devait être classé public");
        }
    }

    #[test]
    fn cidr_base_decides_literal_verdict() {
        assert!(target_is_private_literal("10.0.0.0/24"), "CIDR de base privée -> bloqué");
        assert!(target_is_private_literal("192.168.0.0/16"), "CIDR RFC1918 -> bloqué");
        assert!(target_is_private_literal("fc00::/7"), "CIDR ULA -> bloqué");
        assert!(!target_is_private_literal("93.184.216.0/24"), "CIDR public -> non bloqué");
    }

    #[test]
    fn hostnames_are_not_literal_private() {
        // un hostname (même s'il résout en privé) n'est PAS tranché ici : c'est le moteur Python (roe.py)
        // qui l'attrape autoritativement via getaddrinfo. La couche Rust ne juge QUE le littéral.
        for h in ["example.com", "localhost", "internal.corp", "rebind.attacker.test"] {
            assert!(!target_is_private_literal(h), "{h} n'est pas un littéral -> non bloqué côté Rust");
        }
    }
}

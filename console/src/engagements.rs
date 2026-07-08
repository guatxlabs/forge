// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SOUS-SYSTÈME ENGAGEMENT (objet de 1re classe) extrait de main.rs (PURE MOVE). Regroupe
//! le CRUD gouverné + audité des engagements et la RÉSOLUTION de scope/engagement partagée par le run flow
//! et les vues : le pré-filtre de scope serveur (`host_in_server_scope`/`host_in_scope_list`, fonction PURE
//! fail-closed), la résolution de l'engagement CIBLE d'un run (`resolve_engagement`), de la LECTURE
//! (`resolve_view_engagement_id`) et d'une MUTATION par-engagement (`resolve_mutation_engagement_id`), la
//! dérivation SERVEUR du ledger dédié (`derive_engagement_ledger_path`, anti write-anywhere), la validation
//! PURE du scope (`validate_engagement_scope`), la sérialisation de la liste (`engagement_list_json`) et les
//! handlers HTTP `engagements_list` (GET /api/engagements), `engagements_create` (POST /api/engagements) et
//! `engagements_update` (POST /api/engagements/:id) avec leurs cœurs `engagement_do_update`/
//! `engagement_do_delete`.
//!
//! Les structs d'ÉTAT (App / Engagement) RESTENT à la racine de crate (stage `state`) et sont référencées
//! via `crate::*`. Réutilise App + les helpers de la racine (`load_engagement`/`attribution_login`/
//! `check_operator`/`operator_denied`/`check_admin`/`admin_denied`/`append_console_ledger`/
//! `append_run_ledger_path`/`ledger_append_standalone`/`valid_engagement_name`/`valid_scope_entry`/
//! `technique_selection_key`/`workflows_key`/`tenancy`/`compliance` …) via `use crate::*`, et est re-exporté
//! à la racine par `pub(crate) use crate::engagements::*` — les routes de build_router
//! (`get(engagements_list).post(engagements_create)`, `post(engagements_update)`), les appelants
//! inter-modules (`crate::resolve_view_engagement_id`, `crate::resolve_mutation_engagement_id`,
//! `crate::resolve_engagement`, `crate::host_in_server_scope`, `crate::host_in_scope_list` …) ET les tests
//! inline de main.rs (`super::*`) résolvent donc ces handlers/helpers INCHANGÉS.
use crate::*;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Vrai si l'hôte appartient au scope serveur (in_scope). Match littéral exact ou suffixe de domaine
/// (sous-domaine d'une entrée listée). Conservateur : pas de glob côté console — le moteur Python
/// applique le vrai matching ROE, ceci n'est qu'un pré-filtre fail-closed pour ne pas spawner hors scope.
pub(crate) fn host_in_server_scope(app: &App, host: &str) -> bool {
    host_in_scope_list(&app.scope_in, host)
}

/// Appartenance d'un host à une liste in_scope ARBITRAIRE (match exact, suffixe de domaine, wildcard
/// `*.`). Fail-closed : liste VIDE => faux (rien n'est lançable). C'est la règle unique partagée par le
/// pré-filtre /api/run (scope de l'ENGAGEMENT résolu — jamais les App globals) et host_in_server_scope
/// (rétro-compat lecture). Fonction PURE (testable sans App).
pub(crate) fn host_in_scope_list(scope_in: &[String], host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    if scope_in.is_empty() {
        return false; // fail-closed : scope vide => rien n'est lançable
    }
    scope_in.iter().any(|p| {
        let p = p.to_ascii_lowercase();
        let p = p.strip_prefix("*.").unwrap_or(&p);
        h == p || h.ends_with(&format!(".{p}"))
    })
}

/// Résout l'engagement CIBLE d'un run. `requested` (corps/query `engagement_id`) => cet engagement
/// précis (erreur si introuvable). Absent => l'engagement ACTIF le plus ancien (status='active'),
/// sinon le plus ancien tout court (rétro-compat : engagement #1). C'est CET engagement (son scope,
/// son mode, son ledger) que le run flow consomme — JAMAIS les App globals (qui restent seulement les
/// défauts de l'engagement #1 pour la rétro-compat). Verrouille et libère son propre lock DB.
pub(crate) fn resolve_engagement(app: &App, headers: &HeaderMap, requested: Option<i64>) -> Result<Engagement, String> {
    // ENTERPRISE (flag-gated) : un run ne peut cibler QUE un engagement d'un tenant accordé (fail-closed —
    // resolve avant tout spawn). Les checks tenant verrouillent/relâchent leur propre lock DB, on ne les
    // appelle donc PAS en tenant `app.db()`. Community => branche historique EXACTE (byte-identique).
    if tenancy::enabled(app) {
        let id = tenancy::run_engagement_id(app, headers, requested)?;
        let db = app.db();
        return load_engagement(&db, id).ok_or_else(|| format!("engagement {id} introuvable"));
    }
    let db = app.db();
    let id = match requested {
        Some(id) => id,
        None => db
            .query_row(
                "SELECT id FROM engagement WHERE status='active' ORDER BY id LIMIT 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .or_else(|_| {
                db.query_row("SELECT id FROM engagement ORDER BY id LIMIT 1", [], |r| r.get::<_, i64>(0))
            })
            .map_err(|_| "aucun engagement provisionné".to_string())?,
    };
    load_engagement(&db, id).ok_or_else(|| format!("engagement {id} introuvable"))
}

// =====================================================================================
// ENGAGEMENT — sélecteur d'engagement ACTIF (lecture) + CRUD gouverné (objet de 1re classe).
//
// « Engagement actif » : mécanisme le plus simple et sans état serveur — les endpoints LECTURE/écriture
// acceptent `?engagement=<id>` ; à défaut, l'engagement ACTIF le plus récent. Le SPA persiste l'id côté
// client (localStorage) et l'ajoute à CHAQUE requête. Les vues (findings/runrecords/roe/ledger/coverage/
// runs) FILTRENT strictement sur cet id -> un engagement ne voit JAMAIS les données d'un autre.
//
// CRUD : create/edit = OPÉRATEUR (fail-closed) ; archive/delete = ADMIN (fail-closed). Chaque mutation
// est ATTRIBUÉE + LEDGERISÉE (`console.engagement.*`). Chaque engagement reçoit SON ledger_path DÉDIÉ
// (dérivé côté serveur — jamais un chemin fourni par le client : anti write-anywhere). GARDE-FOU
// fail-closed : on ne peut ni archiver ni supprimer le DERNIER engagement actif (il faut toujours un
// espace de travail actif) ; l'engagement par défaut #1 (ancre rétro-compat) n'est jamais supprimable.
// =====================================================================================

/// Résout l'engagement CIBLE d'une LECTURE (vue/liste) depuis le query `?engagement=<id>`. Présent et
/// entier => cet id TEL QUEL (même s'il n'existe pas : la vue filtre dessus et renvoie du VIDE —
/// fail-closed, un id inconnu ne montre JAMAIS les données d'un autre engagement). Absent/malformé =>
/// engagement ACTIF le plus récent (status='active', ORDER BY id DESC), sinon le plus récent tout court,
/// sinon 1 (rétro-compat mono-engagement). Verrouille et libère son propre lock DB (ne pas appeler en
/// tenant déjà `app.db()`).
pub(crate) fn resolve_view_engagement_id(app: &App, headers: &HeaderMap, q: &HashMap<String, String>) -> i64 {
    // ENTERPRISE (flag-gated) : résolution TENANT-AWARE fail-closed — un engagement d'un tenant non
    // accordé résout vers NO_ENGAGEMENT (zéro ligne). Community => branche historique EXACTE (byte-identique).
    if tenancy::enabled(app) {
        let requested = q.get("engagement").and_then(|s| s.trim().parse::<i64>().ok());
        return tenancy::view_engagement_id(app, headers, requested);
    }
    if let Some(id) = q.get("engagement").and_then(|s| s.trim().parse::<i64>().ok()) {
        return id;
    }
    let db = app.db();
    db.query_row("SELECT id FROM engagement WHERE status='active' ORDER BY id DESC LIMIT 1", [], |r| r.get::<_, i64>(0))
        .or_else(|_| db.query_row("SELECT id FROM engagement ORDER BY id DESC LIMIT 1", [], |r| r.get::<_, i64>(0)))
        .unwrap_or(1)
}

/// Résout l'engagement d'une MUTATION par-engagement (sélection de techniques / workflows). Priorité :
/// query `?engagement=` > body `engagement_id` > défaut (resolve_view_engagement_id). Un id EXPLICITE
/// doit EXISTER (fail-closed : on n'écrit jamais une config pour un engagement fantôme). Sans id explicite
/// on retombe sur le défaut (jamais d'erreur) — rétro-compat mono-engagement.
pub(crate) fn resolve_mutation_engagement_id(app: &App, headers: &HeaderMap, q: &HashMap<String, String>, body: &Value) -> Result<i64, String> {
    match q.get("engagement").and_then(|s| s.trim().parse::<i64>().ok())
        .or_else(|| body.get("engagement_id").and_then(|v| v.as_i64())) {
        Some(id) => {
            let exists = { let db = app.db(); db.query_row("SELECT 1 FROM engagement WHERE id=?", [id], |_| Ok(())).is_ok() };
            if !exists {
                return Err(format!("engagement {id} introuvable"));
            }
            // ENTERPRISE (flag-gated) fail-closed : on n'écrit JAMAIS une config par-engagement pour un
            // engagement d'un tenant NON accordé — message identique à « introuvable » (pas de fuite
            // d'existence). No-op en community (engagement_visible => true).
            if tenancy::enabled(app) && !tenancy::engagement_visible(app, headers, id) {
                return Err(format!("engagement {id} introuvable"));
            }
            Ok(id)
        }
        None => {
            let eid = resolve_view_engagement_id(app, headers, q);
            // ENTERPRISE : aucun engagement accordé => refus (fail-closed) plutôt que d'écrire sur #1.
            if tenancy::enabled(app) && eid == tenancy::NO_ENGAGEMENT {
                return Err("aucun engagement accessible (aucun tenant accordé)".into());
            }
            Ok(eid)
        }
    }
}

/// Dérive le ledger_path DÉDIÉ d'un NOUVEL engagement (jamais fourni par le client — anti write-anywhere) :
/// fichier `engagement-<id>.jsonl` FRÈRE du ledger console (App.ledger_path). Ledger console au chemin nu
/// ou vide => chemin relatif `engagement-<id>.jsonl`.
///
/// ENTERPRISE (flag-gated) : le ledger est GROUPÉ par tenant (`tenant-<tid>/engagement-<id>.jsonl`) via
/// tenancy::scoped_engagement_ledger_path. Community (flag OFF) => tenancy renvoie None et on garde le
/// chemin PLAT historique (byte-identique). La signature Ed25519 par-ledger (.ed25519 frère) est inchangée.
pub(crate) fn derive_engagement_ledger_path(app: &App, id: i64, tenant_id: i64) -> String {
    if let Some(scoped) = tenancy::scoped_engagement_ledger_path(app, app.ledger_path.as_str(), id, tenant_id) {
        return scoped;
    }
    let base = app.ledger_path.as_str();
    if base.is_empty() {
        return format!("engagement-{id}.jsonl");
    }
    match std::path::Path::new(base).parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(format!("engagement-{id}.jsonl")).to_string_lossy().into_owned(),
        None => format!("engagement-{id}.jsonl"),
    }
}

/// Valide/canonicalise le scope d'un engagement depuis un objet `{mode?, in_scope?, out_scope?}`.
/// mode ∈ {white,grey,black} (défaut grey). in_scope/out_scope = tableaux (≤256) de motifs bornés.
/// Renvoie (scope_json canonique, mode). Fonction PURE (aucune I/O).
pub(crate) fn validate_engagement_scope(v: &Value) -> Result<(String, String), String> {
    if !v.is_object() {
        return Err("scope_json attendu : objet {mode?, in_scope?, out_scope?}".into());
    }
    let mode = match v.get("mode") {
        None | Some(Value::Null) => "grey".to_string(),
        Some(Value::String(s)) => {
            if !matches!(s.as_str(), "white" | "grey" | "black") {
                return Err(format!("mode '{s}' invalide (white|grey|black)"));
            }
            s.clone()
        }
        Some(_) => return Err("mode doit être une chaîne".into()),
    };
    fn arr(v: &Value, key: &str) -> Result<Vec<String>, String> {
        match v.get(key) {
            None | Some(Value::Null) => Ok(vec![]),
            Some(Value::Array(a)) => {
                if a.len() > 256 {
                    return Err(format!("{key} trop volumineux (>256 entrées)"));
                }
                let mut out = Vec::new();
                for (i, e) in a.iter().enumerate() {
                    let s = e.as_str().ok_or_else(|| format!("{key}[{i}] : chaîne attendue"))?;
                    let s = s.trim();
                    if !valid_scope_entry(s) {
                        return Err(format!("{key}[{i}] : entrée '{s}' mal formée (host/CIDR/wildcard)"));
                    }
                    out.push(s.to_string());
                }
                Ok(out)
            }
            Some(_) => Err(format!("{key} doit être un tableau de chaînes")),
        }
    }
    let in_scope = arr(v, "in_scope")?;
    let out_scope = arr(v, "out_scope")?;
    let canonical = json!({"mode": mode, "in_scope": in_scope, "out_scope": out_scope}).to_string();
    Ok((canonical, mode))
}

/// Liste des engagements + compteurs agrégés (findings/runs) — aucune donnée d'un autre engagement n'est
/// exposée (juste id/nom/statut/mode/date + compteurs). Lecture pure. Ordre par id.
pub(crate) fn engagement_list_json(app: &App, headers: &HeaderMap) -> Vec<Value> {
    // ENTERPRISE (flag-gated) : la liste ne montre QUE les engagements des tenants accordés au caller.
    // Community => aucun filtre (WHERE vide) : SQL byte-identique à l'historique. Un grant vide => la
    // clause `e.tenant_id IN (-1)` ne matche rien (fail-closed).
    let where_clause = match tenancy::list_filter_sql(app, headers, "e") {
        Some(cond) => format!(" WHERE {cond}"),
        None => String::new(),
    };
    // ENTERPRISE (flag-gated) : n'expose `tenant_id` par engagement QUE sous le flag — le SPA en a besoin
    // pour la hiérarchie tenant → engagement (filtrage du sélecteur par tenant actif). Community => champ
    // ABSENT : le payload reste BYTE-IDENTIQUE à l'historique (aucune fuite de la dimension tenant).
    let expose_tenant = tenancy::enabled(app);
    let db = app.db();
    let mut stmt = match db.prepare(&format!(
        "SELECT e.id, e.name, e.status, e.mode, e.created,
                (SELECT COUNT(*) FROM finding f WHERE f.engagement_id=e.id),
                (SELECT COUNT(*) FROM run_job j WHERE j.engagement_id=e.id),
                e.tenant_id
         FROM engagement e{where_clause} ORDER BY e.id",
    )) { Ok(s) => s, Err(_) => return vec![] };
    stmt.query_map([], |r| {
        let tenant_id = r.get::<_, i64>(7)?;
        let mut o = json!({
            "id": r.get::<_, i64>(0)?,
            "name": r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            "status": r.get::<_, Option<String>>(2)?.unwrap_or_else(|| "active".into()),
            "mode": r.get::<_, Option<String>>(3)?.unwrap_or_else(|| "grey".into()),
            "created": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            "counts": {"findings": r.get::<_, i64>(5)?, "runs": r.get::<_, i64>(6)?},
        });
        if expose_tenant {
            o["tenant_id"] = json!(tenant_id);
        }
        Ok(o)
    })
    .map(|it| it.filter_map(|x| x.ok()).collect())
    .unwrap_or_default()
}

/// GET /api/engagements — liste + compteurs (viewer). Sert le sélecteur d'engagement du SPA.
/// ENTERPRISE : restreinte aux tenants accordés (fail-closed) ; community => tous (no-op).
pub(crate) async fn engagements_list(State(app): State<App>, headers: HeaderMap) -> impl IntoResponse {
    Json(json!({"engagements": engagement_list_json(&app, &headers)}))
}

/// POST /api/engagements {name, mode?, scope_json?} — CRÉE un engagement (OPÉRATEUR, fail-closed 403).
/// Nouvel espace de travail ISOLÉ avec SON PROPRE ledger DÉDIÉ (dérivé serveur). Mutation ATTRIBUÉE +
/// LEDGERISÉE (`console.engagement.create` — dans le ledger dédié du nouvel engagement ET le ledger console).
pub(crate) async fn engagements_create(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !valid_engagement_name(&name) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_name", "why": "nom d'engagement invalide (1..80, pas de '-' en tête)"}))).into_response();
    }
    // scope_json : {mode?, in_scope?, out_scope?}. Absent -> scope VIDE (fail-closed : rien lançable tant
    // qu'un in_scope n'est pas défini). mode explicite (body.mode) prime sur celui du scope si fourni.
    let scope_v = body.get("scope_json").cloned().unwrap_or_else(|| json!({}));
    let (scope_json, scope_mode) = match validate_engagement_scope(&scope_v) {
        Ok(x) => x,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_scope", "why": e}))).into_response(),
    };
    let mode = match body.get("mode").and_then(|v| v.as_str()) {
        Some(m) if matches!(m, "white" | "grey" | "black") => m.to_string(),
        Some(m) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_mode", "why": format!("mode '{m}' invalide (white|grey|black)")}))).into_response(),
        None => scope_mode,
    };
    let actor = attribution_login(&app, &headers);
    // ENTERPRISE (flag-gated) : un engagement naît DANS un tenant accordé au créateur (fail-closed — on
    // ne crée jamais un espace dans un tenant qu'on ne possède pas). Community => None (tenant #1 par
    // défaut de la colonne, byte-identique). Résolu AVANT l'INSERT pour refuser (400) sans rien écrire.
    let target_tenant: Option<i64> = if tenancy::enabled(&app) {
        match tenancy::resolve_create_tenant(&app, &headers, &body) {
            Ok(t) => Some(t),
            Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_tenant", "why": why}))).into_response(),
        }
    } else {
        None
    };
    // INSERT (ledger_path provisoire vide) -> last_insert_rowid -> rattache le tenant. Un engagement démarre
    // TOUJOURS actif. Le ledger_path DÉDIÉ est dérivé HORS du guard (derive_engagement_ledger_path consulte
    // tenancy::enabled qui reverrouille le mutex DB — ne JAMAIS l'appeler en tenant `app.db()`), puis posé
    // par un UPDATE. Le champ reste '' entre l'INSERT et l'UPDATE (id pas encore divulgué : microfenêtre sûre).
    let id = {
        let db = app.db();
        if let Err(e) = db.execute(
            "INSERT INTO engagement(name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(?,?,?,?,'',datetime('now'),datetime('now'))",
            rusqlite::params![name, "active", mode, scope_json],
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "create_failed", "why": e.to_string()}))).into_response();
        }
        let id = db.last_insert_rowid();
        // ENTERPRISE : rattache le nouvel engagement au tenant accordé résolu (community: pas d'UPDATE).
        if let Some(t) = target_tenant {
            let _ = db.execute("UPDATE engagement SET tenant_id=? WHERE id=?", rusqlite::params![t, id]);
        }
        id
    };
    // Le ledger est GROUPÉ par tenant en enterprise (tenant-<tid>/…) ; en community target_tenant=None
    // => tenant #1 et tenancy renvoie le chemin PLAT (byte-identique).
    let ledger_path = derive_engagement_ledger_path(&app, id, target_tenant.unwrap_or(tenancy::DEFAULT_TENANT));
    {
        let db = app.db();
        let _ = db.execute("UPDATE engagement SET ledger_path=? WHERE id=?", rusqlite::params![ledger_path, id]);
    }
    // genèse : 1re entrée dans le ledger DÉDIÉ du nouvel engagement (isolation) + trace console globale.
    append_run_ledger_path(&app, &ledger_path, "console.engagement.create", json!({
        "actor": actor, "engagement_id": id, "name": name, "mode": mode,
    }));
    if ledger_path != app.ledger_path.as_str() {
        append_console_ledger(&app, "console.engagement.create", json!({
            "actor": actor, "engagement_id": id, "name": name, "mode": mode,
        }));
    }
    (StatusCode::OK, Json(json!({"ok": true, "engagement": {"id": id, "name": name, "status": "active", "mode": mode}}))).into_response()
}

/// ÉDITE un engagement (name/mode/scope/status). GARDE-FOU fail-closed : on ne peut pas ARCHIVER le
/// DERNIER engagement actif. Check + mutations sous un seul guard DB (atomique). Ledgerise l'action
/// EFFECTIVE (edit|archive|activate). Retourne la vue ou (code, message).
pub(crate) fn engagement_do_update(app: &App, id: i64, actor: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    let cur_status: String = {
        let db = app.db();
        db.query_row("SELECT status FROM engagement WHERE id=?", [id], |r| r.get(0))
            .map_err(|_| (StatusCode::NOT_FOUND, format!("engagement {id} introuvable")))?
    };
    let new_name: Option<String> = match body.get("name") {
        None => None,
        Some(n) => {
            let n = n.as_str().unwrap_or("").trim().to_string();
            if !valid_engagement_name(&n) {
                return Err((StatusCode::BAD_REQUEST, "nom d'engagement invalide (1..80, pas de '-' en tête)".into()));
            }
            Some(n)
        }
    };
    let mut new_scope: Option<String> = None;
    let mut new_mode: Option<String> = None;
    if let Some(sv) = body.get("scope_json") {
        let (sj, m) = validate_engagement_scope(sv).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        new_scope = Some(sj);
        new_mode = Some(m);
    }
    if let Some(m) = body.get("mode").and_then(|v| v.as_str()) {
        if !matches!(m, "white" | "grey" | "black") {
            return Err((StatusCode::BAD_REQUEST, format!("mode '{m}' invalide (white|grey|black)")));
        }
        new_mode = Some(m.to_string());
    }
    let new_status: Option<String> = match body.get("status").and_then(|v| v.as_str()) {
        None => None,
        Some(s) if matches!(s, "active" | "archived") => Some(s.to_string()),
        Some(s) => return Err((StatusCode::BAD_REQUEST, format!("status '{s}' invalide (active|archived)"))),
    };
    if new_name.is_none() && new_scope.is_none() && new_mode.is_none() && new_status.is_none() {
        return Err((StatusCode::BAD_REQUEST, "aucun changement fourni (name|mode|scope_json|status)".into()));
    }
    let archiving = new_status.as_deref() == Some("archived") && cur_status == "active";
    {
        let db = app.db();
        if archiving {
            let active_count: i64 = db.query_row("SELECT COUNT(*) FROM engagement WHERE status='active'", [], |r| r.get(0)).unwrap_or(0);
            if active_count <= 1 {
                return Err((StatusCode::CONFLICT, "impossible : dernier engagement actif (archivage refusé, fail-closed)".into()));
            }
        }
        if let Some(n) = &new_name { let _ = db.execute("UPDATE engagement SET name=?, updated=datetime('now') WHERE id=?", rusqlite::params![n, id]); }
        if let Some(s) = &new_scope { let _ = db.execute("UPDATE engagement SET scope_json=?, updated=datetime('now') WHERE id=?", rusqlite::params![s, id]); }
        if let Some(m) = &new_mode { let _ = db.execute("UPDATE engagement SET mode=?, updated=datetime('now') WHERE id=?", rusqlite::params![m, id]); }
        if let Some(s) = &new_status { let _ = db.execute("UPDATE engagement SET status=?, updated=datetime('now') WHERE id=?", rusqlite::params![s, id]); }
    }
    let action = if new_status.as_deref() == Some("archived") { "archive" }
        else if new_status.as_deref() == Some("active") && cur_status == "archived" { "activate" }
        else { "edit" };
    append_console_ledger(app, &format!("console.engagement.{action}"), json!({
        "actor": actor, "engagement_id": id,
        "name": new_name, "mode": new_mode, "status": new_status, "scope_changed": new_scope.is_some(),
    }));
    Ok(json!({"ok": true, "engagement_id": id, "action": action}))
}

/// SUPPRIME un engagement + ses données possédées (findings/runrecords/roe/run_job) + sa config
/// par-engagement (technique_selection/workflows). GARDE-FOUS fail-closed : #1 (défaut) non supprimable ;
/// jamais le DERNIER engagement actif. Le fichier ledger DÉDIÉ RESTE sur disque (piste d'audit préservée),
/// avec une entrée finale `console.engagement.delete`. Ledgerise aussi dans le ledger console.
pub(crate) fn engagement_do_delete(app: &App, id: i64, actor: &str) -> Result<Value, (StatusCode, String)> {
    if id == 1 {
        return Err((StatusCode::CONFLICT, "engagement par défaut (#1) non supprimable — archivez-le".into()));
    }
    let (status, ledger, findings, runs): (String, String, i64, i64) = {
        let db = app.db();
        let (status, ledger): (String, String) = db
            .query_row("SELECT status, ledger_path FROM engagement WHERE id=?", [id], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|_| (StatusCode::NOT_FOUND, format!("engagement {id} introuvable")))?;
        let f: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=?", [id], |r| r.get(0)).unwrap_or(0);
        let r: i64 = db.query_row("SELECT COUNT(*) FROM run_job WHERE engagement_id=?", [id], |r| r.get(0)).unwrap_or(0);
        (status, ledger, f, r)
    };
    if status == "active" {
        let db = app.db();
        let active_count: i64 = db.query_row("SELECT COUNT(*) FROM engagement WHERE status='active'", [], |r| r.get(0)).unwrap_or(0);
        if active_count <= 1 {
            return Err((StatusCode::CONFLICT, "impossible : dernier engagement actif (suppression refusée, fail-closed)".into()));
        }
    }
    // entrée FINALE dans le ledger DÉDIÉ (avant retrait de la ligne) — l'audit du fichier survit.
    if !ledger.is_empty() && ledger != app.ledger_path.as_str() {
        let _ = ledger_append_standalone(&ledger, "console.engagement.delete",
            &json!({"actor": actor, "engagement_id": id, "findings": findings, "runs": runs}));
    }
    {
        let db = app.db();
        let _ = db.execute("DELETE FROM finding WHERE engagement_id=?", [id]);
        let _ = db.execute("DELETE FROM runrecord WHERE engagement_id=?", [id]);
        let _ = db.execute("DELETE FROM roe_decision WHERE engagement_id=?", [id]);
        let _ = db.execute("DELETE FROM run_job WHERE engagement_id=?", [id]);
        let _ = db.execute("DELETE FROM settings WHERE key=?", [technique_selection_key(id)]);
        let _ = db.execute("DELETE FROM settings WHERE key=?", [workflows_key(id)]);
        let _ = db.execute("DELETE FROM engagement WHERE id=?", [id]);
    }
    append_console_ledger(app, "console.engagement.delete", json!({
        "actor": actor, "engagement_id": id, "findings": findings, "runs": runs,
    }));
    Ok(json!({"ok": true, "engagement_id": id, "deleted": {"findings": findings, "runs": runs}}))
}

/// POST /api/engagements/:id — ÉDITE (name/mode/scope/activate → OPÉRATEUR), ARCHIVE (status=archived →
/// ADMIN) ou SUPPRIME (`{"delete":true}` → ADMIN). Rôle GATÉ selon l'opération (fail-closed). Chaque
/// mutation attribuée + ledgerisée. Dernier engagement actif protégé (409).
pub(crate) async fn engagements_update(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    let is_delete = body.get("delete").and_then(|v| v.as_bool()).unwrap_or(false);
    let archiving = body.get("status").and_then(|v| v.as_str()) == Some("archived");
    // GATE RÔLE : delete/archive => ADMIN (fail-closed) ; edit/activate => OPÉRATEUR (fail-closed).
    if is_delete || archiving {
        if !check_admin(&app, &headers) {
            return admin_denied().into_response();
        }
    } else if !check_operator(&app, &headers, Some(peer.ip())) {
        let (s, j) = operator_denied(&app);
        return (s, j).into_response();
    }
    // ENTERPRISE (flag-gated) fail-closed : on ne peut ÉDITER/ARCHIVER/SUPPRIMER QUE un engagement d'un
    // tenant accordé. Un engagement d'un AUTRE tenant -> 404 (jamais divulgué, pas d'action cross-tenant).
    // No-op en community (engagement_visible => true).
    if tenancy::enabled(&app) && !tenancy::engagement_visible(&app, &headers, id) {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_engagement", "id": id}))).into_response();
    }
    // ENTERPRISE (E3 COMPLIANCE, flag-gated) WORM : un LEGAL-HOLD bloque la suppression ET l'archivage,
    // quelle que soit la rétention (hold always wins, fail-closed). INERTE (None) tant que le flag compliance
    // est OFF => community byte-identique. Ne touche que delete/archive (édition/activation non concernées).
    if is_delete || archiving {
        if let Some(scope) = compliance::deletion_blocked(&app, id) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "legal_hold", "why": format!("legal hold ({scope}) en vigueur — suppression/archivage bloqué (WORM, fail-closed)")})),
            )
                .into_response();
        }
        // ENTERPRISE (E3 COMPLIANCE, flag-gated) WORM : la RÉTENTION gagne aussi sur delete/archive, exactement
        // comme sur purge — un enregistrement ledgerisé ENCORE dans la fenêtre de rétention ne peut être détruit.
        // INERTE (None) tant que le flag compliance est OFF => community byte-identique.
        if let Some(why) = compliance::retention_blocked(&app, id) {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "retention", "why": why}))).into_response();
        }
    }
    let actor = attribution_login(&app, &headers);
    let res = if is_delete {
        engagement_do_delete(&app, id, &actor)
    } else {
        engagement_do_update(&app, id, &actor, &body)
    };
    match res {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "engagement_update_failed", "why": why}))).into_response(),
    }
}

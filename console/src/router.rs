// SPDX-License-Identifier: AGPL-3.0-or-later
//! Câblage du routeur HTTP — PURE MOVE de `build_router` depuis main.rs.
//!
//! `build_router` ne fait QUE câbler des handlers déjà définis + re-exportés `pub(crate)` à la
//! racine de crate (findings/runs/engagements/ledger_api/…). Depuis ce module enfant de la racine,
//! ces symboles restent accessibles via `use crate::*;` (mêmes items privés visibles qu'en inline).
//! Aucun handler déplacé, aucun ordre de `.route()`/`.merge()` modifié, aucune string changée =>
//! binaire release byte-identique. Le seul ajout est la liste d'`use` (garantie exhaustive par le
//! compilateur) + la visibilité `pub(crate)` sur la signature (identique à l'accès inline).
//!
//! `use crate::*;` suffit : les imports externes de la racine (`axum::{Router, get, post, middleware,
//! DefaultBodyLimit}`, `tower_http::services::ServeDir`) sont visibles depuis ce module descendant et
//! re-globés ici — exactement comme le module de tests inline les résolvait via `use super::*;`.
use crate::*;

pub(crate) fn build_router(app: App, web_dir: &str) -> Router {
    // routes protégées par auth_guard ; ServeDir sert les assets statiques (style.css/app.js/quetzal.svg/
    // favicon.svg/fonts/…) en fallback pour toute route non-API non matchée — l'index `/` reste rendu
    // par include_str!.
    let protected = Router::new()
        .route("/api/whoami", get(whoami))
        .route("/api/ingest", post(ingest))
        .route("/api/findings", get(findings))
        // BULK-OPS (#8) : transition de statut de masse (validée par finding, engagement-scopée) + export
        // CSV/JSON de la sélection. Segments STATIQUES `bulk/...` (2 segments) — pas de collision matchit
        // avec `/api/findings/:id` (1 segment param). DÉCLARÉES AVANT `:id` par prudence (spécifique d'abord).
        .route("/api/findings/bulk/status", post(findings_bulk_status))
        .route("/api/findings/bulk/export", post(findings_bulk_export))
        // OWNERSHIP (P1-4) : bulk-assign (segments STATIQUES `bulk/assign`) + single-assign (`:id/assign`) +
        // jeu des assignables (`assignable`, statique — pas de collision matchit avec `:id`).
        .route("/api/findings/bulk/assign", post(findings_bulk_assign))
        .route("/api/findings/assignable", get(findings_assignable))
        // TRIAGE WORKFLOW : bulk-triage (segments STATIQUES `bulk/triage`) + flux SSE des transitions
        // (`events`, statique — pas de collision matchit avec `:id`) + single-triage (`:id/triage`).
        .route("/api/findings/bulk/triage", post(findings_bulk_triage))
        .route("/api/findings/events", get(finding_events))
        .route("/api/findings/:id", get(finding_detail).post(finding_update))
        .route("/api/findings/:id/assign", post(finding_assign))
        .route("/api/findings/:id/triage", post(finding_triage))
        .route("/api/runrecords", get(runrecords))
        .route("/api/coverage", get(coverage))
        // Matrice ATT&CK par engagement : grille tactique × technique (kill-chain), engagement-scopée.
        .route("/api/attack-matrix", get(attack_matrix))
        // Couverture de détection : nom canonique + alias rétro-compat /api/purple/coverage (le SPA
        // interroge encore /purple/coverage — l'alias garantit qu'il ne casse pas).
        .route("/api/detection/coverage", get(purple_coverage))
        .route("/api/purple/coverage", get(purple_coverage))
        // Test admin d'une source de détection (config fournie ou stockée) — ne renvoie jamais le secret.
        .route("/api/detection/test", post(detection_test))
        // Config admin de la SOURCE de détection : GET (secret RETIRÉ) + POST (persiste settings.detection_source,
        // recharge le cache, ledgerise ; write-only sur le secret). Réservé admin (check_admin, 403 sinon).
        .route("/api/detection/source", get(detection_source_get).post(detection_source_set))
        .route("/api/modules", get(modules))
        .route("/api/modules/refresh", post(modules_refresh))
        // SÉLECTION DE TECHNIQUES PAR-SCOPE — catalogue groupé par catégorie (lecture) + mutation
        // gouvernée (opérateur/admin, ledgerisée) de la sélection (profil + toggles catégorie/technique).
        .route("/api/techniques", get(techniques_catalog))
        .route("/api/techniques/selection", post(technique_selection_set))
        // WORKFLOWS éditables & sauvegardés — pipelines composés (absorbe reNgine/Osmedeus/Trickest).
        // GET = liste (viewer) ; POST /api/workflows = créer, POST /api/workflows/:name = éditer/
        // supprimer — mutations OPÉRATEUR/ADMIN gouvernées + ledgerisées, builtins protégés. matchit :
        // le segment statique `selection` (techniques) et `:name` (workflows) ne collisionnent pas.
        .route("/api/workflows", get(workflows_list).post(workflow_create))
        .route("/api/workflows/:name", post(workflow_edit))
        // GOUVERNANCE CONNECTEUR (#4) : écriture réservée admin (check_admin, fail-closed 403), attribuée +
        // ledgerisée. Le segment statique `refresh` prime sur le paramètre `:kind` (matchit). Disabling
        // un connecteur l'empêche RÉELLEMENT de tirer (enforcement au spawn, cf. run_create).
        .route("/api/modules/:kind", post(module_governance))
        // OUTILS AJOUTÉS PAR L'UI (« add a tool from the web UI ») — ADMIN-ONLY (check_admin, 403 sinon),
        // ledgerisé, validé fail-closed. POST déclare un ToolSpec gouverné (binaire + argv no-shell +
        // allowlist), le persiste dans le dir server-managed + HOT-RELOAD le catalogue ; GET liste les
        // outils UI ; DELETE :kind en retire un (jamais un built-in). Ne collisionne pas avec /api/modules.
        .route("/api/tools", get(tools_list).post(tools_add))
        .route("/api/tools/:kind", axum::routing::delete(tools_delete))
        .route("/api/campaigns", get(campaigns))
        // ENGAGEMENT (objet de 1re classe) : liste + compteurs (viewer) ; create = OPÉRATEUR ; edit/
        // archive/delete via POST :id (edit=OPÉRATEUR, archive/delete=ADMIN, cf. handler). Chaque mutation
        // ledgerisée `console.engagement.*`. Les vues (findings/runrecords/roe/ledger/coverage/runs) filtrent
        // sur l'engagement actif (`?engagement=`). Le segment `:id` (i64) ne collisionne pas avec la liste.
        .route("/api/engagements", get(engagements_list).post(engagements_create))
        .route("/api/engagements/:id", post(engagements_update))
        // POLITIQUE RÉSEAU (privé/LAN/loopback) — MASTER SWITCH GLOBAL (admin, ledgerisé). GET lit l'état,
        // POST le bascule. C'est le « gros bouton rouge » instance-wide : OFF (défaut) = aucun scan privé
        // possible depuis AUCUN engagement (l'effectif exige aussi l'opt-in per-engagement + le scope).
        .route("/api/network-policy", get(network_policy_get).post(network_policy_set))
        .route("/api/roe", get(roe))
        // --- ADMINISTRATION comptes (#4) : réservé admin (check_admin, fail-closed 403 sinon). Chaque
        //     mutation est attribuée à l'admin acteur + ledgerisée ; GET ne renvoie jamais pass_hash ;
        //     recompute_auth_required après chaque mutation (gate DB-state) ; dernier admin protégé.
        .route("/api/users", get(users_list).post(users_create))
        .route("/api/users/:login", post(users_update).delete(users_delete))
        // --- SAUVEGARDE / RESTAURATION CHIFFRÉES (admin, ledgerisées). L'archive est TOUJOURS chiffrée ;
        //     la passphrase (corps) est transitoire (jamais stockée/loggée/ledgerisée). Le restore VALIDE
        //     par défaut (non destructif) ; un swap en place exige apply=true+confirm=true (redémarrage
        //     requis). La politique (schedule/rétention/offsite) pilote le runner programmé ; GET rédige
        //     tout secret. DefaultBodyLimit relevé sur /api/restore (archive base64 volumineuse possible).
        .route("/api/backup", post(api_backup))
        .route("/api/restore", post(api_restore).layer(DefaultBodyLimit::max(512 * 1024 * 1024)))
        .route("/api/backup/policy", get(api_backup_policy_get).post(api_backup_policy_set))
        // --- parité LECTURE / gouvernance ---
        .route("/api/scope-check", post(scope_check))
        .route("/api/plan", post(plan))
        // LEDGER (lecture + vérification hash-chain) : routes définies DANS le module dédié
        // (console/src/ledger_api.rs). Fusionnées AVANT le fallback + le route_layer => elles héritent
        // de l'auth_guard/host_guard exactement comme leur câblage inline d'origine (parité stricte).
        .merge(ledger_api::routes())
        .route("/api/query", get(query).post(query_post))
        .route("/api/dashboards", get(dashboards_list).post(dashboard_create))
        .route("/api/dashboards/:id", post(dashboard_update).delete(dashboard_delete))
        .route("/api/panels", get(panels_list).post(panel_create))
        .route("/api/panels/:id", post(panel_update).delete(panel_delete))
        .route("/api/panels/:id/data", get(panel_data))
        // --- IMPORT (migration Faraday/Trickest/reNgine/Osmedeus) : ingestion de sorties de scanners
        //     existantes en findings orientés preuve. OPÉRATEUR (fail-closed) + ledgerisé + scope-guardé.
        //     PUR DATA (aucune exécution). DefaultBodyLimit relevé (fichiers de scan volumineux possibles).
        .route("/api/import", post(import_scan).layer(DefaultBodyLimit::max(64 * 1024 * 1024)))
        // --- C2-light : lancement gouverné/audité (opérateur fail-closed sur run/cancel) ---
        .route("/api/run", post(run_create))
        .route("/api/runs", get(runs_list))
        .route("/api/runs/:id", get(run_detail))
        .route("/api/runs/:id/report", get(run_report))
        .route("/api/runs/:id/cancel", post(run_cancel))
        .route("/api/runs/:id/logs", get(run_logs))
        .route("/api/runs/:id/events", get(run_sse))
        // FINDINGS LIBRARY (modèles réutilisables) : routes définies DANS le module dédié
        // (finding_templates.rs). Fusionnées AVANT le fallback + le route_layer => elles héritent de
        // l'auth_guard et du host_guard comme toute route protégée. GET=liste (global), POST=create
        // (operator), POST/:id=edit (operator), DELETE/:id=delete (admin), POST/:id/apply=applique un
        // modèle en un finding de l'engagement ACTIF (isolation). Chaque mutation ledgerisée.
        .merge(finding_templates::routes())
        // SAVED VIEWS (#8) : jeux de filtres sauvegardés de la vue Findings, PERSONNELS (scopés au login
        // de l'appelant + engagement optionnel). Routes DANS console/src/saved_views.rs, fusionnées AVANT
        // le fallback + le route_layer => héritent de l'auth_guard/host_guard. GET=liste (vues de
        // l'appelant), POST=create (operator), DELETE/:id=delete (operator, propriété stricte). Ledgerisé.
        .merge(saved_views::routes())
        // PRESENCE (#9) : roster multi-opérateur LIVE (in-memory, per-instance). Routes DANS
        // console/src/presence.rs, fusionnées AVANT le fallback + le route_layer => héritent de
        // l'auth_guard/host_guard. GET /api/presence[?engagement] = roster ; GET /api/presence/events =
        // flux SSE (join au connect, leave au drop, heartbeat interne) ; POST /api/presence/heartbeat.
        // FAIL-CLOSED auth + tenant-scopé. L'état vit dans l'Extension câblée sur le routeur externe.
        .merge(presence::routes())
        // NOTIFICATIONS (triage enrichi) : boîte de réception in-app PERSONNELLE. Routes DANS
        // console/src/notifications.rs, fusionnées AVANT le fallback + le route_layer => héritent de
        // l'auth_guard/host_guard. GET /api/notifications = mes notifs (non-lues d'abord + compteur non-lu) ;
        // POST /api/notifications/read = marquer lues (les MIENNES) ; GET /api/notifications/events = flux SSE
        // filtré sur mon user_id. Fail-closed au user_id de l'appelant (jamais celles d'un autre). Émission
        // sur les hooks assign/triage de findings.rs (best-effort, grant-scopée).
        .merge(notifications::routes())
        // LIVRABLE CLIENT (rapport d'engagement agrégé, brandé) : routes définies DANS console/src/
        // reports.rs. Fusionnées AVANT le fallback + le route_layer => héritent de l'auth_guard/host_guard.
        // GET /api/engagements/:id/report?format=… (viewer+, ISOLÉ à l'engagement, ledgerisé) ; GET/POST
        // /api/report/branding (config admin-éditable). Secrets rédigés dans tous les formats.
        .merge(reports::routes())
        // ENTERPRISE (separable, flag-gated) — TENANT ADMIN surface (console/src/tenancy.rs) : CRUD tenant
        // (create/rename/archive) + gestion des grants, PLATFORM-ADMIN gated + ledgerisé `console.tenant.*`.
        // Fusionné AVANT le fallback + le route_layer => hérite de l'auth_guard/host_guard. Chaque route
        // refuse (403 enterprise_disabled) tant que le flag n'est pas engagé => community byte-identique
        // (aucune surface d'administration tenant). La lecture cross-tenant du super-admin (audité) vit dans
        // les résolveurs tenancy déjà câblés — pas de nouvelle route pour ça.
        .merge(tenancy::routes())
        // ENTERPRISE (separable, flag-gated) — E3 COMPLIANCE surface (console/src/compliance.rs) : retention
        // policy + legal-hold config (admin) + the GOVERNED WORM purge, all `console.compliance.*` ledgered.
        // Merged AVANT le fallback + le route_layer => hérite de l'auth_guard/host_guard. Chaque route 404
        // (not_found) tant que le flag n'est pas engagé => community byte-identique (aucune surface compliance).
        .merge(compliance::routes())
        // CONSOLE FORGE IN-UI (P5) — POST /api/console/exec : runner gouverné, ADMIN-ONLY (check_admin
        // interne, 403 sinon), ledgerisé `console.exec`, STREAMÉ (SSE). Allowlist stricte de sous-commandes
        // `forge` + schéma d'arguments typé par commande ; argv FIXE, sans shell ; `upgrade` (effet d'état)
        // exige confirm:true. Fusionné AVANT le fallback + route_layer => hérite de l'auth_guard/host_guard.
        .merge(exec::routes())
        .fallback_service(ServeDir::new(web_dir))
        .route_layer(middleware::from_fn_with_state(app.clone(), auth_guard));
    Router::new()
        // /health : sonde ouverte (hors auth_guard). JSON {status, version, db} — `version` provient du
        // fichier VERSION (source unique) ; `db` (ADDITIF Stage 4) PING le store ACTIF. `forge doctor
        // --purple` et le healthcheck compose ne testent que le code HTTP 200 (forme préservée).
        .route("/health", get(health))
        // / : SHELL SPA STATIQUE (hors auth_guard). `index()` retourne include_str!("../web/index.html") —
        // un document statique SANS secret, contenu IDENTIQUE à `/index.html` déjà public via ServeDir. Il
        // DOIT être atteignable par navigation top-level pour que le SPA se rende et affiche le portail de
        // login / wizard stylé ; un 401+WWW-Authenticate sur `/` déclencherait le popup Basic natif du
        // navigateur au lieu du SPA. Toutes les DONNÉES restent derrière `/api/*` sous auth_guard.
        .route("/", get(index))
        // /api/login HORS auth_guard (sinon impossible de se connecter quand pass_hash est posé) ;
        // reste sous host_guard (anti-rebinding). Pose une session individuelle (cookie + bearer).
        .route("/api/login", post(login))
        // WIZARD 1er DÉPLOIEMENT — PUBLIC (hors auth_guard) : sonde d'état + provision AUTO-DÉSACTIVANTE
        // (409 une fois provisionné). Sous host_guard comme tout le reste. Le SPA sonde /api/setup/state
        // au boot pour afficher le wizard sur un fresh install ; POST /api/setup crée le 1er admin.
        .route("/api/setup/state", get(setup_state))
        .route("/api/setup", post(setup_provision))
        // IMPORT DE DONNÉES (pré-provision) : migre un install existant vers cette base + ledger.
        // PUBLIC mais 409 une fois provisionné (comme /api/setup). UX primaire = CLI `migrate`.
        .route("/api/setup/migrate", post(setup_migrate))
        // ENTERPRISE (separable, flag-gated) — OIDC SSO (console/src/sso.rs). Merged in the OUTER router
        // (NOT `protected`) because /api/sso/login and /api/sso/callback must be reachable WITHOUT a prior
        // session (that is the point of SSO) — they self-gate on the flag + config. The admin-only
        // /api/sso/config routes enforce check_admin internally (fail-closed). Every route 404s while the
        // flag is OFF => community build shows NO SSO surface and LOCAL login is byte-identical. Under
        // host_guard like everything else.
        .merge(sso::routes())
        // ENTERPRISE (separable, flag-gated) — SCIM 2.0 provisioning (console/src/scim.rs). Merged in the
        // OUTER router (NOT `protected`) because the IdP has NO session — /scim/v2/* authenticates with a
        // SCIM BEARER TOKEN internally (hashed at rest, constant-time, fail-closed 401). The admin-only
        // /api/scim/config route enforces check_admin internally. Every route 404s while the flag is OFF =>
        // community build shows NO SCIM surface and LOCAL accounts are byte-identical. Under host_guard.
        .merge(scim::routes())
        // ENTERPRISE (separable, flag-gated) — advanced RBAC config (console/src/rbac.rs). The admin-only
        // /api/rbac/group-map routes enforce check_admin internally (fail-closed). Every route 404s while
        // BOTH the SSO and SCIM flags are OFF => community build shows NO advanced-RBAC surface and role
        // assignment stays admin-only exactly as today. Under host_guard like everything else.
        .merge(rbac::routes())
        .merge(protected)
        // PRESENCE (#9) : registre EN MÉMOIRE per-instance, câblé UNE fois ici (Extension partagée par
        // tous les clones d'App/handlers). Créé par routeur (donc par serveur) -> isolation naturelle en
        // test ; jamais persisté (aucune table, aucun changement de schéma). Les handlers presence::* le
        // récupèrent via `Extension<PresenceRegistry>` ; les autres routes l'ignorent (inoffensif).
        .layer(axum::Extension(presence::PresenceRegistry::for_app(&app)))
        .layer(middleware::from_fn_with_state(app.clone(), host_guard))
        // FILET ANTI-PANIC — couche la PLUS EXTERNE (appliquée en DERNIER => elle enveloppe TOUT, y
        // compris host_guard/auth_guard/Extension et tous les handlers). Une panique de n'importe quel
        // task de handler devient un `500 {"error":"internal", …}` JSON lisible, JAMAIS une connexion
        // resetée (« Failed to fetch » côté navigateur). Le process n'est pas affecté (catch_unwind local
        // au task). Cf. `catch_panic_response` pour le corps stable non-fuyant.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(
            catch_panic_response,
        ))
        // EN-TÊTES DE SÉCURITÉ — couche la PLUS EXTERNE (ajoutée en DERNIER => appliquée en PREMIER à
        // l'entrée, en DERNIER à la sortie) : elle tamponne DONC toutes les réponses, y compris le 421
        // anti-rebinding du host_guard et le 500 du filet anti-panic ci-dessus. X-Frame-Options/nosniff/
        // Referrer-Policy/CSP sur tout ; HSTS SCHEME-AWARE (seulement derrière TLS, cf. security_headers).
        .layer(middleware::from_fn(security_headers))
        .with_state(app)
}

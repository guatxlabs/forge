// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — store + API pour les findings/run-records de Forge.
//!
//! Fork minimal de la colonne Plume (axum + rusqlite, binaire unique). Donne à Forge :
//!   - un store SQLite du modèle ROUGE (finding / runrecord) — au lieu d'event/metric côté Plume ;
//!   - `POST /api/ingest` (token bearer) = LE point de jonction de la boucle purple : le moteur
//!     Python POSTe ses findings + run-records ATT&CK ici ; Plume corrèle ensuite par champ `mitre` ;
//!   - des endpoints de lecture (findings / runrecords / coverage) + une console opérateur minimale.
//!
//! Bind 127.0.0.1 par défaut. `ingest` exige le token ; les lectures sont localhost-only (v0).
//! Durcissement prévu (réutiliser auth_guard/RBAC de Plume) : voir ARCHITECTURE.md. Single binary.

// cœur partagé (extrait) — le moteur soql est désormais consommé DIRECTEMENT par les modules qui en
// ont besoin (`query.rs` : exec_soql/panels ; `cli.rs` : sous-commande `query`), chacun via son propre
// `use guatx_core::soql`. Ce fichier ne le référence plus depuis l'extraction query.rs.

// ConnectInfo n'est plus consommé par un handler de main.rs depuis que les handlers qui l'extrayaient
// (engagements_create/engagements_update) ont migré vers engagements.rs (PURE MOVE) ; il reste requis par
// le harness de tests inline (conn_info(), via `use super::*`). L'allow ne s'applique QU'EN build non-test
// (community/default) où l'import est effectivement inutilisé — binaire byte-identique (aucun code émis).
#[cfg_attr(not(test), allow(unused_imports))]
use axum::extract::ConnectInfo;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    response::Json,
    routing::{get, post},
    Router,
};
// Extracteurs (`State`/`Path`/`Query`), types HTTP (`HeaderMap`/`StatusCode`) et traits/types de réponse
// (`IntoResponse`/`Response`) ne sont plus consommés par le code non-test de main.rs depuis l'extraction
// de l'App core + de ses handlers (index/purple_coverage/detection_*/run_report) vers state.rs (PURE
// MOVE) : ils ne servent plus qu'au harness de tests inline (via `use super::*`, qui appelle les handlers
// directement + `.into_response()`). L'allow ne s'applique QU'EN build non-test — binaire byte-identique.
#[cfg_attr(not(test), allow(unused_imports))]
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
// `base64::Engine` (trait fournissant .encode/.decode) et `std::net::IpAddr` ne sont plus consommés par
// le code non-test de main.rs depuis l'extraction de check_basic/whoami vers auth.rs (PURE MOVE) : ils ne
// servent plus qu'au harness de tests inline (via `use super::*`). L'allow ne s'applique QU'EN build
// non-test (community/default) où l'import est effectivement inutilisé — binaire byte-identique.
#[cfg_attr(not(test), allow(unused_imports))]
use base64::Engine;
use rusqlite::Connection;
use serde_json::json;
// `Value` n'est plus consommé par le code non-test de main.rs depuis l'extraction de l'App core/détection
// vers state.rs ; il ne sert plus qu'au harness de tests inline (via `use super::*`). Byte-identique.
#[cfg_attr(not(test), allow(unused_imports))]
use serde_json::Value;
use std::collections::HashMap;
#[cfg_attr(not(test), allow(unused_imports))]
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;

// `Duration` n'est plus consommé que via chemin complet (`std::time::Duration`) par main() et par le
// harness de tests inline (bare `Duration::from_millis`, via `use super::*`) depuis l'extraction du
// substrat App/détection vers state.rs. L'allow ne s'applique QU'EN build non-test — byte-identique.
#[cfg_attr(not(test), allow(unused_imports))]
use std::time::Duration;
use tokio::sync::{broadcast, Mutex as AsyncMutex};

// FINDINGS LIBRARY (modèles de findings réutilisables — livrable client type Ghostwriter). Feature
// console à part entière : ses handlers/logique vivent dans son PROPRE module (règle : pas de gros bloc
// de handlers dans ce main.rs déjà volumineux). Ce main.rs n'y contribue que la ligne `mod` + le
// `merge` des routes (build_router). Le module réutilise App + les helpers d'auth/ledger de ce fichier
// (visibles depuis un module descendant de la racine de crate).
mod finding_templates;
// SAVED VIEWS (#8) — jeux de filtres sauvegardés de la vue Findings, PERSONNELS (scopés au login de
// l'appelant). Même discipline que finding_templates : handlers/logique dans son PROPRE module ; ce
// main.rs n'y contribue que la ligne `mod` + le `merge` des routes (build_router). Réutilise App + les
// helpers d'auth/ledger de ce fichier (visibles depuis un module descendant de la racine de crate).
mod saved_views;
// PRESENCE (#9) — roster multi-opérateur LIVE (qui est connecté/en train d'opérer). Même discipline :
// handlers/état dans son PROPRE module ; main.rs n'y contribue que la ligne `mod`, le `merge` des routes
// ET le câblage d'UN `Extension<PresenceRegistry>` (état EN MÉMOIRE, per-instance) dans build_router — donc
// AUCUN champ ajouté à App (zéro site de construction touché). Réutilise App + le bus App.events + auth/tenancy.
mod presence;
// HA (#10 Wave A/B) — leader lease + heartbeat + run-leader (enqueue/claim/spawn), PG-only + opt-in
// FORGE_HA. The MODULE is now compiled UNCONDITIONALLY because Wave B routes the SHARED run-flow through
// its PORTABLE predicates (`ha_enabled`/`is_leader`/`my_instance_id`) — in the community build those
// collapse to "HA off / always leader / no owner", so the run flow stays byte-identical (direct spawn,
// reconcile-all, local cancel). The lease CORE (`acquire_or_renew`/`LEASE_*`) and the heartbeat/tick
// stay gated inside the module (`store-postgres` / `test`), so the community build still compiles NONE of
// the Postgres-only machinery.
mod ha;
// Helpers "feuilles" SANS ÉTAT (crypto/hash, échappement HTML, CWE/CVSS, pagination, validateurs purs)
// extraits de ce main.rs (Wave-2 PURE MOVE). Ré-exportés au crate root pour que `crate::<helper>`
// (appels cross-module) et `super::<helper>` (bloc de tests inline) résolvent à l'identique.
mod common;
pub(crate) use crate::common::*;
// Shared internal substrate for the flag-gated enterprise modules (dedup, behaviour-neutral):
//   error  — compact typed ApiError + IntoResponse (byte-identical `{"error","why"}` envelope).
//   flags  — the single copy of `env_truthy` + `enterprise_enabled` (env|per-DB config gate).
//   redact — the single copy of the two secret redactors (string scan + JSON-key walk).
mod error;
mod flags;
mod redact;
mod reports;
// ENTERPRISE (separable, flag-gated) — row-level multi-tenancy. Community (default) build never engages
// it (tenancy::enabled() false => single implicit tenant #1, byte-identical). Wired as its OWN module
// (minimal main.rs delta) so the open core does not depend on it. See COMMUNITY_VS_ENTERPRISE.md.
mod tenancy;
// ENTERPRISE (separable, flag-gated) — OIDC SSO login. Community (default) build never engages it
// (sso::enabled() false => LOCAL accounts only, byte-identical; every /api/sso/* route 404s). Wired as
// its OWN module (minimal main.rs delta = this line + one route merge) so the open core does not depend
// on it. Behind the runtime flag FORGE_ENTERPRISE_SSO / enterprise.sso. See COMMUNITY_VS_ENTERPRISE.md.
mod sso;
// ENTERPRISE (separable, flag-gated) — SCIM 2.0 provisioning (automated user/group provisioning from an
// IdP: Okta/Azure AD). Community (default) build never engages it (scim::enabled() false => LOCAL accounts
// only; every /scim/* + /api/scim/config route 404s). Wired as its OWN module (minimal main.rs delta =
// this line + one route merge). Authenticated by a SCIM BEARER TOKEN (hashed at rest, constant-time), NOT
// a session. Behind FORGE_ENTERPRISE_SCIM / enterprise.scim (or the SSO flag). See COMMUNITY_VS_ENTERPRISE.md.
mod scim;
// ENTERPRISE (separable, flag-gated) — advanced RBAC: the CONFIGURABLE IdP-group -> {role, tenant grant}
// mapping consulted by BOTH the SSO login (`groups` claim) and SCIM group membership. Community (default)
// build never engages it (rbac::enabled() = sso||scim, both OFF => role assignment stays admin-only,
// byte-identical; every /api/rbac/* route 404s, the mapping table is never created). FAIL-CLOSED /
// least-privilege: an SSO/SCIM identity gets ONLY what its group mapping confers, NEVER super-admin. Wired
// as its OWN module (minimal main.rs delta = this line + one route merge). See COMMUNITY_VS_ENTERPRISE.md.
mod rbac;
// ENTERPRISE (separable, flag-gated) — E3 COMPLIANCE: WORM / retention / legal-hold on the audit ledger +
// engagement data. Community (default) build never engages it (compliance::enabled() OFF => every
// /api/compliance/* route 404s, WORM/retention/hold inert, ledger + data byte-identical). A GOVERNED purge
// (behind FORGE_ENTERPRISE_COMPLIANCE / enterprise.compliance) archives the expired ledger segment ENCRYPTED
// (reusing the backup discipline) then re-anchors + emits a signed `console.compliance.purge` checkpoint so
// the chain stays verifiable — NEVER a silent delete. Wired as its OWN module (this line + one route merge +
// one SPA flag + a flag-gated delete guard). See COMMUNITY_VS_ENTERPRISE.md + forge/compliance_signer.py.
mod compliance;
// Sous-modules E3 COMPLIANCE extraits de compliance.rs (PURE MOVE, corps identiques) : math pure
// policy/WORM/retention + parsing timestamp (compliance_policy) ; export/rendu evidence + helpers de
// purge (compliance_evidence). Les handlers HTTP restent dans compliance.rs et appellent ces modules.
mod compliance_policy;
mod compliance_evidence;
// SAUVEGARDE / RESTAURATION CHIFFRÉE (+ politique/scheduler offsite, /api/backup*, /api/restore) et
// MIGRATION / CHIFFREMENT AU REPOS — deux sous-systèmes cohésifs déplacés hors de main.rs (PURE MOVE,
// Wave 2). Re-exportés `pub(crate)` à la racine de crate pour que le module de tests (`super::*`) ET les
// appelants inter-modules (`crate::backup_write_atomic`, `crate::backup_encrypt`, `crate::sha256_hex_bytes`,
// … depuis compliance) continuent de les résoudre inchangés. `dbmigrate::copy_ledger_and_key` référence
// `crate::backup::backup_write_atomic` (dépendance croisée volontaire — même trio base+ledger+clé).
mod backup;
mod backup_crypto;
mod backup_sched;
mod dbmigrate;
pub(crate) use crate::backup::*;
pub(crate) use crate::dbmigrate::*;
// Sous-système CLI (useradd/seed-demo/findings|roe|coverage|query/ledger verify) extrait de main.rs
// (PURE MOVE, Wave 2). Re-exporté à la racine pour que le dispatch de main() ET les tests inline
// (`super::*`) résolvent run_*_cli/print_table/cli_* INCHANGÉS, et que backup/dbmigrate continuent de
// résoudre cli_opt/cli_flag/cli_db_path via `crate::*`.
mod cli;
pub(crate) use crate::cli::*;
// Rendu des rapports d'engagement (run-report) — purs constructeurs de chaînes markdown + HTML
// brandé + génération PDF + prose du résumé exécutif + lecture read-only findings/verdicts, extrait
// de main.rs (PURE MOVE, Wave 2). Re-exporté à la racine pour que les tests inline (`super::*`) ET
// les appelants inter-modules (reports.rs -> `crate::render_pdf_from_html`, `crate::sev_css_class`,
// `crate::REPORT_CSS`) ET le handler `run_report` (resté dans main.rs) résolvent INCHANGÉS.
mod report_render;
pub(crate) use crate::report_render::*;
// Handler d'ingestion (`POST /api/ingest`, jonction de la boucle purple) extrait de main.rs (PURE
// MOVE). Re-exporté à la racine pour que la route de build_router et les tests inline (`super::*`)
// résolvent `ingest` INCHANGÉ.
mod ingest;
pub(crate) use crate::ingest::*;
// Login + wizard de 1er déploiement (login / setup_state / setup_provision / setup_migrate,
// /api/login + /api/setup*) extraits de main.rs (PURE MOVE). setup_migrate conserve VERBATIM son
// garde-fou (gate FORGE_ALLOW_API_MIGRATE + allowlist validate_api_migrate_paths). Re-exporté à la
// racine pour que les routes de build_router ET les tests inline (`super::*`) résolvent INCHANGÉS.
mod setup;
pub(crate) use crate::setup::*;
// SOUS-SYSTÈME LEDGER (lecture + vérification hash-chain SHA-256 + append console) extrait de main.rs
// (PURE MOVE). Re-exporté `pub(crate)` à la racine pour que les routes de build_router
// (ledger_api::routes()), les tests inline (`super::*` → super::ledger, read_ledger_lines, canon_json,
// verify_ledger_chain, append_console_ledger, engagement_ledger_path) ET les appelants inter-modules
// (compliance.rs/reports.rs/cli.rs/dbmigrate.rs/backup.rs : `crate::canon_json`,
// `crate::verify_ledger_chain`, `crate::append_console_ledger`, `crate::read_ledger_lines`,
// `crate::engagement_ledger_path`, `crate::ledger_verify_api_json`, `LedgerVerify`) résolvent INCHANGÉS.
mod ledger_api;
pub(crate) use crate::ledger_api::*;
// HANDLERS DE LECTURE du modèle ROUGE (finding/finding_detail/runrecords/campaigns/roe/coverage +
// le helper générique rows_to_json) extraits de main.rs (PURE MOVE). Re-exporté `pub(crate)` à la
// racine pour que les routes de build_router (`get(findings)`, `get(coverage)`, …) ET les tests inline
// (`super::*`) résolvent ces handlers INCHANGÉS. Les vues restent isolées par engagement actif.
mod findings;
pub(crate) use crate::findings::*;
// SOUS-SYSTÈME QUERY / DASHBOARDS (moteur soql read-only exec_soql/exec_soql_time + helpers cell/
// soql_stats, /api/query GET+POST, CRUD dashboards+panels) extrait de main.rs (PURE MOVE). Re-exporté
// `pub(crate)` à la racine pour que les routes de build_router (`get(query).post(query_post)`,
// `get(dashboards_list)`, `get(panels_list)`, …), le handler coverage (findings.rs -> exec_soql_time)
// ET les tests inline (`super::*`) résolvent INCHANGÉS.
mod query;
pub(crate) use crate::query::*;
// PLANIFICATION / TECHNIQUES / WORKFLOWS / MODULES — catalogue+refresh de modules, pré-vol de
// scope, plan à blanc, registre/sélection de techniques ATT&CK, CRUD des workflows — extraits de
// main.rs (PURE MOVE). Re-exporté `pub(crate)` à la racine pour que les routes de build_router
// (`get(modules)`, `post(plan)`, `post(scope_check)`, `get(techniques_catalog)`, …), les appelants
// inter-fichiers (run_create -> `modules_catalog`/`filter_enabled_modules`) ET les tests inline
// (`super::*`) résolvent ces handlers/helpers INCHANGÉS.
mod planning;
pub(crate) use crate::planning::*;
// RUN-LIFECYCLE / C2-light (lancement gouverné + audité de campagnes depuis l'UI web) : run_create /
// run_cancel / runs_list / run_detail / run_logs / run_sse + le superviseur détaché (spawn_supervisor) +
// le réconciliateur de boot (reconcile_runs) + l'ingestion de scanners (import_scan) + la validation de
// params RUN-SPÉCIFIQUE (validate_module_params/validate_modules/high_impact_*) — extraits de main.rs
// (PURE MOVE). Les structs d'ÉTAT (App/RunState/RunHandle/RunEvent/Engagement) RESTENT ici (stage state),
// référencées via crate::. Re-exporté `pub(crate)` à la racine pour que les routes de build_router
// (`post(run_create)`, `get(runs_list)`, …), les appelants inter-fichiers (run_report -> `RUN_JOB_COLS`/
// `run_job_json`) ET les tests inline (`super::*`) résolvent ces handlers/helpers INCHANGÉS.
mod runs;
pub(crate) use crate::runs::*;
// RUN-LIFECYCLE (suite, PURE MOVE) — god-file `runs.rs` scindé en modules cohésifs, tous re-exportés
// `pub(crate)` à la racine (mêmes résolutions `crate::*`/`super::*` INCHANGÉES) : `runs_proc` (supervision
// de process OS : spawn_setsid/kill_group/purge_stale_run_dirs/push_run_log/claim_and_spawn/
// spawn_supervisor), `runs_ha` (HA/leader : reconcile_runs/ReconcileScope/reap_dead_leader_runs/
// RunReservation/reserve_engagement_slot/RunSpawnSpec/enqueue_pending/claim_run_running/
// unclaim_running_on_failure/run_cancel_ha/LEADER_TICK_SECS/leader_tick_loop/cancel_watch_tick/
// claim_pending_tick), `runs_validate` (validation params : validate_module_params/validate_modules/
// high_impact_modules/high_impact_gate).
mod runs_proc;
pub(crate) use crate::runs_proc::*;
mod runs_ha;
pub(crate) use crate::runs_ha::*;
mod runs_validate;
pub(crate) use crate::runs_validate::*;
// ENGAGEMENT (objet de 1re classe) : CRUD gouverné + audité (engagements_list/create/update +
// engagement_do_update/engagement_do_delete) + la résolution de scope/engagement partagée par le run flow
// et les vues (host_in_server_scope/host_in_scope_list/resolve_engagement/resolve_view_engagement_id/
// resolve_mutation_engagement_id/derive_engagement_ledger_path/validate_engagement_scope/
// engagement_list_json) — extraits de main.rs (PURE MOVE). Les structs d'ÉTAT (App/Engagement) RESTENT
// ici (stage state), référencées via crate::. Re-exporté `pub(crate)` à la racine pour que les routes de
// build_router (`get(engagements_list).post(engagements_create)`, `post(engagements_update)`), les
// appelants inter-fichiers (ledger_api/finding_templates/planning/runs/findings -> resolve_*_engagement_id,
// host_in_server_scope, resolve_engagement) ET les tests inline (`super::*`) résolvent INCHANGÉS.
mod engagements;
pub(crate) use crate::engagements::*;
// AUTH / SESSIONS / GARDES (auth opérateur argon2 + RBAC repris de Plume, politique source-CIDR,
// identité résolue + sessions, handler whoami, middlewares host_guard/auth_guard) extraits de main.rs
// (PURE MOVE). Re-exporté `pub(crate)` à la racine pour que les routes/middlewares de build_router
// (`get(whoami)`, `host_guard`, `auth_guard`), les appelants inter-modules (`crate::check_admin`,
// `crate::check_operator`, `crate::attribution_login`, `crate::create_session`,
// `crate::resolve_session_identity`, `crate::session_token_from_headers`, `crate::operator_denied`,
// `crate::admin_denied`, `crate::Identity` …) ET les tests inline (`super::*`) résolvent INCHANGÉS.
mod auth;
pub(crate) use crate::auth::*;
// CLIENT HTTP-OUT (fetcher intégré std-only, sans TLS/openssl) : HttpAuth + parse_http_auth +
// http_get_blocking + dechunk, extraits de main.rs (PURE MOVE). Re-exporté `pub(crate)` à la racine pour
// que les appelants inter-modules (`crate::http_get_blocking`, `crate::HttpAuth`, `crate::dechunk` depuis
// sso/scim/detection) ET les tests inline (`super::*`) résolvent INCHANGÉS.
mod net;
pub(crate) use crate::net::*;
// ADMINISTRATION WEB DES COMPTES (#4) — CRUD des comptes réservé check_admin + GOUVERNANCE opérateur des
// connecteurs (module_governance), extraits de main.rs (PURE MOVE). Les structs d'ÉTAT (App) RESTENT ici
// (stage state), référencées via crate::. Re-exporté `pub(crate)` à la racine pour que les routes de
// build_router (`get(users_list).post(users_create)`, `post(users_update).delete(users_delete)`,
// `post(module_governance)`), les appelants inter-modules (`crate::role_rank` depuis rbac) ET les tests
// inline (`super::*` → admin_create_user/admin_update_user/admin_delete_user/admin_list_users/users_*/
// module_governance) résolvent ces handlers/helpers INCHANGÉS.
mod users;
pub(crate) use crate::users::*;
// ÉTAT PARTAGÉ (`App`) + substrat couplé (structs App/RunState/RunHandle/RunEvent/LedgerHead/Engagement,
// SCHEMA+migrate()+ensure_default_*/populate_modules, resolve_web_dir/load_server_scope, settings_get/set,
// now_epoch, sous-système DÉTECTION/purple + run_report) extrait de main.rs (PURE MOVE, stage `state`). Les
// frères ne voyant plus les champs privés d'App une fois hors racine, ils sont passés `pub(crate)` (pure
// visibilité). Re-exporté à la racine pour que build_router/main, les modules frères (`crate::App`,
// `crate::settings_get`, `crate::migrate`, `crate::now_epoch`, `crate::resolve_web_dir` …) ET les tests
// inline (`super::*`) résolvent ces items INCHANGÉS.
mod state;
pub(crate) use crate::state::*;

// SCHÉMA DB + SEEDING (`SCHEMA`/`PG_SCHEMA`, `migrate()`, `ensure_default_*`, `populate_modules`,
// `advance_pg_identity_sequences*`) — cluster cohésif EXTRAIT de state.rs (PURE MOVE, byte-identique).
mod schema;
pub(crate) use crate::schema::*;

// SOUS-SYSTÈME DÉTECTION / purple-coverage (source configurable + collecte + corrélation + handlers
// `purple_coverage`/`detection_*`) — cluster cohésif EXTRAIT de state.rs (PURE MOVE, byte-identique).
mod detection;
pub(crate) use crate::detection::*;

// PORTABLE DB-ACCESS SEAM (Stage 0) — backend-agnostic façade over the SQLite connection whose public
// API leaks no rusqlite type (see store.rs). `App::store()` wraps the SAME `Mutex<Connection>` as
// `App::db()`; modules migrate onto it one at a time (`App::db()` stays available for the rest).
mod store;

// BLOBSTORE SEAM (readiness-dossier #12) — store d'artefacts backend-agnostique (archive de backup
// offsite, exports/évidence). Le build PAR DÉFAUT (community) ne compile QUE `LocalFsBlobStore`
// (système de fichiers, AUCUNE dép nouvelle) : chemin par défaut inchangé. `S3BlobStore` (S3/MinIO) +
// sa dép `rust-s3` vivent DERRIÈRE la feature OPT-IN `object-store` (openssl-free : sync-rustls-tls ->
// attohttpc + rustls/ring). Référencé fully-qualified (`crate::blob::…`) — pas de glob re-export.
mod blob;



/// Construit le routeur axum complet : routes PUBLIQUES (hors auth_guard : /health, /api/login, wizard
/// de 1er déploiement /api/setup*) + routes PROTÉGÉES (derrière auth_guard) + fallback ServeDir, le
/// tout sous host_guard (anti-rebinding). Extrait de main() pour être exercé TEL QUEL par les tests
/// d'intégration (parité stricte du câblage : ce qui est gaté en prod l'est en test). `app` est déplacé
/// dans le routeur (with_state) ; le ConnectInfo est branché au moment du `serve`, pas ici.
/// GET /health — sonde PUBLIQUE (hors auth_guard). ADDITIF Stage 4 : PING du store ACTIF (SQLite ou
/// Postgres) via un `SELECT 1` à travers le seam. RAPIDE + NON-FATAL : /health répond TOUJOURS 200
/// (liveness du routeur HTTP) et ajoute `db: "ok" | "degraded"` — `degraded` si le ping échoue (PG
/// down/injoignable ; sous PG le ping traverse le reconnect+retry single-shot, donc une coupure
/// transitoire GUÉRIT en `ok`, un serveur réellement down retombe en `degraded`). Champ `db` ADDITIF : la
/// forme community `{status, version}` reste compatible (le healthcheck compose ne teste que le 200).
async fn health(axum::extract::State(app): axum::extract::State<App>) -> Json<Value> {
    let db_ok = health_db_ping(&app);
    #[allow(unused_mut)] // `body` is only mutated under the `store-postgres` HA arm below.
    let mut body = json!({
        "status": "ok",
        "version": forge_version(),
        "db": if db_ok { "ok" } else { "degraded" },
    });
    // SCHEMA VERSION (ADDITIF) : version LOGIQUE de la base (settings.schema_version), tamponnée par
    // migrate()/le boot PG. Répond « à quelle version est cette base » — base de l'upgrade sûr. Omis
    // (jamais `null`) sur une base ANTÉRIEURE au stamp (clé absente) : additif, ne casse aucun consommateur.
    if let Some(sv) = crate::schema::read_schema_version(&app.store()) {
        body["schema_version"] = json!(sv);
    }
    // HA (#10 Wave A) — ADDITIVE `leader`/`instance_id`. PG-only (feature-gated): the community build does
    // not compile this arm, so its `/health` stays `{status, version, db}` byte-identical. In the Postgres
    // build a SINGLE instance (FORGE_HA unset) reports `leader:true` (ha::is_leader short-circuits); under HA
    // exactly one replica reports `leader:true` (it holds the lease), the others `leader:false`.
    #[cfg(feature = "store-postgres")]
    {
        body["leader"] = Value::Bool(crate::ha::is_leader(&app));
        body["instance_id"] = Value::String((*app.instance_id).clone());
    }
    Json(body)
}

/// PING léger et borné du store ACTIF : `SELECT 1` via `App::store()`. `true` si la valeur `1` revient.
/// SYNCHRONE (aucun `.await` en tenant le guard `!Send`) et sans panique (toute `Err` -> `false`). Sous
/// Postgres, `store().query_row` traverse le reconnect+retry HA : une coupure transitoire est guérie
/// (db:ok), un PG réellement down échoue la (re)connexion -> `false` -> `db:degraded`.
fn health_db_ping(app: &App) -> bool {
    let store = app.store();
    store
        .query_row("SELECT 1", &crate::sql_params![], |r| r.get_i64(0))
        .map(|v| v == 1)
        .unwrap_or(false)
}

fn build_router(app: App, web_dir: &str) -> Router {
    // routes protégées par auth_guard ; ServeDir sert les assets statiques (style.css/app.js/quetzal.svg/
    // favicon.svg/fonts/…) en fallback pour toute route non-API non matchée — l'index `/` reste rendu
    // par include_str!.
    let protected = Router::new()
        .route("/", get(index))
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
        .route("/api/campaigns", get(campaigns))
        // ENGAGEMENT (objet de 1re classe) : liste + compteurs (viewer) ; create = OPÉRATEUR ; edit/
        // archive/delete via POST :id (edit=OPÉRATEUR, archive/delete=ADMIN, cf. handler). Chaque mutation
        // ledgerisée `console.engagement.*`. Les vues (findings/runrecords/roe/ledger/coverage/runs) filtrent
        // sur l'engagement actif (`?engagement=`). Le segment `:id` (i64) ne collisionne pas avec la liste.
        .route("/api/engagements", get(engagements_list).post(engagements_create))
        .route("/api/engagements/:id", post(engagements_update))
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
        .fallback_service(ServeDir::new(web_dir))
        .route_layer(middleware::from_fn_with_state(app.clone(), auth_guard));
    Router::new()
        // /health : sonde ouverte (hors auth_guard). JSON {status, version, db} — `version` provient du
        // fichier VERSION (source unique) ; `db` (ADDITIF Stage 4) PING le store ACTIF. `forge doctor
        // --purple` et le healthcheck compose ne testent que le code HTTP 200 (forme préservée).
        .route("/health", get(health))
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
        .with_state(app)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // sous-commandes de provisioning de hash argon2id :
    //   forge-console hashpw <password>           -> hash du viewer (FORGE_CONSOLE_PASS_HASH)
    //   forge-console hashpw-operator <password>  -> hash du rôle OPÉRATEUR C2 (FORGE_CONSOLE_OPERATOR_HASH)
    let args: Vec<String> = std::env::args().collect();
    // Dispatch CLI extrait dans `dispatch_cli` (PURE EXTRACTION, parité stricte) : `Some(code)` => une
    // sous-commande a tourné, on sort avec ce code ; `None` => aucune sous-commande, on enchaîne sur le
    // boot serveur. Mêmes sous-commandes, MÊMES codes de sortie, même ordre qu'avant.
    if let Some(code) = dispatch_cli(&args) {
        std::process::exit(code);
    }
    serve().await;
}

/// Dispatch des sous-commandes CLI (hors chemin HTTP) — PURE EXTRACTION du `match args.get(1)` inline
/// de main() : mêmes sous-commandes, MÊMES codes de sortie, même ordre. Renvoie `Some(exit_code)` si une
/// sous-commande a été prise en charge (l'appelant sort avec ce code) ou `None` pour enchaîner sur le
/// boot serveur. Purement synchrone (aucun await).
fn dispatch_cli(args: &[String]) -> Option<i32> {
    match args.get(1).map(String::as_str) {
        // --version / -V : imprime la version unique (fichier VERSION, include_str! à la compile).
        Some("--version") | Some("-V") => {
            println!("forge-console {}", forge_version());
            Some(0)
        }
        Some("hashpw") | Some("hashpw-operator") => {
            match args.get(2) {
                Some(pw) if !pw.is_empty() => {
                    println!("{}", hash_pw(pw));
                    Some(0)
                }
                _ => {
                    eprintln!("usage: forge-console {} <password>", args[1]);
                    Some(2)
                }
            }
        }
        // Parité LECTURE locale (CLI) : lit la MÊME base SQLite que l'API, en READ-ONLY, et
        // imprime en table (défaut) ou JSON (--json). Aucune écriture, aucun spawn — pure lecture.
        Some(cmd @ ("findings" | "roe" | "coverage" | "query")) => {
            Some(run_read_cli(cmd, &args[2..]))
        }
        // Provisioning d'un COMPTE INDIVIDUEL : forge-console useradd <login> <role> [--pass <pw>]
        //   role ∈ {viewer|operator|admin}. Le mot de passe est lu sur STDIN par défaut (jamais en
        //   argv -> pas de fuite via ps/cmdline) ; `--pass <pw>` est toléré pour le scripting. Le hash
        //   argon2id est calculé ici et stocké dans `users` (idempotent par login : upsert + réactive).
        Some("useradd") => {
            Some(run_useradd_cli(&args[2..]))
        }
        // AMORÇAGE DÉMO : forge-console seed-demo [--dir <path>] [--campaign <name>]
        //   Charge l'engagement de référence synthétique (examples/reference-engagement/) DIRECTEMENT
        //   dans la base SQLite (hors-ligne, sans réseau, sans /api/ingest) pour qu'une console fraîche
        //   affiche immédiatement Findings/Coverage/Purple/Runs. Idempotent (purge la campagne démo).
        Some("seed-demo") => {
            Some(run_seed_demo_cli(&args[2..]))
        }
        // MIGRATION DE DONNÉES : forge-console migrate --from <dir|db> --to <db> [--ledger <path>]
        //   [--verify] [--encrypt --key-env <ENVVAR>]. Importe un install Forge existant (non-Docker)
        //   vers une base cible (Docker/autre) : copie DB (VACUUM INTO / SQLCipher), ledger + clé
        //   .ed25519 (0600), puis SCHEMA + migrate() sur la cible. UX primaire = conteneur one-shot.
        Some("migrate") => {
            Some(run_migrate_cli(&args[2..]))
        }
        // MIGRATION DE STORE (feature `store-postgres`) : forge-console migrate-store --to <postgres-url>
        //   [--from <sqlite-path>] [--dry-run] [--force] [--ledger <path>]. Copie gouvernée SQLite ->
        //   Postgres à travers le seam (ids + typage préservés, ordre FK, recalage IDENTITY, vérif des
        //   comptes, checkpoint ledger signé). Arm ENTIÈREMENT gardé par la feature -> le build community
        //   (défaut) ne la connaît pas (retombe sur le boot serveur), et reste BYTE-IDENTICAL.
        #[cfg(feature = "store-postgres")]
        Some("migrate-store") => {
            Some(crate::cli::run_migrate_store_cli(&args[2..]))
        }
        // SAUVEGARDE CHIFFRÉE : forge-console backup --out <archive> --passphrase-env <ENVVAR>
        //   [--db <path>] [--ledger <path>]. Archive TOUJOURS chiffrée (argon2id + XChaCha20-Poly1305)
        //   regroupant snapshot DB (VACUUM INTO) + ledger + clé .ed25519 + manifest.json. Passphrase
        //   lue UNIQUEMENT depuis l'ENV (jamais argv). Chaîne ledger vérifiée avant, backup tracé.
        Some("backup") => {
            Some(run_backup_cli(&args[2..]))
        }
        // RESTAURATION CHIFFRÉE : forge-console restore --in <archive> --passphrase-env <ENVVAR>
        //   [--to <db>] [--ledger <path>] [--force]. Déchiffre (mauvaise passphrase/altération => rien
        //   écrit), vérifie les sha256 du manifest + la chaîne ledger, refuse d'écraser un install non
        //   vide sans --force, place db/ledger/clé (.ed25519 = 0600). Restore tracé au ledger.
        Some("restore") => {
            Some(run_restore_cli(&args[2..]))
        }
        // ROUND-TRIP BLOBSTORE (feature `object-store`) : forge-console blob-selftest [--key <key>]
        //   [--no-delete]. PUT -> GET -> compare octets -> EXISTS -> (DELETE) sur le store ACTIF (S3/MinIO
        //   si FORGE_BLOB_S3_* configuré, sinon local FORGE_BLOB_DIR). Preuve d'aller-retour sans serveur.
        //   Arm ENTIÈREMENT gardé par la feature -> le build community (défaut) ne le connaît pas.
        #[cfg(feature = "object-store")]
        Some("blob-selftest") => {
            Some(crate::blob::run_blob_selftest_cli(&args[2..]))
        }
        // VÉRIF LEDGER (lecture seule, NON INTERACTIVE, RAPIDE) : forge-console ledger verify
        //   [--ledger <path>] [--json]. Recompute la chaîne SHA-256 du ledger JSONL et exit immédiat
        //   (0 intègre / 1 rompu-absent / 2 usage). NE démarre PAS le serveur, n'ouvre PAS la base,
        //   ne lit PAS STDIN. La vérif de signature reste côté `forge ledger verify --pubkey` (Python).
        Some("ledger") => {
            Some(run_ledger_cli(&args[2..]))
        }
        // ÉTAT (lecture seule, NON INTERACTIF, RAPIDE) : forge-console status [--db <path>]
        //   [--ledger <path>] [--json]. Imprime version, VERSION DE SCHÉMA persistée, backend actif,
        //   base RÉDIGÉE, tête de ledger vérifiée — SANS démarrer le serveur. Base d'un upgrade sûr.
        Some("status") => {
            Some(run_status_cli(&args[2..]))
        }
        // UPGRADE SÛR EN UNE COMMANDE (fail-closed avec rollback) : forge-console upgrade
        //   --passphrase-env <ENV> [--db <path>] [--ledger <path>] [--backup-dir <dir>]
        //   [--to <postgres-url>] [--force] [--dry-run]. Snapshot pré-upgrade CHIFFRÉ (moteur backup
        //   audité) -> migrate additif (+ migration de store si --to) -> vérif schéma/ledger/santé ->
        //   RESTORE (rollback à l'état exact d'avant) sur tout échec. Idempotent ; --dry-run ne mute rien.
        Some("upgrade") => {
            Some(run_upgrade_cli(&args[2..]))
        }
        _ => None,
    }
}

/// Boot du serveur HTTP — PURE EXTRACTION du corps de main() après le dispatch CLI. Sélection du store
/// (gate enterprise), pool PG hors-runtime, gate HA fail-closed, chargement du scope serveur, construction
/// de l'App, amorçage boot routé par le backend ACTIF (SQLite/Postgres), spawns des boucles de fond
/// (heartbeat/leader-tick/cache-poll/présence puis backup-scheduler) puis bind + serve. L'ordre des étapes,
/// l'ordre des spawns et le gating HA sont STRICTEMENT inchangés par rapport à l'ancien main() monolithique.
async fn serve() {
    let db_path = std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge-console.db".to_string());
    let conn = Connection::open(&db_path).expect("open db");
    // CHIFFREMENT AU REPOS (opt-in, feature `encryption`) : si FORGE_DB_KEY est posé, `PRAGMA key`
    // DOIT précéder TOUTE autre requête (sinon SQLCipher lit une base illisible). Dans le build par
    // défaut (feature off), ce hook n'est pas compilé -> base en clair, comportement inchangé.
    #[cfg(feature = "encryption")]
    apply_db_key_on_boot(&conn);
    // WAL : meilleure concurrence lecture/écriture (les /api lecture-seule via une 2e connexion
    // read-only ne bloquent plus les écritures) + reprise sur crash plus propre. busy_timeout évite
    // qu'une écriture concurrente échoue immédiatement sur SQLITE_BUSY. Best-effort (PRAGMA renvoie une
    // ligne -> query_row), error-ignoré : si le FS ne supporte pas WAL, on retombe sur le mode par défaut.
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    // SQLITE CARVE-OUT (connexion brute, backend-specific) : PRAGMA/SCHEMA/migrate/SQLCipher préparent
    // la base SQLite qui devient `App.db` (toujours présente, même en mode Postgres — c'est le fallback
    // du seam). `execute_batch(SCHEMA)+migrate()` est la BRANCHE SQLITE du backend-switch de DDL boot :
    // quand le backend actif sera Postgres, PG_SCHEMA est appliqué EN PLUS via `app.store()` après la
    // construction de l'App (cf. plus bas). L'AMORÇAGE (ensure_default_*/populate_modules/reconcile_runs)
    // ne s'exécute plus ICI : il est routé par le backend ACTIF (`app.store()`), après l'App.
    conn.execute_batch(SCHEMA).expect("schema");
    migrate(&conn); // ALTER additifs error-ignored (run_id, fix, panel étendu, run_job C2, dashboard_id)

    // ENTERPRISE STORE (Postgres) — CÂBLÉ (Stage 2b batch 5). La gate décide le backend ACTIF depuis
    // FORGE_ENTERPRISE_STORE + FORGE_DB_URL : Postgres UNIQUEMENT si la feature `store-postgres` est
    // compilée ET FORGE_DB_URL est posé (sinon erreur claire) ; tout autre cas => SQLite (défaut
    // community inchangé/byte-identique). Le split-brain d'antan n'existe plus : quand PG est actif,
    // TOUT le DML + l'amorçage boot passent par `app.store()` (routé sur le client PG) et le DDL boot
    // applique PG_SCHEMA au lieu de SCHEMA+migrate (cf. bloc AMORÇAGE plus bas). La connexion SQLite
    // ouverte ci-dessus reste le repli du seam (`App.db`), non utilisée quand `App.pg` est `Some`.
    let requested_store = std::env::var("FORGE_ENTERPRISE_STORE").ok();
    let db_url_env = std::env::var("FORGE_DB_URL").ok();
    let store_selection = match enterprise_store_gate(requested_store.as_deref(), db_url_env.as_deref()) {
        Ok(sel) => sel,
        Err(msg) => {
            eprintln!("[forge-console] FATAL {msg}");
            std::process::exit(2);
        }
    };
    // Connexion PG (feature `store-postgres`) : établie HORS du runtime tokio (le client `postgres`
    // synchrone pilote son PROPRE `block_on` — le connecter depuis le runtime `#[tokio::main]`
    // paniquerait « runtime within a runtime »). On la fait donc sur un `std::thread` dédié, puis on
    // porte le client session-pinné dans `App.pg`. En SQLite (ou build community, bloc non compilé) :
    // `None` -> `store()` retombe sur SQLite.
    #[cfg(feature = "store-postgres")]
    let pg: Option<Arc<crate::store::PgPool>> = match &store_selection {
        StoreSelection::Postgres(url) => {
            let url = url.clone();
            // Taille du pool : FORGE_PG_POOL (défaut 8, borné 1..=64). N clients = N écritures
            // concurrentes non sérialisées au sein d'une instance.
            let pool_size = std::env::var("FORGE_PG_POOL")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n > 0)
                .map(|n| n.min(64))
                .unwrap_or(8);
            let connect_url = url.clone();
            // Connexion HORS du runtime tokio (le client `postgres` synchrone pilote son PROPRE
            // `block_on` — connecter depuis `#[tokio::main]` paniquerait « runtime within a runtime »).
            // On connecte les N clients sur un `std::thread` dédié ; un échec sur l'un est fatal.
            let clients: Vec<crate::store::PgClient> = std::thread::spawn(move || {
                (0..pool_size)
                    .map(|_| crate::store::connect_postgres(&connect_url))
                    .collect::<Result<Vec<_>, _>>()
            })
            .join()
            .expect("postgres connect thread panicked")
            .unwrap_or_else(|e| {
                eprintln!("[forge-console] FATAL {e}");
                std::process::exit(2);
            });
            println!("[forge-console] store: Postgres (FORGE_DB_URL) — pool de {pool_size} clients connecté (écritures concurrentes, reconnect+retry HA armé)");
            // Stage 4 HA : le DSN voyage AVEC le pool pour re-établir un client cassé dans son slot après
            // une coupure (restart/failover) — cf. `Store::postgres_reconnectable`.
            Some(Arc::new(crate::store::PgPool::new(url, clients)))
        }
        StoreSelection::Sqlite => None,
    };
    #[cfg(not(feature = "store-postgres"))]
    let _ = &store_selection; // SQLite only (community) — variable consommée pour éviter un warning

    // ================================ HA (#10 Wave A) — OPT-IN + FAIL-CLOSED ================================
    // HA engages ONLY when FORGE_HA is truthy AND the ACTIVE store is Postgres. On a NON-Postgres store a
    // shared leader lease is meaningless (each replica has its own SQLite file) and UNSAFE, so we FAIL CLOSED
    // at boot (clear error + non-zero exit) rather than silently run split-brain. `instance_id` is this
    // process's identity (FORGE_INSTANCE_ID | container hostname | a boot gen_token) — the lease holder key
    // and a per-replica id under `--scale`. Read ONCE here; stored on `App.{ha,instance_id,is_leader}`.
    #[cfg(feature = "store-postgres")]
    let (ha, instance_id) = {
        let want_ha = flags::env_truthy("FORGE_HA");
        if want_ha && pg.is_none() {
            eprintln!("[forge-console] FATAL FORGE_HA=1 requires FORGE_ENTERPRISE_STORE=postgres — HA is unsafe on SQLite");
            std::process::exit(2);
        }
        let iid = std::env::var("FORGE_INSTANCE_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(gen_token);
        (want_ha && pg.is_some(), iid)
    };
    // Community build (no Postgres backend compiled): HA is impossible. If the operator set FORGE_HA expecting
    // it, FAIL CLOSED with the same guidance rather than silently running a single unsynchronised instance.
    #[cfg(not(feature = "store-postgres"))]
    if flags::env_truthy("FORGE_HA") {
        eprintln!("[forge-console] FATAL FORGE_HA=1 requires FORGE_ENTERPRISE_STORE=postgres — HA is unsafe on SQLite (this binary has no Postgres backend; rebuild with --features store-postgres)");
        std::process::exit(2);
    }

    let token = std::env::var("FORGE_CONSOLE_TOKEN").unwrap_or_else(|_| gen_token());
    let user = std::env::var("FORGE_CONSOLE_USER").unwrap_or_else(|_| "forge".to_string());
    let pass_hash = std::env::var("FORGE_CONSOLE_PASS_HASH").unwrap_or_default();
    // rôle OPÉRATEUR (C2) — FAIL-CLOSED : vide => tout endpoint C2 renvoie 403.
    let operator_hash = std::env::var("FORGE_CONSOLE_OPERATOR_HASH").unwrap_or_default();
    // racine du paquet Forge (où vit `forge/`) — cwd du spawn `python -m forge.cli campaign`.
    let pkg_dir = std::env::var("FORGE_PKG_DIR").unwrap_or_else(|_| "..".to_string());
    let python = std::env::var("FORGE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let run_timeout_secs = std::env::var("FORGE_RUN_TIMEOUT").ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1800); // 30 min
    // scope serveur autorisé : pré-filtre fail-closed des cibles lançables depuis le web.
    // Source : FORGE_CONSOLE_SCOPE (chemin d'un scope.json) ; sinon scope.json relatif au pkg_dir.
    let (scope_in, scope_mode) = load_server_scope(&pkg_dir);
    // DÉTECTION (mesure de couverture, purple) : la SOURCE est configurable (settings.detection_source),
    // avec repli rétro-compat sur l'env legacy PLUME_URL/PLUME_TOKEN. Le cache est chargé JUSTE APRÈS la
    // construction de l'App (reload_detection_source, qui lit la table settings + l'env). Source absente
    // => /api/detection/coverage (alias /api/purple/coverage) répond en FAIL-OPEN LISIBLE.
    let mut allowed = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
    if let Ok(h) = std::env::var("FORGE_CONSOLE_HOST") {
        if !h.is_empty() {
            allowed.push(h);
        }
    }

    // ledger JSONL : chemin par défaut relatif au pkg dir Forge (où `forge campaign --ledger` écrit).
    let ledger_path = std::env::var("FORGE_CONSOLE_LEDGER").unwrap_or_else(|_| "engagement.jsonl".to_string());
    // NB: l'amorçage ENGAGEMENT #1 / TENANT #1 (migration ZÉRO-PERTE) est routé par le backend ACTIF via
    // `app.store()` APRÈS la construction de l'App (cf. bloc « AMORÇAGE BOOT »), plus ici sur `conn` brut.
    // racine des assets web statiques (style.css/app.js/fonts/…) servis en fallback.
    let web_dir = resolve_web_dir();
    println!("[forge-console] web assets: {web_dir}");

    // NE PAS journaliser le token en clair (fuite via logs/journald/historique terminal). On affiche
    // une empreinte courte (8 hex de sha256) — suffisante pour corréler/diagnostiquer sans exposer le
    // secret. Le token en clair reste disponible à l'opérateur via FORGE_CONSOLE_TOKEN (qu'il a posé).
    let token_was_provided = std::env::var("FORGE_CONSOLE_TOKEN").map(|v| !v.is_empty()).unwrap_or(false);
    let token_fp = &sha_hex(&token)[..8];
    if token_was_provided {
        println!("[forge-console] ingest token: (fourni via env) fp=sha8:{token_fp}");
    } else {
        // token auto-généré, ÉPHÉMÈRE : on n'imprime QUE l'empreinte (comme la branche env), JAMAIS le
        // secret en clair (fuite via logs/journald/historique terminal). Le moteur spawné le reçoit en
        // mémoire (App.token_raw) — la boucle purple / l'ingest interne fonctionnent sans l'afficher. Pour
        // un `/api/ingest` MANUEL reproductible, l'opérateur POSE `FORGE_CONSOLE_TOKEN=<valeur connue>`
        // (qu'il choisit) et redémarre : la branche « fourni via env » ci-dessus s'appliquera alors.
        println!("[forge-console] ingest token (auto-généré, éphémère) fp=sha8:{token_fp} — pose FORGE_CONSOLE_TOKEN=<valeur connue> pour le fixer et t'en servir en /api/ingest manuel");
    }
    println!("[forge-console] db: {db_path}");
    println!("[forge-console] ledger: {ledger_path}");
    // ÉTAT DB de la gate d'auth : un compte activé en base engage la gate MÊME sans hash env (ferme le
    // trou dev-open historique). On le calcule ici sur `conn` (avant son déplacement dans App) pour un
    // log fidèle ; App.recompute_auth_required() recalcule ensuite le cache faisant autorité.
    let has_enabled_user: bool =
        conn.query_row("SELECT 1 FROM users WHERE disabled=0 LIMIT 1", [], |_| Ok(())).is_ok();
    if pass_hash.is_empty() && !has_enabled_user {
        println!("[forge-console] AUTH OFF (dev localhost) — ni FORGE_CONSOLE_PASS_HASH ni compte activé en base. `forge-console useradd <login> admin` (ou pose le hash env) pour engager la gate.");
    } else if pass_hash.is_empty() {
        println!("[forge-console] auth ON (état DB) — gate engagée par au moins un compte activé (table users) ; connexion via POST /api/login (session individuelle) ; hash env absent");
    } else {
        println!("[forge-console] auth ON — user={user}, lectures protégées (Basic), écritures par token (comptes individuels via POST /api/login également acceptés)");
    }
    if operator_hash.is_empty() {
        println!("[forge-console] C2 FAIL-CLOSED — rôle opérateur NON provisionné (FORGE_CONSOLE_OPERATOR_HASH absent) : /api/run* renverra 403. `forge-console hashpw-operator '...'` pour l'activer.");
    } else {
        println!("[forge-console] C2 armé — rôle opérateur via en-tête X-Forge-Operator ; cibles ⊆ scope serveur ({} entrée(s)) ; exploit/destructif possibles UNIQUEMENT via opt-in haut-impact gouverné (allow_high_impact + arm + reason, journalisé au ledger) ; scope-guard moteur inchangé (hors-scope = VETO) ; watchdog={run_timeout_secs}s", scope_in.len());
    }

    // (log DÉTECTION déplacé après la construction de l'App + reload_detection_source — la source
    //  n'est connue qu'une fois le cache chargé depuis settings/env.)

    // [SÉCURITÉ XFF] Garde-fou/migration du réglage `trusted_proxy` : il doit désormais contenir le/les
    // CIDR(s) du proxy amont (Traefik/cluster, egress Cloudflare…). Une valeur héritée « truthy » non-CIDR
    // (ex. "1"/"true") ne produit AUCUN CIDR valide -> on n'accorde foi à AUCUN X-Forwarded-For (repli
    // fail-closed sur le pair TCP). On alerte l'opérateur pour qu'il reconfigure explicitement.
    match settings_get(&conn, "trusted_proxy") {
        Some(raw) if !raw.trim().is_empty() && parse_trusted_proxy_cidrs(&raw).is_empty() => {
            eprintln!("[forge-console] WARN trusted_proxy={raw:?} n'est PAS un CIDR valide — X-Forwarded-For sera IGNORÉ (repli fail-closed sur le pair TCP). Reconfigure `trusted_proxy` sur le(s) CIDR(s) du proxy amont réel (ex. le CIDR Traefik/cluster ou l'egress Cloudflare), sinon la politique opérateur source-CIDR verra l'IP du proxy et jamais celle du client.");
        }
        Some(raw) if !raw.trim().is_empty() => {
            println!("[forge-console] trusted_proxy: X-Forwarded-For honoré UNIQUEMENT si le pair TCP appartient à {:?}", parse_trusted_proxy_cidrs(&raw));
        }
        _ => {}
    }

    let (events, _) = broadcast::channel::<RunEvent>(1024);
    let app = App {
        db: Arc::new(Mutex::new(conn)),
        db_path: Arc::new(db_path.clone()),
        // ENTERPRISE STORE (Stage 2b batch 5) : `Some(client)` quand PG est sélectionné (gate ci-dessus),
        // sinon `None` -> `store()` route sur SQLite. Le champ n'existe que sous la feature (struct
        // byte-identique quand OFF).
        #[cfg(feature = "store-postgres")]
        pg,
        // HA (#10 Wave A) — computed once above. `is_leader` starts at `!ha` : a single instance (or a
        // non-HA Postgres deploy) is leader immediately; under HA it starts NOT-leader until the first
        // heartbeat acquires the lease (`ha::is_leader` short-circuits to true when `ha` is false anyway).
        #[cfg(feature = "store-postgres")]
        ha,
        #[cfg(feature = "store-postgres")]
        instance_id: Arc::new(instance_id),
        #[cfg(feature = "store-postgres")]
        is_leader: Arc::new(AtomicBool::new(!ha)),
        token_sha: Arc::new(sha_hex(&token)),
        token_raw: Arc::new(token.clone()),
        user: Arc::new(user),
        pass_hash: Arc::new(pass_hash),
        auth_required: Arc::new(AtomicBool::new(false)), // recalculé juste après (recompute_auth_required)
        operator_hash: Arc::new(operator_hash),
        allowed_hosts: Arc::new(allowed),
        ledger_path: Arc::new(ledger_path),
        pkg_dir: Arc::new(pkg_dir),
        python: Arc::new(python),
        scope_in: Arc::new(scope_in),
        scope_mode: Arc::new(scope_mode),
        // cache provisoire (kind=none) ; rechargé depuis settings/env juste après (reload_detection_source).
        detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
        run_timeout_secs,
        run_state: Arc::new(AsyncMutex::new(RunState { current: HashMap::new() })),
        run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        events,
        ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
    };

    // ========================= AMORÇAGE BOOT (routé par le backend ACTIF) =========================
    // Backend-switch du DDL boot : la BRANCHE SQLITE (execute_batch(SCHEMA)+migrate) a déjà tourné sur
    // la connexion de repli ci-dessus ; si le backend ACTIF est Postgres (`app.pg` = Some), on applique
    // PG_SCHEMA via `app.store()` (routé sur le client PG) — le miroir PG du SCHEMA, colonnes de
    // migrate() déjà fusionnées — À LA PLACE de SCHEMA+migrate pour le backend actif. En SQLite (`app.pg`
    // = None, et build community non compilé) cette branche ne s'exécute pas : SCHEMA+migrate sur la
    // connexion SQLite = App.db font foi. L'amorçage ci-dessous passe ENSUITE par `app.store()` : il sème
    // le backend ACTIF (SQLite = byte-identique ; Postgres via le MÊME chemin seeder, cf. seeders portés).
    // WAVE-B LOW FIX — COLD-START DDL RACE (HA) : sous HA, deux réplicas démarrant un cluster VIERGE lancent
    // `execute_batch(PG_SCHEMA)` + les seeders id=1 (dashboard/engagement/tenant) SIMULTANÉMENT. `CREATE …
    // IF NOT EXISTS` (catalogue PG PARTAGÉ) et `SELECT COUNT(*) … puis INSERT id=1` NE sont PAS concurrency-
    // safe -> un réplica panique (« tuple concurrently updated » sur pg_type/pg_class, ou duplicate key). On
    // SÉRIALISE toute la section DDL+seed sous un `pg_advisory_xact_lock(BOOT_DDL_LOCK_KEY)` cluster-global :
    // un SEUL réplica applique schéma/seeds à la fois, les autres attendent puis voient tout déjà présent
    // (idempotent, aucun panic/abort). `populate_modules` (spawn python, upsert ON CONFLICT row-safe) et le
    // boot-reconcile restent HORS du verrou (aucune course id=1 ; on ne tient pas le verrou pendant un spawn).
    // En SQLite/community : chemin INCHANGÉ (aucun catalogue partagé -> aucun verrou, seeders directs).
    #[cfg(feature = "store-postgres")]
    let pg_active = app.pg.is_some();
    #[cfg(not(feature = "store-postgres"))]
    let pg_active = false;
    if pg_active {
        // PG : PG_SCHEMA + seeders id=1 + recalage des séquences IDENTITY, TOUT sous le verrou DDL cluster-
        // global (pg_advisory_xact_lock, auto-relâché au COMMIT). Le miroir PG du SCHEMA a les colonnes de
        // migrate() déjà fusionnées. Les seeders reçoivent le store TRANSACTIONNEL (tx.store()) -> même
        // connexion, dans le BEGIN, donc dans la section critique verrouillée.
        #[cfg(feature = "store-postgres")]
        app.store()
            .with_tx(|tx| {
                // FIX (isolation assumption): this serialization is correct ONLY under READ COMMITTED — the
                // seam's `with_tx` default isolation. Under READ COMMITTED the SECOND replica, once it wins the
                // advisory lock, re-evaluates its `SELECT COUNT(*)` seeder predicates against the FIRST
                // replica's ALREADY-COMMITTED rows and sees id=1 present -> no re-seed (idempotent). A stricter
                // level (REPEATABLE READ / SERIALIZABLE) would pin the second replica's snapshot at BEGIN,
                // BEFORE the first replica committed, so its COUNT(*) would still read 0 and it would re-INSERT
                // id=1 -> duplicate-key / double-seed. Do NOT raise the isolation of THIS boot tx without
                // moving the seeders to ON CONFLICT DO NOTHING upserts. (Comment only — no behaviour change.)
                tx.execute("SELECT pg_advisory_xact_lock(?)", &crate::sql_params![crate::ha::BOOT_DDL_LOCK_KEY])?;
                tx.execute_batch(PG_SCHEMA)?;
                // `tx.store()` is a getter returning the tx-owned `&Store` (the transaction owns the critical
                // section — there is no separate guard to tighten); call it inline so no aliasing binding is
                // held past its use. Behaviour-identical to a `let s = tx.store();` alias.
                ensure_default_dashboard(tx.store()); // dashboard #1 (rétro-compat) + rattache les panels orphelins
                // ENGAGEMENT #1 / TENANT #1 (migration ZÉRO-PERTE) — idempotents (count>0 => no-op). Sous le
                // verrou, un seul réplica les crée ; l'autre voit count>0 et ne réinsère pas id=1.
                ensure_default_engagement(tx.store(), &app.scope_in, &app.scope_mode, &app.ledger_path);
                ensure_default_tenant(tx.store());
                // Après TOUT seeding à id explicite : recale les séquences IDENTITY sur max(id) (sinon le 1er
                // INSERT-sans-id régénère id=1 -> duplicate key). Idempotent.
                advance_pg_identity_sequences(tx.store());
                // SCHEMA VERSION STAMP (parité avec la branche SQLite où `migrate()` tamponne) : le backend
                // Postgres applique `PG_SCHEMA` (colonnes de migrate déjà fusionnées) sans passer par
                // `migrate()`, donc on tamponne ICI, sous le même verrou DDL, après le schéma+seed.
                crate::schema::stamp_schema_version(tx.store());
                Ok::<(), crate::store::StoreError>(())
            })
            .expect("pg boot schema+seed (serialized under the DDL advisory lock)");
    } else {
        // SQLite (repli du seam) / community : SCHEMA+migrate ont déjà tourné sur la connexion brute ci-dessus.
        // Seeders directs, exactement comme historiquement (byte-identique). advance_pg_identity_sequences est
        // un NO-OP en SQLite (is_postgres()=false).
        ensure_default_dashboard(&app.store());
        ensure_default_engagement(&app.store(), &app.scope_in, &app.scope_mode, &app.ledger_path);
        ensure_default_tenant(&app.store());
        advance_pg_identity_sequences(&app.store());
    }
    // `populate_modules` : INCONDITIONNEL sur CHAQUE instance (upsert idempotent de la table `module`
    // PARTAGÉE, jamais leader-sensible ; hors du verrou DDL car il spawn un process python). En HA les 2
    // réplicas peuplent (upsert ON CONFLICT row-safe). En mono-instance : identique à avant.
    populate_modules(&app.store());
    // BOOT-RECONCILE (run_job 'running' orphelins d'un crash -> 'failed', killpg des pgid locaux) :
    //   - mono-instance (!ha) : ICI, scope=All (byte-identique au comportement historique) ;
    //   - HA : DIFFÉRÉ au leader-tick (is_leader est FAUX au boot ; cf. runs::leader_tick_loop) — boot-
    //     reconcile OWNER-SCOPÉ des propres orphelins une fois le bail acquis, jamais killpg cross-host.
    if !crate::ha::ha_enabled(&app) {
        reconcile_runs(&app.store(), runs_ha::ReconcileScope::All);
    }

    // Cache faisant autorité de la gate d'auth : engagée si hash env OU compte activé en base. À
    // recalculer aussi après toute mutation de comptes (routes d'administration à venir).
    app.recompute_auth_required();
    // Cache de la SOURCE DE DÉTECTION : settings.detection_source (verbatim) sinon repli env legacy
    // PLUME_URL/PLUME_TOKEN (kind=plume) sinon kind=none. Recalculé après chaque mutation (wizard).
    app.reload_detection_source();
    {
        let cfg = app.detection_config();
        let kind = ds_kind(&cfg);
        let endpoint = ds_endpoint(&cfg);
        let http_kind = kind == "plume" || kind == "generic_http";
        if kind == "none" || kind.is_empty() || (http_kind && endpoint.is_empty()) {
            println!("[forge-console] DÉTECTION OFF — aucune source configurée : /api/detection/coverage (alias /api/purple/coverage) répondra en fail-open lisible (source_reachable:false). Configure `settings.detection_source` (wizard) ou pose PLUME_URL/PLUME_TOKEN (rétro-compat kind=plume).");
        } else {
            // JAMAIS le secret dans le log — kind + endpoint + type d'auth seuls.
            println!("[forge-console] DÉTECTION armée — kind={kind} endpoint={endpoint} auth={} ; LECTURE seule, joint runrecord[fired] (red) vs détections de la source (blue).",
                ds_auth_type(&cfg));
        }
    }

    // HA (#10 Wave A) — HEARTBEAT : quand HA est engagé (FORGE_HA + store Postgres actif), une tâche
    // périodique renouvelle/acquiert le bail `run-worker` toutes les ~TTL/3 s et publie l'état de
    // leadership sur `App.is_leader` (lu par /health). INERTE cette vague : AUCUN consumer ne gate encore
    // sur is_leader (reconcile/run/scheduler inchangés). Non-HA (single instance) : aucun ticker, is_leader
    // reste true. Cloné AVANT que build_router ne déplace `app`.
    #[cfg(feature = "store-postgres")]
    if app.ha {
        println!(
            "[forge-console] HA ARMÉ — instance_id={} ; bail scope='run-worker' TTL={}s ; heartbeat toutes les {}s ; leader-tick toutes les {}s (claim pending + reap failover + cancel-watch, leader-only) ; leader/instance_id publiés sur /health.",
            app.instance_id, crate::ha::LEASE_TTL_SECS, crate::ha::HEARTBEAT_TICK_SECS, crate::runs_ha::LEADER_TICK_SECS
        );
        tokio::spawn(crate::ha::heartbeat_loop(app.clone()));
        // RUN-LEADER (Wave B) : le tick du leader draine la file 'pending' (claim + spawn), réape les
        // orphelins des leaders morts (failover) et exécute les cancels observés pour ses runs. Ne fait le
        // travail QUE quand `is_leader` (cf. leader_tick_loop). Cloné AVANT que build_router ne déplace `app`.
        tokio::spawn(crate::runs_ha::leader_tick_loop(app.clone()));
        // CACHE-INVALIDATION CROSS-INSTANCE (Wave C, B6) : chaque réplica poll `settings.cache_epoch` et
        // recharge ses caches locaux (detection_source / auth_required) quand un PAIR l'a bumpé (mutation
        // detection-source / user create-disable-role-delete). Tourne sur CHAQUE instance (pas seulement le
        // leader). Cloné AVANT que build_router ne déplace `app`.
        tokio::spawn(crate::ha::cache_poll_loop(app.clone()));
        // GC PRÉSENCE PÉRIODIQUE (Wave C, write-amplification fix) : la purge des lignes `presence` périmées
        // n'est PLUS faite sur chaque lecture `/api/presence` (amplification proportionnelle au trafic) mais
        // par un DELETE de fond leader-only à la cadence du heartbeat ; le snapshot filtre déjà les périmés
        // sur la lecture (TTL inchangé). Cloné AVANT que build_router ne déplace `app`.
        tokio::spawn(crate::presence::presence_gc_loop(app.clone()));
    }

    // RUNNER DE SAUVEGARDE PROGRAMMÉE (fail-open) : tâche périodique qui, SI une politique
    // `settings.backup_policy` existe et est DUE, crée une archive chiffrée et l'expédie offsite en
    // ledgerisant chaque exécution. Sans politique -> ne fait rien (aucune sauvegarde codée en dur). Un
    // échec logge + ledgerise mais ne fait JAMAIS crasher la console. Cloné AVANT que build_router ne
    // déplace `app` (with_state).
    tokio::spawn(backup_scheduler_loop(app.clone()));

    // Câblage du routeur extrait dans build_router (parité stricte prod/test : ce qui est gaté ici
    // l'est aussi dans les tests d'intégration). ConnectInfo est branché au serve pour que les
    // handlers C2 (run/cancel/refresh) reçoivent l'IP du pair (contrainte source-CIDR opérateur).
    let router = build_router(app, &web_dir);

    let addr = std::env::var("FORGE_CONSOLE_ADDR").unwrap_or_else(|_| "127.0.0.1:7100".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("[forge-console] http://{addr}");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("serve");
}

/// Backend the console boots on, as decided by [`enterprise_store_gate`]. The `Postgres` arm only
/// exists under the `store-postgres` feature (the DEFAULT build can only ever select SQLite).
#[derive(Debug)]
enum StoreSelection {
    Sqlite,
    #[cfg(feature = "store-postgres")]
    Postgres(String), // the FORGE_DB_URL DSN to connect the session-pinned client to
}

/// Enterprise store-selection gate (Stage 2b batch 5). Decides — from the runtime values of
/// `FORGE_ENTERPRISE_STORE` (`requested`) and `FORGE_DB_URL` (`db_url`) — which backend the console
/// boots on, FAIL-CLOSED:
///   - `requested == Some("postgres")` WITH the `store-postgres` feature compiled: `Ok(Postgres(url))`
///     IFF `FORGE_DB_URL` is set to a non-empty DSN; otherwise `Err` (clear "requires FORGE_DB_URL").
///   - `requested == Some("postgres")` WITHOUT the feature: `Err` telling the operator to rebuild with
///     `--features store-postgres` (the Postgres arm is not compiled into this binary).
///   - Anything else (`None`, `"sqlite"`, `""`, …): `Ok(Sqlite)` — the community default, unchanged.
///
/// Pure over its inputs so the whole contract is unit-testable without touching the environment.
fn enterprise_store_gate(requested: Option<&str>, db_url: Option<&str>) -> Result<StoreSelection, String> {
    if requested == Some("postgres") {
        #[cfg(feature = "store-postgres")]
        {
            return match db_url {
                Some(u) if !u.is_empty() => Ok(StoreSelection::Postgres(u.to_string())),
                _ => Err("FORGE_ENTERPRISE_STORE=postgres requires FORGE_DB_URL to be set to a \
                          postgres:// DSN; refusing to start without it."
                    .to_string()),
            };
        }
        #[cfg(not(feature = "store-postgres"))]
        {
            let _ = db_url; // unused in the community build
            return Err("FORGE_ENTERPRISE_STORE=postgres requires a binary built with the \
                        store-postgres feature; rebuild with --features store-postgres."
                .to_string());
        }
    }
    Ok(StoreSelection::Sqlite)
}

// =====================================================================================
// Tests de régression des correctifs de sûreté/sécurité (durcissement audit).
// =====================================================================================
#[cfg(test)]
pub(crate) mod testutil;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    /// GATE CONTRACT (Stage 2b batch 5) : la sélection du backend enterprise est FAIL-CLOSED.
    ///   - Toute valeur non-postgres (`None`/`"sqlite"`/`""`) -> `Sqlite`, dans LES DEUX builds.
    ///   - `postgres` SANS la feature -> refus clair « rebuild with --features store-postgres ».
    ///   - `postgres` AVEC la feature -> `Postgres(url)` SSI FORGE_DB_URL non vide ; sinon refus
    ///     nommant FORGE_DB_URL. (Bloc feature-gated ci-dessous.)
    #[test]
    fn enterprise_store_gate_contract() {
        // Non-postgres selections always boot on SQLite, in both builds.
        assert!(matches!(enterprise_store_gate(None, None), Ok(StoreSelection::Sqlite)),
                "default (unset) starts on SQLite");
        assert!(matches!(enterprise_store_gate(Some("sqlite"), None), Ok(StoreSelection::Sqlite)),
                "explicit sqlite starts on SQLite");
        assert!(matches!(enterprise_store_gate(Some(""), None), Ok(StoreSelection::Sqlite)),
                "empty value starts on SQLite");
        // A stray FORGE_DB_URL is IGNORED unless postgres is explicitly requested.
        assert!(matches!(enterprise_store_gate(None, Some("postgres://x")), Ok(StoreSelection::Sqlite)),
                "db_url alone does not select postgres");

        #[cfg(not(feature = "store-postgres"))]
        {
            // Without the feature compiled, postgres is refused with a rebuild message, whatever the url.
            let e = enterprise_store_gate(Some("postgres"), None)
                .expect_err("postgres refused without the feature");
            assert!(e.contains("store-postgres"), "names the feature to rebuild with: {e}");
            let e2 = enterprise_store_gate(Some("postgres"), Some("postgres://x"))
                .expect_err("still refused even with a url");
            assert!(e2.contains("store-postgres"), "names the feature: {e2}");
        }
        #[cfg(feature = "store-postgres")]
        {
            // With the feature, postgres is ACCEPTED iff FORGE_DB_URL is a non-empty DSN.
            match enterprise_store_gate(Some("postgres"), Some("postgres://u@h/db")) {
                Ok(StoreSelection::Postgres(u)) => assert_eq!(u, "postgres://u@h/db", "carries the DSN"),
                other => panic!("expected Postgres selection, got {other:?}"),
            }
            let e = enterprise_store_gate(Some("postgres"), None)
                .expect_err("postgres refused without FORGE_DB_URL");
            assert!(e.contains("FORGE_DB_URL"), "names the missing var: {e}");
            assert!(enterprise_store_gate(Some("postgres"), Some("")).is_err(),
                    "empty FORGE_DB_URL refused");
        }
    }


    /// App minimale pour tester append_console_ledger (ledger sur disque, reste inerte).
    fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(SCHEMA).expect("schema");
        let (events, _) = broadcast::channel::<RunEvent>(64);
        App {
            db: Arc::new(Mutex::new(conn)),
            db_path: Arc::new(":memory:".into()),
            #[cfg(feature = "store-postgres")]
            pg: None,
            #[cfg(feature = "store-postgres")]
            ha: false,
            #[cfg(feature = "store-postgres")]
            instance_id: Arc::new("test-instance".into()),
            #[cfg(feature = "store-postgres")]
            is_leader: Arc::new(AtomicBool::new(true)),
            token_sha: Arc::new(sha_hex("t")),
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
            run_state: Arc::new(AsyncMutex::new(RunState { current: HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        }
    }


    /// App de test avec un SCOPE SERVEUR non vide (pour les endpoints scope-guardés comme /api/import).
    /// Applique aussi `migrate()` (colonnes additives run_id/cwe/cvss du finding) comme en production —
    /// le boot serveur enchaîne toujours SCHEMA puis migrate ; les INSERT findings en dépendent.
    fn test_app_scoped(ledger_path: &str, scope_in: Vec<String>) -> App {
        let mut a = test_app(ledger_path);
        a.scope_in = Arc::new(scope_in);
        { let db = a.db(); migrate(&db); }
        a
    }

    /// [2b] try_create_session PROPAGE l'échec d'écriture au lieu de l'avaler : si la table `session` est
    /// absente, l'INSERT échoue -> `Err` (aucun token non persisté rendu). Le handler /api/login le remonte
    /// en 500 (plus de faux-200 avec un token mort qui serait rejeté au 1er usage).
    #[tokio::test]
    async fn create_session_write_failure_propagates() {
        let path = tmp_path("forge-test-session-propagate");
        let app = test_app(&path);
        { let db = app.db(); upsert_user(&db, "sessu", "operator", &hash_pw("pw")).unwrap(); }
        let uid = uid_of(&app, "sessu");
        assert!(try_create_session(&app, uid).is_ok(), "nominal -> session persistée (Ok)");
        // casse l'écriture : sans table `session`, l'INSERT échoue -> Err doit remonter.
        { let db = app.db(); db.execute_batch("DROP TABLE session").unwrap(); }
        assert!(try_create_session(&app, uid).is_err(), "INSERT échoué -> Err (pas de faux-succès)");
        // bout-en-bout : login avec de BONS identifiants mais persistance impossible -> 500, pas 200.
        let r = login(State(app.clone()), Json(json!({"login": "sessu", "password": "pw"}))).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR, "login -> 500 sur échec de persistance de session");
        let b = resp_json(r).await;
        assert_eq!(b["error"], "session_persist_failed");
        let _ = std::fs::remove_file(&path);
    }

    /// [3] Lockout du login local après N échecs, SANS fuite d'existence de compte. (a) N échecs sur un
    /// compte EXISTANT -> 401 ; (b) seuil franchi -> verrou : MÊME le BON mot de passe est refusé ; (c)
    /// ANTI-ÉNUMÉRATION : un login INEXISTANT verrouillé par le même martelage renvoie un 401 BYTE-IDENTIQUE
    /// au compte existant verrouillé (indistinguables) ; (d) un compte sain non martelé se connecte (200).
    #[tokio::test]
    async fn login_lockout_triggers_without_user_enumeration() {
        async fn attempt(app: &App, login_name: &str, pw: &str) -> (StatusCode, Value) {
            let r = login(State(app.clone()), Json(json!({"login": login_name, "password": pw}))).await;
            let st = r.status();
            (st, resp_json(r).await)
        }
        let path = tmp_path("forge-test-login-lockout");
        let app = test_app(&path);
        { let db = app.db(); upsert_user(&db, "lockknownx", "operator", &hash_pw("goodpw")).unwrap(); }

        // (a) N échecs sur un compte existant -> chacun 401 invalid_credentials.
        for _ in 0..LOGIN_MAX_FAILS {
            let (st, b) = attempt(&app, "lockknownx", "wrong").await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
            assert_eq!(b["error"], "invalid_credentials");
        }
        // (b) seuil franchi -> verrou : le BON mot de passe est désormais refusé (le lockout mord).
        let (st_known, b_known) = attempt(&app, "lockknownx", "goodpw").await;
        assert_eq!(st_known, StatusCode::UNAUTHORIZED, "compte verrouillé : bon mdp refusé");
        assert_eq!(b_known["error"], "invalid_credentials");

        // (c) verrouiller un login INEXISTANT par le même martelage -> réponse IDENTIQUE (pas d'oracle).
        for _ in 0..LOGIN_MAX_FAILS {
            let _ = attempt(&app, "lockunknownx", "wrong").await;
        }
        let (st_unknown, b_unknown) = attempt(&app, "lockunknownx", "whatever").await;
        assert_eq!(st_unknown, st_known, "verrouillé inconnu == verrouillé connu (statut)");
        assert_eq!(b_unknown, b_known, "verrouillé inconnu == verrouillé connu (corps) — indistinguable");

        // (d) un AUTRE compte, non martelé, se connecte normalement (pas de lock-out collatéral).
        { let db = app.db(); upsert_user(&db, "freshuserx", "viewer", &hash_pw("okpw")).unwrap(); }
        let (st_ok, b_ok) = attempt(&app, "freshuserx", "okpw").await;
        assert_eq!(st_ok, StatusCode::OK, "compte sain -> login 200");
        assert!(b_ok.get("token").is_some(), "token émis pour le compte sain");
        let _ = std::fs::remove_file(&path);
    }

    /// [HIGH] gen_token : entropie CSPRNG -> non tous-zeros, longueur fixe, valeurs distinctes.
    #[test]
    fn gen_token_is_random_not_zero() {
        let a = gen_token();
        let b = gen_token();
        assert_eq!(a.len(), 32, "16 octets -> 32 hex");
        assert_ne!(a, "0".repeat(32), "token tous-zeros = entropie ignorée (régression)");
        assert_ne!(a, b, "deux tokens consécutifs doivent différer");
    }

    /// [HIGH] hash_pw : sel CSPRNG -> deux hash du MÊME mot de passe diffèrent (sel non constant),
    /// et la vérification réussit (format argon2id valide).
    #[test]
    fn hash_pw_salt_is_random_and_verifies() {
        let h1 = hash_pw("hunter2");
        let h2 = hash_pw("hunter2");
        assert_ne!(h1, h2, "même mdp -> hash identiques = sel constant/tous-zeros (régression)");
        assert!(verify_pw("hunter2", &h1), "hash doit se vérifier");
        assert!(!verify_pw("wrong", &h1), "mauvais mdp doit échouer");
    }


    /// Construit un HeaderMap avec un X-Forge-Operator (repli bootstrap env-hash).
    fn operator_headers(pw: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forge-operator", pw.parse().unwrap());
        h
    }

    /// [#6 comptes] validate_login / validate_role : grammaire stricte, rôles fermés (fail-closed).
    #[test]
    fn user_login_and_role_validation() {
        assert!(validate_login("alice").is_ok());
        assert!(validate_login("a.b_c-1").is_ok());
        assert!(validate_login("").is_err(), "login vide refusé");
        assert!(validate_login("-x").is_err(), "login débutant par '-' refusé (anti-flag)");
        assert!(validate_login("a b").is_err(), "espace refusé");
        assert!(validate_login("évil").is_err(), "non-ASCII refusé");
        assert!(validate_role("viewer").is_ok());
        assert!(validate_role("operator").is_ok());
        assert!(validate_role("admin").is_ok());
        assert!(validate_role("root").is_err(), "rôle inconnu refusé");
        assert!(validate_role("").is_err());
    }

    /// [#6 comptes] upsert_user -> session -> resolve_session_identity : un compte individuel en
    /// session est résolu (login/rôle réels), is_operator suit le rôle.
    #[test]
    fn session_resolves_individual_identity() {
        let path = tmp_path("forge-test-users-resolve");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "carol", "operator", &hash_pw("pw")).unwrap();
        }
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='carol'", [], |r| r.get(0)).unwrap() };
        let (tok, _exp) = create_session(&app, uid);
        let id = resolve_session_identity(&app, &bearer_headers(&tok)).expect("session valide -> identité");
        assert_eq!(id.login, "carol");
        assert_eq!(id.role, "operator");
        assert!(id.is_operator, "operator -> is_operator");
        assert!(id.via_session, "via_session=true pour un compte individuel");
        // token inconnu -> pas d'identité.
        assert!(resolve_session_identity(&app, &bearer_headers("deadbeef")).is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 comptes] disabled / expiration : un compte désactivé et une session expirée sont refusés
    /// (fail-closed), et la session expirée est purgée.
    #[test]
    fn session_disabled_and_expired_are_rejected() {
        let path = tmp_path("forge-test-users-disabled");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "dave", "viewer", &hash_pw("pw")).unwrap();
        }
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='dave'", [], |r| r.get(0)).unwrap() };
        let (tok, _) = create_session(&app, uid);
        // désactivation -> refus immédiat même session valide.
        { let db = app.db(); db.execute("UPDATE users SET disabled=1 WHERE id=?", [uid]).unwrap(); }
        assert!(resolve_session_identity(&app, &bearer_headers(&tok)).is_none(), "compte désactivé refusé");
        // réactive + force une session expirée -> refus + purge.
        { let db = app.db(); db.execute("UPDATE users SET disabled=0 WHERE id=?", [uid]).unwrap(); }
        let token_sha = sha_hex(&tok);
        { let db = app.db(); db.execute("UPDATE session SET expires=1 WHERE token_sha=?", [&token_sha]).unwrap(); }
        assert!(resolve_session_identity(&app, &bearer_headers(&tok)).is_none(), "session expirée refusée");
        let purged: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM session WHERE token_sha=?", [&token_sha], |r| r.get(0)).unwrap() };
        assert_eq!(purged, 0, "session expirée purgée");
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 RÉTRO-COMPAT] check_operator : repli bootstrap par hash env quand AUCUNE session n'est
    /// présentée — la console live (hash via env) continue de fonctionner.
    #[test]
    fn check_operator_falls_back_to_env_hash() {
        let path = tmp_path("forge-test-op-env");
        let mut app = test_app(&path);
        app.operator_hash = Arc::new(hash_pw("s3cr3t"));
        assert!(check_operator(&app, &operator_headers("s3cr3t"), None), "bonne preuve env -> opérateur");
        assert!(!check_operator(&app, &operator_headers("wrong"), None), "mauvaise preuve env -> refus");
        assert!(!check_operator(&app, &HeaderMap::new(), None), "aucune preuve -> refus (fail-closed)");
        // attribution sans session -> 'bootstrap' (compte env-hash).
        assert_eq!(attribution_login(&app, &operator_headers("s3cr3t")), "bootstrap");
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 sécurité] check_operator : une session VIEWER ne passe JAMAIS le C2, même si un hash env
    /// opérateur est présent (un viewer authentifié ne doit pas escalader via le secret partagé).
    /// Une session OPERATOR passe, et l'attribution porte le login individuel.
    #[test]
    fn session_viewer_cannot_arm_operator_can() {
        let path = tmp_path("forge-test-op-session");
        let mut app = test_app(&path);
        app.operator_hash = Arc::new(hash_pw("s3cr3t")); // hash env présent (ne doit pas sauver le viewer)
        {
            let db = app.db();
            upsert_user(&db, "viewy", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oppy", "operator", &hash_pw("pw")).unwrap();
        }
        let (vid, oid): (i64, i64) = {
            let db = app.db();
            (db.query_row("SELECT id FROM users WHERE login='viewy'", [], |r| r.get(0)).unwrap(),
             db.query_row("SELECT id FROM users WHERE login='oppy'", [], |r| r.get(0)).unwrap())
        };
        let (vtok, _) = create_session(&app, vid);
        let (otok, _) = create_session(&app, oid);
        assert!(!check_operator(&app, &bearer_headers(&vtok), None), "session viewer NE PASSE PAS le C2");
        assert!(check_operator(&app, &bearer_headers(&otok), None), "session operator passe le C2");
        assert_eq!(attribution_login(&app, &bearer_headers(&otok)), "oppy", "attribution = login individuel");
        let _ = std::fs::remove_file(&path);
    }

    /// [#6 RÉTRO-COMPAT] attribution_login : sans aucune identité (dev-open, ni session ni hash env),
    /// retombe sur le littéral historique 'operator' (comportement existant préservé).
    #[test]
    fn attribution_defaults_to_operator_when_no_identity() {
        let path = tmp_path("forge-test-attr-default");
        let app = test_app(&path); // operator_hash vide
        assert_eq!(attribution_login(&app, &HeaderMap::new()), "operator");
        let _ = std::fs::remove_file(&path);
    }

    /// [SEC gate DB-state] auth_guard s'engage sur l'ÉTAT DB, pas seulement sur le hash env. Fresh
    /// install : hash env VIDE (pass_hash="") mais un compte ACTIVÉ présent -> gate engagée -> une
    /// requête sans preuve est REFUSÉE (le middleware répond alors 401, le SPA montre le login).
    /// Une session valide de ce compte passe. Ferme le trou dev-open « comptes en base, env vide ».
    #[test]
    fn auth_gate_engages_on_enabled_user_without_env_hash() {
        let path = tmp_path("forge-test-auth-gate");
        let app = test_app(&path); // pass_hash vide (dev), aucun compte au départ
        // 1) sans hash env ni compte -> dev-open : la gate est désengagée, tout passe.
        app.recompute_auth_required();
        assert!(!app.auth_required(), "sans hash env ni compte activé -> dev-open (gate désengagée)");
        assert!(auth_guard_allows(&app, &HeaderMap::new()), "dev-open : requête anonyme passe");
        // 2) un compte ACTIVÉ est provisionné en base -> après recompute, la gate DOIT s'engager,
        //    MÊME si le hash env reste vide (c'est exactement le trou historique qu'on ferme).
        {
            let db = app.db();
            upsert_user(&db, "erin", "viewer", &hash_pw("pw")).unwrap();
        }
        app.recompute_auth_required();
        assert!(app.auth_required(), "un compte activé engage la gate même sans hash env");
        assert!(!auth_guard_allows(&app, &HeaderMap::new()),
            "gate engagée : requête anonyme REFUSÉE -> le middleware renvoie 401");
        // 3) une session valide de ce compte passe la gate ; un token inconnu ne passe pas.
        let uid: i64 = { let db = app.db(); db.query_row("SELECT id FROM users WHERE login='erin'", [], |r| r.get(0)).unwrap() };
        let (tok, _) = create_session(&app, uid);
        assert!(auth_guard_allows(&app, &bearer_headers(&tok)), "session individuelle valide passe la gate");
        assert!(!auth_guard_allows(&app, &bearer_headers("deadbeef")), "session inconnue -> refus (401)");
        // 4) contrapositive de la règle : désactiver l'UNIQUE compte, hash env toujours vide -> plus
        //    aucun compte activé -> la gate se désengage (règle « engage si hash OU compte activé »).
        { let db = app.db(); db.execute("UPDATE users SET disabled=1 WHERE id=?", [uid]).unwrap(); }
        app.recompute_auth_required();
        assert!(!app.auth_required(), "dernier compte activé désactivé + hash env vide -> gate désengagée");
        let _ = std::fs::remove_file(&path);
    }

    /// [SEC gate DB-state] un hash env posé engage la gate à lui seul (rétro-compat) : même sans aucun
    /// compte en base, auth_required=true et une requête anonyme est refusée.
    #[test]
    fn auth_gate_engages_on_env_hash_alone() {
        let path = tmp_path("forge-test-auth-gate-env");
        let mut app = test_app(&path);
        app.pass_hash = Arc::new(hash_pw("viewerpw")); // hash env posé, aucun compte en base
        app.recompute_auth_required();
        assert!(app.auth_required(), "hash env posé -> gate engagée même sans compte");
        assert!(!auth_guard_allows(&app, &HeaderMap::new()), "gate engagée : anonyme refusé (401)");
        // Basic viewer avec le bon mdp passe (rétro-compat viewer par hash env).
        let mut h = HeaderMap::new();
        let b64 = base64::engine::general_purpose::STANDARD.encode("forge:viewerpw");
        h.insert("authorization", format!("Basic {b64}").parse().unwrap());
        assert!(auth_guard_allows(&app, &h), "Basic viewer (hash env) passe la gate");
        let _ = std::fs::remove_file(&path);
    }

    /// [SEC admin] check_admin : FAIL-CLOSED, session ADMIN uniquement. Un viewer et un operator sont
    /// REFUSÉS ; un admin est autorisé. PAS de repli hash env (contrairement à operator) : une preuve
    /// X-Forge-Operator seule ne confère JAMAIS l'admin (attribution individuelle obligatoire).
    #[test]
    fn check_admin_requires_admin_session_no_env_fallback() {
        let path = tmp_path("forge-test-admin");
        let mut app = test_app(&path);
        app.operator_hash = Arc::new(hash_pw("s3cr3t")); // hash env opérateur présent -> ne doit PAS conférer l'admin
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let sid = |login: &str, app: &App| -> i64 {
            let db = app.db();
            db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
        };
        let (vtok, _) = create_session(&app, sid("vv", &app));
        let (otok, _) = create_session(&app, sid("oo", &app));
        let (atok, _) = create_session(&app, sid("aa", &app));
        assert!(!check_admin(&app, &bearer_headers(&vtok)), "viewer refusé (fail-closed)");
        assert!(!check_admin(&app, &bearer_headers(&otok)), "operator refusé (admin != operator)");
        assert!(check_admin(&app, &bearer_headers(&atok)), "admin autorisé");
        assert!(!check_admin(&app, &operator_headers("s3cr3t")), "hash env opérateur NE confère PAS l'admin (pas de repli)");
        assert!(!check_admin(&app, &HeaderMap::new()), "aucune preuve -> refus (fail-closed)");
        let _ = std::fs::remove_file(&path);
    }

    /// Compte les sessions d'un user_id (helper de test).
    fn session_count(app: &App, uid: i64) -> i64 {
        let db = app.db();
        db.query_row("SELECT COUNT(*) FROM session WHERE user_id=?", [uid], |r| r.get(0)).unwrap()
    }

    /// [ADMIN #4] admin_create_user + admin_list_users : création, vue publique SANS pass_hash, ledger
    /// de création SANS mot de passe/hash, attribution à l'acteur, doublon de login -> 409.
    #[test]
    fn admin_create_lists_and_never_leaks_pass_hash() {
        let path = tmp_path("forge-test-admin-create");
        let app = test_app(&path);
        let out = admin_create_user(&app, "aa", &json!({"login": "newbie", "role": "viewer", "password": "s3cretPW"}))
            .expect("création OK");
        assert_eq!(out["login"], "newbie");
        assert_eq!(out["role"], "viewer");
        assert_eq!(out["disabled"], false);
        assert!(out.get("pass_hash").is_none(), "la réponse de création ne contient jamais pass_hash");
        // liste : champs attendus, pass_hash structurellement absent.
        let users = admin_list_users(&app);
        let u = users.iter().find(|u| u["login"] == "newbie").expect("compte listé");
        assert!(u.get("pass_hash").is_none(), "la liste ne renvoie JAMAIS pass_hash");
        assert_eq!(u["role"], "viewer");
        assert_eq!(u["disabled"], false);
        // ledger : entrée create, attribuée, SANS le mot de passe ni le hash argon2.
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.admin.user.create");
        assert_eq!(last["detail"]["actor"], "aa");
        assert_eq!(last["detail"]["login"], "newbie");
        let ser = canon_json(last).to_lowercase();
        assert!(!ser.contains("s3cretpw"), "le mot de passe ne DOIT jamais entrer dans le ledger");
        assert!(!ser.contains("argon2"), "le hash ne DOIT jamais entrer dans le ledger");
        // le compte est réellement provisionné avec un hash vérifiable (mais jamais exposé).
        let ph: String = { let db = app.db(); db.query_row("SELECT pass_hash FROM users WHERE login='newbie'", [], |r| r.get(0)).unwrap() };
        assert!(verify_pw("s3cretPW", &ph), "mot de passe créé vérifiable côté DB");
        // doublon de login -> 409 (l'édition sert à modifier).
        let dup = admin_create_user(&app, "aa", &json!({"login": "newbie", "role": "admin", "password": "x"}));
        assert_eq!(dup.unwrap_err().0, StatusCode::CONFLICT, "login déjà pris -> 409");
        // login/rôle invalides -> 400.
        assert_eq!(admin_create_user(&app, "aa", &json!({"login": "-bad", "role": "viewer", "password": "x"})).unwrap_err().0, StatusCode::BAD_REQUEST);
        assert_eq!(admin_create_user(&app, "aa", &json!({"login": "ok", "role": "root", "password": "x"})).unwrap_err().0, StatusCode::BAD_REQUEST);
        assert_eq!(admin_create_user(&app, "aa", &json!({"login": "ok", "role": "viewer", "password": ""})).unwrap_err().0, StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] admin_update_user : la DÉSACTIVATION purge les sessions du compte + ledgerise (actor,
    /// sessions_purged). La RÉTROGRADATION purge aussi. Le RESET de mot de passe purge et n'expose rien.
    #[test]
    fn admin_update_disable_downgrade_reset_purge_sessions_and_ledger() {
        let path = tmp_path("forge-test-admin-update");
        let app = test_app(&path);
        admin_create_user(&app, "boot", &json!({"login": "root", "role": "admin", "password": "pw"})).unwrap();
        admin_create_user(&app, "root", &json!({"login": "bob", "role": "operator", "password": "pw"})).unwrap();
        let bob = uid_of(&app, "bob");
        let (btok, _) = create_session(&app, bob);
        assert!(resolve_session_identity(&app, &bearer_headers(&btok)).is_some(), "session bob valide au départ");
        // DÉSACTIVATION -> purge des sessions + ledger.
        let out = admin_update_user(&app, "root", "bob", &json!({"disabled": true})).unwrap();
        assert_eq!(out["disabled"], true);
        assert_eq!(out["sessions_purged"], true);
        assert_eq!(session_count(&app, bob), 0, "les sessions du compte désactivé sont purgées");
        assert!(resolve_session_identity(&app, &bearer_headers(&btok)).is_none(), "session révoquée");
        let last = read_ledger_lines(&path).pop().unwrap();
        assert_eq!(last["kind"], "console.admin.user.update");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["sessions_purged"], true);
        // RÉTROGRADATION admin->viewer purge (créer un 2e admin d'abord pour ne pas heurter le garde-fou).
        admin_create_user(&app, "root", &json!({"login": "admin2", "role": "admin", "password": "pw"})).unwrap();
        let a2 = uid_of(&app, "admin2");
        let (a2tok, _) = create_session(&app, a2);
        let out = admin_update_user(&app, "root", "admin2", &json!({"role": "viewer"})).unwrap();
        assert_eq!(out["role"], "viewer");
        assert_eq!(out["sessions_purged"], true, "la rétrogradation purge les sessions");
        assert!(resolve_session_identity(&app, &bearer_headers(&a2tok)).is_none(), "session purgée après rétrogradation");
        // RESET de mot de passe : purge + nouveau mot de passe effectif + rien de sensible au ledger.
        let root_id = uid_of(&app, "root");
        let (rtok, _) = create_session(&app, root_id);
        let out = admin_update_user(&app, "root", "root", &json!({"password": "brandNEW"})).unwrap();
        assert_eq!(out["password_reset"], true);
        assert_eq!(out["sessions_purged"], true, "un reset de mot de passe purge les sessions");
        assert!(resolve_session_identity(&app, &bearer_headers(&rtok)).is_none(), "ancienne session invalidée par le reset");
        let ph: String = { let db = app.db(); db.query_row("SELECT pass_hash FROM users WHERE login='root'", [], |r| r.get(0)).unwrap() };
        assert!(verify_pw("brandNEW", &ph) && !verify_pw("pw", &ph), "nouveau mot de passe effectif, ancien invalidé");
        let ser = canon_json(&read_ledger_lines(&path).pop().unwrap()).to_lowercase();
        assert!(!ser.contains("brandnew"), "aucun mot de passe dans le ledger (reset)");
        // corps vide -> 400 (aucun changement).
        assert_eq!(admin_update_user(&app, "root", "root", &json!({})).unwrap_err().0, StatusCode::BAD_REQUEST);
        // cible inexistante -> 404.
        assert_eq!(admin_update_user(&app, "root", "ghost", &json!({"role": "viewer"})).unwrap_err().0, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] garde-fou DERNIER ADMIN (fail-closed 409) : impossible de désactiver, rétrograder ou
    /// supprimer le seul admin activé ; possible dès qu'il en existe un second. Un refus 409 NE
    /// ledgerise PAS. La suppression réussie purge les sessions et ledgerise (actor).
    #[test]
    fn admin_last_admin_is_protected_on_disable_downgrade_delete() {
        let path = tmp_path("forge-test-admin-last");
        let app = test_app(&path);
        admin_create_user(&app, "boot", &json!({"login": "root", "role": "admin", "password": "pw"})).unwrap();
        let root_id = uid_of(&app, "root");
        let (rtok, _) = create_session(&app, root_id);
        // seul admin activé : désactivation / rétrogradation / suppression -> 409, SANS ledgeriser.
        let before = read_ledger_lines(&path).len();
        assert_eq!(admin_update_user(&app, "root", "root", &json!({"disabled": true})).unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(admin_update_user(&app, "root", "root", &json!({"role": "viewer"})).unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(admin_delete_user(&app, "root", "root").unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(read_ledger_lines(&path).len(), before, "un refus 409 ne ledgerise pas");
        assert!(resolve_session_identity(&app, &bearer_headers(&rtok)).is_some(), "root intact -> sa session survit");
        // 2e admin -> la suppression du 1er devient possible (purge ses sessions + ledger delete).
        admin_create_user(&app, "root", &json!({"login": "root2", "role": "admin", "password": "pw"})).unwrap();
        let del = admin_delete_user(&app, "root2", "root").expect("avec 2 admins, suppression permise");
        assert_eq!(del["deleted"], "root");
        assert_eq!(session_count(&app, root_id), 0, "sessions du compte supprimé purgées");
        let last = read_ledger_lines(&path).pop().unwrap();
        assert_eq!(last["kind"], "console.admin.user.delete");
        assert_eq!(last["detail"]["actor"], "root2");
        assert_eq!(last["detail"]["login"], "root");
        // il ne reste que root2 (seul admin) -> re-bloqué.
        assert_eq!(admin_delete_user(&app, "root2", "root2").unwrap_err().0, StatusCode::CONFLICT);
        // un NON-admin peut être supprimé même seul de son rôle ; inexistant -> 404.
        admin_create_user(&app, "root2", &json!({"login": "viewy", "role": "viewer", "password": "pw"})).unwrap();
        assert!(admin_delete_user(&app, "root2", "viewy").is_ok());
        assert_eq!(admin_delete_user(&app, "root2", "ghost").unwrap_err().0, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(&path);
    }

    /// [ADMIN #4] gate des ROUTES : viewer et operator (et l'anonyme) reçoivent 403 sur /api/users
    /// (list/create/update/delete) ; l'admin passe. Vérifie les handlers HTTP réels (check_admin).
    #[tokio::test]
    async fn users_routes_are_admin_only_403() {
        let path = tmp_path("forge-test-users-403");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        app.recompute_auth_required();
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));
        let (atok, _) = create_session(&app, uid_of(&app, "aa"));
        // GET : viewer/operator/anonyme -> 403 ; admin -> 200.
        assert_eq!(users_list(State(app.clone()), bearer_headers(&vtok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(users_list(State(app.clone()), bearer_headers(&otok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(users_list(State(app.clone()), HeaderMap::new()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(users_list(State(app.clone()), bearer_headers(&atok)).await.status(), StatusCode::OK);
        // POST create : operator -> 403 (et le compte n'est PAS créé) ; admin -> 200.
        let body = || Json(json!({"login": "mallory", "role": "viewer", "password": "pw"}));
        assert_eq!(users_create(State(app.clone()), bearer_headers(&otok), body()).await.status(), StatusCode::FORBIDDEN);
        assert!(!admin_list_users(&app).iter().any(|u| u["login"] == "mallory"), "un create refusé (403) ne provisionne rien");
        assert_eq!(users_create(State(app.clone()), bearer_headers(&atok), body()).await.status(), StatusCode::OK);
        // POST update + DELETE : viewer -> 403.
        assert_eq!(
            users_update(State(app.clone()), bearer_headers(&vtok), Path("mallory".into()), Json(json!({"role": "operator"}))).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            users_delete(State(app.clone()), bearer_headers(&vtok), Path("mallory".into())).await.status(),
            StatusCode::FORBIDDEN
        );
        let _ = std::fs::remove_file(&path);
    }

    /// [SUBSTRAT settings] settings_get/settings_set : round-trip d'une clé, upsert (pas de doublon),
    /// horodatage `updated` renseigné, clé absente -> None.
    #[test]
    fn settings_get_set_round_trip() {
        let path = tmp_path("forge-test-settings");
        let app = test_app(&path);
        let db = app.db();
        assert!(settings_get(&db, "operator_policy").is_none(), "clé absente -> None (aucune valeur inventée)");
        settings_set(&db, "operator_policy", "{\"arm_required\":true}").unwrap();
        assert_eq!(settings_get(&db, "operator_policy").as_deref(), Some("{\"arm_required\":true}"),
            "la valeur écrite est relue à l'identique (round-trip)");
        let updated: String = db.query_row("SELECT updated FROM settings WHERE key='operator_policy'", [], |r| r.get(0)).unwrap();
        assert!(!updated.is_empty(), "horodatage `updated` renseigné à l'écriture");
        // upsert : re-écrire la MÊME clé remplace la valeur sans créer de doublon (PRIMARY KEY).
        settings_set(&db, "operator_policy", "{\"arm_required\":false}").unwrap();
        assert_eq!(settings_get(&db, "operator_policy").as_deref(), Some("{\"arm_required\":false}"), "valeur mise à jour");
        let count: i64 = db.query_row("SELECT COUNT(*) FROM settings WHERE key='operator_policy'", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "PRIMARY KEY -> une seule ligne par clé (upsert, pas d'insertion doublon)");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------------------------------------
    // WIZARD 1er DÉPLOIEMENT + politique opérateur source-CIDR
    // ---------------------------------------------------------------------------------------------

    /// Client HTTP brut minimal (aucune dép externe) : envoie `req` et lit toute la réponse jusqu'à EOF
    /// (le serveur ferme la connexion sur `Connection: close`). Suffisant pour tester le câblage réel.
    async fn http_raw(addr: SocketAddr, req: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        s.write_all(req.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.expect("read");
        String::from_utf8_lossy(&buf).into_owned()
    }
    fn get_req(path: &str, extra: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\r\n")
    }
    fn post_req(path: &str, body: &str, extra: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
    }
    fn parse_status(resp: &str) -> u16 {
        resp.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }
    fn body_of(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }
    fn cookie_token(resp: &str) -> Option<String> {
        let head = resp.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(resp);
        let idx = head.find("forge_session=")?;
        let rest = &head[idx + "forge_session=".len()..];
        let end = rest.find(';').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }

    /// [SETUP wizard] Flux END-TO-END sur le VRAI routeur (build_router) : fresh -> needs_setup ;
    /// POST /api/setup crée l'admin, pose le cookie, bascule provisioned ; 2e POST -> 409 ;
    /// detection_source + operator_policy atterrissent dans settings ; /api/setup* restent joignables
    /// SANS auth tandis qu'une route protégée (/api/whoami) passe à 401 une fois la gate engagée.
    #[tokio::test]
    async fn setup_wizard_live_end_to_end() {
        let ledger = tmp_path("forge-test-setup-ledger");
        let app = test_app(&ledger);
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // 1) fresh install -> needs_setup:true, sqlcipher:false (build par défaut), joignable SANS auth.
        let r = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert_eq!(parse_status(&r), 200, "setup/state public: {r}");
        assert!(body_of(&r).contains("\"needs_setup\":true"), "fresh -> needs_setup:true : {}", body_of(&r));
        assert!(body_of(&r).contains("\"provisioned\":false"));
        assert!(body_of(&r).contains("\"sqlcipher\":false"), "build par défaut -> sqlcipher:false");

        // 2) POST /api/setup SANS auth -> 200 + cookie posé + settings persistés.
        let setup_body = json!({
            "admin_login": "root",
            "admin_password": "hunter2pw",
            "session_ttl": 1800,
            "operator_policy": {"require_reason": true, "source_cidrs": ["10.0.0.0/24"], "high_impact_approval": false},
            "detection_source": {"kind": "plume", "endpoint": "http://soc.local:8080", "auth_type": "basic"}
        })
        .to_string();
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 200, "provision -> 200 : {r}");
        assert!(body_of(&r).contains("\"provisioned\":true"));
        let tok = cookie_token(&r).expect("cookie forge_session posé par le provisioning");
        assert!(!tok.is_empty());

        // 3) l'état bascule : provisioned:true / needs_setup:false.
        let r = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert!(body_of(&r).contains("\"needs_setup\":false"), "après provision -> needs_setup:false");
        assert!(body_of(&r).contains("\"provisioned\":true"));

        // 4) SECONDE provision -> 409 (route auto-désactivante).
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 409, "2e provision -> 409 : {r}");

        // 5) detection_source + operator_policy (+ session_ttl) atterrissent VERBATIM dans settings.
        {
            let db = app.db();
            assert!(settings_get(&db, "operator_policy").unwrap().contains("10.0.0.0/24"), "operator_policy stocké");
            assert!(settings_get(&db, "detection_source").unwrap().contains("plume"), "detection_source stocké");
            assert_eq!(settings_get(&db, "session_ttl").as_deref(), Some("1800"), "session_ttl stocké");
        }
        assert!(app.any_enabled_admin(), "un admin activé existe après provision");

        // 6) la gate d'auth est désormais engagée : /api/whoami SANS auth -> 401 ; AVEC session -> 200.
        let r = http_raw(addr, &get_req("/api/whoami", "")).await;
        assert_eq!(parse_status(&r), 401, "route protégée sans auth, gate engagée -> 401 : {r}");
        let r = http_raw(addr, &get_req("/api/whoami", &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "route protégée avec session -> 200 : {r}");
        assert!(body_of(&r).contains("\"login\":\"root\""), "session = nouvel admin root : {}", body_of(&r));

        // 7) /api/setup/state RESTE joignable sans auth même gate engagée (hors auth_guard).
        let r = http_raw(addr, &get_req("/api/setup/state", "")).await;
        assert_eq!(parse_status(&r), 200, "setup/state toujours public une fois provisionné");

        // ledger : entrée de provision attribuée à root, JAMAIS le mot de passe/hash.
        let last = read_ledger_lines(&ledger).pop().expect("ledger provision");
        assert_eq!(last["kind"], "console.setup.provision");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["operator_policy_set"], true);
        assert_eq!(last["detail"]["detection_source_set"], true);
        let ser = canon_json(&last).to_lowercase();
        assert!(!ser.contains("hunter2pw"), "le mot de passe ne DOIT jamais entrer dans le ledger");
        assert!(!ser.contains("argon2"), "le hash ne DOIT jamais entrer dans le ledger");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [SETUP migrate] POST /api/setup/migrate : PUBLIC en pré-provision (exécute la migration + rend
    /// le rapport verify), puis AUTO-DÉSACTIVANTE (409) dès qu'un admin activé existe. Chemin plaintext
    /// (aucun sqlcipher requis).
    // env_lock() sérialise l'ENV process-global entre threads de test ; le garder à travers l'await
    // de setup_migrate est VOULU (l'ENV doit rester stable pendant l'appel awaité). Runtime de test
    // current_thread => aucun risque de blocage de l'exécuteur.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn setup_migrate_public_pre_provision_then_409_once_provisioned() {
        // COUCHE 1+2 activées : flag opt-in ON + racine d'import = temp_dir (où vivent from/to/ledger)
        // -> l'endpoint accepte l'import pré-provision. (Le verrou sérialise vs le test flag-OFF.)
        let _g = env_lock();
        std::env::set_var("FORGE_ALLOW_API_MIGRATE", "1");
        std::env::set_var("FORGE_CONSOLE_IMPORT_DIR", std::env::temp_dir().to_string_lossy().to_string());

        // source sur disque : base ANCIENNE + ledger intact.
        let src_dir = tmp_dir("forge-mig-http-src");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        ledger_append_standalone(&src_ledger, "engagement.start", &json!({"a": 1})).unwrap();

        let led = tmp_path("forge-test-setup-migrate-ledger");
        let app = test_app(&led);
        let to = tmp_path("forge-mig-http-to.db");
        let target_ledger = tmp_path("forge-mig-http-to.jsonl");
        let body = json!({"from": src_dir, "to": to, "ledger": target_ledger, "verify": true});

        // 1) PRÉ-PROVISION : route publique -> exécute la migration -> 200 + cible écrite.
        let r = setup_migrate(State(app.clone()), Json(body.clone())).await;
        assert_eq!(r.status(), StatusCode::OK, "pré-provision -> 200");
        assert!(std::path::Path::new(&to).exists(), "migration exécutée (cible écrite)");

        // 2) provisionne un admin -> la route se ferme (409), sans relancer de migration.
        {
            let db = app.db();
            upsert_user(&db, "root", "admin", &hash_pw("pw123456")).unwrap();
        }
        app.recompute_auth_required();
        assert!(app.provisioned(), "un admin activé -> provisionné");
        let r = setup_migrate(State(app.clone()), Json(body)).await;
        assert_eq!(r.status(), StatusCode::CONFLICT, "une fois provisionné -> 409");

        std::env::remove_var("FORGE_ALLOW_API_MIGRATE");
        std::env::remove_var("FORGE_CONSOLE_IMPORT_DIR");
        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&led);
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::remove_file(&target_ledger);
        let _ = std::fs::remove_file(format!("{target_ledger}.ed25519"));
    }

    /// [SETUP migrate — COUCHE 1] Défaut OFF : sans FORGE_ALLOW_API_MIGRATE, l'endpoint REFUSE (403)
    /// AVANT toute I/O — la primitive d'écriture/suppression de fichier non-auth n'existe pas dans le
    /// déploiement par défaut. Preuve : la cible n'est JAMAIS écrite malgré une source valide.
    // env_lock() sérialise l'ENV process-global entre threads de test ; le garder à travers l'await
    // de setup_migrate est VOULU (l'ENV doit rester stable pendant l'appel awaité). Runtime de test
    // current_thread => aucun risque de blocage de l'exécuteur.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn setup_migrate_api_disabled_by_default_no_file_op() {
        let _g = env_lock();
        std::env::remove_var("FORGE_ALLOW_API_MIGRATE");

        let src_dir = tmp_dir("forge-mig-flagoff-src");
        seed_old_source_db(&format!("{src_dir}/forge-console.db"));
        let led = tmp_path("forge-mig-flagoff-led");
        let app = test_app(&led); // non provisionnée -> la fenêtre de setup est ouverte.
        assert!(!app.provisioned(), "console non provisionnée (fenêtre setup ouverte)");
        let to = tmp_path("forge-mig-flagoff-to.db");
        let body = json!({"from": src_dir, "to": to});

        let r = setup_migrate(State(app.clone()), Json(body)).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "flag OFF -> 403 (migration API désactivée)");
        assert!(!std::path::Path::new(&to).exists(), "AUCUN fichier écrit quand la migration API est OFF");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&led);
    }

    /// [SETUP migrate — COUCHE 2] Validation de chemin (flag ON) : (c) cible/ source SOUS la base
    /// acceptées ; (b) traversal `..` + absolu hors base rejetés ; (d) cible PRÉEXISTANTE hors base
    /// refusée SANS y toucher. Teste le helper directement (base injectée) -> aucune course d'ENV.
    #[test]
    fn api_migrate_path_validation_confines_to_base() {
        let base = tmp_dir("forge-mig-base");
        let base_canon = std::path::Path::new(&base).canonicalize().expect("canon base");

        // (c) cible neuve VALIDE sous la base (parent = base existe, fichier absent) -> acceptée.
        let ok_to = format!("{base}/staging.db");
        assert!(validate_api_migrate_path(&base_canon, &ok_to, "to", false).is_ok(),
            "cible neuve sous la base -> acceptée");
        // source existante VALIDE sous la base -> acceptée (must_exist).
        let src = format!("{base}/src.db");
        std::fs::write(&src, b"x").unwrap();
        assert!(validate_api_migrate_path(&base_canon, &src, "from", true).is_ok(),
            "source existante sous la base -> acceptée");

        // (b) traversal `..` -> rejeté AVANT toute résolution.
        let trav = format!("{base}/../etc/evil");
        assert!(validate_api_migrate_path(&base_canon, &trav, "to", false).is_err(),
            "composant `..` -> rejeté");
        // (b bis) chemin ABSOLU hors base -> rejeté.
        assert!(validate_api_migrate_path(&base_canon, "/etc/passwd", "from", true).is_err(),
            "absolu hors base -> rejeté");
        // source inexistante -> rejetée (introuvable), jamais silencieusement acceptée.
        assert!(validate_api_migrate_path(&base_canon, &format!("{base}/nope.db"), "from", true).is_err(),
            "source introuvable -> rejetée");

        // (d) cible PRÉEXISTANTE hors base -> refus d'écrasement, fichier intact.
        let outside_dir = tmp_dir("forge-mig-outside");
        let victim = format!("{outside_dir}/victim.db");
        std::fs::write(&victim, b"precious").unwrap();
        assert!(validate_api_migrate_path(&base_canon, &victim, "to", false).is_err(),
            "cible préexistante HORS base -> refusée (pas d'écrasement)");
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious", "la cible hors base reste intacte");

        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside_dir);
    }

    /// [SETUP wizard] Validation d'entrée + auto-désactivation par HASH ENV : login invalide -> 400,
    /// mot de passe vide -> 400 ; une install avec un hash d'amorçage env est déjà provisionnée -> 409
    /// (pas de nouvelle provision anonyme), même sans compte en base.
    #[tokio::test]
    async fn setup_provision_validates_and_self_disables_on_env_hash() {
        let path = tmp_path("forge-test-setup-validate");
        // login invalide -> 400
        {
            let app = test_app(&path);
            let r = setup_provision(State(app.clone()), Json(json!({"admin_login": "-bad", "admin_password": "x"}))).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "login invalide -> 400");
            // mot de passe vide -> 400
            let r = setup_provision(State(app.clone()), Json(json!({"admin_login": "ok", "admin_password": ""}))).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "mot de passe vide -> 400");
            assert!(!app.any_enabled_admin(), "aucun refus 400 ne provisionne quoi que ce soit");
        }
        // hash env d'amorçage posé -> provisioned d'emblée -> 409.
        {
            let mut app = test_app(&path);
            app.pass_hash = Arc::new(hash_pw("bootstrap"));
            app.recompute_auth_required();
            assert!(app.provisioned(), "hash env -> déjà provisionné");
            let r = setup_provision(State(app.clone()), Json(json!({"admin_login": "root", "admin_password": "x"}))).await;
            assert_eq!(r.status(), StatusCode::CONFLICT, "hash env d'amorçage -> /api/setup fermée (409)");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// [OPÉRATEUR source-CIDR] ip_in_cidr : appartenance v4/v6, IP exacte, /0, familles hétérogènes,
    /// et rejet fail-closed des entrées malformées (préfixe non numérique / hors borne, réseau invalide).
    #[test]
    fn ip_in_cidr_membership_and_fail_closed() {
        let v4 = "10.0.0.5".parse::<IpAddr>().unwrap();
        assert!(ip_in_cidr(&v4, "10.0.0.0/24"));
        assert!(ip_in_cidr(&v4, "10.0.0.0/8"));
        assert!(!ip_in_cidr(&v4, "10.0.1.0/24"));
        assert!(ip_in_cidr(&v4, "10.0.0.5"), "sans '/' -> comparaison exacte");
        assert!(!ip_in_cidr(&v4, "10.0.0.6"));
        assert!(ip_in_cidr(&v4, "0.0.0.0/0"), "/0 -> tout l'espace v4");
        assert!(!ip_in_cidr(&v4, "garbage"), "réseau invalide -> false");
        assert!(!ip_in_cidr(&v4, "10.0.0.0/33"), "préfixe hors borne -> false");
        assert!(!ip_in_cidr(&v4, "10.0.0.0/x"), "préfixe non numérique -> false");
        let v6 = "2001:db8::5".parse::<IpAddr>().unwrap();
        assert!(ip_in_cidr(&v6, "2001:db8::/32"));
        assert!(!ip_in_cidr(&v6, "2001:dead::/32"));
        assert!(!ip_in_cidr(&v4, "2001:db8::/32"), "v4 vs réseau v6 -> false");
        assert!(!ip_in_cidr(&v6, "10.0.0.0/8"), "v6 vs réseau v4 -> false");
    }

    /// [OPÉRATEUR source-CIDR] check_operator : la contrainte source ne s'applique QUE si configurée.
    /// Non configurée -> toute IP passe (défaut = none). Configurée -> hors-allowlist REFUSÉ, dans
    /// l'allowlist AUTORISÉ, IP indéterminée REFUSÉE (fail-closed). trusted_proxy (CIDR du proxy) ->
    /// honore le dernier hop XFF UNIQUEMENT si le pair TCP EST ce proxy ; un client direct (pair hors
    /// CIDR) qui forge un XFF est IGNORÉ (repli sur le pair) ; valeur héritée "1" -> aucun proxy de
    /// confiance. Un viewer ne passe jamais.
    #[tokio::test]
    async fn operator_source_cidr_enforced_only_when_configured() {
        let path = tmp_path("forge-test-op-cidr");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "op", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
        }
        let (otok, _) = create_session(&app, uid_of(&app, "op"));
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let h = bearer_headers(&otok);
        let ip_ok = "10.0.0.5".parse::<IpAddr>().unwrap();
        let ip_bad = "192.168.1.9".parse::<IpAddr>().unwrap();

        // (a) AUCUNE politique -> toute IP passe (défaut = none), y compris IP indéterminée.
        assert!(check_operator(&app, &h, Some(ip_ok)));
        assert!(check_operator(&app, &h, Some(ip_bad)), "sans politique, IP hors 'futur allowlist' passe");
        assert!(check_operator(&app, &h, None), "sans politique, IP indéterminée passe");

        // (b) politique source_cidrs configurée -> restriction fail-closed.
        {
            let db = app.db();
            settings_set(&db, "operator_policy", "{\"source_cidrs\":[\"10.0.0.0/24\"]}").unwrap();
        }
        assert!(check_operator(&app, &h, Some(ip_ok)), "IP dans le CIDR -> autorisée");
        assert!(!check_operator(&app, &h, Some(ip_bad)), "IP hors CIDR -> refusée (fail-closed)");
        assert!(!check_operator(&app, &h, None), "politique active + IP indéterminée -> refus");

        // (c) AUCUN trusted_proxy configuré -> X-Forwarded-For IGNORÉ (on prend le pair). Pair hors
        //     CIDR -> refus, même si le XFF prétend une IP autorisée.
        let mut hx = bearer_headers(&otok);
        hx.insert("x-forwarded-for", "10.0.0.5".parse().unwrap());
        assert!(!check_operator(&app, &hx, Some(ip_bad)), "sans trusted_proxy -> XFF ignoré, pair hors CIDR -> refus");

        // (d) [RÉTRO-COMPAT] valeur héritée "1" (truthy non-CIDR) -> traitée comme AUCUN proxy de
        //     confiance -> XFF ignoré, repli fail-closed sur le pair. Ne vaut JAMAIS « fais confiance à
        //     tout XFF » (ce qui rouvrirait le contournement).
        {
            let db = app.db();
            settings_set(&db, "trusted_proxy", "1").unwrap();
        }
        let mut hlegacy = bearer_headers(&otok);
        hlegacy.insert("x-forwarded-for", "203.0.113.7, 10.0.0.5".parse().unwrap());
        assert!(!check_operator(&app, &hlegacy, Some(ip_bad)),
            "trusted_proxy='1' (héritée) -> aucun proxy de confiance -> XFF ignoré, pair hors CIDR -> refus");

        // On configure désormais trusted_proxy = le CIDR RÉEL du proxy amont.
        {
            let db = app.db();
            settings_set(&db, "trusted_proxy", "172.16.0.0/12").unwrap();
        }
        let proxy_ip = "172.16.0.9".parse::<IpAddr>().unwrap(); // pair ∈ trusted_proxy CIDR

        // (e) [RÉGRESSION anti-contournement] client DIRECT (pair hors trusted_proxy CIDR) qui FORGE un
        //     X-Forwarded-For revendiquant une IP de l'allowlist -> XFF IGNORÉ (le pair n'est pas le
        //     proxy) -> repli sur le pair (ip_bad) -> REFUSÉ. Fermeture du bypass XFF spoofé.
        let mut hspoof = bearer_headers(&otok);
        hspoof.insert("x-forwarded-for", "10.0.0.5".parse().unwrap());
        assert!(!check_operator(&app, &hspoof, Some(ip_bad)),
            "client direct + XFF spoofé prétendant une IP autorisée -> XFF ignoré, repli sur pair -> REFUSÉ (bypass fermé)");

        // (f) requête RÉELLEMENT relayée : le pair TCP EST le proxy de confiance (∈ CIDR) et le dernier
        //     hop XFF est dans l'allowlist opérateur -> honoré -> AUTORISÉ (le pair-proxy n'est PAS dans
        //     l'allowlist, ce qui prouve que c'est bien le XFF qui décide).
        let mut hp = bearer_headers(&otok);
        hp.insert("x-forwarded-for", "203.0.113.7, 10.0.0.5".parse().unwrap());
        assert!(check_operator(&app, &hp, Some(proxy_ip)),
            "pair = proxy de confiance + dernier hop XFF dans le CIDR -> autorisé");

        // (f-bis) même proxy de confiance mais dernier hop XFF hors allowlist -> refusé (fail-closed sur
        //     l'IP réelle du client telle que déclarée par le proxy).
        let mut hp2 = bearer_headers(&otok);
        hp2.insert("x-forwarded-for", "203.0.113.7, 192.168.1.9".parse().unwrap());
        assert!(!check_operator(&app, &hp2, Some(proxy_ip)),
            "pair = proxy de confiance mais dernier hop XFF hors CIDR -> refusé");

        // (g) un viewer ne passe JAMAIS, quelle que soit l'IP/politique.
        assert!(!check_operator(&app, &bearer_headers(&vtok), Some(ip_ok)), "viewer refusé indépendamment de la politique source");
        let _ = std::fs::remove_file(&path);
    }

    /// [SÉCURITÉ XFF] parse_trusted_proxy_cidrs : tableau JSON / CSV / CIDR unique -> liste ; valeurs
    /// héritées truthy non-CIDR ("1"/"true"), vide, ou déchet -> liste VIDE (aucun proxy de confiance).
    /// effective_client_ip : XFF honoré SEULEMENT si le pair ∈ un trusted_proxy CIDR ; sinon IGNORÉ
    /// (repli fail-closed sur le pair, ou None si pair inconnu).
    #[test]
    fn trusted_proxy_cidr_parse_and_effective_ip_fail_closed() {
        // parse : formats acceptés
        assert_eq!(parse_trusted_proxy_cidrs("10.0.0.0/24"), vec!["10.0.0.0/24".to_string()]);
        assert_eq!(parse_trusted_proxy_cidrs("[\"10.0.0.0/24\",\"172.16.0.0/12\"]"),
                   vec!["10.0.0.0/24".to_string(), "172.16.0.0/12".to_string()]);
        assert_eq!(parse_trusted_proxy_cidrs("10.0.0.0/24, 172.16.0.0/12"),
                   vec!["10.0.0.0/24".to_string(), "172.16.0.0/12".to_string()]);
        assert_eq!(parse_trusted_proxy_cidrs("203.0.113.4"), vec!["203.0.113.4".to_string()], "IP nue -> match exact");
        // parse : héritées / invalides -> vide (fail-closed, jamais « trust all »)
        assert!(parse_trusted_proxy_cidrs("1").is_empty(), "'1' hérité -> aucun proxy de confiance");
        assert!(parse_trusted_proxy_cidrs("true").is_empty(), "'true' hérité -> aucun proxy de confiance");
        assert!(parse_trusted_proxy_cidrs("").is_empty());
        assert!(parse_trusted_proxy_cidrs("garbage").is_empty());
        assert!(parse_trusted_proxy_cidrs("10.0.0.0/33").is_empty(), "préfixe hors borne -> écarté");

        let cidrs = vec!["172.16.0.0/12".to_string()];
        let proxy = "172.16.0.9".parse::<IpAddr>().unwrap();
        let direct = "192.168.1.9".parse::<IpAddr>().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.5".parse().unwrap());

        // pair = proxy de confiance -> dernier hop XFF honoré
        assert_eq!(effective_client_ip(Some(proxy), &h, &cidrs), Some("10.0.0.5".parse().unwrap()));
        // pair = client direct (hors CIDR) -> XFF IGNORÉ, repli sur le pair
        assert_eq!(effective_client_ip(Some(direct), &h, &cidrs), Some(direct));
        // aucun trusted_proxy -> XFF ignoré, repli sur le pair
        assert_eq!(effective_client_ip(Some(proxy), &h, &[]), Some(proxy));
        // pair inconnu -> None (fail-closed), jamais l'XFF
        assert_eq!(effective_client_ip(None, &h, &cidrs), None);
    }

    /// [LOW sec] ct_eq_str : égalité correcte, inégalité correcte (la propriété temps-constant n'est
    /// pas mesurable en test unitaire, mais on garantit la correction fonctionnelle).
    #[test]
    fn ct_eq_str_correctness() {
        assert!(ct_eq_str("deadbeef", "deadbeef"));
        assert!(!ct_eq_str("deadbeef", "deadbee0"));
        assert!(!ct_eq_str("deadbeef", "deadbeeff")); // longueurs différentes
        assert!(!ct_eq_str("", "x"));
    }

    /// [WebUI] L'aide in-app est présente et accessible : bouton « ? » persistant (annoncé comme
    /// dialog) + indices de champ inline sur le wizard config-heavy dans l'index compilé, et le front
    /// définit le centre d'aide (openHelp + registre HELP_TOPICS + rubrique gouvernance/modèle de
    /// sûreté) avec la modale role=dialog/aria-modal et les indices des formulaires config-heavy.
    /// Garde-fou anti-régression : ces marqueurs ne doivent pas disparaître silencieusement.
    #[test]
    fn webui_help_affordance_and_registry_present() {
        let index = include_str!("../web/index.html");
        assert!(index.contains("id=\"help\""), "bouton d'aide manquant dans l'en-tête");
        assert!(index.contains("aria-haspopup=\"dialog\""), "affordance d'aide non annoncée comme dialog");
        assert!(index.contains("class=\"fhint\""), "indices de champ (.fhint) absents du wizard de 1er déploiement");

        // Le front est désormais découpé en modules ES (app.js = entrée ; le code vit sous web/js/**).
        // On agrège les modules porteurs de ces marqueurs et on cherche dans l'ensemble : le centre
        // d'aide (help.js), la modale accessible (ui.js) et les indices de source de détection (admin.js).
        let app = [
            include_str!("../web/app.js"),
            include_str!("../web/js/core/help.js"),
            include_str!("../web/js/core/ui.js"),
            include_str!("../web/js/views/admin.js"),
            include_str!("../web/js/components/detection-source-form.js"),
        ]
        .concat();
        assert!(app.contains("function openHelp("), "openHelp() absent du front");
        assert!(app.contains("HELP_TOPICS"), "registre d'aide HELP_TOPICS absent");
        assert!(app.contains("'governance'"), "rubrique « Comment Forge fonctionne » (gouvernance) absente");
        assert!(app.contains("'aria-modal'"), "la modale d'aide n'est pas marquée aria-modal");
        assert!(app.contains("'dialog'"), "la modale d'aide n'a pas role=dialog");
        assert!(app.contains("modal-fhint"), "indices de champ des modales (users/backup) absents");
        assert!(app.contains("det-fhint"), "indices de champ de la source de détection absents");
    }

    /// [LOW sec] host_guard fail-closed : Host vide/absent REFUSÉ ; hors allowlist refusé ; in-allowlist
    /// accepté (port ignoré).
    #[test]
    fn host_guard_rejects_empty_and_unknown() {
        let allow = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        assert!(!host_allowed("", &allow), "Host vide doit être refusé (fail-closed)");
        assert!(!host_allowed(":7100", &allow), "Host vide avec port doit être refusé");
        assert!(!host_allowed("evil.example", &allow), "Host hors allowlist refusé");
        assert!(host_allowed("localhost", &allow));
        assert!(host_allowed("localhost:7100", &allow), "port ignoré");
        assert!(host_allowed("127.0.0.1:8080", &allow));
    }

    /// [MED race ledger] append_console_ledger : la chaîne SHA-256 reste valide sur N appends
    /// séquentiels (prev chaîné, seq incrémental). Recalcule la chaîne comme /api/ledger/verify.
    #[test]
    fn ledger_chain_is_consistent() {
        let path = tmp_path("forge-test-ledger");
        let app = test_app(&path);
        for i in 0..25 {
            append_console_ledger(&app, "console.test", json!({"i": i, "msg": "événement"}));
        }
        let entries = read_ledger_lines(&path);
        assert_eq!(entries.len(), 25, "25 entrées écrites");
        const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
        let mut prev = GENESIS.to_string();
        for (n, rec) in entries.iter().enumerate() {
            let seq = rec.get("seq").and_then(|v| v.as_i64()).unwrap();
            assert_eq!(seq, (n as i64) + 1, "seq strictement incrémental sans trou ni doublon");
            let stored_prev = rec.get("prev").and_then(|v| v.as_str()).unwrap();
            assert_eq!(stored_prev, prev, "chaînage prev rompu à l'entrée {n}");
            let ts = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("");
            let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let detail = rec.get("detail").cloned().unwrap_or(Value::Null);
            let preimage = format!("{prev}|{seq}|{ts}|{kind}|{}", canon_json(&detail));
            let recomputed = sha_hex(&preimage);
            let stored_hash = rec.get("hash").and_then(|v| v.as_str()).unwrap();
            assert_eq!(recomputed, stored_hash, "hash recalculé != stocké à l'entrée {n}");
            prev = stored_hash.to_string();
        }
        let _ = std::fs::remove_file(&path);
    }

    /// [MED race ledger] head caché : un 2e cycle d'appends (après relecture disque par une AUTRE App)
    /// continue la chaîne sans réinitialiser seq/prev (pas de doublon de seq).
    #[test]
    fn ledger_continues_across_reload() {
        let path = tmp_path("forge-test-ledger-reload");
        {
            let app = test_app(&path);
            append_console_ledger(&app, "k", json!({"a": 1}));
            append_console_ledger(&app, "k", json!({"a": 2}));
        }
        // nouvelle App (head cache vide) -> doit relire le disque et reprendre à seq=3.
        let app2 = test_app(&path);
        append_console_ledger(&app2, "k", json!({"a": 3}));
        let entries = read_ledger_lines(&path);
        assert_eq!(entries.len(), 3);
        let seqs: Vec<i64> = entries.iter().filter_map(|e| e.get("seq").and_then(|v| v.as_i64())).collect();
        assert_eq!(seqs, vec![1, 2, 3], "seq doit reprendre après reload (pas de doublon)");
        let _ = std::fs::remove_file(&path);
    }

    // =========================================================================================
    // MIGRATION DE DONNÉES — chemin PLAINTEXT (aucun sqlcipher requis : ces tests tournent dans la
    // suite PAR DÉFAUT). Le chemin CHIFFRÉ est gardé derrière `#[cfg(feature="encryption")]` plus bas
    // (skip quand non compilé) pour ne JAMAIS faire dépendre la suite par défaut de SQLCipher/openssl.
    // =========================================================================================








    // ---------------------------------------------------------------------------------------
    // SAUVEGARDE / RESTAURATION CHIFFRÉE (backup / restore)
    // ---------------------------------------------------------------------------------------










    // ---------------------------------------------------------------------------------------------
    // API SAUVEGARDE / RESTAURATION / POLITIQUE (admin-gated) + runner programmé
    // ---------------------------------------------------------------------------------------------











    /// [parité lecture] host_in_server_scope : match exact, suffixe de domaine, wildcard `*.`, et
    /// fail-closed quand le scope serveur est vide. Réutilisé par /api/scope-check ET le pré-filtre run.
    #[test]
    fn scope_check_decision_matches_server_scope() {
        let path = tmp_path("forge-test-scope");
        let mut app = test_app(&path);
        // scope vide -> rien n'est in_scope (fail-closed).
        assert!(!host_in_server_scope(&app, "example.com"), "scope vide => fail-closed");
        app.scope_in = Arc::new(vec!["example.com".to_string(), "*.lab.test".to_string()]);
        assert!(host_in_server_scope(&app, "example.com"), "match exact");
        assert!(host_in_server_scope(&app, "api.example.com"), "sous-domaine d'une entrée listée");
        assert!(host_in_server_scope(&app, "a.lab.test"), "wildcard *. -> suffixe");
        assert!(host_in_server_scope(&app, "lab.test"), "wildcard *. -> base elle-même");
        assert!(!host_in_server_scope(&app, "evil.test"), "hors scope refusé");
        assert!(!host_in_server_scope(&app, "notexample.com"), "pas un vrai suffixe de domaine");
        let _ = std::fs::remove_file(&path);
    }

    // =============================================================================================
    // ENGAGEMENT (objet de 1re classe) — migration zéro-perte + isolation du run flow.
    // =============================================================================================

    /// Insère un engagement de test (scope_json dérivé de scope_in/mode, out_scope vide).
    fn insert_test_engagement(app: &App, id: i64, scope_in: &[&str], mode: &str, ledger: &str) {
        
        let scope_json = json!({"mode": mode, "in_scope": scope_in, "out_scope": []}).to_string();
        app.db().execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(?,?,'active',?,?,?,datetime('now'),datetime('now'))",
            rusqlite::params![id, format!("eng{id}"), mode, scope_json, ledger],
        )
        .unwrap();
    }

    /// Corps /api/run minimal (campaign + targets + engagement_id optionnel).
    fn run_body(campaign: &str, engagement_id: Option<i64>, targets: &[&str]) -> Value {
        let mut b = json!({"campaign": campaign, "targets": targets, "mode": "propose"});
        if let Some(e) = engagement_id {
            b["engagement_id"] = json!(e);
        }
        b
    }

    /// [ENGAGEMENT #1 — migration ZÉRO-PERTE] `migrate()` ajoute engagement_id NOT NULL DEFAULT 1 :
    /// une ligne finding PRÉ-EXISTANTE (schéma ancien, sans la colonne) est rétro-rattachée à
    /// l'engagement #1. `ensure_default_engagement` crée l'engagement #1 depuis le scope serveur COURANT
    /// (in_scope + mode) + le ledger courant, et est IDEMPOTENT (n'écrase jamais un engagement existant).
    #[test]
    fn migrate_creates_engagement_one_and_backfills_engagement_id() {
        // `conn()` rend une garde fraîche sur la MÊME connexion (le seeder prend désormais un `&Store` ;
        // les ops rusqlite directes + migrate/load_engagement gardent leur `&Connection` via le deref).
        let dbm = Mutex::new(Connection::open_in_memory().expect("mem db"));
        let conn = || dbm.lock().unwrap_or_else(|e| e.into_inner());
        conn().execute_batch(SCHEMA).expect("schema"); // `finding` n'a PAS encore engagement_id
        // ligne « ancienne » insérée AVANT l'ajout de la colonne (simule une base antérieure).
        conn().execute(
            "INSERT INTO finding(id,title,target,campaign) VALUES(1,'old-finding','h.example','c1')",
            [],
        )
        .unwrap();
        migrate(&conn()); // ALTER ... ADD COLUMN engagement_id NOT NULL DEFAULT 1 -> backfill à 1
        let eid: i64 = conn()
            .query_row("SELECT engagement_id FROM finding WHERE id=1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(eid, 1, "ligne existante rétro-rattachée à l'engagement #1 (DEFAULT)");

        // table engagement vide -> ensure_default_engagement crée #1 depuis le scope/ledger COURANTS.
        let n0: i64 = conn().query_row("SELECT COUNT(*) FROM engagement", [], |r| r.get(0)).unwrap();
        assert_eq!(n0, 0, "aucun engagement avant l'amorçage");
        ensure_default_engagement(
            &crate::store::Store::sqlite(conn()),
            &["a.example.com".to_string(), "*.b.example.com".to_string()],
            "grey",
            "/tmp/eng1.jsonl",
        );
        let eng = load_engagement(&crate::store::Store::sqlite(conn()), 1).expect("engagement #1 créé");
        assert_eq!(eng.id, 1);
        assert_eq!(eng.mode, "grey");
        assert_eq!(eng.scope_in, vec!["a.example.com".to_string(), "*.b.example.com".to_string()],
            "scope de l'engagement #1 = scope serveur courant");
        assert_eq!(eng.ledger_path, "/tmp/eng1.jsonl", "ledger de l'engagement #1 = ledger courant");

        // idempotent : un 2e appel (scope/ledger DIFFÉRENTS) ne réécrit PAS l'engagement #1.
        ensure_default_engagement(&crate::store::Store::sqlite(conn()), &["changed.example".to_string()], "black", "/tmp/other.jsonl");
        let eng2 = load_engagement(&crate::store::Store::sqlite(conn()), 1).unwrap();
        assert_eq!(eng2.scope_in, vec!["a.example.com".to_string(), "*.b.example.com".to_string()],
            "idempotent : scope inchangé");
        assert_eq!(eng2.ledger_path, "/tmp/eng1.jsonl", "idempotent : ledger inchangé");
        let cnt: i64 = conn().query_row("SELECT COUNT(*) FROM engagement", [], |r| r.get(0)).unwrap();
        assert_eq!(cnt, 1, "idempotent : pas de doublon d'engagement");
    }

    /// [RUN FLOW — scope + ledger de L'ENGAGEMENT, pas les App globals] Un run créé pour l'engagement #2
    /// est validé contre le scope de #2 (pas les App globals) et journalisé dans le ledger DÉDIÉ de #2 ;
    /// le run_job porte engagement_id=2. Une cible qui n'est DANS les globals mais PAS dans #2 est
    /// refusée (preuve que ce sont bien les données de l'engagement qui gouvernent, jamais les globals).
    #[tokio::test]
    async fn run_uses_engagement_scope_and_ledger_not_app_globals() {
        let globals_ledger = tmp_path("forge-test-eng-globals");
        // App globals : scope = global.example.com, ledger = globals_ledger. (défauts de l'engagement #1)
        let mut app = test_app_scoped(&globals_ledger, vec!["global.example.com".into()]);
        app.python = Arc::new("true".into()); // spawn no-op : prouve qu'on a PASSÉ la validation sans lancer le moteur
        let eng2_ledger = tmp_path("forge-test-eng2-ledger");
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
        }
        // engagement #1 (globals) + #2 (scope + ledger DISTINCTS des globals).
        insert_test_engagement(&app, 1, &["global.example.com"], "grey", &globals_ledger);
        insert_test_engagement(&app, 2, &["eng2.example.com"], "grey", &eng2_ledger);
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // (a) cible DANS les globals mais HORS du scope de #2 -> refusée (on n'utilise PAS les globals).
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("c2", Some(2), &["global.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "cible du scope GLOBAL refusée pour l'engagement #2");
        let j = resp_json(resp).await;
        assert_eq!(j["error"], "out_of_scope");

        // (b) cible DANS le scope de #2 (mais PAS dans les globals) -> ACCEPTÉE (scope de l'engagement).
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("c2", Some(2), &["eng2.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED,
            "cible du scope de l'engagement #2 acceptée (le run utilise le scope de #2, pas les globals)");

        // run_job estampillé engagement_id=2.
        let run_eid: i64 = {
            let db = app.db();
            db.query_row("SELECT engagement_id FROM run_job WHERE campaign='c2'", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(run_eid, 2, "run_job porte l'engagement #2");

        // ledger : console.run.start est dans le ledger DÉDIÉ de #2, JAMAIS dans les globals.
        let eng2_entries = read_ledger_lines(&eng2_ledger);
        assert!(eng2_entries.iter().any(|e| e["kind"] == "console.run.start"
            && e["detail"]["engagement_id"] == 2),
            "run.start journalisé dans le ledger de l'engagement #2");
        let globals_entries = read_ledger_lines(&globals_ledger);
        assert!(!globals_entries.iter().any(|e| e["kind"] == "console.run.start"),
            "le ledger GLOBAL ne reçoit PAS le run d'un autre engagement (isolation)");

        let _ = std::fs::remove_file(&globals_ledger);
        let _ = std::fs::remove_file(&eng2_ledger);
    }

    /// [ISOLATION] Deux engagements aux scopes DISJOINTS restent isolés : un run pour A valide contre le
    /// scope de A UNIQUEMENT (la cible de B est refusée), et réciproquement. Un run pour B accepte sa
    /// propre cible et journalise dans SON ledger — jamais celui de A.
    #[tokio::test]
    async fn two_engagements_stay_isolated_run_validates_own_scope() {
        let ledger_a = tmp_path("forge-test-engA-ledger");
        let ledger_b = tmp_path("forge-test-engB-ledger");
        // App globals volontairement PERMISSIFS (les 2 hosts) : prouve que la validation vient bien du
        // scope de l'engagement (disjoint), pas des globals (qui accepteraient tout).
        let mut app = test_app_scoped(&ledger_a, vec!["a.example.com".into(), "b.example.com".into()]);
        app.python = Arc::new("true".into());
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
        }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger_a); // A
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger_b); // B
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // A ne valide QUE le scope de A : la cible de B est refusée pour l'engagement A.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cA", Some(1), &["b.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "A refuse la cible de B (isolation)");
        // B ne valide QUE le scope de B : la cible de A est refusée pour l'engagement B.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cB", Some(2), &["a.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "B refuse la cible de A (isolation)");

        // B accepte SA propre cible et journalise dans le ledger de B (jamais celui de A).
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cB", Some(2), &["b.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "B accepte sa propre cible");
        let entries_b = read_ledger_lines(&ledger_b);
        assert!(entries_b.iter().any(|e| e["kind"] == "console.run.start" && e["detail"]["engagement_id"] == 2),
            "run de B journalisé dans le ledger de B");
        let entries_a = read_ledger_lines(&ledger_a);
        assert!(!entries_a.iter().any(|e| e["kind"] == "console.run.start"),
            "le ledger de A ne reçoit JAMAIS le run de B (isolation ledger)");

        let _ = std::fs::remove_file(&ledger_a);
        let _ = std::fs::remove_file(&ledger_b);
    }

    /// [CONCURRENCE INTER-ENGAGEMENT + FIFO PAR ENGAGEMENT] Le slot de run n'est PLUS un FIFO
    /// console-global : c'est une map `engagement_id -> RunHandle`. Ce test prouve, de façon
    /// déterministe (slots posés à la main, sans dépendre de la durée d'un process), que :
    ///   (1) DEUX engagements peuvent avoir un run vivant EN MÊME TEMPS (la map porte 2 clés) ;
    ///   (2) un 2e /api/run sur un engagement DÉJÀ vivant -> 409 (FIFO PAR engagement), et le 409 porte
    ///       le bon engagement_id ;
    ///   (3) démarrer un run pour un TROISIÈME engagement pendant que #1 et #2 sont vivants -> 202
    ///       (aucun 409 croisé — la concurrence inter-engagement est réelle) ;
    ///   (4) le run de #3 est journalisé dans le ledger de #3 UNIQUEMENT (jamais ceux de #1/#2).
    // ALLOW significant_drop_tightening: the fixture below holds the run_state guard across two inserts +
    // an invariant assertion so the two simultaneous live runs are published as one atomic unit (mirrors
    // the production promotion). Nursery-lint FP on a deliberately-atomic block.
    #[allow(clippy::significant_drop_tightening)]
    #[tokio::test]
    async fn run_slot_is_per_engagement_not_global_fifo() {
        let ledger_a = tmp_path("forge-test-conc-A");
        let ledger_b = tmp_path("forge-test-conc-B");
        let ledger_c = tmp_path("forge-test-conc-C");
        // Globals volontairement PERMISSIFS (les 3 hosts) : la validation vient du scope de l'engagement.
        let mut app = test_app_scoped(&ledger_a,
            vec!["a.example.com".into(), "b.example.com".into(), "c.example.com".into()]);
        app.python = Arc::new("true".into()); // spawn no-op : le run #3 aboutit sans lancer le moteur
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
        }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger_a); // A
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger_b); // B
        insert_test_engagement(&app, 3, &["c.example.com"], "grey", &ledger_c); // C
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // (1) On pose À LA MAIN deux runs vivants simultanés (A sous la clé 1, B sous la clé 2). pgid=-1
        // => kill_group ignore (aucun process réel visé). Deux engagements vivants EN MÊME TEMPS.
        {
            let mut st = app.run_state.lock().await;
            st.current.insert(1, RunHandle { run_id: "run-held-A".into(), pgid: -1 });
            st.current.insert(2, RunHandle { run_id: "run-held-B".into(), pgid: -1 });
            assert_eq!(st.current.len(), 2, "deux engagements ont un run vivant EN MÊME TEMPS (map à 2 clés)");
        }

        // (2) 2e run sur un engagement DÉJÀ vivant -> 409, avec l'engagement_id fautif dans le corps.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cA2", Some(1), &["a.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "2e run sur #1 (déjà vivant) -> 409 (FIFO par engagement)");
        let j = resp_json(resp).await;
        assert_eq!(j["error"], "run_in_progress");
        assert_eq!(j["engagement_id"], 1, "le 409 identifie l'engagement occupé (#1)");
        // idem pour #2 (l'autre engagement vivant) -> 409, jamais un faux 202.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cB2", Some(2), &["b.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "2e run sur #2 (déjà vivant) -> 409");
        assert_eq!(resp_json(resp).await["engagement_id"], 2);

        // (3) un run pour un TROISIÈME engagement pendant que #1 ET #2 sont vivants -> 202 (aucun 409
        // croisé : la présence de runs pour #1/#2 n'entrave pas #3). C'est LA preuve de la concurrence.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cC", Some(3), &["c.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED,
            "run pour #3 pendant que #1 et #2 sont vivants -> 202 (concurrence inter-engagement, pas de 409 croisé)");
        // run_job de #3 estampillé engagement_id=3.
        let eid3: i64 = { let db = app.db(); db.query_row("SELECT engagement_id FROM run_job WHERE campaign='cC'", [], |r| r.get(0)).unwrap() };
        assert_eq!(eid3, 3, "le run concurrent porte l'engagement #3");

        // (4) isolation ledger : run.start de #3 dans SON ledger, JAMAIS dans ceux de #1/#2.
        assert!(read_ledger_lines(&ledger_c).iter().any(|e| e["kind"] == "console.run.start" && e["detail"]["engagement_id"] == 3),
            "run.start de #3 journalisé dans le ledger de #3");
        assert!(!read_ledger_lines(&ledger_a).iter().any(|e| e["kind"] == "console.run.start"),
            "le ledger de #1 ne reçoit PAS le run de #3 (isolation)");
        assert!(!read_ledger_lines(&ledger_b).iter().any(|e| e["kind"] == "console.run.start"),
            "le ledger de #2 ne reçoit PAS le run de #3 (isolation)");

        let _ = std::fs::remove_file(&ledger_a);
        let _ = std::fs::remove_file(&ledger_b);
        let _ = std::fs::remove_file(&ledger_c);
    }

    /// [ISOLATION VERROUILLÉE] Un run pour A écrit UNIQUEMENT le ledger de A et n'altère RIEN de B :
    ///   - PROBE (fail-closed) : un run de A contre une cible qui n'est QUE dans le scope de B est
    ///     refusé (400 out_of_scope) — A ne peut PAS tirer sur le périmètre de B (isolation par scope) ;
    ///   - le run de A (sur sa propre cible) est ACCEPTÉ et journalisé dans le ledger de A ;
    ///   - le ledger de B est INCHANGÉ (aucune ligne ajoutée, aucun run.start de A) ;
    ///   - les findings de B (engagement_id=2) sont INTACTS (nombre + contenu).
    #[tokio::test]
    async fn run_for_a_writes_only_a_ledger_and_leaves_b_untouched() {
        let ledger_a = tmp_path("forge-test-lock-A");
        let ledger_b = tmp_path("forge-test-lock-B");
        // Globals permissifs (a+b) : la validation doit venir du scope de l'engagement, pas des globals.
        let mut app = test_app_scoped(&ledger_a, vec!["a.example.com".into(), "b.example.com".into()]);
        app.python = Arc::new("true".into());
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
            // Sème l'état de B : un finding (engagement_id=2) + une entrée de ledger propre à B.
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('finding-de-B','b.example.com','cB','HIGH',2)", []).unwrap();
        }
        ledger_append_standalone(&ledger_b, "engagement.seed", &json!({"note": "état initial de B"})).unwrap();
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger_a); // A
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger_b); // B
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // Instantané de l'état de B AVANT tout run de A.
        let b_ledger_before = read_ledger_lines(&ledger_b).len();
        let b_findings_before: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=2", [], |r| r.get(0)).unwrap() };
        assert_eq!(b_findings_before, 1, "B a bien 1 finding au départ");

        // PROBE : A ne peut PAS tirer contre une cible qui n'est QUE dans le scope de B -> 400 out_of_scope.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cA-probe", Some(1), &["b.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "A refuse une cible du scope de B (probe d'isolation)");
        assert_eq!(resp_json(resp).await["error"], "out_of_scope");

        // Run LÉGITIME de A sur sa propre cible -> 202, journalisé dans le ledger de A.
        let resp = run_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(run_body("cA", Some(1), &["a.example.com"]))).await.into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "A accepte SA propre cible");
        assert!(read_ledger_lines(&ledger_a).iter().any(|e| e["kind"] == "console.run.start" && e["detail"]["engagement_id"] == 1),
            "run.start de A journalisé dans le ledger de A");

        // VERROU : B est resté totalement intact — ledger et findings.
        let b_ledger_after = read_ledger_lines(&ledger_b);
        assert_eq!(b_ledger_after.len(), b_ledger_before, "le ledger de B n'a reçu AUCUNE ligne d'un run de A");
        assert!(!b_ledger_after.iter().any(|e| e["kind"] == "console.run.start"),
            "aucun run.start (a fortiori de A) n'apparaît dans le ledger de B");
        let b_findings_after: i64 = { let db = app.db(); db.query_row("SELECT COUNT(*) FROM finding WHERE engagement_id=2", [], |r| r.get(0)).unwrap() };
        assert_eq!(b_findings_after, b_findings_before, "les findings de B sont intacts (nombre inchangé)");
        let b_title: String = { let db = app.db(); db.query_row("SELECT title FROM finding WHERE engagement_id=2 LIMIT 1", [], |r| r.get(0)).unwrap() };
        assert_eq!(b_title, "finding-de-B", "le finding de B est intact (contenu inchangé)");

        let _ = std::fs::remove_file(&ledger_a);
        let _ = std::fs::remove_file(&ledger_b);
    }

    /// Query<HashMap> pratique pour cibler un engagement en lecture dans les tests (`?engagement=<id>`).
    fn eng_query(id: i64) -> Query<HashMap<String, String>> {
        Query(HashMap::from([("engagement".to_string(), id.to_string())]))
    }

    /// [ENGAGEMENT — vues filtrées] Les endpoints de LISTE ne renvoient QUE les données de l'engagement
    /// ciblé par `?engagement=<id>` : les findings/runrecords/roe/runs/campagnes/couverture de A ne sont
    /// JAMAIS visibles sous B, et réciproquement (isolation stricte des vues, fail-closed).
    #[tokio::test]
    async fn list_endpoints_filter_by_engagement() {
        let ledger = tmp_path("forge-test-eng-list");
        let ledger2 = tmp_path("forge-test-eng-list2");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger);
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger2);
        {
            let db = app.db();
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('fa','a.example.com','cA','HIGH',1)", []).unwrap();
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('fb','b.example.com','cB','LOW',2)", []).unwrap();
            db.execute("INSERT INTO runrecord(campaign,target,kind,mitre,fired,engagement_id) VALUES('cA','a.example.com','recon.http','T1190',1,1)", []).unwrap();
            db.execute("INSERT INTO runrecord(campaign,target,kind,mitre,fired,engagement_id) VALUES('cB','b.example.com','recon.http','T1046',1,2)", []).unwrap();
            db.execute("INSERT INTO roe_decision(campaign,run_id,action_id,target,kind,verdict,engagement_id) VALUES('cA','r1','a1','a.example.com','recon.http','FIRE',1)", []).unwrap();
            db.execute("INSERT INTO roe_decision(campaign,run_id,action_id,target,kind,verdict,engagement_id) VALUES('cB','r2','a2','b.example.com','recon.http','VETO',2)", []).unwrap();
            db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('r1','cA','done','propose',1)", []).unwrap();
            db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('r2','cB','done','propose',2)", []).unwrap();
        }

        // findings : #1 ne voit que fa, #2 que fb.
        let j = resp_json(findings(State(app.clone()), HeaderMap::new(), eng_query(1)).await.into_response()).await;
        let t1: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(t1.contains(&"fa".to_string()) && !t1.contains(&"fb".to_string()), "engagement #1 ne voit que SES findings");
        let j = resp_json(findings(State(app.clone()), HeaderMap::new(), eng_query(2)).await.into_response()).await;
        let t2: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(t2.contains(&"fb".to_string()) && !t2.contains(&"fa".to_string()), "engagement #2 ne voit que SES findings");

        // runrecords : isolés par engagement.
        let j = resp_json(runrecords(State(app.clone()), HeaderMap::new(), eng_query(1)).await.into_response()).await;
        assert!(j.as_array().unwrap().iter().all(|x| x["campaign"] == "cA"), "runrecords #1 isolés");
        assert!(!j.as_array().unwrap().is_empty(), "runrecords #1 non vides");

        // roe : isolés par engagement.
        let j = resp_json(roe(State(app.clone()), HeaderMap::new(), eng_query(2)).await.into_response()).await;
        assert!(j.as_array().unwrap().iter().all(|x| x["campaign"] == "cB"), "roe #2 isolés");

        // runs : isolés par engagement.
        let j = resp_json(runs_list(State(app.clone()), HeaderMap::new(), eng_query(1)).await.into_response()).await;
        assert!(j.as_array().unwrap().iter().all(|x| x["campaign"] == "cA"), "runs #1 isolés");

        // campagnes (dérivées des findings) : isolées par engagement.
        let j = resp_json(campaigns(State(app.clone()), HeaderMap::new(), eng_query(2)).await.into_response()).await;
        let camps: Vec<String> = j.as_array().unwrap().iter().map(|c| c["campaign"].as_str().unwrap().to_string()).collect();
        assert!(camps.contains(&"cB".to_string()) && !camps.contains(&"cA".to_string()), "campagnes #2 isolées");

        // couverture ATT&CK : isolée par engagement (T1190 chez #1, T1046 chez #2).
        let j = resp_json(coverage(State(app.clone()), HeaderMap::new(), eng_query(1)).await.into_response()).await;
        let mitres: Vec<String> = j.as_array().unwrap().iter().map(|c| c["mitre"].as_str().unwrap().to_string()).collect();
        assert!(mitres.contains(&"T1190".to_string()) && !mitres.contains(&"T1046".to_string()), "couverture #1 isolée");

        // finding_detail : un id de #2 n'est PAS servi sous #1 (404, isolation).
        let fid_b: i64 = { let db = app.db(); db.query_row("SELECT id FROM finding WHERE title='fb'", [], |r| r.get(0)).unwrap() };
        let resp = finding_detail(State(app.clone()), HeaderMap::new(), Path(fid_b), eng_query(1)).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "détail d'un finding d'un AUTRE engagement -> 404");
        let resp = finding_detail(State(app.clone()), HeaderMap::new(), Path(fid_b), eng_query(2)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "détail servi dans SON engagement");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    // =====================================================================================
    // ENTERPRISE — ROW-LEVEL MULTI-TENANCY (tenancy.rs), flag-gated. Fail-closed tenant isolation +
    // community no-op (byte-identical). Ces tests sont MUTATION-PROVABLES : affaiblir le filtre central
    // (tenancy::engagement_visible / engagement_in / granted_tenants) fait passer un test AU ROUGE.
    // =====================================================================================

    /// Engage le flag enterprise via la config par-DB `enterprise.tenancy=on` (isolé par test, pas d'ENV
    /// global). Le comportement community reste le défaut (flag absent).
    fn enable_enterprise_tenancy(app: &App) {
        let db = app.db();
        settings_set(&db, "enterprise.tenancy", "on").unwrap();
    }

    /// Rattache l'engagement `eid` au tenant `tid` (crée la ligne tenant si besoin).
    fn set_engagement_tenant(app: &App, eid: i64, tid: i64) {
        let db = app.db();
        db.execute(
            "INSERT OR IGNORE INTO tenant(id,name,status,created,updated) VALUES(?,?,'active',datetime('now'),datetime('now'))",
            rusqlite::params![tid, format!("tenant{tid}")],
        ).unwrap();
        db.execute("UPDATE engagement SET tenant_id=? WHERE id=?", rusqlite::params![tid, eid]).unwrap();
    }

    /// Accorde à `user_id` l'accès au tenant `tid` (rôle tenant_*).
    fn grant_tenant(app: &App, user_id: i64, tid: i64, role: &str) {
        let db = app.db();
        db.execute(
            "INSERT OR IGNORE INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,?,?,datetime('now'))",
            rusqlite::params![user_id, tid, role],
        ).unwrap();
    }

    /// PER-ENGAGEMENT RBAC (readiness #14) : pose un grant engagement-spécifique (override tenant).
    fn grant_engagement(app: &App, user_id: i64, eid: i64, role: &str) {
        let db = app.db();
        db.execute(
            "INSERT OR REPLACE INTO engagement_grant(user_id,engagement_id,role,created) VALUES(?,?,?,datetime('now'))",
            rusqlite::params![user_id, eid, role],
        ).unwrap();
    }

    /// Sème deux tenants (1,2), deux engagements (#1->tenant1, #2->tenant2), chacun avec un finding/
    /// runrecord/roe/run_job, et deux users (alice->tenant1, bob->tenant2). Retourne (app, alice_headers,
    /// bob_headers, fid_a, fid_b). L'app est en mode ENTERPRISE.
    fn seed_two_tenants(ledger: &str, ledger2: &str) -> (App, HeaderMap, HeaderMap, i64, i64) {
        let app = test_app_scoped(ledger, vec!["a.example.com".into(), "b.example.com".into()]);
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", ledger);  // A
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", ledger2); // B
        set_engagement_tenant(&app, 1, 1);
        set_engagement_tenant(&app, 2, 2);
        {
            let db = app.db();
            upsert_user(&db, "alice", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "bob", "operator", &hash_pw("pw")).unwrap();
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('fa','a.example.com','cA','HIGH',1)", []).unwrap();
            db.execute("INSERT INTO finding(title,target,campaign,severity,engagement_id) VALUES('fb','b.example.com','cB','LOW',2)", []).unwrap();
            db.execute("INSERT INTO runrecord(campaign,target,kind,mitre,fired,engagement_id) VALUES('cA','a.example.com','recon.http','T1190',1,1)", []).unwrap();
            db.execute("INSERT INTO runrecord(campaign,target,kind,mitre,fired,engagement_id) VALUES('cB','b.example.com','recon.http','T1046',1,2)", []).unwrap();
            db.execute("INSERT INTO roe_decision(campaign,run_id,action_id,target,kind,verdict,engagement_id) VALUES('cA','r1','a1','a.example.com','recon.http','FIRE',1)", []).unwrap();
            db.execute("INSERT INTO roe_decision(campaign,run_id,action_id,target,kind,verdict,engagement_id) VALUES('cB','r2','a2','b.example.com','recon.http','VETO',2)", []).unwrap();
            db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('r1','cA','done','propose',1)", []).unwrap();
            db.execute("INSERT INTO run_job(run_id,campaign,status,mode,engagement_id) VALUES('r2','cB','done','propose',2)", []).unwrap();
        }
        let (uid_a, uid_b) = (uid_of(&app, "alice"), uid_of(&app, "bob"));
        grant_tenant(&app, uid_a, 1, "tenant_operator");
        grant_tenant(&app, uid_b, 2, "tenant_operator");
        let (atok, _) = create_session(&app, uid_a);
        let (btok, _) = create_session(&app, uid_b);
        let fid_a: i64 = { let db = app.db(); db.query_row("SELECT id FROM finding WHERE title='fa'", [], |r| r.get(0)).unwrap() };
        let fid_b: i64 = { let db = app.db(); db.query_row("SELECT id FROM finding WHERE title='fb'", [], |r| r.get(0)).unwrap() };
        enable_enterprise_tenancy(&app);
        (app, bearer_headers(&atok), bearer_headers(&btok), fid_a, fid_b)
    }

    /// [TENANCY — community no-op] Flag OFF (défaut) : le filtre tenant est INERTE. Un user SANS aucun
    /// grant voit TOUS les engagements et TOUTES leurs données (comportement mono-tenant historique,
    /// byte-identique). C'est la garantie « default build = single implicit tenant ».
    #[tokio::test]
    async fn tenancy_disabled_is_community_noop() {
        let ledger = tmp_path("forge-test-tnc-noop");
        let ledger2 = tmp_path("forge-test-tnc-noop2");
        // seed_two_tenants ENGAGE le flag ; on le DÉSACTIVE pour ce test (config community).
        let (app, alice, _bob, _fa, fid_b) = seed_two_tenants(&ledger, &ledger2);
        { let db = app.db(); db.execute("DELETE FROM settings WHERE key='enterprise.tenancy'", []).unwrap(); }
        assert!(!tenancy::enabled(&app), "flag OFF => community");

        // alice n'a de grant QUE sur tenant 1, mais en community elle voit AUSSI le tenant 2 (no-op).
        assert!(tenancy::engagement_visible(&app, &alice, 2), "community : visibilité universelle (no-op)");
        let engs = engagement_list_json(&app, &alice);
        assert_eq!(engs.len(), 2, "community : la liste montre les DEUX engagements (no filtre)");
        // findings de l'engagement #2 servis à alice malgré l'absence de grant (mono-tenant).
        let j = resp_json(findings(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await;
        let titles: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(titles.contains(&"fb".to_string()), "community : findings de #2 visibles (no-op)");
        // finding_detail d'un id de #2 servi sous #2 (200) même sans grant.
        let resp = finding_detail(State(app.clone()), alice.clone(), Path(fid_b), eng_query(2)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "community : détail servi (no-op)");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY — fail-closed cross-tenant] ENTERPRISE ON. alice (tenant A) ne peut NI LISTER, NI LIRE,
    /// NI AGIR sur les engagements/findings/runs/roe/ledger/couverture/rapport de bob (tenant B), et
    /// réciproquement. Aucun grant => zéro ligne / 403 (deny-by-default, comme le ROE).
    ///
    /// ⚠️ MUTATION-PROOF : si l'on affaiblit le filtre central (ex. `engagement_in`/`engagement_visible`
    /// renvoient `true`), `view_engagement_id(alice, Some(2))` cesserait de renvoyer NO_ENGAGEMENT et les
    /// findings/runs de B DÉBORDERAIENT chez alice -> les asserts « n'est PAS visible » passent AU ROUGE.
    #[tokio::test]
    async fn enterprise_tenant_isolation_is_fail_closed() {
        let ledger = tmp_path("forge-test-tnc-iso");
        let ledger2 = tmp_path("forge-test-tnc-iso2");
        let (app, alice, bob, _fa, fid_b) = seed_two_tenants(&ledger, &ledger2);
        assert!(tenancy::enabled(&app), "flag ON => enterprise");

        // (a) LISTE : alice ne voit QUE l'engagement de son tenant (A), bob QUE le sien (B).
        let ea: Vec<i64> = engagement_list_json(&app, &alice).iter().map(|e| e["id"].as_i64().unwrap()).collect();
        assert_eq!(ea, vec![1], "alice ne liste QUE l'engagement de son tenant");
        let eb: Vec<i64> = engagement_list_json(&app, &bob).iter().map(|e| e["id"].as_i64().unwrap()).collect();
        assert_eq!(eb, vec![2], "bob ne liste QUE l'engagement de son tenant");

        // (b) FINDINGS : alice voit fa (A), JAMAIS fb (B) — même en ciblant explicitement ?engagement=2.
        let j = resp_json(findings(State(app.clone()), alice.clone(), eng_query(1)).await.into_response()).await;
        let ta: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(ta.contains(&"fa".to_string()), "alice voit SES findings");
        let j = resp_json(findings(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await;
        assert!(j["findings"].as_array().unwrap().is_empty(), "alice ne voit AUCUN finding de B (fail-closed)");

        // (c) FINDING_DETAIL : un id de B n'est PAS servi à alice, même sous ?engagement=2 -> 404.
        let resp = finding_detail(State(app.clone()), alice.clone(), Path(fid_b), eng_query(2)).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "détail d'un finding de B refusé à alice (404)");

        // (d) RUNRECORDS / ROE / RUNS / COVERAGE de B invisibles à alice.
        assert!(resp_json(runrecords(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await.as_array().unwrap().is_empty(), "runrecords de B invisibles");
        assert!(resp_json(roe(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await.as_array().unwrap().is_empty(), "roe de B invisibles");
        assert!(resp_json(runs_list(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await.as_array().unwrap().is_empty(), "runs de B invisibles");
        assert!(resp_json(coverage(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await.as_array().unwrap().is_empty(), "couverture de B invisible");

        // (e) LEDGER : alice n'obtient PAS le ledger de B — ni entrées, ni chemin (aucun repli/leak).
        let jl = resp_json(super::ledger(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await;
        assert!(jl["entries"].as_array().unwrap().is_empty(), "ledger de B : aucune entrée servie à alice");
        assert_eq!(jl["path"].as_str().unwrap(), "", "ledger de B : aucun chemin divulgué (pas de repli sur le ledger par défaut)");

        // (f) RAPPORT / ÉDITION / RUN : le prédicat de garde (engagement_visible) refuse tout acte de A sur B.
        assert!(!tenancy::engagement_visible(&app, &alice, 2), "alice ne voit pas l'engagement de B (gate rapport/CRUD)");
        assert!(tenancy::engagement_visible(&app, &bob, 2), "bob voit SON engagement");
        // run_create : alice ne peut cibler l'engagement de B (resolve -> Err, run refusé AVANT tout spawn).
        assert!(resolve_engagement(&app, &alice, Some(2)).is_err(), "alice ne peut lancer un run sur l'engagement de B");
        assert!(resolve_engagement(&app, &bob, Some(2)).is_ok(), "bob peut lancer un run sur SON engagement");
        // technique-selection / workflows (mutation par-engagement) : refus cross-tenant.
        let q2 = HashMap::from([("engagement".to_string(), "2".to_string())]);
        assert!(resolve_mutation_engagement_id(&app, &alice, &q2, &json!({})).is_err(), "alice ne peut poser une config par-engagement sur B");
        assert!(resolve_mutation_engagement_id(&app, &bob, &q2, &json!({})).is_ok(), "bob peut poser une config sur SON engagement");

        // (g) ÉDITION/ARCHIVE/SUPPRESSION cross-tenant via le handler -> 404 (jamais divulgué ni muté).
        let resp = engagements_update(State(app.clone()), conn_info(), alice.clone(), Path(2i64),
            Json(json!({"name": "pwned-by-A"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "alice ne peut PAS éditer l'engagement de B (404)");
        {  let n: String = app.db().query_row("SELECT name FROM engagement WHERE id=2", [], |r| r.get(0)).unwrap();
          assert_ne!(n, "pwned-by-A", "l'engagement de B N'A PAS été muté par A"); }

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY — sans grant = rien] ENTERPRISE ON. Un compte SANS aucun tenant_grant (carol) n'accède à
    /// RIEN : liste vide, résolution vers NO_ENGAGEMENT (zéro ligne), aucun engagement visible. Fail-closed
    /// deny-by-default (miroir du ROE). Le repli bootstrap (hash env) n'a pas non plus de grant.
    #[tokio::test]
    async fn enterprise_no_grant_sees_nothing() {
        let ledger = tmp_path("forge-test-tnc-nogrant");
        let ledger2 = tmp_path("forge-test-tnc-nogrant2");
        let (app, _alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // carol : compte activé mais AUCUN grant.
        { let db = app.db(); upsert_user(&db, "carol", "operator", &hash_pw("pw")).unwrap(); }
        let (ctok, _) = create_session(&app, uid_of(&app, "carol"));
        let carol = bearer_headers(&ctok);

        assert!(engagement_list_json(&app, &carol).is_empty(), "sans grant : aucune liste");
        assert_eq!(tenancy::view_engagement_id(&app, &carol, None), tenancy::NO_ENGAGEMENT, "sans grant : NO_ENGAGEMENT");
        assert_eq!(tenancy::view_engagement_id(&app, &carol, Some(1)), tenancy::NO_ENGAGEMENT, "sans grant : #1 non résolu");
        assert!(!tenancy::engagement_visible(&app, &carol, 1), "sans grant : #1 invisible");
        assert!(!tenancy::engagement_visible(&app, &carol, 2), "sans grant : #2 invisible");
        // requête anonyme (aucune session) : jamais aucun tenant accordé.
        assert!(tenancy::granted_tenants(&app, &HeaderMap::new()).is_empty(), "anonyme : aucun tenant accordé");
        let j = resp_json(findings(State(app.clone()), carol.clone(), eng_query(1)).await.into_response()).await;
        assert!(j["findings"].as_array().unwrap().is_empty(), "sans grant : aucun finding servi");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY — filtre central, unité] Sémantique exacte de tenancy::view_engagement_id / engagement_visible
    /// (l'ancre mutation-proof la plus directe : ces fonctions sont LE filtre). Enterprise ON.
    #[tokio::test]
    async fn tenancy_central_filter_semantics() {
        let ledger = tmp_path("forge-test-tnc-central");
        let ledger2 = tmp_path("forge-test-tnc-central2");
        let (app, alice, bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // visibilité stricte par appartenance tenant.
        assert!(tenancy::engagement_visible(&app, &alice, 1) && !tenancy::engagement_visible(&app, &alice, 2), "alice: A oui, B non");
        assert!(tenancy::engagement_visible(&app, &bob, 2) && !tenancy::engagement_visible(&app, &bob, 1), "bob: B oui, A non");
        // resolution explicite : id du tenant accordé -> id ; sinon NO_ENGAGEMENT.
        assert_eq!(tenancy::view_engagement_id(&app, &alice, Some(1)), 1);
        assert_eq!(tenancy::view_engagement_id(&app, &alice, Some(2)), tenancy::NO_ENGAGEMENT);
        // resolution par défaut (sans id) -> un engagement du tenant du caller (jamais NO_ENGAGEMENT s'il a un grant).
        assert_eq!(tenancy::view_engagement_id(&app, &alice, None), 1, "défaut alice -> son engagement");
        assert_eq!(tenancy::view_engagement_id(&app, &bob, None), 2, "défaut bob -> son engagement");
        // granted_tenants reflète les grants.
        assert!(tenancy::granted_tenants(&app, &alice).contains(&tenancy::DEFAULT_TENANT), "alice accède au tenant #1 (défaut)");
        assert!(tenancy::granted_tenants(&app, &bob).contains(&2) && !tenancy::granted_tenants(&app, &bob).contains(&1), "bob accède UNIQUEMENT à tenant 2");
        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [PER-ENGAGEMENT RBAC #14 — effective role, most-specific-wins, fail-closed] ENTERPRISE ON. Deux
    /// engagements (#1, #3) DANS LE MÊME tenant (1). alice est tenant_operator sur le tenant => operator sur
    /// LES DEUX par héritage. Un engagement_grant tenant_viewer sur #1 RÉTROGRADE alice à viewer sur #1
    /// SEULEMENT (most-specific-wins) : elle reste operator sur #3. Fail-closed : carol (aucun grant) n'a
    /// AUCUN rôle effectif. ⚠️ MUTATION-PROOF : si effective_engagement_role cessait de préférer l'override
    /// engagement, alice pourrait opérer sur #1 -> l'assert « viewer sur #1 » passe AU ROUGE.
    #[tokio::test]
    async fn per_engagement_rbac_effective_role_most_specific_wins() {
        let ledger = tmp_path("forge-test-eg-rbac");
        let ledger2 = tmp_path("forge-test-eg-rbac2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // 3e engagement DANS le tenant 1 (même tenant qu'alice).
        insert_test_engagement(&app, 3, &["a.example.com"], "grey", &ledger);
        set_engagement_tenant(&app, 3, 1);
        let uid_a = uid_of(&app, "alice");

        // (a) héritage tenant : alice (tenant_operator sur tenant 1) opère sur #1 ET #3.
        assert_eq!(tenancy::effective_engagement_role(&app, &alice, 1).as_deref(), Some("tenant_operator"), "alice hérite operator sur #1");
        assert_eq!(tenancy::effective_engagement_role(&app, &alice, 3).as_deref(), Some("tenant_operator"), "alice hérite operator sur #3");
        assert!(tenancy::can_operate_engagement(&app, &alice, 1) && tenancy::can_operate_engagement(&app, &alice, 3), "operator sur les deux (hérité)");
        assert!(!tenancy::can_admin_engagement(&app, &alice, 1), "tenant_operator n'est PAS admin engagement");

        // (b) override MOST-SPECIFIC : viewer sur #1 SEULEMENT.
        grant_engagement(&app, uid_a, 1, "tenant_viewer");
        assert_eq!(tenancy::effective_engagement_role(&app, &alice, 1).as_deref(), Some("tenant_viewer"), "override viewer sur #1 gagne");
        assert!(!tenancy::can_operate_engagement(&app, &alice, 1), "viewer-on-#1 : operate DENIED (fail-closed)");
        // #3 INCHANGÉ (toujours operator hérité) — la composition est par-engagement.
        assert_eq!(tenancy::effective_engagement_role(&app, &alice, 3).as_deref(), Some("tenant_operator"), "#3 reste operator");
        assert!(tenancy::can_operate_engagement(&app, &alice, 3), "operator-on-#3 : operate OK (operator sur A / viewer sur B)");

        // (c) override ADMIN sur #3 : alice devient tenant_admin sur #3 uniquement.
        grant_engagement(&app, uid_a, 3, "tenant_admin");
        assert!(tenancy::can_admin_engagement(&app, &alice, 3), "override admin sur #3");
        assert!(!tenancy::can_admin_engagement(&app, &alice, 1), "toujours pas admin sur #1");

        // (d) FAIL-CLOSED : carol (compte activé, AUCUN grant) n'a aucun rôle effectif -> ni operate ni admin.
        { let db = app.db(); upsert_user(&db, "carol", "operator", &hash_pw("pw")).unwrap(); }
        let (ctok, _) = create_session(&app, uid_of(&app, "carol"));
        let carol = bearer_headers(&ctok);
        assert!(tenancy::effective_engagement_role(&app, &carol, 1).is_none(), "carol : aucun rôle effectif (fail-closed)");
        assert!(!tenancy::can_operate_engagement(&app, &carol, 1) && !tenancy::can_operate_engagement(&app, &carol, 3), "carol : operate refusé partout");
        // requête anonyme (aucune session) : jamais aucun rôle effectif.
        assert!(tenancy::effective_engagement_role(&app, &HeaderMap::new(), 1).is_none(), "anonyme : aucun rôle effectif");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [PER-ENGAGEMENT RBAC #14 — handler wiring] ENTERPRISE ON. La mutation d'engagement (POST
    /// /api/engagements/:id, chemin edit=operator) est GATÉE par le rôle effectif par-engagement. alice
    /// (operator hérité) édite #1 -> OK ; après rétrogradation viewer sur #1 -> 403 engagement_operator_required,
    /// bien qu'elle VOIE toujours #1. Preuve du câblage fail-closed (pas seulement le helper).
    #[tokio::test]
    async fn per_engagement_rbac_edit_handler_gate() {
        let ledger = tmp_path("forge-test-eg-gate");
        let ledger2 = tmp_path("forge-test-eg-gate2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        let uid_a = uid_of(&app, "alice");

        // operator hérité : édition autorisée.
        let resp = engagements_update(State(app.clone()), conn_info(), alice.clone(), Path(1i64),
            Json(json!({"name": "renamed-by-operator"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "operator hérité : édition OK");

        // rétrogradation viewer sur #1 -> édition REFUSÉE (403), engagement toujours VISIBLE.
        grant_engagement(&app, uid_a, 1, "tenant_viewer");
        assert!(tenancy::engagement_visible(&app, &alice, 1), "viewer voit toujours #1");
        let resp = engagements_update(State(app.clone()), conn_info(), alice.clone(), Path(1i64),
            Json(json!({"name": "renamed-by-viewer"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer-on-#1 : édition refusée (403, fail-closed)");
        {  let n: String = app.db().query_row("SELECT name FROM engagement WHERE id=1", [], |r| r.get(0)).unwrap();
          assert_ne!(n, "renamed-by-viewer", "l'engagement n'a PAS été muté par le viewer"); }

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY — migration zéro-perte] ensure_default_tenant sur une base au SCHEMA courant : crée le
    /// tenant #1, rattache TOUS les engagements existants au tenant #1, et sème un grant tenant #1 pour
    /// CHAQUE utilisateur existant (rôle dérivé du RBAC). Idempotent (ne réécrit pas si un tenant existe).
    #[test]
    fn ensure_default_tenant_seeds_and_backfills() {
        // `conn()` rend une garde fraîche sur la MÊME connexion (le seeder prend désormais un `&Store` ;
        // les ops rusqlite directes + migrate gardent leur `&Connection` via le deref de la garde).
        let dbm = Mutex::new(Connection::open_in_memory().expect("mem db"));
        let conn = || dbm.lock().unwrap_or_else(|e| e.into_inner());
        conn().execute_batch(SCHEMA).expect("schema");
        migrate(&conn());
        // deux engagements + deux users AVANT toute provision tenant.
        conn().execute("INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path) VALUES(1,'e1','active','grey','{}','')", []).unwrap();
        conn().execute("INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path) VALUES(7,'e7','active','grey','{}','')", []).unwrap();
        conn().execute("INSERT INTO users(login,role,pass_hash,disabled,created) VALUES('root','admin','h',0,'')", []).unwrap();
        conn().execute("INSERT INTO users(login,role,pass_hash,disabled,created) VALUES('joe','viewer','h',0,'')", []).unwrap();

        ensure_default_tenant(&crate::store::Store::sqlite(conn()));
        // tenant #1 créé.
        let tcount: i64 = conn().query_row("SELECT COUNT(*) FROM tenant WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(tcount, 1, "tenant #1 (défaut) créé");
        // TOUS les engagements rattachés au tenant #1.
        let bad: i64 = conn().query_row("SELECT COUNT(*) FROM engagement WHERE tenant_id<>1", [], |r| r.get(0)).unwrap();
        assert_eq!(bad, 0, "tous les engagements existants -> tenant #1");
        // grants rétro-compat : chaque user existant accède au tenant #1, rôle dérivé du RBAC.
        let root_role: String = conn().query_row("SELECT g.role FROM tenant_grant g JOIN users u ON u.id=g.user_id WHERE u.login='root' AND g.tenant_id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(root_role, "tenant_admin", "admin -> tenant_admin");
        let joe_role: String = conn().query_row("SELECT g.role FROM tenant_grant g JOIN users u ON u.id=g.user_id WHERE u.login='joe' AND g.tenant_id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(joe_role, "tenant_viewer", "viewer -> tenant_viewer");

        // IDEMPOTENT : un 2e appel ne recrée rien ni n'écrase (renomme le tenant #1 -> doit rester).
        conn().execute("UPDATE tenant SET name='custom' WHERE id=1", []).unwrap();
        ensure_default_tenant(&crate::store::Store::sqlite(conn()));
        let n: String = conn().query_row("SELECT name FROM tenant WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(n, "custom", "ensure_default_tenant idempotent (n'écrase pas un provisioning existant)");
    }

    // =====================================================================================
    // ENTERPRISE — SUPER-ADMIN + TENANT CRUD + PER-TENANT LEDGER (tenancy.rs). Fail-closed, audited,
    // separable. Non-disablable super-admin (mirror Plume), audited cross-tenant READ, platform-admin
    // gated tenant CRUD, last-tenant/last-admin guards, tenant-scoped ledger paths.
    // =====================================================================================

    /// Provisionne un compte `admin` + une session, renvoie ses headers bearer.
    fn admin_session(app: &App, login: &str) -> HeaderMap {
        { let db = app.db(); upsert_user(&db, login, "admin", &hash_pw("pw")).unwrap(); }
        let (tok, _) = create_session(app, uid_of(app, login));
        bearer_headers(&tok)
    }

    /// Désigne le(s) super-admin(s) via la clé de PROVISIONING par-DB `enterprise.superadmin` (isolée par
    /// test, pas d'ENV global). N'est PAS une route UI normale (aucune API n'écrit une clé settings arbitraire).
    fn designate_superadmin(app: &App, csv: &str) {
        let db = app.db();
        settings_set(&db, "enterprise.superadmin", csv).unwrap();
    }

    /// [SUPER-ADMIN — désignation fail-closed, provisioning-only] Sans désignation, PERSONNE n'est
    /// super-admin (même une session admin valide). La désignation (clé de provisioning) fait d'un admin
    /// un super-admin ; un login non désigné, un opérateur désigné, ou un anonyme ne le sont JAMAIS.
    #[test]
    fn superadmin_designation_is_fail_closed() {
        let ledger = tmp_path("forge-test-sa-desig");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        let root = admin_session(&app, "root");
        // aucune désignation => fail-closed (personne).
        assert!(!tenancy::is_superadmin(&app, &root), "aucune désignation => personne n'est super-admin");
        assert!(!tenancy::is_superadmin_login(&app, "root"), "root non désigné");
        // désignation via la clé de provisioning.
        designate_superadmin(&app, "root");
        assert!(tenancy::is_superadmin_login(&app, "root"), "root désigné");
        assert!(tenancy::is_superadmin(&app, &root), "root (session admin) est super-admin");
        // un AUTRE admin non désigné n'est pas super-admin.
        let mallory = admin_session(&app, "mallory");
        assert!(!tenancy::is_superadmin(&app, &mallory), "mallory non désignée => pas super-admin");
        // un login désigné mais NON admin (operator) n'est pas super-admin (session admin obligatoire).
        { let db = app.db(); upsert_user(&db, "opsa", "operator", &hash_pw("pw")).unwrap(); }
        designate_superadmin(&app, "root, opsa");
        let (otok, _) = create_session(&app, uid_of(&app, "opsa"));
        assert!(!tenancy::is_superadmin(&app, &bearer_headers(&otok)), "opérateur désigné => PAS super-admin (admin requis)");
        // anonyme (aucune session) jamais super-admin.
        assert!(!tenancy::is_superadmin(&app, &HeaderMap::new()), "anonyme jamais super-admin");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [SUPER-ADMIN — cross-tenant READ audité] Un super-admin (sans grant natif) LIT les données d'un
    /// autre tenant ; chaque accès émet `console.superadmin.access` (tenant + quoi). Un admin NON super
    /// (grant natif ailleurs) ne traverse PAS. ⚠️ MUTATION-PROOF : retirer le bypass super-admin de
    /// view_engagement_id fait échouer la lecture cross-tenant ; retirer l'audit fait échouer l'assert ledger.
    #[tokio::test]
    async fn superadmin_cross_tenant_read_is_ledgered() {
        let ledger = tmp_path("forge-test-sa-read");
        let ledger2 = tmp_path("forge-test-sa-read2");
        let (app, _alice, _bob, _fa, fid_b) = seed_two_tenants(&ledger, &ledger2);
        // root : admin, AUCUN grant natif, super-admin désigné.
        let root = admin_session(&app, "root");
        designate_superadmin(&app, "root");
        assert!(tenancy::is_superadmin(&app, &root), "root super-admin");
        // résolution cross-tenant explicite (tenant B) + lecture des findings de B.
        assert_eq!(tenancy::view_engagement_id(&app, &root, Some(2)), 2, "super-admin traverse vers l'engagement de B");
        let j = resp_json(findings(State(app.clone()), root.clone(), eng_query(2)).await.into_response()).await;
        let titles: Vec<String> = j["findings"].as_array().unwrap().iter().map(|f| f["title"].as_str().unwrap().to_string()).collect();
        assert!(titles.contains(&"fb".to_string()), "super-admin voit les findings du tenant B");
        let resp = finding_detail(State(app.clone()), root.clone(), Path(fid_b), eng_query(2)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "détail cross-tenant servi au super-admin");
        // AUDIT : au moins une entrée console.superadmin.access (tenant=2, actor=root).
        let hit = read_ledger_lines(&ledger).iter().any(|e| e["kind"] == "console.superadmin.access"
            && e["detail"]["tenant"] == json!(2) && e["detail"]["actor"] == json!("root"));
        assert!(hit, "cross-tenant read super-admin ledgerisé (console.superadmin.access, tenant=2)");

        // CONTRÔLE : un admin NON super-admin (grant natif tenant 1) ne traverse PAS vers B.
        let admin2 = admin_session(&app, "admin2");
        grant_tenant(&app, uid_of(&app, "admin2"), 1, "tenant_admin");
        assert!(!tenancy::is_superadmin(&app, &admin2), "admin2 non désigné => pas super-admin");
        assert_eq!(tenancy::view_engagement_id(&app, &admin2, Some(2)), tenancy::NO_ENGAGEMENT, "admin non-super ne traverse pas vers B");
        let j = resp_json(findings(State(app.clone()), admin2.clone(), eng_query(2)).await.into_response()).await;
        assert!(j["findings"].as_array().unwrap().is_empty(), "admin non-super ne voit AUCUN finding de B");
        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY CONTEXT — flag OFF = single implicit tenant, byte-identique] Le probe SPA GET /api/tenancy
    /// renvoie EXACTEMENT `{"enabled": false}` en community : c'est CE signal qui fait que le SPA ne rend
    /// AUCUNE surface tenant (ni sélecteur, ni vue #tenants, ni lien nav). La liste d'engagements n'expose
    /// alors PAS `tenant_id` (payload historique) et un user sans grant voit TOUS les engagements
    /// (mono-tenant, no-op) — un flux représentatif reste servi sans aucun filtrage tenant visible.
    #[tokio::test]
    async fn tenancy_context_flag_off_is_single_tenant() {
        let ledger = tmp_path("forge-test-tnc-ctx-off");
        let ledger2 = tmp_path("forge-test-tnc-ctx-off2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // community : on retire le flag semé par seed_two_tenants.
        { let db = app.db(); db.execute("DELETE FROM settings WHERE key='enterprise.tenancy'", []).unwrap(); }
        assert!(!tenancy::enabled(&app), "flag OFF => community");

        // /api/tenancy => {"enabled": false} STRICT — rien d'autre (pas de tenants, pas de super-admin).
        let ctx = resp_json(tenancy::tenancy_context(State(app.clone()), alice.clone()).await).await;
        assert_eq!(ctx, json!({"enabled": false}), "community : contexte tenant fermé (le SPA ne montre rien)");

        // Flux représentatif : liste d'engagements servie SANS `tenant_id` (byte-identique), un user sans
        // grant voit les DEUX engagements (visibilité universelle, no-op).
        let engs = engagement_list_json(&app, &alice);
        assert_eq!(engs.len(), 2, "community : les deux engagements listés (no filtre)");
        assert!(engs.iter().all(|e| e.get("tenant_id").is_none()), "community : aucun `tenant_id` exposé (byte-identique)");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANCY CONTEXT — flag ON = enforcement actif] Le probe SPA reflète le modèle multi-tenant : un
    /// user normal (alice, grant tenant 1) reçoit `enabled=true`, `is_platform_admin=false` et UNIQUEMENT
    /// son tenant ; un SUPER-ADMIN reçoit `is_platform_admin=true` et TOUS les tenants. La liste
    /// d'engagements expose alors `tenant_id` (hiérarchie tenant→engagement) et le filtre de grant reste
    /// fail-closed (alice ne liste QUE son engagement).
    /// ⚠️ MUTATION-PROOF : élargir `accessible_tenants` (renvoyer TOUS les tenants à un non-super-admin)
    /// fait passer l'assert « alice ne voit QUE le tenant 1 » AU ROUGE.
    #[tokio::test]
    async fn tenancy_context_flag_on_scopes_tenants_and_superadmin() {
        let ledger = tmp_path("forge-test-tnc-ctx-on");
        let ledger2 = tmp_path("forge-test-tnc-ctx-on2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        assert!(tenancy::enabled(&app), "flag ON => enterprise");

        // (a) user normal : enabled=true, PAS platform-admin, tenants = [1] uniquement (fail-closed).
        let ctx = resp_json(tenancy::tenancy_context(State(app.clone()), alice.clone()).await).await;
        assert_eq!(ctx["enabled"], json!(true), "flag ON => enabled");
        assert_eq!(ctx["is_platform_admin"], json!(false), "alice (operator) n'est pas platform-admin");
        assert_eq!(ctx["is_superadmin"], json!(false), "alice n'est pas super-admin");
        let tids: Vec<i64> = ctx["tenants"].as_array().unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect();
        assert_eq!(tids, vec![1], "alice ne voit QUE le tenant de son grant (fail-closed)");

        // (b) grant filter actif : liste d'engagements restreinte + `tenant_id` exposé (hiérarchie).
        let engs = engagement_list_json(&app, &alice);
        let ids: Vec<i64> = engs.iter().map(|e| e["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, vec![1], "alice ne liste QUE l'engagement de son tenant");
        assert_eq!(engs[0]["tenant_id"], json!(1), "flag ON => `tenant_id` exposé");

        // (c) SUPER-ADMIN : platform-admin + TOUS les tenants dans le contexte (surface #tenants + switch).
        let root = admin_session(&app, "root");
        designate_superadmin(&app, "root");
        let ctx = resp_json(tenancy::tenancy_context(State(app.clone()), root.clone()).await).await;
        assert_eq!(ctx["is_superadmin"], json!(true), "root désigné => super-admin");
        assert_eq!(ctx["is_platform_admin"], json!(true), "super-admin => platform-admin");
        let mut tids: Vec<i64> = ctx["tenants"].as_array().unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect();
        tids.sort_unstable();
        assert_eq!(tids, vec![1, 2], "super-admin voit TOUS les tenants");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [TENANT_ADMIN de A -> 403 sur B] Un tenant_admin (rôle de GRANT) de A, non-admin console, ne voit
    /// RIEN de B (data) et ne peut PAS administrer les tenants (403) — ni B, ni le sien. « A normal
    /// tenant_admin can NEVER cross tenants. »
    #[tokio::test]
    async fn tenant_admin_of_a_cannot_cross_to_b() {
        let ledger = tmp_path("forge-test-ta-cross");
        let ledger2 = tmp_path("forge-test-ta-cross2");
        let (app, alice, _bob, _fa, _fb) = seed_two_tenants(&ledger, &ledger2);
        // alice : grant tenant_admin sur A, mais RBAC operator (pas admin console). uid_of AVANT le guard
        // DB (uid_of reverrouille le mutex — jamais en tenant `app.db()`).
        let ua = uid_of(&app, "alice");
        { let db = app.db(); db.execute("UPDATE tenant_grant SET role='tenant_admin' WHERE user_id=? AND tenant_id=1", [ua]).unwrap(); }
        // DATA : rien de B.
        assert_eq!(tenancy::view_engagement_id(&app, &alice, Some(2)), tenancy::NO_ENGAGEMENT, "tenant_admin de A ne traverse pas vers B");
        let j = resp_json(findings(State(app.clone()), alice.clone(), eng_query(2)).await.into_response()).await;
        assert!(j["findings"].as_array().unwrap().is_empty(), "aucun finding de B");
        // MANAGEMENT : pas platform-admin => 403 sur le tenant B ET à la création.
        let resp = tenancy::tenant_grant_add(State(app.clone()), alice.clone(), Path(2i64), Json(json!({"login":"alice","role":"tenant_admin"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "tenant_admin (grant) de A -> 403 sur la gestion de B");
        let resp = tenancy::tenants_create(State(app.clone()), alice.clone(), Json(json!({"name":"AlicesTenant"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "un non-admin console ne crée pas de tenant (403)");
        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [SUPER-ADMIN — NON-DISABLABLE] Un super-admin désigné ne peut être désactivé / supprimé / rétrogradé
    /// sous admin (guard + handlers CRUD câblés). Deux admins présents => ce n'est PAS le garde-fou
    /// « dernier admin » qui joue, mais bien le marqueur super-admin (fail-closed).
    #[tokio::test]
    async fn superadmin_account_is_non_disablable() {
        let ledger = tmp_path("forge-test-sa-nondis");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        let _root = admin_session(&app, "root");
        let _backup = admin_session(&app, "backup"); // 2e admin => le garde-fou dernier-admin ne joue pas
        designate_superadmin(&app, "root");
        // guard unitaire.
        assert!(tenancy::guard_superadmin_user_mutation(&app, "root", true, None, false).is_err(), "désactivation refusée");
        assert!(tenancy::guard_superadmin_user_mutation(&app, "root", false, None, true).is_err(), "suppression refusée");
        assert!(tenancy::guard_superadmin_user_mutation(&app, "root", false, Some("viewer"), false).is_err(), "rétrogradation refusée");
        assert!(tenancy::guard_superadmin_user_mutation(&app, "root", false, Some("admin"), false).is_ok(), "rester admin OK");
        assert!(tenancy::guard_superadmin_user_mutation(&app, "backup", true, None, true).is_ok(), "login ordinaire : guard no-op");
        // via les handlers CRUD réels (câblés) -> 409 avec un message super-admin.
        let e = admin_update_user(&app, "backup", "root", &json!({"disabled": true})).unwrap_err();
        assert_eq!(e.0, StatusCode::CONFLICT); assert!(e.1.contains("super-admin"), "message super-admin: {}", e.1);
        let e = admin_delete_user(&app, "backup", "root").unwrap_err();
        assert_eq!(e.0, StatusCode::CONFLICT); assert!(e.1.contains("super-admin"), "message super-admin: {}", e.1);
        // root reste admin activé (non muté).
        {  let (role, dis): (String, i64) = app.db().query_row("SELECT role, disabled FROM users WHERE login='root'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
          assert_eq!(role, "admin", "root reste admin"); assert_eq!(dis, 0, "root reste activé"); }
        let _ = std::fs::remove_file(&ledger);
    }

    /// [TENANT CRUD — gated + ledgerisé] Community (flag OFF) : la surface tenant est FERMÉE (403
    /// enterprise_disabled) => byte-identique. Enterprise ON : create/rename/grant/revoke réservés à un
    /// platform-admin (operator -> 403), chacun ledgerisé `console.tenant.*`.
    #[tokio::test]
    async fn tenant_crud_gated_and_ledgered() {
        let ledger = tmp_path("forge-test-tenant-crud");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let store = app.store(); ensure_default_tenant(&store); }
        let admin = admin_session(&app, "adm");
        let opr = { { let db = app.db(); upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap(); } let (t,_) = create_session(&app, uid_of(&app, "opr")); bearer_headers(&t) };
        // community : flag OFF => 403 enterprise_disabled (aucune surface tenant).
        let resp = tenancy::tenants_create(State(app.clone()), admin.clone(), Json(json!({"name":"Acme"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "flag OFF => 403 enterprise_disabled");
        enable_enterprise_tenancy(&app);
        // operator => 403 ; admin => 200.
        let resp = tenancy::tenants_create(State(app.clone()), opr.clone(), Json(json!({"name":"Acme"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "operator (non platform-admin) refusé");
        let resp = tenancy::tenants_create(State(app.clone()), admin.clone(), Json(json!({"name":"Acme Corp"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "admin crée un tenant");
        let tid = resp_json(resp).await["tenant"]["id"].as_i64().unwrap();
        let resp = tenancy::tenants_update(State(app.clone()), admin.clone(), Path(tid), Json(json!({"name":"Acme Renamed"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "rename ok");
        { let db = app.db(); upsert_user(&db, "carol", "viewer", &hash_pw("pw")).unwrap(); }
        let resp = tenancy::tenant_grant_add(State(app.clone()), admin.clone(), Path(tid), Json(json!({"login":"carol","role":"tenant_viewer"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "grant add ok");
        let resp = tenancy::tenant_grant_add(State(app.clone()), opr.clone(), Path(tid), Json(json!({"login":"carol","role":"tenant_admin"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "grant add par operator refusé");
        let resp = tenancy::tenant_grant_remove(State(app.clone()), admin.clone(), Path((tid, "carol".to_string()))).await;
        assert_eq!(resp.status(), StatusCode::OK, "grant remove ok");
        // LEDGER : chaque mutation console.tenant.*.
        let kinds: Vec<String> = read_ledger_lines(&ledger).iter().filter_map(|e| e["kind"].as_str().map(String::from)).collect();
        for k in ["console.tenant.create", "console.tenant.rename", "console.tenant.grant", "console.tenant.revoke"] {
            assert!(kinds.iter().any(|x| x == k), "{k} ledgerisé");
        }
        let _ = std::fs::remove_file(&ledger);
    }

    /// [TENANT — garde-fous fail-closed] Impossible d'archiver le DERNIER tenant actif ; impossible de
    /// retirer le DERNIER grant tenant_admin d'un tenant (son dernier admin).
    #[tokio::test]
    async fn tenant_last_active_and_last_admin_protections() {
        let ledger = tmp_path("forge-test-tenant-guards");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let store = app.store(); ensure_default_tenant(&store); }
        enable_enterprise_tenancy(&app);
        let admin = admin_session(&app, "adm");
        let tid2 = resp_json(tenancy::tenants_create(State(app.clone()), admin.clone(), Json(json!({"name":"Second"}))).await).await["tenant"]["id"].as_i64().unwrap();
        // archive #1 (reste #2 actif) => OK.
        let resp = tenancy::tenants_update(State(app.clone()), admin.clone(), Path(1i64), Json(json!({"status":"archived"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "archivage OK tant qu'un tenant reste actif");
        // #2 seul actif : archivage REFUSÉ.
        let resp = tenancy::tenants_update(State(app.clone()), admin.clone(), Path(tid2), Json(json!({"status":"archived"}))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "dernier tenant actif : archivage refusé");
        // dernier tenant_admin de #2 (adm, auto-grant à la création) : retrait REFUSÉ.
        let resp = tenancy::tenant_grant_remove(State(app.clone()), admin.clone(), Path((tid2, "adm".to_string()))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "dernier admin du tenant : retrait refusé");
        // ajouter un 2e tenant_admin -> le retrait du 1er devient OK.
        { let db = app.db(); upsert_user(&db, "dave", "operator", &hash_pw("pw")).unwrap(); }
        let resp = tenancy::tenant_grant_add(State(app.clone()), admin.clone(), Path(tid2), Json(json!({"login":"dave","role":"tenant_admin"}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "2e admin ajouté");
        let resp = tenancy::tenant_grant_remove(State(app.clone()), admin.clone(), Path((tid2, "adm".to_string()))).await;
        assert_eq!(resp.status(), StatusCode::OK, "retrait OK dès qu'un 2e admin existe");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [PER-TENANT LEDGER — unité] Community (flag OFF) => None (chemin plat, byte-identique). Enterprise
    /// ON => `tenant-<tid>/engagement-<eid>.jsonl` (groupé par tenant, cross-platform via PathBuf). Deux
    /// tenants distincts => sous-dossiers distincts (isolation). La signature Ed25519 par-ledger est inchangée.
    #[test]
    fn per_tenant_ledger_path_is_scoped_and_community_flat() {
        let ledger = tmp_path("forge-test-ledger-scope");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        let base = std::path::Path::new(&std::env::temp_dir()).join("forge").join("engagement.jsonl").to_string_lossy().into_owned();
        // community => None.
        assert!(tenancy::scoped_engagement_ledger_path(&app, &base, 7, 3).is_none(), "community => pas de scoping (chemin plat)");
        enable_enterprise_tenancy(&app);
        let p = tenancy::scoped_engagement_ledger_path(&app, &base, 7, 3).expect("scoped");
        let expect = std::path::Path::new(&base).parent().unwrap().join("tenant-3").join("engagement-7.jsonl").to_string_lossy().into_owned();
        assert_eq!(p, expect, "ledger groupé par tenant (tenant-3/engagement-7.jsonl)");
        // même tenant => même sous-dossier ; tenant différent => dossier différent.
        assert!(tenancy::scoped_engagement_ledger_path(&app, &base, 8, 3).unwrap().contains("tenant-3"), "même tenant, même sous-dossier");
        let p3 = tenancy::scoped_engagement_ledger_path(&app, &base, 9, 4).unwrap();
        assert!(p3.contains("tenant-4") && !p3.contains("tenant-3"), "tenant différent => dossier différent");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [PER-TENANT LEDGER — bout-en-bout] Un engagement créé en mode enterprise dans le tenant 5 reçoit un
    /// ledger DÉDIÉ groupé sous `tenant-5/`, et sa genèse `console.engagement.create` y est écrite (le
    /// fichier existe réellement). Prouve le câblage derive_engagement_ledger_path -> tenancy.
    #[tokio::test]
    async fn engagement_create_writes_tenant_scoped_ledger() {
        let dir = tmp_path("forge-test-eng-tenant-ledger");
        std::fs::create_dir_all(&dir).unwrap();
        let ledger = format!("{dir}/engagement.jsonl");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let store = app.store(); ensure_default_tenant(&store); }
        // opérateur granté sur un tenant 5. upsert PUIS (guard relâché) uid_of PUIS insert grant — uid_of
        // reverrouille le mutex DB, ne jamais l'appeler en tenant `app.db()`.
        { let db = app.db();
          upsert_user(&db, "op5", "operator", &hash_pw("pw")).unwrap();
          db.execute("INSERT INTO tenant(id,name,status,created,updated) VALUES(5,'T5','active',datetime('now'),datetime('now'))", []).unwrap();
        }
        let uid5 = uid_of(&app, "op5");
        { let db = app.db(); db.execute("INSERT INTO tenant_grant(user_id,tenant_id,role,created) VALUES(?,5,'tenant_operator',datetime('now'))", [uid5]).unwrap(); }
        enable_enterprise_tenancy(&app);
        let (t,_) = create_session(&app, uid_of(&app, "op5"));
        let opr = bearer_headers(&t);
        let resp = engagements_create(State(app.clone()), conn_info(), opr.clone(),
            Json(json!({"name":"Eng T5","scope_json":{"in_scope":["a.example.com"]},"tenant_id":5}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "création engagement dans tenant 5");
        let id = resp_json(resp).await["engagement"]["id"].as_i64().unwrap();
        let lp: String = { let db = app.db(); db.query_row("SELECT ledger_path FROM engagement WHERE id=?", [id], |r| r.get(0)).unwrap() };
        let want = std::path::Path::new(&dir).join("tenant-5").join(format!("engagement-{id}.jsonl")).to_string_lossy().into_owned();
        assert_eq!(lp, want, "ledger scoppé tenant-5");
        assert!(std::path::Path::new(&lp).exists(), "fichier ledger tenant-scopé créé sur disque");
        assert!(read_ledger_lines(&lp).iter().any(|e| e["kind"] == "console.engagement.create"), "genèse écrite dans le ledger du tenant");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [ENGAGEMENT — CRUD gouverné + ledgerisé] Création/édition = OPÉRATEUR (viewer -> 403) ; archive/
    /// suppression = ADMIN (opérateur -> 403). Chaque mutation est journalisée `console.engagement.*`.
    #[tokio::test]
    async fn engagement_crud_role_gated_and_ledgered() {
        let ledger = tmp_path("forge-test-eng-crud");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        {
            let db = app.db();
            upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap();
            upsert_user(&db, "adm", "admin", &hash_pw("pw")).unwrap();
        }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger); // défaut #1 actif
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));
        let (atok, _) = create_session(&app, uid_of(&app, "adm"));

        // création sans session opérateur -> 403 (fail-closed).
        let resp = engagements_create(State(app.clone()), conn_info(), HeaderMap::new(),
            Json(json!({"name": "X", "scope_json": {"in_scope": ["x.example.com"]}}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "création sans opérateur refusée");

        // création par un OPÉRATEUR -> 200 + nouvel engagement (id >= 2) + ledger create.
        let resp = engagements_create(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(json!({"name": "Client Q3", "mode": "grey", "scope_json": {"in_scope": ["c.example.com"], "out_scope": []}}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "opérateur autorisé à créer");
        let j = resp_json(resp).await;
        let new_id = j["engagement"]["id"].as_i64().unwrap();
        assert!(new_id >= 2, "nouvel engagement id >= 2");
        assert!(read_ledger_lines(&ledger).iter().any(|e| e["kind"] == "console.engagement.create" && e["detail"]["engagement_id"] == new_id),
            "création ledgerisée dans le ledger console");

        // édition (rename) par un OPÉRATEUR -> 200.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&otok), Path(new_id),
            Json(json!({"name": "Renamed"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "opérateur autorisé à éditer");

        // archive par un OPÉRATEUR -> 403 (réservé admin).
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&otok), Path(new_id),
            Json(json!({"status": "archived"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "archive réservée admin");

        // archive par un ADMIN -> 200 (il reste #1 actif, donc pas le dernier) + ledger archive.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&atok), Path(new_id),
            Json(json!({"status": "archived"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "admin autorisé à archiver");
        assert!(read_ledger_lines(&ledger).iter().any(|e| e["kind"] == "console.engagement.archive"), "archive ledgerisée");

        // suppression par un OPÉRATEUR -> 403 (réservé admin).
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&otok), Path(new_id),
            Json(json!({"delete": true}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "suppression réservée admin");

        // suppression par un ADMIN (engagement #new_id, archivé, pas #1, pas le dernier actif) -> 200 + ledger.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&atok), Path(new_id),
            Json(json!({"delete": true}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "admin autorisé à supprimer");
        assert!(read_ledger_lines(&ledger).iter().any(|e| e["kind"] == "console.engagement.delete"), "suppression ledgerisée");
        assert!(app.db().query_row("SELECT 1 FROM engagement WHERE id=?", [new_id], |_| Ok(())).is_err(), "engagement supprimé de la base");

        let _ = std::fs::remove_file(&ledger);
    }

    /// [ENGAGEMENT — dernier actif protégé] On ne peut NI archiver NI supprimer le DERNIER engagement
    /// actif (fail-closed : il faut toujours un espace de travail actif). #1 (défaut) n'est jamais
    /// supprimable non plus.
    #[tokio::test]
    async fn last_active_engagement_archive_blocked() {
        let ledger = tmp_path("forge-test-eng-last");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let db = app.db(); upsert_user(&db, "adm", "admin", &hash_pw("pw")).unwrap(); }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger); // UNIQUE engagement actif
        let (atok, _) = create_session(&app, uid_of(&app, "adm"));

        // archiver le dernier engagement actif -> 409.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&atok), Path(1i64),
            Json(json!({"status": "archived"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "dernier engagement actif : archivage bloqué");
        {  let st: String = app.db().query_row("SELECT status FROM engagement WHERE id=1", [], |r| r.get(0)).unwrap();
          assert_eq!(st, "active", "l'engagement reste actif (mutation refusée)"); }

        // supprimer #1 (défaut + dernier actif) -> 409.
        let resp = engagements_update(State(app.clone()), conn_info(), bearer_headers(&atok), Path(1i64),
            Json(json!({"delete": true}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "#1 par défaut non supprimable");

        let _ = std::fs::remove_file(&ledger);
    }

    /// [ENGAGEMENT — sélection de techniques PAR-ENGAGEMENT] La sélection (profil + toggles) posée pour
    /// l'engagement A n'affecte PAS B : chaque engagement round-trip sa propre sélection isolée.
    /// L'engagement #1 utilise la clé LEGACY `technique_selection` (rétro-compat), les autres la clé
    /// suffixée `technique_selection:<id>`.
    #[tokio::test]
    async fn per_engagement_technique_selection_round_trips() {
        let ledger = tmp_path("forge-test-eng-tech");
        let ledger2 = tmp_path("forge-test-eng-tech2");
        let app = test_app_scoped(&ledger, vec!["a.example.com".into()]);
        { let db = app.db(); upsert_user(&db, "opr", "operator", &hash_pw("pw")).unwrap(); }
        insert_test_engagement(&app, 1, &["a.example.com"], "grey", &ledger);
        insert_test_engagement(&app, 2, &["b.example.com"], "grey", &ledger2);
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));

        // #1 -> profil pentest (+ toggle SQLi=false) ; #2 -> profil custom (+ rce.probe=true).
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(1), bearer_headers(&otok),
            Json(json!({"profile": "pentest", "categories": {"SQLi": false}, "techniques": {}}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "sélection #1 posée");
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(2), bearer_headers(&otok),
            Json(json!({"profile": "custom", "categories": {}, "techniques": {"rce.probe": true}}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK, "sélection #2 posée");

        // round-trip : chaque engagement relit SA sélection (isolation).
        assert_eq!(technique_selection_value_for(&app, 1)["profile"], "pentest", "#1 -> pentest");
        assert_eq!(technique_selection_value_for(&app, 2)["profile"], "custom", "#2 -> custom");
        assert_eq!(technique_selection_value_for(&app, 1)["categories"]["SQLi"], json!(false), "toggle #1 isolé");
        assert_eq!(technique_selection_value_for(&app, 2)["techniques"]["rce.probe"], json!(true), "toggle #2 isolé");

        // clés de stockage : legacy pour #1, suffixée pour #2.
        {
            let db = app.db();
            assert!(settings_get(&db, "technique_selection").is_some(), "engagement #1 -> clé legacy");
            assert!(settings_get(&db, "technique_selection:2").is_some(), "engagement #2 -> clé suffixée");
        }

        // un id EXPLICITE inexistant est refusé (fail-closed : pas d'écriture pour un engagement fantôme).
        let resp = technique_selection_set(State(app.clone()), conn_info(), eng_query(99), bearer_headers(&otok),
            Json(json!({"profile": "pentest"}))).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "engagement inexistant -> 400");

        let _ = std::fs::remove_file(&ledger);
        let _ = std::fs::remove_file(&ledger2);
    }

    /// [parité lecture] parse_plan_verdicts : extrait verdict + kind→target des lignes du moteur
    /// (mode propose), ignore les lignes sans verdict, tolère `->` et `→`. Couvre le format inline
    /// (CLI `forge plan` : `[VERDICT] kind → target`).
    #[test]
    fn plan_verdicts_extracted_from_engine_output() {
        let stdout = "\
[plan] access_control.idor -> api.example.com : DRY_RUN (non armé)
[plan] exploit.rce -> api.example.com : VETO (capacité non autorisée)
ligne sans verdict ignorée
[plan] recon.http → web.example.com : FIRE
";
        let v = parse_plan_verdicts(stdout);
        assert_eq!(v.len(), 3, "3 lignes avec verdict reconnu (la 3e ignorée)");
        assert_eq!(v[0]["verdict"], "DRY_RUN");
        assert_eq!(v[0]["kind"], "access_control.idor");
        assert_eq!(v[0]["target"], "api.example.com");
        assert_eq!(v[1]["verdict"], "VETO");
        assert_eq!(v[2]["verdict"], "FIRE");
        assert_eq!(v[2]["kind"], "recon.http", "séparateur unicode → géré");
    }

    /// [parité lecture] parse_plan_verdicts sur la sortie RÉELLE du moteur (`report.py`) : les
    /// lignes d'action vivent sous un en-tête de section et ne portent PAS le mot-clé du verdict ;
    /// les compteurs de synthèse en gras (`- **Tirées (FIRE)** : 0`) ne doivent JAMAIS produire de
    /// faux verdicts. Régression du dry-plan console (gouvernance : 1 action réelle, pas 3 fantômes).
    #[test]
    fn plan_verdicts_from_real_report_section_aware() {
        let stdout = "\
Tirées=0  Simulées=1  Refusées=0  Erreurs=0  Findings=0
## Couverture & transparence (ROE / anti-masquage)

- **Tirées (FIRE)** : 0
- **Simulées (DRY_RUN)** : 1
- **Refusées (VETO — hors scope / capacité non autorisée)** : 0
- **Erreurs / skips** : 0

**Simulées (non armé/approuvé)**
- `recon.httpx` → `guatx.com` : engagement non armé (dry-run)

**Refusées (VETO)**
- `exploit.rce` → `evil.example` : capacité non autorisée

**Classes jamais tentées**
- `guatx.com` : access_control, auth, ato
";
        let v = parse_plan_verdicts(stdout);
        assert_eq!(v.len(), 2, "2 actions réelles (les compteurs en gras et la ligne 'classes' ignorés)");
        assert_eq!(v[0]["verdict"], "DRY_RUN", "verdict tiré de la section, pas du compteur");
        assert_eq!(v[0]["kind"], "recon.httpx", "backticks retirés");
        assert_eq!(v[0]["target"], "guatx.com", "raisons `: …` coupées de la cible");
        assert_eq!(v[1]["verdict"], "VETO");
        assert_eq!(v[1]["kind"], "exploit.rce");
        assert_eq!(v[1]["target"], "evil.example");
    }

    /// [parité lecture] render_run_report_md : miroir markdown de build_report — synthèse par
    /// sévérité (findings du run), findings détaillés, transparence ROE (compteurs run_job + verdicts).
    #[test]
    fn run_report_markdown_mirrors_build_report() {
        let path = tmp_path("forge-test-report");
        let app = test_app(&path);
        {
            let db = app.db();
            migrate(&db); // ALTER additifs (run_id sur finding/runrecord) — comme au boot réel
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,tool,run_id)
                 VALUES('t','c','api.example.com','IDOR exposé','HIGH','access_control','T1190','confirmé','idor','run-1')",
                [],
            ).unwrap();
            db.execute(
                "INSERT INTO roe_decision(ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons)
                 VALUES('t','c','run-1','a1','api.example.com','exploit.rce','VETO',1,0,'[\"capacité non autorisée\"]')",
                [],
            ).unwrap();
            db.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,started_by)
                 VALUES('run-1','c',datetime('now'),'done','propose',0,2,1,0,'operator')",
                [],
            ).unwrap();
        }
        let store = app.store();
        let job = store.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), &crate::sql_params!["run-1"], run_job_json).unwrap();
        let md = render_run_report_md(&store, "run-1", &job, None, None);
        drop(store);
        assert!(md.contains("# Forge — rapport d'engagement (`run-1`)"), "titre avec run_id");
        assert!(md.contains("| HIGH | 1 |"), "synthèse sévérité HIGH=1");
        assert!(md.contains("### [HIGH] IDOR exposé — `api.example.com`"), "finding détaillé rendu");
        assert!(md.contains("**Refusées (VETO"), "section transparence ROE présente");
        assert!(md.contains("`VETO` `exploit.rce` → `api.example.com` : capacité non autorisée"), "verdict VETO détaillé avec raison");
        assert!(md.contains("**Simulées (DRY_RUN)** : 2"), "compteur dry_run depuis run_job");
        // [LOT REPORTING] CWE/CVSS séparés : le finding n'a pas de colonne cwe/cvss -> dérivés
        // (CWE depuis category vide => '—' ; CVSS depuis sévérité HIGH).
        assert!(md.contains("## Résumé exécutif"), "executive summary présent");
        assert!(md.contains("Posture :"), "phrase posture présente");
        assert!(md.contains("**CWE**") && md.contains("**CVSS**"), "CWE et CVSS rendus séparément");
        assert!(md.contains("7.5"), "CVSS de base dérivé de la sévérité HIGH");
        let _ = std::fs::remove_file(&path);
    }

    /// [LOT REPORTING] extract_cwe : extrait un CWE canonique de formes variées, '' si absent.
    #[test]
    fn extract_cwe_variants() {
        assert_eq!(extract_cwe("CWE-639"), "CWE-639");
        assert_eq!(extract_cwe("cwe_862"), "CWE-862");
        assert_eq!(extract_cwe("CWE 918"), "CWE-918");
        assert_eq!(extract_cwe("access_control.CWE-284 (idor)"), "CWE-284");
        assert_eq!(extract_cwe("access_control"), "", "pas de CWE -> vide");
        assert_eq!(extract_cwe(""), "");
    }

    /// [LOT REPORTING] cvss_base_for_severity : (vecteur,score) par bande ; INFO/inconnu -> ('',0).
    #[test]
    fn cvss_base_by_severity() {
        assert_eq!(cvss_base_for_severity("CRITICAL").1, 9.8);
        assert_eq!(cvss_base_for_severity("high").1, 7.5, "casse insensible");
        assert_eq!(cvss_base_for_severity("MEDIUM").1, 5.3);
        assert_eq!(cvss_base_for_severity("LOW").1, 3.1);
        assert_eq!(cvss_base_for_severity("INFO"), ("", 0.0), "INFO -> pas de CVSS inventé");
        assert!(cvss_base_for_severity("CRITICAL").0.starts_with("CVSS:3.1/"));
    }

    /// [LOT REPORTING] html_escape : neutralise les métacaractères HTML (anti-injection rapport).
    #[test]
    fn html_escape_neutralizes() {
        assert_eq!(html_escape("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
        assert_eq!(html_escape("a&b \"q\" 'x'"), "a&amp;b &quot;q&quot; &#39;x&#39;");
        assert_eq!(html_escape("texte normal"), "texte normal");
    }

    /// [LOT REPORTING] render_run_report_html : document brandé autonome — page de garde GuatX/Forge
    /// + quetzal, sommaire, résumé exécutif EN PROSE (Campaign.notes), findings avec CWE/CVSS SÉPARÉS
    /// + FIX, CSS print, annexe chaîne-de-custody (head ledger, attribution, commande verify --pubkey).
    ///
    /// Le contenu hostile est échappé (anti-injection).
    #[test]
    fn run_report_html_branded_deliverable() {
        let path = tmp_path("forge-test-html");
        let app = test_app(&path);
        {
            let db = app.db();
            migrate(&db);
            db.execute("INSERT INTO campaign(name,started,notes) VALUES('c','t','Pentest grey-box autorisé du périmètre client.')", []).unwrap();
            // finding AVEC cwe/cvss explicites + un titre hostile (doit être échappé).
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,cwe,cvss_vector,cvss_score,mitre,status,evidence,poc,fix,tool,run_id)
                 VALUES('t','c','api.example.com','<b>IDOR</b>','HIGH','access_control','CWE-639','CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',8.1,'T1190','confirmé','dump user 42','curl -H ...','Contrôle ownership serveur','idor','run-1')",
                [],
            ).unwrap();
            db.execute(
                "INSERT INTO run_job(run_id,campaign,ts,status,mode,fired,dry_run,vetoed,errors,started_by,targets,started,finished)
                 VALUES('run-1','c',datetime('now'),'done','propose',1,0,0,0,'alice+high_impact','[\"api.example.com\"]','2026-06-01T10:00:00Z','2026-06-01T12:00:00Z')",
                [],
            ).unwrap();
        }
        // ledger non vide -> annexe custody avec head + intégrité VALIDE.
        append_console_ledger(&app, "console.run.start", json!({"run_id":"run-1","actor":"alice","by":"operator"}));
        let job = {
            let store = app.store();
            store.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), &crate::sql_params!["run-1"], run_job_json).unwrap()
        };
        let custody = build_ledger_custody(&app, "alice+high_impact");
        let store = app.store();
        let html = render_run_report_html(&store, "run-1", &job, None, &custody);
        drop(store);
        // structure & branding
        assert!(html.starts_with("<!doctype html>"), "document HTML autonome");
        assert!(html.contains("Guat<span class=\"x\">X</span>"), "branding GuatX");
        assert!(html.contains("/quetzal.svg"), "quetzal sur la page de garde");
        assert!(html.contains("@media print"), "CSS print fourni");
        assert!(html.contains("class=\"toc\""), "sommaire présent");
        // executive summary en prose + contexte Campaign.notes
        assert!(html.contains("Résumé exécutif"), "section résumé exécutif");
        assert!(html.contains("Pentest grey-box autorisé"), "Campaign.notes branchées dans le contexte");
        assert!(html.contains("posture"), "posture rendue");
        // CWE/CVSS SÉPARÉS + FIX
        assert!(html.contains("CWE</b> CWE-639"), "CWE rendu séparément");
        assert!(html.contains("8.1"), "CVSS score rendu");
        assert!(html.contains("Remédiation") && html.contains("Contrôle ownership serveur"), "FIX rendu");
        // anti-injection : le titre hostile est échappé, pas exécutable
        assert!(html.contains("&lt;b&gt;IDOR&lt;/b&gt;"), "titre hostile échappé");
        assert!(!html.contains("<b>IDOR</b>"), "pas de balise hostile brute");
        // annexe chaîne-de-custody
        assert!(html.contains("Annexe — chaîne de custody"), "annexe custody");
        assert!(html.contains("forge ledger verify --ledger") && html.contains("--pubkey"), "commande de vérif externe");
        assert!(html.contains("VALIDE"), "intégrité de la chaîne recalculée");
        assert!(html.contains("alice") && html.contains("HAUT-IMPACT"), "attribution actor + opt-in haut-impact");
        let _ = std::fs::remove_file(&path);
    }

    /// [purple] parse_fire_ts : l'ISO-8601 UTC émis par Forge -> epoch s correct (ancrage connu),
    /// offsets honorés (Z, +02:00, -05:00), fractions ignorées, epoch nu toléré, illisible -> None.
    #[test]
    fn parse_fire_ts_iso_to_epoch() {
        // 2026-06-26T00:00:00Z == 1782432000 (UTC). Vérifié par days_from_civil.
        assert_eq!(parse_fire_ts("2026-06-26T00:00:00+00:00"), Some(1782432000));
        assert_eq!(parse_fire_ts("2026-06-26T00:00:00Z"), Some(1782432000));
        // offset +02:00 -> le même instant UTC est 2h plus tôt -> epoch - 7200.
        assert_eq!(parse_fire_ts("2026-06-26T02:00:00+02:00"), Some(1782432000));
        // offset -05:00 -> 5h plus tard en UTC.
        assert_eq!(parse_fire_ts("2026-06-25T19:00:00-05:00"), Some(1782432000));
        // fraction de seconde ignorée.
        assert_eq!(parse_fire_ts("2026-06-26T00:00:00.512Z"), Some(1782432000));
        // epoch nu toléré (défensif).
        assert_eq!(parse_fire_ts("1782432000"), Some(1782432000));
        // illisible -> None (MTTD marqué indisponible, jamais inventé).
        assert_eq!(parse_fire_ts(""), None);
        assert_eq!(parse_fire_ts("pas-une-date"), None);
        // l'epoch Unix (référence) doit retomber sur 0.
        assert_eq!(parse_fire_ts("1970-01-01T00:00:00Z"), Some(0));
    }

    /// [purple] compute_purple_coverage : detected = intersection sur mitre, missed = techniques
    /// tirées absentes des détections, MTTD = first_detection - dernier tir (tronqué >=0), agrégats.
    #[test]
    fn compute_purple_coverage_detected_missed_mttd() {
        // T1110 tiré 2× (dernier tir @1000), détecté @1042 (MTTD=42) ; T1190 tiré @2000 détecté @1990
        // (détection ANTÉRIEURE -> MTTD tronqué à 0) ; T1046 tiré @3000 jamais détecté (missed).
        let fired = vec![
            ("T1110".to_string(), Some(500)),
            ("T1110".to_string(), Some(1000)),
            ("T1190".to_string(), Some(2000)),
            ("T1046".to_string(), Some(3000)),
            ("".to_string(), Some(9)), // mitre vide ignoré
        ];
        let mut det = std::collections::HashMap::new();
        det.insert("T1110".to_string(), (3i64, 1042i64));
        det.insert("T1190".to_string(), (1i64, 1990i64));
        let cov = compute_purple_coverage(&fired, &det);
        assert_eq!(cov["techniques_fired"], json!(3), "3 techniques distinctes tirées (mitre vide exclu)");
        assert_eq!(cov["techniques_detected"], json!(2), "T1110 + T1190 détectées");
        assert_eq!(cov["techniques_missed"], json!(1), "T1046 = trou de détection");
        // taux 2/3.
        let rate = cov["detection_rate"].as_f64().unwrap();
        assert!((rate - 2.0 / 3.0).abs() < 1e-9, "taux de détection = 2/3");
        // MTTD : T1110 = 1042-1000 = 42 ; T1190 = max(1990-2000,0) = 0 -> moyenne 21, max 42.
        assert_eq!(cov["mttd_avg_secs"].as_f64().unwrap(), 21.0);
        assert_eq!(cov["mttd_max_secs"], json!(42));
        // missed contient bien T1046.
        let missed = cov["missed"].as_array().unwrap();
        assert_eq!(missed.len(), 1);
        assert_eq!(missed[0]["mitre"], json!("T1046"));
        assert_eq!(missed[0]["fires"], json!(1));
        // detected T1110 porte fires=2 (dernier tir retenu pour le MTTD) et mttd_secs=42.
        let detected = cov["detected"].as_array().unwrap();
        let t1110 = detected.iter().find(|d| d["mitre"] == json!("T1110")).unwrap();
        assert_eq!(t1110["fires"], json!(2));
        assert_eq!(t1110["mttd_secs"], json!(42));
        assert_eq!(t1110["alert_count"], json!(3));
    }

    /// [purple FAIL-OPEN] aucune détection (SOC muet, map vide) NE produit PAS « tout détecté » :
    /// toutes les techniques tirées tombent en missed, taux 0, aucun MTTD inventé (null).
    #[test]
    fn compute_purple_coverage_empty_detections_all_missed() {
        let fired = vec![("T1110".to_string(), Some(1000)), ("T1046".to_string(), Some(2000))];
        let det = std::collections::HashMap::new();
        let cov = compute_purple_coverage(&fired, &det);
        assert_eq!(cov["techniques_detected"], json!(0), "rien détecté");
        assert_eq!(cov["techniques_missed"], json!(2), "tout en trou de détection");
        assert_eq!(cov["detection_rate"], json!(0.0));
        assert_eq!(cov["mttd_avg_secs"], Value::Null, "aucun MTTD inventé");
        assert_eq!(cov["mttd_max_secs"], Value::Null);
        assert!(cov["detected"].as_array().unwrap().is_empty());
    }

    /// [purple FAIL-OPEN LISIBLE] purple_fail_open : plume_reachable=false, raison présente,
    /// detected/missed VIDES et compteurs/MTTD nuls — un SOC injoignable n'est ni « tout détecté »
    /// ni « tout raté ». techniques_fired reste informatif (distinctes, mitre vide exclu).
    #[test]
    fn purple_fail_open_invents_nothing() {
        let fired = vec![
            ("T1110".to_string(), Some(1000)),
            ("T1110".to_string(), Some(1100)),
            ("T1046".to_string(), Some(2000)),
            ("".to_string(), None),
        ];
        let v = purple_fail_open("http://plume:7000", &fired, "Plume injoignable: timeout");
        assert_eq!(v["plume_reachable"], json!(false));
        assert_eq!(v["plume_url"], json!("http://plume:7000"));
        assert_eq!(v["error"], json!("Plume injoignable: timeout"));
        assert_eq!(v["techniques_fired"], json!(2), "T1110+T1046 distinctes, mitre vide exclu");
        assert_eq!(v["techniques_detected"], json!(0));
        assert_eq!(v["techniques_missed"], json!(0), "rien classé missed quand la mesure est impossible");
        assert_eq!(v["detection_rate"], json!(0.0));
        assert_eq!(v["mttd_avg_secs"], Value::Null);
        assert!(v["detected"].as_array().unwrap().is_empty());
        assert!(v["missed"].as_array().unwrap().is_empty());
    }

    /// [purple report] render_purple_section : la section markdown reflète detected/missed/MTTD
    /// quand plume_reachable=true, et affiche le fail-open lisible (sans couverture inventée) sinon.
    #[test]
    fn render_purple_section_reachable_and_fail_open() {
        // cas joignable : section avec compteurs + trous.
        let cov = json!({
            "plume_reachable": true,
            "techniques_fired": 2, "techniques_detected": 1, "techniques_missed": 1,
            "detection_rate": 0.5, "mttd_avg_secs": 42.0, "mttd_max_secs": 42,
            "detected": [{"mitre": "T1110", "alert_count": 3, "mttd_secs": 42}],
            "missed": [{"mitre": "T1046", "fires": 1}],
        });
        let mut out: Vec<String> = Vec::new();
        render_purple_section(&mut out, &cov);
        let md = out.join("\n");
        assert!(md.contains("## Couverture détection (purple)"));
        assert!(md.contains("**Techniques tirées (red)** : 2"));
        assert!(md.contains("**Taux de détection** : 50%"));
        assert!(md.contains("`T1046` (tirée 1×) — aucune alerte SOC"), "trou de détection listé");
        assert!(md.contains("`T1110` — 3 alerte(s), MTTD 42s"), "détection avec MTTD listée");

        // cas fail-open : la section l'indique explicitement, sans détecté/raté.
        let fo = purple_fail_open("", &[("T1110".to_string(), Some(1))], "PLUME_URL non configuré");
        let mut out2: Vec<String> = Vec::new();
        render_purple_section(&mut out2, &fo);
        let md2 = out2.join("\n");
        assert!(md2.contains("## Couverture détection (purple)"));
        assert!(md2.contains("Mesure indisponible (fail-open)"), "fail-open lisible dans le rapport");
        assert!(md2.contains("PLUME_URL non configuré"));
        assert!(!md2.contains("aucune alerte SOC"), "aucun trou inventé en fail-open");
    }

    /// [purple http] http_get_blocking : pour kind=plume (allow_https=false) une URL https:// est
    /// rejetée (TLS non géré, rétro-compat EXACTE) avec un message lisible mentionnant http://.
    #[test]
    fn http_get_blocking_rejects_non_http() {
        let e = http_get_blocking(
            "https://plume:7000/api/coverage/detections",
            &HttpAuth::None,
            Duration::from_millis(50),
            false, // allow_https=false (chemin plume)
        );
        assert!(e.is_err(), "https non géré (plume) -> Err");
        assert!(e.unwrap_err().contains("http://"), "message lisible mentionnant http://");
    }

    // =============================================================================================
    // SOURCE DE DÉTECTION CONFIGURABLE (plugin) — refactor infra-agnostique de la boucle purple.
    // =============================================================================================

    /// Écrit la config de source de détection dans le cache de l'App (utilitaire de test).
    fn set_detection_source(app: &App, cfg: Value) {
        *app.detection_source.write().unwrap() = Arc::new(cfg);
    }

    /// Serveur HTTP mock (UNE connexion) : renvoie `body` en 200 et retourne la requête reçue (ligne +
    /// en-têtes) pour inspection (ex. vérifier l'en-tête d'auth). Bind éphémère 127.0.0.1:0.
    async fn mock_http_once(body: String) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.expect("accept mock");
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
            req // le drop de `sock` en fin de tâche ferme la connexion (EOF côté client)
        });
        (addr, handle)
    }

    /// [détection RÉTRO-COMPAT] resolve_detection_source : sans settings, l'env legacy PLUME_URL/
    /// PLUME_TOKEN produit `{kind:plume, endpoint, auth:{type:basic,secret}}` ; une config `settings`
    /// PRIME sur l'env (la clé settings verbatim gagne). Ces deux branches figent le repli rétro-compat.
    #[test]
    fn resolve_detection_source_env_fallback_and_settings_precedence() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        // env posé, settings vide -> repli plume implicite.
        std::env::set_var("PLUME_URL", "http://soc.internal:7000/");
        std::env::set_var("PLUME_TOKEN", "dXNlcjpwYXNz");
        let v = resolve_detection_source(&conn);
        std::env::remove_var("PLUME_URL");
        std::env::remove_var("PLUME_TOKEN");
        assert_eq!(ds_kind(&v), "plume", "repli env -> kind plume");
        assert_eq!(ds_endpoint(&v), "http://soc.internal:7000", "endpoint = PLUME_URL (slash final retiré)");
        assert_eq!(ds_auth_type(&v), "basic");
        assert_eq!(ds_secret(&v), "dXNlcjpwYXNz", "auth.secret = PLUME_TOKEN");
        // settings présent -> gagne, MÊME si l'env est posé.
        std::env::set_var("PLUME_URL", "http://ignore-me:1");
        settings_set(&conn, "detection_source",
            "{\"kind\":\"generic_http\",\"endpoint\":\"http://siem:9200\",\"auth\":{\"type\":\"bearer\",\"secret\":\"abc\"}}").unwrap();
        let v2 = resolve_detection_source(&conn);
        std::env::remove_var("PLUME_URL");
        assert_eq!(ds_kind(&v2), "generic_http", "settings prime sur l'env");
        assert_eq!(ds_endpoint(&v2), "http://siem:9200");
    }

    /// [détection RÉTRO-COMPAT bout-en-bout] une source `kind=plume` (endpoint = mock renvoyant le
    /// contrat historique `{detections:[{mitre,count,first_ts}]}`) produit EXACTEMENT la même couverture
    /// que l'ancien chemin Plume : mapping IDENTITÉ, mêmes detected/missed/MTTD que compute_purple_coverage.
    #[tokio::test]
    async fn plume_source_yields_same_coverage_backcompat() {
        let app = test_app(&tmp_path("det-plume-ledger"));
        let body = r#"{"detections":[{"mitre":"T1110","count":3,"first_ts":1042},{"mitre":"T1190","count":1,"first_ts":1990}]}"#;
        let (addr, handle) = mock_http_once(body.to_string()).await;
        set_detection_source(&app, json!({
            "kind": "plume",
            "endpoint": format!("http://{addr}"),
            "auth": {"type": "basic", "secret": "dXNlcjpwYXNz"}
        }));
        let fired = vec![
            ("T1110".to_string(), Some(1000)),
            ("T1190".to_string(), Some(2000)),
            ("T1046".to_string(), Some(3000)),
        ];
        let cov = fetch_purple_coverage(&app, fired).await;
        let req = handle.await.unwrap();
        // le chemin plume envoie GET /api/coverage/detections?since=... + Basic (rétro-compat exacte).
        assert!(req.contains("GET /api/coverage/detections?since=1000"), "chemin/param plume: {req}");
        assert!(req.contains("Authorization: Basic dXNlcjpwYXNz"), "auth Basic transmise: {req}");
        assert_eq!(cov["plume_reachable"], json!(true), "rétro-compat: plume_reachable conservé");
        assert_eq!(cov["source_reachable"], json!(true), "miroir neutre présent");
        assert_eq!(cov["source_kind"], json!("plume"));
        assert_eq!(cov["techniques_detected"], json!(2));
        assert_eq!(cov["techniques_missed"], json!(1));
        let t1110 = cov["detected"].as_array().unwrap().iter().find(|d| d["mitre"] == json!("T1110")).unwrap();
        assert_eq!(t1110["mttd_secs"], json!(42), "MTTD identique à l'ancien calcul");
        assert_eq!(t1110["alert_count"], json!(3));
    }

    /// [détection generic_http + bearer + mapping] une source `generic_http` avec auth bearer est
    /// interrogée (en-tête `Authorization: Bearer …` transmis) et la réponse aux CHAMPS NATIFS
    /// (results/tech/seen/ts) est remappée puis corrélée — même jointure MITRE que plume.
    #[tokio::test]
    async fn generic_http_bearer_fetched_and_mapped() {
        let app = test_app(&tmp_path("det-generic-ledger"));
        let body = r#"{"results":[{"tech":"T1110","seen":3,"ts":1042},{"tech":"T1190","seen":1,"ts":1990}]}"#;
        let (addr, handle) = mock_http_once(body.to_string()).await;
        set_detection_source(&app, json!({
            "kind": "generic_http",
            "endpoint": format!("http://{addr}/api/alerts"),
            "auth": {"type": "bearer", "secret": "tok-abc-123"},
            "mapping": {"records": "results", "mitre": "tech", "count": "seen", "ts": "ts"}
        }));
        let fired = vec![
            ("T1110".to_string(), Some(1000)),
            ("T1190".to_string(), Some(2000)),
            ("T1046".to_string(), Some(3000)),
        ];
        let cov = fetch_purple_coverage(&app, fired).await;
        let req = handle.await.unwrap();
        assert!(req.contains("GET /api/alerts "), "endpoint generic respecté: {req}");
        assert!(req.contains("Authorization: Bearer tok-abc-123"), "bearer transmis: {req}");
        assert_eq!(cov["source_reachable"], json!(true));
        assert_eq!(cov["source_kind"], json!("generic_http"));
        assert_eq!(cov["techniques_detected"], json!(2), "T1110+T1190 remappés et détectés");
        assert_eq!(cov["techniques_missed"], json!(1), "T1046 = trou");
        let t1110 = cov["detected"].as_array().unwrap().iter().find(|d| d["mitre"] == json!("T1110")).unwrap();
        assert_eq!(t1110["alert_count"], json!(3), "count natif `seen` remappé");
        assert_eq!(t1110["mttd_secs"], json!(42));
    }

    /// [détection FAIL-OPEN LISIBLE] une source injoignable (port fermé) => source_reachable:false SANS
    /// aucun detected/missed inventé ; une config kind=none => idem. Le secret n'apparaît nulle part.
    #[tokio::test]
    async fn unreachable_source_fails_open_readable() {
        let app = test_app(&tmp_path("det-unreach-ledger"));
        set_detection_source(&app, json!({
            "kind": "generic_http",
            "endpoint": "http://127.0.0.1:1/x", // port 1 -> connexion refusée
            "auth": {"type": "bearer", "secret": "MUST-NOT-LEAK-XYZ"}
        }));
        let fired = vec![("T1110".to_string(), Some(1000)), ("T1046".to_string(), Some(2000))];
        let cov = fetch_purple_coverage(&app, fired).await;
        assert_eq!(cov["source_reachable"], json!(false), "injoignable -> fail-open lisible");
        assert_eq!(cov["plume_reachable"], json!(false), "miroir rétro-compat");
        assert_eq!(cov["techniques_detected"], json!(0), "rien détecté inventé");
        assert_eq!(cov["techniques_missed"], json!(0), "rien classé missed (mesure impossible)");
        assert!(cov["detected"].as_array().unwrap().is_empty());
        assert!(cov["missed"].as_array().unwrap().is_empty());
        assert!(cov.get("error").is_some(), "raison lisible présente");
        let ser = serde_json::to_string(&cov).unwrap();
        assert!(!ser.contains("MUST-NOT-LEAK-XYZ"), "le secret ne DOIT jamais apparaître dans la réponse");

        // config kind=none -> même fail-open lisible.
        set_detection_source(&app, json!({"kind": "none"}));
        let cov2 = fetch_purple_coverage(&app, vec![("T1110".to_string(), Some(1))]).await;
        assert_eq!(cov2["source_reachable"], json!(false));
        assert_eq!(cov2["techniques_detected"], json!(0));
        assert!(cov2["detected"].as_array().unwrap().is_empty());
    }

    /// [détection /api/detection/test] ADMIN uniquement (sans session -> refus), n'expose JAMAIS le
    /// secret dans la réponse ni le ledger, et renvoie {reachable,count,sample_mitres,error?}. Flux réel
    /// via build_router (parité prod/test) : provision admin -> cookie -> POST test.
    #[tokio::test]
    async fn detection_test_admin_only_and_never_leaks_secret() {
        let ledger = tmp_path("det-test-ledger");
        let app = test_app(&ledger);
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // provision d'un admin -> cookie de session admin.
        let setup_body = json!({"admin_login": "root", "admin_password": "hunter2pw"}).to_string();
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 200, "provision: {r}");
        let tok = cookie_token(&r).expect("cookie admin");

        let secret = "DETECT-SECRET-NEVER-LEAK-9999";
        let test_body = json!({"detection_source": {
            "kind": "generic_http",
            "endpoint": "http://127.0.0.1:1/x",   // injoignable -> reachable:false
            "auth": {"type": "bearer", "secret": secret}
        }}).to_string();

        // 1) SANS session -> refusé (gate engagée : 401/403, jamais 200).
        let r = http_raw(addr, &post_req("/api/detection/test", &test_body, "")).await;
        assert_ne!(parse_status(&r), 200, "sans admin -> pas 200 : {r}");

        // 2) AVEC session admin -> 200 + reachable:false + secret ABSENT de la réponse.
        let r = http_raw(addr, &post_req("/api/detection/test", &test_body,
            &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "admin -> 200 : {r}");
        let b = body_of(&r);
        assert!(b.contains("\"reachable\":false"), "source injoignable -> reachable:false : {b}");
        assert!(b.contains("\"count\":0"));
        assert!(!b.contains(secret), "le secret ne DOIT jamais être renvoyé : {b}");

        // 3) le ledger trace le test SANS le secret (endpoint + type d'auth seuls).
        let last = read_ledger_lines(&ledger).pop().expect("ledger detection.test");
        assert_eq!(last["kind"], "console.detection.test");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["kind"], "generic_http");
        assert_eq!(last["detail"]["auth_type"], "bearer");
        let ser = canon_json(&last);
        assert!(!ser.contains(secret), "le secret ne DOIT jamais entrer dans le ledger : {ser}");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [détection GET /api/detection/source] ADMIN uniquement (sans session -> refus) et RÉDACTION du
    /// secret : la config effective est renvoyée SANS `auth.secret`, avec `secret_set:true` et l'endpoint
    /// (non secret) conservé. Flux réel via build_router (provision admin -> cookie -> GET).
    #[tokio::test]
    async fn detection_source_get_redacts_secret_and_admin_gated() {
        let ledger = tmp_path("det-src-get-ledger");
        let app = test_app(&ledger);
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // provision d'un admin AVEC une source de détection portant un secret.
        let secret = "GET-REDACT-SECRET-7777";
        let setup_body = json!({
            "admin_login": "root", "admin_password": "hunter2pw",
            "detection_source": {"kind": "generic_http", "endpoint": "http://soc.local:9/x",
                                 "auth": {"type": "bearer", "secret": secret}}
        }).to_string();
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 200, "provision: {r}");
        let tok = cookie_token(&r).expect("cookie admin");

        // 1) GET SANS session -> refusé (gate engagée : jamais 200).
        let r = http_raw(addr, &get_req("/api/detection/source", "")).await;
        assert_ne!(parse_status(&r), 200, "GET sans admin -> refus : {r}");

        // 2) GET AVEC session admin -> 200 + secret ABSENT + secret_set:true + endpoint (non secret) présent.
        let r = http_raw(addr, &get_req("/api/detection/source", &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "admin -> 200 : {r}");
        let b = body_of(&r);
        assert!(!b.contains(secret), "le secret ne DOIT jamais être renvoyé par GET : {b}");
        assert!(b.contains("\"secret_set\":true"), "secret_set:true attendu : {b}");
        assert!(b.contains("generic_http"), "kind conservé : {b}");
        assert!(b.contains("soc.local"), "endpoint (non secret) conservé pour l'édition : {b}");
        let _ = std::fs::remove_file(&ledger);
    }

    /// [REPORTS UI wiring — livrable client] Flux END-TO-END sur le VRAI routeur (build_router) : prouve
    /// que le sous-routeur reports::routes() est bien MERGÉ (routes joignables, sous auth_guard/host_guard),
    /// que le rapport d'engagement reflète l'engagement ACTIF (JSON/HTML contient son finding), que la
    /// config de branding ROUND-TRIP (POST admin -> GET effective + rendu dans le HTML) et qu'elle est
    /// ADMIN-GATÉE (viewer -> 403 en écriture mais 200 en lecture ; anonyme -> jamais 200 une fois la gate
    /// engagée). Engagement #1 seedé avant service (Arc partagé) ; admin provisionné via /api/setup.
    #[tokio::test]
    async fn reports_ui_endpoints_wired_branding_round_trips_and_admin_gated() {
        let ledger = tmp_path("reports-ui-ledger");
        let app = test_app(&ledger);
        // parité prod : colonnes additives (engagement_id/cwe/cvss) + engagement #1 + un finding dedans.
        {
            let db = app.db();
            migrate(&db);
            db.execute(
                "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
                 VALUES(1,'Wired Eng','active','grey','{\"in_scope\":[\"a.example.com\"]}','',datetime('now'),datetime('now'))",
                [],
            ).unwrap();
            db.execute(
                "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,fix,run_id,cwe,cvss_vector,cvss_score,engagement_id)
                 VALUES(datetime('now'),'camp','a.example.com','WIRED-REPORT-FINDING','HIGH','idor','T1190','vulnerable','preuve','oracle.idor','','fix','','CWE-639','',0,1)",
                [],
            ).unwrap();
        }
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // provision admin -> cookie admin (la gate d'auth s'engage).
        let r = http_raw(addr, &post_req("/api/setup",
            &json!({"admin_login": "root", "admin_password": "hunter2pw"}).to_string(), "")).await;
        assert_eq!(parse_status(&r), 200, "provision: {r}");
        let admin = cookie_token(&r).expect("cookie admin");
        let admin_h = format!("Cookie: forge_session={admin}\r\n");

        // crée un viewer (admin) puis logue-le -> cookie viewer.
        let r = http_raw(addr, &post_req("/api/users",
            &json!({"login": "vv", "role": "viewer", "password": "viewerpw"}).to_string(), &admin_h)).await;
        assert_eq!(parse_status(&r), 200, "création viewer: {r}");
        let r = http_raw(addr, &post_req("/api/login",
            &json!({"login": "vv", "password": "viewerpw"}).to_string(), "")).await;
        assert_eq!(parse_status(&r), 200, "login viewer: {r}");
        let viewer = cookie_token(&r).expect("cookie viewer");
        let viewer_h = format!("Cookie: forge_session={viewer}\r\n");

        // 1) RAPPORT WIRÉ + ISOLÉ : GET .../engagements/1/report?format=json (admin) -> 200 + le finding.
        let r = http_raw(addr, &get_req("/api/engagements/1/report?format=json", &admin_h)).await;
        assert_eq!(parse_status(&r), 200, "report json wiré: {r}");
        let b = body_of(&r);
        assert!(b.contains("WIRED-REPORT-FINDING"), "le rapport reflète le finding de l'engagement actif: {b}");
        assert!(b.contains("\"id\":1") || b.contains("\"id\": 1"), "engagement #1 dans le rapport: {b}");

        // format CSV wiré aussi (en-tête stable).
        let r = http_raw(addr, &get_req("/api/engagements/1/report?format=csv", &admin_h)).await;
        assert_eq!(parse_status(&r), 200, "report csv wiré: {r}");
        assert!(body_of(&r).contains("WIRED-REPORT-FINDING"), "CSV contient le finding");

        // 2) BRANDING lecture viewer+ : GET (viewer) -> 200 (endpoint wiré, lecture ouverte viewer+).
        let r = http_raw(addr, &get_req("/api/report/branding", &viewer_h)).await;
        assert_eq!(parse_status(&r), 200, "GET branding viewer -> 200: {r}");

        // 3) ADMIN-GATÉ en écriture : POST branding viewer -> 403 (jamais 200), rien changé.
        let r = http_raw(addr, &post_req("/api/report/branding",
            &json!({"customer_name": "NOPE"}).to_string(), &viewer_h)).await;
        assert_eq!(parse_status(&r), 403, "POST branding viewer -> 403 (admin-gated): {r}");
        // anonyme (aucune session) -> jamais 200 une fois la gate engagée.
        let r = http_raw(addr, &post_req("/api/report/branding",
            &json!({"customer_name": "NOPE2"}).to_string(), "")).await;
        assert_ne!(parse_status(&r), 200, "POST branding anonyme -> jamais 200: {r}");

        // 4) ROUND-TRIP admin : POST (admin) -> 200, puis GET effective.customer_name == valeur posée.
        let r = http_raw(addr, &post_req("/api/report/branding",
            &json!({"customer_name": "ACME LIVE", "vendor": "GuatX Forge"}).to_string(), &admin_h)).await;
        assert_eq!(parse_status(&r), 200, "POST branding admin -> 200: {r}");
        let r = http_raw(addr, &get_req("/api/report/branding", &admin_h)).await;
        assert_eq!(parse_status(&r), 200);
        let cfg: Value = serde_json::from_str(body_of(&r)).expect("branding json");
        assert_eq!(cfg["effective"]["customer_name"], "ACME LIVE", "round-trip du branding");

        // 5) le branding est RENDU dans le rapport HTML de l'engagement actif.
        let r = http_raw(addr, &get_req("/api/engagements/1/report?format=html", &admin_h)).await;
        assert_eq!(parse_status(&r), 200);
        assert!(body_of(&r).contains("ACME LIVE"), "branding rendu dans le rapport HTML");

        let _ = std::fs::remove_file(&ledger);
    }

    /// [détection POST /api/detection/source] ADMIN uniquement (sans session -> refus, rien persisté) ;
    /// une sauvegarde admin est LEDGERISÉE (console.detection.source.set, sans le secret) et persiste
    /// `settings.detection_source` VERBATIM ; write-only : `keep_secret` conserve le secret déjà posé
    /// sans le re-saisir, et le secret n'apparaît JAMAIS dans une réponse ni le ledger.
    #[tokio::test]
    async fn detection_source_set_admin_gated_ledgered_and_write_only_secret() {
        let ledger = tmp_path("det-src-set-ledger");
        let app = test_app(&ledger);
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // provision d'un admin SANS source de détection -> cookie admin.
        let setup_body = json!({"admin_login": "root", "admin_password": "hunter2pw"}).to_string();
        let r = http_raw(addr, &post_req("/api/setup", &setup_body, "")).await;
        assert_eq!(parse_status(&r), 200, "provision: {r}");
        let tok = cookie_token(&r).expect("cookie admin");

        let secret = "SET-SECRET-NEVER-LEAK-4242";
        let cfg = json!({"detection_source": {"kind": "generic_http", "endpoint": "http://soc.local:9/x",
                        "auth": {"type": "bearer", "secret": secret}}}).to_string();

        // 1) POST SANS session -> refusé + RIEN persisté (fail-closed avant toute écriture).
        let r = http_raw(addr, &post_req("/api/detection/source", &cfg, "")).await;
        assert_ne!(parse_status(&r), 200, "POST sans admin -> refus : {r}");
        {
            let db = app.db();
            assert!(settings_get(&db, "detection_source").is_none(), "aucune écriture sans session admin");
        }

        // 2) POST AVEC session admin -> 200 + settings persistés VERBATIM + ledger source.set (sans secret).
        let r = http_raw(addr, &post_req("/api/detection/source", &cfg, &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "admin -> 200 : {r}");
        let b = body_of(&r);
        assert!(!b.contains(secret), "la réponse de sauvegarde ne DOIT jamais contenir le secret : {b}");
        assert!(b.contains("\"saved\":true"));
        {
            
            let stored = settings_get(&app.db(), "detection_source").expect("detection_source persisté");
            assert!(stored.contains("generic_http"), "config persistée");
            assert!(stored.contains(secret), "secret persisté verbatim côté serveur (jamais renvoyé)");
        }
        let last = read_ledger_lines(&ledger).pop().expect("ledger source.set");
        assert_eq!(last["kind"], "console.detection.source.set");
        assert_eq!(last["detail"]["actor"], "root");
        assert_eq!(last["detail"]["kind"], "generic_http");
        assert_eq!(last["detail"]["auth_type"], "bearer");
        let ser = canon_json(&last);
        assert!(!ser.contains(secret), "le secret ne DOIT jamais entrer dans le ledger : {ser}");

        // 3) WRITE-ONLY : POST keep_secret SANS secret (endpoint modifié) -> le secret déjà posé est CONSERVÉ.
        let cfg2 = json!({"keep_secret": true, "detection_source": {"kind": "generic_http",
                         "endpoint": "http://soc.local:9/y", "auth": {"type": "bearer"}}}).to_string();
        let r = http_raw(addr, &post_req("/api/detection/source", &cfg2, &format!("Cookie: forge_session={tok}\r\n"))).await;
        assert_eq!(parse_status(&r), 200, "keep_secret -> 200 : {r}");
        {
            
            let stored = settings_get(&app.db(), "detection_source").expect("detection_source persisté");
            assert!(stored.contains("soc.local:9/y"), "endpoint mis à jour");
            assert!(stored.contains(secret), "secret conservé via keep_secret (write-only) : {stored}");
        }
        // 4) GET ne renvoie JAMAIS le secret, même après le round-trip keep_secret.
        let r = http_raw(addr, &get_req("/api/detection/source", &format!("Cookie: forge_session={tok}\r\n"))).await;
        let b = body_of(&r);
        assert!(!b.contains(secret), "GET post-keep_secret : secret toujours rédigé : {b}");
        assert!(b.contains("\"secret_set\":true"));
        let _ = std::fs::remove_file(&ledger);
    }

    /// [parité lecture] validate_host : /api/scope-check rejette les cibles malformées (métacaractères,
    /// `-` en tête) avant même la décision de scope — pas d'injection possible via le champ target.
    #[test]
    fn scope_check_rejects_malformed_target() {
        assert!(validate_host("api.example.com").is_ok());
        assert!(validate_host("10.0.0.0/8").is_ok());
        assert!(validate_host("-evil").is_err(), "tête '-' refusée (anti flag CLI)");
        assert!(validate_host("a;rm -rf").is_err(), "métacaractère shell refusé");
        assert!(validate_host("").is_err(), "vide refusé");
    }

    /// [MED resource] db() récupère une connexion empoisonnée (un panic en section critique ne gèle
    /// plus l'API). On empoisonne volontairement le Mutex puis on vérifie que db() fonctionne encore.
    #[test]
    fn db_recovers_from_poison() {
        let path = tmp_path("forge-test-poison-ledger");
        let app = test_app(&path);
        let app2 = app.clone();
        // empoisonne : un thread panique en tenant le verrou DB.
        let h = std::thread::spawn(move || {
            let _g = app2.db.lock().unwrap();
            panic!("poison volontaire");
        });
        let _ = h.join(); // le panic empoisonne le Mutex
        assert!(app.db.lock().is_err(), "le Mutex doit être empoisonné");
        // db() doit malgré tout rendre une garde utilisable (into_inner).
        
        let n: i64 = app.db().query_row("SELECT 1", [], |r| r.get(0)).expect("requête OK après poison");
        assert_eq!(n, 1, "la connexion reste exploitable après récupération du poison");
        let _ = std::fs::remove_file(&path);
    }

    /// Seed la table `module` d'une App de test avec un module recon (web_allowed) et un module
    /// exploit (haut-impact). Réutilisé par les tests du gate haut-impact.
    fn seed_modules(app: &App) {
        let db = app.db();
        // recon.httpx : ni exploit ni destructif -> web_allowed=1 (lançable web par défaut).
        db.execute(
            "INSERT OR REPLACE INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed)
             VALUES('recon.httpx',0,0,1,'','recon',1)", [],
        ).unwrap();
        // exploit.rce : exploit=1 -> web_allowed=0 (sous plancher exploit).
        db.execute(
            "INSERT OR REPLACE INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed)
             VALUES('exploit.rce',1,0,1,'T1190','rce',0)", [],
        ).unwrap();
    }

    /// [HIGH gouvernance] high_impact_gate (fonction pure) : honore l'opt-in UNIQUEMENT avec
    /// operator + arm + reason non vide ; défaut (opt-in absent) => Ok(false) inchangé ; toute
    /// condition manquante => Err 'high_impact_requires_arm_and_reason'.
    #[test]
    fn high_impact_gate_requires_all_conditions() {
        // défaut : opt-in non demandé -> Ok(false), comportement actuel (plancher tient).
        assert!(!high_impact_gate(false, true, true, "raison").unwrap());
        assert!(!high_impact_gate(false, false, false, "").unwrap(),
            "opt-in absent prime : aucune erreur même sans arm/reason");
        // opt-in demandé + 3 conditions réunies -> Ok(true).
        assert!(high_impact_gate(true, true, true, "test autorisé par l'opérateur").unwrap());
        // opt-in demandé mais une condition manque -> Err 400 explicite.
        for (op, arm, reason) in [
            (false, true, "r"),   // pas operator
            (true, false, "r"),   // pas arm
            (true, true, ""),     // reason vide
            (true, true, "   "),  // reason blanche (trim)
        ] {
            let err = high_impact_gate(true, op, arm, reason).unwrap_err();
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
            assert_eq!(err.code, "high_impact_requires_arm_and_reason",
                "condition manquante (op={op}, arm={arm}, reason={reason:?}) doit 400");
        }
    }

    /// [HIGH gouvernance] validate_modules : SANS opt-in (allow_high_impact=false) le plancher tient
    /// (exploit.rce -> 400 exploit_floor) ; AVEC opt-in honoré, exploit.rce passe ; un kind inconnu
    /// est TOUJOURS refusé, même armé (le contrôle unknown_module ne s'affaiblit jamais).
    #[test]
    fn validate_modules_high_impact_lifts_floor_only() {
        let path = tmp_path("forge-test-vmods");
        let app = test_app(&path);
        seed_modules(&app);
        // sans opt-in : recon OK, exploit refusé (plancher).
        assert!(validate_modules(&app, &["recon.httpx".into()], false).is_ok());
        let err = validate_modules(&app, &["exploit.rce".into()], false).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "exploit_floor", "plancher exploit tient sans opt-in");
        // avec opt-in honoré : exploit accepté.
        assert!(validate_modules(&app, &["exploit.rce".into()], true).is_ok(),
            "opt-in honoré -> exploit/destructif acceptés");
        // INVARIANT : kind inconnu refusé même avec opt-in (anti-injection d'argv préservé).
        let err = validate_modules(&app, &["forge.injected".into()], true).unwrap_err();
        assert_eq!(err.code, "unknown_module", "kind inconnu refusé même armé");
        let _ = std::fs::remove_file(&path);
    }

    /// [HIGH gouvernance] high_impact_modules : liste UNIQUEMENT les modules exploit/destructif parmi
    /// les demandés (pour l'audit ledger/run_job). Ignore les modules recon et les kinds inconnus.
    #[test]
    fn high_impact_modules_lists_only_high_impact() {
        let path = tmp_path("forge-test-himods");
        let app = test_app(&path);
        seed_modules(&app);
        let hi = high_impact_modules(&app, &["recon.httpx".into(), "exploit.rce".into(), "inconnu".into()]);
        assert_eq!(hi, vec!["exploit.rce".to_string()], "seul l'exploit listé pour l'audit");
        let _ = std::fs::remove_file(&path);
    }

    // =================================================================================================
    // GOUVERNANCE CONNECTEUR (#4) — enabled / available_override : intention opérateur + enforcement.
    // =================================================================================================

    /// [connecteur] module_operator_disabled / module_effectively_available (fonctions PURES) :
    /// désactivé ssi enabled=0 OU override=Some(false) ; un binaire simplement absent (probed=0, sans
    /// override) N'EST PAS une désactivation opérateur. effective = enabled AND (override ?? probed).
    #[test]
    fn module_governance_pure_predicates() {
        // enabled + rien -> suit la sonde.
        assert!(!module_operator_disabled(true, None), "enabled sans override -> pas désactivé opérateur");
        assert!(module_effectively_available(true, None, true), "enabled + sonde OK -> effectif");
        assert!(!module_effectively_available(true, None, false), "enabled + sonde KO -> non effectif (sonde)");
        // enabled=0 -> désactivé opérateur, jamais effectif (même sonde OK).
        assert!(module_operator_disabled(false, None), "enabled=0 -> désactivé");
        assert!(!module_effectively_available(false, None, true), "enabled=0 prime sur une sonde positive");
        // override=Some(false) -> désactivé opérateur MÊME si la sonde est positive (binaire présent).
        assert!(module_operator_disabled(true, Some(false)), "override=false -> désactivé opérateur");
        assert!(!module_effectively_available(true, Some(false), true), "override=false masque un binaire présent");
        // override=Some(true) -> PAS une désactivation ; effectif même sonde négative.
        assert!(!module_operator_disabled(true, Some(true)), "override=true -> pas désactivé");
        assert!(module_effectively_available(true, Some(true), false), "override=true force la disponibilité");
    }

    /// [connecteur --modules filter] filter_enabled_modules + operator_disabled_modules : un connecteur
    /// DÉSACTIVÉ (enabled=0) OU masqué par override=0 est RETIRÉ de la liste `--modules` passée au moteur
    /// au spawn, ET figure dans l'ensemble injecté au scope.json. Un binaire absent (probed=0, sans
    /// override) N'est PAS considéré « désactivé opérateur » (le moteur le SKIP via sa propre sonde).
    #[test]
    fn module_governance_filter_and_disabled_set() {
        let path = tmp_path("forge-test-modfilter");
        let app = test_app(&path);
        seed_modules(&app); // recon.httpx (enabled=1, dispo), exploit.rce (enabled=1, dispo)
        {
            let db = app.db();
            // recon.disabled : présent (available=1) mais DÉSACTIVÉ par l'opérateur (enabled=0).
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled) \
                        VALUES('recon.disabled',0,0,1,'','recon',1,0)", []).unwrap();
            // recon.masked : ENABLED mais override=0 -> masqué malgré un binaire présent.
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled,available_override) \
                        VALUES('recon.masked',0,0,1,'','recon',1,1,0)", []).unwrap();
            // recon.absent : ENABLED, pas d'override, binaire ABSENT (available=0) -> PAS désactivé opérateur.
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled) \
                        VALUES('recon.absent',0,0,0,'','recon',1,1)", []).unwrap();
        }
        let disabled = operator_disabled_modules(&app);
        assert!(disabled.contains(&"recon.disabled".to_string()), "enabled=0 -> dans le set désactivé");
        assert!(disabled.contains(&"recon.masked".to_string()), "override=0 -> dans le set désactivé");
        assert!(!disabled.contains(&"recon.absent".to_string()), "binaire absent (sans override) -> PAS désactivé opérateur");
        assert!(!disabled.contains(&"recon.httpx".to_string()), "connecteur actif -> hors set");
        // filtre --modules : les désactivés SONT retirés, les actifs et l'absent (géré par la sonde) restent.
        let filtered = filter_enabled_modules(&app,
            &["recon.httpx".into(), "recon.disabled".into(), "recon.masked".into(), "recon.absent".into()]);
        assert_eq!(filtered, vec!["recon.httpx".to_string(), "recon.absent".to_string()],
            "le filtre spawn retire recon.disabled + recon.masked, conserve httpx + absent");
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur validate] validate_modules CONSULTE enabled/override : un connecteur désactivé est
    /// refusé (400 module_disabled) — MÊME sous opt-in haut-impact (désinstaller un connecteur est au
    /// -dessus du plancher exploit). Un module actif reste accepté. Un binaire absent (sans override)
    /// N'est PAS refusé (comportement inchangé : accepté puis SKIP par le moteur).
    #[test]
    fn validate_modules_rejects_operator_disabled() {
        let path = tmp_path("forge-test-vmods-disabled");
        let app = test_app(&path);
        seed_modules(&app);
        {
            let db = app.db();
            db.execute("UPDATE module SET enabled=0 WHERE kind='recon.httpx'", []).unwrap(); // désactive
            db.execute("INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed,enabled) \
                        VALUES('recon.absent',0,0,0,'','recon',1,1)", []).unwrap();           // absent mais actif
        }
        // désactivé -> 400 module_disabled (sans opt-in).
        let err = validate_modules(&app, &["recon.httpx".into()], false).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "module_disabled", "connecteur désactivé refusé");
        // désactivé -> 400 module_disabled MÊME sous opt-in haut-impact (au-dessus du plancher exploit).
        let err = validate_modules(&app, &["recon.httpx".into()], true).unwrap_err();
        assert_eq!(err.code, "module_disabled", "désactivé refusé même armé (gouvernance > plancher)");
        // réactive -> OK ; binaire absent (actif) -> accepté (skip côté moteur, pas un refus web).
        { let db = app.db(); db.execute("UPDATE module SET enabled=1 WHERE kind='recon.httpx'", []).unwrap(); }
        assert!(validate_modules(&app, &["recon.httpx".into()], false).is_ok(), "réactivé -> accepté");
        assert!(validate_modules(&app, &["recon.absent".into()], false).is_ok(),
            "binaire absent sans intention opérateur -> accepté (SKIP moteur), pas 400");
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur no-clobber] upsert_probed_module (chemin populate_modules) : un DISABLE manuel
    /// (enabled=0 + available_override=0 + web_allowed=0) SURVIT à un re-probe qui met à jour les
    /// champs sondés (exploit/available/mitre/descr). Régression : le refresh ne doit JAMAIS écraser
    /// l'intention opérateur.
    #[test]
    fn refresh_does_not_clobber_manual_disable() {
        let path = tmp_path("forge-test-noclobber");
        let app = test_app(&path);
        {
            let store = app.store();
            // 1er probe : module recon dispo.
            upsert_probed_module(&store, "recon.httpx", false, false, true, "", "recon httpx");
            // l'admin DÉSACTIVE le connecteur + masque + retire du web (intention opérateur).
            store.execute("UPDATE module SET enabled=0, available_override=0, web_allowed=0 WHERE kind='recon.httpx'", &crate::sql_params![]).unwrap();
            // re-probe (nouvelle version : gagne une capacité exploit, sonde toujours dispo, descr changée).
            upsert_probed_module(&store, "recon.httpx", true, false, true, "T1190", "recon httpx v2");
            let (enabled, ov, web, exploit, descr): (i64, Option<i64>, i64, i64, String) = store.query_row(
                "SELECT enabled, available_override, web_allowed, exploit, descr FROM module WHERE kind='recon.httpx'",
                &crate::sql_params![], |r| Ok((r.get_i64(0)?, r.get_opt_i64(1)?, r.get_i64(2)?, r.get_i64(3)?, r.get_str(4)?))).unwrap();
            drop(store);
            // INTENTION OPÉRATEUR préservée :
            assert_eq!(enabled, 0, "enabled=0 préservé au re-probe (no-clobber)");
            assert_eq!(ov, Some(0), "available_override=0 préservé au re-probe");
            assert_eq!(web, 0, "web_allowed préservé au re-probe (intention opérateur)");
            // champs SONDÉS mis à jour :
            assert_eq!(exploit, 1, "champ sondé exploit MIS À JOUR par le re-probe");
            assert_eq!(descr, "recon httpx v2", "champ sondé descr MIS À JOUR par le re-probe");
        }
        // un NOUVEAU module hérite des DEFAULT enabled=1 / override=NULL.
        {
            let store = app.store();
            upsert_probed_module(&store, "recon.new", false, false, true, "", "neuf");
            let (enabled, ov): (i64, Option<i64>) = store.query_row(
                "SELECT enabled, available_override FROM module WHERE kind='recon.new'", &crate::sql_params![],
                |r| Ok((r.get_i64(0)?, r.get_opt_i64(1)?))).unwrap();
            drop(store); // release before the assertions below (no DB access there)
            assert_eq!(enabled, 1, "nouveau module -> enabled par défaut");
            assert_eq!(ov, None, "nouveau module -> pas d'override par défaut (suit la sonde)");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur endpoint] module_governance : ADMIN-GATED (viewer -> 403 sans aucune mutation) +
    /// LEDGERISÉ (une mutation admin écrit `console.admin.module.set` attribuée à l'acteur). Preuve que
    /// l'endpoint est la contrepartie écriture gouvernée de GET /api/modules.
    #[tokio::test]
    async fn module_governance_endpoint_admin_gated_and_ledgered() {
        let path = tmp_path("forge-test-modgov");
        let app = test_app(&path);
        seed_modules(&app);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "aa", "admin", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (atok, _) = create_session(&app, uid_of(&app, "aa"));

        // viewer -> 403 (fail-closed) ET aucune mutation (le connecteur reste enabled=1).
        let resp = module_governance(
            State(app.clone()), bearer_headers(&vtok), Path("recon.httpx".into()),
            Json(json!({"enabled": false}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "non-admin refusé (fail-closed)");
        let en: i64 = { let db = app.db(); db.query_row("SELECT enabled FROM module WHERE kind='recon.httpx'", [], |r| r.get(0)).unwrap() };
        assert_eq!(en, 1, "un refus 403 ne DOIT rien muter");

        // admin -> 200 + mutation persistée + entrée ledger attribuée.
        let resp = module_governance(
            State(app.clone()), bearer_headers(&atok), Path("recon.httpx".into()),
            Json(json!({"enabled": false, "available_override": true}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "admin autorisé");
        let (en, ov): (i64, Option<i64>) = { let db = app.db(); db.query_row(
            "SELECT enabled, available_override FROM module WHERE kind='recon.httpx'", [],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap() };
        assert_eq!(en, 0, "admin a désactivé le connecteur");
        assert_eq!(ov, Some(1), "admin a posé available_override=true");
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.admin.module.set", "mutation ledgerisée");
        assert_eq!(last["detail"]["actor"], "aa", "attribuée à l'admin acteur");
        assert_eq!(last["detail"]["kind"], "recon.httpx");
        assert_eq!(last["detail"]["enabled"], false);

        // kind inconnu -> 404 (pas de module fantôme créé depuis l'admin).
        let resp = module_governance(
            State(app.clone()), bearer_headers(&atok), Path("recon.ghost".into()),
            Json(json!({"enabled": false}))).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "connecteur inconnu -> 404");
        // corps sans aucun champ -> 400 (aucun changement).
        let resp = module_governance(
            State(app.clone()), bearer_headers(&atok), Path("recon.httpx".into()),
            Json(json!({}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "aucun changement -> 400");
        let _ = std::fs::remove_file(&path);
    }

    /// [connecteur routeur] le param `/api/modules/:kind` coexiste avec le statique
    /// `/api/modules/refresh` (matchit : le statique prime). Construire ce sous-routeur ne doit PAS
    /// paniquer — garde-fou contre un conflit de routes introduit par la gouvernance connecteur.
    #[test]
    fn module_routes_do_not_conflict() {
        let _r: Router<App> = Router::new()
            .route("/api/modules", get(modules))
            .route("/api/modules/refresh", post(modules_refresh))
            .route("/api/modules/:kind", post(module_governance));
    }

    // =============================================================================================
    // SÉLECTION DE TECHNIQUES PAR-SCOPE (profil + toggles catégorie/technique) — validation, persistance,
    // catalogue groupé par catégorie (spawn moteur), endpoint gouverné (opérateur/admin) + ledgerisé.
    // =============================================================================================

    fn conn_info() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:5555".parse().unwrap())
    }

    /// Aplati {groups:{cat:[{kind,enabled_for_current_scope}]}} en une map kind -> activé.
    fn flatten_enabled(body: &Value) -> std::collections::HashMap<String, bool> {
        let mut m = std::collections::HashMap::new();
        if let Some(groups) = body.get("groups").and_then(|g| g.as_object()) {
            for rows in groups.values() {
                for r in rows.as_array().into_iter().flatten() {
                    if let (Some(k), Some(e)) = (
                        r.get("kind").and_then(|v| v.as_str()),
                        r.get("enabled_for_current_scope").and_then(|v| v.as_bool()),
                    ) {
                        m.insert(k.to_string(), e);
                    }
                }
            }
        }
        m
    }

    /// [sélection pure] validate_technique_selection : profils fermés, toggles typés bool + clés bien
    /// formées, défauts, clés INCONNUES tolérées (le résolveur moteur les ignore — pas de capacité forgée).
    #[test]
    fn validate_technique_selection_grammar_and_defaults() {
        // corps vide -> défaut profil bug_bounty + toggles vides.
        let v = validate_technique_selection(&json!({})).unwrap();
        assert_eq!(v["profile"], "bug_bounty");
        assert_eq!(v["categories"], json!({}));
        assert_eq!(v["techniques"], json!({}));
        // profils FERMÉS.
        for p in ["bug_bounty", "pentest", "custom"] {
            assert_eq!(validate_technique_selection(&json!({"profile": p})).unwrap()["profile"], p);
        }
        assert!(validate_technique_selection(&json!({"profile": "root"})).is_err(), "profil inconnu refusé");
        // toggles : bool requis, clé bien formée ; clé inconnue TOLÉRÉE (résolveur moteur l'ignore).
        let v = validate_technique_selection(&json!({"categories": {"SQLi": false}, "techniques": {"rce.probe": true}})).unwrap();
        assert_eq!(v["categories"]["SQLi"], false);
        assert_eq!(v["techniques"]["rce.probe"], true);
        assert!(validate_technique_selection(&json!({"categories": {"SQLi": "no"}})).is_err(), "valeur non-bool refusée");
        assert!(validate_technique_selection(&json!({"categories": {"bad key": true}})).is_err(), "clé mal formée refusée");
        assert!(validate_technique_selection(&json!({"techniques": []})).is_err(), "techniques doit être un objet");
    }

    /// [sélection persistance] technique_selection_value : défaut bug_bounty si absent ; round-trip après
    /// settings_set ; valeur illisible -> défaut (fail-soft, jamais de valeur inventée).
    #[test]
    fn technique_selection_value_default_and_round_trip() {
        let path = tmp_path("forge-test-techsel");
        let app = test_app(&path);
        assert_eq!(technique_selection_value(&app)["profile"], "bug_bounty", "absent -> défaut bug_bounty");
        {
            let db = app.db();
            settings_set(&db, "technique_selection",
                &json!({"profile":"pentest","categories":{"SQLi":false},"techniques":{}}).to_string()).unwrap();
        }
        let v = technique_selection_value(&app);
        assert_eq!(v["profile"], "pentest");
        assert_eq!(v["categories"]["SQLi"], false);
        { let db = app.db(); settings_set(&db, "technique_selection", "pas du json").unwrap(); }
        assert_eq!(technique_selection_value(&app)["profile"], "bug_bounty", "illisible -> défaut (fail-soft)");
        let _ = std::fs::remove_file(&path);
    }

    /// [sélection endpoint] POST /api/techniques/selection : OPÉRATEUR/ADMIN-gated (viewer -> 403 SANS
    /// mutation) + LEDGERISÉ (`console.techniques.selection.set` attribuée à l'acteur) + persisté.
    #[tokio::test]
    async fn technique_selection_endpoint_operator_gated_and_ledgered() {
        let path = tmp_path("forge-test-techsel-ep");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));

        // viewer -> 403 (fail-closed) ET aucune persistance.
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&vtok),
            Json(json!({"profile": "pentest"}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer refusé (fail-closed)");
        { let db = app.db(); assert!(settings_get(&db, "technique_selection").is_none(), "un refus ne persiste rien"); }

        // operator -> 200 + persistance + ledger attribué.
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"profile": "pentest", "categories": {"SQLi": false}}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "operator autorisé");
        let stored = { let db = app.db(); settings_get(&db, "technique_selection").unwrap() };
        let sv: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(sv["profile"], "pentest");
        assert_eq!(sv["categories"]["SQLi"], false);
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.techniques.selection.set", "mutation ledgerisée");
        assert_eq!(last["detail"]["actor"], "oo", "attribuée à l'acteur opérateur");
        assert_eq!(last["detail"]["selection"]["profile"], "pentest");

        // profil invalide -> 400.
        let resp = technique_selection_set(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"profile": "root"}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "profil invalide -> 400");
        let _ = std::fs::remove_file(&path);
    }

    // =============================================================================================
    // WORKFLOWS ÉDITABLES & SAUVEGARDÉS — validation pure, routes non-conflictuelles, CRUD gouverné
    // (opérateur/admin) + ledgerisé + persisté, builtins protégés (fail-closed).
    // =============================================================================================

    /// [workflows routes] les 2 routes workflows coexistent (segment statique vs `:name`, matchit).
    #[test]
    fn workflow_routes_do_not_conflict() {
        let _r: Router<App> = Router::new()
            .route("/api/workflows", get(workflows_list).post(workflow_create))
            .route("/api/workflows/:name", post(workflow_edit));
    }

    /// [workflows pur] validate_workflow_body : grammaire nom/kind, steps typées, défauts, name_override,
    /// kinds inconnus TOLÉRÉS (l'engine les LARGUE via ∩ enabled — pas de capacité forgée).
    #[test]
    fn validate_workflow_grammar_and_defaults() {
        // minimal -> défauts (description "", builtin false, steps normalisées {kind, params}).
        let v = validate_workflow_body(&json!({"name": "wf1", "steps": [{"kind": "recon.httpx"}]}), None).unwrap();
        assert_eq!(v["name"], "wf1");
        assert_eq!(v["description"], "");
        assert_eq!(v["builtin"], false);
        assert_eq!(v["steps"][0]["kind"], "recon.httpx");
        assert_eq!(v["steps"][0]["params"], json!({}));
        // name_override (segment d'URL) prime sur le corps.
        let v = validate_workflow_body(&json!({"name": "ignored", "steps": []}), Some("from-url")).unwrap();
        assert_eq!(v["name"], "from-url");
        // noms mal formés refusés.
        for bad in ["", "-x", "a b", "a/b"] {
            assert!(validate_workflow_body(&json!({"name": bad, "steps": []}), None).is_err(), "nom '{bad}' refusé");
        }
        // kind mal formé refusé ; params non-objet refusé ; steps non-liste refusé.
        assert!(validate_workflow_body(&json!({"name": "w", "steps": [{"kind": "bad kind"}]}), None).is_err());
        assert!(validate_workflow_body(&json!({"name": "w", "steps": [{"kind": "recon.httpx", "params": []}]}), None).is_err());
        assert!(validate_workflow_body(&json!({"name": "w", "steps": "nope"}), None).is_err());
        // kind INCONNU du registre : toléré (résolveur moteur/engine le LARGUE).
        let v = validate_workflow_body(&json!({"name": "w", "steps": [{"kind": "not.a.real.kind"}]}), None).unwrap();
        assert_eq!(v["steps"][0]["kind"], "not.a.real.kind");
        // trop d'étapes -> refus.
        let many: Vec<Value> = (0..129).map(|_| json!({"kind": "recon.httpx"})).collect();
        assert!(validate_workflow_body(&json!({"name": "w", "steps": many}), None).is_err(), "> 128 étapes refusé");
    }

    /// [workflows builtins protégés] validate + noms réservés (miroir local, sans spawn moteur).
    #[test]
    fn workflow_builtin_names_reserved() {
        for n in WORKFLOW_BUILTIN_NAMES {
            assert!(workflow_name_is_builtin(n), "'{n}' est un builtin réservé");
        }
        assert!(!workflow_name_is_builtin("my-custom"), "un nom utilisateur n'est pas réservé");
    }

    /// [workflows endpoint] CRUD GOUVERNÉ : viewer -> 403 SANS mutation ; operator -> create/edit
    /// persistés (`settings.workflows`) + ledgerisés (`console.workflows.save/delete` attribués) ;
    /// suppression d'un builtin -> 409 (protégé, fail-closed) ; suppression d'un inconnu -> 404 ;
    /// création avec nom réservé -> 409. Appelle les handlers HTTP réels (check_operator).
    #[tokio::test]
    async fn workflow_endpoints_operator_gated_and_ledgered() {
        let path = tmp_path("forge-test-wf-ep");
        let app = test_app(&path);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));

        // viewer -> 403 (fail-closed) ET aucune persistance.
        let resp = workflow_create(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&vtok),
            Json(json!({"name": "my-wf", "steps": [{"kind": "recon.httpx"}]}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer refusé (fail-closed)");
        { let db = app.db(); assert!(settings_get(&db, "workflows").is_none(), "un refus ne persiste rien"); }

        // operator create -> 200 + persistance + ledger attribué.
        let resp = workflow_create(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"name": "my-wf", "description": "d", "steps": [{"kind": "recon.httpx"}, {"kind": "sqli.probe", "params": {"param": "q"}}]}))).await;
        assert_eq!(resp.status(), StatusCode::OK, "operator autorisé");
        let stored = { let db = app.db(); settings_get(&db, "workflows").unwrap() };
        let sv: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(sv["my-wf"]["steps"][1]["kind"], "sqli.probe");
        assert_eq!(sv["my-wf"]["steps"][1]["params"]["param"], "q");
        let last = read_ledger_lines(&path).into_iter().last().unwrap();
        assert_eq!(last["kind"], "console.workflows.save", "création ledgerisée");
        assert_eq!(last["detail"]["actor"], "oo", "attribuée à l'acteur opérateur");
        assert_eq!(last["detail"]["name"], "my-wf");

        // operator edit via :name -> 200 (remplace les étapes).
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("my-wf".into()), Json(json!({"steps": [{"kind": "web.nuclei"}]}))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let sv: Value = { let db = app.db(); serde_json::from_str(&settings_get(&db, "workflows").unwrap()).unwrap() };
        assert_eq!(sv["my-wf"]["steps"].as_array().unwrap().len(), 1);
        assert_eq!(sv["my-wf"]["steps"][0]["kind"], "web.nuclei");

        // création/édition avec un nom RÉSERVÉ (builtin) -> 409, aucune persistance du builtin.
        let resp = workflow_create(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Json(json!({"name": "full-pentest", "steps": []}))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "nom réservé refusé");
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("bug-bounty-web".into()), Json(json!({"steps": []}))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "édition d'un builtin refusée");

        // suppression d'un BUILTIN -> 409 (protégé), même par operator.
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("recon-surface".into()), Json(json!({"delete": true}))).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "builtin non supprimable (fail-closed)");

        // suppression d'un INCONNU -> 404.
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("ghost".into()), Json(json!({"delete": true}))).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // viewer ne peut pas supprimer -> 403 (my-wf reste).
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&vtok),
            Path("my-wf".into()), Json(json!({"delete": true}))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        {  let sv: Value = serde_json::from_str(&settings_get(&app.db(), "workflows").unwrap()).unwrap();
          assert!(sv.get("my-wf").is_some(), "un delete refusé ne supprime rien"); }

        // operator supprime son workflow -> 200 + ledger `console.workflows.delete`.
        let resp = workflow_edit(State(app.clone()), conn_info(), Query(HashMap::new()), bearer_headers(&otok),
            Path("my-wf".into()), Json(json!({"delete": true}))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let sv: Value = { let db = app.db(); serde_json::from_str(&settings_get(&db, "workflows").unwrap()).unwrap() };
        assert!(sv.get("my-wf").is_none(), "supprimé de la map");
        let last = read_ledger_lines(&path).into_iter().last().unwrap();
        assert_eq!(last["kind"], "console.workflows.delete", "suppression ledgerisée");
        let _ = std::fs::remove_file(&path);
    }

    /// [workflows GET] GET /api/workflows — LISTE (viewer) : workflows UTILISATEUR (settings) +
    /// INTÉGRÉS dérivés du registre via le moteur (`forge workflows --json`). Nécessite python3 + forge
    /// (..) comme le test du catalogue de techniques (SOURCE UNIQUE moteur). Chaque entrée porte
    /// `step_kinds` + `step_count` ; les builtins portent `builtin:true` ; le user workflow apparaît.
    #[tokio::test]
    async fn workflows_list_returns_builtins_and_user() {
        let path = tmp_path("forge-test-wf-list");
        let app = test_app(&path);
        {
            let db = app.db();
            settings_set(&db, "workflows",
                &json!({"my-wf": {"name": "my-wf", "description": "d", "builtin": false,
                                   "steps": [{"kind": "recon.httpx", "params": {}}, {"kind": "sqli.probe", "params": {}}]}}).to_string()).unwrap();
        }
        let resp = workflows_list(State(app.clone()), HeaderMap::new(), Query(HashMap::new())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = resp_json(resp).await;
        // builtins dérivés du moteur : recon-surface / bug-bounty-web / full-pentest, builtin:true.
        let builtins = j["builtins"].as_array().expect("builtins array");
        assert!(builtins.len() >= 3, "au moins 3 workflows intégrés (dérivés du registre)");
        let bnames: Vec<&str> = builtins.iter().filter_map(|b| b["name"].as_str()).collect();
        for n in WORKFLOW_BUILTIN_NAMES {
            assert!(bnames.contains(n), "workflow intégré '{n}' présent");
        }
        assert!(builtins.iter().all(|b| b["builtin"] == true), "les intégrés portent builtin:true");
        assert!(builtins.iter().all(|b| b["step_count"].as_u64().unwrap_or(0) > 0), "chaque intégré a des étapes");
        // le workflow utilisateur apparaît avec ses step_kinds dédupliqués/ordonnés.
        let user = j["workflows"].as_array().expect("workflows array");
        let mine = user.iter().find(|w| w["name"] == "my-wf").expect("user workflow listé");
        assert_eq!(mine["builtin"], false);
        assert_eq!(mine["step_count"], 2);
        assert_eq!(mine["step_kinds"], json!(["recon.httpx", "sqli.probe"]));
        let _ = std::fs::remove_file(&path);
    }

    /// [MIGRATION] POST /api/import — ingestion de scans EXISTANTS, OPÉRATEUR-gaté + LEDGERISÉ +
    /// SCOPE-GUARDÉ. Viewer -> 403 (rien ingéré/ledgerisé). Operator -> 200 : findings insérés
    /// (ORIENTÉS PREUVE : jamais `vulnerable`), ledger `console.import` attribué + compteurs, et le
    /// CONTENU du fichier n'apparaît JAMAIS dans le ledger (filename assaini au basename). Un asset
    /// HORS scope serveur est JETÉ. Un format inconnu -> 400. Nécessite python3 + forge (..), comme
    /// le test du catalogue de techniques (le parse partage la SOURCE UNIQUE des parseurs du moteur).
    #[tokio::test]
    async fn import_endpoint_operator_gated_ledgered_and_scope_guarded() {
        let path = tmp_path("forge-test-import-ep");
        let app = test_app_scoped(&path, vec!["example.com".into(), "*.example.com".into()]);
        {
            let db = app.db();
            upsert_user(&db, "vv", "viewer", &hash_pw("pw")).unwrap();
            upsert_user(&db, "oo", "operator", &hash_pw("pw")).unwrap();
        }
        let (vtok, _) = create_session(&app, uid_of(&app, "vv"));
        let (otok, _) = create_session(&app, uid_of(&app, "oo"));

        let nmap = "<?xml version=\"1.0\"?><!DOCTYPE nmaprun><nmaprun><host>\
            <address addr=\"1.1.1.1\" addrtype=\"ipv4\"/><hostnames><hostname name=\"example.com\"/></hostnames>\
            <ports><port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><service name=\"https\"/></port></ports>\
            </host></nmaprun>";
        let body = json!({"campaign": "imp", "format": "auto", "filename": "../etc/scan.xml", "content": nmap});

        // viewer -> 403 (fail-closed), rien ingéré.
        let resp = import_scan(State(app.clone()), conn_info(), bearer_headers(&vtok), Json(body.clone())).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer refusé (fail-closed)");
        {  let n: i64 = app.db().query_row("SELECT COUNT(*) FROM finding", [], |r| r.get(0)).unwrap(); assert_eq!(n, 0, "un refus n'ingère rien"); }

        // operator -> 200 : findings insérés, orientés preuve, ledgerisés.
        let resp = import_scan(State(app.clone()), conn_info(), bearer_headers(&otok), Json(body.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK, "operator autorisé (nécessite python3+forge dans ..)");
        let jr = resp_json(resp).await;
        assert_eq!(jr["format"], "nmap", "format auto-détecté");
        assert!(jr["ingested"].as_i64().unwrap() >= 1, "au moins un finding ingéré");
        {
            let db = app.db();
            let n: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE campaign='imp'", [], |r| r.get(0)).unwrap();
            assert!(n >= 1, "findings insérés pour la campagne");
            let vuln: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE status='vulnerable'", [], |r| r.get(0)).unwrap();
            assert_eq!(vuln, 0, "un import ne CONFIRME jamais (orienté preuve : jamais vulnerable)");
            let tested: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE status='tested' AND tool='nmap'", [], |r| r.get(0)).unwrap();
            drop(db);
            assert!(tested >= 1, "nmap -> recon tested");
        }
        // ledger : console.import attribué + compteurs ; JAMAIS le contenu (filename assaini au basename).
        let entries = read_ledger_lines(&path);
        let last = entries.last().unwrap();
        assert_eq!(last["kind"], "console.import", "mutation ledgerisée");
        assert_eq!(last["detail"]["actor"], "oo", "attribuée à l'acteur opérateur");
        assert!(last["detail"]["counts"]["ingested"].as_i64().unwrap() >= 1);
        assert_eq!(last["detail"]["filename"], "scan.xml", "filename assaini (basename, pas de ../)");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("nmaprun"), "le contenu du fichier ne fuit JAMAIS dans le ledger");

        // out-of-scope : un asset hors scope serveur est JETÉ (compté out_of_scope, 0 ingéré).
        let oos = "<?xml version=\"1.0\"?><!DOCTYPE nmaprun><nmaprun><host>\
            <address addr=\"9.9.9.9\" addrtype=\"ipv4\"/><hostnames><hostname name=\"evil.attacker.test\"/></hostnames>\
            <ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/><service name=\"ssh\"/></port></ports>\
            </host></nmaprun>";
        let resp = import_scan(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(json!({"campaign": "imp2", "format": "nmap", "content": oos}))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let jr = resp_json(resp).await;
        assert_eq!(jr["counts"]["out_of_scope"], 1, "asset hors scope compté");
        assert_eq!(jr["ingested"].as_i64().unwrap(), 0, "asset hors scope JETÉ (rien ingéré)");
        {  let n: i64 = app.db().query_row("SELECT COUNT(*) FROM finding WHERE campaign='imp2'", [], |r| r.get(0)).unwrap(); assert_eq!(n, 0, "aucun finding hors scope inséré"); }

        // format inconnu -> 400 (grammaire fermée, fail-closed).
        let resp = import_scan(State(app.clone()), conn_info(), bearer_headers(&otok),
            Json(json!({"campaign": "imp", "format": "nessus-xml", "content": nmap}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "format inconnu refusé");

        let _ = std::fs::remove_file(&path);
    }

    /// [catalogue] GET /api/techniques : spawne le moteur, GROUPE par catégorie et reflète l'état activé
    /// du scope. Défaut (bug_bounty) : rce.probe désactivé, sqli.probe activé. Une sélection persistée
    /// (pentest) réactive rce.probe. DÉRIVÉ du registre (SOURCE UNIQUE) — nécessite python3 + forge (..).
    #[tokio::test]
    async fn techniques_catalog_groups_by_category_and_reflects_scope() {
        let path = tmp_path("forge-test-techcat");
        let app = test_app(&path);
        // défaut (aucune sélection persistée -> bug_bounty).
        let resp = techniques_catalog(State(app.clone()), HeaderMap::new(), Query(HashMap::new())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp_json(resp).await;
        assert!(body.get("error").is_none(), "catalogue indisponible (spawn moteur): {body:?}");
        assert_eq!(body["profile"], "bug_bounty");
        let groups = body["groups"].as_object().expect("groups objet");
        assert!(groups.contains_key("SQLi") && groups.contains_key("IDOR"), "groupé par catégorie (SQLi/IDOR)");
        let state = flatten_enabled(&body);
        assert_eq!(state.get("rce.probe"), Some(&false), "rce.probe pentest-only -> désactivé en bug_bounty");
        assert_eq!(state.get("sqli.probe"), Some(&true), "sqli.probe bug_bounty -> activé");
        // chaque ligne porte tools + éligibilité.
        let sqli = groups["SQLi"].as_array().unwrap().iter().find(|r| r["kind"] == "sqli.probe").unwrap();
        assert!(sqli.get("tools").is_some() && sqli.get("bug_bounty_eligible").is_some(),
            "chaque technique porte tools + éligibilité BB");

        // sélection persistée pentest -> rce.probe activé (reflète le scope courant).
        {
            let db = app.db();
            settings_set(&db, "technique_selection",
                &json!({"profile":"pentest","categories":{},"techniques":{}}).to_string()).unwrap();
        }
        let resp = techniques_catalog(State(app.clone()), HeaderMap::new(), Query(HashMap::new())).await;
        let body = resp_json(resp).await;
        assert_eq!(body["profile"], "pentest");
        assert_eq!(flatten_enabled(&body).get("rce.probe"), Some(&true), "pentest -> rce.probe activé");
        let _ = std::fs::remove_file(&path);
    }

    // =============================================================================================
    // AUTONOMIE (STANDALONE) — Forge ne DÉPEND JAMAIS de Plume / d'une source de détection.
    // Plume (et tout SIEM/IDS) n'est qu'un enrichissement OPTIONNEL de la boucle purple.
    // =============================================================================================

    /// [STANDALONE] Sans réglage `settings.detection_source` NI env PLUME_URL/PLUME_TOKEN, la source
    /// résolue au boot est `{kind:none}` : la console démarre en AUTONOME, aucune dépendance Plume.
    /// (Défense en profondeur : on RETIRE explicitement l'env legacy pour prouver l'absence de repli.)
    #[test]
    fn standalone_default_detection_source_is_none_without_plume_env() {
        let _g = env_lock();
        std::env::remove_var("PLUME_URL");
        std::env::remove_var("PLUME_TOKEN");
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let v = resolve_detection_source(&conn);
        assert_eq!(ds_kind(&v), "none", "aucune source ni env -> kind none (Forge autonome, pas de Plume requis)");
        assert!(ds_endpoint(&v).is_empty(), "aucun endpoint inventé en autonome");
        assert!(ds_secret(&v).is_empty(), "aucun secret en autonome");
    }

    /// [STANDALONE] fetch_purple_coverage sans source configurée (kind=none) : FAIL-OPEN LISIBLE et
    /// EXPLICITEMENT AUTONOME — `source_reachable:false`, `source_configured:false`, `source_kind:"none"`,
    /// AUCUNE métrique fabriquée (detected/missed vides, taux/MTTD nuls), et `techniques_fired` reste
    /// informatif. C'est un état NORMAL (pas une erreur) : la boucle purple est simplement OFF.
    #[tokio::test]
    async fn fetch_purple_coverage_standalone_invents_nothing() {
        let app = test_app(&tmp_path("standalone-cov-ledger"));
        // cache par défaut = {kind:none} (test_app). On l'affirme pour la lisibilité du test.
        set_detection_source(&app, json!({"kind": "none"}));
        let fired = vec![
            ("T1110".to_string(), Some(1000)),
            ("T1110".to_string(), Some(1100)),
            ("T1046".to_string(), Some(2000)),
            ("".to_string(), None),
        ];
        let cov = fetch_purple_coverage(&app, fired).await;
        assert_eq!(cov["source_reachable"], json!(false), "autonome -> non joignable (fail-open)");
        assert_eq!(cov["plume_reachable"], json!(false), "miroir rétro-compat");
        assert_eq!(cov["source_configured"], json!(false), "AUCUNE source configurée -> standalone");
        assert_eq!(cov["source_kind"], json!("none"));
        assert_eq!(cov["techniques_detected"], json!(0), "rien de détecté fabriqué");
        assert_eq!(cov["techniques_missed"], json!(0), "rien classé raté quand la mesure est impossible");
        assert_eq!(cov["detection_rate"], json!(0.0));
        assert_eq!(cov["mttd_avg_secs"], Value::Null);
        assert_eq!(cov["mttd_max_secs"], Value::Null);
        assert!(cov["detected"].as_array().unwrap().is_empty());
        assert!(cov["missed"].as_array().unwrap().is_empty());
        assert_eq!(cov["techniques_fired"], json!(2), "info offensive conservée (T1110+T1046 distinctes)");
        assert!(cov["error"].as_str().unwrap_or("").contains("non configurée"), "raison lisible");
    }

    /// [STANDALONE] Une source POSÉE mais INJOIGNABLE se distingue de l'autonome : `source_configured:true`
    /// + `source_reachable:false`. Le SPA peut ainsi afficher une ANOMALIE (source injoignable) là, et un
    /// état NEUTRE (autonome) quand aucune source n'est configurée — sans jamais bloquer l'UI.
    #[tokio::test]
    async fn fetch_purple_coverage_configured_but_unreachable_is_distinct() {
        let app = test_app(&tmp_path("unreachable-cov-ledger"));
        // endpoint bidon fermé -> injoignable, mais une source EST bien configurée.
        set_detection_source(&app, json!({
            "kind": "plume", "endpoint": "http://127.0.0.1:1", "auth": {"type": "basic", "secret": "dXNlcjpwYXNz"}
        }));
        let cov = fetch_purple_coverage(&app, vec![("T1110".to_string(), Some(1))]).await;
        assert_eq!(cov["source_reachable"], json!(false), "endpoint fermé -> injoignable");
        assert_eq!(cov["source_configured"], json!(true), "une source EST configurée (pas autonome)");
        assert_eq!(cov["source_kind"], json!("plume"));
        assert!(cov["detected"].as_array().unwrap().is_empty(), "aucune couverture inventée même configurée");
    }

    /// [STANDALONE bout-en-bout] Sur le VRAI routeur (build_router), SANS aucune source de détection :
    /// /health répond 200 et /api/purple/coverage (+ alias /api/detection/coverage) répond 200 en état
    /// AUTONOME (source_reachable:false, source_configured:false) — l'endpoint ne renvoie JAMAIS d'erreur
    /// qui bloquerait l'UI. Prouve que la console BOOTE et sert la vue purple sans Plume.
    #[tokio::test]
    async fn standalone_boot_serves_health_and_coverage_without_plume() {
        let app = test_app(&tmp_path("standalone-boot-ledger")); // détection par défaut = {kind:none}
        let router = build_router(app.clone(), "web");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // /health : la console est up (aucun PLUME_URL requis pour démarrer).
        let r = http_raw(addr, &get_req("/health", "")).await;
        assert_eq!(parse_status(&r), 200, "/health up en autonome : {r}");
        assert!(body_of(&r).contains("\"status\":\"ok\""));

        // /api/purple/coverage : 200 + état AUTONOME lisible (jamais une 5xx/erreur bloquante).
        let r = http_raw(addr, &get_req("/api/purple/coverage", "")).await;
        assert_eq!(parse_status(&r), 200, "coverage 200 en autonome (pas d'erreur bloquante) : {r}");
        let b = body_of(&r);
        assert!(b.contains("\"source_reachable\":false"), "autonome -> source_reachable:false : {b}");
        assert!(b.contains("\"source_configured\":false"), "autonome -> source_configured:false : {b}");
        assert!(!b.contains("\"techniques_detected\":1"), "aucune détection fabriquée en autonome");

        // alias canonique /api/detection/coverage : même contrat 200 autonome.
        let r2 = http_raw(addr, &get_req("/api/detection/coverage", "")).await;
        assert_eq!(parse_status(&r2), 200, "alias /api/detection/coverage 200 en autonome : {r2}");
    }

    /// [/health SCHEMA VERSION] Après `migrate()` (qui TAMPONNE `settings.schema_version`), le handler
    /// /health SURFACE `schema_version == SCHEMA_VERSION` (en plus de status/version/db). ADDITIF : la
    /// forme historique {status, version, db} est préservée ; on ajoute seulement le champ tamponné.
    #[tokio::test]
    async fn health_surfaces_stamped_schema_version() {
        let app = test_app(&tmp_path("health-schema-version-ledger"));
        { let db = app.db(); migrate(&db); } // tamponne settings.schema_version
        let Json(body) = health(axum::extract::State(app)).await;
        assert_eq!(body["status"], json!("ok"), "forme historique préservée");
        assert_eq!(body["schema_version"], json!(crate::schema::SCHEMA_VERSION), "/health surface la version tamponnée");
    }

    // =============================================================================================
    // LEDGER VERIFY CLI — lecture seule, NON INTERACTIVE, RAPIDE (ne démarre PAS le serveur).
    // Régression : `forge-console ledger verify` retombait sur le boot serveur et PENDAIT.
    // =============================================================================================

}

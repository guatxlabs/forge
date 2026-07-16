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
// NOTIFICATIONS (triage enrichi) — couche LÉGÈRE de collaboration in-app posée sur l'ownership (assignee)
// + le cycle de triage. Même discipline que presence/saved_views : handlers/logique dans son PROPRE module ;
// main.rs n'y contribue que la ligne `mod` + le `merge` des routes. Émet sur les hooks assign/triage de
// findings.rs (best-effort, grant-scopé), réutilise App + le bus App.events (topic dédié) — zéro champ App.
mod notifications;
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
// `*_FILE` secret indirection (Docker/k8s secrets) — env holds a PATH, secret lives in a mounted file.
mod secret_env;
pub(crate) use crate::secret_env::*;
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
// `crate::resolve_session_identity`, `crate::operator_denied`,
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
// OUTILS AJOUTÉS PAR L'UI (« add a tool from the web UI ») — routes admin `tools_add`/`tools_list`/
// `tools_delete` (POST/GET /api/tools, DELETE /api/tools/:kind) qui déclarent un ToolSpec GOUVERNÉ
// (binaire + argv no-shell + allowlist), le persistent dans le dir server-managed (`FORGE_TOOLSPECS`) et
// HOT-RELOADENT le catalogue via `populate_modules`. Re-exporté `pub(crate)` pour build_router + tests.
mod tools;
pub(crate) use crate::tools::{tools_add, tools_delete, tools_list};
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
// CONSOLE FORGE IN-UI (roadmap P5) — POST /api/console/exec : runner GOUVERNÉ, admin-only, ledgerisé,
// STREAMÉ (SSE) d'un ALLOWLIST STRICT de sous-commandes `forge` (status/ledger verify/read-*/backup/
// upgrade), chacune avec un SCHÉMA D'ARGUMENTS typé. PAS un shell : argv FIXE construit depuis
// l'allowlist (jamais `sh -c`, jamais de texte utilisateur promu en flag). Retire le besoin de
// `docker compose exec forge forge …` pour les ops courantes. Re-exporté pour build_router.
mod exec;



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

/// FILET ANTI-PANIC (safety net) — responder de `tower_http::catch_panic::CatchPanicLayer`. Câblé comme
/// couche la PLUS EXTERNE du routeur (cf. `build_router`), il transforme TOUTE panique d'un handler (ou
/// des middlewares auth_guard/host_guard) en une réponse `500` PROPRE au lieu d'une connexion resetée
/// (RST -> le navigateur voyait « Failed to fetch », process survivant). Corps STABLE et GÉNÉRIQUE :
/// ne fuit JAMAIS le message de panique ni la backtrace (aucun `downcast` de l'erreur) — juste
/// `{"error":"internal", ...}` + `content-type: application/json`, lisible par le client. C'est un
/// dernier rempart : les chemins gouvernés (run_create/claim_and_spawn …) renvoient déjà des erreurs
/// JSON typées ; cette couche garantit qu'une panique IMPRÉVUE reste une réponse HTTP, jamais un drop.
fn catch_panic_response(_err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    // Corps figé : aucun détail de `_err` (message/backtrace) n'est exposé. Response::builder() sur des
    // valeurs statiques valides -> jamais d'erreur (l'`unwrap` ne peut pas paniquer ici).
    axum::response::Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            r#"{"error":"internal","why":"une erreur interne est survenue"}"#,
        ))
        .expect("static 500 panic response is always valid")
}

fn build_router(app: App, web_dir: &str) -> Router {
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

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // sous-commandes de provisioning de hash argon2id :
    //   forge hashpw <password>           -> hash du viewer (FORGE_CONSOLE_PASS_HASH)
    //   forge hashpw-operator <password>  -> hash du rôle OPÉRATEUR C2 (FORGE_CONSOLE_OPERATOR_HASH)
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
            println!("forge {}", forge_version());
            Some(0)
        }
        Some("hashpw") | Some("hashpw-operator") => {
            match args.get(2) {
                Some(pw) if !pw.is_empty() => {
                    println!("{}", hash_pw(pw));
                    Some(0)
                }
                _ => {
                    eprintln!("usage: forge {} <password>", args[1]);
                    Some(2)
                }
            }
        }
        // Parité LECTURE locale (CLI) : lit la MÊME base SQLite que l'API, en READ-ONLY, et
        // imprime en table (défaut) ou JSON (--json). Aucune écriture, aucun spawn — pure lecture.
        Some(cmd @ ("findings" | "roe" | "coverage" | "query")) => {
            Some(run_read_cli(cmd, &args[2..]))
        }
        // Provisioning d'un COMPTE INDIVIDUEL : forge useradd <login> <role> [--pass <pw>]
        //   role ∈ {viewer|operator|admin}. Le mot de passe est lu sur STDIN par défaut (jamais en
        //   argv -> pas de fuite via ps/cmdline) ; `--pass <pw>` est toléré pour le scripting. Le hash
        //   argon2id est calculé ici et stocké dans `users` (idempotent par login : upsert + réactive).
        Some("useradd") => {
            Some(run_useradd_cli(&args[2..]))
        }
        // AMORÇAGE DÉMO : forge seed-demo [--dir <path>] [--campaign <name>]
        //   Charge l'engagement de référence synthétique (examples/reference-engagement/) DIRECTEMENT
        //   dans la base SQLite (hors-ligne, sans réseau, sans /api/ingest) pour qu'une console fraîche
        //   affiche immédiatement Findings/Coverage/Purple/Runs. Idempotent (purge la campagne démo).
        Some("seed-demo") => {
            Some(run_seed_demo_cli(&args[2..]))
        }
        // MIGRATION DE DONNÉES : forge migrate --from <dir|db> --to <db> [--ledger <path>]
        //   [--verify] [--encrypt --key-env <ENVVAR>]. Importe un install Forge existant (non-Docker)
        //   vers une base cible (Docker/autre) : copie DB (VACUUM INTO / SQLCipher), ledger + clé
        //   .ed25519 (0600), puis SCHEMA + migrate() sur la cible. UX primaire = conteneur one-shot.
        Some("migrate") => {
            Some(run_migrate_cli(&args[2..]))
        }
        // MIGRATION DE STORE (feature `store-postgres`) : forge migrate-store --to <postgres-url>
        //   [--from <sqlite-path>] [--dry-run] [--force] [--ledger <path>]. Copie gouvernée SQLite ->
        //   Postgres à travers le seam (ids + typage préservés, ordre FK, recalage IDENTITY, vérif des
        //   comptes, checkpoint ledger signé). Arm ENTIÈREMENT gardé par la feature -> le build community
        //   (défaut) ne la connaît pas (retombe sur le boot serveur), et reste BYTE-IDENTICAL.
        #[cfg(feature = "store-postgres")]
        Some("migrate-store") => {
            Some(crate::cli::run_migrate_store_cli(&args[2..]))
        }
        // SAUVEGARDE CHIFFRÉE : forge backup --out <archive> --passphrase-env <ENVVAR>
        //   [--db <path>] [--ledger <path>]. Archive TOUJOURS chiffrée (argon2id + XChaCha20-Poly1305)
        //   regroupant snapshot DB (VACUUM INTO) + ledger + clé .ed25519 + manifest.json. Passphrase
        //   lue UNIQUEMENT depuis l'ENV (jamais argv). Chaîne ledger vérifiée avant, backup tracé.
        Some("backup") => {
            Some(run_backup_cli(&args[2..]))
        }
        // RESTAURATION CHIFFRÉE : forge restore --in <archive> --passphrase-env <ENVVAR>
        //   [--to <db>] [--ledger <path>] [--force]. Déchiffre (mauvaise passphrase/altération => rien
        //   écrit), vérifie les sha256 du manifest + la chaîne ledger, refuse d'écraser un install non
        //   vide sans --force, place db/ledger/clé (.ed25519 = 0600). Restore tracé au ledger.
        Some("restore") => {
            Some(run_restore_cli(&args[2..]))
        }
        // ROUND-TRIP BLOBSTORE (feature `object-store`) : forge blob-selftest [--key <key>]
        //   [--no-delete]. PUT -> GET -> compare octets -> EXISTS -> (DELETE) sur le store ACTIF (S3/MinIO
        //   si FORGE_BLOB_S3_* configuré, sinon local FORGE_BLOB_DIR). Preuve d'aller-retour sans serveur.
        //   Arm ENTIÈREMENT gardé par la feature -> le build community (défaut) ne le connaît pas.
        #[cfg(feature = "object-store")]
        Some("blob-selftest") => {
            Some(crate::blob::run_blob_selftest_cli(&args[2..]))
        }
        // VÉRIF LEDGER (lecture seule, NON INTERACTIVE, RAPIDE) : forge ledger verify
        //   [--ledger <path>] [--json]. Recompute la chaîne SHA-256 du ledger JSONL et exit immédiat
        //   (0 intègre / 1 rompu-absent / 2 usage). NE démarre PAS le serveur, n'ouvre PAS la base,
        //   ne lit PAS STDIN. La vérif de signature reste côté `forge ledger verify --pubkey` (Python).
        Some("ledger") => {
            Some(run_ledger_cli(&args[2..]))
        }
        // ÉTAT (lecture seule, NON INTERACTIF, RAPIDE) : forge status [--db <path>]
        //   [--ledger <path>] [--json]. Imprime version, VERSION DE SCHÉMA persistée, backend actif,
        //   base RÉDIGÉE, tête de ledger vérifiée — SANS démarrer le serveur. Base d'un upgrade sûr.
        Some("status") => {
            Some(run_status_cli(&args[2..]))
        }
        // UPGRADE SÛR EN UNE COMMANDE (fail-closed avec rollback) : forge upgrade
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
    let db_path = std::env::var("FORGE_CONSOLE_DB").unwrap_or_else(|_| "forge.db".to_string());
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
            eprintln!("[forge] FATAL {msg}");
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
                eprintln!("[forge] FATAL {e}");
                std::process::exit(2);
            });
            println!("[forge] store: Postgres (FORGE_DB_URL) — pool de {pool_size} clients connecté (écritures concurrentes, reconnect+retry HA armé)");
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
            eprintln!("[forge] FATAL FORGE_HA=1 requires FORGE_ENTERPRISE_STORE=postgres — HA is unsafe on SQLite");
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
        eprintln!("[forge] FATAL FORGE_HA=1 requires FORGE_ENTERPRISE_STORE=postgres — HA is unsafe on SQLite (this binary has no Postgres backend; rebuild with --features store-postgres)");
        std::process::exit(2);
    }

    // Ingest/console bearer: resolve FORGE_CONSOLE_TOKEN with a `*_FILE` fallback (Docker/k8s secret),
    // then auto-generate an ephemeral token when NEITHER is supplied. An empty/unreadable source is
    // treated as "not provided" (never a silent empty bearer that would leave /api/ingest open).
    let provided_token = secret_from_env("FORGE_CONSOLE_TOKEN");
    let token = provided_token.clone().unwrap_or_else(gen_token);
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
    println!("[forge] web assets: {web_dir}");

    // NE PAS journaliser le token en clair (fuite via logs/journald/historique terminal). On affiche
    // une empreinte courte (8 hex de sha256) — suffisante pour corréler/diagnostiquer sans exposer le
    // secret. Le token en clair reste disponible à l'opérateur via FORGE_CONSOLE_TOKEN (qu'il a posé).
    let token_was_provided = provided_token.is_some();
    let token_fp = &sha_hex(&token)[..8];
    if token_was_provided {
        println!("[forge] ingest token: (fourni via env) fp=sha8:{token_fp}");
    } else {
        // token auto-généré, ÉPHÉMÈRE : on n'imprime QUE l'empreinte (comme la branche env), JAMAIS le
        // secret en clair (fuite via logs/journald/historique terminal). Le moteur spawné le reçoit en
        // mémoire (App.token_raw) — la boucle purple / l'ingest interne fonctionnent sans l'afficher. Pour
        // un `/api/ingest` MANUEL reproductible, l'opérateur POSE `FORGE_CONSOLE_TOKEN=<valeur connue>`
        // (qu'il choisit) et redémarre : la branche « fourni via env » ci-dessus s'appliquera alors.
        println!("[forge] ingest token (auto-généré, éphémère) fp=sha8:{token_fp} — pose FORGE_CONSOLE_TOKEN=<valeur connue> pour le fixer et t'en servir en /api/ingest manuel");
    }
    println!("[forge] db: {db_path}");
    println!("[forge] ledger: {ledger_path}");
    // ÉTAT DB de la gate d'auth : un compte activé en base engage la gate MÊME sans hash env (ferme le
    // trou dev-open historique). On le calcule ici sur `conn` (avant son déplacement dans App) pour un
    // log fidèle ; App.recompute_auth_required() recalcule ensuite le cache faisant autorité.
    let has_enabled_user: bool =
        conn.query_row("SELECT 1 FROM users WHERE disabled=0 LIMIT 1", [], |_| Ok(())).is_ok();
    if pass_hash.is_empty() && !has_enabled_user {
        println!("[forge] AUTH OFF (dev localhost) — ni FORGE_CONSOLE_PASS_HASH ni compte activé en base. `forge useradd <login> admin` (ou pose le hash env) pour engager la gate.");
    } else if pass_hash.is_empty() {
        println!("[forge] auth ON (état DB) — gate engagée par au moins un compte activé (table users) ; connexion via POST /api/login (session individuelle) ; hash env absent");
    } else {
        println!("[forge] auth ON — user={user}, lectures protégées (Basic), écritures par token (comptes individuels via POST /api/login également acceptés)");
    }
    if operator_hash.is_empty() {
        println!("[forge] C2 FAIL-CLOSED — rôle opérateur NON provisionné (FORGE_CONSOLE_OPERATOR_HASH absent) : /api/run* renverra 403. `forge hashpw-operator '...'` pour l'activer.");
    } else {
        println!("[forge] C2 armé — rôle opérateur via en-tête X-Forge-Operator ; cibles ⊆ scope serveur ({} entrée(s)) ; exploit/destructif possibles UNIQUEMENT via opt-in haut-impact gouverné (allow_high_impact + arm + reason, journalisé au ledger) ; scope-guard moteur inchangé (hors-scope = VETO) ; watchdog={run_timeout_secs}s", scope_in.len());
    }

    // (log DÉTECTION déplacé après la construction de l'App + reload_detection_source — la source
    //  n'est connue qu'une fois le cache chargé depuis settings/env.)

    // [SÉCURITÉ XFF] Garde-fou/migration du réglage `trusted_proxy` : il doit désormais contenir le/les
    // CIDR(s) du proxy amont (Traefik/cluster, egress Cloudflare…). Une valeur héritée « truthy » non-CIDR
    // (ex. "1"/"true") ne produit AUCUN CIDR valide -> on n'accorde foi à AUCUN X-Forwarded-For (repli
    // fail-closed sur le pair TCP). On alerte l'opérateur pour qu'il reconfigure explicitement.
    match settings_get(&conn, "trusted_proxy") {
        Some(raw) if !raw.trim().is_empty() && parse_trusted_proxy_cidrs(&raw).is_empty() => {
            eprintln!("[forge] WARN trusted_proxy={raw:?} n'est PAS un CIDR valide — X-Forwarded-For sera IGNORÉ (repli fail-closed sur le pair TCP). Reconfigure `trusted_proxy` sur le(s) CIDR(s) du proxy amont réel (ex. le CIDR Traefik/cluster ou l'egress Cloudflare), sinon la politique opérateur source-CIDR verra l'IP du proxy et jamais celle du client.");
        }
        Some(raw) if !raw.trim().is_empty() => {
            println!("[forge] trusted_proxy: X-Forwarded-For honoré UNIQUEMENT si le pair TCP appartient à {:?}", parse_trusted_proxy_cidrs(&raw));
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
    // OUTILS AJOUTÉS PAR L'UI : re-marque `module.user_added=1` pour les ToolSpecs présents dans le dir
    // server-managed (le re-probe upsert le module mais `user_added` défaute à 0). Idempotent, no-op si
    // aucun outil UI. Garantit que GET/DELETE /api/tools reconnaissent les outils utilisateur après reboot.
    crate::tools::sync_user_added_flags(&app.store());
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
            println!("[forge] DÉTECTION OFF — aucune source configurée : /api/detection/coverage (alias /api/purple/coverage) répondra en fail-open lisible (source_reachable:false). Configure `settings.detection_source` (wizard) ou pose PLUME_URL/PLUME_TOKEN (rétro-compat kind=plume).");
        } else {
            // JAMAIS le secret dans le log — kind + endpoint + type d'auth seuls.
            println!("[forge] DÉTECTION armée — kind={kind} endpoint={endpoint} auth={} ; LECTURE seule, joint runrecord[fired] (red) vs détections de la source (blue).",
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
            "[forge] HA ARMÉ — instance_id={} ; bail scope='run-worker' TTL={}s ; heartbeat toutes les {}s ; leader-tick toutes les {}s (claim pending + reap failover + cancel-watch, leader-only) ; leader/instance_id publiés sur /health.",
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
    println!("[forge] http://{addr}");
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
mod tests;

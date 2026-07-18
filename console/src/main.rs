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
// BULK-OPS + VUES DE REPORTING du modèle ROUGE — god-file `findings.rs` scindé en modules cohésifs (PURE
// MOVE), tous re-exportés `pub(crate)` à la racine (mêmes résolutions `crate::*`/`super::*` INCHANGÉES) :
// `findings_bulk` (opérations de masse : findings_bulk_status/assign/triage/export + parse_ids/csv_field)
// et `findings_report` (vues lecture-seule : runrecords/campaigns/roe/coverage/attack_matrix + le catalogue
// ATT&CK). Les routes de build_router (`post(findings_bulk_status)`, `get(coverage)`, `get(attack_matrix)`,
// …) ET les tests inline (`super::*`) résolvent ces handlers INCHANGÉS.
mod findings_bulk;
pub(crate) use crate::findings_bulk::*;
mod findings_report;
pub(crate) use crate::findings_report::*;
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

// Câblage du routeur HTTP extrait dans `console/src/router.rs` (PURE MOVE) : `build_router` ne fait
// QUE câbler des handlers déjà définis + re-exportés `pub(crate)` à la racine — aucun ordre de
// `.route()`/`.merge()`, aucune string, aucun code de sortie ne change (binaire release byte-identique).
// Ré-importé ici pour que le call-site inchangé de `serve()` (`build_router(app, &web_dir)`) résolve.
mod router;
use crate::router::build_router;

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

// Boot serveur + dispatch CLI + store-gate extraits dans console/src/boot.rs (PURE MOVE, STEP 4 du
// refactor archi) : serve/dispatch_cli/enterprise_store_gate/StoreSelection ne consomment que App +
// les helpers déjà re-exportés à la racine ; le déplacement n'ajoute que des `use`. Re-exporté
// `pub(crate)` à la racine pour que main() (dispatch_cli/serve) ET les tests (`super::*` ->
// enterprise_store_gate/StoreSelection, cf. tests_http_boot) résolvent INCHANGÉS.
mod boot;
pub(crate) use crate::boot::*;

// =====================================================================================
// Tests de régression des correctifs de sûreté/sécurité (durcissement audit).
// =====================================================================================
#[cfg(test)]
pub(crate) mod testutil;

// TESTS D'INTÉGRATION — `tests.rs` (le `mod tests` inline historique, ~4600 l) a été SCINDÉ en
// modules cohésifs miroir des sous-systèmes source (STEP 2 du refactor archi,
// docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2). Chaque fichier est un module ENFANT de la racine de
// crate (donc `super::*` y résout la racine à l'identique de l'ancien inline) et importe les
// fixtures partagées via `use crate::testutil::*`. PURE MOVE : aucun corps de test modifié.
#[cfg(test)]
mod tests_http_boot;
#[cfg(test)]
mod tests_auth_session;
#[cfg(test)]
mod tests_users_admin;
#[cfg(test)]
mod tests_setup;
#[cfg(test)]
mod tests_net_policy;
#[cfg(test)]
mod tests_ledger;
#[cfg(test)]
mod tests_runs_engagement;
#[cfg(test)]
mod tests_tenancy_rbac;
#[cfg(test)]
mod tests_planning_techniques;
#[cfg(test)]
mod tests_reports_purple;
#[cfg(test)]
mod tests_modules_tools;
